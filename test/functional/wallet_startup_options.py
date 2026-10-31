#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet startup options -upgradewallet, -salvagewallet and
-blocksonly, and the startup checks of a damaged wallet.dat and wallet
database environment.

- -upgradewallet=<n> below the wallet's version is an init error; with no
  value it keeps an HD wallet at 139900 and a non-HD wallet at 60000.
- -salvagewallet renames wallet.dat to wallet.dat.<time>.bak, keeps only
  the keys and rescans: keys, balance and transactions survive, labels and
  key metadata don't.
- A wallet.dat that fails the database check is salvaged automatically at
  startup (warning), or the start fails ("salvage failed"); a non-database
  file stays in place. A transaction record that doesn't load adds a second
  warning, and the rescan finds the transaction again.
- Salvage in aggressive mode also reads the free space of the leaf pages,
  where BDB leaves old index entries and items (for example after a page
  split). The salvage steps zero that space first, so their results don't
  depend on what the file holds there.
- Known failures: a silent -salvagewallet failure, a wallet.dat restored
  after a failed salvage is moved aside again, -salvagewallet drops the HD
  chain split, a raw exception for a file named "database", a segfault
  on a damaged database log (the environment is moved aside first), and a
  stale copy of a key record's key in the free space of an earlier page
  that salvage keeps instead of the record, so the salvaged wallet doesn't
  load.
- -blocksonly turns wallet broadcasting off unless -walletbroadcast=1.
"""
import os
import re
import resource
import struct
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch, FailedToStartError, describe_exit_code
from test_framework.util import assert_equal, assert_raises_rpc_error

HD_VERSION = 139900
NON_HD_VERSION = 60000
BTREE_MAGIC = 0x053162
PAGE_TYPE_LEAF = 5
PAGE_TYPE_META = 9
# A BDB btree page starts with a 26-byte header (number of index entries at
# offset 20, HOFFSET, the offset of the lowest item, at 22, page type at 25),
# followed by the index: one 2-byte item offset per entry, key and data items
# alternating. The items fill the page from its end down to HOFFSET; each is a
# 2-byte length, a 1-byte type (1: the bytes follow) and the bytes. The space
# between the index and HOFFSET is free.
PAGE_HEADER_SIZE = 26
ITEM_DATA = 1


def page_size(data):
    """The page size of a little-endian BDB btree file, after checking its
    magic number."""
    assert_equal(struct.unpack_from('<I', data, 12)[0], BTREE_MAGIC)
    return struct.unpack_from('<I', data, 20)[0]


def leaf_pages(data, ps):
    return [p for p in range(1, len(data) // ps) if data[p * ps + 25] == PAGE_TYPE_LEAF]


def entries_and_hoffset(data, ps, p):
    return struct.unpack_from('<HH', data, p * ps + 20)


def leaf_records(data, ps, p):
    """(offset of the key item in data, key bytes) of the records on leaf
    page p whose key and data items both hold their bytes."""
    entries, _ = entries_and_hoffset(data, ps, p)
    for i in range(0, entries, 2):
        key, value = (p * ps + o for o in struct.unpack_from('<HH', data, p * ps + PAGE_HEADER_SIZE + 2 * i))
        length, key_type = struct.unpack_from('<HB', data, key)
        if key_type == ITEM_DATA and data[value + 2] == ITEM_DATA:
            yield key, bytes(data[key + 3:key + 3 + length])


def clear_free_space(data, ps):
    """Zero the free space of every leaf page.

    BDB leaves old index entries and items there, e.g. of records that a page
    split moved to another page, and salvage in aggressive mode reads them as
    records."""
    for p in leaf_pages(data, ps):
        entries, hoffset = entries_and_hoffset(data, ps, p)
        start = p * ps + PAGE_HEADER_SIZE + 2 * entries
        data[start:p * ps + hoffset] = bytes(p * ps + hoffset - start)


def corrupt_tx_record(data, ps, txid):
    """Change the last byte of the key of txid's "tx" record (the end of the
    txid), so that the record no longer loads: a non-critical error."""
    record_key = b'\x02tx' + bytes.fromhex(txid)[::-1]
    for p in leaf_pages(data, ps):
        for key, key_bytes in leaf_records(data, ps, p):
            if key_bytes == record_key:
                data[key + 3 + len(record_key) - 1] ^= 0xff
                return
    raise AssertionError("no tx record for %s" % txid)


def add_stale_key_copy(data, ps):
    """Copy the key item of a "key" record into the free space of a leaf page
    before the record's page, behind an index entry past the page's entries
    with no data item after it, as a page split can leave it. Salvage reads
    the pages in order, so it finds the copy before the record."""
    pages = leaf_pages(data, ps)
    record_page, key = next((p, k) for p in reversed(pages) for k, b in leaf_records(data, ps, p)
                            if b.startswith(b'\x03key'))
    item = bytes(data[key:key + 3 + struct.unpack_from('<H', data, key)[0]])
    for p in pages[:pages.index(record_page)]:
        if p == 1:
            continue  # the master database's page, which the steps damage
        entries, hoffset = entries_and_hoffset(data, ps, p)
        index_end = PAGE_HEADER_SIZE + 2 * (entries + 2)
        offset = (hoffset - len(item)) & ~3  # items are 4-byte aligned
        if offset >= index_end:  # room for the copy
            data[p * ps + offset:p * ps + offset + len(item)] = item
            # The copy's index entry, and a zero one where its data item would be.
            struct.pack_into('<HH', data, p * ps + index_end - 4, offset, 0)
            return
    raise AssertionError("no room for the copy")


def no_core_dump():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class WalletStartupOptionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[], ['-usehd=0']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def wallet_path(self, *name):
        return os.path.join(self.nodes[0].datadir, *name)

    def write_wallet(self, data):
        with open(self.wallet_path('wallet.dat'), 'wb') as f:
            f.write(data)

    def tick(self):
        # Every renamed file gets a fresh <name>.<mocktime>.bak name.
        self.set_mocktime(self.mocktime + 10)
        return self.mocktime

    def state(self, node):
        return (node.getbalance(), {t: node.gettransaction(t)['confirmations'] for t in self.txids},
                [node.dumpprivkey(a)['private_key'] for a in self.addrs])

    def run_test(self):
        n0, n1 = self.nodes
        self.set_mocktime(int(time.time()))

        self.log.info("-upgradewallet on an HD wallet")
        assert_equal(n0.getwalletinfo()['walletversion'], HD_VERSION)
        self.stop_node(0)
        for v in (1, NON_HD_VERSION, HD_VERSION - 1):
            n0.assert_start_raises_init_error(['-upgradewallet=%d' % v], "Error: Cannot downgrade wallet")
        for args in (['-upgradewallet'], ['-upgradewallet=%d' % HD_VERSION]):
            self.start_node(0, args)
            info = n0.getwalletinfo()
            assert_equal((info['walletversion'], info['keypoolsize_hd_internal']), (HD_VERSION, 100))
            self.stop_node(0)

        self.log.info("-upgradewallet on a non-HD wallet keeps it non-HD")
        self.stop_node(1)
        n1.assert_start_raises_init_error(['-usehd=0', '-upgradewallet=%d' % (NON_HD_VERSION - 1)], "Error: Cannot downgrade wallet")
        self.start_node(1, ['-usehd=0', '-upgradewallet'])
        info = n1.getwalletinfo()
        assert_equal(info['walletversion'], NON_HD_VERSION)
        assert 'hdmasterkeyid' not in info

        self.log.info("-salvagewallet on a healthy wallet")
        self.start_node(0)
        self.addrs = [n0.getnewaddress('label%d' % i) for i in range(3)]
        self_payment = n0.sendtoaddress(address=self.addrs[0], amount=3)
        n0.generate(1)
        self.txids = set(t['txid'] for t in n0.listtransactions('*', 1000))
        old_paths = [int(re.match(r"m/0'/0'/(\d+)'", n0.validateaddress(a)['hdkeypath']).group(1)) for a in self.addrs]
        before = self.state(n0)
        self.stop_node(0)
        # Salvage also reads the pages' free space (see clear_free_space).
        with open(self.wallet_path('wallet.dat'), 'rb') as f:
            wallet = bytearray(f.read())
        clear_free_space(wallet, page_size(wallet))
        self.write_wallet(bytes(wallet))
        t = self.tick()
        with n0.assert_debug_log(['parameter interaction: -salvagewallet=1 -> setting -rescan=1',
                                  'Renamed wallet.dat to wallet.dat.%d.bak' % t,
                                  'Rescanning last']):
            self.start_node(0, ['-salvagewallet'])
        assert os.path.isfile(self.wallet_path('wallet.dat.%d.bak' % t))
        assert_equal(self.state(n0), before)
        # Only keys are kept: labels and key metadata are gone.
        assert_equal([n0.getaccount(a) for a in self.addrs], ['', '', ''])
        assert 'hdkeypath' not in n0.validateaddress(self.addrs[1])
        # Pins today's behaviour: without its label the self-payment's output
        # counts as change, so listtransactions no longer shows it.
        assert self_payment not in [t['txid'] for t in n0.listtransactions('*', 1000)]
        # The HD counter survives, so no key is handed out twice.
        new_path = n0.validateaddress(n0.getnewaddress())['hdkeypath']
        assert int(re.match(r"m/0'/0'/(\d+)'", new_path).group(1)) > max(old_paths)
        self.restart_node(0)

        def hd_split_kept():
            info = n0.getwalletinfo()
            assert_equal(info['walletversion'], HD_VERSION)
            assert n0.validateaddress(n0.getrawchangeaddress())['hdkeypath'].startswith("m/0'/1'/")
        self.known_failure("salvage drops the HD chain split (YslI5Qz7 item 3)", hd_split_kept,
                           expected="not(%d == %d)" % (NON_HD_VERSION, HD_VERSION))
        healthy_txcount = n0.getwalletinfo()['txcount']
        self.stop_node(0)

        with open(self.wallet_path('wallet.dat'), 'rb') as f:
            healthy = f.read()
        ps = page_size(healthy)
        # Page 1 is the master database's leaf, page 2 the meta page of "main".
        assert_equal((healthy[ps + 25], healthy[2 * ps + 25]), (PAGE_TYPE_LEAF, PAGE_TYPE_META))

        def salvage_warning(t):
            return ('Warning: Warning: Wallet file corrupt, data salvaged! Original wallet.dat saved as '
                    'wallet.dat.%d.bak in "%s"; if your balance or transactions are incorrect you should '
                    'restore from a backup.') % (t, n0.datadir)

        def damage_page_1(data):
            for k in range(ps + 8, ps + 12):  # page 1's page number
                data[k] ^= 0xff

        self.log.info("A wallet.dat with a damaged page is salvaged at startup")
        damaged = bytearray(healthy)
        clear_free_space(damaged, ps)
        # The self-payment's record doesn't load: the second warning. Its
        # block is newer than the wallet's keys, so the rescan finds it again.
        corrupt_tx_record(damaged, ps, self_payment)
        damage_page_1(damaged)
        self.write_wallet(bytes(damaged))
        t = self.tick()
        self.start_node(0)
        assert os.path.isfile(self.wallet_path('wallet.dat.%d.bak' % t))
        assert_equal(self.state(n0), before)
        # InitWarning adds a second "Warning: " (as for -paytxfee).
        self.stop_node(0, expected_stderr=salvage_warning(t) + (
            '\nWarning: Error reading wallet.dat! All keys read correctly, but transaction data or '
            'address book entries might be missing or incorrect.'))

        self.log.info("A stale copy of a key record's key in an earlier page: the salvaged wallet loads")
        damaged = bytearray(healthy)
        clear_free_space(damaged, ps)
        add_stale_key_copy(damaged, ps)
        damage_page_1(damaged)
        self.write_wallet(bytes(damaged))
        t = self.tick()

        def salvaged_wallet_loaded():
            # Fixed, the record wins over the copy and the wallet loads.
            n0.start([])
            try:
                n0.wait_for_rpc_connection()
            except FailedToStartError:
                code = n0.wait_for_exit()
                raise AssertionError("exit code %d, stderr:\n%s" % (code, n0.read_stderr().strip()))
            assert_equal(self.state(n0), before)
            self.stop_node(0, expected_stderr=salvage_warning(t))
        # Salvage keeps the first copy of each key it reads, the stale one.
        self.known_failure("MG-007", salvaged_wallet_loaded,
                           expected="exit code 1, stderr:\n%s\nError: Error loading wallet.dat: Wallet corrupted"
                           % salvage_warning(t))

        self.log.info("A wallet.dat that is not a database: salvage fails and the file stays")
        junk = bytes(range(256)) * 16
        self.write_wallet(junk)
        t = self.tick()
        n0.assert_start_raises_init_error([], "Error: wallet.dat corrupt, salvage failed")
        assert not os.path.exists(self.wallet_path('wallet.dat.%d.bak' % t))
        with open(self.wallet_path('wallet.dat'), 'rb') as f:
            assert_equal(f.read(), junk)
        self.known_failure("silent -salvagewallet failure (YslI5Qz7 item 4)",
                           lambda: n0.assert_start_raises_init_error(['-salvagewallet'], r'\S', match=ErrorMatch.PARTIAL_REGEX),
                           expected='does not partially match stderr:\n""')

        self.log.info("A failed salvage moves wallet.dat away, also when it is restored afterwards")
        damaged = bytearray(healthy)
        damaged[2 * ps + 25] ^= 0xff  # page 2's page type
        self.write_wallet(bytes(damaged))
        t = self.tick()
        n0.assert_start_raises_init_error([], "Error: wallet.dat corrupt, salvage failed")
        assert os.path.isfile(self.wallet_path('wallet.dat.%d.bak' % t))
        assert not os.path.exists(self.wallet_path('wallet.dat'))
        # The user restores the healthy file.
        self.write_wallet(healthy)
        self.start_node(0)

        def restored_wallet_loaded():
            assert_equal(n0.getwalletinfo()['txcount'], healthy_txcount)
        self.known_failure("restored wallet.dat moved aside (YslI5Qz7 item 2)", restored_wallet_loaded,
                           expected="not(0 == %d)" % healthy_txcount)
        assert os.path.isfile(self.wallet_path('wallet.dat.%d.bak' % t))
        assert_raises_rpc_error(-4, "Wallet doesn't manage coins in this address", n0.dumpprivkey, self.addrs[0])
        self.stop_node(0)

        self.log.info("A regular file in place of the database directory")
        self.write_wallet(healthy)
        # A clean shutdown removes the database directory.
        assert not os.path.exists(self.wallet_path('database'))
        with open(self.wallet_path('database'), 'wb') as f:
            f.write(junk)

        def no_raw_exception():
            # Fixed, the start either fails with an init error or moves the
            # file aside and starts.
            n0.start([])
            try:
                n0.wait_for_rpc_connection()
            except FailedToStartError:
                n0.wait_for_exit()
                stderr = n0.read_stderr()
                assert 'EXCEPTION' not in stderr and stderr.startswith('Error: '), stderr
            else:
                self.stop_node(0)
        self.known_failure("raw exception for a database file (YslI5Qz7 item 5)", no_raw_exception,
                           expected='EXCEPTION: N5boost10filesystem16filesystem_errorE')
        os.remove(self.wallet_path('database'))

        self.log.info("A damaged database environment is moved aside")
        os.makedirs(self.wallet_path('database'))
        # Any non-zero log content; BDB accepts an all-zero log as empty.
        with open(self.wallet_path('database', 'log.0000000001'), 'wb') as f:
            f.write(junk)
        t = self.tick()

        def env_retry():
            n0.start([], preexec_fn=no_core_dump)
            try:
                n0.wait_for_rpc_connection()
            except FailedToStartError:
                raise AssertionError("exit code %s" % describe_exit_code(n0.wait_for_exit()))
        # CDBEnv::Open closes the DbEnv on failure, and the retry reuses it.
        self.known_failure("segfault on damaged db log (YslI5Qz7 item 1)", env_retry,
                           expected="exit code -11 (SIGSEGV)")
        assert os.path.isdir(self.wallet_path('database.%d.bak' % t))

        self.log.info("-blocksonly turns wallet broadcasting off")
        with n0.assert_debug_log(['parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0']):
            self.start_node(0, ['-blocksonly'])
        assert_equal(self.state(n0), before)
        txid = n0.sendtoaddress(address=n0.getnewaddress(), amount=1)
        assert_equal(n0.getrawmempool(), [])
        assert_equal(n0.gettransaction(txid)['confirmations'], 0)
        assert_raises_rpc_error(-4, "Error: Wallet transaction broadcasting is disabled with -walletbroadcast", n0.resendwallettransactions)
        self.stop_node(0)
        # txid2 is received later, so it is listed second.
        self.tick()
        self.start_node(0, ['-blocksonly', '-walletbroadcast=1'])
        assert_equal(n0.getrawmempool(), [txid])
        txid2 = n0.sendtoaddress(address=n0.getnewaddress(), amount=1)
        assert_equal(sorted(n0.getrawmempool()), sorted([txid, txid2]))
        assert_equal(n0.resendwallettransactions(), [txid, txid2])


if __name__ == '__main__':
    WalletStartupOptionsTest().main()
