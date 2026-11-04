#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool persistence.

By default, bitcoind will dump mempool on shutdown and
then reload it on startup. This can be overridden with
the -persistmempool=0 command line option.

Test is as follows:

  - start node0, node1 and node2. node1 has -persistmempool=0
  - create 5 transactions on node2 to its own address. Note that these
    are not sent to node0 or node1 addresses because we don't want
    them to be saved in the wallet.
  - check that node0 and node1 have 5 transactions in their mempools
  - shutdown all nodes.
  - startup node0. Verify that it still has 5 transactions
    in its mempool. Shutdown node0. This tests that by default the
    mempool is persistent.
  - startup node1. Verify that its mempool is empty. Shutdown node1.
    This tests that with -persistmempool=0, the mempool is not
    dumped to disk when the node is shut down.
  - Restart node0 with -persistmempool=0. Verify that its mempool is
    empty. Shutdown node0. This tests that with -persistmempool=0,
    the mempool is not loaded from disk on start up.
  - Restart node0 with -persistmempool. Verify that it has 5
    transactions in its mempool. This tests that -persistmempool=0
    does not overwrite a previously valid mempool stored on disk.
  - (Linux only) Start node2 and send node0 a large transaction from it.
    Stop node0 with mempool.dat.new a symbolic link to /dev/full.
    Verify that the dump fails, that mempool.dat is unchanged and that
    node0 loads the 5 transactions of the earlier dump on its next start.

"""
import os
import sys
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class MempoolPersistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [[], ["-persistmempool=0"], []]

    def run_test(self):
        chain_height = self.nodes[0].getblockcount()
        assert_equal(chain_height, 41)

        self.log.debug("Mine a single block to get out of IBD")
        self.nodes[0].generate(1)
        self.sync_all()

        self.log.debug("Send 5 transactions from node2 (to its own address)")
        for i in range(5):
            self.nodes[2].sendtoaddress(self.nodes[2].getnewaddress(), Decimal("10"))
        self.sync_all()

        self.log.debug("Verify that node0 and node1 have 5 transactions in their mempools")
        assert_equal(len(self.nodes[0].getrawmempool()), 5)
        assert_equal(len(self.nodes[1].getrawmempool()), 5)

        self.log.debug("Stop-start node0 and node1. Verify that node0 has the transactions in its mempool and node1 does not.")
        self.stop_nodes()
        self.start_node(0)
        self.start_node(1)
        # Give bitcoind a second to reload the mempool
        time.sleep(1)
        wait_until(lambda: len(self.nodes[0].getrawmempool()) == 5)
        assert_equal(len(self.nodes[1].getrawmempool()), 0)

        self.log.debug("Stop-start node0 with -persistmempool=0. Verify that it doesn't load its mempool.dat file.")
        self.stop_nodes()
        self.start_node(0, extra_args=["-persistmempool=0"])
        # Give bitcoind a second to reload the mempool
        time.sleep(1)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)

        self.log.debug("Stop-start node0. Verify that it has the transactions in its mempool.")
        self.stop_nodes()
        self.start_node(0)
        wait_until(lambda: len(self.nodes[0].getrawmempool()) == 5)

        if sys.platform.startswith('linux') and os.path.exists('/dev/full'):
            self.test_dump_failure()
        else:
            self.log.info("Skipping the failed dump: it needs /dev/full (Linux)")

    def test_dump_failure(self):
        self.log.debug("Send node0 a transaction larger than the stdio buffer from node2")
        earlier = set(self.nodes[0].getrawmempool())
        self.start_node(2)
        connect_nodes(self.nodes[0], 2)
        utxo = max(self.nodes[2].listunspent(0), key=lambda u: u['amount'])
        assert utxo['amount'] > 4
        outputs = {self.nodes[2].getnewaddress(): Decimal("0.01") for _ in range(300)}
        outputs[self.nodes[2].getnewaddress()] = utxo['amount'] - Decimal("4")
        raw = self.nodes[2].createrawtransaction([{"txid": utxo['txid'], "vout": utxo['vout']}], outputs)
        large = self.nodes[2].sendrawtransaction(self.nodes[2].signrawtransaction(raw)['hex'])
        sync_mempools([self.nodes[0], self.nodes[2]])
        assert large in self.nodes[0].getrawmempool()

        self.log.debug("Stop node0 with mempool.dat.new pointing at a full device. Verify that the dump fails and mempool.dat keeps the earlier dump.")
        mempool_dat = os.path.join(self.nodes[0].datadir, 'mempool.dat')
        with open(mempool_dat, 'rb') as f:
            earlier_dump = f.read()
        os.symlink('/dev/full', mempool_dat + '.new')
        with self.nodes[0].assert_debug_log(["Failed to dump mempool: "]):
            self.stop_node(0)
        assert os.path.islink(mempool_dat + '.new')
        with open(mempool_dat, 'rb') as f:
            assert_equal(f.read(), earlier_dump)

        self.log.debug("Start node0 again. Verify that it loads the earlier dump.")
        os.remove(mempool_dat + '.new')
        self.start_node(0)
        wait_until(lambda: set(self.nodes[0].getrawmempool()) == earlier)

if __name__ == '__main__':
    MempoolPersistTest().main()
