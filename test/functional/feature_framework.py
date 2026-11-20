#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Self-checks of the YACoin parts of the test framework.

Later tests rely on these helpers, so check them against a real node, here on
regtest:
- the chain choice: a script without a chain line runs on regtest; regtest=1
  in yacoin.conf (main gets no chain line), the nodes report chain regtest
  and keep their files in <datadir>/regtest (TestNode.chain_path); a main
  node (main_test_node) runs main in the data directory itself.
- the maxtipage line in a regtest node's yacoin.conf (none on main).
- test nodes connect only to the nodes of their test: connect=0 and listen=1
  in yacoin.conf, no automatic outbound connections; a node started with its
  own -connect gets only that value.
- the fork and token heights through -testactivationheight, with a script's
  own tokens@<height> after the framework's; a fork above 1 moves the
  Heliopolis height to the fork height.
- the RPC cookie and debug.log in the chain's directory: cookie
  authentication, assert_debug_log and combine_logs.py (also on a main
  layout).
- node exit codes and the signal helpers (TestNode.wait_until_stopped,
  send_signal, wait_for_exit).
- stop_node goes on when the reply to stop is lost and the node exits, and
  the wait after it still fails when the node keeps running.
- connect_nodes returns only when both sides finished the handshake, and
  peers() drops YACoin's extra getpeerinfo element.
- CTransaction computes the node's txids (scriptSigs ignored from version 2
  on, except for coinbases) and CBlock the merkle root.
- mininode connections announce the node's height and can use another
  loopback source address.
- set_mocktime / mine_with_mocktime keep one forward-only clock on all
  nodes, also across restarts.
- raw_rpc, rpcauth_value, the wallet fee rule and single_utxo_wallet.
- known_failure passes while its check fails and fails once it passes.
- the RPC client resends a request without a trace only when it cannot have
  reached the node, and with a warning when its reply was lost.
- start_nodes, when one node fails to start, stops the nodes it connected
  to by the stop RPC and the others by SIGTERM, and raises the start error;
  wait_for_exit_or_kill kills a node that does not exit in time.
"""

from decimal import Decimal
import http.client
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse

from test_framework.authproxy import JSONRPCException
from test_framework.messages import COIN, CBlock, CTransaction, FromHex, TX_VERSION
from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import FailedToStartError, TestNode
from test_framework.util import (
    CONNECT_LINE,
    REGTEST_MAX_TIP_AGE,
    REGTEST_TOKEN_HEIGHT,
    assert_equal,
    assert_raises,
    assert_raises_rpc_error,
    connect_nodes,
    get_auth_cookie,
    initialize_datadir,
    non_loopback_ipv4,
    p2p_port,
    peers,
    raw_rpc,
    rpcauth_value,
)
from test_framework.wallet_util import assert_yac_fee, expected_fee


class DroppedReplyConnection(http.client.HTTPConnection):
    """An RPC connection that sends each request in full and then closes
    without reading the reply: what the client sees when the node shuts down
    before it writes the reply to stop."""

    def getresponse(self):
        self.close()
        raise http.client.RemoteDisconnected("reply dropped by the test")


def drop_rpc_replies(node, host, port):
    """Send node's RPC calls to host:port and drop their replies."""
    node.rpc.auth_service_proxy_instance._set_conn(DroppedReplyConnection(host, port, timeout=node.rpc_timeout))


class CountingConnection(http.client.HTTPConnection):
    """An RPC connection that counts the requests it sends and the times it
    opens its socket."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requests = 0
        self.connects = 0

    def connect(self):
        self.connects += 1
        super().connect()

    def request(self, *args, **kwargs):
        self.requests += 1
        super().request(*args, **kwargs)


class LostReplyConnection(CountingConnection):
    """Sends the request in full and lets the node reply, then drops the
    first reply and raises error, as when the connection breaks after the
    node received the request."""

    def __init__(self, *args, error, **kwargs):
        super().__init__(*args, **kwargs)
        self.error = error

    def getresponse(self):
        response = super().getresponse()
        if self.error is None:
            return response
        # Read the whole reply first, so the node has finished the call.
        response.read()
        self.close()
        error, self.error = self.error, None
        raise error


class FailedSendConnection(CountingConnection):
    """The first request fails before anything is written to the socket."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fail = True

    def request(self, *args, **kwargs):
        if self.fail:
            self.requests += 1
            self.fail = False
            raise BrokenPipeError("send failed in the test")
        super().request(*args, **kwargs)


class CountingDroppedReplyConnection(CountingConnection, DroppedReplyConnection):
    """DroppedReplyConnection with counters: every reply is lost."""


class CaptureWarnings(logging.Handler):
    """Collects the warnings of the RPC client's logger."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())

    def __enter__(self):
        logging.getLogger("TestFramework.authproxy").addHandler(self)
        return self

    def __exit__(self, *exc):
        logging.getLogger("TestFramework.authproxy").removeHandler(self)


class CaptureDebug(logging.Handler):
    """Collects the messages of the framework's util logger, debug level
    included."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())

    def __enter__(self):
        logging.getLogger("TestFramework.utils").addHandler(self)
        return self

    def __exit__(self, *exc):
        logging.getLogger("TestFramework.utils").removeHandler(self)


def read_lines(path):
    with open(path, encoding='utf8') as f:
        return f.read().splitlines()


class FrameworkTest(BitcoinTestFramework):
    def set_test_params(self):
        # No chain line: the nodes run regtest.
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Set the clock before the nodes exist: they must start on it.
        self.set_mocktime(int(time.time()))
        self.start_mocktime = self.mocktime
        # The connection checks connect the nodes themselves.
        self.setup_nodes()

    def run_test(self):
        self.test_mocktime_at_start()
        self.test_regtest_chain()
        self.test_main_node()
        self.test_tip_age()
        self.test_no_automatic_connections()
        self.test_conf_lines()
        self.test_activation_heights()
        self.test_cookie()
        self.test_debug_log()
        self.test_exit_codes()
        self.test_lost_stop_reply()
        self.test_connect_nodes()
        self.test_txid()
        self.test_mininode_options()
        self.test_mocktime()
        self.test_raw_rpc()
        self.test_wallet_helpers()
        self.test_known_failure()
        self.test_rpc_resend()
        self.test_start_nodes_failure()
        self.test_combine_logs()
        self.test_token_height_override()

    def test_mocktime_at_start(self):
        self.log.info("Nodes added after set_mocktime start on the test's clock")
        for node in self.nodes:
            assert "-mocktime=%d" % self.start_mocktime in node.process.args
        block = self.nodes[0].getblockheader(self.nodes[0].generate(1)[0])
        assert_equal(block['time'], self.start_mocktime)

    def test_regtest_chain(self):
        self.log.info("A script without a chain line runs on regtest")
        assert_equal(self.chain, 'regtest')
        self.log.info("The nodes run regtest: regtest=1 in yacoin.conf, the chain's files in <datadir>/regtest")
        for node in self.nodes:
            lines = read_lines(os.path.join(node.datadir, 'yacoin.conf'))
            assert_equal(lines[0], 'regtest=1')
            assert not [line for line in lines if line.startswith('[')], lines
            assert_equal(node.gettimechaininfo()['chain'], 'regtest')
            assert os.path.isfile(os.path.join(node.datadir, 'regtest', 'debug.log'))
            assert os.path.isdir(os.path.join(node.datadir, 'regtest', 'blocks'))
            assert not os.path.exists(os.path.join(node.datadir, 'blocks'))
            assert_equal(node.chain_path('blocks'), os.path.join(node.datadir, 'regtest', 'blocks'))

    def test_conf_lines(self):
        self.log.info("initialize_datadir writes regtest=1 and maxtipage for regtest, neither for main")
        main_conf = read_lines(os.path.join(initialize_datadir(os.path.join(self.options.tmpdir, 'conf_main'), 0, 'main'), 'yacoin.conf'))
        regtest_conf = read_lines(os.path.join(initialize_datadir(os.path.join(self.options.tmpdir, 'conf_regtest'), 0, 'regtest'), 'yacoin.conf'))
        tip_age_line = 'maxtipage=%d' % REGTEST_MAX_TIP_AGE
        assert tip_age_line in regtest_conf, regtest_conf
        assert_equal(regtest_conf, ['regtest=1'] + main_conf[:main_conf.index('listen=1') + 1] + [tip_age_line] +
                     main_conf[main_conf.index('listen=1') + 1:])

    def test_main_node(self):
        self.log.info("An explicit main node runs main, in the data directory itself")
        node = self.main_test_node(2)
        assert_equal(node.chain_path('blocks'), os.path.join(node.datadir, 'blocks'))
        node.start()
        node.wait_for_rpc_connection()
        assert_equal(node.gettimechaininfo()['chain'], 'main')
        node.stop_node()
        node.wait_until_stopped()
        assert os.path.isfile(os.path.join(node.datadir, 'debug.log'))
        assert os.path.isdir(os.path.join(node.datadir, 'blocks'))
        assert not os.path.exists(os.path.join(node.datadir, 'regtest'))

    def test_tip_age(self):
        node = self.nodes[1]
        conf = os.path.join(node.datadir, 'yacoin.conf')
        self.log.info("A regtest node's yacoin.conf has the maxtipage line, a main node's none")
        assert 'maxtipage=%d' % REGTEST_MAX_TIP_AGE in read_lines(conf)
        main_conf = os.path.join(self.main_test_node(2).datadir, 'yacoin.conf')
        assert not [line for line in read_lines(main_conf) if line.startswith('maxtipage=')]

    def test_no_automatic_connections(self):
        node0, node1 = self.nodes
        conf = os.path.join(node1.datadir, 'yacoin.conf')
        self.log.info("A lone node makes no automatic connections")
        # connect=0: the node starts no automatic connection thread (opencon).
        with node1.assert_debug_log(["addcon thread start"], unexpected_msgs=["opencon thread start"]):
            self.restart_node(1)
        assert_equal(peers(node1), [])

        self.log.info("yacoin.conf has connect=0 and listen=1")
        for node in self.nodes:
            lines = read_lines(os.path.join(node.datadir, 'yacoin.conf'))
            assert CONNECT_LINE in lines and 'listen=1' in lines, lines

        self.log.info("A node started with its own -connect gets only that value")
        # A port nothing listens on (node 2's), so the node stays at genesis.
        target = "127.0.0.1:%d" % p2p_port(2)
        with node1.assert_debug_log(["opencon thread start", "trying connection %s lastseen" % target],
                                    unexpected_msgs=["trying connection 0 lastseen"], timeout=10):
            self.restart_node(1, ["-connect=%s" % target])
        assert CONNECT_LINE not in read_lines(conf)

        self.log.info("Without its own -connect the line is back")
        self.restart_node(1)
        assert CONNECT_LINE in read_lines(conf)
        assert_equal(peers(node0), [])
        assert_equal(peers(node1), [])

    def test_activation_heights(self):
        self.log.info("Regtest nodes get the fork and token heights through -testactivationheight")
        for node in self.nodes:
            args = node.process.args
            assert "-testactivationheight=newlogic@%d" % self.block_fork_1_0 in args, args
            assert "-testactivationheight=tokens@%d" % REGTEST_TOKEN_HEIGHT in args, args
            assert not [arg for arg in args if arg.startswith(("-testnetNewLogicBlockNumber", "-tokenSupportBlockNumber"))], args

        self.log.info("A main node gets the fork height through -testnetNewLogicBlockNumber")
        main_node = self.main_test_node()
        assert "-testnetNewLogicBlockNumber=%d" % self.block_fork_1_0 in main_node.args, main_node.args
        assert not [arg for arg in main_node.args if arg.startswith("-testactivationheight")], main_node.args

        self.log.info("A fork above 1 moves the Heliopolis height to the fork height on regtest")
        for fork, heliopolis in ((0, []), (1, []), (2, ["-testactivationheight=heliopolis@2"]),
                                 (30, ["-testactivationheight=heliopolis@30"])):
            node = self.test_node_with_fork('regtest', fork)
            assert_equal([arg for arg in node.args if arg.startswith("-testactivationheight=heliopolis")], heliopolis)
        node = self.test_node_with_fork('main', 30)
        assert not [arg for arg in node.args if arg.startswith("-testactivationheight")], node.args

    def test_node_with_fork(self, chain, fork):
        """A TestNode with the given fork height; not started."""
        return TestNode(0, os.path.join(self.options.tmpdir, 'fork_%s_%d' % (chain, fork)), chain=chain, rpchost=None,
                        timewait=self.rpc_timeout, bitcoind=self.options.bitcoind,
                        bitcoin_cli=self.options.bitcoincli, coverage_dir=None, cwd=self.options.tmpdir,
                        block_fork_1_0=fork)

    def test_cookie(self):
        node = self.nodes[1]
        conf = os.path.join(node.datadir, 'yacoin.conf')
        cookie = os.path.join(node.datadir, 'regtest', '.cookie')
        self.log.info("A regtest node without the rpcuser and rpcpassword lines is reached through <datadir>/regtest/.cookie")
        height = node.getblockcount()
        self.stop_node(1)
        lines = read_lines(conf)
        credentials = [line for line in lines if line.startswith(('rpcuser=', 'rpcpassword='))]
        assert_equal(len(credentials), 2)
        with open(conf, 'w', encoding='utf8') as f:
            f.write("".join(line + "\n" for line in lines if line not in credentials))

        self.log.info("A leftover cookie file is deleted before the start")
        with open(cookie, 'w', encoding='ascii') as f:
            f.write("leftover:cookie")
        with CaptureDebug() as log:
            node.start()
        assert_equal(log.messages, ["Deleting leftover cookie file"])
        node.wait_for_rpc_connection()
        assert_equal(node.getblockcount(), height)
        with open(cookie, encoding='ascii') as f:
            assert_equal(":".join(get_auth_cookie(node.datadir, 'regtest')), f.read())
        assert_equal(raw_rpc(node, {"method": "getblockcount"})[0], 200)
        self.stop_node(1)
        with open(conf, 'w', encoding='utf8') as f:
            f.write("".join(line + "\n" for line in lines))
        self.start_node(1)

        self.log.info("get_auth_cookie reads <datadir>/.cookie on main")
        main_dir = os.path.join(self.options.tmpdir, 'cookie_main')
        os.makedirs(main_dir)
        with open(os.path.join(main_dir, '.cookie'), 'w', encoding='ascii') as f:
            f.write("testuser:testpass")
        assert_equal(get_auth_cookie(main_dir, 'main'), ('testuser', 'testpass'))

        self.log.info("Without credentials in yacoin.conf or a cookie, get_auth_cookie raises")
        empty_dir = os.path.join(self.options.tmpdir, 'no_credentials')
        os.makedirs(empty_dir)
        # The main cookie is not regtest's.
        for datadir, chain in ((empty_dir, 'main'), (empty_dir, 'regtest'), (main_dir, 'regtest')):
            try:
                get_auth_cookie(datadir, chain)
            except ValueError as e:
                assert_equal(str(e), "No RPC credentials")
            else:
                raise AssertionError("get_auth_cookie found credentials in %s for %s" % (datadir, chain))

    def test_debug_log(self):
        node = self.nodes[1]
        self.log.info("debug_log_path is the chain's debug.log")
        assert_equal(node.debug_log_path, os.path.join(node.datadir, 'regtest', 'debug.log'))
        main_node = self.main_test_node()
        assert_equal(main_node.debug_log_path, os.path.join(main_node.datadir, 'debug.log'))

        self.log.info("assert_debug_log finds a line the node writes to regtest's debug.log")
        with node.assert_debug_log(["Done loading"]):
            self.restart_node(1)

        self.log.info("assert_debug_log fails for a line the node does not write")
        try:
            with node.assert_debug_log(["no such line in the log"], timeout=0.2):
                node.getblockcount()
        except AssertionError as e:
            assert "does not partially match log" in str(e), str(e)
        else:
            raise AssertionError("assert_debug_log passed for a line the node did not write")

    def test_exit_codes(self):
        node = self.nodes[1]

        self.log.info("SIGTERM shuts the node down cleanly (exit code 0)")
        node.send_signal(signal.SIGTERM)
        assert_equal(node.wait_for_exit(), 0)
        assert_equal(node.read_stderr(), "")
        assert not node.running
        self.start_node(1)

        self.log.info("wait_until_stopped accepts the expected exit code")
        node.send_signal(signal.SIGKILL)
        node.wait_until_stopped(expected_ret_code=-signal.SIGKILL)
        self.start_node(1)

        self.log.info("wait_until_stopped fails on an unexpected exit code, and the node can be restarted")
        node.send_signal(signal.SIGKILL)
        try:
            node.wait_until_stopped()
        except AssertionError as e:
            assert "Node returned exit code -9 (SIGKILL), expected 0" in str(e), str(e)
        else:
            raise AssertionError("wait_until_stopped did not fail on exit code -9")
        assert not node.running
        self.start_node(1)
        assert_equal(node.getblockcount(), 0)

    def test_lost_stop_reply(self):
        node = self.nodes[1]

        self.log.info("stop_node goes on when the reply to stop is lost and the node exits")
        url = urllib.parse.urlparse(node.url)
        drop_rpc_replies(node, url.hostname, url.port)
        self.stop_node(1)
        assert not node.running
        self.start_node(1)
        assert_equal(node.getblockcount(), 0)

        self.log.info("A stop that is lost while the node keeps running still fails the wait")
        # A listener that never accepts: the request ends in its backlog and
        # never reaches the node.
        nowhere = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            nowhere.bind(("127.0.0.1", 0))
            nowhere.listen(8)
            drop_rpc_replies(node, *nowhere.getsockname())
            node.stop_node()
            self.log.info("Expected: the next wait times out, and wait_until() logs its failure as an ERROR")
            try:
                node.wait_until_stopped(timeout=3)
            except AssertionError as e:
                assert "not true after 3 seconds" in str(e), str(e)
            else:
                raise AssertionError("wait_until_stopped returned for a node that is still running")
        finally:
            nowhere.close()
        assert node.process.poll() is None
        node.process.kill()
        node.wait_for_exit()
        self.start_node(1)
        assert_equal(node.getblockcount(), 0)

    def test_connect_nodes(self):
        self.log.info("peers() drops the extra getpeerinfo element")
        assert_equal(len(self.nodes[0].getpeerinfo()), 1)
        assert_equal(peers(self.nodes[0]), [])

        self.log.info("connect_nodes returns when both sides finished the handshake")
        connect_nodes(self.nodes[0], 1)
        # No waiting here: both sides must already agree.
        outbound = peers(self.nodes[0])
        inbound = peers(self.nodes[1])
        assert_equal(len(outbound), 1)
        assert_equal(len(inbound), 1)
        assert_equal(outbound[0]['addr'], "127.0.0.1:%d" % p2p_port(1))
        assert not outbound[0]['inbound']
        assert inbound[0]['inbound']
        assert outbound[0]['version'] != 0 and inbound[0]['version'] != 0
        assert 'verack' in inbound[0]['bytesrecv_per_msg']
        assert 'pong' in outbound[0]['bytesrecv_per_msg']

    def check_txid(self, txid):
        raw = self.nodes[0].getrawtransaction(txid)
        tx = FromHex(CTransaction(), raw)
        assert_equal(tx.serialize().hex(), raw)
        assert_equal(tx.rehash(), txid)
        return tx

    def test_txid(self):
        node = self.nodes[0]
        node.generate(12)
        self.sync_blocks()

        self.log.info("Coinbase txid: full serialization")
        coinbase = self.check_txid(node.getblock(node.getbestblockhash())['tx'][0])
        assert coinbase.is_coinbase()
        assert_equal(coinbase.nVersion, TX_VERSION)

        self.log.info("Wallet transaction txids: scriptSigs ignored")
        one_input = self.check_txid(node.sendtoaddress(address=node.getnewaddress(), amount=Decimal('1.5')))
        assert_equal(len(one_input.vin), 1)
        # COIN matches the node's unit.
        for n, txout in enumerate(node.getrawtransaction(one_input.hash, 1)['vout']):
            assert_equal(Decimal(one_input.vout[n].nValue) / COIN, txout['value'])
        self.fee_txids = [one_input.hash]
        many_inputs = self.check_txid(node.sendtoaddress(address=node.getnewaddress(), amount=node.getbalance() - 1))
        assert len(many_inputs.vin) > 1
        assert not many_inputs.is_coinbase()
        self.fee_txids.append(many_inputs.hash)

        self.log.info("Merkle root of a block with these transactions")
        block_hash = node.generate(1)[0]
        assert_equal(len(node.getblock(block_hash)['tx']), 3)
        block = FromHex(CBlock(), node.getblock(block_hash, False))
        assert_equal(block.calc_merkle_root(), int(node.getblock(block_hash)['merkleroot'], 16))

        self.log.info("Version 1 transaction: full serialization")
        v1 = CTransaction(one_input)
        v1.nVersion = 1
        v1.rehash()
        assert_equal(node.decoderawtransaction(v1.serialize().hex())['txid'], v1.hash)
        assert v1.hash != one_input.hash

        self.log.info("Signing doesn't change a version 2 txid")
        utxo = node.listunspent()[0]
        unsigned = node.createrawtransaction([{"txid": utxo['txid'], "vout": utxo['vout']}], {node.getnewaddress(): Decimal('0.5')})
        signed = node.signrawtransaction(unsigned)['hex']
        assert_equal(FromHex(CTransaction(), unsigned).rehash(), FromHex(CTransaction(), signed).rehash())
        assert_equal(FromHex(CTransaction(), signed).rehash(), node.decoderawtransaction(signed)['txid'])

    def test_mininode_options(self):
        node = self.nodes[0]
        self.log.info("A mininode announces the node's height")
        node.add_p2p_connection(P2PInterface())
        info = peers(node)[-1]
        assert_equal(info['subver'], "/python-mininode-tester:0.0.3/")
        assert_equal(info['startingheight'], node.getblockcount())

        # Only Linux routes all of 127.0.0.0/8 to the loopback interface.
        if sys.platform.startswith('linux'):
            self.log.info("local_addr gives a mininode its own source address")
            node.add_p2p_connection(P2PInterface(), local_addr=("127.0.0.2", 0))
            assert peers(node)[-1]['addr'].startswith("127.0.0.2:")
        node.disconnect_p2ps()

    def test_mocktime(self):
        node = self.nodes[0]
        self.log.info("mine_with_mocktime spaces blocks by the given time")
        height = node.getblockcount()
        hashes = self.mine_with_mocktime(node, 3, spacing=90)
        assert_equal(node.getblockcount(), height + 3)
        times = [node.getblockheader(h)['time'] for h in hashes]
        assert_equal([times[1] - times[0], times[2] - times[1]], [90, 90])
        assert_equal(times[2], self.mocktime)
        assert_equal(self.nodes[1].getbestblockhash(), hashes[-1])

        self.log.info("set_mocktime refuses to move the clock back")
        assert_raises(AssertionError, self.set_mocktime, self.mocktime - 1)

        self.log.info("A node stopped while the clock moves comes back with the current mocktime")
        self.stop_node(1)
        self.mine_with_mocktime(node, 2)
        self.start_node(1)
        connect_nodes(self.nodes[1], 0)
        self.sync_blocks()
        block = self.nodes[1].getblockheader(self.nodes[1].generate(1)[0])
        assert_equal(block['time'], self.mocktime)
        self.sync_blocks()

    def test_raw_rpc(self):
        node = self.nodes[0]
        self.log.info("raw_rpc returns status and body as sent by the node")
        status, headers, body = raw_rpc(node, {"method": "getblockcount", "params": [], "id": 1})
        assert_equal(status, 200)
        assert_equal(headers['Content-Type'], 'application/json')
        assert body.startswith(b'{"result":%d,' % node.getblockcount())
        assert_equal(raw_rpc(node, {"method": "getblockcount"}, auth=False)[0], 401)

        self.log.info("rpcauth_value gives a working -rpcauth entry")
        self.restart_node(1, extra_args=["-rpcauth=" + rpcauth_value("alice", "secret")])
        connect_nodes(self.nodes[1], 0)
        assert_equal(raw_rpc(self.nodes[1], {"method": "getblockcount"}, auth=("alice", "secret"))[0], 200)
        assert_equal(raw_rpc(self.nodes[1], {"method": "getblockcount"}, auth=("alice", "wrong"))[0], 401)

        # netutil reads the interfaces through a Linux-only ioctl.
        if sys.platform.startswith('linux'):
            address = non_loopback_ipv4()
            self.log.info("non_loopback_ipv4: %s", address)
            assert address is None or not address.startswith("127.")

    def test_wallet_helpers(self):
        self.log.info("expected_fee matches the wallet's fees, for a small and a large transaction")
        for txid in self.fee_txids:
            assert_yac_fee(self.nodes[0], txid)
        assert_equal(-self.nodes[0].gettransaction(self.fee_txids[0])['fee'], Decimal('0.01'))
        large_size = len(self.nodes[0].getrawtransaction(self.fee_txids[1])) // 2
        assert large_size > 1000
        assert expected_fee(large_size) > Decimal('0.01')

        self.log.info("single_utxo_wallet leaves exactly one UTXO")
        utxo = self.single_utxo_wallet(self.nodes[0], self.nodes[1], Decimal('2.5'))
        assert_equal(utxo['confirmations'], 1)

    def test_known_failure(self):
        node = self.nodes[0]
        out_of_range = lambda: node.getblockhash(100000)

        self.log.info("known_failure passes while the check fails with the expected symptom")
        self.known_failure("example bug", lambda: assert_equal(1, 2), "not(1 == 2)")
        self.known_failure("example bug", lambda: assert_equal(1, 2), re.compile(r"not\(1 == \d\)"))
        self.known_failure("example bug", out_of_range, "Block height out of range")
        self.known_failure("example bug", out_of_range, -8)

        self.log.info("known_failure fails once the check passes")
        try:
            self.known_failure("example bug", lambda: assert_equal(1, 1), "not(1 == 2)")
        except AssertionError as e:
            assert_equal(str(e), "example bug no longer fails; remove the known-failure marker")
        else:
            raise AssertionError("known_failure did not fail on a passing check")

        self.log.info("known_failure raises an unexpected failure unchanged")
        try:
            self.known_failure("example bug", lambda: assert_equal(1, 2), "not(1 == 3)")
        except AssertionError as e:
            assert_equal(str(e), "not(1 == 2)")
        else:
            raise AssertionError("known_failure accepted the wrong assertion")
        for expected in ("Method not found", -5):
            try:
                self.known_failure("example bug", out_of_range, expected)
            except JSONRPCException as e:
                assert_equal(e.error['code'], -8)
            else:
                raise AssertionError("known_failure accepted the wrong RPC error")
        try:
            self.known_failure("example bug", lambda: assert_equal(1, 2), -8)
        except AssertionError as e:
            assert_equal(str(e), "not(1 == 2)")
        else:
            raise AssertionError("known_failure matched an error code against an assertion")

    def use_connection(self, node, connection_class, **kwargs):
        """Send node's RPC calls through a new connection_class connection."""
        url = urllib.parse.urlparse(node.url)
        conn = connection_class(url.hostname, url.port, timeout=node.rpc_timeout, **kwargs)
        node.rpc.auth_service_proxy_instance._set_conn(conn)
        return conn

    def test_rpc_resend(self):
        self.check_lost_reply_resent()
        self.check_lost_batch_reply_resent()
        self.check_failed_send_resent()
        self.check_failed_resend_raises()
        self.check_idle_close_reconnects()

    def check_lost_reply_resent(self):
        node = self.nodes[0]
        for error in (ConnectionResetError("reset by the test"), http.client.RemoteDisconnected("closed by the test")):
            self.log.info("A request whose reply is lost is sent again with a warning (%s)", type(error).__name__)
            height = node.getblockcount()
            conn = self.use_connection(node, LostReplyConnection, error=error)
            with CaptureWarnings() as warnings:
                assert_equal(len(node.generate(1)), 1)
            assert_equal(conn.requests, 2)
            # The node ran the call twice: the resend is not silent.
            assert_equal(node.getblockcount(), height + 2)
            assert_equal(len(warnings.messages), 1)
            # TestNode.generate sends generatetoaddress.
            assert warnings.messages[0].startswith("Sending generatetoaddress again:"), warnings.messages[0]
            assert repr(error) in warnings.messages[0], warnings.messages[0]

    def check_lost_batch_reply_resent(self):
        node = self.nodes[0]
        self.log.info("A batch whose reply is lost is named as a batch in the warning")
        height = node.getblockcount()
        conn = self.use_connection(node, LostReplyConnection, error=ConnectionResetError("reset by the test"))
        with CaptureWarnings() as warnings:
            replies = node.batch([node.getblockcount.get_request()])
        assert_equal(conn.requests, 2)
        assert_equal(replies[0]['result'], height)
        assert_equal(len(warnings.messages), 1)
        assert "batch" in warnings.messages[0], warnings.messages[0]

    def check_failed_send_resent(self):
        node = self.nodes[0]
        self.log.info("A request that failed while sending is sent again without a warning")
        height = node.getblockcount()
        conn = self.use_connection(node, FailedSendConnection)
        with CaptureWarnings() as warnings:
            assert_equal(node.getblockcount(), height)
        assert_equal(conn.requests, 2)
        assert_equal(warnings.messages, [])

    def check_failed_resend_raises(self):
        node = self.nodes[0]
        self.log.info("When the resend loses its reply too, its error goes to the caller")
        conn = self.use_connection(node, CountingDroppedReplyConnection)
        with CaptureWarnings() as warnings:
            assert_raises(http.client.RemoteDisconnected, node.getblockcount)
        assert_equal(conn.requests, 2)
        assert_equal(len(warnings.messages), 1)
        self.use_connection(node, http.client.HTTPConnection)
        assert node.getblockcount() > 0

    def check_idle_close_reconnects(self):
        self.log.info("An open connection is reused")
        node = self.nodes[0]
        height = node.getblockcount()
        conn = self.use_connection(node, CountingConnection)
        # Default -rpcservertimeout (30 s): the node keeps the connection open.
        assert_equal(node.getblockcount(), height)
        assert_equal(node.getblockcount(), height)
        assert_equal((conn.requests, conn.connects), (2, 1))

        self.log.info("A connection the node closed while idle is reopened before the request is sent")
        node = self.nodes[1]
        self.restart_node(1, extra_args=["-rpcservertimeout=1"])
        height = node.getblockcount()
        conn = self.use_connection(node, CountingConnection)
        with CaptureWarnings() as warnings:
            assert_equal(node.getblockcount(), height)
            time.sleep(4)
            assert_equal(node.getblockcount(), height)
        assert_equal((conn.requests, conn.connects), (2, 2))
        assert_equal(warnings.messages, [])

    def test_start_nodes_failure(self):
        self.log.info("start_nodes with a node that fails to start before one that starts stops both quickly and raises the start error")
        self.stop_nodes()
        good = self.nodes[1]
        pids = []
        start = good.start

        def start_and_record_pid(*args, **kwargs):
            start(*args, **kwargs)
            pids.append(good.process.pid)
        good.start = start_and_record_pid
        began = time.time()
        try:
            self.start_nodes([["-paytxfee=abc"], []])
        except FailedToStartError as e:
            error = e
        else:
            raise AssertionError("start_nodes did not fail")
        finally:
            del good.start
        elapsed = time.time() - began
        self.log.info("start_nodes failed after %.1f s: %r", elapsed, error)
        assert "exited with status 1 during initialization" in str(error), str(error)
        assert elapsed < 30, elapsed
        assert "Invalid amount for -paytxfee=<amount>: 'abc'" in self.nodes[0].read_stderr()
        for node in self.nodes:
            assert not node.running
            assert node.process is None
        assert_equal(len(pids), 1)
        assert_raises(ProcessLookupError, os.kill, pids[0], 0)

        self.log.info("The nodes start normally afterwards")
        self.start_nodes()
        for node in self.nodes:
            assert node.getblockcount() > 0

        self.log.info("wait_for_exit_or_kill kills a node that does not exit in time")
        good.send_signal(signal.SIGSTOP)
        assert_equal(good.wait_for_exit_or_kill(timeout=1), -signal.SIGKILL)
        assert not good.running
        self.start_node(1)
        assert good.getblockcount() > 0

    def combine_logs(self, testdir):
        """combine_logs.py's output for testdir and the sources it names."""
        script = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'combine_logs.py')
        output = subprocess.run([sys.executable, script, testdir], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, check=True).stdout
        # " <source> ..." starts each log event.
        events = [re.match(r" (test|node\d+) ", line) for line in output.splitlines()]
        return output, {event.group(1) for event in events if event}

    def test_combine_logs(self):
        self.log.info("combine_logs.py combines the test log and the nodes' regtest debug.log")
        output, sources = self.combine_logs(self.options.tmpdir)
        assert_equal(sources, {"test", "node0", "node1"})
        assert "Done loading" in output

        self.log.info("combine_logs.py reads a main layout's node0/debug.log")
        main_dir = os.path.join(self.options.tmpdir, 'logs_main')
        os.makedirs(os.path.join(main_dir, 'node0'))
        shutil.copy(os.path.join(self.options.tmpdir, 'test_framework.log'), main_dir)
        shutil.copy(self.nodes[0].debug_log_path, os.path.join(main_dir, 'node0', 'debug.log'))
        output, sources = self.combine_logs(main_dir)
        assert_equal(sources, {"test", "node0"})
        assert "Done loading" in output

    def test_token_height_override(self):
        node = self.nodes[1]
        token_height = node.getblockcount() + 1
        self.log.info("A script's own -testactivationheight=tokens@%d comes after the framework's", token_height)
        self.restart_node(1, extra_args=["-testactivationheight=tokens@%d" % token_height])
        token_args = [arg for arg in node.process.args if arg.startswith("-testactivationheight=tokens@")]
        assert_equal(token_args, ["-testactivationheight=tokens@%d" % REGTEST_TOKEN_HEIGHT,
                                  "-testactivationheight=tokens@%d" % token_height])

        self.log.info("The token RPCs refuse below that height and work at it")
        assert_raises_rpc_error(-1, "THIS COMMAND IS NOT YET ACTIVE", node.listtokens)
        self.mine_with_mocktime(node, 1, sync=False)
        assert_equal(node.getblockcount(), token_height)
        assert_equal(node.listtokens("*", True), {})


if __name__ == '__main__':
    FrameworkTest().main()
