#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Self-checks of the YACoin parts of the test framework.

Later tests rely on these helpers, so check them against a real node:
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
- start_nodes, when one node fails to start, stops the others without
  waiting for their RPC and raises the start error; wait_for_exit_or_kill
  kills a node that does not exit in time.
"""

from decimal import Decimal
import http.client
import logging
import re
import os
import signal
import socket
import sys
import time
import urllib.parse

from test_framework.authproxy import JSONRPCException
from test_framework.messages import COIN, CBlock, CTransaction, FromHex, TX_VERSION
from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import FailedToStartError
from test_framework.util import (
    assert_equal,
    assert_raises,
    connect_nodes,
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


class FrameworkTest(BitcoinTestFramework):
    def set_test_params(self):
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

    def test_mocktime_at_start(self):
        self.log.info("Nodes added after set_mocktime start on the test's clock")
        for node in self.nodes:
            assert "-mocktime=%d" % self.start_mocktime in node.process.args
        block = self.nodes[0].getblockheader(self.nodes[0].generate(1)[0])
        assert_equal(block['time'], self.start_mocktime)

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
        # Not raised while handling a cleanup error.
        assert error.__context__ is None, repr(error.__context__)
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


if __name__ == '__main__':
    FrameworkTest().main()
