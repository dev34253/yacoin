#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test blocks on a chain with every activation height passed.

Three regtest nodes with every activation height at 0
(all_activation_heights_zero), node 2 connected only to node 1, on a chain
of at least 30 blocks with block times on real time, out of initial
download:

- On each node every activation height is 0, the best block is version 7,
  getblocktemplate answers with version 7 and listtokens answers.
- A block from a test peer with a payment from node 0 is accepted by node 0
  and reaches nodes 1 and 2; the payment leaves every mempool.
- A block mined by node 2 reaches nodes 1 and 0.
- Node 1's template holds a payment and a token issue from node 0; the block
  built from it is accepted by submitblock and reaches every node, and node
  2 shows the token.
- A token transfer from node 0 to node 1, mined by node 2: node 1 holds the
  amount, node 0 the rest.
- Node 0 apart from the other nodes, with a test peer as its only peer,
  rejects blocks from that peer: a second coinbase (bad-cb-multiple; the
  peer is disconnected); a coinbase with the wrong height (bad-cb-height;
  the peer is disconnected, the block is invalid); a transaction spending
  more than its inputs (bad-txns-in-belowout; the peer is disconnected, the
  block is invalid); a block time more than 2 hours after the nodes' time
  (time-too-new; the peer stays connected, and once the nodes' time has
  moved forward the same block is accepted). Node 0 then joins node 1
  again: the best block is unchanged on every node, or the accepted block
  on every node.
- Node 2 alone mines a branch with more chain trust than node 0's branch,
  which holds a payment from node 0: every node ends on node 2's branch,
  node 0's branch is a valid-fork, the payment returns to node 0's mempool
  and is mined in the next block.
- Node 2 alone mines a branch with the same chain trust as node 0's: nodes 0
  and 1 stay on their branch, node 1 lists node 2's block, which is not
  active there; the next block on node 0's branch brings node 2 over.
- Node 0 apart from the other nodes, a test peer gives it three blocks that
  branch off one block below its best block, the third spending more than
  its inputs: node 0 ends on the second, which has more chain trust than
  its former best block; the third is invalid and the peer is disconnected.
  Node 0 joins node 1 again, and nodes 1 and 2 follow node 0.
"""

from decimal import Decimal
import time

from test_framework.blocktools import (
    create_block_yac,
    create_coinbase_yac,
    get_template,
    solve_block,
    txs_from_template,
)
from test_framework.messages import CTransaction, FromHex, REJECT_INVALID, msg_block
from test_framework.mininode import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
    node_peers,
    wait_until,
)

TOKEN = "ACTIVATED"
FEE = Decimal("0.01")


class ActivatedChainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.all_activation_heights_zero = True

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[1], 0)
        connect_nodes(self.nodes[2], 1)

    def run_test(self):
        self.log.info("Every node: every activation height 0, a chain of at least 30 blocks, version 7, "
                      "getblocktemplate and listtokens answer")
        self.mine_activated_chain(35)

        self.test_block_from_peer()
        self.test_block_from_node()
        self.test_template_and_submitblock()
        self.test_token_transfer()
        self.test_second_coinbase()
        self.test_wrong_coinbase_height()
        self.test_spend_above_inputs()
        self.test_time_too_new()
        self.test_longer_branch()
        self.test_branch_of_same_trust()
        self.test_longer_branch_with_invalid_block()

    # Helpers

    def best_blocks(self):
        return [node.getbestblockhash() for node in self.nodes]

    def chaintrust(self, node, block_hash):
        return int(node.getblockheader(block_hash)['chaintrust'], 16)

    def listed_status(self, node, block_hash):
        return [entry["status"] for entry in node.getchaintips() if entry["hash"] == block_hash]

    def own_output(self, node, txid, address):
        """(txid, vout, amount) of the output of txid paying address."""
        outputs = [(txid, out['n'], out['value']) for out in node.getrawtransaction(txid, 1)['vout']
                   if out['scriptPubKey'].get('addresses') == [address]]
        assert_equal(len(outputs), 1)
        return outputs[0]

    def payment_from(self, node, output):
        """A payment from node's wallet spending output (txid, vout, amount)
        to a new address of node, sent to its mempool. Returns the txid and
        the address."""
        txid, vout, amount = output
        address = node.getnewaddress()
        raw = node.createrawtransaction([{"txid": txid, "vout": vout}], {address: amount - FEE})
        result = node.signrawtransaction(raw)
        assert_equal(result['complete'], True)
        return node.sendrawtransaction(result['hex']), address

    def spend_above_inputs(self, node, output):
        """A transaction from node's wallet spending output (txid, vout,
        amount) and paying one coin more than it; not sent anywhere."""
        txid, vout, amount = output
        raw = node.createrawtransaction([{"txid": txid, "vout": vout}], {node.getnewaddress(): amount + 1})
        result = node.signrawtransaction(raw)
        assert_equal(result['complete'], True)
        return FromHex(CTransaction(), result['hex'])

    def new_peer(self):
        node = self.nodes[0]
        node.disconnect_p2ps()
        return node.add_p2p_connection(P2PDataStore())

    def send_rejected(self, block, reason):
        """Node 0 apart from the other nodes, a new test peer gives it block;
        node 0 rejects it with reason, disconnects the peer and keeps its
        best block. After node 0 joins node 1 again the best block is the
        same as before on every node."""
        before = self.best_blocks()
        self.separate_node0()
        peer = self.new_peer()
        peer.send_blocks_and_test([block], self.nodes[0], success=False, expect_disconnect=True)
        peer.wait_for_reject(message=b"block", code=REJECT_INVALID, reason=reason, data=block.sha256)
        assert_equal(self.nodes[0].getbestblockhash(), before[0])
        self.join_node0()
        assert_equal(self.best_blocks(), before)

    def separate_node0(self):
        disconnect_nodes(self.nodes[1], 0)
        wait_until(lambda: node_peers(self.nodes[0]) == [] and len(node_peers(self.nodes[1])) == 1)

    def join_node0(self):
        self.nodes[0].disconnect_p2ps()
        connect_nodes(self.nodes[1], 0)
        self.sync_blocks()

    def separate_node2(self):
        disconnect_nodes(self.nodes[2], 1)
        wait_until(lambda: node_peers(self.nodes[2]) == [] and len(node_peers(self.nodes[1])) == 1)

    # Cases

    def test_block_from_peer(self):
        node0, node1, node2 = self.nodes
        self.log.info("A block from a test peer with a payment from node 0 is accepted by node 0 and reaches nodes 1 and 2")
        address = node0.getnewaddress()
        txid = node0.sendtoaddress(address, 10)
        self.sync_mempools()
        tx = FromHex(CTransaction(), node0.getrawtransaction(txid))
        block = solve_block(node0, create_block_yac(node0, [tx]))
        peer = self.new_peer()
        peer.send_blocks_and_test([block], node0, success=True)
        wait_until(lambda: node1.getbestblockhash() == block.hash)
        wait_until(lambda: node2.getbestblockhash() == block.hash)
        self.log.info("The payment leaves every mempool")
        for node in self.nodes:
            assert txid not in node.getrawmempool()
        node0.disconnect_p2ps()
        # Locked until test_longer_branch spends it.
        self.first_payment = self.own_output(node0, txid, address)
        node0.lockunspent(False, [{"txid": txid, "vout": self.first_payment[1]}])

    def test_block_from_node(self):
        node0, node1, node2 = self.nodes
        self.log.info("A block mined by node 2 reaches nodes 1 and 0")
        block_hash = node2.generate(1)[0]
        wait_until(lambda: node1.getbestblockhash() == block_hash)
        wait_until(lambda: node0.getbestblockhash() == block_hash)

    def test_template_and_submitblock(self):
        node0, node1, node2 = self.nodes
        self.log.info("Node 1's template holds a payment and a token issue from node 0")
        pay_txid = node0.sendtoaddress(node1.getnewaddress(), 5)
        issue_txid = node0.issue(TOKEN, 1000)
        self.sync_mempools()
        tmpl = get_template(node1)
        assert_equal(sorted(t['txid'] for t in tmpl['transactions']), sorted([pay_txid, issue_txid]))
        self.log.info("The block built from it is accepted by submitblock and reaches every node")
        block = solve_block(node1, create_block_yac(node1, txs_from_template(tmpl), tmpl=tmpl))
        assert_equal(node1.submitblock(block.serialize().hex()), None)
        self.sync_blocks()
        assert_equal(self.best_blocks(), [block.hash] * 3)
        self.log.info("Node 2 shows the token")
        data = node2.gettokendata(TOKEN)
        assert_equal((data['name'], data['amount']), (TOKEN, "1000"))

    def test_token_transfer(self):
        node0, node1, node2 = self.nodes
        self.log.info("A token transfer from node 0 to node 1, mined by node 2")
        txid = node0.transfer(TOKEN, 400, node1.getnewaddress())
        self.sync_mempools()
        block_hash = node2.generate(1)[0]
        self.sync_blocks()
        assert txid in node2.getblock(block_hash)['tx']
        self.log.info("Node 1 holds the amount, node 0 the rest")
        assert_equal(node1.listmytokens()[TOKEN], "400")
        assert_equal(node0.listmytokens()[TOKEN], "600")

    def test_second_coinbase(self):
        node0 = self.nodes[0]
        self.log.info("Node 0 apart from the other nodes, a block with a second coinbase from a test peer: "
                      "rejected with bad-cb-multiple; the peer is disconnected")
        tmpl = get_template(node0)
        second = create_coinbase_yac(tmpl['height'], tmpl['curtime'], 0)
        block = solve_block(node0, create_block_yac(node0, [second], tmpl=tmpl))
        self.send_rejected(block, b"bad-cb-multiple")

    def test_wrong_coinbase_height(self):
        node0 = self.nodes[0]
        self.log.info("Node 0 apart from the other nodes, a coinbase with the wrong height from a test peer: "
                      "rejected with bad-cb-height; the peer is disconnected")
        tmpl = get_template(node0)
        coinbase = create_coinbase_yac(tmpl['height'] + 1, tmpl['curtime'], tmpl['coinbasevalue'])
        block = solve_block(node0, create_block_yac(node0, tmpl=tmpl, coinbase=coinbase))
        self.send_rejected(block, b"bad-cb-height")
        self.log.info("getchaintips shows the block invalid")
        assert_equal(self.listed_status(node0, block.hash), ['invalid'])

    def test_spend_above_inputs(self):
        node0 = self.nodes[0]
        self.log.info("Node 0 apart from the other nodes, a transaction spending more than its inputs from a test peer: "
                      "rejected with bad-txns-in-belowout; "
                      "the peer is disconnected")
        tx = self.spend_above_inputs(node0, self.first_payment)
        block = solve_block(node0, create_block_yac(node0, [tx]))
        self.send_rejected(block, b"bad-txns-in-belowout")
        self.log.info("getchaintips shows the block invalid")
        assert_equal(self.listed_status(node0, block.hash), ['invalid'])

    def test_time_too_new(self):
        node0 = self.nodes[0]
        self.log.info("Node 0 apart from the other nodes, a block time more than 2 hours after the nodes' time "
                      "from a test peer: rejected with time-too-new; the peer stays connected")
        before = self.best_blocks()
        self.set_mocktime(int(time.time()))
        block_time = self.mocktime + 2 * 60 * 60 + 60
        block = solve_block(node0, create_block_yac(node0, ntime=block_time))
        self.separate_node0()
        peer = self.new_peer()
        peer.send_message(msg_block(block))
        peer.wait_for_reject(message=b"block", code=REJECT_INVALID, reason=b"time-too-new", data=block.sha256)
        peer.sync_with_ping()
        assert peer.is_connected
        assert_equal(node0.getbestblockhash(), before[0])

        self.log.info("Once the nodes' time has moved forward, the same block is accepted")
        self.set_mocktime(self.mocktime + 2 * 60)
        peer.send_message(msg_block(block))
        wait_until(lambda: node0.getbestblockhash() == block.hash)
        self.log.info("Node 0 joins node 1 again: every node reaches the block")
        self.join_node0()
        assert_equal(self.best_blocks(), [block.hash] * 3)

    def test_longer_branch(self):
        node0, node1, node2 = self.nodes
        self.log.info("Node 2 alone mines a branch with more chain trust than node 0's branch, "
                      "which holds a payment from node 0")
        self.separate_node2()
        own_branch = self.mine_with_mocktime(node2, 3, sync=False)
        node0.lockunspent(True, [{"txid": self.first_payment[0], "vout": self.first_payment[1]}])
        pay_txid, address = self.payment_from(node0, self.first_payment)
        self.sync_mempools([node0, node1])
        other_branch = self.mine_with_mocktime(node0, 2, sync=[node0, node1])
        assert pay_txid in node0.getblock(other_branch[0])['tx']
        assert self.chaintrust(node2, own_branch[-1]) > self.chaintrust(node0, other_branch[-1])

        self.log.info("Every node ends on node 2's branch; node 0's branch is a valid-fork")
        connect_nodes(node2, 1)
        self.sync_blocks()
        assert_equal(self.best_blocks(), [own_branch[-1]] * 3)
        assert_equal(self.listed_status(node0, other_branch[-1]), ['valid-fork'])

        self.log.info("The payment returns to node 0's mempool and is mined in the next block")
        wait_until(lambda: pay_txid in node0.getrawmempool())
        block_hash = self.mine_with_mocktime(node0, 1)[0]
        assert pay_txid in node0.getblock(block_hash)['tx']
        for node in self.nodes:
            assert_equal(node.getrawmempool(), [])
        self.second_payment = self.own_output(node0, pay_txid, address)

    def test_branch_of_same_trust(self):
        node0, node1, node2 = self.nodes
        self.log.info("Node 2 alone mines a branch with the same chain trust as node 0's")
        self.separate_node2()
        own_block = self.mine_with_mocktime(node2, 1, sync=False)[0]
        other_block = self.mine_with_mocktime(node0, 1, sync=[node0, node1])[0]
        assert_equal(self.chaintrust(node2, own_block), self.chaintrust(node0, other_block))

        self.log.info("Nodes 0 and 1 stay on their branch; node 1 lists node 2's block, which is not active there")
        connect_nodes(node2, 1)
        wait_until(lambda: self.listed_status(node1, own_block) != [])
        assert_equal(self.best_blocks(), [other_block, other_block, own_block])

        self.log.info("The next block on node 0's branch brings node 2 over")
        block_hash = self.mine_with_mocktime(node0, 1)[0]
        assert_equal(self.best_blocks(), [block_hash] * 3)

    def test_longer_branch_with_invalid_block(self):
        node0 = self.nodes[0]
        self.log.info("Node 0 apart from the other nodes, a test peer gives it three blocks that branch off "
                      "one block below its best block, the third spending more than its inputs")
        former = node0.getbestblockhash()
        parent = node0.getblockheader(former)['previousblockhash']
        height = node0.getblockheader(parent)['height'] + 1
        tx = self.spend_above_inputs(node0, self.second_payment)
        first = solve_block(node0, create_block_yac(node0, prev=parent, ntime=tx.nTime))
        second = solve_block(node0, create_block_yac(node0, prev=first, height=height + 1, ntime=tx.nTime + 1))
        third = solve_block(node0, create_block_yac(node0, [tx], prev=second, height=height + 2, ntime=tx.nTime + 2))
        self.separate_node0()
        peer = self.new_peer()
        peer.send_blocks_and_test([first, second, third], node0, success=False, expect_disconnect=True)
        peer.wait_for_reject(message=b"block", code=REJECT_INVALID, reason=b"bad-txns-in-belowout", data=third.sha256)

        self.log.info("Node 0 ends on the second block, which has more chain trust than its former best block; "
                      "the third is invalid")
        assert_equal(node0.getbestblockhash(), second.hash)
        assert self.chaintrust(node0, second.hash) > self.chaintrust(node0, former)
        assert_equal(self.listed_status(node0, third.hash), ['invalid'])

        self.log.info("Node 0 joins node 1 again: nodes 1 and 2 follow node 0")
        self.join_node0()
        assert_equal(self.best_blocks(), [second.hash] * 3)


if __name__ == '__main__':
    ActivatedChainTest().main()
