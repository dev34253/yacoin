#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the invalidateblock RPC.

- the node reorgs to another chain when its own is invalidated, and doesn't
  reorg to a chain with less work;
- an unknown hash is an error;
- the transactions of an invalidated block go back to the mempool;
- a child of an invalidated block is rejected (bad-prevblk);
- the invalid status survives a restart; -reindex forgets it;
- the genesis block can't be invalidated;
- the coin set (gettxout) across a block, its invalidation, the next block
  and a restart; verifychain at level 4 afterwards;
- invalidating a block on a side branch leaves the active chain alone, and
  the node doesn't move to that branch when its tip is invalidated later.
"""

from test_framework.blocktools import create_block_yac, solve_block
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    node_peers,
    wait_until,
)


class InvalidateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        # -reindex below; with the fork at block 0 it fails (XpHqZPNh).
        self.block_fork_1_0 = 1

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.log.info("Make sure we repopulate setBlockIndexCandidates after InvalidateBlock:")
        self.log.info("Mine 4 blocks on Node 0")
        self.nodes[0].generatetoaddress(4, self.nodes[0].get_deterministic_priv_key().address)
        assert_equal(self.nodes[0].getblockcount(), 4)
        besthash_n0 = self.nodes[0].getbestblockhash()

        self.log.info("Mine competing 6 blocks on Node 1")
        self.nodes[1].generatetoaddress(6, self.nodes[1].get_deterministic_priv_key().address)
        assert_equal(self.nodes[1].getblockcount(), 6)

        self.log.info("Connect nodes to force a reorg")
        connect_nodes(self.nodes[0], 1)
        self.sync_blocks(self.nodes[0:2])
        assert_equal(self.nodes[0].getblockcount(), 6)
        badhash = self.nodes[1].getblockhash(2)

        self.log.info("Invalidate block 2 on node 0 and verify we reorg to node 0's original chain")
        self.nodes[0].invalidateblock(badhash)
        assert_equal(self.nodes[0].getblockcount(), 4)
        assert_equal(self.nodes[0].getbestblockhash(), besthash_n0)

        self.log.info("Make sure we won't reorg to a lower work chain:")
        connect_nodes(self.nodes[1], 2)
        self.log.info("Sync node 2 to node 1 so both have 6 blocks")
        self.sync_blocks(self.nodes[1:3])
        assert_equal(self.nodes[2].getblockcount(), 6)
        self.log.info("Invalidate block 5 on node 1 so its tip is now at 4")
        self.nodes[1].invalidateblock(self.nodes[1].getblockhash(5))
        assert_equal(self.nodes[1].getblockcount(), 4)
        self.log.info("Invalidate block 3 on node 2, so its tip is now 2")
        self.nodes[2].invalidateblock(self.nodes[2].getblockhash(3))
        assert_equal(self.nodes[2].getblockcount(), 2)
        self.log.info("..and then mine a block")
        self.nodes[2].generatetoaddress(1, self.nodes[2].get_deterministic_priv_key().address)
        self.log.info("Verify all nodes are at the right height")
        wait_until(lambda: self.nodes[2].getblockcount() == 3, timeout=5)
        wait_until(lambda: self.nodes[0].getblockcount() == 4, timeout=5)
        wait_until(lambda: self.nodes[1].getblockcount() == 4, timeout=5)

        node = self.nodes[0]
        disconnect_nodes(node, 1)
        wait_until(lambda: node_peers(node) == [])

        self.log.info("An unknown block hash is an error")
        assert_raises_rpc_error(-5, "Block not found", node.invalidateblock, "00" * 32)

        self.log.info("The transactions of an invalidated block go back to the mempool")
        address = node.get_deterministic_priv_key().address
        node.generatetoaddress(6, address)
        txid = node.sendtoaddress(address=node.getnewaddress(), amount=1)
        bad_hash = node.generatetoaddress(1, address)[0]
        bad_height = node.getblockcount()
        assert_equal(node.getrawmempool(), [])
        node.invalidateblock(bad_hash)
        assert_equal(node.getblockcount(), bad_height - 1)
        assert_equal(node.getrawmempool(), [txid])
        assert {"height": bad_height, "hash": bad_hash, "branchlen": 1, "status": "invalid"} in node.getchaintips()

        self.log.info("A child of the invalidated block is rejected")
        parent = node.getblockheader(bad_hash)
        child = create_block_yac(node, prev=bad_hash, nbits=int(parent['bits'], 16), ntime=parent['time'])
        solve_block(node, child)
        assert_equal(node.submitblock(child.serialize().hex()), "bad-prevblk")
        assert child.hash not in [tip['hash'] for tip in node.getchaintips()]

        self.log.info("The invalid status survives a restart")
        tip = node.getbestblockhash()
        tips = sorted(node.getchaintips(), key=lambda t: t['hash'])
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(sorted(node.getchaintips(), key=lambda t: t['hash']), tips)
        assert_equal(node.getrawmempool(), [txid])

        self.log.info("-reindex rebuilds the block index from the block files and forgets it")
        self.restart_node(0, extra_args=["-reindex"])
        wait_until(lambda: node.getblockcount() == bad_height, timeout=60)
        assert_equal(node.getbestblockhash(), bad_hash)
        assert_equal([t for t in node.getchaintips() if t['status'] == 'invalid'], [])
        assert_equal(node.getrawmempool(), [])

        self.log.info("Invalidating the genesis block is an error and changes nothing")
        # Today it disconnects every block, connects them again and reports success.
        genesis = node.getblockhash(0)
        self.known_failure("invalidateblock on genesis (VdCO5Ac4 item 6)",
                           lambda: assert_raises_rpc_error(None, None, node.invalidateblock, genesis),
                           "No exception raised")
        assert_equal(node.getbestblockhash(), bad_hash)
        assert_equal([t for t in node.getchaintips() if t['status'] == 'invalid'], [])

        self.log.info("The coin set across a block, its invalidation, the next block and a restart")
        txid = node.sendtoaddress(address=node.getnewaddress(), amount=1)
        decoded = node.decoderawtransaction(node.getrawtransaction(txid))
        spent = [(i['txid'], i['vout']) for i in decoded['vin']]
        created = [(txid, o['n']) for o in decoded['vout']]

        def coins(outpoints):
            return [node.gettxout(t, n, False) for t, n in outpoints]

        def without_bestblock(entries):
            return [{k: v for k, v in e.items() if k != 'bestblock'} for e in entries]
        before = coins(spent)
        assert None not in before
        assert_equal(coins(created), [None] * len(created))

        block = node.generatetoaddress(1, address)[0]
        coinbase = [(node.getblock(block)['tx'][0], 0)]
        assert_equal(coins(spent), [None] * len(spent))
        after = coins(created + coinbase)
        assert None not in after
        assert all(e['bestblock'] == block and e['confirmations'] == 1 for e in after)

        node.invalidateblock(block)
        assert_equal(coins(spent), before)
        assert_equal(coins(created + coinbase), [None] * (len(created) + 1))

        # The next block confirms the transaction again (yacoind has no reconsiderblock); its
        # coinbase pays another address, so it isn't the invalidated block once more
        assert_equal(node.getrawmempool(), [txid])
        node.generatetoaddress(1, node.getnewaddress())
        assert_equal(coins(spent), [None] * len(spent))
        assert_equal(without_bestblock(coins(created)), without_bestblock(after[:-1]))
        assert_equal(coins(coinbase), [None])

        # Coins read back from disk after a restart give the same answers
        expected = coins(spent + created)
        self.restart_node(0)
        assert_equal(coins(spent + created), expected)
        assert node.verifychain(4, 3)

        self.log.info("Invalidating a block on a side branch leaves the active chain alone")
        tip = node.getbestblockhash()
        tip_header = node.getblockheader(tip)
        height = tip_header['height']
        parent = tip_header['previousblockhash']
        # Same parent and work as the tip, received later: it stays on the side
        side = create_block_yac(node, prev=parent, nbits=int(tip_header['bits'], 16), ntime=tip_header['time'])
        solve_block(node, side)
        assert_equal(node.submitblock(side.serialize().hex()), "inconclusive")
        assert_equal(node.getbestblockhash(), tip)
        assert {"height": height, "hash": side.hash, "branchlen": 1, "status": "valid-headers"} in node.getchaintips()

        node.invalidateblock(side.hash)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.getblockcount(), height)
        assert {"height": height, "hash": side.hash, "branchlen": 1, "status": "invalid"} in node.getchaintips()
        assert_equal(node.submitblock(side.serialize().hex()), "duplicate-invalid")

        self.log.info("The node doesn't move to the invalidated side branch when its tip is invalidated")
        node.invalidateblock(tip)
        assert_equal(node.getbestblockhash(), parent)
        assert_equal(node.getblockcount(), height - 1)
        assert {"height": height, "hash": side.hash, "branchlen": 1, "status": "invalid"} in node.getchaintips()
        assert {"height": height, "hash": tip, "branchlen": 1, "status": "invalid"} in node.getchaintips()
        assert_equal(node.getrawmempool(), [txid])


if __name__ == '__main__':
    InvalidateTest().main()
