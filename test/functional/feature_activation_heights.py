#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test blocks at the activation heights on regtest.

Heights (-testactivationheight): the 1.0 fork height 10, the token height
20, the CLTV height 42, the CSV height 44 and the Heliopolis height 46.

- The 1.0 fork height (a multiple of the epoch interval): blocks 1-9 are
  version 6, block 10 is version 7 and its coinbase pays the epoch reward.
- Token height: at height 19 issue is refused, at height 20 it is accepted
  into the mempool, block 21 contains it and gettokendata returns the token.
- CLTV height: a block with a spend that fails OP_CHECKLOCKTIMEVERIFY is
  accepted at height 41 and rejected at height 42.
- CSV height: a block with a spend that fails OP_CHECKSEQUENCEVERIFY is
  accepted at height 43 and rejected at height 44.
- Heliopolis height: a version 6 block is accepted at height 45 and rejected
  at heights 46 and 47; version 7 blocks are accepted there. Node 1 rejects
  a version 6 block at height 46 on a side branch.
- Reorgs: node 0 switches to a longer branch from node 1, and back to a
  longer branch with the blocks accepted at heights 41, 43 and 45; node 1
  refuses a longer branch with a CLTV-failing spend at height 42 or a
  CSV-failing spend at height 44; node 1 takes node 0's chain from its peer.
"""

from test_framework.blocktools import (
    assert_block_accepted,
    assert_block_rejected,
    create_block_yac,
    epoch_reward,
    solve_block,
    TIME_GENESIS_BLOCK,
)
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    node_peers,
    wait_until,
)
from test_framework.yac_tx import (
    cltv_p2sh_redeem_script,
    csv_p2sh_redeem_script,
    key_from_wif,
    p2pkh_script,
    p2sh_script,
    sign_p2pkh_input,
    sign_p2sh_input,
)

FORK_1_0_HEIGHT = 10
TOKEN_HEIGHT = 20
CLTV_HEIGHT = 42
CSV_HEIGHT = 44
HELIOPOLIS_HEIGHT = 46

CLTV_LOCK = 1000
CSV_LOCK = 100
AMOUNT = COIN // 5
FEE = COIN // 100

LOCKTIME_FAILED = "non-mandatory-script-verify-flag (Locktime requirement not satisfied)"
BAD_VERSION_6 = "bad-version(0x00000006)"
NOT_ACTIVE = "THIS COMMAND IS NOT YET ACTIVE"
TOKEN = "HEIGHTS"


class ActivationHeightsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.block_fork_1_0 = FORK_1_0_HEIGHT
        heights = [
            "-testactivationheight=tokens@%d" % TOKEN_HEIGHT,
            "-testactivationheight=cltv@%d" % CLTV_HEIGHT,
            "-testactivationheight=csv@%d" % CSV_HEIGHT,
            "-testactivationheight=heliopolis@%d" % HELIOPOLIS_HEIGHT,
        ]
        # Node 0: -par=1 for the exact reject reason.
        self.extra_args = [heights + ["-par=1"], heights]

    def mine_to(self, node, height):
        while node.getblockcount() < height:
            self.mine_with_mocktime(node, 1)

    def fund(self):
        """A transaction paying AMOUNT to two CLTV and two CSV P2SH outputs
        (in that order) from an unspent coinbase of node 0, mined by node 0."""
        node = self.nodes[0]
        for height in range(1, node.getblockcount()):
            coinbase = node.getblock(node.getblockhash(height), 2)['tx'][0]
            if node.gettxout(coinbase['txid'], 0) is not None:
                break
        else:
            raise AssertionError("no unspent coinbase")
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(coinbase['txid'], 16), 0))]
        scripts = [self.cltv_script] * 2 + [self.csv_script] * 2
        tx.vout = [CTxOut(AMOUNT, p2sh_script(script)) for script in scripts]
        tx.vout.append(CTxOut(int(coinbase['vout'][0]['value'] * COIN) - len(scripts) * AMOUNT - FEE,
                              p2pkh_script(self.pubkey)))
        sign_p2pkh_input(tx, 0, self.key)
        assert_equal(node.sendrawtransaction(tx.serialize().hex()), tx.hash)
        block_hash = self.mine_with_mocktime(node, 1)[0]
        assert tx.hash in node.getblock(block_hash)['tx']
        return tx

    def cltv_spend(self, n):
        """A spend of the funding output n (CLTV, lock 1000) with nLockTime 0."""
        return self.spend(n, self.cltv_script, 0xfffffffe)

    def csv_spend(self, n):
        """A spend of the funding output n (CSV, lock 100) with nSequence 1."""
        return self.spend(n, self.csv_script, 1)

    def spend(self, n, redeem_script, sequence):
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.nLockTime = 0
        tx.vin = [CTxIn(COutPoint(self.funding.sha256, n), b"", sequence)]
        tx.vout = [CTxOut(AMOUNT - FEE, p2pkh_script(self.pubkey))]
        sign_p2sh_input(tx, 0, redeem_script, [self.key])
        return tx

    def block(self, node, prev, txs=(), *, version=7):
        """A solved block with txs on prev, a block hash the node knows."""
        self.set_mocktime(self.mocktime + 60)
        block = create_block_yac(node, txs, prev=prev, ntime=self.mocktime, nbits=self.nbits)
        block.nVersion = version
        return solve_block(node, block)

    def branch(self, node, prev, length, txs_at):
        """Submit a branch of length blocks on prev to node, with txs_at[k]
        in its k-th block (from 1). Every block but the last one returns
        "inconclusive". Returns the blocks."""
        blocks = []
        for k in range(1, length + 1):
            block = self.block(node, blocks[-1].hash if blocks else prev, txs_at.get(k, ()))
            if k < length:
                assert_equal(node.submitblock(block.serialize().hex()), "inconclusive")
            blocks.append(block)
        return blocks

    def disconnect(self):
        n0, n1 = self.nodes
        disconnect_nodes(n0, 1)
        wait_until(lambda: node_peers(n0) == [] and node_peers(n1) == [])

    def assert_chain_tip_status(self, node, block_hash, status):
        tips = {tip['hash']: tip['status'] for tip in node.getchaintips()}
        assert_equal(tips.get(block_hash), status)

    def run_test(self):
        n0, n1 = self.nodes
        self.key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        self.pubkey = self.key.get_pubkey().get_bytes()
        self.cltv_script = cltv_p2sh_redeem_script(CLTV_LOCK, self.pubkey)
        self.csv_script = csv_p2sh_redeem_script(CSV_LOCK, self.pubkey)
        self.set_mocktime(TIME_GENESIS_BLOCK)

        self.log.info("1.0 fork height: blocks 1-9 are version 6, block 10 is version 7")
        self.mine_to(n0, FORK_1_0_HEIGHT - 1)
        for height in range(1, FORK_1_0_HEIGHT):
            assert_equal(n0.getblock(n0.getblockhash(height))['version'], 6)
        reward = epoch_reward(n0, FORK_1_0_HEIGHT, FORK_1_0_HEIGHT)
        self.mine_to(n0, FORK_1_0_HEIGHT)
        block10 = n0.getblock(n0.getblockhash(FORK_1_0_HEIGHT), 2)
        assert_equal(block10['version'], 7)
        self.log.info("1.0 fork height: block 10's coinbase pays the epoch reward")
        assert_equal(sum(int(out['value'] * COIN) for out in block10['tx'][0]['vout']), reward)

        self.log.info("Token height: issue is refused at height 19")
        self.mine_to(n0, TOKEN_HEIGHT - 1)
        assert_raises_rpc_error(-1, NOT_ACTIVE, n0.issue, TOKEN, 1000)
        self.log.info("Token height: issue is accepted at height 20, block 21 contains it")
        self.mine_to(n0, TOKEN_HEIGHT)
        issue_txid = n0.issue(TOKEN, 1000)
        assert issue_txid in n0.getrawmempool()
        block21 = self.mine_with_mocktime(n0, 1)[0]
        assert_equal(n0.getblock(block21)['height'], TOKEN_HEIGHT + 1)
        assert issue_txid in n0.getblock(block21)['tx']
        token = n0.gettokendata(TOKEN)
        assert_equal(token['name'], TOKEN)
        assert_equal(token['amount'], "1000")

        self.mine_to(n0, 25)
        self.funding = self.fund()
        self.mine_to(n0, 40)
        hash40 = n0.getbestblockhash()
        self.nbits = int(n0.getblockheader(hash40)['bits'], 16)
        self.disconnect()

        self.log.info("CLTV height: a block with a CLTV-failing spend is accepted at height 41")
        cltv_a41 = self.cltv_spend(0)
        a41 = self.block(n0, hash40, [cltv_a41])
        assert_block_accepted(n0, a41)
        self.log.info("CLTV height: a block with a CLTV-failing spend is rejected at height 42")
        cltv_rejected = self.cltv_spend(1)
        assert_block_rejected(n0, self.block(n0, a41.hash, [cltv_rejected]), LOCKTIME_FAILED)
        a42 = self.block(n0, a41.hash)
        assert_block_accepted(n0, a42)

        self.log.info("CSV height: a block with a CSV-failing spend is accepted at height 43")
        csv_a43 = self.csv_spend(2)
        a43 = self.block(n0, a42.hash, [csv_a43])
        assert_block_accepted(n0, a43)
        self.log.info("CSV height: a block with a CSV-failing spend is rejected at height 44")
        csv_rejected = self.csv_spend(3)
        assert_block_rejected(n0, self.block(n0, a43.hash, [csv_rejected]), LOCKTIME_FAILED)
        a44 = self.block(n0, a43.hash)
        assert_block_accepted(n0, a44)

        self.log.info("Heliopolis height: a version 6 block is accepted at height 45")
        a45 = self.block(n0, a44.hash, version=6)
        assert_block_accepted(n0, a45)
        assert_equal(n0.getblock(a45.hash)['version'], 6)
        self.log.info("Heliopolis height: a version 6 block is rejected at heights 46 and 47")
        assert_block_rejected(n0, self.block(n0, a45.hash, version=6), BAD_VERSION_6)
        a46 = self.block(n0, a45.hash)
        assert_block_accepted(n0, a46)
        assert_block_rejected(n0, self.block(n0, a46.hash, version=6), BAD_VERSION_6)
        a47 = self.block(n0, a46.hash)
        assert_block_accepted(n0, a47)

        self.log.info("Reorg: node 0 switches to node 1's longer branch")
        branch_b = self.mine_with_mocktime(n1, 8, sync=False)
        assert_equal(n1.getblockcount(), 48)
        connect_nodes(n0, 1)
        wait_until(lambda: n0.getbestblockhash() == branch_b[-1])
        assert {'height': 47, 'hash': a47.hash, 'branchlen': 7, 'status': 'valid-fork'} in n0.getchaintips()
        mempool = n0.getrawmempool()
        assert cltv_a41.hash not in mempool
        assert csv_a43.hash not in mempool

        self.log.info("Reorg: node 0 switches back to its longer branch")
        self.disconnect()
        a48 = self.block(n0, a47.hash)
        assert_equal(n0.submitblock(a48.serialize().hex()), "inconclusive")
        a49 = self.block(n0, a48.hash)
        assert_block_accepted(n0, a49)
        for height, block in ((41, a41), (43, a43), (45, a45), (49, a49)):
            assert_equal(n0.getblockhash(height), block.hash)

        self.log.info("Reorg: node 1 refuses a longer branch with a CSV-failing spend at height 44")
        assert_equal(n1.getbestblockhash(), branch_b[-1])
        branch_c = self.branch(n1, hash40, 9, {4: [csv_rejected]})
        assert_block_rejected(n1, branch_c[-1], "inconclusive")
        self.assert_chain_tip_status(n1, branch_c[-1].hash, 'invalid')

        self.log.info("Reorg: node 1 refuses a longer branch with a CLTV-failing spend at height 42")
        branch_d = self.branch(n1, hash40, 9, {2: [cltv_rejected]})
        assert_block_rejected(n1, branch_d[-1], "inconclusive")
        self.assert_chain_tip_status(n1, branch_d[-1].hash, 'invalid')

        self.log.info("Heliopolis height: node 1 rejects a version 6 block at height 46 on a side branch")
        assert_block_rejected(n1, self.block(n1, branch_b[4], version=6), BAD_VERSION_6)

        self.log.info("Node 1 takes node 0's chain from its peer")
        connect_nodes(n1, 0)
        wait_until(lambda: n1.getbestblockhash() == a49.hash)
        assert_equal(n1.getblock(a45.hash)['version'], 6)
        assert cltv_a41.hash in n1.getblock(a41.hash)['tx']
        assert csv_a43.hash in n1.getblock(a43.hash)['tx']


if __name__ == '__main__':
    ActivationHeightsTest().main()
