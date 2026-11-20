#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getsubsidy before the 1.0 fork (here at block 1000).

- getsubsidy() is the value of the next coinbase.
- With a target, the reward follows it: 100 YAC / (powLimit / target) **
  (1/6), with regtest's powLimit, capped at MAX_MINT_PROOF_OF_WORK (100 YAC).

mining_basic.py checks getsubsidy after the fork.
"""

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

FORK = 1000


class MiningSubsidyBeforeForkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        self.block_fork_1_0 = FORK

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Before the fork getsubsidy is the next coinbase value")
        # Blocks below the fork hash with the time-based N-factor, so they are
        # mined on a clock near the genesis time.
        self.mine_with_mocktime(node, 3)
        subsidy = node.getsubsidy()
        block_hash = self.mine_with_mocktime(node, 1)[0]
        coinbase = node.getrawtransaction(node.getblock(block_hash)['tx'][0], 1)
        assert_equal(coinbase['vout'][0]['value'] * COIN, subsidy)

        self.log.info("Before the fork the reward follows the target")
        assert_equal(node.getsubsidy('00ffff' + '00' * 29), 44540000)
        assert_equal(node.getsubsidy('00000fff' + '00' * 28), 11140000)
        assert_equal(node.getsubsidy('0000000fff' + '00' * 27), 4420000)
        assert_equal(node.getsubsidy('ff' * 32), 100 * COIN)


if __name__ == '__main__':
    MiningSubsidyBeforeForkTest().main()
