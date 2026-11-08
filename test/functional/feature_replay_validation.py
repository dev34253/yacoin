#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -replayvalidation, the validation for replays of the block history.

Builds a chain of about 200 blocks with wallet payments, some with several
inputs, then restarts the node with -reindex and -replayvalidation=reject and
=report: the node logs the mode, replays the chain to the same tip and reports
no failure. An unknown mode is an init error.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_greater_than

REPORT = "replayvalidation: failure"


class ReplayValidationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.block_fork_1_0 = 1

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Build a chain with wallet payments")
        self.mine_with_mocktime(node, 30)
        addresses = [node.getnewaddress() for _ in range(4)]
        multi_input = 0
        while node.getblockcount() < 200:
            for i, address in enumerate(addresses):
                txid = node.sendtoaddress(address, 1 + i)
                if len(node.decoderawtransaction(node.gettransaction(txid)['hex'])['vin']) > 1:
                    multi_input += 1
            # A payment larger than any single coin spends several of them.
            balance = node.getbalance()
            if balance > 100:
                txid = node.sendtoaddress(addresses[0], int(balance / 2))
                if len(node.decoderawtransaction(node.gettransaction(txid)['hex'])['vin']) > 1:
                    multi_input += 1
            self.mine_with_mocktime(node, 5)
        assert_greater_than(multi_input, 0)
        tip = node.getbestblockhash()
        height = node.getblockcount()

        for mode in ["reject", "report"]:
            self.log.info("-reindex with -replayvalidation=%s" % mode)
            self.stop_node(0)
            with node.assert_debug_log(["replayvalidation: mode %s" % mode, "Reindexing finished"],
                                       unexpected_msgs=[REPORT]):
                self.start_node(0, ["-reindex", "-replayvalidation=%s" % mode])
            assert_equal(node.getbestblockhash(), tip)
            assert_equal(node.getblockcount(), height)

        self.log.info("An unknown mode is an init error")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-replayvalidation=bogus"],
            "Error: Invalid -replayvalidation value 'bogus' (0, report or reject)",
            match=ErrorMatch.FULL_TEXT)


if __name__ == '__main__':
    ReplayValidationTest().main()
