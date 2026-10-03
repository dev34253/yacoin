#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Snapshot of the parameters a node really runs with (task P0-20).

The functional tests do not use -regtest: they run the main parameters of the
low-difficulty build with the values the framework sets (review A3):
epochinterval=10 and nFactorAtHardfork=4 in yacoin.conf
(test_framework/util.py) and -testnetNewLogicBlockNumber=<block_fork_1_0> on
the command line (test_framework/test_node.py). Without them the node uses the
compiled-in mainnet defaults from init.cpp (fork height 1,890,000, token
height 1,911,210, N-factor 21, epoch 21000). Those are file-static in
init.cpp, so only debug.log shows them; this test pins both sets there, plus
the low-difficulty genesis block over RPC. The chain parameters themselves are
pinned in src/test/chainparams_snapshot_tests.cpp.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Low-difficulty build genesis (chainparams.cpp, LOW_DIFFICULTY_FOR_DEVELOPMENT).
GENESIS_HASH = "1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848"
GENESIS_MERKLE_ROOT = "678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f"
GENESIS_TIME = 1367991220  # nChainStartTime + 20
GENESIS_NONCE = 127358
GENESIS_BITS = "201fffff"  # powLimit ~uint256(0) >> 3
GENESIS_MODIFIER_CHECKSUM = "fd11f4e7"  # stake-modifier checkpoint 0 (kernel.cpp)

FORK_HEIGHT = 7  # a per-test fork height different from the default 0

FRAMEWORK_LINES = [
    "Param nEpochInterval = 10, nFactorAtHardfork = 4\n",
    "Param nMainnetNewLogicBlockNumber = {}\n".format(FORK_HEIGHT),
    "Param nTokenSupportBlockNumber = 1911210\n",
]
DEFAULT_LINES = [
    "Param nEpochInterval = 21000, nFactorAtHardfork = 21\n",
    "Param nMainnetNewLogicBlockNumber = 1890000\n",
    "Param nTokenSupportBlockNumber = 1911210\n",
]


class ParamsSnapshotTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # Only the genesis block: the cached chain is mined with fork height
        # 0 and would be re-checked under pre-fork rules after the restart.
        self.setup_clean_chain = True
        self.block_fork_1_0 = FORK_HEIGHT

    def check_genesis(self, node):
        assert_equal(node.getblockhash(0), GENESIS_HASH)
        block = node.getblock(GENESIS_HASH)
        assert_equal(block["height"], 0)
        assert_equal(block["merkleroot"], GENESIS_MERKLE_ROOT)
        assert_equal(block["time"], GENESIS_TIME)
        assert_equal(block["nonce"], GENESIS_NONCE)
        assert_equal(block["bits"], GENESIS_BITS)
        assert_equal(block["version"], 1)
        assert_equal(block["modifierchecksum"], GENESIS_MODIFIER_CHECKSUM)
        assert_equal(block["flags"], "proof-of-work stake-modifier")

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Framework values: epoch 10, N-factor 4, per-test fork height")
        # The node was started in setup_nodes(), so read the whole debug.log.
        with open(os.path.join(node.datadir, "debug.log"), encoding="utf-8") as f:
            log = f.read()
        for line in FRAMEWORK_LINES:
            if line not in log:
                raise AssertionError("missing in debug.log: {!r}".format(line))
        self.check_genesis(node)

        self.log.info("Compiled-in defaults: restart without the framework values")
        self.stop_node(0)
        conf_path = os.path.join(node.datadir, "yacoin.conf")
        with open(conf_path, encoding="utf-8") as f:
            conf = f.read().splitlines(keepends=True)
        kept = [l for l in conf if not l.startswith(("epochinterval=", "nFactorAtHardfork="))]
        assert_equal(len(conf) - len(kept), 2)
        with open(conf_path, "w", encoding="utf-8") as f:
            f.writelines(kept)
        args_before = len(node.args)
        node.args = [a for a in node.args if not a.startswith("-testnetNewLogicBlockNumber=")]
        assert_equal(args_before - len(node.args), 1)

        with node.assert_debug_log(expected_msgs=DEFAULT_LINES,
                                   unexpected_msgs=["Failed stake modifier checkpoint"]):
            self.start_node(0)
        self.check_genesis(node)


if __name__ == '__main__':
    ParamsSnapshotTest().main()
