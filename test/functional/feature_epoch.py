#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test sending and receiving coins 
"""

import copy
import time
from decimal import Decimal

from test_framework.blocktools import (
    create_coinbase,
    TIME_GENESIS_BLOCK,
)
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    BLOCK_HEADER_SIZE
)
from test_framework.mininode import (
    P2PDataStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_approx,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.script import CScriptNum


def assert_template(node, block, expect, rehash=True):
    if rehash:
        block.hashMerkleRoot = block.calc_merkle_root()
    rsp = node.getblocktemplate(template_request={'data': block.serialize().hex(), 'mode': 'proposal', 'rules': ['segwit']})
    assert_equal(rsp, expect)


class BasicTransfer_Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK
        self.blocks_mined = 0
        
    def setmocktimeforallnodes(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks(self, nodeId, numberOfBlocks, blockvalue, difficulty):
        timeBetweenBlocks = 120
        for _ in range(numberOfBlocks):            
            self.log.info("Mining block "+str(self.blocks_mined+1))
            self.setmocktimeforallnodes(self.mocktime)
            self.mocktime=self.mocktime+timeBetweenBlocks            
            mininginfo = self.nodes[nodeId].getmininginfo()
            assert_equal(mininginfo['blockvalue'], blockvalue) # use blockvalue instead of powreward for checking
            assert_approx(mininginfo['difficulty']['proof-of-work'],difficulty, vspan=1E-12)
            self.nodes[nodeId].generate(1)
            self.blocks_mined += 1
        self.sync_all()

    def run_test(self):
        self.mine_blocks(0, 10, 3802570, 1.8626176E-9)
        self.mine_blocks(0, 10, 3802570, 5.96046448E-8) # too little change in total money supply so powreward stays the same
        self.mine_blocks(0, 10, 3802571, 0.0000000596046448)
        self.mine_blocks(0, 10, 3802572, 0.0000000596046448)

if __name__ == '__main__':
    BasicTransfer_Test().main()
