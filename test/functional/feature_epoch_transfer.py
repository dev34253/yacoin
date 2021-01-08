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
        
    def setmocktimeforallnodes(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        for i in range(numberOfBlocks):
            self.setmocktimeforallnodes(self.mocktime)
            self.mocktime=self.mocktime+timeBetweenBlocks      
            self.nodes[nodeId].generate(1)
        self.sync_all()

    def log_accounts(self, description):        
        node_0_accounts = self.nodes[0].listaccounts()
        node_1_accounts = self.nodes[1].listaccounts()
        self.log.info('List accounts 0 '+description+': '+str(node_0_accounts))
        self.log.info('List accounts 1 '+description+': '+str(node_1_accounts))

    def run_test(self):
        address_0 = self.nodes[0].getaccountaddress('')
        address_1 = self.nodes[1].getaccountaddress('')
        self.log.info('Address 0: '+str(address_0))
        self.log.info('Address 1: '+str(address_1))

        self.mine_blocks(0, 1)
        assert_equal(self.nodes[0].getblockcount(), 1)
        assert_equal(self.nodes[1].getblockcount(), 1)

        mininginfo=self.nodes[0].getmininginfo()
        info=self.nodes[0].getinfo()
        difficulty_epoch_0 = mininginfo['difficulty']['proof-of-work']
        powreward_epoch_0 = mininginfo['powreward']

        assert_equal(difficulty_epoch_0, info['difficulty']['proof-of-work'])

        for i in range(9):
            self.mine_blocks(0,1)
            assert_equal(self.nodes[0].getblockcount(), i+2)
            assert_equal(self.nodes[1].getblockcount(), i+2)
            mininginfo=self.nodes[0].getmininginfo()
            info=self.nodes[0].getinfo()
            assert_equal(mininginfo['difficulty']['proof-of-work'], difficulty_epoch_0)
            assert_equal(info['difficulty']['proof-of-work'], difficulty_epoch_0)
            assert_equal(mininginfo['powreward'], powreward_epoch_0)

        self.mine_blocks(0,1)
        assert_equal(self.nodes[0].getblockcount(), 11)
        assert_equal(self.nodes[1].getblockcount(), 11)

        mininginfo=self.nodes[0].getmininginfo()
        info=self.nodes[0].getinfo()
        difficulty_epoch_1 = mininginfo['difficulty']['proof-of-work']       
        powreward_epoch_1 = mininginfo['powreward']
        
        assert(difficulty_epoch_0 != difficulty_epoch_1)
        assert(powreward_epoch_0 != powreward_epoch_1)

        for i in range(9):
            self.mine_blocks(0,1)
            assert_equal(self.nodes[0].getblockcount(), i+11)
            assert_equal(self.nodes[1].getblockcount(), i+11)
            mininginfo=self.nodes[0].getmininginfo()
            info=self.nodes[0].getinfo()
            assert_equal(mininginfo['difficulty']['proof-of-work'], difficulty_epoch_1)
            assert_equal(info['difficulty']['proof-of-work'], difficulty_epoch_1)
            assert_equal(mininginfo['powreward'], powreward_epoch_1)

if __name__ == '__main__':
    BasicTransfer_Test().main()
