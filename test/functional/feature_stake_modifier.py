#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the stake fields getblock reports, with the fork at block 40
(-testnetNewLogicBlockNumber).

- Every block: the entropy bit is the lowest bit of its hash; the proof hash of
  a proof-of-work block is its hash.
- Below fork height - 1, every block gets a stake modifier: the genesis block
  generates 0; a block generates a new one when its parent is in a later
  6-hour interval than the last generated modifier, the others keep the last
  one. The checksum chains the previous checksum, the flags, the proof-of-stake
  hash (0 for proof-of-work blocks) and the modifier.
- From fork height - 1 on, the modifier is 0 and not generated, and the
  checksum is 0 until a restart computes it for every block.
"""

import hashlib
import struct

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

FORK = 40
MODIFIER_INTERVAL = 6 * 60 * 60
START_TIME = 1368516000
BLOCK_STAKE_ENTROPY = 1 << 1
BLOCK_STAKE_MODIFIER = 1 << 2


def checksum(prev_checksum, flags, modifier):
    """GetStakeModifierChecksum of a proof-of-work block (prev_checksum None: genesis)."""
    data = b"" if prev_checksum is None else struct.pack("<I", prev_checksum)
    data += struct.pack("<I", flags) + bytes(32) + struct.pack("<Q", modifier)
    digest = hashlib.sha256(hashlib.sha256(data).digest()).digest()
    return int.from_bytes(digest, "little") >> 224


class StakeModifierTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.block_fork_1_0 = FORK

    def blocks(self):
        node = self.nodes[0]
        return [node.getblock(node.getblockhash(h)) for h in range(node.getblockcount() + 1)]

    def run_test(self):
        node = self.nodes[0]
        self.set_mocktime(START_TIME)
        # 50 minutes apart: a new 6-hour interval every 7 or 8 blocks
        self.mine_with_mocktime(node, FORK + 5, spacing=3000)
        blocks = self.blocks()

        self.log.info("Entropy bit and proof hash of every block")
        for block in blocks:
            assert_equal(block['entropybit'], int(block['hash'], 16) & 1)
            assert_equal(block['proofhash'], block['hash'])

        self.log.info("Modifiers below fork height - 1")
        assert_equal(blocks[0]['flags'], 'proof-of-work stake-modifier')
        assert_equal(blocks[0]['modifier'], '0' * 16)
        last_modifier_time = blocks[0]['time']
        generated = 0
        for height in range(1, FORK - 1):
            block, prev = blocks[height], blocks[height - 1]
            expected = prev['time'] // MODIFIER_INTERVAL > last_modifier_time // MODIFIER_INTERVAL
            assert_equal(block['flags'], 'proof-of-work stake-modifier' if expected else 'proof-of-work')
            if expected:
                last_modifier_time = block['time']
                generated += 1
            else:
                assert_equal(block['modifier'], prev['modifier'])
        assert_equal(generated, 6)

        self.log.info("Checksums below fork height - 1")
        self.check_checksums(blocks, FORK - 1)

        self.log.info("From fork height - 1 on: no modifier, checksum 0")
        for block in blocks[FORK - 1:]:
            assert_equal(block['flags'], 'proof-of-work')
            assert_equal(block['modifier'], '0' * 16)
            assert_equal(block['modifierchecksum'], '0' * 8)

        self.log.info("After a restart every block's checksum is computed")
        self.restart_node(0)
        restarted = self.blocks()
        for block, before in zip(restarted, blocks):
            assert_equal(block['modifier'], before['modifier'])
            assert_equal(block['flags'], before['flags'])
        for block, before in zip(restarted[:FORK - 1], blocks):
            assert_equal(block['modifierchecksum'], before['modifierchecksum'])
        self.check_checksums(restarted, len(restarted))

    def check_checksums(self, blocks, end):
        prev_checksum = None
        for block in blocks[:end]:
            flags = block['entropybit'] * BLOCK_STAKE_ENTROPY
            if 'stake-modifier' in block['flags']:
                flags |= BLOCK_STAKE_MODIFIER
            prev_checksum = checksum(prev_checksum, flags, int(block['modifier'], 16))
            assert_equal(block['modifierchecksum'], '%08x' % prev_checksum)


if __name__ == '__main__':
    StakeModifierTest().main()
