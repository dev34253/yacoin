#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the hidden RPC dumpconsensusvalues (task P0-08).

Mines a PoW chain across the fork (block 15) and three epoch boundaries
(epoch interval 10), with one block that has fees, dumps it and checks
every row against getblock/getblockheader, the format (columns, comment
lines, trailer), ranges, determinism and the error cases. The format is
described in src/test/README.md ("Consensus value dump").
"""

import os
from decimal import Decimal

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

# Format version 1, in output order (src/consensusdump.cpp).
COLUMNS = [
    "height", "hash", "prev_hash", "time", "bits", "version", "nonce", "merkle_root", "flags",
    "stake_modifier", "hash_proof_of_stake", "prevout_stake", "stake_time",
    "header_sha256", "nfactor", "is_pos", "median_time_past", "required_bits", "min_bits_since_fork",
    "block_trust", "chain_trust", "stake_modifier_checksum",
    "kernel_prevout", "kernel_block_from_hash", "kernel_block_from_time", "kernel_tx_prev_time",
    "kernel_tx_prev_offset", "kernel_value_in", "kernel_tx_time", "kernel_stake_modifier",
    "kernel_modifier_height", "kernel_hash", "kernel_target", "kernel_ok",
    "tx_count", "block_size", "sigops", "max_sigops", "coinbase_value", "fees", "pow_reward",
    "coinstake_value_in", "coinstake_value_out", "coin_age", "pos_reward", "pos_reward_limit",
    "max_block_size", "mint", "money_supply",
]
INDEX_CHAIN_COLUMNS = COLUMNS[:13]  # P0-47 loader columns
POS_COLUMNS = COLUMNS[22:34] + ["coinstake_value_in", "coinstake_value_out", "coin_age", "pos_reward",
                                "pos_reward_limit"]

FORK_HEIGHT = 15
EPOCH_INTERVAL = 10
COIN = 1000000
POW_LIMIT_BITS = 0x201fffff  # low-difficulty build
MAX_GENESIS_BLOCK_SIZE = 1000000


def amount(value):
    """RPC amount (ValueFromAmount) to the smallest unit."""
    return int(Decimal(str(value)) * COIN)


def trust_hex(rpc_value):
    """RPC trust (hex without leading zeros, '' for zero) in dump form."""
    return "0x" + (rpc_value if rpc_value else "0")


def nfactor_for(version, time):
    """N-factor of the scrypt header hash (CBlockHeader::CalculateHash)."""
    if version >= 7:
        return 4  # nFactorAtHardfork in the functional tests
    steps = [1368515488, 1368777632, 1369039776, 1369826208, 1370088352, 1372185504]
    for i, step in enumerate(steps):
        if time < step:
            return 4 + i
    raise AssertionError("time %d beyond the steps this test expects" % time)


def read_dump(path):
    """Parse a dump: (meta dict, header list, rows as dicts, trailer dict)."""
    meta, header, rows, trailer = {}, None, [], None
    with open(path, encoding="utf8") as f:
        lines = f.read().split("\n")
    assert_equal(lines[-1], "")  # ends with a newline
    lines = lines[:-1]
    assert lines[0].startswith("# format=yacoin-consensus-dump version=1 "), lines[0]
    for line in lines:
        if line.startswith("# end "):
            assert trailer is None
            trailer = dict(t.split("=", 1) for t in line[2:].split()[1:])
        elif line.startswith("#"):
            assert header is None, "comment after the header: " + line
            meta.update(t.split("=", 1) for t in line[1:].split() if "=" in t)
        elif header is None:
            header = line.split(",")
        else:
            assert trailer is None, "row after the trailer"
            fields = line.split(",")
            assert_equal(len(fields), len(header))
            rows.append(dict(zip(header, fields)))
    return meta, header, rows, trailer


class DumpConsensusValuesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.mocktime = TIME_GENESIS_BLOCK
        self.block_fork_1_0 = FORK_HEIGHT

    def mine(self, n):
        node = self.nodes[0]
        for _ in range(n):
            self.mocktime += 60
            node.setmocktime(self.mocktime)
            node.generate(1)

    def run_test(self):
        node = self.nodes[0]
        datadir = node.datadir

        self.log.info("Mine across the fork and the epoch boundaries")
        self.mine(34)  # heights 1..34: fork at 15, boundaries 20 and 30
        # Post-fork coinbase maturity is 6: spend one to get a block with fees.
        txid = node.sendtoaddress(node.getnewaddress(), 1)
        self.mine(1)  # height 35 contains txid
        fee_height = node.getblockcount()
        assert txid in node.getblock(node.getblockhash(fee_height))["tx"]
        self.mine(6)  # up to 41: boundary 40
        tip = node.getblockcount()
        assert_equal(tip, 41)

        self.log.info("Hidden: not in help, but help for the command works")
        assert "dumpconsensusvalues" not in node.help()
        assert node.help("dumpconsensusvalues").startswith("dumpconsensusvalues \"filename\"")

        self.log.info("Dump the whole chain (relative path = data directory)")
        res = node.dumpconsensusvalues("dump.csv")
        path = os.path.join(datadir, "dump.csv")
        assert_equal(os.path.abspath(res["filename"]), os.path.abspath(path))
        assert os.path.isfile(path)
        assert not os.path.exists(path + ".incomplete")
        assert_equal(res["rows"], tip + 1)
        assert_equal(res["start_height"], 0)
        assert_equal(res["end_height"], tip)
        assert_equal(res["end_hash"], node.getbestblockhash())
        for counter in ["pos_blocks", "kernel_failed", "kernel_hash_mismatch", "kernel_rehash_mismatch",
                        "kernel_modifier_after_prev", "fees_mismatch", "coinbase_over_reward",
                        "coinstake_over_limit", "pos_without_coinstake", "coinstake_in_pow_block",
                        "nfactor_mismatch"]:
            assert_equal(res[counter], 0)
        # Two header layouts at N-factor 4: version < 7 by time, version 7
        # by nFactorAtHardfork.
        assert_equal(res["nfactor_checked"], 2)

        meta, header, rows, trailer = read_dump(path)
        assert_equal(header, COLUMNS)
        assert_equal(header[:13], INDEX_CHAIN_COLUMNS)
        assert_equal(meta["format"], "yacoin-consensus-dump")
        assert_equal(meta["version"], "1")
        assert_equal(meta["chain"], "main")
        assert_equal(meta["lowdiff"], "1")
        assert_equal(meta["fork_height"], str(FORK_HEIGHT))
        assert_equal(meta["nfactor_at_hardfork"], "4")
        assert_equal(meta["epoch_interval"], str(EPOCH_INTERVAL))
        assert_equal(meta["start_height"], "0")
        assert_equal(meta["end_height"], str(tip))
        assert_equal(trailer, {"rows": str(tip + 1), "end_hash": node.getbestblockhash()})
        assert_equal(len(rows), tip + 1)

        self.log.info("Compare every row with getblock/getblockheader")
        min_ease = POW_LIMIT_BITS
        required_mismatch = 0
        prev = None
        for h, row in enumerate(rows):
            block_hash = node.getblockhash(h)
            hdr = node.getblockheader(block_hash)
            blk = node.getblock(block_hash, 2)
            assert_equal(int(row["height"]), h)
            assert_equal(row["hash"], block_hash)
            assert_equal(row["prev_hash"], hdr.get("previousblockhash", ""))
            assert_equal(int(row["time"]), hdr["time"])
            assert_equal(row["bits"], "0x" + hdr["bits"])
            assert_equal(int(row["version"]), hdr["version"])
            assert_equal(int(row["nonce"]), hdr["nonce"])
            assert_equal(row["merkle_root"], hdr["merkleroot"])
            flags = int(row["flags"])
            assert_equal(flags & 1, 0)
            assert_equal((flags >> 1) & 1, blk["entropybit"])
            assert_equal(bool(flags & 4), "stake-modifier" in blk["flags"])
            assert_equal(row["stake_modifier"], "0x" + blk["modifier"])
            assert_equal(row["hash_proof_of_stake"], "")
            assert_equal(row["prevout_stake"], "")
            assert_equal(row["stake_time"], "")
            assert_equal(int(row["nfactor"]), nfactor_for(hdr["version"], hdr["time"]))
            assert_equal(row["is_pos"], "0")
            assert_equal(int(row["median_time_past"]), hdr["mediantime"])
            assert_equal(row["block_trust"], trust_hex(blk["blocktrust"]))
            assert_equal(row["chain_trust"], trust_hex(blk["chaintrust"]))
            assert_equal(row["stake_modifier_checksum"], "0x" + blk["modifierchecksum"])
            for col in POS_COLUMNS:
                assert_equal(row[col], "")
            assert_equal(int(row["tx_count"]), len(blk["tx"]))
            assert_equal(int(row["block_size"]), blk["size"])
            coinbase = sum(amount(out["value"]) for out in blk["tx"][0]["vout"])
            assert_equal(int(row["coinbase_value"]), coinbase)
            assert_equal(int(row["mint"]), amount(blk["mint"]))
            assert_equal(int(row["money_supply"]), amount(blk["money supply"]))

            if h == 0:
                for col in ["prev_hash", "required_bits", "min_bits_since_fork", "fees", "pow_reward",
                            "max_block_size", "max_sigops"]:
                    assert_equal(row[col], "")
                prev = row
                continue

            # Mined coinbases pay to a script with a signature check.
            assert_greater_than(int(row["sigops"]), 0)
            # Chain trust accumulates the block trust.
            assert_equal(int(row["chain_trust"], 16), int(prev["chain_trust"], 16) + int(row["block_trust"], 16))
            # Fees from the undo data equal mint - money supply change.
            fees = int(row["fees"])
            assert_equal(fees, int(row["mint"]) - (int(row["money_supply"]) - int(prev["money_supply"])))
            assert_equal(fees > 0, h == fee_height)
            # Coinbase within the reward (for PoW blocks mint == coinbase).
            assert_equal(int(row["mint"]), coinbase)
            assert int(row["coinbase_value"]) <= int(row["pow_reward"])
            if h < FORK_HEIGHT:
                assert_equal(row["min_bits_since_fork"], "")
                assert_equal(int(row["max_block_size"]), MAX_GENESIS_BLOCK_SIZE)
                assert_equal(int(row["max_sigops"]), MAX_GENESIS_BLOCK_SIZE // 50)
            else:
                # nMinEase of a node validating block h: fork..h-1.
                assert_equal(row["min_bits_since_fork"], "0x%08x" % min_ease)
                min_ease = min(min_ease, int(row["bits"], 16))
                # After the fork the reward ignores fees; max size = reward * 1000 / MIN_TX_FEE.
                assert_equal(int(row["max_block_size"]), int(row["pow_reward"]) * 1000 // 10000)
                assert_equal(int(row["max_sigops"]), max(int(row["max_block_size"]), MAX_GENESIS_BLOCK_SIZE) // 50)
            # The required target equals nBits except possibly at post-fork
            # epoch boundaries, where today's value depends on the tip (B7).
            if row["required_bits"] != row["bits"]:
                assert h > FORK_HEIGHT and h % EPOCH_INTERVAL == 0, "required_bits differs at height %d" % h
                required_mismatch += 1
            prev = row
        assert_equal(res["required_bits_mismatch"], required_mismatch)
        self.log.info("required_bits differs from nBits at %d epoch boundaries" % required_mismatch)
        assert_equal(rows[-1]["header_sha256"], node.getbestblockhashsha256())

        self.log.info("A second dump is byte for byte identical")
        node.dumpconsensusvalues(os.path.join(datadir, "dump2.csv"))
        with open(path, "rb") as f1, open(os.path.join(datadir, "dump2.csv"), "rb") as f2:
            assert f1.read() == f2.read()

        self.log.info("A range gives the same rows")
        res = node.dumpconsensusvalues("range.csv", 12, 31)
        assert_equal(res["rows"], 20)
        assert_equal(res["end_hash"], node.getblockhash(31))
        rmeta, rheader, rrows, rtrailer = read_dump(os.path.join(datadir, "range.csv"))
        assert_equal((rmeta["start_height"], rmeta["end_height"]), ("12", "31"))
        assert_equal(rrows, rows[12:32])
        assert_equal(rtrailer, {"rows": "20", "end_hash": node.getblockhash(31)})
        res = node.dumpconsensusvalues("one.csv", tip, tip)
        assert_equal(res["rows"], 1)

        self.log.info("Errors")
        assert_raises_rpc_error(-8, "file already exists", node.dumpconsensusvalues, "dump.csv")
        assert_raises_rpc_error(-8, "invalid height range 5..4", node.dumpconsensusvalues, "x.csv", 5, 4)
        assert_raises_rpc_error(-8, "invalid height range -1..", node.dumpconsensusvalues, "x.csv", -1)
        assert_raises_rpc_error(-8, "invalid height range 0..42 (tip 41)", node.dumpconsensusvalues, "x.csv", 0, tip + 1)
        assert_raises_rpc_error(-8, "filename must not be empty", node.dumpconsensusvalues, "")
        assert not os.path.exists(os.path.join(datadir, "x.csv"))


if __name__ == '__main__':
    DumpConsensusValuesTest().main()
