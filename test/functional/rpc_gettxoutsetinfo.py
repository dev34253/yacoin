#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the RPC gettxoutsetinfo (task P0-48).

Two nodes with different options (node 1 has -tokenindex) follow the same
chain. Checks that identical chainstates give identical results, that the
UTXO hash changes with every block, that a token issue changes the token
hash, that the result survives a restart, and that disconnecting a block
restores the earlier result. The hash definitions are in the RPC help and
doc/functional-specification.md (section 7).
"""

from decimal import Decimal

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_is_hash_string,
    assert_raises_rpc_error,
    connect_nodes,
)

TOKEN_SUPPORT_HEIGHT = 10
KEYS = ["height", "bestblock", "transactions", "txouts", "bogosize", "hash_serialized",
        "disk_size", "total_amount", "tokens", "hash_tokens"]


def comparable(info):
    """Result without disk_size, which depends on the node's database layout."""
    return {k: v for k, v in info.items() if k != "disk_size"}


class GetTxOutSetInfoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [
            ["-tokenSupportBlockNumber=%d" % TOKEN_SUPPORT_HEIGHT],
            ["-tokenSupportBlockNumber=%d" % TOKEN_SUPPORT_HEIGHT, "-tokenindex=1"],
        ]
        self.mocktime = TIME_GENESIS_BLOCK

    def mine(self, n):
        for _ in range(n):
            self.mocktime += 60
            for node in self.nodes:
                node.setmocktime(self.mocktime)
            self.nodes[0].generate(1)
        self.sync_all()

    def info_both(self):
        """gettxoutsetinfo of both nodes; checks they agree and returns node 0's."""
        a, b = (node.gettxoutsetinfo() for node in self.nodes)
        assert_equal(comparable(a), comparable(b))
        return a

    def check_utxo_totals(self, info):
        """txouts/total_amount against the outputs of every block (blocks 1..tip)."""
        node = self.nodes[0]
        created = {}
        spent = set()
        for height in range(1, info["height"] + 1):
            block = node.getblock(node.getblockhash(height), 2)
            for tx in block["tx"]:
                for vin in tx["vin"]:
                    if "txid" in vin:
                        spent.add((vin["txid"], vin["vout"]))
                for vout in tx["vout"]:
                    created[(tx["txid"], vout["n"])] = (vout["value"], vout["scriptPubKey"].get("type"))
        unspent = {k: v for k, v in created.items() if k not in spent and v[1] != "nulldata"}
        assert_equal(info["txouts"], len(unspent))
        assert_equal(info["transactions"], len({k[0] for k in unspent}))
        assert_equal(Decimal(str(info["total_amount"])), sum(Decimal(str(v[0])) for v in unspent.values()))

    def run_test(self):
        n0 = self.nodes[0]

        self.log.info("Help text and argument check")
        assert "gettxoutsetinfo" in n0.help()
        assert "hash_serialized" in n0.help("gettxoutsetinfo")
        assert_raises_rpc_error(-1, "gettxoutsetinfo", n0.gettxoutsetinfo, 1)

        self.log.info("Genesis: both nodes agree")
        genesis = self.info_both()
        assert_equal(sorted(genesis.keys()), sorted(KEYS))
        assert_equal(genesis["height"], 0)
        assert_equal(genesis["bestblock"], n0.getblockhash(0))
        assert_is_hash_string(genesis["hash_serialized"])
        assert_is_hash_string(genesis["hash_tokens"])
        assert_equal(genesis["tokens"], 0)

        self.log.info("Mine 30 blocks: hash changes with every block, nodes agree")
        seen = {genesis["hash_serialized"]}
        for _ in range(30):
            self.mine(1)
            info = self.info_both()
            assert info["hash_serialized"] not in seen
            seen.add(info["hash_serialized"])
        assert_equal(info["height"], 30)
        assert_equal(info["bestblock"], n0.getbestblockhash())
        assert_greater_than(info["bogosize"], 0)
        # LevelDB's size estimate covers table files only; a small chainstate
        # still in the write-ahead log reports 0.
        assert isinstance(info["disk_size"], int) and info["disk_size"] >= 0
        assert_equal(info["tokens"], 0)
        self.check_utxo_totals(info)
        # Reading again without a new block gives the same result.
        assert_equal(comparable(n0.gettxoutsetinfo()), comparable(info))

        self.log.info("Spend: a wallet transaction changes the UTXO set")
        n0.sendtoaddress(self.nodes[1].getnewaddress(), 5)
        self.mine(1)
        info = self.info_both()
        self.check_utxo_totals(info)
        before_issue = info

        self.log.info("Issue a token: token hash changes, both nodes agree (node 1 has -tokenindex)")
        n0.issue("P048_TOKEN", 1000, 4, True, False, "", n0.getnewaddress(), "")
        self.mine(1)
        after_issue = self.info_both()
        assert_greater_than(after_issue["tokens"], 0)
        assert after_issue["hash_tokens"] != before_issue["hash_tokens"]
        assert after_issue["hash_serialized"] != before_issue["hash_serialized"]
        self.check_utxo_totals(after_issue)
        self.log.info("tokens after issue: %d" % after_issue["tokens"])

        self.log.info("Restart both nodes: results unchanged")
        self.stop_nodes()
        self.start_nodes()
        connect_nodes(self.nodes[0], 1)
        restarted = self.info_both()
        assert_equal(comparable(restarted), comparable(after_issue))

        self.log.info("Disconnect the issue block on node 0: earlier result restored")
        n0 = self.nodes[0]
        n0.invalidateblock(n0.getbestblockhash())
        assert_equal(n0.getblockcount(), before_issue["height"])
        assert_equal(comparable(n0.gettxoutsetinfo()), comparable(before_issue))


if __name__ == '__main__':
    GetTxOutSetInfoTest().main()
