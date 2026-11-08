#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test contrib/replay/replay.py: run, digest and compare on a real node.

Builds a chain of about 150 blocks with wallet payments and a restart in
the middle, stops the node and takes the digest of its data directory.
A run on a copy of its block files reaches the same tip and digest without
failures and compare calls the two reports identical; a run stopped at a
lower height differs from the first after that height. The coins section
holds exactly the outputs gettxout calls unspent, and every height row the
mint of getblock. The run's node command line has the options the script
sets, and the source block directory is not changed. run refuses an
existing output directory and a port in use.
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import NFACTOR_AT_HARDFORK, assert_equal, assert_greater_than, p2p_port, rpc_port


def snapshot(path):
    """Names, sizes and SHA-256 of every file under path."""
    out = {}
    for root, _, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            with open(full, "rb") as f:
                out[os.path.relpath(full, path)] = (os.path.getsize(full), hashlib.sha256(f.read()).hexdigest())
    return out


class ToolReplayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.block_fork_1_0 = 1

    def setup_replay(self):
        src = self.config["environment"]["SRCDIR"]
        self.script = os.path.join(src, "contrib", "replay", "replay.py")
        sys.path.insert(0, os.path.join(src, "contrib", "replay"))
        from replaylib import digest, report
        self.digest_mod = digest
        self.report_mod = report
        self.binary = os.path.abspath(self.options.bitcoind)

    def replay(self, *args, expect=0):
        p = subprocess.run([sys.executable, "-I", self.script] + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True)
        self.log.debug("replay.py %s: %d\n%s%s" % (args[0], p.returncode, p.stdout, p.stderr))
        assert_equal(p.returncode, expect)
        return p.stdout, p.stderr

    def out(self, name):
        return os.path.join(self.options.tmpdir, name)

    def pay(self, node, addresses, rounds):
        for _ in range(rounds):
            for i, address in enumerate(addresses):
                node.sendtoaddress(address, 1 + i)
            # A payment larger than any single coin spends several of them.
            balance = node.getbalance()
            if balance > 100:
                node.sendtoaddress(addresses[0], int(balance / 2))
            self.mine_with_mocktime(node, 5)

    def run_test(self):
        self.setup_replay()
        node = self.nodes[0]

        self.log.info("Build a chain with wallet payments and a restart")
        self.mine_with_mocktime(node, 30)
        addresses = [node.getnewaddress() for _ in range(3)]
        self.pay(node, addresses, 9)
        self.restart_node(0)
        self.pay(node, addresses, 15)
        assert_equal(node.getmempoolinfo()["size"], 0)
        tip_height = node.getblockcount()
        tip_hash = node.getbestblockhash()
        assert_greater_than(tip_height, 140)

        self.log.info("Collect the outputs of the main chain and their state")
        mints = {}
        outputs = set()
        unspent = set()
        spent = 0
        for height in range(tip_height + 1):
            block = node.getblock(node.getblockhash(height))
            mints[height] = int(Decimal(block["mint"]) * COIN)
            if height == 0:
                continue
            for txid in block["tx"]:
                tx = node.decoderawtransaction(node.getrawtransaction(txid))
                for vout in tx["vout"]:
                    outpoint = (txid, vout["n"])
                    outputs.add(outpoint)
                    if node.gettxout(txid, vout["n"]) is None:
                        spent += 1
                    else:
                        unspent.add(outpoint)
        assert_greater_than(spent, 10)

        self.log.info("digest refuses the data directory of a running node")
        _, err = self.replay("digest", node.datadir, self.out("refused"), expect=1)
        assert "in use by a running node" in err, err
        assert not os.path.exists(self.out("refused"))

        self.stop_node(0)
        blocks = os.path.join(node.datadir, "blocks")
        before = snapshot(blocks)
        for db in ("chainstate", os.path.join("blocks", "index")):
            sizes = {name[-4:]: size for name, (size, _) in snapshot(os.path.join(node.datadir, db)).items()}
            assert sizes.get(".ldb", 0) > 0 and sizes.get(".log", 0) > 0, (db, sizes)

        self.log.info("digest of the stopped node")
        self.replay("digest", node.datadir, self.out("node"))
        node_report = self.report_mod.load(self.out("node"))
        assert_equal(node_report.report["tip"], {"height": tip_height, "hash": tip_hash})
        assert_equal(node_report.report["status"], "complete")
        assert_equal(sorted(node_report.rows), list(range(tip_height + 1)))
        for height, row in node_report.rows.items():
            assert_equal(row.mint, mints[height])
        coins = {self.digest_mod.decode_coin_key(k) for k, _ in self.digest_mod.read_coins(node.datadir)}
        assert_equal(coins, unspent)
        assert coins < outputs
        assert_equal(node_report.report["sections"]["coins"]["count"], len(unspent))

        self.log.info("run on a copy of the node's block files")
        port, rpcport = p2p_port(1), rpc_port(1)
        node_args = ["-testnetNewLogicBlockNumber=%d" % self.block_fork_1_0, "-epochinterval=10",
                     "-nFactorAtHardfork=%d" % NFACTOR_AT_HARDFORK, "-mocktime=%d" % node.mocktime]
        run1 = self.out("run1")
        self.replay("run", "--port", str(port), "--rpcport", str(rpcport), self.binary, blocks, run1,
                    "--", *node_args)
        run_report = self.report_mod.load(run1)
        rep = run_report.report
        assert_equal(rep["status"], "complete")
        assert_equal(rep["incomplete_reasons"], [])
        assert_equal(rep["exit_status"], 0)
        assert_equal(rep["tip"], {"height": tip_height, "hash": tip_hash})
        assert_equal(rep["digest"], node_report.report["digest"])
        assert_equal(rep["sections"], node_report.report["sections"])
        assert_equal(run_report.rows, node_report.rows)
        assert_equal((rep["failures"], rep["failure_blocks"]), (0, 0))
        assert_equal(run_report.failures, [])
        assert rep["reindex_finished"] and rep["done_loading"]
        for field in ("wall_seconds", "cpu_seconds", "peak_rss_kib"):
            assert_greater_than(rep[field], 0)
        for phase in ("copy_seconds", "reindex_finished_seconds", "done_loading_seconds", "node_seconds",
                      "digest_seconds"):
            assert rep["phases"][phase] is not None, phase
        assert_equal(rep["binary"]["path"], self.binary)
        with open(self.binary, "rb") as f:
            assert_equal(rep["binary"]["sha256"], hashlib.sha256(f.read()).hexdigest())
        copied = [n for n in os.listdir(os.path.join(run1, "datadir", "blocks")) if n.startswith("blk")]
        assert_equal(sorted(copied), sorted(n for n in before if n.startswith("blk")))
        for name in copied:
            path = os.path.join(run1, "datadir", "blocks", name)
            assert not os.path.islink(path)
            assert os.stat(path).st_ino != os.stat(os.path.join(blocks, name)).st_ino

        self.log.info("The node's command line and the unchanged source")
        datadir = os.path.join(run1, "datadir")
        assert_equal(rep["command"], [
            self.binary, "-datadir=" + datadir, "-conf=" + os.path.join(datadir, "yacoin.conf"),
            "-daemon=0", "-reindex", "-replayvalidation=report",
            "-connect=0", "-listen=0", "-dnsseed=0", "-discover=0", "-upnp=0", "-listenonion=0",
            "-server=0", "-disablewallet", "-printtoconsole=0",
            "-port=%d" % port, "-rpcport=%d" % rpcport] + node_args)
        assert_equal(snapshot(blocks), before)

        self.log.info("compare: the run and the node's digest are identical")
        out, _ = self.replay("compare", self.out("node"), run1)
        assert_equal(out, "identical\n")
        out, _ = self.replay("compare", os.path.join(run1, "report.json"), self.out("node"))
        assert_equal(out, "identical\n")

        self.log.info("A run stopped at a lower height")
        stop = tip_height - 25
        run2 = self.out("run2")
        self.replay("run", "--port", str(port), "--rpcport", str(rpcport), "--stop-at-height", str(stop),
                    self.binary, blocks, run2, "--", *node_args)
        rep2 = self.report_mod.load(run2).report
        assert_equal(rep2["status"], "complete")
        assert_equal(rep2["tip"]["height"], stop)
        assert_equal(rep2["tip"]["hash"], node_report.rows[stop].hash)
        assert_equal(rep2["command"][-len(node_args) - 1:], ["-stopatheight=%d" % stop] + node_args)
        out, _ = self.replay("compare", run1, run2, expect=1)
        lines = out.splitlines()
        assert_equal(lines[0], "first difference at height %d: only in A" % (stop + 1))
        assert "sections that differ: chain, undo, coins" in lines, lines
        assert_equal(snapshot(blocks), before)

        self.log.info("run refuses an existing output directory and a port in use")
        _, err = self.replay("run", "--port", str(port), "--rpcport", str(rpcport), self.binary, blocks, run1,
                             expect=2)
        assert "output directory exists" in err, err
        for busy_option in ("--port", "--rpcport"):
            busy = p2p_port(2) if busy_option == "--port" else rpc_port(2)
            args = {"--port": port, "--rpcport": rpcport, busy_option: busy}
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", busy))
                s.listen(1)
                _, err = self.replay("run", "--port", str(args["--port"]), "--rpcport", str(args["--rpcport"]),
                                     self.binary, blocks, self.out("busy"), expect=2)
            assert "port %d is in use" % busy in err, err
            assert not os.path.exists(self.out("busy"))
        with open(os.path.join(run1, "report.json")) as f:
            assert_equal(json.load(f), rep)


if __name__ == '__main__':
    ToolReplayTest().main()
