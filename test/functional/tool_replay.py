#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test contrib/replay/replay.py: run, snapshot, digest and compare on a
real node.

Builds a chain of about 150 blocks with wallet payments and a restart in
the middle, stops the node and takes the digest of its data directory.
A run on a copy of its block files reaches the same tip and digest without
failures and compare calls the two reports identical; a run stopped at a
lower height differs from the first after that height. The coins section
holds exactly the outputs gettxout calls unspent, and every height row the
mint of getblock. The run's node command line has the options the script
sets, and the source block directory is not changed. run refuses an
existing output directory and a port in use.

snapshot refuses the run stopped at a lower height. The node mines on with
wallet payments. A run up to a height H below the tip, with the node's data
directory as the chain, gets the main-chain blocks 0 to H in height order
and ends at H; snapshot makes a snapshot of it. A snapshot run on the
node's block files gets the main-chain blocks above H in height order,
reaches the node's tip and digest and compares identical with the node and
with a full run, also when the tip is stored before its parent in the
block files; stopped at a height above H it ends there. The snapshot's
files are unchanged by the runs. A full run on block files with an added
block that is not valid is incomplete with that block not in the block
index. run --snapshot refuses a directory without snapshot.json and a run
without --chain.
"""

import hashlib
import json
import os
import shutil
import socket
import stat
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


def tree_state(path):
    """Per path under path (directories included): mode, mtime, and the
    size and SHA-256 of a file."""
    out = {}
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            full = os.path.join(root, name)
            st = os.lstat(full)
            entry = (st.st_mode, st.st_mtime_ns)
            if name in files:
                with open(full, "rb") as f:
                    entry += (st.st_size, hashlib.sha256(f.read()).hexdigest())
            out[os.path.relpath(full, path)] = entry
    return out


def block_records(directory):
    """The blocks of the records in blk00000.dat, blk00001.dat, ... of
    directory, in file order."""
    out = []
    n = 0
    while os.path.exists(os.path.join(directory, "blk%05d.dat" % n)):
        with open(os.path.join(directory, "blk%05d.dat" % n), "rb") as f:
            data = f.read()
        pos = 0
        while pos < len(data):
            size = int.from_bytes(data[pos + 4:pos + 8], "little")
            out.append(data[pos + 8:pos + 8 + size])
            pos += 8 + size
        n += 1
    return out


def make_writable(path):
    for root, dirs, files in os.walk(path):
        os.chmod(root, os.stat(root).st_mode | stat.S_IWUSR)
        for name in files:
            os.chmod(os.path.join(root, name), os.stat(os.path.join(root, name)).st_mode | stat.S_IWUSR)


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
        assert_equal(rep["mode"], "full")
        assert_equal(rep["snapshot"], None)
        assert_equal(rep["blocks_above_snapshot"], None)
        assert_equal(rep["block_file_check"], {"blocks": tip_height + 1, "not_in_index": 0, "stored_above_tip": None})

        self.log.info("snapshot refuses the run made with --stop-at-height")
        _, err = self.replay("snapshot", run2, self.out("snap-refused"), expect=2)
        assert "--stop-at-height" in err, err
        assert not os.path.exists(self.out("snap-refused"))

        self.log.info("The node mines on with wallet payments")
        self.start_node(0)
        self.pay(node, addresses, 3)
        new_tip_height = node.getblockcount()
        new_tip_hash = node.getbestblockhash()
        assert_greater_than(new_tip_height, tip_height + 10)
        raw = [bytes.fromhex(node.getblock(node.getblockhash(h), False)) for h in range(new_tip_height + 1)]
        self.stop_node(0)
        self.replay("digest", node.datadir, self.out("node2"))
        node2_report = self.report_mod.load(self.out("node2"))
        node2 = node2_report.report
        assert_equal(node2["tip"], {"height": new_tip_height, "hash": new_tip_hash})
        node_args[-1] = "-mocktime=%d" % node.mocktime
        chain = {"datadir": node.datadir, "height": new_tip_height, "hash": new_tip_hash}

        self.log.info("A run up to a height below the tip, with the node's data directory as the chain")
        height = tip_height - 20
        run_h = self.out("run-h")
        self.replay("run", "--up-to-height", str(height), "--chain", node.datadir, "--port", str(port),
                    "--rpcport", str(rpcport), self.binary, blocks, run_h, "--", *node_args)
        rep_h = self.report_mod.load(run_h).report
        assert_equal(rep_h["status"], "complete")
        assert_equal(rep_h["tip"], {"height": height, "hash": node2_report.rows[height].hash})
        assert_equal((rep_h["up_to_height"], rep_h["chain"]), (height, chain))
        assert_equal(rep_h["block_file_check"], {"blocks": height + 1, "not_in_index": 0, "stored_above_tip": None})
        assert "-reindex" in rep_h["command"]
        # The node got the main-chain blocks 0 to H in height order.
        assert_equal(block_records(os.path.join(run_h, "datadir", "blocks")), raw[:height + 1])
        out, _ = self.replay("compare", self.out("node2"), run_h, expect=1)
        assert_equal(out.splitlines()[0], "first difference at height %d: only in A" % (height + 1))

        self.log.info("snapshot of the run up to H")
        snap = self.out("snap")
        out, _ = self.replay("snapshot", run_h, snap)
        assert_equal(out, "snapshot at height %d %s, digest %s\n" % (height, rep_h["tip"]["hash"], rep_h["digest"]))
        with open(os.path.join(snap, "snapshot.json")) as f:
            meta = json.load(f)
        assert_equal((meta["height"], meta["digest"], meta["up_to_height"]), (height, rep_h["digest"], height))
        assert_equal((meta["failures"], meta["failure_blocks"], meta["failures_off_main_chain"]), (0, 0, 0))
        assert_equal(sorted({p.split(os.sep)[0] for p in meta["manifest"]}), ["blocks", "chainstate", "tokens"])
        snap_state = tree_state(snap)
        for path, entry in snap_state.items():
            assert_equal((path, entry[0] & 0o222), (path, 0))

        self.log.info("Snapshot run on the node's block files")
        run3 = self.out("run3")
        self.replay("run", "--snapshot", snap, "--chain", node.datadir, "--port", str(port), "--rpcport", str(rpcport),
                    self.binary, blocks, run3, "--", *node_args)
        rep3 = self.report_mod.load(run3).report
        assert_equal(rep3["status"], "complete")
        assert_equal(rep3["incomplete_reasons"], [])
        assert_equal(rep3["exit_status"], 0)
        assert_equal(rep3["mode"], "snapshot")
        assert_equal(rep3["snapshot"], {"path": snap, "height": height, "hash": rep_h["tip"]["hash"],
                                        "digest": rep_h["digest"], "binary": rep_h["binary"]})
        assert_equal(rep3["snapshot"]["binary"]["path"], self.binary)
        assert_equal(rep3["chain"], chain)
        assert_equal(rep3["blocks_above_snapshot"], new_tip_height - height)
        assert_equal(rep3["tip"], node2["tip"])
        assert_equal(rep3["digest"], node2["digest"])
        assert_equal((rep3["failures"], rep3["failure_blocks"]), (0, 0))
        assert_equal(rep3["block_file_check"], {"blocks": new_tip_height - height, "not_in_index": 0,
                                                "stored_above_tip": None})
        # The import files hold the main-chain blocks above H in height order.
        import_dir = os.path.join(run3, "import")
        assert_equal(block_records(import_dir), raw[height + 1:])
        datadir3 = os.path.join(run3, "datadir")
        imports = sorted(os.path.join(import_dir, n) for n in os.listdir(import_dir))
        assert_equal(rep3["command"], [
            self.binary, "-datadir=" + datadir3, "-conf=" + os.path.join(datadir3, "yacoin.conf"),
            "-daemon=0", "-replayvalidation=report",
            "-connect=0", "-listen=0", "-dnsseed=0", "-discover=0", "-upnp=0", "-listenonion=0",
            "-server=0", "-disablewallet", "-printtoconsole=0",
            "-port=%d" % port, "-rpcport=%d" % rpcport] + ["-loadblock=" + p for p in imports] * 2 + node_args)
        out, _ = self.replay("compare", self.out("node2"), run3)
        assert_equal(out, "identical\n")

        self.log.info("The full replay in two parts compares identical with a full run")
        run4 = self.out("run4")
        self.replay("run", "--port", str(port), "--rpcport", str(rpcport), self.binary, blocks, run4,
                    "--", *node_args)
        out, _ = self.replay("compare", run4, run3)
        assert_equal(out, "identical\n")

        self.log.info("Snapshot run stopped at a height below the tip")
        stop = height + 5
        run5 = self.out("run5")
        self.replay("run", "--snapshot", snap, "--chain", node.datadir, "--stop-at-height", str(stop),
                    "--port", str(port), "--rpcport", str(rpcport), self.binary, blocks, run5, "--", *node_args)
        rep5 = self.report_mod.load(run5).report
        assert_equal(rep5["status"], "complete")
        assert_equal(rep5["exit_status"], 1)
        assert_equal(rep5["blocks_above_snapshot"], 5)
        assert_equal(rep5["tip"], {"height": stop, "hash": self.report_mod.load(run4).rows[stop].hash})
        out, _ = self.replay("compare", run4, run5, expect=1)
        assert_equal(out.splitlines()[0], "first difference at height %d: only in A" % (stop + 1))

        self.log.info("Snapshot run on block files with the tip stored before its parent")
        swapped = self.out("blocks-swapped")
        shutil.copytree(blocks, swapped)
        last = os.path.join(swapped, sorted(n for n in os.listdir(swapped) if n.startswith("blk"))[-1])
        with open(last, "rb") as f:
            data = f.read()
        parent_pos, tip_pos = data.rfind(raw[-2]), data.rfind(raw[-1])
        assert_equal(tip_pos - 8, parent_pos + len(raw[-2]))
        parent_record = data[parent_pos - 8:parent_pos + len(raw[-2])]
        tip_record = data[tip_pos - 8:tip_pos + len(raw[-1])]
        with open(last, "wb") as f:
            f.write(data[:parent_pos - 8] + tip_record + parent_record + data[tip_pos + len(raw[-1]):])
        run8 = self.out("run8")
        self.replay("run", "--snapshot", snap, "--chain", node.datadir, "--port", str(port), "--rpcport", str(rpcport),
                    self.binary, swapped, run8, "--", *node_args)
        assert_equal(block_records(os.path.join(run8, "import")), raw[height + 1:])
        out, _ = self.replay("compare", self.out("node2"), run8)
        assert_equal(out, "identical\n")

        self.log.info("The snapshot's files are unchanged")
        assert_equal(tree_state(snap), snap_state)

        self.log.info("A full run on block files with an added block that is not valid")
        bad_blocks = self.out("blocks-added")
        shutil.copytree(blocks, bad_blocks)
        names = sorted(n for n in os.listdir(bad_blocks) if n.startswith("blk"))
        last = os.path.join(bad_blocks, names[-1])
        with open(last, "rb") as f:
            data = f.read()
        pos = data.rfind(raw[-1])
        assert_greater_than(pos, 7)
        # The record's marker and size from the file, the block with only its
        # merkle root changed.
        changed = raw[-1][:36] + bytes(b ^ 0xff for b in raw[-1][36:68]) + raw[-1][68:]
        with open(last, "ab") as f:
            f.write(data[pos - 8:pos] + changed)
        run6 = self.out("run6")
        self.replay("run", "--port", str(port), "--rpcport", str(rpcport), self.binary, bad_blocks, run6,
                    "--", *node_args, expect=1)
        rep6 = self.report_mod.load(run6).report
        assert_equal(rep6["status"], "incomplete")
        assert_equal(rep6["block_file_check"]["not_in_index"], 1)
        assert "1 blocks of the block files are not in the block index" in rep6["incomplete_reasons"], rep6

        self.log.info("run --snapshot refuses a directory without snapshot.json and a run without --chain")
        _, err = self.replay("run", "--snapshot", self.out("node2"), "--chain", node.datadir, "--port", str(port),
                             "--rpcport", str(rpcport), self.binary, blocks, self.out("run7"), expect=2)
        assert "no snapshot.json" in err, err
        _, err = self.replay("run", "--snapshot", snap, "--port", str(port), "--rpcport", str(rpcport),
                             self.binary, blocks, self.out("run7"), expect=2)
        assert "--chain is needed with --snapshot" in err, err
        assert not os.path.exists(self.out("run7"))
        assert_equal(tree_state(snap), snap_state)
        # A snapshot is read-only; deleting it needs write permission.
        make_writable(snap)


if __name__ == '__main__':
    ToolReplayTest().main()
