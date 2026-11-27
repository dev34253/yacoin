"""Tests of the run and digest commands of contrib/replay
(replaylib/runner.py and replay.py) with a fake node.

The fake node is a Python script. Its behaviour comes from FAKE_MODE:

  normal     writes the reindex and start-up lines to debug.log, waits for
             SIGTERM, writes a synthetic data directory and exits 0
  stop       the same, but exits 1 on its own after "Done loading" (a node
             stopped by -stopatheight during the import)
  noreindex  writes "Done loading" without "Reindexing finished", waits for
             SIGTERM, exits 0
  error      exits 1 at once
  signal     ends itself with SIGKILL after the reindex line
  slow       writes the reindex line only; on SIGTERM it writes
             <datadir>/sigterm, takes 0.5 s, writes <datadir>/exited and
             exits 0
  gate       as normal, but waits after the reindex line until
             <datadir>/go exists
  extra      as normal, with a block in its block files that is not in
             its block index
  index-removed  as normal, without its blocks/index
  reject     logs two pairs of InvalidChainFound lines (invalid blocks
             at heights 3 and 4), waits FAKE_REJECT_WAIT seconds (default
             20), then goes on as normal
  reject-late  as normal, with the two pairs logged after "Done loading"
  reject-exit  logs the two pairs and exits 1 at once

Modes of a node started on a snapshot's copy (run --snapshot): first it
records every file of its data directory in <datadir>/files.json (SHA-256,
link count, inode), then

  import           logs "Importing blocks file" for every -loadblock,
                   appends to its copy of blocks/blk00000.dat, writes a
                   synthetic data directory with a tip at height 5, logs
                   "Done loading", waits for SIGTERM and exits 0
  import-missing   the same without the line of the last -loadblock
  import-unopened  logs "Could not open blocks file" for the first one
  import-stop      as import, but exits 1 on its own after "Done loading"
  import-reject    as import, with the two pairs and the wait of reject
                   after the "Importing blocks file" lines

Without SIGTERM it exits with status 3 after 20 s. It records its
arguments in <datadir>/args.json, its process id in
<datadir>/pid and its blocked-signal mask (SigBlk of /proc/self/status,
where there is one) in <datadir>/sigblk. With -regtest, <datadir> in all
of this is the regtest subdirectory of its -datadir, as for yacoind.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import errno
import gzip
import importlib.util
import io
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import replay_testutil as tu
from replaylib import compare, logscan, report, runner, snapshot

FAKE_NODE = r"""#!%(python)s -I
import json, os, signal, sys, time
sys.path.insert(0, %(testdir)r)
import replay_testutil as tu
import hashlib
datadir = [a.split("=", 1)[1] for a in sys.argv if a.startswith("-datadir=")][0]
if "-regtest" in sys.argv:
    datadir = os.path.join(datadir, "regtest")
    os.makedirs(datadir, exist_ok=True)
mode = os.environ["FAKE_MODE"]
files = {}
for root, _, names in os.walk(datadir):
    for name in names:
        full = os.path.join(root, name)
        with open(full, "rb") as f:
            st = os.stat(full)
            files[os.path.relpath(full, datadir)] = [hashlib.sha256(f.read()).hexdigest(), st.st_nlink, st.st_ino]
with open(os.path.join(datadir, "files.json"), "w") as f:
    json.dump(files, f)
with open(os.path.join(datadir, "args.json"), "w") as f:
    json.dump(sys.argv, f)
with open(os.path.join(datadir, "pid"), "w") as f:
    f.write(str(os.getpid()))
if os.path.exists("/proc/self/status"):
    with open("/proc/self/status") as status, open(os.path.join(datadir, "sigblk"), "w") as f:
        f.write([l.split()[1] for l in status if l.startswith("SigBlk:")][0])
stop = []
signal.signal(signal.SIGTERM, lambda *a: stop.append(1))
deadline = time.time() + 20  # a node that never gets SIGTERM ends a test, not hangs it
def log(line):
    with open(os.path.join(datadir, "debug.log"), "a") as f:
        f.write("2026-11-08 10:00:00 " + line + "\n")
def reject(wait):
    for h in (3, 4):
        log("InvalidChainFound: invalid block=%%s  height=%%d  trust=%%d  moneysupply=0.00  date=2026-11-08 10:00:00"
            "  moneysupply=0.00" %% (tu.fake_hash(h, 9)[::-1].hex(), h, h))
        log("InvalidChainFound:  current best=%%s  height=%%d  trust=%%d  moneysupply=0.00  date=2026-11-08 10:00:00"
            "  moneysupply=0.00" %% (tu.fake_hash(h - 1)[::-1].hex(), h - 1, h - 1))
    end = min(deadline, time.time() + wait)
    while time.time() < end:
        time.sleep(0.05)
reject_wait = float(os.environ.get("FAKE_REJECT_WAIT", "20"))
if mode == "error":
    sys.exit(1)
log("replayvalidation: mode report")
log("replayvalidation: failure height=2 block=%%s check=script tx=%%s input=0 error=test-error"
    %% (tu.fake_hash(2)[::-1].hex(), "d4" * 32))
log("replayvalidation: failure height=1 block=%%s check=script tx=- input=- error=test-error"
    %% tu.fake_hash(1, 5)[::-1].hex())
if mode == "signal":
    os.kill(os.getpid(), signal.SIGKILL)
if mode.startswith("import"):
    loads = [a.split("=", 1)[1] for a in sys.argv if a.startswith("-loadblock=")]
    for i, path in enumerate(loads):
        if mode == "import-unopened" and i == 0:
            log("Warning: Could not open blocks file %%s" %% path)
        elif mode != "import-missing" or i < len(loads) - 1:
            log("Importing blocks file %%s..." %% path)
    if mode == "import-reject":
        reject(reject_wait)
    try:
        with open(os.path.join(datadir, "blocks", "blk00000.dat"), "ab") as f:
            f.write(b"written by the node")
    except OSError as e:
        log("cannot write: %%s" %% e)
    for name in ("blocks", "chainstate", "tokens"):
        os.rename(os.path.join(datadir, name), os.path.join(datadir, name + ".snapshot"))
    tu.make_datadir(datadir, heights=5, blk=True)
    log("Done loading")
    if mode == "import-stop":
        sys.exit(1)
    while not stop and time.time() < deadline:
        time.sleep(0.05)
    sys.exit(0 if stop else 3)
if mode == "reject":
    reject(reject_wait)
if mode == "reject-exit":
    reject(0)
    sys.exit(1)
if mode != "noreindex":
    log("Reindexing finished")
if mode == "gate":
    while not os.path.exists(os.path.join(datadir, "go")) and time.time() < deadline:
        time.sleep(0.05)
if mode == "slow":
    while not stop and time.time() < deadline:
        time.sleep(0.05)
    if not stop:
        sys.exit(3)
    open(os.path.join(datadir, "sigterm"), "w").close()
    time.sleep(0.5)
    open(os.path.join(datadir, "exited"), "w").close()
    sys.exit(0)
os.rename(os.path.join(datadir, "blocks"), os.path.join(datadir, "blocks.copied"))
tu.make_datadir(datadir, heights=3, blk=True)
if mode == "index-removed":
    import shutil
    shutil.rmtree(os.path.join(datadir, "blocks", "index"))
if mode == "extra":
    with open(os.path.join(datadir, "blocks", "blk00000.dat"), "ab") as f:
        f.write(tu.block_record({"version": 7, "hash_prev": tu.fake_hash(3), "merkle": tu.fake_hash(4, salt=7),
                                 "time": 1700000300, "bits": 0x1e0fffff, "nonce": 0x4c39}))
log("Done loading")
if mode == "reject-late":
    reject(0)
if mode == "stop":
    sys.exit(1)
while not stop and time.time() < deadline:
    time.sleep(0.05)
sys.exit(0 if stop else 3)
"""


# Fixed values of report format 1: the keys of a run's report.json.
RUN_REPORT_KEYS = [
    "binary", "block_file_check", "block_files", "blocks_above_snapshot", "chain", "command", "cpu_seconds",
    "datadir", "digest", "digest_error", "done_loading", "end_time", "exit_signal", "exit_status", "failure_blocks",
    "failures", "failures_off_main_chain", "format", "incomplete_reasons", "kind", "mode", "peak_rss_kib", "phases",
    "reindex_finished", "sections", "snapshot", "source", "start_time", "status", "stop_at_height", "system_seconds",
    "tip", "up_to_height", "user_seconds", "wall_seconds"]
# The block the fake node of mode reject logs first as invalid.
REJECTED = tu.fake_hash(3, 9)[::-1].hex()
KILLED_REASON = "the node marked block %s at height 3 invalid; killed (--kill-at-first-invalid-block)" % REJECTED


def heights_text(out):
    with gzip.open(os.path.join(out, "heights.tsv.gz"), "rt") as f:
        return f.read()


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-run-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = os.path.join(self.tmp, "yacoind")
        with open(self.bin, "w") as f:
            f.write(FAKE_NODE % {"python": sys.executable, "testdir": tu.HERE})
        os.chmod(self.bin, stat.S_IRWXU)
        self.source = os.path.join(self.tmp, "source")
        os.makedirs(self.source)
        for n in (0, 1, 3):
            with open(os.path.join(self.source, "blk%05d.dat" % n), "wb") as f:
                f.write(b"block file %d" % n)
        with open(os.path.join(self.source, "rev00000.dat"), "wb") as f:
            f.write(b"undo")
        self.ports = self.free_ports()

    def free_ports(self):
        socks = [socket.socket() for _ in range(2)]
        for s in socks:
            s.bind(("127.0.0.1", 0))
        ports = [s.getsockname()[1] for s in socks]
        for s in socks:
            s.close()
        return ports

    def run_cli(self, mode, *args, out="out", extra=(), env=None):
        cmd = [sys.executable, "-I", tu.REPLAY_SCRIPT, "run", "--port", str(self.ports[0]),
               "--rpcport", str(self.ports[1])] + list(args) + [self.bin, self.source, os.path.join(self.tmp, out)]
        if extra:
            cmd += ["--"] + list(extra)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           env=dict(os.environ, FAKE_MODE=mode, **(env or {})), timeout=60)
        return p.returncode, p.stdout, p.stderr

    def report(self, out="out"):
        with open(os.path.join(self.tmp, out, "report.json")) as f:
            return json.load(f)

    def node_args(self, out="out", chain_dir=""):
        with open(os.path.join(self.tmp, out, "datadir", chain_dir, "args.json")) as f:
            return json.load(f)

    def test_complete_run(self):
        code, stdout, _ = self.run_cli("normal", "--dbcache", "300", extra=["-par=2"])
        self.assertEqual(code, 0, stdout)
        self.assertTrue(stdout.startswith("complete: tip 3 "), stdout)
        rep = self.report()
        datadir = os.path.join(self.tmp, "out", "datadir")
        self.assertEqual(rep["status"], "complete")
        self.assertEqual(rep["exit_status"], 0)
        self.assertEqual(rep["block_files"], {"count": 2, "bytes": 24})
        self.assertEqual(sorted(os.listdir(os.path.join(datadir, "blocks.copied"))), ["blk00000.dat", "blk00001.dat"])
        self.assertEqual(rep["command"], self.node_args())
        self.assertEqual(rep["command"], [
            self.bin, "-datadir=" + datadir, "-conf=" + os.path.join(datadir, "yacoin.conf"), "-daemon=0",
            "-reindex", "-replayvalidation=report", "-connect=0", "-listen=0", "-dnsseed=0", "-discover=0",
            "-upnp=0", "-listenonion=0", "-server=0", "-disablewallet", "-printtoconsole=0",
            "-port=%d" % self.ports[0], "-rpcport=%d" % self.ports[1], "-dbcache=300", "-par=2"])
        self.assertTrue(os.path.isfile(os.path.join(datadir, "yacoin.conf")))
        self.assertEqual((rep["failures"], rep["failure_blocks"], rep["failures_off_main_chain"]), (2, 2, 1))
        with open(os.path.join(self.tmp, "out", "failures.tsv")) as f:
            mains = [line.split("\t")[5] for line in f.read().splitlines()[1:]]
        self.assertEqual(mains, ["1", "0"])
        self.assertEqual(rep["tip"]["height"], 3)
        self.assertIsNone(rep["digest_error"])
        self.assertTrue(rep["reindex_finished"] and rep["done_loading"])
        for key in ("copy_seconds", "reindex_finished_seconds", "done_loading_seconds", "node_seconds",
                    "digest_seconds"):
            self.assertIsNotNone(rep["phases"][key], key)
        for key in ("wall_seconds", "cpu_seconds", "user_seconds", "system_seconds", "peak_rss_kib"):
            self.assertGreaterEqual(rep[key], 0, key)
        self.assertGreater(rep["peak_rss_kib"], 0)
        self.assertEqual(rep["binary"]["sha256"], runner.file_sha256(self.bin))
        self.assertEqual((rep["mode"], rep["snapshot"], rep["blocks_above_snapshot"]), ("full", None, None))
        self.assertNotIn("regtest", rep)
        self.assertNotIn("chain_seconds", rep["phases"])
        self.assertNotIn("above the snapshot", stdout)
        self.assertEqual(rep["block_file_check"], {"blocks": 4, "not_in_index": 0, "stored_above_tip": None})
        sigblk = os.path.join(datadir, "sigblk")
        if os.path.exists(sigblk):
            with open(sigblk) as f:
                mask = int(f.read(), 16)
            for sig in runner.STOP_SIGNALS:
                self.assertFalse(mask & (1 << (sig - 1)), "%s blocked in the node" % sig.name)
        self.assertEqual(sorted(os.listdir(self.source)), ["blk00000.dat", "blk00001.dat", "blk00003.dat",
                                                           "rev00000.dat"])

    def test_complete_run_on_regtest(self):
        code, stdout, stderr = self.run_cli("normal", "--regtest", "--dbcache", "300", extra=["-par=2"])
        self.assertEqual(code, 0, stdout + stderr)
        self.assertTrue(stdout.startswith("complete: tip 3 "), stdout)
        rep = self.report()
        datadir = os.path.join(self.tmp, "out", "datadir")
        chain_dir = os.path.join(datadir, "regtest")
        # The node command of a run on main with -regtest after -daemon=0.
        self.assertEqual(rep["command"], self.node_args(chain_dir="regtest"))
        self.assertEqual(rep["command"], [
            self.bin, "-datadir=" + datadir, "-conf=" + os.path.join(datadir, "yacoin.conf"), "-daemon=0",
            "-regtest", "-reindex", "-replayvalidation=report", "-connect=0", "-listen=0", "-dnsseed=0",
            "-discover=0", "-upnp=0", "-listenonion=0", "-server=0", "-disablewallet", "-printtoconsole=0",
            "-port=%d" % self.ports[0], "-rpcport=%d" % self.ports[1], "-dbcache=300", "-par=2"])
        self.assertIs(rep["regtest"], True)
        self.assertEqual(rep["datadir"], datadir)
        # The block files are copied into the chain directory, the node's
        # debug.log is read and the digest taken there.
        self.assertEqual(sorted(os.listdir(datadir)), ["regtest", "yacoin.conf"])
        self.assertEqual(sorted(os.listdir(os.path.join(chain_dir, "blocks.copied"))),
                         ["blk00000.dat", "blk00001.dat"])
        self.assertEqual(rep["status"], "complete")
        self.assertEqual((rep["failures"], rep["failure_blocks"], rep["failures_off_main_chain"]), (2, 2, 1))
        self.assertTrue(rep["reindex_finished"] and rep["done_loading"])
        self.assertEqual(rep["tip"]["height"], 3)
        self.assertEqual(rep["digest"], runner.digest_mod.compute(chain_dir).overall)
        self.assertEqual(rep["block_file_check"], {"blocks": 4, "not_in_index": 0, "stored_above_tip": None})
        # The same run without the option: the report has the same fields
        # but regtest.
        code, _, _ = self.run_cli("normal", "--dbcache", "300", out="main", extra=["-par=2"])
        self.assertEqual(code, 0)
        self.assertEqual(set(rep), set(self.report("main")) | {"regtest"})

    def test_block_not_in_the_index_is_incomplete(self):
        code, stdout, _ = self.run_cli("extra")
        self.assertEqual(code, 1)
        rep = self.report()
        self.assertEqual(rep["incomplete_reasons"], ["1 blocks of the block files are not in the block index"])
        self.assertEqual(rep["block_file_check"], {"blocks": 5, "not_in_index": 1, "stored_above_tip": None})
        self.assertIn("incomplete: 1 blocks of the block files are not in the block index", stdout)

    def test_stop_at_height_exit_status_1(self):
        code, stdout, _ = self.run_cli("stop", "--stop-at-height", "3")
        self.assertEqual(code, 0, stdout)
        rep = self.report()
        self.assertEqual((rep["status"], rep["exit_status"], rep["stop_at_height"]), ("complete", 1, 3))
        self.assertEqual(rep["command"][-1], "-stopatheight=3")

    def test_stop_at_height_other_tip_is_incomplete(self):
        code, stdout, _ = self.run_cli("stop", "--stop-at-height", "5")
        self.assertEqual(code, 1)
        self.assertIn("incomplete: tip height 3, not --stop-at-height 5", stdout)

    def test_exit_status_1_without_stop_at_height_is_incomplete(self):
        code, stdout, _ = self.run_cli("stop")
        self.assertEqual(code, 1)
        self.assertEqual(self.report()["incomplete_reasons"], ["node exit status 1"])

    def test_no_reindex_line_is_incomplete(self):
        code, stdout, _ = self.run_cli("noreindex")
        self.assertEqual(code, 1)
        self.assertEqual(self.report()["incomplete_reasons"], ["no \"Reindexing finished\" in debug.log"])
        self.assertIsNotNone(self.report()["digest"])

    def test_init_error_is_incomplete_without_digest(self):
        code, stdout, _ = self.run_cli("error", "--stop-at-height", "3")
        self.assertEqual(code, 1)
        rep = self.report()
        self.assertEqual(rep["incomplete_reasons"], [
            "node exit status 1", "no \"Reindexing finished\" in debug.log", "no digest"])
        self.assertIsNone(rep["digest"])
        self.assertIsNotNone(rep["digest_error"])
        self.assertEqual(rep["failures"], 0)

    def test_signal_is_incomplete(self):
        code, stdout, _ = self.run_cli("signal")
        self.assertEqual(code, 1)
        rep = self.report()
        self.assertEqual(rep["exit_signal"], "SIGKILL")
        self.assertIsNone(rep["exit_status"])
        self.assertIn("node ended by signal SIGKILL", rep["incomplete_reasons"])
        self.assertEqual(rep["failures_off_main_chain"], 2)

    def test_refusals(self):
        os.makedirs(os.path.join(self.tmp, "exists"))
        code, _, err = self.run_cli("normal", out="exists")
        self.assertEqual(code, 2)
        self.assertIn("output directory exists", err)
        self.assertEqual(os.listdir(os.path.join(self.tmp, "exists")), [])
        with socket.socket() as s:
            s.bind(("127.0.0.1", self.ports[1]))
            s.listen(1)
            code, _, err = self.run_cli("normal")
        self.assertEqual(code, 2)
        self.assertIn("port %d is in use" % self.ports[1], err)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out")))
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        with self.assertRaisesRegex(runner.RunRefused, "no blk00000.dat"):
            runner.check(self.bin, empty, os.path.join(self.tmp, "o"), *self.ports)
        with self.assertRaisesRegex(runner.RunRefused, "not an executable"):
            runner.check(os.path.join(self.source, "blk00000.dat"), self.source, os.path.join(self.tmp, "o"),
                         *self.ports)
        with self.assertRaisesRegex(runner.RunRefused, "same"):
            runner.check(self.bin, self.source, os.path.join(self.tmp, "o"), self.ports[0], self.ports[0])

    def test_stop_signal_stops_the_node_first(self):
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signal=sig.name):
                out = "out-" + sig.name
                datadir = os.path.join(self.tmp, out, "datadir")
                cmd = [sys.executable, "-I", tu.REPLAY_SCRIPT, "run", "--port", str(self.ports[0]),
                       "--rpcport", str(self.ports[1]), self.bin, self.source, os.path.join(self.tmp, out)]
                harness = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           universal_newlines=True, env=dict(os.environ, FAKE_MODE="slow"))
                deadline = time.monotonic() + 30
                while not os.path.exists(os.path.join(datadir, "debug.log")) and time.monotonic() < deadline:
                    time.sleep(0.05)
                with open(os.path.join(datadir, "debug.log")) as f:
                    while "Reindexing finished" not in f.read() and time.monotonic() < deadline:
                        time.sleep(0.05)
                        f.seek(0)
                harness.send_signal(sig)
                try:
                    stdout, stderr = harness.communicate(timeout=30)
                finally:
                    with open(os.path.join(datadir, "pid")) as f:
                        node_pid = int(f.read())
                    if not os.path.exists(os.path.join(datadir, "exited")):
                        try:
                            os.kill(node_pid, signal.SIGTERM)  # a fake node the harness left running
                        except ProcessLookupError:
                            pass
                self.assertEqual(harness.returncode, 128 + sig, stderr)
                self.assertIn("interrupted by %s; the node was stopped" % sig.name, stderr)
                # The node got SIGTERM and the harness waited for it to exit.
                self.assertTrue(os.path.exists(os.path.join(datadir, "sigterm")))
                self.assertTrue(os.path.exists(os.path.join(datadir, "exited")))
                self.assertFalse(os.path.exists(os.path.join(self.tmp, out, "report.json")))

    def wait_for_log(self, datadir, text):
        deadline = time.monotonic() + 30
        log = os.path.join(datadir, "debug.log")
        while time.monotonic() < deadline:
            if os.path.exists(log):
                with open(log) as f:
                    if text in f.read():
                        return
            time.sleep(0.05)
        self.fail("no %r in %s" % (text, log))

    def test_ignored_signal_stays_ignored(self):
        datadir = os.path.join(self.tmp, "out", "datadir")
        cmd = [sys.executable, "-I", tu.REPLAY_SCRIPT, "run", "--port", str(self.ports[0]),
               "--rpcport", str(self.ports[1]), self.bin, self.source, os.path.join(self.tmp, "out")]
        harness = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                   env=dict(os.environ, FAKE_MODE="gate"),
                                   preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_IGN))
        try:
            self.wait_for_log(datadir, "Reindexing finished")
            harness.send_signal(signal.SIGHUP)
            time.sleep(0.5)
            self.assertIsNone(harness.poll())
        finally:
            open(os.path.join(datadir, "go"), "w").close()
            stdout, stderr = harness.communicate(timeout=30)
        self.assertEqual(harness.returncode, 0, stderr)
        self.assertEqual(self.report()["status"], "complete")
        self.assertEqual(self.report()["exit_status"], 0)

    def assert_no_stop_signal_blocked(self):
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()) & set(runner.STOP_SIGNALS), set())

    def restore_default_handlers(self):
        signal.signal(signal.SIGINT, signal.default_int_handler)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGHUP, signal.SIG_DFL)

    def recording_handlers(self):
        """Installs a handler for each stop signal that records the signal
        and whether every stop signal has that handler; returns the list of
        records and the handler."""
        events = []

        def handler(signum, frame):
            events.append((signum, all(signal.getsignal(s) is handler for s in runner.STOP_SIGNALS)))

        for sig in runner.STOP_SIGNALS:
            signal.signal(sig, handler)
        self.addCleanup(self.restore_default_handlers)
        return events, handler

    def reap_node(self, datadir, pid=None):
        """Whether the run reaped the fake node of datadir, or the node pid
        (True when it started none); reaps a node the run left behind."""
        pid_path = os.path.join(datadir, "pid")
        if pid is None:
            if not os.path.exists(pid_path):
                return True
            with open(pid_path) as f:
                pid = int(f.read())
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if not done:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        return False

    def test_stop_signal_after_the_reap(self):
        # A stop signal that arrives right after the node was reaped: the
        # script neither signals nor waits for the node again, and the
        # caller's handler gets the signal once the handlers are restored.
        events, _ = self.recording_handlers()
        real_wait4 = os.wait4
        real_kill = os.kill
        calls = []
        sent = []

        def wait4(pid, options):
            calls.append(options)
            result = real_wait4(pid, options)
            if result[0]:
                real_kill(os.getpid(), signal.SIGTERM)
            return result

        def kill(pid, sig):
            sent.append(sig)
            real_kill(pid, sig)

        out = os.path.join(self.tmp, "out")
        with mock.patch.dict(os.environ, FAKE_MODE="normal"), mock.patch.object(runner.os, "wait4", wait4), \
                mock.patch.object(runner.os, "kill", kill):
            rep = runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None)
        self.assertEqual(set(calls), {os.WNOHANG})
        self.assertEqual(sent, [signal.SIGTERM])
        self.assertEqual(events, [(signal.SIGTERM, True)])
        self.assertEqual(rep["status"], "complete")
        self.assertTrue(os.path.exists(os.path.join(out, "report.json")))
        self.assert_no_stop_signal_blocked()

    def test_second_stop_signal_while_stopping_the_node(self):
        # The first SIGTERM arrives while the script waits for the node; a
        # second stop signal arrives as the script starts to stop the node
        # (before it ignores the stop signals) or as it sends the node
        # SIGTERM. The node is stopped and reaped, and the run raises
        # Interrupted for the first signal.
        for point in ("ignore", "kill"):
            for second in runner.STOP_SIGNALS:
                with self.subTest(point=point, second=second.name):
                    out = os.path.join(self.tmp, "out-%s-%s" % (point, second.name))
                    self.second_stop_signal(out, point, second)

    def second_stop_signal(self, out, point, second):
        datadir = os.path.join(out, "datadir")
        log_path = os.path.join(datadir, "debug.log")
        real_signal, real_kill, real_sleep = signal.signal, os.kill, time.sleep
        state = {"first": False, "second": False}

        def sleep(seconds):
            if not state["first"] and os.path.exists(log_path):
                with open(log_path) as f:
                    if "Reindexing finished" in f.read():
                        state["first"] = True
                        real_kill(os.getpid(), signal.SIGTERM)
            real_sleep(seconds)

        def send_second():
            if state["first"] and not state["second"]:
                state["second"] = True
                real_kill(os.getpid(), second)

        def fake_signal(sig, handler):
            if point == "ignore" and handler is signal.SIG_IGN:
                send_second()
            return real_signal(sig, handler)

        def kill(pid, sig):
            if point == "kill" and pid != os.getpid() and sig == signal.SIGTERM:
                send_second()
            real_kill(pid, sig)

        cm = None
        try:
            with mock.patch.dict(os.environ, FAKE_MODE="slow"), \
                    mock.patch.object(runner.signal, "signal", fake_signal), \
                    mock.patch.object(runner.os, "kill", kill), mock.patch.object(runner.time, "sleep", sleep):
                with self.assertRaises(runner.Interrupted) as cm:
                    runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None)
        finally:
            reaped = self.reap_node(datadir)
            handlers = [signal.getsignal(s) for s in runner.STOP_SIGNALS]
            self.restore_default_handlers()
        self.assertTrue(state["second"])
        self.assertEqual(cm.exception.signum, signal.SIGTERM)
        self.assertTrue(os.path.exists(os.path.join(datadir, "sigterm")))
        self.assertTrue(os.path.exists(os.path.join(datadir, "exited")))
        self.assertTrue(reaped)
        self.assertEqual(handlers, [signal.default_int_handler, signal.SIG_DFL, signal.SIG_DFL])
        self.assert_no_stop_signal_blocked()
        self.assertFalse(os.path.exists(os.path.join(out, "report.json")))

    def test_stop_signal_while_the_handlers_are_restored(self):
        # A stop signal that arrives after the run restored the first of the
        # caller's handlers: the run completes, and the caller's handler gets
        # the signal once, after every handler is restored.
        for sig in runner.STOP_SIGNALS:
            with self.subTest(signal=sig.name):
                events, handler = self.recording_handlers()
                real_signal = signal.signal
                sent = []

                def fake_signal(s, h):
                    result = real_signal(s, h)
                    if h is handler and not sent:
                        sent.append(s)
                        os.kill(os.getpid(), sig)
                    return result

                out = os.path.join(self.tmp, "out-" + sig.name)
                with mock.patch.dict(os.environ, FAKE_MODE="normal"), \
                        mock.patch.object(runner.signal, "signal", fake_signal):
                    rep = runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None)
                self.assertEqual(len(sent), 1)
                self.assertEqual(events, [(sig, True)])
                self.assertEqual(rep["status"], "complete")
                with open(os.path.join(out, "report.json")) as f:
                    self.assertEqual(json.load(f)["status"], "complete")
                self.assert_no_stop_signal_blocked()

    def test_stop_signal_while_the_handlers_are_installed(self):
        # SIGTERM arrives while the run installs its handlers: it is handled
        # once the node is started; the node is stopped and reaped.
        real_signal = signal.signal
        sent = []

        def fake_signal(sig, handler):
            if sig == signal.SIGHUP and getattr(handler, "__name__", None) == "interrupt":
                sent.append(sig)
                os.kill(os.getpid(), signal.SIGTERM)
            return real_signal(sig, handler)

        real_popen = subprocess.Popen
        started = []

        def popen(*args, **kwargs):
            started.append(real_popen(*args, **kwargs))
            return started[-1]

        out = os.path.join(self.tmp, "out")
        datadir = os.path.join(out, "datadir")
        cm = None
        try:
            with mock.patch.dict(os.environ, FAKE_MODE="normal"), \
                    mock.patch.object(runner.signal, "signal", fake_signal), \
                    mock.patch.object(runner.subprocess, "Popen", popen):
                with self.assertRaises(runner.Interrupted) as cm:
                    runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None)
        finally:
            reaped = [self.reap_node(datadir, p.pid) for p in started]
            handlers = [signal.getsignal(s) for s in runner.STOP_SIGNALS]
            self.restore_default_handlers()
        self.assertEqual(sent, [signal.SIGHUP])
        self.assertEqual(cm.exception.signum, signal.SIGTERM)
        self.assertEqual(handlers, [signal.default_int_handler, signal.SIG_DFL, signal.SIG_DFL])
        self.assert_no_stop_signal_blocked()
        # The node was started, stopped and reaped.
        self.assertEqual(reaped, [True])
        self.assertIsNotNone(started[0].returncode)
        self.assertFalse(os.path.exists(os.path.join(out, "report.json")))

    def test_stop_signal_when_the_node_cannot_be_started(self):
        # SIGTERM arrives while the node is started and the start fails: the
        # run writes the report of a node that cannot be started, and the
        # caller's handler gets the signal after the handlers are restored.
        events, _ = self.recording_handlers()

        def popen(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            raise OSError(errno.ENOEXEC, "Exec format error")

        out = os.path.join(self.tmp, "out")
        with mock.patch.object(runner.subprocess, "Popen", popen):
            rep = runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None)
        self.assertEqual(rep["incomplete_reasons"], ["cannot start the node: [Errno 8] Exec format error"])
        self.assertTrue(os.path.exists(os.path.join(out, "report.json")))
        self.assertEqual(events, [(signal.SIGTERM, True)])
        self.assert_no_stop_signal_blocked()

    def test_digest_exception_still_writes_the_report(self):
        out = os.path.join(self.tmp, "out")
        with mock.patch.dict(os.environ, FAKE_MODE="normal"), \
                mock.patch.object(runner.digest_mod, "compute", side_effect=MemoryError("test")):
            rep = runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None)
        self.assertEqual(rep["status"], "incomplete")
        self.assertEqual(rep["incomplete_reasons"], ["no digest"])
        self.assertEqual(rep["digest_error"], "MemoryError: test")
        with open(os.path.join(out, "report.json")) as f:
            written = json.load(f)
        self.assertEqual(written["digest_error"], "MemoryError: test")
        self.assertEqual(written["exit_status"], 0)
        self.assertEqual(written["failures"], 2)
        self.assertGreater(written["peak_rss_kib"], 0)
        # The signal handlers of the caller are back.
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)

    def test_one_read_of_the_block_index(self):
        out = os.path.join(self.tmp, "out")
        with mock.patch.dict(os.environ, FAKE_MODE="normal"), tu.IndexReads() as reads:
            rep = runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None)
        self.assertEqual(rep["status"], "complete")
        self.assertEqual(dict(reads.counts), {os.path.join(out, "datadir", "blocks", "index"): 1})
        with tu.IndexReads() as reads:
            runner.digest_only(os.path.join(out, "datadir"), os.path.join(self.tmp, "digest"))
        self.assertEqual(dict(reads.counts), {os.path.join(out, "datadir", "blocks", "index"): 1})

    def test_unreadable_block_index(self):
        code, stdout, _ = self.run_cli("index-removed")
        self.assertEqual(code, 1)
        rep = self.report()
        self.assertIn(os.path.join("blocks", "index"), rep["digest_error"])
        self.assertIsNone(rep["block_file_check"])
        self.assertEqual(rep["incomplete_reasons"], ["no digest"])

    def assert_killed(self, rep, out, stdout=None):
        """rep is the report of a run killed at the first block of mode
        reject, written in out."""
        self.assertEqual(rep["status"], "incomplete")
        self.assertEqual(rep["incomplete_reasons"][0], KILLED_REASON)
        self.assertIn("node ended by signal SIGKILL", rep["incomplete_reasons"])
        self.assertEqual((rep["exit_status"], rep["exit_signal"]), (None, "SIGKILL"))
        self.assertEqual((rep["kill_at_first_invalid_block"], rep["invalid_block"]),
                         (True, {"height": 3, "hash": REJECTED}))
        for key in ("digest", "digest_error", "tip", "block_file_check"):
            self.assertIsNone(rep[key], key)
        self.assertEqual(rep["sections"], {})
        self.assertNotIn("digest_seconds", rep["phases"])
        self.assertEqual((rep["failures"], rep["failure_blocks"], rep["failures_off_main_chain"]), (2, 2, 2))
        self.assertFalse(os.path.exists(os.path.join(out, "datadir")))
        self.assertFalse(os.path.exists(os.path.join(out, "import")))
        with open(os.path.join(out, "debug.log")) as f:
            self.assertIn("InvalidChainFound: invalid block=%s  height=3" % REJECTED, f.read())
        self.assertEqual(heights_text(out), report.HEIGHTS_HEADER)
        with open(os.path.join(out, "failures.tsv")) as f:
            self.assertEqual(len(f.read().splitlines()), 3)
        if stdout is not None:
            self.assertEqual(stdout, "incomplete: tip None None, digest None, 2 failures in 2 blocks\n" + "".join(
                "incomplete: %s\n" % reason for reason in rep["incomplete_reasons"]))

    def test_kill_at_first_invalid_block(self):
        code, stdout, stderr = self.run_cli("reject", "--kill-at-first-invalid-block")
        self.assertEqual(code, 1, stdout + stderr)
        rep = self.report()
        out = os.path.join(self.tmp, "out")
        self.assert_killed(rep, out, stdout)
        self.assertFalse(rep["done_loading"])
        self.assertEqual(sorted(os.listdir(out)), ["debug.log", "failures.tsv", "heights.tsv.gz", "node-stderr.log",
                                                   "node-stdout.log", "report.json"])
        self.assertIn("killing the node", stderr)

    def test_rejection_lines_without_the_option(self):
        code, stdout, stderr = self.run_cli("reject", env={"FAKE_REJECT_WAIT": "0"})
        self.assertEqual(code, 0, stdout + stderr)
        rep = self.report()
        self.assertEqual(sorted(rep), RUN_REPORT_KEYS)
        self.assertEqual((rep["status"], rep["incomplete_reasons"], rep["exit_status"]), ("complete", [], 0))
        self.assertTrue(rep["done_loading"])
        self.assertEqual(rep["tip"]["height"], 3)
        self.assertEqual(rep["block_file_check"], {"blocks": 4, "not_in_index": 0, "stored_above_tip": None})
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "out", "datadir", "chainstate")))

    def test_option_without_a_rejection(self):
        code, stdout, stderr = self.run_cli("normal", "--kill-at-first-invalid-block")
        self.assertEqual(code, 0, stdout + stderr)
        rep = self.report()
        self.assertEqual(sorted(rep), sorted(RUN_REPORT_KEYS + ["invalid_block", "kill_at_first_invalid_block"]))
        self.assertEqual((rep["kill_at_first_invalid_block"], rep["invalid_block"]), (True, None))
        self.assertEqual((rep["status"], rep["incomplete_reasons"]), ("complete", []))
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "out", "datadir", "chainstate")))

    def test_rejection_after_done_loading(self):
        code, stdout, stderr = self.run_cli("reject-late", "--kill-at-first-invalid-block")
        self.assertEqual(code, 0, stdout + stderr)
        rep = self.report()
        self.assertEqual((rep["status"], rep["incomplete_reasons"], rep["exit_status"]), ("complete", [], 0))
        self.assertEqual((rep["kill_at_first_invalid_block"], rep["invalid_block"]), (True, None))
        self.assertEqual(rep["tip"]["height"], 3)

    def test_kill_below_the_stop_height(self):
        code, stdout, stderr = self.run_cli("reject", "--kill-at-first-invalid-block", "--stop-at-height", "5")
        self.assertEqual(code, 1, stdout + stderr)
        rep = self.report()
        self.assert_killed(rep, os.path.join(self.tmp, "out"))
        self.assertEqual(rep["stop_at_height"], 5)
        self.assertIn("-stopatheight=5", rep["command"])

    def test_node_that_exits_after_the_rejection(self):
        code, stdout, stderr = self.run_cli("reject-exit", "--kill-at-first-invalid-block")
        self.assertEqual(code, 1, stdout + stderr)
        rep = self.report()
        self.assertEqual(rep["incomplete_reasons"][0],
                         "the node marked block %s at height 3 invalid (--kill-at-first-invalid-block)" % REJECTED)
        self.assertEqual((rep["exit_status"], rep["exit_signal"]), (1, None))
        self.assertEqual(rep["invalid_block"], {"height": 3, "hash": REJECTED})
        self.assertIsNone(rep["digest"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out", "datadir")))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, "out", "debug.log")))

    def test_stop_signal_after_the_kill(self):
        # The script gets SIGTERM right after it killed the node: it sends the
        # node nothing more, waits for it, removes the node's files as after
        # a kill and writes no report.
        real_kill = os.kill
        sent = []
        logged = []

        def kill(pid, sig):
            if pid != os.getpid():
                sent.append(sig)
            real_kill(pid, sig)
            if sig == signal.SIGKILL:
                real_kill(os.getpid(), signal.SIGTERM)

        out = os.path.join(self.tmp, "out")
        with mock.patch.dict(os.environ, FAKE_MODE="reject"), mock.patch.object(runner.os, "kill", kill):
            with self.assertRaises(runner.Interrupted) as cm:
                runner.run(self.bin, self.source, out, *self.ports, log=logged.append,
                           kill_at_first_invalid_block=True)
        self.assertEqual(cm.exception.signum, signal.SIGTERM)
        self.assertEqual(sent, [signal.SIGKILL])
        self.assertIn("waiting for the node (interrupted by SIGTERM; the node was stopped)", logged)
        self.assertEqual(sorted(os.listdir(out)), ["debug.log", "node-stderr.log", "node-stdout.log"])
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        self.assert_no_stop_signal_blocked()

    def test_stop_signal_as_the_node_is_killed(self):
        # SIGTERM arrives as the script is about to send the node SIGKILL
        # (when it looks up os.kill): the node is killed all the same, then
        # waited for and reaped, and the run raises Interrupted.
        real_os = os
        sent = []
        armed = [True]

        class OsProxy:
            def __getattr__(self, name):
                if name != "kill":
                    return getattr(real_os, name)
                if armed[0]:
                    armed[0] = False
                    real_os.kill(real_os.getpid(), signal.SIGTERM)
                    time.sleep(0)

                def kill(pid, sig):
                    sent.append(sig)
                    real_os.kill(pid, sig)
                return kill

        real_popen = subprocess.Popen
        started = []

        def popen(*args, **kwargs):
            started.append(real_popen(*args, **kwargs))
            return started[-1]

        out = os.path.join(self.tmp, "out")
        cm = None
        try:
            with mock.patch.dict(os.environ, FAKE_MODE="reject"), mock.patch.object(runner, "os", OsProxy()), \
                    mock.patch.object(runner.subprocess, "Popen", popen):
                with self.assertRaises(runner.Interrupted) as cm:
                    runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None,
                               kill_at_first_invalid_block=True)
        finally:
            reaped = [self.reap_node(os.path.join(out, "datadir"), p.pid) for p in started]
            handlers = [signal.getsignal(s) for s in runner.STOP_SIGNALS]
            self.restore_default_handlers()
        self.assertFalse(armed[0])
        self.assertEqual(cm.exception.signum, signal.SIGTERM)
        self.assertEqual(sent, [signal.SIGKILL])
        self.assertEqual(reaped, [True])
        self.assertEqual(started[0].returncode, -signal.SIGKILL)
        self.assertEqual(handlers, [signal.default_int_handler, signal.SIG_DFL, signal.SIG_DFL])
        self.assert_no_stop_signal_blocked()
        self.assertEqual(sorted(os.listdir(out)), ["debug.log", "node-stderr.log", "node-stdout.log"])

    def test_nothing_sent_after_the_kill(self):
        # The kill reaches the node 2 s late, after its "Done loading": the
        # script sends no SIGTERM meanwhile.
        real_kill = os.kill
        sent = []

        def kill(pid, sig):
            sent.append(sig)
            if sig == signal.SIGKILL:
                threading.Timer(2, real_kill, (pid, sig)).start()
            else:
                real_kill(pid, sig)

        out = os.path.join(self.tmp, "out")
        with mock.patch.dict(os.environ, FAKE_MODE="reject", FAKE_REJECT_WAIT="0"), \
                mock.patch.object(runner.os, "kill", kill):
            rep = runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None,
                             kill_at_first_invalid_block=True)
        self.assertEqual(sent, [signal.SIGKILL])
        self.assertTrue(rep["done_loading"])
        self.assertEqual(rep["incomplete_reasons"][0], KILLED_REASON)

    def test_stop_signal_during_the_deletion(self):
        # SIGTERM during the deletion of OUT/datadir is handled when the
        # deletion is done.
        out = os.path.join(self.tmp, "out")
        datadir = os.path.join(out, "datadir")
        events = []
        old = signal.signal(signal.SIGTERM, lambda *args: events.append(("signal", os.path.exists(datadir))))
        self.addCleanup(signal.signal, signal.SIGTERM, old)
        real_rmtree = shutil.rmtree

        def rmtree(path, *args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            events.append(("rmtree", path))
            real_rmtree(path, *args, **kwargs)

        with mock.patch.dict(os.environ, FAKE_MODE="reject"), mock.patch.object(runner.shutil, "rmtree", rmtree):
            rep = runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None,
                             kill_at_first_invalid_block=True)
        self.assertEqual(events, [("rmtree", datadir), ("signal", False)])
        self.assertEqual(rep["incomplete_reasons"][0], KILLED_REASON)

    def test_stop_signal_after_the_node_ended(self):
        # SIGTERM after the killed node was reaped, while the script reads
        # the rest of its log: handled once OUT/datadir is deleted.
        out = os.path.join(self.tmp, "out")
        datadir = os.path.join(out, "datadir")
        events = []
        old = signal.signal(signal.SIGTERM, lambda *args: events.append(("signal", os.path.exists(datadir))))
        self.addCleanup(signal.signal, signal.SIGTERM, old)
        real_finish = logscan.LogFollower.finish

        def finish(follower):
            os.kill(os.getpid(), signal.SIGTERM)
            events.append(("finish", os.path.exists(datadir)))
            real_finish(follower)

        with mock.patch.dict(os.environ, FAKE_MODE="reject"), mock.patch.object(logscan.LogFollower, "finish", finish):
            rep = runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None,
                             kill_at_first_invalid_block=True)
        self.assertEqual(events, [("finish", True), ("signal", False)])
        self.assertEqual(rep["incomplete_reasons"][0], KILLED_REASON)
        # No stop signal is left blocked.
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()) & set(runner.STOP_SIGNALS), set())

    def test_option_reaches_the_run(self):
        spec = importlib.util.spec_from_file_location("replay_script", tu.REPLAY_SCRIPT)
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        rep = {"status": "complete", "tip": None, "digest": None, "failures": 0, "failure_blocks": 0,
               "incomplete_reasons": []}
        for args, value in (([], False), (["--kill-at-first-invalid-block"], True)):
            with mock.patch.object(script.runner, "run", return_value=rep) as run, \
                    mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(script.main(["run"] + args + [self.bin, self.source, "out"]), 0)
            self.assertIs(run.call_args[1]["kill_at_first_invalid_block"], value)
        p = subprocess.run([sys.executable, "-I", tu.REPLAY_SCRIPT, "run", "--help"], stdout=subprocess.PIPE,
                           universal_newlines=True)
        self.assertIn("--kill-at-first-invalid-block", p.stdout)

    def test_sigint_ends_the_run_command(self):
        # SIGINT handled by the default handler (KeyboardInterrupt), for
        # example after the node exited: exit status 130 and a log line.
        spec = importlib.util.spec_from_file_location("replay_script", tu.REPLAY_SCRIPT)
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        with mock.patch.object(script.runner, "run", side_effect=KeyboardInterrupt), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout, \
                mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(script.main(["run", self.bin, self.source, "out"]), 130)
        self.assertEqual(stderr.getvalue(), "replay: interrupted by SIGINT\n")
        self.assertEqual(stdout.getvalue(), "")

    def test_output_inside_source_is_refused(self):
        with self.assertRaisesRegex(runner.RunRefused, "inside the source directory"):
            runner.check(self.bin, self.source, os.path.join(self.source, "sub", "out"), *self.ports)
        link = os.path.join(self.tmp, "link")
        os.symlink(self.source, link)
        with self.assertRaisesRegex(runner.RunRefused, "inside the source directory"):
            runner.check(self.bin, self.source, os.path.join(link, "out"), *self.ports)
        runner.check(self.bin, self.source, self.source + "-out", *self.ports)
        code, _, err = self.run_cli("normal", out=os.path.join("source", "out"))
        self.assertEqual(code, 2)
        self.assertIn("inside the source directory", err)
        self.assertFalse(os.path.exists(os.path.join(self.source, "out")))

    def test_port_that_cannot_be_checked_is_refused(self):
        sock = mock.MagicMock()
        sock.bind.side_effect = OSError(errno.EACCES, "Permission denied")
        with mock.patch.object(runner.socket, "socket", return_value=sock):
            with self.assertRaisesRegex(runner.RunRefused, "cannot check port 80 on 127.0.0.1: Permission denied"):
                runner.port_in_use(80)
        with self.assertRaisesRegex(runner.RunRefused, "port 70000 is not between 1 and 65535"):
            runner.port_in_use(70000)
        self.ports[0] = 70000
        code, _, err = self.run_cli("normal")
        self.assertEqual(code, 2)
        self.assertIn("not between 1 and 65535", err)

    def test_node_arguments_set_by_the_script_are_refused(self):
        for arg in ("-printtoconsole=1", "--datadir=/elsewhere", "-nolisten", "-reindex", "-stopatheight=5",
                    "-conf=x.conf", "-noserver=0", "-dbcache=100", "-loadblock=/x/blk00000.dat", "-regtest",
                    "-regtest=1", "-noregtest"):
            for options in ([], ["--regtest"]):
                with self.subTest(arg=arg, options=options):
                    code, _, err = self.run_cli("normal", *options, extra=[arg])
                    self.assertEqual(code, 2)
                    self.assertIn("node argument %s: -" % arg, err)
                    self.assertIn("is set by the script", err)
                    self.assertFalse(os.path.exists(os.path.join(self.tmp, "out")))
        for arg in ("-par=2", "-nodebug", "-debug=net", "-portable", "-listenx", "x-datadir", "-rpcthreads=2"):
            with self.subTest(arg=arg):
                self.assertIsNone(runner.own_option(arg))

    def test_node_that_cannot_be_started(self):
        bad = os.path.join(self.tmp, "not-a-program")
        with open(bad, "wb") as f:
            f.write(b"\x00\x01\x02 neither ELF nor a script\n")
        os.chmod(bad, stat.S_IRWXU)
        out = os.path.join(self.tmp, "out")
        p = subprocess.run([sys.executable, "-I", tu.REPLAY_SCRIPT, "run", "--port", str(self.ports[0]),
                            "--rpcport", str(self.ports[1]), bad, self.source, out],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        rep = self.report()
        self.assertEqual(rep["status"], "incomplete")
        self.assertEqual(len(rep["incomplete_reasons"]), 1)
        self.assertTrue(rep["incomplete_reasons"][0].startswith("cannot start the node: "), rep["incomplete_reasons"])
        self.assertIn("incomplete: cannot start the node: ", p.stdout)
        self.assertIsNone(rep["exit_status"])
        self.assertIsNone(rep["digest"])
        self.assertEqual(rep["command"][0], bad)
        self.assertTrue(os.path.exists(os.path.join(out, "heights.tsv.gz")))
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_port_in_use(self):
        with socket.socket() as s:
            s.bind(("0.0.0.0", self.ports[0]))
            s.listen(1)
            self.assertTrue(runner.port_in_use(self.ports[0]))
        self.assertFalse(runner.port_in_use(self.ports[0]))

    def test_node_arguments_only_for_run(self):
        p = subprocess.run([sys.executable, "-I", tu.REPLAY_SCRIPT, "digest", self.tmp, "x", "--", "-par=2"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("only taken by run", p.stderr)


class UpToHeightTest(unittest.TestCase):
    """run --up-to-height with the fake node (which ends at height 3); the
    chain (--chain) and the source block files hold the blocks up to height
    5 and a side block."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-uptoheight-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = os.path.join(self.tmp, "yacoind")
        with open(self.bin, "w") as f:
            f.write(FAKE_NODE % {"python": sys.executable, "testdir": tu.HERE})
        os.chmod(self.bin, stat.S_IRWXU)
        self.chain = os.path.join(self.tmp, "chain")
        hashes = tu.make_datadir(self.chain, heights=5, blk=True, side_blocks=1)
        self.records = {f["height"]: tu.block_record(f) for h, f in tu.index_records(self.chain).items()
                        if h in hashes}
        self.source = os.path.join(self.chain, "blocks")
        self.ports = RunTest.free_ports(self)

    def run_cli(self, mode, *args, out="out", env=None):
        cmd = [sys.executable, "-I", tu.REPLAY_SCRIPT, "run", "--port", str(self.ports[0]),
               "--rpcport", str(self.ports[1])] + list(args) + [self.bin, self.source, os.path.join(self.tmp, out)]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           env=dict(os.environ, FAKE_MODE=mode, **(env or {})), timeout=60)
        return p.returncode, p.stdout, p.stderr

    def report(self, out="out"):
        with open(os.path.join(self.tmp, out, "report.json")) as f:
            return json.load(f)

    def test_complete_run_up_to_height(self):
        code, stdout, stderr = self.run_cli("normal", "--up-to-height", "3", "--chain", self.chain)
        self.assertEqual(code, 0, stdout + stderr)
        rep = self.report()
        datadir = os.path.join(self.tmp, "out", "datadir")
        self.assertEqual(rep["status"], "complete")
        self.assertEqual(rep["up_to_height"], 3)
        self.assertEqual(rep["chain"], {"datadir": self.chain, "height": 5, "hash": tu.fake_hash(5)[::-1].hex()})
        self.assertEqual((rep["mode"], rep["snapshot"], rep["stop_at_height"]), ("full", None, None))
        self.assertGreaterEqual(rep["phases"]["chain_seconds"], 0)
        self.assertIn("-reindex", rep["command"])
        self.assertFalse([a for a in rep["command"] if a.startswith("-loadblock")])
        # The node got the main-chain blocks 0 to 3 in height order.
        copied = os.path.join(datadir, "blocks.copied")
        self.assertEqual(os.listdir(copied), ["blk00000.dat"])
        expected = b"".join(self.records[h] for h in range(4))
        with open(os.path.join(copied, "blk00000.dat"), "rb") as f:
            self.assertEqual(f.read(), expected)
        self.assertEqual(rep["block_files"], {"count": 1, "bytes": len(expected)})

    def test_complete_run_up_to_height_on_regtest(self):
        # The chain is the chain directory of a regtest node.
        code, stdout, stderr = self.run_cli("normal", "--regtest", "--up-to-height", "3", "--chain", self.chain)
        self.assertEqual(code, 0, stdout + stderr)
        rep = self.report()
        datadir = os.path.join(self.tmp, "out", "datadir")
        self.assertEqual(rep["status"], "complete")
        self.assertIs(rep["regtest"], True)
        self.assertEqual(rep["chain"], {"datadir": self.chain, "height": 5, "hash": tu.fake_hash(5)[::-1].hex()})
        self.assertEqual(rep["command"][4:6], ["-regtest", "-reindex"])
        copied = os.path.join(datadir, "regtest", "blocks.copied")
        with open(os.path.join(copied, "blk00000.dat"), "rb") as f:
            self.assertEqual(f.read(), b"".join(self.records[h] for h in range(4)))
        self.assertEqual(sorted(os.listdir(datadir)), ["regtest", "yacoin.conf"])

    def test_kill_at_first_invalid_block(self):
        code, stdout, stderr = self.run_cli("reject", "--kill-at-first-invalid-block", "--up-to-height", "3",
                                            "--chain", self.chain)
        self.assertEqual(code, 1, stdout + stderr)
        rep = self.report()
        RunTest.assert_killed(self, rep, os.path.join(self.tmp, "out"))
        self.assertEqual(rep["up_to_height"], 3)

    def test_one_read_of_each_block_index(self):
        out = os.path.join(self.tmp, "out")
        with mock.patch.dict(os.environ, FAKE_MODE="normal"), tu.IndexReads() as reads:
            rep = runner.run(self.bin, self.source, out, *self.ports, up_to_height=3, chain=self.chain,
                             log=lambda msg: None)
        self.assertEqual(rep["status"], "complete")
        self.assertEqual(dict(reads.counts), {os.path.join(self.chain, "blocks", "index"): 1,
                                              os.path.join(out, "datadir", "blocks", "index"): 1})

    def test_other_tip_is_incomplete(self):
        code, stdout, _ = self.run_cli("normal", "--up-to-height", "4", "--chain", self.chain)
        self.assertEqual(code, 1)
        self.assertEqual(self.report()["incomplete_reasons"], ["tip height 3, not --up-to-height 4"])

    def test_height_missing_in_the_source(self):
        self.source = os.path.join(self.tmp, "source")
        os.makedirs(self.source)
        with open(os.path.join(self.source, "blk00000.dat"), "wb") as f:
            f.write(b"".join(self.records[h] for h in (0, 1, 3, 4)))
        code, stdout, stderr = self.run_cli("normal", "--up-to-height", "3", "--chain", self.chain)
        self.assertEqual(code, 1, stderr)
        rep = self.report()
        self.assertEqual(rep["incomplete_reasons"], ["1 heights of the chain are not in the block files, "
                                                     "the first at height 2"])
        self.assertIsNone(rep["exit_status"])
        self.assertIsNone(rep["command"])
        self.assertGreaterEqual(rep["phases"]["chain_seconds"], 0)
        self.assertIn("incomplete: 1 heights of the chain are not in the block files", stdout)

    def test_refusals(self):
        cases = [
            (["--up-to-height", "3", "--chain", self.chain, "--stop-at-height", "3"],
             "--up-to-height is not taken with --stop-at-height"),
            (["--up-to-height", "3"], "--chain is needed with --up-to-height"),
            (["--chain", self.chain], "--chain is only taken with --up-to-height or --snapshot"),
            (["--up-to-height", "9", "--chain", self.chain],
             "the chain of %s ends at height 5, below --up-to-height 9" % self.chain),
            (["--up-to-height", "-1", "--chain", self.chain], "--up-to-height -1 is below 0"),
            (["--up-to-height", "3", "--chain", os.path.join(self.tmp, "none")],
             "--chain %s: " % os.path.join(self.tmp, "none")),
        ]
        for args, text in cases:
            with self.subTest(args=args):
                code, _, err = self.run_cli("normal", *args)
                self.assertEqual(code, 2, err)
                self.assertIn(text, err)
                self.assertNotIn("Traceback", err)
                self.assertFalse(os.path.exists(os.path.join(self.tmp, "out")))


class SnapshotRunTest(unittest.TestCase):
    """run --snapshot with the fake node, from a snapshot at height 3 of a
    synthetic run; the chain (--chain) and the source block files hold the
    blocks up to height 5 and a side block."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-snaprun-test.")
        self.addCleanup(self.cleanup)
        self.bin = os.path.join(self.tmp, "yacoind")
        with open(self.bin, "w") as f:
            f.write(FAKE_NODE % {"python": sys.executable, "testdir": tu.HERE})
        os.chmod(self.bin, stat.S_IRWXU)
        self.run_out = os.path.join(self.tmp, "run")
        tu.make_run(self.run_out, heights=3)
        self.snap = os.path.join(self.tmp, "snap")
        self.meta = snapshot.make(self.run_out, self.snap, log=lambda msg: None)
        # The source: the blocks up to height 5 and the side block in
        # blk00000.dat, the second half of them again in blk00001.dat, and a
        # blk00003.dat after a gap.
        self.chain = os.path.join(self.tmp, "chain")
        hashes = tu.make_datadir(self.chain, heights=5, blk=True, side_blocks=1)
        self.records = {f["height"]: tu.block_record(f) for h, f in tu.index_records(self.chain).items()
                        if h in hashes}
        with open(os.path.join(self.chain, "blocks", "blk00000.dat"), "rb") as f:
            data = f.read()
        self.source = os.path.join(self.tmp, "source")
        os.makedirs(self.source)
        for n, content in ((0, data), (1, data[len(data) // 2:] + b"\0" * 32), (3, b"block file 3")):
            with open(os.path.join(self.source, "blk%05d.dat" % n), "wb") as f:
                f.write(content)
        self.ports = RunTest.free_ports(self)
        self.snap_state = tu.tree_state(self.snap)

    def cleanup(self):
        tu.make_writable(self.tmp)
        shutil.rmtree(self.tmp)

    def run_cli(self, mode, *args, out="out", extra=(), snap=None, chain=None, env=None):
        cmd = [sys.executable, "-I", tu.REPLAY_SCRIPT, "run", "--snapshot", snap or self.snap,
               "--port", str(self.ports[0]), "--rpcport", str(self.ports[1])] + list(args)
        if chain != "":
            cmd += ["--chain", chain or self.chain]
        cmd += [self.bin, self.source, os.path.join(self.tmp, out)]
        if extra:
            cmd += ["--"] + list(extra)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           env=dict(os.environ, FAKE_MODE=mode, **(env or {})), timeout=60)
        return p.returncode, p.stdout, p.stderr

    def report(self, out="out"):
        with open(os.path.join(self.tmp, out, "report.json")) as f:
            return json.load(f)

    def datadir_file(self, name, out="out"):
        with open(os.path.join(self.tmp, out, "datadir", name)) as f:
            return json.load(f)

    def test_complete_snapshot_run(self):
        code, stdout, stderr = self.run_cli("import", "--dbcache", "300", extra=["-par=2"])
        self.assertEqual(code, 0, stdout + stderr)
        self.assertTrue(stdout.startswith("complete: tip 5 "), stdout)
        self.assertIn(", 2 blocks above the snapshot at height 3\n", stdout)
        out = os.path.join(self.tmp, "out")
        datadir = os.path.join(out, "datadir")
        imports = [os.path.join(out, "import", "blk00000.dat")]
        rep = self.report()
        self.assertEqual(rep["command"], self.datadir_file("args.json"))
        self.assertEqual(rep["command"], [
            self.bin, "-datadir=" + datadir, "-conf=" + os.path.join(datadir, "yacoin.conf"), "-daemon=0",
            "-replayvalidation=report", "-connect=0", "-listen=0", "-dnsseed=0", "-discover=0",
            "-upnp=0", "-listenonion=0", "-server=0", "-disablewallet", "-printtoconsole=0",
            "-port=%d" % self.ports[0], "-rpcport=%d" % self.ports[1], "-dbcache=300"]
            + ["-loadblock=" + p for p in imports] * 2 + ["-par=2"])
        self.assertEqual(rep["status"], "complete")
        self.assertEqual(rep["incomplete_reasons"], [])
        self.assertEqual(rep["mode"], "snapshot")
        self.assertEqual(rep["snapshot"], {"path": self.snap, "height": 3, "hash": self.meta["hash"],
                                           "digest": self.meta["digest"], "binary": self.meta["binary"]})
        self.assertEqual(rep["snapshot"]["binary"], {"path": "/bin/yacoind", "sha256": "ab" * 32})
        self.assertEqual(rep["tip"]["height"], 5)
        self.assertEqual(rep["blocks_above_snapshot"], 2)
        self.assertFalse(rep["reindex_finished"])
        self.assertTrue(rep["done_loading"])
        self.assertEqual(rep["block_files"], {"count": 1, "bytes": len(self.records[4] + self.records[5])})
        self.assertEqual(rep["block_file_check"], {"blocks": 2, "not_in_index": 0, "stored_above_tip": None})
        self.assertEqual(rep["source"], self.source)
        self.assertEqual(rep["chain"], {"datadir": self.chain, "height": 5,
                                        "hash": tu.fake_hash(5)[::-1].hex()})
        self.assertIsNone(rep["up_to_height"])
        self.assertGreaterEqual(rep["phases"]["chain_seconds"], 0)
        # The import files hold the main-chain blocks above the snapshot, in
        # height order.
        self.assertEqual(os.listdir(os.path.join(out, "import")), ["blk00000.dat"])
        with open(imports[0], "rb") as f:
            self.assertEqual(f.read(), self.records[4] + self.records[5])
        # The node got copies of the snapshot's files: the same content,
        # one link, another inode.
        files = self.datadir_file("files.json")
        self.assertEqual(files.pop("yacoin.conf")[0], runner.file_sha256(os.path.join(datadir, "yacoin.conf")))
        self.assertEqual(sorted(files), sorted(self.meta["manifest"]))
        for path, (sha256, nlink, ino) in files.items():
            self.assertEqual(sha256, self.meta["manifest"][path]["sha256"], path)
            self.assertEqual(nlink, 1, path)
            self.assertNotEqual(ino, os.stat(os.path.join(self.snap, path)).st_ino, path)
        with open(os.path.join(datadir, "debug.log")) as f:
            self.assertNotIn("cannot write", f.read())
        # The snapshot is unchanged: listing, content, size, mode, mtime.
        self.assertEqual(tu.tree_state(self.snap), self.snap_state)

    def test_complete_snapshot_run_on_regtest(self):
        run_out = os.path.join(self.tmp, "regtest-run")
        tu.make_run(run_out, heights=3, regtest=True)
        snap = os.path.join(self.tmp, "regtest-snap")
        meta = snapshot.make(run_out, snap, log=lambda msg: None)
        code, stdout, stderr = self.run_cli("import", "--regtest", snap=snap)
        self.assertEqual(code, 0, stdout + stderr)
        self.assertIn(", 2 blocks above the snapshot at height 3\n", stdout)
        out = os.path.join(self.tmp, "out")
        datadir = os.path.join(out, "datadir")
        rep = self.report()
        self.assertEqual(rep["status"], "complete")
        self.assertIs(rep["regtest"], True)
        self.assertEqual(rep["command"][:5], [self.bin, "-datadir=" + datadir,
                                              "-conf=" + os.path.join(datadir, "yacoin.conf"), "-daemon=0",
                                              "-regtest"])
        self.assertEqual(rep["command"], self.datadir_file(os.path.join("regtest", "args.json")))
        # The snapshot's files are restored into the chain directory.
        files = self.datadir_file(os.path.join("regtest", "files.json"))
        self.assertEqual(sorted(files), sorted(meta["manifest"]))
        for path, (sha256, nlink, ino) in files.items():
            self.assertEqual(sha256, meta["manifest"][path]["sha256"], path)
        self.assertEqual(sorted(os.listdir(datadir)), ["regtest", "yacoin.conf"])
        self.assertEqual(rep["tip"]["height"], 5)
        self.assertEqual(rep["block_file_check"], {"blocks": 2, "not_in_index": 0, "stored_above_tip": None})

    def test_snapshot_and_run_on_different_chains_are_refused(self):
        run_out = os.path.join(self.tmp, "regtest-run")
        tu.make_run(run_out, heights=3, regtest=True)
        snap = os.path.join(self.tmp, "regtest-snap")
        snapshot.make(run_out, snap, log=lambda msg: None)
        code, _, err = self.run_cli("import", snap=snap)
        self.assertEqual(code, 2)
        self.assertIn("the snapshot %s was made from a run on regtest; run with --regtest" % snap, err)
        code, _, err = self.run_cli("import", "--regtest")
        self.assertEqual(code, 2)
        self.assertIn("the snapshot %s was made from a run on main; run without --regtest" % self.snap, err)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out")))

    def test_missing_import_line_is_incomplete(self):
        code, stdout, _ = self.run_cli("import-missing")
        self.assertEqual(code, 1)
        path = os.path.join(self.tmp, "out", "import", "blk00000.dat")
        self.assertEqual(self.report()["incomplete_reasons"],
                         ["\"Importing blocks file\" logged 1 of 2 times for %s" % path])

    def test_unopened_import_file_is_incomplete(self):
        code, stdout, _ = self.run_cli("import-unopened")
        self.assertEqual(code, 1)
        path = os.path.join(self.tmp, "out", "import", "blk00000.dat")
        self.assertEqual(self.report()["incomplete_reasons"], [
            "\"Importing blocks file\" logged 1 of 2 times for %s" % path,
            "\"Could not open blocks file\" for %s" % path])

    def test_node_error_is_incomplete(self):
        # The node exits at once; the copied snapshot is the state.
        code, stdout, _ = self.run_cli("error")
        self.assertEqual(code, 1)
        rep = self.report()
        path = os.path.join(self.tmp, "out", "import", "blk00000.dat")
        self.assertEqual(rep["incomplete_reasons"], [
            "node exit status 1", "no \"Done loading\" in debug.log",
            "\"Importing blocks file\" logged 0 of 2 times for %s" % path,
            "2 blocks of the block files are not in the block index"])
        self.assertEqual((rep["tip"]["height"], rep["digest"]), (3, self.meta["digest"]))
        # Nothing above the snapshot: the summary line shows it.
        self.assertEqual(rep["blocks_above_snapshot"], 0)
        self.assertIn(", 0 blocks above the snapshot at height 3\n", stdout)
        self.assertEqual(rep["mode"], "snapshot")
        self.assertEqual(tu.tree_state(self.snap), self.snap_state)

    def test_tip_below_the_snapshot_is_incomplete(self):
        compute = runner.digest_mod.compute
        with mock.patch.dict(os.environ, FAKE_MODE="import"), \
                mock.patch.object(runner.digest_mod, "compute",
                                  side_effect=lambda *args: _digest_at(compute(*args), 2)):
            rep = runner.run(self.bin, self.source, os.path.join(self.tmp, "out"), *self.ports,
                             snapshot=self.snap, chain=self.chain, log=lambda msg: None)
        self.assertIn("tip height 2 below the snapshot's height 3", rep["incomplete_reasons"])

    def test_height_missing_in_the_source(self):
        source = os.path.join(self.tmp, "source-4")
        os.makedirs(source)
        with open(os.path.join(source, "blk00000.dat"), "wb") as f:
            f.write(b"".join(self.records[h] for h in range(5)))
        self.source = source
        code, stdout, stderr = self.run_cli("import")
        self.assertEqual(code, 1, stderr)
        rep = self.report()
        self.assertEqual(rep["incomplete_reasons"], ["1 heights of the chain are not in the block files, "
                                                     "the first at height 5"])
        self.assertIsNone(rep["exit_status"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out", "datadir", "args.json")))
        self.assertEqual(tu.tree_state(self.snap), self.snap_state)

    def test_kill_at_first_invalid_block(self):
        code, stdout, stderr = self.run_cli("import-reject", "--kill-at-first-invalid-block")
        self.assertEqual(code, 1, stdout + stderr)
        rep = self.report()
        out = os.path.join(self.tmp, "out")
        RunTest.assert_killed(self, rep, out)
        self.assertEqual(rep["mode"], "snapshot")
        self.assertEqual(sorted(os.listdir(out)), ["debug.log", "failures.tsv", "heights.tsv.gz", "node-stderr.log",
                                                   "node-stdout.log", "report.json"])
        self.assertEqual(tu.tree_state(self.snap), self.snap_state)

    def test_one_read_of_each_block_index(self):
        out = os.path.join(self.tmp, "out")
        with mock.patch.dict(os.environ, FAKE_MODE="import"), tu.IndexReads() as reads:
            rep = runner.run(self.bin, self.source, out, *self.ports, snapshot=self.snap, chain=self.chain,
                             log=lambda msg: None)
        self.assertEqual(rep["status"], "complete")
        self.assertEqual(dict(reads.counts), {os.path.join(self.chain, "blocks", "index"): 1,
                                              os.path.join(out, "datadir", "blocks", "index"): 1})

    def test_stop_at_height(self):
        code, stdout, stderr = self.run_cli("import-stop", "--stop-at-height", "5")
        self.assertEqual(code, 0, stdout + stderr)
        rep = self.report()
        self.assertEqual((rep["status"], rep["exit_status"], rep["stop_at_height"]), ("complete", 1, 5))
        self.assertIn("-stopatheight=5", rep["command"])
        self.assertLess(rep["command"].index("-stopatheight=5"), rep["command"].index(
            "-loadblock=" + os.path.join(self.tmp, "out", "import", "blk00000.dat")))

    def test_failures_of_the_run_the_snapshot_was_made_from(self):
        # Part 1 logged a failure at height 3; the snapshot run carries it.
        fail = logscan.Failure(3, tu.fake_hash(3)[::-1].hex(), "script", "d4" * 32, "1", "test-error")
        run_out = os.path.join(self.tmp, "run-failure")
        tu.make_run(run_out, heights=3, failures=[fail])
        snap = os.path.join(self.tmp, "snap-failure")
        snapshot.make(run_out, snap, log=lambda msg: None)
        code, stdout, stderr = self.run_cli("import", snap=snap)
        self.assertEqual(code, 0, stdout + stderr)
        rep = self.report()
        # The fake node logs two failures of its own (heights 2 and 1).
        self.assertEqual((rep["failures"], rep["failure_blocks"], rep["failures_off_main_chain"]), (3, 3, 1))
        loaded = report.load(os.path.join(self.tmp, "out"))
        self.assertEqual(loaded.failures[0], fail)
        with open(os.path.join(self.tmp, "out", "failures.tsv")) as f:
            self.assertIn("3\t%s\tscript\t%s\t1\t1\ttest-error\n" % (fail.block, fail.tx), f.read())
        # Against a report of the same state without failures, with the fake
        # node's own failures expected, compare names height 3.
        clean = os.path.join(self.tmp, "clean")
        runner.digest_only(os.path.join(self.tmp, "out", "datadir"), clean)
        expected = os.path.join(self.tmp, "expected.txt")
        with open(expected, "w") as f:
            for fl in loaded.failures[1:]:
                f.write("%s %s %s %s\n" % (fl.block, fl.check, fl.tx, fl.input))
        lines = compare.compare(loaded, report.load(clean), compare.load_expected(expected))
        self.assertEqual(lines, ["first difference at height 3: unexpected failure in A: block=%s check=script "
                                 "tx=%s input=1 error=test-error" % (fail.block, fail.tx)])

    def test_same_size_change_of_a_snapshot_file(self):
        tu.make_writable(self.snap)
        rev = os.path.join(self.snap, "blocks", "rev00000.dat")
        with open(rev, "rb") as f:
            data = f.read()
        with open(rev, "wb") as f:
            f.write(data[:-1] + bytes([data[-1] ^ 1]))
        code, stdout, stderr = self.run_cli("import")
        self.assertEqual(code, 1, stderr)
        rep = self.report()
        self.assertEqual(rep["incomplete_reasons"],
                         ["snapshot file blocks/rev00000.dat differs from the snapshot's manifest"])
        self.assertIsNone(rep["exit_status"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out", "datadir", "args.json")))

    def test_changed_snapshot_file(self):
        tu.make_writable(self.snap)
        rev = os.path.join(self.snap, "blocks", "rev00000.dat")
        size = os.path.getsize(rev)
        with open(rev, "ab") as f:
            f.write(b"\0")
        code, stdout, stderr = self.run_cli("import")
        self.assertEqual(code, 1, stderr)
        rep = self.report()
        self.assertEqual(rep["status"], "incomplete")
        self.assertEqual(rep["incomplete_reasons"],
                         ["snapshot file blocks/rev00000.dat differs from the snapshot's manifest"])
        self.assertIsNone(rep["exit_status"])
        self.assertIsNone(rep["digest"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out", "datadir", "args.json")))
        os.truncate(rev, size)
        os.remove(os.path.join(self.snap, "tokens", "CURRENT"))
        self.assertEqual(self.run_cli("import", out="out2")[0], 1)
        self.assertIn("snapshot file tokens/CURRENT is missing", self.report("out2")["incomplete_reasons"][0])

    def test_refusals(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        code, _, err = self.run_cli("import", snap=empty)
        self.assertEqual(code, 2)
        self.assertIn("no snapshot.json in %s" % empty, err)
        unknown = os.path.join(self.tmp, "unknown")
        os.makedirs(unknown)
        with open(os.path.join(unknown, "snapshot.json"), "w") as f:
            json.dump(dict(self.meta, format=99), f)
        code, _, err = self.run_cli("import", snap=unknown)
        self.assertEqual(code, 2)
        self.assertIn("unknown snapshot format 99", err)
        with open(os.path.join(unknown, "snapshot.json"), "w") as f:
            f.write("{")
        code, _, err = self.run_cli("import", snap=unknown)
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)
        for height in ("3", "2"):
            code, _, err = self.run_cli("import", "--stop-at-height", height)
            self.assertEqual(code, 2)
            self.assertIn("--stop-at-height %s is not above the snapshot's height 3" % height, err)
        code, _, err = self.run_cli("import", chain="")
        self.assertEqual(code, 2)
        self.assertIn("--chain is needed with --snapshot", err)
        other = os.path.join(self.tmp, "other-chain")
        tu.make_datadir(other, heights=5, salt=1)
        short = os.path.join(self.tmp, "short-chain")
        tu.make_datadir(short, heights=2)
        for chain in (other, short):
            code, _, err = self.run_cli("import", chain=chain)
            self.assertEqual(code, 2)
            self.assertIn("the chain of %s does not hold the snapshot's block %s at height 3" % (
                chain, self.meta["hash"]), err)
        at_h = os.path.join(self.tmp, "chain-at-h")
        tu.make_datadir(at_h, heights=3)
        code, _, err = self.run_cli("import", chain=at_h)
        self.assertEqual(code, 2)
        self.assertIn("the chain of %s ends at height 3, the snapshot's height" % at_h, err)
        code, _, err = self.run_cli("import", "--stop-at-height", "9")
        self.assertEqual(code, 2)
        self.assertIn("the chain of %s ends at height 5, below --stop-at-height 9" % self.chain, err)
        code, _, err = self.run_cli("import", chain=os.path.join(self.tmp, "none"))
        self.assertEqual(code, 2)
        self.assertIn("--chain %s: " % os.path.join(self.tmp, "none"), err)
        code, _, err = self.run_cli("import", "--up-to-height", "4")
        self.assertEqual(code, 2)
        self.assertIn("--up-to-height is not taken with --snapshot", err)
        code, _, err = self.run_cli("import", out=os.path.join("chain", "out"))
        self.assertEqual(code, 2)
        self.assertIn("is inside the chain's data directory", err)
        code, _, err = self.run_cli("import", out=os.path.join("snap", "out"))
        self.assertEqual(code, 2)
        self.assertIn("output directory %s is inside the snapshot directory %s" % (
            os.path.join(self.snap, "out"), self.snap), err)
        self.assertNotIn("Traceback", err)
        code, _, err = self.run_cli("import", extra=["-loadblock=/x/blk00000.dat"])
        self.assertEqual(code, 2)
        self.assertIn("-loadblock is set by the script", err)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out")))
        self.assertEqual(tu.tree_state(self.snap), self.snap_state)


def _digest_at(d, height):
    """The digest d with its tip moved to height."""
    return d._replace(tip_height=height, rows=d.rows[:height + 1], tip_hash=d.rows[height].hash)


class DigestCommandTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-digest-cmd-test.")
        self.addCleanup(shutil.rmtree, self.tmp)

    def cli(self, *args):
        p = subprocess.run([sys.executable, "-I", tu.REPLAY_SCRIPT, "digest"] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return p.returncode, p.stdout, p.stderr

    def test_digest_and_compare(self):
        a, b = os.path.join(self.tmp, "a"), os.path.join(self.tmp, "b")
        tu.make_datadir(a, heights=5)
        tu.make_datadir(b, heights=5, block_fields=lambda h: {"data_pos": 1})
        code, out, _ = self.cli(a, os.path.join(self.tmp, "ra"))
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("tip 5 "), out)
        self.assertEqual(self.cli(b, os.path.join(self.tmp, "rb"))[0], 0)
        with open(os.path.join(self.tmp, "ra", "report.json")) as f:
            rep = json.load(f)
        self.assertEqual((rep["kind"], rep["status"], rep["datadir"]), ("digest", "complete", a))
        p = subprocess.run([sys.executable, "-I", tu.REPLAY_SCRIPT, "compare", os.path.join(self.tmp, "ra"),
                            os.path.join(self.tmp, "rb")], stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual((p.returncode, p.stdout), (0, "identical\n"))

    def test_digest_error(self):
        a = os.path.join(self.tmp, "a")
        tu.make_datadir(a, head_blocks=True)
        code, out, err = self.cli(a, os.path.join(self.tmp, "ra"))
        self.assertEqual(code, 1)
        self.assertIn("head-blocks record present", err)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "ra")))

    def test_refusals(self):
        code, _, err = self.cli(os.path.join(self.tmp, "none"), os.path.join(self.tmp, "ra"))
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)
        os.makedirs(os.path.join(self.tmp, "ra"))
        code, _, err = self.cli(self.tmp, os.path.join(self.tmp, "ra"))
        self.assertEqual(code, 2)
        self.assertIn("output directory exists", err)


if __name__ == "__main__":
    unittest.main()
