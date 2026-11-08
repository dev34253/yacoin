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

Without SIGTERM it exits with status 3 after 20 s. It records its
arguments in <datadir>/args.json, its process id in
<datadir>/pid and its blocked-signal mask (SigBlk of /proc/self/status,
where there is one) in <datadir>/sigblk.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import errno
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import replay_testutil as tu
from replaylib import runner

FAKE_NODE = r"""#!%(python)s -I
import json, os, signal, sys, time
sys.path.insert(0, %(testdir)r)
import replay_testutil as tu
datadir = [a.split("=", 1)[1] for a in sys.argv if a.startswith("-datadir=")][0]
mode = os.environ["FAKE_MODE"]
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
if mode == "error":
    sys.exit(1)
log("replayvalidation: mode report")
log("replayvalidation: failure height=2 block=%%s check=script tx=%%s input=0 error=test-error"
    %% (tu.fake_hash(2)[::-1].hex(), "d4" * 32))
log("replayvalidation: failure height=1 block=%%s check=script tx=- input=- error=test-error"
    %% tu.fake_hash(1, 5)[::-1].hex())
if mode == "signal":
    os.kill(os.getpid(), signal.SIGKILL)
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
tu.make_datadir(datadir, heights=3)
log("Done loading")
if mode == "stop":
    sys.exit(1)
while not stop and time.time() < deadline:
    time.sleep(0.05)
sys.exit(0 if stop else 3)
"""


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

    def run_cli(self, mode, *args, out="out", extra=()):
        cmd = [sys.executable, "-I", tu.REPLAY_SCRIPT, "run", "--port", str(self.ports[0]),
               "--rpcport", str(self.ports[1])] + list(args) + [self.bin, self.source, os.path.join(self.tmp, out)]
        if extra:
            cmd += ["--"] + list(extra)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           env=dict(os.environ, FAKE_MODE=mode), timeout=60)
        return p.returncode, p.stdout, p.stderr

    def report(self, out="out"):
        with open(os.path.join(self.tmp, out, "report.json")) as f:
            return json.load(f)

    def node_args(self, out="out"):
        with open(os.path.join(self.tmp, out, "datadir", "args.json")) as f:
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
        sigblk = os.path.join(datadir, "sigblk")
        if os.path.exists(sigblk):
            with open(sigblk) as f:
                mask = int(f.read(), 16)
            for sig in runner.STOP_SIGNALS:
                self.assertFalse(mask & (1 << (sig - 1)), "%s blocked in the node" % sig.name)
        self.assertEqual(sorted(os.listdir(self.source)), ["blk00000.dat", "blk00001.dat", "blk00003.dat",
                                                           "rev00000.dat"])

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

    def test_stop_signal_after_the_reap(self):
        # A stop signal that arrives right after the node was reaped: the
        # script neither signals nor waits for the node again.
        real_wait4 = os.wait4
        calls = []

        def wait4(pid, options):
            calls.append(options)
            result = real_wait4(pid, options)
            if result[0]:
                os.kill(os.getpid(), signal.SIGTERM)
            return result

        out = os.path.join(self.tmp, "out")
        with mock.patch.dict(os.environ, FAKE_MODE="normal"), mock.patch.object(runner.os, "wait4", wait4):
            with self.assertRaises(runner.Interrupted) as cm:
                runner.run(self.bin, self.source, out, *self.ports, log=lambda msg: None)
        self.assertEqual(cm.exception.signum, signal.SIGTERM)
        self.assertEqual(set(calls), {os.WNOHANG})
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        self.assertTrue(os.path.exists(os.path.join(out, "datadir", "chainstate")))

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
