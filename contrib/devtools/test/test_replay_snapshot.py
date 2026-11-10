"""Tests of the snapshot command of contrib/replay
(replaylib/snapshot.py and "replay.py snapshot").

The run directories are synthetic (replay_testutil.make_run): made-up
hashes, heights below 200, the block-file record marker a1 b2 c3 d4.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import replay_testutil as tu
from replaylib import logscan, runner, snapshot

DATABASE_FILES = ("blocks/blk00000.dat", "blocks/rev00000.dat")


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-snapshot-test.")
        self.addCleanup(self.cleanup)
        self.run_out = os.path.join(self.tmp, "run")
        self.snap = os.path.join(self.tmp, "snap")

    def cleanup(self):
        tu.make_writable(self.tmp)
        shutil.rmtree(self.tmp)

    def cli(self, run_out=None, snap=None):
        p = subprocess.run([sys.executable, "-I", tu.REPLAY_SCRIPT, "snapshot", run_out or self.run_out,
                            snap or self.snap], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=60)
        return p.returncode, p.stdout, p.stderr

    def meta(self):
        with open(os.path.join(self.snap, "snapshot.json")) as f:
            return json.load(f)

    def test_snapshot_of_a_complete_run(self):
        rep = tu.make_run(self.run_out, heights=6, side_blocks=1)
        before = tu.tree_state(self.run_out)
        code, out, err = self.cli()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "snapshot at height 6 %s, digest %s\n" % (rep["tip"]["hash"], rep["digest"]))
        meta = self.meta()
        self.assertEqual(meta["format"], snapshot.FORMAT)
        self.assertEqual((meta["height"], meta["hash"], meta["digest"]),
                         (rep["tip"]["height"], rep["tip"]["hash"], rep["digest"]))
        self.assertEqual(meta["sections"], rep["sections"])
        self.assertEqual(meta["command"], rep["command"])
        self.assertEqual(meta["binary"], rep["binary"])
        self.assertEqual(meta["source"], rep["source"])
        self.assertEqual(meta["run"], os.path.abspath(self.run_out))
        self.assertRegex(meta["made"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

        # Only the databases are copied, and the manifest lists every copied
        # file with its size and SHA-256.
        state = tu.tree_state(self.snap)
        files = {p: e for p, e in state.items() if stat.S_ISREG(e[0])}
        copied = sorted(p for p in files if p not in ("snapshot.json", "report.json", "failures.tsv"))
        self.assertEqual(sorted(meta["manifest"]), copied)
        for path in DATABASE_FILES:
            self.assertIn(path, copied)
        for prefix in ("blocks/index/", "chainstate/", "tokens/"):
            self.assertTrue(any(p.startswith(prefix + "MANIFEST-") for p in copied), prefix)
        for path in copied:
            self.assertTrue(path.startswith(("blocks/blk", "blocks/rev", "blocks/index/", "chainstate/", "tokens/")),
                            path)
            self.assertEqual(meta["manifest"][path], {"size": files[path][1], "sha256": files[path][4]})
            with open(os.path.join(self.run_out, "datadir", path), "rb") as f:
                self.assertEqual(runner.file_sha256(os.path.join(self.snap, path)),
                                 hashlib.sha256(f.read()).hexdigest())
        for name in ("debug.log", "yacoin.conf", ".lock", "peers.dat"):
            self.assertNotIn(name, state)
        # The run's report and failures beside it.
        with open(os.path.join(self.snap, "report.json")) as f, \
                open(os.path.join(self.run_out, "report.json")) as g:
            self.assertEqual(json.load(f), json.load(g))
        with open(os.path.join(self.snap, "failures.tsv")) as f, \
                open(os.path.join(self.run_out, "failures.tsv")) as g:
            self.assertEqual(f.read(), g.read())
        self.assertEqual((meta["failures"], meta["failure_blocks"], meta["failures_off_main_chain"]), (0, 0, 0))
        # Every file and directory is read-only.
        for path, entry in list(state.items()) + [(".", tu.tree_state(self.tmp)["snap"])]:
            self.assertEqual(entry[2] & 0o222, 0, path)
        # The run directory is unchanged.
        self.assertEqual(tu.tree_state(self.run_out), before)

    def test_snapshot_of_a_run_up_to_a_height(self):
        chain = {"datadir": "/chain", "height": 9, "hash": "77" * 32}
        rep = tu.make_run(self.run_out, heights=4, fields={"up_to_height": 4, "chain": chain})
        code, out, err = self.cli()
        self.assertEqual(code, 0, err)
        meta = self.meta()
        self.assertEqual((meta["height"], meta["digest"]), (4, rep["digest"]))
        self.assertEqual((meta["up_to_height"], meta["chain"]), (4, chain))

    def test_failures_of_the_run(self):
        fails = [logscan.Failure(2, tu.fake_hash(2)[::-1].hex(), "script", "d4" * 32, "0", "test-error"),
                 logscan.Failure(1, tu.fake_hash(1, 5)[::-1].hex(), "script", "-", "-", "test-error")]
        tu.make_run(self.run_out, failures=fails)
        self.assertEqual(self.cli()[0], 0)
        meta = self.meta()
        self.assertEqual((meta["failures"], meta["failure_blocks"], meta["failures_off_main_chain"]), (2, 2, 1))
        self.assertEqual(snapshot.failures(self.snap, meta), fails)

    def test_refused_without_the_failures_of_the_run(self):
        tu.make_run(self.run_out)
        os.remove(os.path.join(self.run_out, "failures.tsv"))
        self.assert_refused("cannot read")
        self.assertFalse(os.path.exists(self.snap))
        run_out = os.path.join(self.tmp, "run-count")
        tu.make_run(run_out, fields={"failures": 3})
        code, _, err = self.cli(run_out=run_out)
        self.assertEqual(code, 2, err)
        self.assertIn("has 0 rows, the report 3 failures", err)
        self.assertFalse(os.path.exists(self.snap))

    def test_load_checks_format(self):
        tu.make_run(self.run_out)
        self.assertEqual(self.cli()[0], 0)
        meta = snapshot.load(self.snap)
        self.assertEqual(meta["height"], 3)
        with self.assertRaisesRegex(snapshot.SnapshotRefused, "no snapshot.json"):
            snapshot.load(self.tmp)

    def assert_refused(self, text, snap=None):
        code, out, err = self.cli(snap=snap)
        self.assertEqual(code, 2, err)
        self.assertIn(text, err)
        self.assertNotIn("Traceback", err)
        return err

    def test_refused_when_the_target_exists(self):
        tu.make_run(self.run_out)
        os.makedirs(self.snap)
        self.assert_refused("exists")
        self.assertEqual(os.listdir(self.snap), [])

    def test_refused_without_a_report(self):
        os.makedirs(os.path.join(self.run_out, "datadir"))
        self.assert_refused("cannot read")
        self.assertFalse(os.path.exists(self.snap))

    def test_refused_reports(self):
        cases = [
            ({"kind": "digest"}, "not of a run"),
            ({"status": "incomplete", "incomplete_reasons": ["no digest"]}, "not complete"),
            ({"mode": "snapshot", "snapshot": {"path": "/s", "height": 1, "hash": "00" * 32, "digest": "11" * 32}},
             "snapshot run"),
            ({"stop_at_height": 2}, "--stop-at-height"),
            ({"digest": None}, "has no digest"),
        ]
        for fields, text in cases:
            with self.subTest(fields=fields):
                run_out = os.path.join(self.tmp, "run-%d" % len(os.listdir(self.tmp)))
                tu.make_run(run_out, fields=fields)
                code, _, err = self.cli(run_out=run_out)
                self.assertEqual(code, 2, err)
                self.assertIn(text, err)
                self.assertFalse(os.path.exists(self.snap))

    def test_refused_when_a_node_holds_the_lock(self):
        tu.make_run(self.run_out)
        lock = os.path.join(self.run_out, "datadir", ".lock")
        holder = subprocess.Popen(
            [sys.executable, "-I", "-c", "import fcntl, os, sys\n"
             "fd = os.open(sys.argv[1], os.O_RDWR)\n"
             "fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
             "print('locked', flush=True)\n"
             "sys.stdin.read()\n", lock],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
        try:
            self.assertEqual(holder.stdout.readline(), "locked\n")
            self.assert_refused("in use by a running node")
            self.assertFalse(os.path.exists(self.snap))
        finally:
            holder.stdin.close()
            holder.wait(timeout=30)
            holder.stdout.close()

    def test_refused_without_a_database_directory(self):
        tu.make_run(self.run_out)
        shutil.rmtree(os.path.join(self.run_out, "datadir", "tokens"))
        self.assert_refused("no tokens directory")
        self.assertFalse(os.path.exists(self.snap))

    def test_no_snapshot_json_when_making_it_read_only_fails(self):
        tu.make_run(self.run_out)
        chmod = os.chmod
        for failing in ("top", "file"):
            with self.subTest(failing=failing):
                snap = os.path.join(self.tmp, "snap-" + failing)

                def fail(path, mode):
                    if (failing == "top" and path == snap) or (
                            failing == "file" and path.endswith(os.path.join("chainstate", "CURRENT"))):
                        raise PermissionError(1, "test-error", path)
                    chmod(path, mode)

                with mock.patch.object(snapshot.os, "chmod", side_effect=fail):
                    with self.assertRaisesRegex(snapshot.SnapshotFailed, "test-error"):
                        snapshot.make(self.run_out, snap, log=lambda msg: None)
                self.assertTrue(os.path.isdir(snap))
                self.assertEqual([n for n in os.listdir(snap) if n.startswith("snapshot.json")], [])

    def test_load_refuses_a_bad_snapshot_json(self):
        tu.make_run(self.run_out)
        self.assertEqual(self.cli()[0], 0)
        meta = self.meta()
        bad = os.path.join(self.tmp, "bad")
        os.makedirs(bad)

        def write(content):
            with open(os.path.join(bad, "snapshot.json"), "w") as f:
                json.dump(content, f)

        for key in ("height", "hash", "digest", "manifest", "failures"):
            with self.subTest(missing=key):
                write({k: v for k, v in meta.items() if k != key})
                with self.assertRaisesRegex(snapshot.SnapshotRefused, "has no %s" % key):
                    snapshot.load(bad)
        entry = {"size": 1, "sha256": "00" * 32}
        for path in ("../outside.dat", "/etc/outside.dat", "debug.log", os.path.join("blocks", "..", "..", "x")):
            with self.subTest(path=path):
                write(dict(meta, manifest={path: entry}))
                with self.assertRaisesRegex(snapshot.SnapshotRefused, "file outside the databases"):
                    snapshot.load(bad)
        for key, value, kind in (("height", "3", "number"), ("height", True, "number"), ("hash", 3, "string"),
                                 ("failures", None, "number"), ("manifest", [], "mapping")):
            with self.subTest(key=key, value=value):
                write(dict(meta, **{key: value}))
                with self.assertRaisesRegex(snapshot.SnapshotRefused, "%s is not a %s" % (key, kind)):
                    snapshot.load(bad)
        write(meta)
        with open(os.path.join(bad, "failures.tsv"), "w") as f:
            f.write("height\tblock\tcheck\ttx\tinput\tmain\terror\n1\t%s\tscript\t-\t-\t1\ttest-error\n" % ("aa" * 32))
        with self.assertRaisesRegex(snapshot.SnapshotRefused, "has 1 rows, snapshot.json 0 failures"):
            snapshot.failures(bad, snapshot.load(bad))
        write([1, 2])
        with self.assertRaisesRegex(snapshot.SnapshotRefused, "not a snapshot description"):
            snapshot.load(bad)

    def test_refused_inside_the_run(self):
        tu.make_run(self.run_out)
        self.assert_refused("inside", snap=os.path.join(self.run_out, "datadir", "snap"))
        self.assertFalse(os.path.exists(os.path.join(self.run_out, "datadir", "snap")))

    def test_digest_of_the_copy_differs_from_the_report(self):
        rep = tu.make_run(self.run_out)
        # A coin record added after the report.
        other = os.path.join(self.tmp, "other")
        tu.make_datadir(other, coins=[(b"C" + b"\x55" * 32 + b"\x00", b"\x03\x00\x05\x00"),
                                      (b"C" + b"\x56" * 32 + b"\x01", b"\x03\x00\x07\x00")])
        chainstate = os.path.join(self.run_out, "datadir", "chainstate")
        shutil.rmtree(chainstate)
        shutil.copytree(os.path.join(other, "chainstate"), chainstate)
        code, out, err = self.cli()
        self.assertEqual(code, 1, err)
        self.assertIn("digest of the copy %s differs from the report's %s" % (
            snapshot_digest(self.snap), rep["digest"]), err)
        self.assertNotIn("Traceback", err)
        self.assertFalse(os.path.exists(os.path.join(self.snap, "snapshot.json")))

    def test_block_of_the_files_not_in_the_index(self):
        tu.make_run(self.run_out)
        with open(os.path.join(self.run_out, "datadir", "blocks", "blk00000.dat"), "ab") as f:
            f.write(tu.block_record({"version": 7, "hash_prev": tu.fake_hash(3), "merkle": tu.fake_hash(4, salt=7),
                                     "time": 1700000300, "bits": 0x1e0fffff, "nonce": 0x4c39}))
        code, out, err = self.cli()
        self.assertEqual(code, 1, err)
        self.assertIn("1 blocks of the block files are not in the block index", err)
        self.assertFalse(os.path.exists(os.path.join(self.snap, "snapshot.json")))

    def test_unreadable_copy_is_a_failure(self):
        tu.make_run(self.run_out)
        os.remove(os.path.join(self.run_out, "datadir", "blocks", "rev00000.dat"))
        code, out, err = self.cli()
        self.assertEqual(code, 1, err)
        self.assertIn("rev00000.dat", err)
        self.assertFalse(os.path.exists(os.path.join(self.snap, "snapshot.json")))


def snapshot_digest(snap):
    from replaylib import digest
    return digest.compute(snap).overall


if __name__ == "__main__":
    unittest.main()
