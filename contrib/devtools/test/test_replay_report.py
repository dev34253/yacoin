"""Tests of the debug.log scan and the report files of contrib/replay
(replaylib/logscan.py, replaylib/report.py).

The log lines are synthetic: made-up hashes, heights below 200 and the
neutral error text "test-error".

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import gzip
import os
import shutil
import tempfile
import unittest

import replay_testutil  # noqa: F401  (puts contrib/replay on the path)
from replaylib import logscan, report
from replaylib.digest import Row

BLOCK_A = "a1" * 32
BLOCK_B = "b2" * 32
BLOCK_SIDE = "c3" * 32
TX = "d4" * 32

LOG = """\
2026-11-08 10:00:00 Yacoin version v1.11.0.0
2026-11-08 10:00:01 replayvalidation: mode report
2026-11-08 10:00:02 Reindexing block file blk00000.dat...
2026-11-08 10:00:03 replayvalidation: failure height=17 block={a} check=script tx={tx} input=0 error=test-error
2026-11-08 10:00:03 replayvalidation: failure height=17 block={a} check=script tx={tx} input=1 error=test-error two
2026-11-08 10:00:04 UpdateTip: new best={a} height=17
2026-11-08 10:00:05 replayvalidation: failure height=18 block={side} check=script tx={tx} input=0 error=test-error
2026-11-08 10:00:06 replayvalidation: failure height=18 block={b} check=script tx={tx} input=2 error=test-error
2026-11-08 10:00:07 Reindexing finished
2026-11-08 10:00:08 Done loading
""".format(a=BLOCK_A, b=BLOCK_B, side=BLOCK_SIDE, tx=TX)


class LogScanTest(unittest.TestCase):
    def test_failures_and_counts(self):
        s = logscan.LogScanner()
        s.feed(LOG)
        s.finish()
        self.assertEqual(len(s.failures), 4)
        self.assertEqual(s.failures[0], logscan.Failure(17, BLOCK_A, "script", TX, "0", "test-error"))
        self.assertEqual(s.failures[1].error, "test-error two")
        self.assertEqual(s.failures[2], logscan.Failure(18, BLOCK_SIDE, "script", TX, "0", "test-error"))
        rows = [Row(h, "00" * 32, 0, 0, "11" * 32, "-") for h in range(17)]
        rows += [Row(17, BLOCK_A, 0, 0, "11" * 32, "-"), Row(18, BLOCK_B, 0, 0, "11" * 32, "-")]
        marked = logscan.mark_main_chain(s.failures, rows)
        self.assertEqual([m for _, m in marked], [True, True, False, True])
        self.assertEqual(logscan.counts(s.failures), (4, 3))
        # A failure above the main chain's tip is not on it.
        self.assertEqual([m for _, m in logscan.mark_main_chain(s.failures, rows[:18])], [True, True, False, False])

    def test_two_blocks_three_failures(self):
        lines = [l for l in LOG.splitlines(True) if BLOCK_SIDE not in l]
        s = logscan.LogScanner()
        s.feed("".join(lines))
        s.finish()
        self.assertEqual(logscan.counts(s.failures), (3, 2))
        self.assertEqual({f.block for f in s.failures}, {BLOCK_A, BLOCK_B})

    def test_lines_of_another_kind_are_ignored(self):
        s = logscan.LogScanner()
        s.feed("2026-11-08 10:00:00 UpdateTip: new best=%s height=17\n"
               "2026-11-08 10:00:00 replayvalidation: mode report\n"
               "replayvalidation: failure height=x block=zz\n" % BLOCK_A)
        s.finish()
        self.assertEqual(s.failures, [])
        self.assertFalse(s.reindex_finished)
        self.assertFalse(s.done_loading)

    def test_markers(self):
        s = logscan.LogScanner()
        s.feed(LOG.split("Reindexing finished")[0])
        self.assertFalse(s.reindex_finished)
        s.feed("Reindexing finished\n2026-11-08 10:00:08 Done load")
        self.assertTrue(s.reindex_finished)
        self.assertFalse(s.done_loading)
        s.feed("ing\n")
        self.assertTrue(s.done_loading)

    def test_import_lines(self):
        s = logscan.LogScanner()
        s.feed("2026-11-08 10:00:00 Importing blocks file /out/import/blk00000.dat...\n"
               "2026-11-08 10:00:01 Warning: Could not open blocks file /out/import/blk 1.dat\n"
               "2026-11-08 10:00:02 Importing blocks file /out/import/blk00000.dat...\n"
               "2026-11-08 10:00:03 Importing blocks file /out/import/blk00002.dat\n")
        s.finish()
        self.assertEqual(s.imported, ["/out/import/blk00000.dat", "/out/import/blk00000.dat"])
        self.assertEqual(s.not_opened, ["/out/import/blk 1.dat"])

    def test_line_split_across_chunks(self):
        s = logscan.LogScanner()
        for i in range(0, len(LOG), 7):
            s.feed(LOG[i:i + 7])
        s.finish()
        self.assertEqual(len(s.failures), 4)
        self.assertTrue(s.reindex_finished and s.done_loading)

    def test_last_line_without_newline(self):
        s = logscan.LogScanner()
        s.feed(LOG + "2026-11-08 10:00:09 replayvalidation: failure height=19 block=%s check=x tx=- "
               "input=- error=test-error" % BLOCK_B)
        self.assertEqual(len(s.failures), 4)
        s.finish()
        self.assertEqual(len(s.failures), 5)

    def test_follower_reads_a_growing_file(self):
        tmp = tempfile.mkdtemp(prefix="replay-log-test.")
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "debug.log")
        follower = logscan.LogFollower(path)
        follower.poll()  # no file yet
        self.assertFalse(follower.scanner.reindex_finished)
        half = len(LOG) // 2
        with open(path, "w") as f:
            f.write(LOG[:half])
        follower.poll()
        with open(path, "a") as f:
            f.write(LOG[half:])
        follower.poll()
        follower.finish()
        self.assertEqual(len(follower.scanner.failures), 4)
        self.assertTrue(follower.scanner.done_loading)

    def test_scan_file(self):
        tmp = tempfile.mkdtemp(prefix="replay-log-test.")
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "debug.log")
        with open(path, "wb") as f:
            f.write(LOG.encode() + b"\xff\xfe invalid utf-8\n")
        s = logscan.scan_file(path)
        self.assertEqual(len(s.failures), 4)
        self.assertTrue(s.reindex_finished)


class ReportFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-report-test.")
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_round_trip(self):
        rows = [Row(0, "00" * 32, 0, 0, "11" * 32, "-"), Row(1, "01" * 32, 5, 5, "22" * 32, "33" * 32)]
        failures = [logscan.Failure(1, "01" * 32, "script", TX, "0", "test-error")]
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        report.write(out, {"kind": "digest", "tip": {"height": 1, "hash": "01" * 32}}, rows,
                     logscan.mark_main_chain(failures, rows))
        self.assertEqual(sorted(os.listdir(out)), ["failures.tsv", "heights.tsv.gz", "report.json"])
        with gzip.open(os.path.join(out, "heights.tsv.gz"), "rt") as f:
            self.assertEqual(f.readline(), "height\thash\tmint\tmoneysupply\tchain\tundo\n")
        loaded = report.load(out)
        self.assertEqual(loaded.report["kind"], "digest")
        self.assertEqual(loaded.rows, {0: rows[0], 1: rows[1]})
        self.assertEqual(loaded.failures, failures)
        self.assertEqual(report.load(os.path.join(out, "report.json")).rows, loaded.rows)

    def test_heights_file_does_not_depend_on_the_time(self):
        rows = [Row(0, "00" * 32, 0, 0, "11" * 32, "-")]
        for name in ("a", "b"):
            os.makedirs(os.path.join(self.tmp, name))
            report.write(os.path.join(self.tmp, name), {}, rows, [])
        with open(os.path.join(self.tmp, "a", "heights.tsv.gz"), "rb") as a, \
                open(os.path.join(self.tmp, "b", "heights.tsv.gz"), "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_load_without_failures_file(self):
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        report.write(out, {}, [], [])
        os.remove(os.path.join(out, "failures.tsv"))
        self.assertEqual(report.load(out).failures, [])

    def test_load_missing_report_is_an_error(self):
        with self.assertRaisesRegex(report.ReportError, "report.json"):
            report.load(self.tmp)


if __name__ == "__main__":
    unittest.main()
