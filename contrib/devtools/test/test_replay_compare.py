"""Tests of the comparison of two reports of contrib/replay
(replaylib/compare.py and "replay.py compare").

The reports are synthetic: made-up hashes, heights below 200 and the
neutral error text "test-error".

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import copy
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import replay_testutil as tu
from replaylib import compare, logscan, report
from replaylib.digest import Row

TX = "d4" * 32


def h(height, salt=0):
    return tu.fake_hash(height, salt)[::-1].hex()


def make_rows(tip):
    return [Row(i, h(i), 10 * (i > 0), 10 * i, ("%02x" % (i % 256)) * 32, "-" if i == 0 else ("e%d" % (i % 10)) * 32)
            for i in range(tip + 1)]


SECTIONS = {
    "chain": {"count": 0, "sha256": "aa" * 32},
    "undo": {"count": 0, "sha256": "bb" * 32},
    "coins": {"count": 5, "sha256": "cc" * 32},
    "tokens": {"count": 0, "sha256": "dd" * 32},
    "tokenindex": {"count": 0, "sha256": "ee" * 32},
}


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-compare-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.n = 0

    def write(self, rows, failures=(), sections=None, tip=None):
        self.n += 1
        out = os.path.join(self.tmp, "r%d" % self.n)
        os.makedirs(out)
        last = rows[-1]
        rep = {"kind": "run", "status": "complete",
               "tip": tip or {"height": last.height, "hash": last.hash},
               "sections": copy.deepcopy(sections or SECTIONS)}
        report.write(out, rep, rows, logscan.mark_main_chain(list(failures), rows))
        return out

    def expected_file(self, text):
        path = os.path.join(self.tmp, "expected-%d.txt" % self.n)
        with open(path, "w") as f:
            f.write(text)
        return path

    def cli(self, *args):
        p = subprocess.run([sys.executable, "-I", tu.REPLAY_SCRIPT, "compare"] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           cwd=self.tmp)
        return p.returncode, p.stdout, p.stderr

    def compare(self, a, b, expected=None):
        return compare.compare(report.load(a), report.load(b),
                               compare.load_expected(expected) if expected else set())

    def test_identical_reports(self):
        a = self.write(make_rows(150))
        b = self.write(make_rows(150))
        self.assertEqual(self.compare(a, b), [])
        self.assertEqual(self.cli(a, b), (0, "identical\n", ""))

    def test_changed_money_supply_names_its_height(self):
        rows = make_rows(150)
        rows[57] = rows[57]._replace(money_supply=1)
        rows[90] = rows[90]._replace(money_supply=2)
        a = self.write(make_rows(150))
        b = self.write(rows, sections=dict(SECTIONS, chain={"count": 0, "sha256": "ab" * 32}))
        lines = self.compare(a, b)
        self.assertEqual(lines[0], "first difference at height 57: moneysupply (A 570, B 1)")
        self.assertIn("sections that differ: chain", lines)
        code, out, _ = self.cli(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), lines)

    def test_changed_undo_digest_names_its_height(self):
        rows = make_rows(150)
        rows[33] = rows[33]._replace(undo="ff" * 32)
        lines = self.compare(self.write(make_rows(150)), self.write(rows))
        self.assertTrue(lines[0].startswith("first difference at height 33: undo (A "), lines)

    def test_several_columns_at_one_height(self):
        rows = make_rows(20)
        rows[5] = rows[5]._replace(mint=3, chain="00" * 32)
        lines = self.compare(self.write(make_rows(20)), self.write(rows))
        self.assertTrue(lines[0].startswith("first difference at height 5: mint (A 10, B 3), chain (A "), lines)

    def test_shorter_chain_names_first_height_present_in_one(self):
        a = self.write(make_rows(150))
        b = self.write(make_rows(120))
        lines = self.compare(a, b)
        self.assertEqual(lines[0], "first difference at height 121: only in A")
        self.assertIn("tip: A 150 %s, B 120 %s" % (h(150), h(120)), lines)
        self.assertEqual(self.compare(b, a)[0], "first difference at height 121: only in B")

    def test_coins_only_difference_names_section_without_height(self):
        a = self.write(make_rows(150))
        b = self.write(make_rows(150), sections=dict(SECTIONS, coins={"count": 5, "sha256": "00" * 32}))
        lines = self.compare(a, b)
        self.assertEqual(lines, ["sections that differ: coins"])
        self.assertEqual(self.cli(a, b)[0], 1)

    def test_token_section_difference(self):
        a = self.write(make_rows(10))
        b = self.write(make_rows(10), sections=dict(SECTIONS, tokens={"count": 1, "sha256": "dd" * 32},
                                                    tokenindex={"count": 0, "sha256": "01" * 32}))
        self.assertEqual(self.compare(a, b), ["sections that differ: tokens, tokenindex"])

    def test_section_missing_in_one_report(self):
        a = self.write(make_rows(10))
        sections = dict(SECTIONS)
        del sections["undo"]
        b = self.write(make_rows(10), sections=sections)
        self.assertEqual(self.compare(a, b), ["sections that differ: undo"])

    def test_unexpected_failure_names_its_height(self):
        rows = make_rows(150)
        fail = logscan.Failure(77, h(77), "script", TX, "1", "test-error")
        a = self.write(rows)
        b = self.write(rows, failures=[fail])
        lines = self.compare(a, b)
        self.assertEqual(lines[0], "first difference at height 77: unexpected failure in B: block=%s "
                                   "check=script tx=%s input=1 error=test-error" % (h(77), TX))
        self.assertEqual(self.cli(a, b)[0], 1)
        # The same failure in both reports is still a difference.
        self.assertEqual(self.compare(b, b)[0].split(":")[0], "first difference at height 77")

    def test_lowest_height_wins(self):
        rows = make_rows(150)
        rows[100] = rows[100]._replace(mint=0)
        fail = logscan.Failure(60, h(60), "script", TX, "0", "test-error")
        lines = self.compare(self.write(make_rows(150), failures=[fail]), self.write(rows))
        self.assertTrue(lines[0].startswith("first difference at height 60: unexpected failure in A"), lines)

    def test_expected_failure_is_identical(self):
        rows = make_rows(150)
        fails = [logscan.Failure(77, h(77), "script", TX, "1", "test-error"),
                 logscan.Failure(78, h(78), "script", "-", "-", "test-error")]
        a = self.write(rows, failures=fails)
        b = self.write(rows, failures=fails[:1])
        exp = self.expected_file("# expected\n%s script %s 1\n\n%s script - -  # trailing\n"
                                 % (h(77), TX, h(78)))
        self.assertEqual(self.compare(a, b, exp), [])
        self.assertEqual(self.cli(a, b, "--expected-failures", exp), (0, "identical\n", ""))

    def test_expected_entry_matches_without_error_text(self):
        rows = make_rows(100)
        a = self.write(rows, failures=[logscan.Failure(77, h(77), "script", TX, "1", "other text")])
        exp = self.expected_file("%s script %s 1\n" % (h(77), TX))
        self.assertEqual(self.compare(a, self.write(rows), exp), [])

    def test_expected_entry_needs_every_field(self):
        rows = make_rows(100)
        a = self.write(rows, failures=[logscan.Failure(77, h(77), "script", TX, "1", "test-error")])
        for line in ("%s script %s 2" % (h(77), TX), "%s other %s 1" % (h(77), TX),
                     "%s script %s 1" % (h(76), TX), "%s script %s 1" % (h(77), "00" * 32)):
            with self.subTest(line=line):
                self.assertNotEqual(self.compare(a, self.write(rows), self.expected_file(line + "\n")), [])

    def test_expected_entry_that_does_not_occur_is_identical(self):
        a = self.write(make_rows(150))
        b = self.write(make_rows(150))
        exp = self.expected_file("%s script %s 0\n" % (h(5), TX))
        self.assertEqual(self.compare(a, b, exp), [])
        self.assertEqual(self.cli(a, b, "--expected-failures", exp)[:2], (0, "identical\n"))

    def test_malformed_expected_line_is_an_error(self):
        a = self.write(make_rows(10))
        for text in ("%s script %s\n" % (h(1), TX), "%s script %s 0 extra\n" % (h(1), TX),
                     "nothex script %s 0\n" % TX, "%s script %s x\n" % (h(1), TX),
                     "%s script abc 0\n" % h(1)):
            with self.subTest(text=text):
                exp = self.expected_file("# header\n" + text)
                with self.assertRaisesRegex(compare.ExpectedFailuresError, "line 2"):
                    compare.load_expected(exp)
                code, out, err = self.cli(a, a, "--expected-failures", exp)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("line 2", err)

    def test_report_path_must_be_a_directory_or_report_json(self):
        a = self.write(make_rows(10))
        other = os.path.join(a, "heights.tsv.gz")
        with self.assertRaisesRegex(report.ReportError, "not a report directory or report.json: .*heights.tsv.gz"):
            report.load(other)
        code, out, err = self.cli(a, other)
        self.assertEqual(code, 2)
        self.assertIn(other, err)
        self.assertEqual(report.load(os.path.join(a, "report.json")).rows, report.load(a).rows)
        code, out, err = self.cli("report.json", a)
        self.assertEqual(code, 2)
        self.assertIn("report.json", err)

    def test_missing_report_is_an_error(self):
        a = self.write(make_rows(10))
        code, out, err = self.cli(a, os.path.join(self.tmp, "nothing"))
        self.assertEqual(code, 2)
        self.assertIn("report.json", err)


if __name__ == "__main__":
    unittest.main()
