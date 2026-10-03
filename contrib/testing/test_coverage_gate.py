#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for coverage_gate.py (task P0-04) on a small synthetic tracefile.

Run: python3 contrib/testing/test_coverage_gate.py
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage_gate  # noqa: E402

SOURCE = """\
int f(int x)
{
    if (fDebug)
    {
        LogPrintf("x { ; /* ");   // } brace in a string and a comment
    }
    if (fTestNet || x > 1)
        return 1;
    return 0;
}
int dead(int y)
{
    return y;
}
int g(bool b)
{
    if (fDebug) LogPrintf("a;b");
    return b ? 1 : 2;
}
struct S { S(); };
S::S()
{
}
int h(bool b)
{
    if (fDebugElse) { LogPrintf("h"); } else { return 1; }
    return 0;
}
"""

# f, g, S::S() (two constructor variants) ran; dead did not.
TRACEFILE = """\
TN:
SF:/work/src/src/a.cpp
FN:1,10,_Z1fi
FN:11,14,_Z4deadi
FN:15,19,_Z1gb
FN:21,23,_ZN1SC2Ev
FN:21,23,_ZN1SC1Ev
FNDA:5,_Z1fi
FNDA:0,_Z4deadi
FNDA:2,_Z1gb
FNDA:0,_ZN1SC2Ev
FNDA:1,_ZN1SC1Ev
DA:1,5
DA:3,5
DA:5,0
DA:7,5
DA:8,3
DA:9,2
DA:11,0
DA:13,0
DA:15,2
DA:17,2
DA:18,2
DA:21,1
DA:23,1
BRDA:3,0,0,0
BRDA:3,0,1,5
BRDA:7,0,0,5
BRDA:7,0,1,0
BRDA:7,0,2,3
BRDA:7,0,3,2
BRDA:7,e1,0,0
BRDA:13,e0,0,-
BRDA:13,e0,1,-
BRDA:18,0,0,1
BRDA:18,0,1,1
end_of_record
SF:/work/src/src/b.cpp
DA:1,1
DA:2,0
end_of_record
"""

CONFIG = """\
[[exclude]]
kind = "function"
path = "src/a.cpp"
functions = ["dead"]
reason = "dead"

[[exclude]]
kind = "lines"
path = "src/a.cpp"
match = '^\\s*if \\(fDebug\\)'
extent = "block"
all = true
reason = "debug logging"

[[exclude]]
kind = "branches"
path = "src/a.cpp"
match = 'fTestNet \\|\\|'
outcomes = ["0,1"]
branches_on_line = 4
reason = "fTestNet"

[[gate]]
name = "overall"
min = { lines = %(overall_lines)s, functions = 50, branches = 50 }

[[gate]]
name = "f"
paths = ["src/a.cpp"]
select_functions = ["f(int)"]
min = { lines = 60, branches = 80 }
"""


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        os.makedirs(os.path.join(root, "src"))
        self.write("src/a.cpp", SOURCE)
        self.write("merged.info", TRACEFILE)
        self.write_config(CONFIG % {"overall_lines": 70})

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        with open(os.path.join(self.tmp.name, rel), "w") as fh:
            fh.write(text)

    def write_config(self, text):
        self.write("gates.toml", text)

    def run_gate(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = coverage_gate.main([os.path.join(self.tmp.name, "merged.info"),
                                       "--config", os.path.join(self.tmp.name, "gates.toml"),
                                       "--source-root", self.tmp.name] + list(extra))
        return code, out.getvalue(), err.getvalue()

    def results(self):
        files = coverage_gate.parse_tracefile(os.path.join(self.tmp.name, "merged.info"))
        config = coverage_gate.load_config(os.path.join(self.tmp.name, "gates.toml"))
        gate = coverage_gate.Gate(files, config, self.tmp.name)
        gate.apply_exclusions()
        return {(r["gate"], r["metric"]): r for r in gate.evaluate()}, gate

    # -- statement extent
    def test_block_extent(self):
        src = SOURCE.split("\n")
        self.assertEqual(coverage_gate.statement_extent(src, 3), (3, 6))   # braces, '}' in string/comment
        self.assertEqual(coverage_gate.statement_extent(src, 7), (7, 8))   # if without braces
        self.assertEqual(coverage_gate.statement_extent(src, 17), (17, 17))  # ';' in a string
        with self.assertRaisesRegex(coverage_gate.GateError, "else"):
            coverage_gate.statement_extent(src, 26)

    # -- numbers after exclusions
    def test_numbers(self):
        res, gate = self.results()
        # a.cpp lines left: 1,7,8,9 (f) 15,18 (g) 21,23 (S) -> 8, all hit;
        # b.cpp: 1 of 2. dead() (11,13) and the fDebug lines 3,5,17 removed.
        self.assertEqual((res["overall", "lines"]["hit"], res["overall", "lines"]["total"]), (9, 10))
        # functions: f, g, S::S() once (one variant ran) -> 3 of 3.
        self.assertEqual((res["overall", "functions"]["hit"], res["overall", "functions"]["total"]), (3, 3))
        # branches: line 7 keeps 3 of 4 (dead outcome 0,1 removed, exception
        # branch not counted), line 18 two taken -> 5 of 5.
        self.assertEqual((res["overall", "branches"]["hit"], res["overall", "branches"]["total"]), (5, 5))
        # function group f: lines 1,7,8,9 and branches of line 7.
        self.assertEqual((res["f", "lines"]["hit"], res["f", "lines"]["total"]), (4, 4))
        self.assertEqual((res["f", "branches"]["hit"], res["f", "branches"]["total"]), (3, 3))
        self.assertTrue(all(r["ok"] for r in res.values()))
        removed = [r for _, _, r in gate.log]
        self.assertIn((2, 0, 1), removed)   # dead(): 2 lines, exception branches not counted, 1 function

    def test_exception_branches_counted_when_enabled(self):
        self.write_config("[settings]\nexception_branches = true\n" + CONFIG % {"overall_lines": 70})
        res, _ = self.results()
        # line 7: 4 normal + 1 exception, the dead one removed -> 3 of 4.
        self.assertEqual((res["overall", "branches"]["hit"], res["overall", "branches"]["total"]), (5, 6))

    # -- exit codes
    def test_pass_exit_0(self):
        code, out, _ = self.run_gate("--verbose", "--suggest")
        self.assertEqual(code, 0, out)
        self.assertIn("all 5 checks passed", out)
        self.assertIn("lines 3-6", out)

    def test_below_minimum_exit_1(self):
        self.write_config(CONFIG % {"overall_lines": 95})
        code, out, _ = self.run_gate()
        self.assertEqual(code, 1)
        self.assertIn("overall lines 90.00% < minimum 95%", out)

    def test_stale_function_exit_2(self):
        self.write_config(CONFIG.replace('["dead"]', '["gone"]') % {"overall_lines": 70})
        code, _, err = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("'gone' not found", err)

    def test_stale_anchor_exit_2(self):
        self.write_config(CONFIG.replace("fTestNet \\|\\|", "fTestNet &&") % {"overall_lines": 70})
        code, _, err = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("found 0 lines", err)

    def test_dead_branch_that_ran(self):
        # Tests that set fTestNet run the dead outcome: it is removed from
        # the covered and the total count.
        self.write_config(CONFIG.replace('"0,1"', '"0,2"') % {"overall_lines": 70})
        res, gate = self.results()
        self.assertEqual((res["overall", "branches"]["hit"], res["overall", "branches"]["total"]), (4, 5))
        self.assertIn("(1 ran)", gate.log[-1][1])

    def test_branch_count_changed_exit_2(self):
        self.write_config(CONFIG.replace("branches_on_line = 4", "branches_on_line = 6") % {"overall_lines": 70})
        code, _, err = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("has 4 branch outcomes, config expects 6", err)

    def test_unverified_outcome_on_a_line_that_runs_exit_2(self):
        self.write_config(CONFIG.replace("branches_on_line = 4", "branches_on_line = 4\nverified = false")
                          % {"overall_lines": 70})
        code, _, err = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("now runs", err)

    def test_unknown_outcome_exit_2(self):
        self.write_config(CONFIG.replace('"0,1"', '"3,1"') % {"overall_lines": 70})
        code, _, err = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("no branch outcome 3,1", err)

    def test_missing_file_exit_2(self):
        self.write_config(CONFIG.replace('paths = ["src/a.cpp"]', 'paths = ["src/c.cpp"]')
                          % {"overall_lines": 70})
        code, _, err = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("src/c.cpp: not found", err)

    def test_bad_config_exit_2(self):
        self.write_config('[[gate]]\nname = "x"\nmin = { lines = 101 }\n')
        code, _, err = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("0-100", err)

    def test_invalid_regex_exit_2(self):
        self.write_config(CONFIG.replace("fTestNet \\|\\|", "fTestNet [") % {"overall_lines": 70})
        code, _, err = self.run_gate()
        self.assertEqual(code, 2)
        self.assertIn("not a valid regex", err)

    def test_suggest_rule(self):
        self.assertEqual(coverage_gate.suggest(100.0), 100)
        self.assertEqual(coverage_gate.suggest(70.4), 69)
        self.assertEqual(coverage_gate.suggest(70.6), 70)
        self.assertEqual(coverage_gate.suggest(0.2), 0)


if __name__ == "__main__":
    unittest.main()
