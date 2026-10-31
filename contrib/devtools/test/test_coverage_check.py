"""Tests of contrib/devtools/coverage-check.py.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "coverage-check.py")


def load_module():
    spec = importlib.util.spec_from_file_location("coverage_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cc = load_module()


def record(path, lines=(), branches=(), test_name=""):
    """One lcov record: lines as (line, count), branches as
    (line, block, branch, count or "-"); a block may be a string with lcov's
    flags (e.g. "fU0")."""
    out = ["TN:" + test_name, "SF:" + path]
    for line, count in lines:
        out.append("DA:%d,%d" % (line, count))
    for line, block, branch, taken in branches:
        out.append("BRDA:%d,%s,%s,%s" % (line, block, branch, taken))
    out.append("LF:%d" % len(lines))
    out.append("LH:%d" % sum(1 for _, c in lines if c > 0))
    out.append("end_of_record")
    return "\n".join(out) + "\n"


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf8") as f:
            f.write(text)
        return path

    def write_json(self, name, data):
        return self.write(name, json.dumps(data))


class TracefileTest(TempDirTest):
    def test_records_of_one_file_are_merged(self):
        path = self.write("a.info",
                          record("/src/src/a.cpp", [(1, 1), (2, 0), (3, 0)], [(2, 0, 0, "-"), (2, 0, 1, 0)], "t1")
                          + record("/src/src/a.cpp", [(2, 3), (3, 0)], [(2, 0, 0, 2), (2, 0, 1, "-")], "t2"))
        files = cc.read_tracefiles([path], "/src")
        self.assertEqual(sorted(files), ["src/a.cpp"])
        cov = files["src/a.cpp"]
        self.assertEqual(cov.lines, {1: 1, 2: 3, 3: 0})
        self.assertEqual(cov.branches, {(2, 0, 0): 2, (2, 0, 1): 0})
        self.assertEqual(cc.stats(cov), cc.Stats(2, 3, 1, 2))

    def test_several_tracefiles_are_summed(self):
        a = self.write("a.info", record("/src/src/a.cpp", [(1, 0), (2, 1)], [(1, 0, 0, "-")]))
        b = self.write("b.info", record("/src/src/a.cpp", [(1, 2), (5, 0)], [(1, 0, 0, 1)])
                       + record("/src/src/b.cpp", [(1, 0)]))
        files = cc.read_tracefiles([a, b], "/src")
        self.assertEqual(files["src/a.cpp"].lines, {1: 2, 2: 1, 5: 0})
        self.assertEqual(cc.stats(files["src/a.cpp"]), cc.Stats(2, 3, 1, 1))
        self.assertEqual(cc.stats(files["src/b.cpp"]), cc.Stats(0, 1, 0, 0))

    def test_paths_are_made_relative_to_the_root(self):
        path = self.write("a.info", record("/work/tree/src/x/../a.cpp", [(1, 1)])
                          + record("/usr/include/c++/v.h", [(1, 1)]))
        files = cc.read_tracefiles([path], "/work/tree/")
        self.assertEqual(sorted(files), ["/usr/include/c++/v.h", "src/a.cpp"])

    def test_relative_root(self):
        path = self.write("a.info", record(os.path.join(self.dir, "src", "a.cpp"), [(1, 1)]))
        files = cc.read_tracefiles([path], os.path.relpath(self.dir))
        self.assertEqual(sorted(files), ["src/a.cpp"])

    def test_branch_flags(self):
        # lcov 2 marks exception (e) and fallthrough (f) branches and excluded
        # ones (U); excluded branches are not counted, as lcov does.
        path = self.write("a.info",
                          record("/src/src/a.cpp", [(5, 1)],
                                 [(5, "fU0", 0, 4), (5, "eU0", 1, 0), (5, "f0", 2, 4), (5, 0, 3, 0),
                                  (6, "eU0", 0, "-"), (7, "e1", 0, 1)], "t1")
                          + record("/src/src/a.cpp", [(5, 0)], [(5, "f0", 2, "-"), (5, 0, 3, 2)], "t2"))
        cov = cc.read_tracefiles([path], "/src")["src/a.cpp"]
        self.assertEqual(cov.branches, {(5, 0, 2): 4, (5, 0, 3): 2, (7, 1, 0): 1})
        self.assertEqual(cc.stats(cov), cc.Stats(1, 1, 3, 3))

    def test_branch_expressions(self):
        # Tools other than gcc may name a branch by an expression, commas included.
        path = self.write("a.info", record("/src/src/a.cpp", [(1, 1)], [(1, 0, "f(a, b)", 1), (1, 0, "!f(a, b)", 0)]))
        cov = cc.read_tracefiles([path], "/src")["src/a.cpp"]
        self.assertEqual(cov.branches, {(1, 0, "f(a, b)"): 1, (1, 0, "!f(a, b)"): 0})

    def test_malformed_lines_are_errors(self):
        for brda in ("BRDA:5,x0,1,0", "BRDA:5,0,1", "BRDA:5,0,1,x", "BRDA:x,0,1,0", "BRDA:5,Ue0,1,0"):
            path = self.write("c.info", "SF:/src/src/a.cpp\n%s\nend_of_record\n" % brda)
            with self.assertRaises(cc.InputError, msg=brda):
                cc.read_tracefiles([path], "/src")
        path = self.write("a.info", "SF:/src/src/a.cpp\nDA:x,1\nend_of_record\n")
        with self.assertRaises(cc.InputError):
            cc.read_tracefiles([path], "/src")
        path = self.write("b.info", "DA:1,1\n")
        with self.assertRaises(cc.InputError):
            cc.read_tracefiles([path], "/src")

    def test_stats_inside_line_ranges(self):
        cov = cc.Coverage()
        cov.lines.update({1: 1, 5: 0, 6: 2, 9: 1})
        cov.branches.update({(5, 0, 0): 1, (5, 0, 1): 0, (9, 0, 0): 1})
        self.assertEqual(cc.stats(cov, [(5, 6)]), cc.Stats(1, 2, 1, 2))
        # Overlapping ranges count each line once.
        self.assertEqual(cc.stats(cov, [(5, 6), (6, 9)]), cc.Stats(2, 3, 2, 3))
        self.assertEqual(cc.stats(cov, []), cc.Stats(0, 0, 0, 0))


class NameTest(unittest.TestCase):
    def test_function_names(self):
        cases = [
            ("ns::f(int) const", "ns::f"),
            ("double g<double>(double)", "g<double>"),
            ("main", "main"),
            ("HelpMessage(HelpMessageMode)", "HelpMessage"),
            ("HelpMessage[abi:cxx11](HelpMessageMode)", "HelpMessage"),
            ("CFoo::ToString[abi:cxx11]() const", "CFoo::ToString"),
            ("AppInitParameterInteraction()", "AppInitParameterInteraction"),
            ("ns::f(int)::{lambda(int)#1}::operator()(int) const", "ns::f(int)::{lambda(int)#1}::operator()"),
            ("ns::f(int)::{lambda(int, char)#2}::operator()(int, char) const",
             "ns::f(int)::{lambda(int, char)#2}::operator()"),
            ("unsigned long const& std::min<unsigned long>(unsigned long const&, unsigned long const&)",
             "std::min<unsigned long>"),
            ("std::vector<int, std::allocator<int> >::push_back(int&&)",
             "std::vector<int, std::allocator<int> >::push_back"),
            ("CScript::operator<<(long)", "CScript::operator<<"),
            ("CScript::operator<<(std::vector<unsigned char, std::allocator<unsigned char> > const&)",
             "CScript::operator<<"),
            ("operator<(COutPoint const&, COutPoint const&)", "operator<"),
            ("Foo::operator->() const", "Foo::operator->"),
            ("Foo::operator bool() const", "Foo::operator bool"),
            ("operator new(unsigned long)", "operator new"),
            ("(anonymous namespace)::Helper::run(int)", "(anonymous namespace)::Helper::run"),
            ("Foo::get() const &", "Foo::get"),
            ("Foo::get() &&", "Foo::get"),
            ("f(int) [clone .cold]", "f"),
            ("CChain::FindEarliestAtLeast(long) const::{lambda(CBlockIndex*)#1}::operator()(CBlockIndex*) const",
             "CChain::FindEarliestAtLeast(long) const::{lambda(CBlockIndex*)#1}::operator()"),
            ("int Foo::bar<int>() const volatile::{lambda()#1}::operator()() const",
             "Foo::bar<int>() const volatile::{lambda()#1}::operator()"),
            ("Foo::get() &&::{lambda()#1}::operator()() const", "Foo::get() &&::{lambda()#1}::operator()"),
            ("Foo::get() noexcept::{lambda()#2}::operator()() const", "Foo::get() noexcept::{lambda()#2}::operator()"),
            ("std::string const& Foo::name() const", "Foo::name"),
            ("__static_initialization_and_destruction_0(int, int)", "__static_initialization_and_destruction_0"),
        ]
        for demangled, want in cases:
            with self.subTest(demangled=demangled):
                self.assertEqual(cc.function_name(demangled), want)

    def test_display_name_drops_only_the_return_type(self):
        self.assertEqual(cc.display_name("double g<double>(double)"), "g<double>(double)")
        self.assertEqual(cc.display_name("ns::f(int) const"), "ns::f(int) const")
        self.assertEqual(cc.display_name("CChain::Find(long) const::{lambda(int)#1}::operator()(int) const"),
                         "CChain::Find(long) const::{lambda(int)#1}::operator()(int) const")


class ExtentsTest(TempDirTest):
    def test_union_of_extents_files(self):
        a = self.write_json("a.json", {"version": 1, "files": {
            "src/a.cpp": [{"demangled_name": "f(int)", "start_line": 1, "end_line": 4},
                          {"demangled_name": "g()", "start_line": 6, "end_line": 9}]}})
        b = self.write_json("b.json", {"version": 1, "files": {
            "src/a.cpp": [{"demangled_name": "g()", "start_line": 6, "end_line": 9},
                          {"demangled_name": "h()", "start_line": 11, "end_line": 12}],
            "src/b.cpp": [{"demangled_name": "k()", "start_line": 1, "end_line": 2}]}})
        extents = cc.load_extents([a, b])
        self.assertEqual([f.demangled for f in extents["src/a.cpp"]], ["f(int)", "g()", "h()"])
        self.assertEqual(extents["src/b.cpp"][0], cc.Function("k()", 1, 2))

    def test_bad_extents_are_errors(self):
        for data in [{"files": {}}, {"version": 2, "files": {}},
                     {"version": 1, "files": {"a": [{"demangled_name": "f", "start_line": 3}]}},
                     {"version": 1, "files": {"a": [{"demangled_name": "f", "start_line": 3, "end_line": 2}]}},
                     {"version": 1, "files": {}, "extra": 1}]:
            with self.subTest(data=data):
                path = self.write_json("bad.json", data)
                with self.assertRaises(cc.InputError):
                    cc.load_extents([path])


def targets(files, overall=None, tolerance=0.1):
    return {
        "tolerance": tolerance,
        "overall": overall if overall is not None else {"unit_lines": 50.0},
        "tiers": {
            "tier-1": {"unit_lines": 90.0, "unit_branches": 60.0},
            "tier-2": {"all_lines": 90.0, "unit_lines": 50.0},
        },
        "files": files,
    }


class TargetFileTest(TempDirTest):
    def load(self, data):
        return cc.load_targets(self.write_json("targets.json", data))

    def test_valid_file(self):
        t = self.load(targets([
            {"group": "tier-1", "file": "src/a.cpp", "target": "tier-1", "met": False},
            {"group": "prerequisite", "file": "src/a.cpp", "functions": ["f"], "target": {"unit_lines": 90.0},
             "met": True},
            {"group": "prerequisite", "file": "src/a.cpp", "recorded": {"all_lines": 86.8}},
        ]))
        self.assertEqual(t.entries[0].target, {"unit_lines": 90.0, "unit_branches": 60.0})
        self.assertEqual(t.entries[0].tier, "tier-1")
        self.assertEqual(t.entries[1].functions, ["f"])
        self.assertTrue(t.entries[1].met)
        self.assertEqual(t.entries[2].recorded, {"all_lines": 86.8})
        self.assertIsNone(t.entries[2].target)
        self.assertEqual(t.tolerance, 0.1)

    def test_invalid_files(self):
        good = {"group": "g", "file": "src/a.cpp", "target": "tier-1", "met": False}
        bad = [
            dict(good, comment="x"),                                  # unknown key
            dict(good, target="tier-3"),                              # unknown tier
            dict(good, target={"unit_lines": 90, "lines": 1}),        # unknown metric
            dict(good, target={}),                                    # empty target
            dict(good, target={"unit_lines": 101}),                   # out of range
            dict(good, target={"unit_lines": True}),                  # not a number
            {k: v for k, v in good.items() if k != "met"},            # target without met
            {"group": "g", "file": "src/a.cpp", "met": True, "recorded": {"all_lines": 1.0}},
            {"group": "g", "file": "src/a.cpp"},                      # nothing to check
            dict(good, recorded={"all_lines": 1.0}),                  # both kinds in one entry
            dict(good, met="yes"),
            dict(good, functions=[]),
            dict(good, functions=["f", ""]),
            {k: v for k, v in good.items() if k != "group"},
            dict(good, file=""),
            dict(good, group="guarded"),                              # guarded files are met
        ]
        for entry in bad:
            with self.subTest(entry=entry):
                with self.assertRaises(cc.InputError):
                    self.load(targets([entry]))
        with self.assertRaises(cc.InputError):
            self.load(dict(targets([good]), notes="x"))
        with self.assertRaises(cc.InputError):
            self.load(targets([good], overall={"lines": 1.0}))
        with self.assertRaises(cc.InputError):
            self.load(targets([good], tolerance=-1))
        with self.assertRaises(cc.InputError):
            self.load(dict(targets([good]), tiers={"tier-1": {"unit_lines": 90.0, "x": 1}}))
        with self.assertRaises(cc.InputError):
            self.load(targets([good, dict(good)]))                     # duplicate entry
        with self.assertRaises(cc.InputError):
            cc.load_targets(self.write("broken.json", '{"tolerance": 0.1,}'))


class CheckTest(TempDirTest):
    """check() on small tracefiles: src/a.cpp has 10 lines, 4 branches."""

    def setUp(self):
        super().setUp()
        # Unit: 9 of 10 lines, 3 of 4 branches. Functions f (1-4, a lambda at
        # 2-3), g (6-8), a gap at line 5, h (9-10).
        self.unit = {"src/a.cpp": self.cov({1: 1, 2: 1, 3: 1, 4: 1, 5: 0, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1},
                                           {(1, 0, 0): 1, (1, 0, 1): 1, (7, 0, 0): 1, (7, 0, 1): 0}),
                     "src/b.cpp": self.cov({1: 0, 2: 0}, {}),
                     "src/nobranch.h": self.cov({1: 1}, {}),
                     "/usr/include/x.h": self.cov({1: 0, 2: 0, 3: 0}, {})}
        self.all = {"src/a.cpp": self.cov({k: 1 for k in range(1, 11)},
                                          {(1, 0, 0): 1, (1, 0, 1): 1, (7, 0, 0): 1, (7, 0, 1): 1}),
                    "src/b.cpp": self.cov({1: 1, 2: 1}, {}),
                    "src/nobranch.h": self.cov({1: 1}, {})}
        self.extents = {"src/a.cpp": [cc.Function("void ns::f<int>(int)", 1, 4),
                                      cc.Function("void ns::f<int>(int)::{lambda()#1}::operator()() const", 2, 3),
                                      cc.Function("ns::g()", 6, 8),
                                      cc.Function("ns::g(int)", 7, 8),
                                      cc.Function("h()", 9, 10)]}

    @staticmethod
    def cov(lines, branches):
        c = cc.Coverage()
        c.lines.update(lines)
        c.branches.update(branches)
        return c

    def run_check(self, files, overall=None, tolerance=0.1):
        # 76.9: the overall value of these tracefiles, so it adds no notice.
        overall = overall if overall is not None else {"unit_lines": 76.9}
        t = cc.load_targets(self.write_json("targets.json", targets(files, overall, tolerance)))
        return cc.check(t, self.unit, self.all, self.extents)

    def statuses(self, report):
        return [(row.file, row.status) for row in report.rows]

    def test_overall_unit_lines_of_src(self):
        # src/: 9 + 0 + 1 of 10 + 2 + 1 lines; /usr/include is not counted.
        report = self.run_check([], overall={"unit_lines": 76.9})
        self.assertEqual(report.overall_stats["unit_lines"], (10, 13))
        self.assertEqual(report.failures, [])
        self.assertEqual(report.notices, [])

    def test_overall_fall_beyond_tolerance_fails(self):
        self.assertEqual(self.run_check([], overall={"unit_lines": 77.0}).failures, [])   # 76.92: 0.08 below
        report = self.run_check([], overall={"unit_lines": 77.1})                       # 0.18 below
        self.assertEqual(len(report.failures), 1)
        self.assertIn("overall", report.failures[0])

    def test_overall_rise_is_reported(self):
        report = self.run_check([], overall={"unit_lines": 76.9})                       # 76.92: 0.02 above
        self.assertEqual(report.failures, [])
        self.assertEqual(report.notices, [])
        for recorded in (76.8, 70.0):
            with self.subTest(recorded=recorded):
                report = self.run_check([], overall={"unit_lines": recorded})
                self.assertEqual(report.failures, [])
                self.assertEqual(len(report.notices), 1)
                self.assertIn("record the new value", report.notices[0])

    def test_met_target_below_fails(self):
        report = self.run_check([{"group": "tier-1", "file": "src/a.cpp", "target": "tier-1", "met": True}])
        # 90 % lines, 75 % branches: met.
        self.assertEqual(report.failures, [])
        self.assertEqual(self.statuses(report), [("src/a.cpp", "met")])
        report = self.run_check([{"group": "tier-1", "file": "src/a.cpp", "target": {"unit_lines": 90.1},
                                  "met": True}])
        self.assertEqual(len(report.failures), 1)
        self.assertTrue(report.rows[0].failed)
        self.assertIn("src/a.cpp", report.failures[0])

    def test_messages_show_two_decimals_and_counts(self):
        report = self.run_check([], overall={"unit_lines": 80.0})
        self.assertIn("76.92 % (10/13), recorded 80.00", report.failures[0])
        # 2249 of 2500 lines: 89.96 %, shown as 90.0 in the table.
        self.unit["src/big.cpp"] = self.cov({k: 1 if k <= 2249 else 0 for k in range(1, 2501)}, {})
        self.all["src/big.cpp"] = self.cov({k: 1 for k in range(1, 2501)}, {})
        report = self.run_check([{"group": "tier-1", "file": "src/big.cpp", "target": {"unit_lines": 90.0},
                                  "met": True},
                                 {"group": "tier-1", "file": "src/big.cpp", "recorded": {"unit_lines": 90.1}}])
        self.assertEqual(len(report.failures), 2)
        self.assertIn("89.96 % (2249/2500) < 90.00", report.failures[0])
        self.assertIn("89.96 % (2249/2500), recorded 90.10", report.failures[1])
        # 22499 of 25000 lines: 89.996 %, rounded down so it never reads as the target.
        self.unit["src/big.cpp"] = self.cov({k: 1 if k <= 22499 else 0 for k in range(1, 25001)}, {})
        report = self.run_check([{"group": "tier-1", "file": "src/big.cpp", "target": {"unit_lines": 90.0},
                                  "met": True}])
        self.assertIn("89.99 % (22499/25000) < 90.00", report.failures[0])

    def test_unmet_target_below_is_reported_without_failing(self):
        report = self.run_check([{"group": "tier-1", "file": "src/b.cpp", "target": "tier-1", "met": False}])
        self.assertEqual(report.failures, [])
        self.assertEqual(self.statuses(report), [("src/b.cpp", "below target")])
        self.assertFalse(report.rows[0].failed)

    def test_met_but_not_recorded_is_reported(self):
        report = self.run_check([{"group": "tier-2", "file": "src/b.cpp", "target": {"all_lines": 90.0},
                                  "met": False}])
        self.assertEqual(report.failures, [])
        self.assertEqual(self.statuses(report), [("src/b.cpp", "record as met")])
        self.assertEqual(len(report.notices), 1)
        self.assertIn("record as met", report.notices[0])

    def test_nothing_instrumented_counts_as_met(self):
        report = self.run_check([{"group": "prerequisite", "file": "src/nobranch.h", "target": "tier-1", "met": True}])
        self.assertEqual(report.failures, [])
        self.assertEqual(self.statuses(report), [("src/nobranch.h", "met")])

    def test_recorded_value(self):
        files = [{"group": "prerequisite", "file": "src/a.cpp", "recorded": {"unit_lines": 90.1}}]
        self.assertEqual(self.run_check(files).failures, [])
        report = self.run_check([{"group": "prerequisite", "file": "src/a.cpp", "recorded": {"unit_lines": 90.2}}])
        self.assertEqual(len(report.failures), 1)
        report = self.run_check([{"group": "prerequisite", "file": "src/a.cpp", "recorded": {"unit_lines": 89.9}}])
        self.assertEqual(report.failures, [])
        self.assertEqual(len(report.notices), 1)
        self.assertEqual(report.rows[0].status, "record the new value")

    def test_unknown_file_is_an_error(self):
        with self.assertRaises(cc.InputError):
            self.run_check([{"group": "g", "file": "src/none.cpp", "target": "tier-1", "met": False}])

    def test_function_targets(self):
        # f and its lambda: lines 1-4, all hit; branches at line 1: 2 of 2.
        report = self.run_check([{"group": "prerequisite", "file": "src/a.cpp", "functions": ["ns::f<int>"],
                                  "target": {"unit_lines": 100.0, "unit_branches": 100.0}, "met": True}])
        self.assertEqual(report.failures, [])
        self.assertEqual(report.rows[0].unit, cc.Stats(4, 4, 2, 2))
        # Both overloads of g: lines 6-8 counted once; the gap (line 5) nowhere.
        report = self.run_check([{"group": "prerequisite", "file": "src/a.cpp", "functions": ["ns::g", "h"],
                                  "target": {"unit_lines": 100.0}, "met": True}])
        self.assertEqual(report.rows[0].unit, cc.Stats(5, 5, 1, 2))
        self.assertEqual(report.failures, [])

    def test_function_name_that_matches_nothing_is_an_error(self):
        for name in ["ns::nothing", "ns::f", "g"]:
            with self.subTest(name=name):
                with self.assertRaises(cc.InputError):
                    self.run_check([{"group": "prerequisite", "file": "src/a.cpp", "functions": [name],
                                     "target": {"unit_lines": 90.0}, "met": False}])

    def test_function_targets_need_extents(self):
        self.extents = {}
        with self.assertRaises(cc.InputError):
            self.run_check([{"group": "prerequisite", "file": "src/a.cpp", "functions": ["h"],
                             "target": {"unit_lines": 90.0}, "met": False}])

    def test_per_function(self):
        rows = cc.per_function("src/a.cpp", self.unit, self.all, self.extents)
        self.assertEqual([(r.name, r.start, r.end) for r in rows],
                         [("ns::f<int>(int)", 1, 4), ("ns::f<int>(int)::{lambda()#1}::operator()() const", 2, 3),
                          ("ns::g()", 6, 8), ("ns::g(int)", 7, 8), ("h()", 9, 10)])
        self.assertEqual(rows[0].unit, cc.Stats(4, 4, 2, 2))
        self.assertEqual(rows[1].unit, cc.Stats(2, 2, 0, 0))
        self.assertEqual(rows[2].unit, cc.Stats(3, 3, 1, 2))
        self.assertEqual(rows[2].all, cc.Stats(3, 3, 2, 2))
        with self.assertRaises(cc.InputError):
            cc.per_function("src/b.cpp", self.unit, self.all, self.extents)
        with self.assertRaises(cc.InputError):
            cc.per_function("src/none.cpp", self.unit, self.all, self.extents)


class CommandLineTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.unit = self.write("unit.info", record("/src/src/a.cpp", [(1, 1), (2, 1), (3, 0)], [(1, 0, 0, 1),
                                                                                                (1, 0, 1, "-")]))
        self.all = self.write("all.info", record("/src/src/a.cpp", [(1, 1), (2, 1), (3, 1)], [(1, 0, 0, 1),
                                                                                              (1, 0, 1, 1)]))
        self.functions = self.write_json("functions.json", {"version": 1, "files": {
            "src/a.cpp": [{"demangled_name": "f()", "start_line": 1, "end_line": 2},
                          {"demangled_name": "g()", "start_line": 3, "end_line": 3}]}})

    def main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                status = cc.main(list(args))
            except SystemExit as e:
                status = e.code
        return status, out.getvalue(), err.getvalue()

    def targets_file(self, met, overall=66.7):
        return self.write_json("targets.json", targets(
            [{"group": "tier-1", "file": "src/a.cpp", "target": "tier-1", "met": met},
             {"group": "prerequisite", "file": "src/a.cpp", "functions": ["f"], "target": {"unit_lines": 90.0},
              "met": True}],
            overall={"unit_lines": overall}))

    def test_report_and_exit_status(self):
        args = ["--root", "/src", "--unit", self.unit, "--all", self.all, "--functions", self.functions]
        status, out, err = self.main(*args, "--targets", self.targets_file(False))
        self.assertEqual(status, 0, err)
        self.assertIn("src/a.cpp", out)
        self.assertIn("66.7 % (2/3)", out)
        self.assertIn("below target", out)
        self.assertIn("f", out)
        status, out, err = self.main(*args, "--targets", self.targets_file(True))
        self.assertEqual(status, 1)
        self.assertIn("FAIL", out + err)
        status, out, err = self.main(*args, "--targets", self.targets_file(False, overall=80.0))
        self.assertEqual(status, 1)

    def test_markdown_is_appended(self):
        md = self.write("summary.md", "# Earlier step\n")
        status, out, err = self.main("--root", "/src", "--unit", self.unit, "--all", self.all,
                                     "--functions", self.functions, "--targets", self.targets_file(False),
                                     "--markdown", md)
        self.assertEqual(status, 0, err)
        with open(md, encoding="utf8") as f:
            text = f.read()
        self.assertTrue(text.startswith("# Earlier step\n"))
        self.assertIn("| tier-1 | `src/a.cpp` |", text)

    def test_input_errors_exit_with_2(self):
        status, out, err = self.main("--root", "/src", "--unit", self.unit, "--all", self.all,
                                     "--targets", self.targets_file(False))
        self.assertEqual(status, 2)        # function targets without --functions
        self.assertIn("--functions", err)
        status, out, err = self.main("--root", "/src", "--unit", os.path.join(self.dir, "missing.info"),
                                     "--all", self.all, "--targets", self.targets_file(False))
        self.assertEqual(status, 2)
        status, out, err = self.main("--unit", self.unit)
        self.assertEqual(status, 2)

    def test_per_function_mode(self):
        status, out, err = self.main("--root", "/src", "--unit", self.unit, "--all", self.all,
                                     "--functions", self.functions, "--per-function", "src/a.cpp")
        self.assertEqual(status, 0, err)
        lines = [line for line in out.splitlines() if line.endswith((" f()", " g()"))]
        self.assertEqual(len(lines), 2, out)
        self.assertIn("100.0 % (2/2)", lines[0])
        self.assertIn("0.0 % (0/1)", lines[1])

    def test_default_target_file_and_root(self):
        self.assertEqual(cc.REPO_ROOT, os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
        self.assertEqual(cc.DEFAULT_TARGETS, os.path.join(cc.REPO_ROOT, "contrib", "devtools",
                                                          "coverage-targets.json"))


class CommittedTargetFileTest(unittest.TestCase):
    def test_committed_target_file_is_valid(self):
        t = cc.load_targets(cc.DEFAULT_TARGETS)
        groups = {}
        for entry in t.entries:
            groups.setdefault(entry.group, []).append(entry)
        self.assertEqual(sorted(groups), ["guarded", "prerequisite", "tier-1", "tier-2"])
        self.assertEqual(len([e for e in groups["tier-1"]]), 11)
        self.assertEqual(len([e for e in groups["tier-2"]]), 8)
        self.assertTrue(all(e.met for e in groups["guarded"]))
        self.assertFalse(any(e.met for e in groups["tier-1"] + groups["tier-2"]))


if __name__ == "__main__":
    unittest.main()
