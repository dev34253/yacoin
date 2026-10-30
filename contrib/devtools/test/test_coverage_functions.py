"""Tests of contrib/devtools/coverage-functions.py.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "coverage-functions.py")
CHECK = os.path.join(os.path.dirname(HERE), "coverage-check.py")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cf = load("coverage_functions", SCRIPT)
cc = load("coverage_check", CHECK)


def gcov_file(name, functions):
    return {"file": name, "lines": [],
            "functions": [{"name": "_Z" + d, "demangled_name": d, "start_line": s, "end_line": e,
                           "start_column": 1, "end_column": 1, "blocks": 1, "blocks_executed": 0,
                           "execution_count": 0} for d, s, e in functions]}


class ExtentsFromGcovTest(unittest.TestCase):
    def test_paths_resolved_against_the_build_dir(self):
        data = {"format_version": "1", "current_working_directory": "/elsewhere", "files": [
            gcov_file("../../../../src/init.cpp", [("HelpMessage(HelpMessageMode)", 10, 20)]),
            gcov_file("/repo/src/util.h", [("f()", 3, 4)]),
            gcov_file("/usr/include/c++/11/bits/move.h", [("std::move()", 1, 2)]),
            gcov_file("../../../../build/docker-x/depends/include/boost/a.hpp", [("boost::a()", 1, 2)]),
            gcov_file("../../../../src/./wallet/../init.cpp", [("InitLogging()", 30, 40)]),
        ]}
        got = cf.extents_from_gcov(data, "/repo/build/docker-x/cov-unit/src", "/repo")
        self.assertEqual(got, {"src/init.cpp": {("HelpMessage(HelpMessageMode)", 10, 20), ("InitLogging()", 30, 40)},
                               "src/util.h": {("f()", 3, 4)}})

    def test_bad_gcov_output_is_an_error(self):
        for data in [{}, {"files": [{"file": "a.cpp"}]},
                     {"files": [{"file": "a.cpp", "functions": [{"demangled_name": "f", "start_line": 1}]}]}]:
            with self.subTest(data=data):
                with self.assertRaises(cf.GcovError):
                    cf.extents_from_gcov(data, "/repo/src", "/repo")


class FakeGcovTest(unittest.TestCase):
    """The script with a stand-in for gcov that prints prepared JSON."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.build = os.path.join(self.dir, "repo", "build", "src")
        os.makedirs(os.path.join(self.build, "wallet"))
        self.outputs = {}
        for rel, functions in [("a.gcno", [("f(int)", 1, 5)]),
                               ("wallet/a.gcno", [("g()", 2, 3), ("f(int)", 1, 5)]),
                               ("wallet/b.gcno", [("h()", 7, 9)])]:
            path = os.path.join(self.build, rel)
            with open(path, "w") as f:
                f.write(rel)
            # The counters the tests may be writing at the same time: gcov
            # must not be pointed at them.
            with open(path[:-5] + ".gcda", "w") as f:
                f.write("data")
            self.outputs[rel] = {"format_version": "1", "files": [gcov_file("../../src/a.cpp", functions)]}
        self.fake = os.path.join(self.dir, "fake-gcov.py")
        with open(self.fake, "w") as f:
            f.write(textwrap.dedent("""\
                import json, os, sys
                args = sys.argv[1:]
                assert args[:2] == ["-j", "-t"], args
                gcno = args[2]
                outputs = json.load(open(os.environ["FAKE_GCOV_OUTPUTS"]))
                # The script hands gcov a link to the .gcno in a directory
                # of its own, without the .gcda.
                target = os.path.realpath(gcno)
                assert target != os.path.abspath(gcno), gcno
                assert not os.path.exists(gcno[:-5] + ".gcda"), gcno
                with open(target) as f:
                    rel = f.read()
                if rel == "wallet/b.gcno" and os.environ.get("FAKE_GCOV_FAIL"):
                    sys.stderr.write("b.gcno: cannot open notes file\\n")
                    sys.exit(1)
                sys.stderr.write("b.gcda: cannot open data file, assuming not executed\\n")
                print(json.dumps(outputs[rel]))
                """))
        self.outputs_file = os.path.join(self.dir, "outputs.json")
        with open(self.outputs_file, "w") as f:
            json.dump(self.outputs, f)
        os.environ["FAKE_GCOV_OUTPUTS"] = self.outputs_file

    def tearDown(self):
        os.environ.pop("FAKE_GCOV_OUTPUTS", None)
        os.environ.pop("FAKE_GCOV_FAIL", None)
        self._tmp.cleanup()

    def run_script(self, *extra):
        out = os.path.join(self.dir, "functions.json")
        cmd = [sys.executable, "-I", SCRIPT, "--gcov", "%s %s" % (sys.executable, self.fake),
               "--dir", self.build, "--root", os.path.join(self.dir, "repo"), "--out", out] + list(extra)
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return result, out

    def test_union_over_all_gcno_files(self):
        result, out = self.run_script("--jobs", "3")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(out) as f:
            data = json.load(f)
        self.assertEqual(data, {"version": 1, "files": {"src/a.cpp": [
            {"demangled_name": "f(int)", "start_line": 1, "end_line": 5},
            {"demangled_name": "g()", "start_line": 2, "end_line": 3},
            {"demangled_name": "h()", "start_line": 7, "end_line": 9}]}})
        # coverage-check.py reads it.
        extents = cc.load_extents([out])
        self.assertEqual([f.demangled for f in extents["src/a.cpp"]], ["f(int)", "g()", "h()"])
        # The .gcda files are left alone and no temporary files remain.
        self.assertTrue(os.path.exists(os.path.join(self.build, "wallet", "b.gcda")))
        self.assertEqual(sorted(os.listdir(self.dir)), ["fake-gcov.py", "functions.json", "outputs.json", "repo"])

    def test_gcov_failure_fails_and_writes_nothing(self):
        os.environ["FAKE_GCOV_FAIL"] = "1"
        result, out = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot open notes file", result.stderr)
        self.assertIn("b.gcno", result.stderr)
        self.assertFalse(os.path.exists(out))

    def test_no_gcno_files_is_an_error(self):
        shutil.rmtree(self.build)
        os.makedirs(self.build)
        result, out = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(".gcno", result.stderr)


@unittest.skipUnless(shutil.which("g++") and shutil.which("gcov"), "needs g++ and gcov")
class RealGcovTest(unittest.TestCase):
    def test_extents_of_a_compiled_file(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src")
            obj = os.path.join(d, "build", "src")
            os.makedirs(src)
            os.makedirs(obj)
            with open(os.path.join(src, "a.cpp"), "w") as f:
                f.write(textwrap.dedent("""\
                    namespace ns {
                    int f(int x) {
                        auto l = [](int y) {
                            return y * 2;
                        };
                        if (x > 3) return l(x);
                        return 0;
                    }
                    }
                    template<typename T> T g(T t) { return t + 1; }

                    int main(int argc, char**) { return ns::f(argc) + g(argc) + int(g(1.0)); }
                    """))
            subprocess.run(["g++", "-O0", "--coverage", "-c", "../../src/a.cpp", "-o", "a.o"], cwd=obj, check=True)
            out = os.path.join(d, "functions.json")
            subprocess.run([sys.executable, "-I", SCRIPT, "--gcov", shutil.which("gcov"), "--dir", obj,
                            "--root", d, "--out", out], check=True, stdout=subprocess.DEVNULL)
            extents = cc.load_extents([out])
            got = {(cc.function_name(f.demangled), f.start, f.end) for f in extents["src/a.cpp"]}
            self.assertEqual(got, {("ns::f", 2, 8), ("ns::f(int)::{lambda(int)#1}::operator()", 3, 5),
                                   ("g<int>", 10, 10), ("g<double>", 10, 10), ("main", 12, 12)})


if __name__ == "__main__":
    unittest.main()
