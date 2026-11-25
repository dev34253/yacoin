"""Tests of contrib/devtools/warning-count.py.

The build logs here are synthetic warning lines in the formats gcc and clang
print, with paths as an out-of-tree build in /src/build/<dir> prints them.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "warning-count.py")
ROOT = "/src"

# Synthetic warning lines.
PARAM = "../../../../src/example.cpp:10:5: warning: unused parameter 'x' [-Wunused-parameter]"
VARIABLE = "../../../../src/example.cpp:12:5: warning: unused variable 'x' [-Wunused-variable]"
HEADER = "../../../../src/timestamps.h:10:5: warning: implicitly-declared copy constructor is deprecated [-Wdeprecated-copy]"


def load_module():
    spec = importlib.util.spec_from_file_location("warning_count", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WarningCountTest(unittest.TestCase):
    def setUp(self):
        self.wc = load_module()
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf8") as f:
            f.write(text)
        return path

    def log(self, *lines):
        return self.write("build.log", "".join(line + "\n" for line in lines))

    def values(self, data):
        return self.write("values.json", data if isinstance(data, str) else json.dumps(data))

    def count(self, *lines):
        return self.wc.count(lines, ROOT)

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                status = self.wc.main(list(argv))
            except SystemExit as e:  # argparse's usage errors
                status = e.code
        return status, out.getvalue(), err.getvalue()

    def assertWarning(self, line, path, number, column, cls, component):
        w = self.wc.parse_line(line, ROOT)
        self.assertIsNotNone(w, line)
        self.assertEqual((w.path, w.line, w.column, w.cls, w.component), (path, number, column, cls, component))


class ParserTest(WarningCountTest):
    def test_line_with_column_and_flag(self):
        self.assertWarning(PARAM, "src/example.cpp", 10, 5, "-Wunused-parameter", "src")

    def test_line_without_column(self):
        self.assertWarning("../../../../src/example.cpp:12: warning: unused variable 'x' [-Wunused-variable]",
                           "src/example.cpp", 12, None, "-Wunused-variable", "src")

    def test_macro_redefinition_without_flag(self):
        self.assertWarning('../../../../src/timestamps.h:12: warning: "FOO" redefined',
                           "src/timestamps.h", 12, None, '(no flag: "X" redefined)', "src")

    def test_extra_tokens_without_flag(self):
        self.assertWarning("../../../../src/clientversion.cpp:10:5: warning: extra tokens at end of #include directive",
                           "src/clientversion.cpp", 10, 5, "(no flag: extra tokens at end of #include directive)", "src")

    def test_two_macro_names_give_one_class(self):
        c = self.count('../../../../src/timestamps.h:10: warning: "FOO" redefined',
                       '../../../../src/timestamps.h:12: warning: "BAR" redefined')
        self.assertEqual(c.unique_by_class(), {'(no flag: "X" redefined)': 2})

    def test_clang_style_line(self):
        self.assertWarning("../../../../src/example.cpp:12:5: warning: something odd [-Wfoo]",
                           "src/example.cpp", 12, 5, "-Wfoo", "src")

    def test_flag_with_equals_sign_is_kept(self):
        self.assertWarning("../../../../src/example.cpp:12:5: warning: something odd [-Wfoo=]",
                           "src/example.cpp", 12, 5, "-Wfoo=", "src")

    def test_colour_codes_are_ignored(self):
        line = ("\x1b[01m\x1b[K../../../../src/example.cpp:10:5:\x1b[m\x1b[K \x1b[01;35m\x1b[Kwarning: \x1b[m\x1b[K"
                "unused parameter '\x1b[01m\x1b[Kx\x1b[m\x1b[K' [\x1b[01;35m\x1b[K-Wunused-parameter\x1b[m\x1b[K]")
        self.assertWarning(line, "src/example.cpp", 10, 5, "-Wunused-parameter", "src")

    def test_lines_that_are_not_warnings_are_ignored(self):
        for line in ["../../../../src/example.cpp:10:5: note: declared here",
                     "In file included from ../../../../src/example.cpp:10:",
                     "                 from ../../../../src/example.cpp:12,",
                     "../../../../src/example.cpp:10:5: error: 'x' was not declared in this scope",
                     "make[2]: Entering directory '/src/build/x/src'",
                     "make: warning: jobserver unavailable: using -j1",
                     "libtool: warning: something",
                     "warning: no file and line",
                     "   10 |     int x;",
                     "      |         ^",
                     ""]:
            self.assertIsNone(self.wc.parse_line(line, ROOT), line)

    def test_empty_log_gives_zero_counts(self):
        c = self.count()
        self.assertEqual((c.total_emitted(), len(c.locations)), (0, 0))
        self.assertEqual(c.unique_by_class(), {})


class UniqueTest(WarningCountTest):
    def test_header_warning_of_three_translation_units(self):
        c = self.count(HEADER, PARAM, HEADER, HEADER)
        self.assertEqual(c.emitted["-Wdeprecated-copy"], 3)
        self.assertEqual(c.unique_by_class()["-Wdeprecated-copy"], 1)
        self.assertEqual((c.total_emitted(), len(c.locations)), (4, 2))

    def test_one_place_with_two_flags_is_two_locations(self):
        c = self.count("../../../../src/example.cpp:10:5: warning: unused variable 'x' [-Wunused-variable]",
                       "../../../../src/example.cpp:10:5: warning: something odd [-Wfoo]")
        self.assertEqual(len(c.locations), 2)
        self.assertEqual(c.unique_by_class(), {"-Wunused-variable": 1, "-Wfoo": 1})

    def test_with_and_without_column_are_two_locations(self):
        c = self.count("../../../../src/example.cpp:10:5: warning: something odd [-Wfoo]",
                       "../../../../src/example.cpp:10: warning: something odd [-Wfoo]")
        self.assertEqual(len(c.locations), 2)


class PathTest(WarningCountTest):
    def where(self, path):
        w = self.wc.parse_line(path + ":10:5: warning: something odd [-Wfoo]", ROOT)
        return w.path, w.component

    def test_absolute_under_the_root(self):
        self.assertEqual(self.where("/src/src/clientversion.cpp"), ("src/clientversion.cpp", "src"))

    def test_relative_to_the_build_directory(self):
        self.assertEqual(self.where("../../../src/clientversion.cpp"), ("src/clientversion.cpp", "src"))

    def test_dot_dot_inside_the_path(self):
        self.assertEqual(self.where("/src/src/consensus/../timestamps.h"), ("src/timestamps.h", "src"))
        self.assertEqual(self.where("../../../../src/consensus/../timestamps.h"), ("src/timestamps.h", "src"))

    def test_depends_headers(self):
        self.assertEqual(self.where("/src/build/docker-ubuntu.22.04/depends/include/boost/x.hpp"),
                         ("depends/include/boost/x.hpp", "depends"))
        self.assertEqual(self.where("../../depends/include/boost/x.hpp"), ("depends/include/boost/x.hpp", "depends"))

    def test_depends_after_the_first_depends_component(self):
        self.assertEqual(self.where("/src/depends/x86_64-pc-linux-gnu/include/depends/x.h"),
                         ("depends/x86_64-pc-linux-gnu/include/depends/x.h", "depends"))

    def test_components(self):
        for path, component in [("../../../../src/test/example_tests.cpp", "src/test"),
                                ("../../../../src/wallet/test/example_tests.cpp", "src/wallet/test"),
                                ("../../../../src/leveldb/db/example.cc", "src/leveldb"),
                                ("../../../../src/secp256k1/src/example.c", "src/secp256k1"),
                                ("../../../../src/univalue/lib/example.cpp", "src/univalue"),
                                ("../../../../src/wallet/example.cpp", "src"),
                                ("../../../../src/example.cpp", "src")]:
            self.assertEqual(self.where(path)[1], component, path)

    def test_outside_src_and_depends(self):
        self.assertEqual(self.where("/usr/include/x.h"), ("/usr/include/x.h", "other"))
        self.assertEqual(self.where("config/example.h"), ("config/example.h", "other"))
        self.assertEqual(self.where("/srcx/src/example.cpp"), ("/srcx/src/example.cpp", "other"))

    def test_same_location_absolute_and_relative_counts_once(self):
        c = self.count("/src/src/clientversion.cpp:10:5: warning: something odd [-Wfoo]",
                       "../../../src/clientversion.cpp:10:5: warning: something odd [-Wfoo]",
                       "/src/build/docker-ubuntu.22.04/depends/include/boost/x.hpp:12:5: warning: something odd [-Wfoo]",
                       "../../depends/include/boost/x.hpp:12:5: warning: something odd [-Wfoo]")
        self.assertEqual((c.total_emitted(), len(c.locations)), (4, 2))
        self.assertEqual(c.unique_by_component(), {"src": 1, "depends": 1})


class OutputTest(WarningCountTest):
    def test_every_class_and_component_is_printed(self):
        lines = ["../../../../src/example.cpp:%d:5: warning: something odd [-Wfoo%d]" % (10 + i, i) for i in range(12)]
        lines += [HEADER, HEADER, "../../../../src/test/example_tests.cpp:10:5: warning: something odd [-Wfoo]"]
        status, out, err = self.run_main("--root", ROOT, self.log(*lines))
        self.assertEqual((status, err), (0, ""))
        self.assertIn("warnings in %s: 15 emitted, 14 unique locations" % os.path.join(self.dir, "build.log"), out)
        rows = {line.split()[0]: line.split()[1:] for line in out.splitlines() if line.strip()}
        for i in range(12):
            self.assertEqual(rows["-Wfoo%d" % i], ["1", "1"])
        self.assertEqual(rows["-Wdeprecated-copy"], ["2", "1"])
        self.assertEqual(rows["-Wfoo"], ["1", "1"])
        self.assertEqual(rows["src"], ["14", "13"])
        self.assertEqual(rows["src/test"], ["1", "1"])
        for component in ("src/wallet/test", "src/leveldb", "src/secp256k1", "src/univalue", "depends", "other"):
            self.assertEqual(rows[component], ["0", "0"])

    def test_classes_sorted_by_unique_locations_then_name(self):
        status, out, _ = self.run_main("--root", ROOT, self.log(
            "../../../../src/example.cpp:10:5: warning: something odd [-Wfoo]", PARAM, VARIABLE,
            "../../../../src/example.cpp:14:5: warning: unused variable 'x' [-Wunused-variable]"))
        self.assertEqual(status, 0)
        names = [line.split()[0] for line in out.splitlines() if line.startswith("-W")]
        self.assertEqual(names, ["-Wunused-variable", "-Wfoo", "-Wunused-parameter"])

    def test_empty_log_without_values(self):
        status, out, err = self.run_main("--root", ROOT, self.log())
        self.assertEqual((status, err), (0, ""))
        self.assertIn(": 0 emitted, 0 unique locations", out)


class GateTest(WarningCountTest):
    def gate(self, values, *lines):
        return self.run_main("--root", ROOT, "--values", self.values(values), self.log(*lines))

    def test_counts_equal_to_the_values_pass(self):
        status, out, err = self.gate({"-Wunused-parameter": 1, "-Wdeprecated-copy": 1}, PARAM, HEADER, HEADER)
        self.assertEqual((status, err), (0, ""))
        self.assertIn("warning count: 0 failure(s), 0 to lower", out)
        self.assertNotIn("FAIL", out)

    def test_class_above_its_value_fails_and_lists_its_locations(self):
        status, out, _ = self.gate({"-Wunused-variable": 1, "-Wunused-parameter": 1}, PARAM, VARIABLE,
                                   "../../../../src/timestamps.h:10:5: warning: unused variable 'x' [-Wunused-variable]")
        self.assertEqual(status, 1)
        lines = out.splitlines()
        i = lines.index("FAIL  -Wunused-variable: 2 unique locations, recorded 1")
        self.assertEqual(lines[i + 1:i + 3], ["  src/example.cpp:12:5", "  src/timestamps.h:10:5"])
        self.assertFalse(lines[i + 3].startswith("  "))
        self.assertNotIn("src/example.cpp:10:5", out)
        self.assertIn("warning count: 1 failure(s), 0 to lower", out)

    def test_class_without_value_fails_and_lists_its_locations(self):
        status, out, _ = self.gate({"-Wunused-parameter": 1}, PARAM, "../../../../src/example.cpp:12: warning: odd [-Wfoo]")
        self.assertEqual(status, 1)
        lines = out.splitlines()
        i = lines.index("FAIL  -Wfoo: 1 unique location, no recorded value")
        self.assertEqual(lines[i + 1], "  src/example.cpp:12")

    def test_class_below_its_value_passes_with_a_note(self):
        status, out, _ = self.gate({"-Wunused-parameter": 3}, PARAM)
        self.assertEqual(status, 0)
        self.assertIn("NOTE  -Wunused-parameter: 1 unique location, recorded 3: lower the recorded value to 1", out)
        self.assertIn("warning count: 0 failure(s), 1 to lower", out)

    def test_class_in_the_values_and_not_in_the_log_is_below(self):
        status, out, _ = self.gate({"-Wunused-parameter": 1, "-Wfoo": 2}, PARAM)
        self.assertEqual(status, 0)
        self.assertIn("NOTE  -Wfoo: 0 unique locations, recorded 2: lower the recorded value to 0", out)

    def test_class_recorded_as_zero_and_absent_passes(self):
        status, out, _ = self.gate({"-Wunused-parameter": 1, "-Wfoo": 0}, PARAM)
        self.assertEqual(status, 0)
        self.assertIn("warning count: 0 failure(s), 0 to lower", out)

    def test_status_column(self):
        status, out, _ = self.gate({"-Wunused-parameter": 1, "-Wunused-variable": 2, "-Wdeprecated-copy": 0},
                                   PARAM, VARIABLE, HEADER, "../../../../src/example.cpp:12: warning: odd [-Wfoo]")
        self.assertEqual(status, 1)
        rows = {line.split()[0]: line.split()[1:] for line in out.splitlines() if line.startswith("-W")}
        self.assertEqual(rows["-Wunused-parameter"], ["1", "1", "1", "ok"])
        self.assertEqual(rows["-Wunused-variable"], ["1", "1", "2", "below"])
        self.assertEqual(rows["-Wdeprecated-copy"], ["1", "1", "0", "above"])
        self.assertEqual(rows["-Wfoo"], ["1", "1", "-", "no", "value"])

    def test_log_without_warnings_and_values_above_zero_fails(self):
        log = self.log("make: Nothing to be done for 'all'.")
        status, out, err = self.run_main("--root", ROOT, "--values", self.values({"-Wunused-parameter": 1}), log)
        self.assertEqual((status, out), (2, ""))
        self.assertIn("warning-count: error: %s: no warnings in the log" % log, err)

    def test_log_without_warnings_and_values_of_zero_passes(self):
        status, _, err = self.gate({"-Wunused-parameter": 0})
        self.assertEqual((status, err), (0, ""))
        status, _, err = self.gate({})
        self.assertEqual((status, err), (0, ""))

    def test_unwritable_markdown_file_is_an_input_error(self):
        md = os.path.join(self.dir, "missing", "summary.md")
        status, _, err = self.run_main("--root", ROOT, "--values", self.values({"-Wunused-parameter": 1}),
                                       "--markdown", md, self.log(PARAM))
        self.assertEqual(status, 2)
        self.assertIn("warning-count: error: %s: " % md, err)

    def test_markdown_holds_the_tables_without_locations(self):
        md = self.write("summary.md", "earlier text\n")
        status, _, _ = self.run_main("--root", ROOT, "--values", self.values({"-Wunused-variable": 0, "-Wfoo": 2}),
                                     "--markdown", md, self.log(PARAM, VARIABLE))
        self.assertEqual(status, 1)
        with open(md, encoding="utf8") as f:
            text = f.read()
        self.assertTrue(text.startswith("earlier text\n"))
        self.assertIn("| `-Wunused-variable` | 1 | 1 | 0 | **above** |", text)
        self.assertIn("| `src` | 2 | 2 |", text)
        self.assertIn("- -Wunused-variable: 1 unique location, recorded 0", text)
        self.assertIn("- -Wunused-parameter: 1 unique location, no recorded value", text)
        self.assertIn("- -Wfoo: 0 unique locations, recorded 2: lower the recorded value to 0", text)
        self.assertNotIn("src/example.cpp", text)


class InputTest(WarningCountTest):
    def assertInputError(self, argv, *texts):
        status, out, err = self.run_main(*argv)
        self.assertEqual(status, 2)
        for text in texts:
            self.assertIn(text, err)
        return out

    def test_bad_values_files(self):
        log = self.log(PARAM)
        missing = os.path.join(self.dir, "missing.json")
        self.assertInputError(["--values", missing, log], "warning-count: error: %s: " % missing)
        for name, text in [("not JSON", "{"), ("not an object", "[1]"), ("a negative value", '{"-Wfoo": -1}'),
                           ("a fraction", '{"-Wfoo": 1.5}'), ("a string", '{"-Wfoo": "1"}'), ("a boolean", '{"-Wfoo": true}'),
                           ("null", '{"-Wfoo": null}'), ("a class twice", '{"-Wfoo": 1, "-Wfoo": 2}')]:
            with self.subTest(name):
                values = self.values(text)
                out = self.assertInputError(["--values", values, log], "warning-count: error: %s: " % values)
                self.assertEqual(out, "")

    def test_missing_log(self):
        missing = os.path.join(self.dir, "missing.log")
        self.assertInputError([missing], "warning-count: error: %s: " % missing)
        self.assertInputError(["--values", self.values({"-Wfoo": 1}), missing], "warning-count: error: %s: " % missing)

    def test_check_values(self):
        status, out, err = self.run_main("--values", self.values({"-Wfoo": 2, "-Wunused-parameter": 1}), "--check-values")
        self.assertEqual((status, err), (0, ""))
        self.assertIn("2 classes, 3 unique locations", out)
        values = self.values("{")
        self.assertInputError(["--values", values, "--check-values"], "warning-count: error: %s: " % values)

    def test_check_values_needs_values_and_no_log(self):
        self.assertInputError(["--check-values"], "--check-values")
        self.assertInputError(["--values", self.values({"-Wfoo": 1}), "--check-values", self.log(PARAM)], "--check-values")

    def test_no_log(self):
        self.assertInputError([], "LOG")
        self.assertInputError(["--values", self.values({"-Wfoo": 1})], "LOG")


if __name__ == "__main__":
    unittest.main()
