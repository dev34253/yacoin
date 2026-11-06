"""Tests of contrib/devtools/run-unit-suites.sh.

The test binary is a fake: a shell script that lists suites for
--list_content and, for --run_test=<selector>, prints what the test gives it
and exits with the given status. A run marked "colour" prints its stderr in
colour unless --color_output=no is given, whatever the environment says. A
run marked "xml" prints that stderr instead when BOOST_TEST_OUTPUT_FORMAT is
set, whatever the options say, as Boost 1.64 does. A run with "cases" prints
an "Entering test case" line for each of its cases that no
--run_test=!<selector>/<case> option leaves out, as Boost 1.64 applies such
disabling filters after the selector. Every call also records the
BOOST_TEST_* variables it was started with.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "run-unit-suites.sh")

# Boost.Test's summary of a completed run without errors (report level confirm)
NO_ERRORS = "\n*** No errors detected\n"
# The same summary as Boost.Test prints it with colour output on
NO_ERRORS_COLOURED = "\n\033[1;32;49m*** No errors detected\033[0;39;49m\n"
# The same summary with BOOST_TEST_OUTPUT_FORMAT=XML
XML_REPORT = '<TestResult><TestSuite name="Bitcoin Test Suite" result="passed"/></TestResult>'
ENTERING = "Entering test module \"Bitcoin Test Suite\"\n" \
           "test/x.cpp(10): Entering test suite \"{0}\"\n" \
           "test/x.cpp(12): Entering test case \"{0}_case\"\n"
# --list_content of the suites with several cases (the fake prints it on
# stderr, as Boost.Test does: a "*" after the name of a unit enabled by
# default, then its description, if any)
CASES_LISTING = "a_tests*\n    case_one*\n    case_two*: the second case\n    case_three*\n" \
                "b_tests*\n    b_case*\n    nested_tests*\n        inner_case*\n"


def passing(stdout="", stderr=NO_ERRORS):
    return {"stdout": stdout, "stderr": stderr, "status": 0}


class RunUnitSuitesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="run-unit-suites-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = os.path.join(self.tmp, "test_bitcoin")
        self.logdir = os.path.join(self.tmp, "logs")
        self.argsdir = os.path.join(self.tmp, "args")
        os.mkdir(self.argsdir)
        self.envdir = os.path.join(self.tmp, "env")
        os.mkdir(self.envdir)

    def write_bin(self, suites, listing=None, listing_status=0):
        """suites: selector -> {"stdout", "stderr", "status"} and optionally
        "colour": the stderr printed instead unless --color_output=no is given,
        "xml": the stderr printed instead when BOOST_TEST_OUTPUT_FORMAT is set,
        "cases": the names of the test cases the selector runs.
        listing: the output of --list_content (default: every selector as a
        suite)."""
        if listing is None:
            listing = "".join("%s*\n    %s_case*\n" % (s, s) for s in suites)
        lines = [
            "#!/bin/sh",
            # Every call's arguments, one per line, for the checks of what
            # the runner passes
            'printf "%s\\n" "$@" > "$(mktemp ' + shlex.quote(self.argsdir) + '/call.XXXXXX)"',
            # and the Boost.Test variables in its environment
            'env | grep "^BOOST_TEST_" > "$(mktemp ' + shlex.quote(self.envdir) + '/call.XXXXXX)"',
            'case "$1" in',
            "--list_content) printf %s " + shlex.quote(listing) + " >&2; exit %d ;;" % listing_status,
        ]
        for selector, run in suites.items():
            lines.append("--run_test=%s)" % shlex.quote(selector))
            lines.append("    printf %s " + shlex.quote(run["stdout"]))
            for case in run.get("cases", []):
                disabler = "--run_test=!%s/%s" % (selector, case)
                lines.append('    run=yes; for a in "$@"; do [ "$a" = %s ] && run=no; done' % shlex.quote(disabler))
                lines.append('    [ "$run" = no ] || printf "Entering test case \\"%s\\"\\n" ' + shlex.quote(case))
            if "xml" in run:
                lines.append('    if [ -n "${BOOST_TEST_OUTPUT_FORMAT+set}" ]; then printf %s '
                             + shlex.quote(run["xml"]) + " >&2")
                lines.append("    else printf %s " + shlex.quote(run["stderr"]) + " >&2; fi")
            elif "colour" in run:
                lines.append('    colour=yes')
                lines.append('    for a in "$@"; do [ "$a" = --color_output=no ] && colour=no; done')
                lines.append('    if [ "$colour" = yes ]; then printf %s ' + shlex.quote(run["colour"]) + " >&2")
                lines.append("    else printf %s " + shlex.quote(run["stderr"]) + " >&2; fi")
            else:
                lines.append("    printf %s " + shlex.quote(run["stderr"]) + " >&2")
            lines.append("    exit %d ;;" % run["status"])
        lines.append('*) echo "unexpected arguments: $*" >&2; exit 99 ;;')
        lines.append("esac")
        with open(self.bin, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(self.bin, 0o755)

    def run_runner(self, *selectors, jobs="2", env=None, exclude=None):
        env = dict(os.environ, TMPDIR=self.tmp, **(env or {}))
        options = ["--exclude-cases", exclude] if exclude is not None else []
        return subprocess.run(["bash", SCRIPT] + options + [self.bin, self.logdir, jobs] + list(selectors),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, env=env)

    def write_list(self, text):
        """A list of test cases to leave out, for --exclude-cases"""
        path = os.path.join(self.tmp, "excluded-cases")
        with open(path, "w") as f:
            f.write(text)
        return path

    def write_cases_bin(self, listing_status=0):
        self.write_bin({
            "a_tests": dict(passing(), cases=["case_one", "case_two", "case_three"]),
            "b_tests": dict(passing(), cases=["b_case", "nested_tests/inner_case"]),
        }, listing=CASES_LISTING, listing_status=listing_status)

    def log_of(self, selector):
        """The log the runner wrote for selector"""
        name = selector.replace("/", "_")
        logs = [n for n in os.listdir(self.logdir) if n.partition("-")[2] == name + ".log"]
        self.assertEqual(len(logs), 1, (selector, os.listdir(self.logdir)))
        with open(os.path.join(self.logdir, logs[0])) as f:
            return f.read()

    def entered_cases(self, selector):
        return re.findall(r'^Entering test case "([^"]*)"$', self.log_of(selector), re.M)

    def disablers(self, call):
        return [a for a in call if a.startswith("--run_test=!")]

    def summary(self):
        with open(os.path.join(self.logdir, "summary.txt")) as f:
            return f.read().splitlines()

    def run_calls(self):
        """The argument lists of the --run_test calls"""
        calls = []
        for name in os.listdir(self.argsdir):
            with open(os.path.join(self.argsdir, name)) as f:
                args = f.read().splitlines()
            if args and args[0].startswith("--run_test="):
                calls.append(args)
        return calls

    def test_exit_0_with_summary_passes(self):
        self.write_bin({"good_tests": passing(stdout=ENTERING.format("good_tests"))})
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary(), ["PASS good_tests"])
        self.assertIn("1 passed, 0 failed", result.stdout)

    def test_exit_0_without_summary_fails(self):
        # What a fixture that ends the process during setup leaves behind
        self.write_bin({"silent_tests": {"stdout": ENTERING.format("silent_tests"), "stderr": "", "status": 0}})
        result = self.run_runner()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary(), ["FAIL silent_tests (no test report)"])
        self.assertIn("0 passed, 1 failed", result.stdout)

    def test_nonzero_exit_fails(self):
        failure = "\n*** 1 failure is detected in the test module \"Bitcoin Test Suite\"\n"
        self.write_bin({
            "reported_tests": {"stdout": "", "stderr": failure, "status": 201},
            "crashed_tests": {"stdout": ENTERING.format("crashed_tests"), "stderr": "", "status": 1},
        })
        result = self.run_runner()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary(), ["FAIL crashed_tests", "FAIL reported_tests"])

    def test_nonzero_exit_with_no_errors_line_fails(self):
        self.write_bin({"odd_tests": {"stdout": "", "stderr": NO_ERRORS, "status": 1}})
        result = self.run_runner()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary(), ["FAIL odd_tests"])

    def test_mixed_suites(self):
        self.write_bin({
            "a_tests": passing(),
            "b_tests": {"stdout": ENTERING.format("b_tests"), "stderr": "", "status": 0},
            "c_tests": {"stdout": "", "stderr": "", "status": 200},
            "d_tests": passing(stdout=NO_ERRORS, stderr=""),
        })
        result = self.run_runner(jobs="3")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary(), [
            "PASS a_tests",
            "FAIL b_tests (no test report)",
            "FAIL c_tests",
            "PASS d_tests",
        ])
        self.assertIn("2 passed, 2 failed", result.stdout)
        for suite in ("a_tests", "b_tests", "c_tests", "d_tests"):
            self.assertTrue(any(name.endswith("-" + suite + ".log") for name in os.listdir(self.logdir)), suite)

    def test_summary_on_stderr_only_is_found(self):
        self.write_bin({"stderr_tests": {"stdout": "", "stderr": NO_ERRORS, "status": 0}})
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary(), ["PASS stderr_tests"])

    def test_summary_text_not_on_its_own_line_does_not_count(self):
        for text in ("a test printed *** No errors detected\n",
                     "*** No errors detected so far\n",
                     "No errors detected\n",
                     "  *** No errors detected\n"):
            with self.subTest(text=text):
                self.write_bin({"chatty_tests": {"stdout": ENTERING.format("chatty_tests") + text,
                                                 "stderr": "", "status": 0}})
                result = self.run_runner()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.summary(), ["FAIL chatty_tests (no test report)"])

    def test_report_format_is_passed(self):
        # An environment variable such as BOOST_TEST_REPORT_LEVEL=no must not
        # be able to suppress the summary the runner looks for.
        self.write_bin({"a_tests": passing()})
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.run_calls()
        self.assertEqual(len(calls), 1)
        for arg in ("--run_test=a_tests", "--report_level=confirm", "--report_format=HRF",
                    "--report_sink=stderr", "--color_output=no"):
            self.assertIn(arg, calls[0])

    def test_colour_output_is_off_for_explicit_selectors(self):
        self.write_bin({"a_tests/case_one": passing(), "!b_tests": passing()},
                       listing="", listing_status=1)
        result = self.run_runner("a_tests/case_one", "!b_tests")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.run_calls()
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertIn("--color_output=no", call)

    def test_colour_output_in_the_environment_does_not_fail_a_suite(self):
        # BOOST_TEST_COLOR_OUTPUT=yes wraps the summary in colour codes; the
        # runner turns colour off, so the summary is found. The fake colours
        # whenever the option is missing, so the test also fails if only the
        # environment is cleaned.
        self.write_bin({"a_tests": dict(passing(), colour=NO_ERRORS_COLOURED)})
        result = self.run_runner(env={"BOOST_TEST_COLOR_OUTPUT": "yes"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary(), ["PASS a_tests"])

    def test_output_format_in_the_environment_does_not_fail_a_suite(self):
        # In Boost 1.64 BOOST_TEST_OUTPUT_FORMAT overrides --report_format;
        # the runner starts the binary without it.
        self.write_bin({"a_tests": dict(passing(), xml=XML_REPORT)})
        result = self.run_runner(env={"BOOST_TEST_OUTPUT_FORMAT": "XML"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary(), ["PASS a_tests"])

    def test_no_boost_test_variable_reaches_the_binary(self):
        self.write_bin({"a_tests": passing()})
        result = self.run_runner(env={"BOOST_TEST_OUTPUT_FORMAT": "XML", "BOOST_TEST_LOG_LEVEL": "all",
                                      "BOOST_TEST_COLOR_OUTPUT": "yes", "BOOST_TEST_FUTURE_OPTION": "x"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = os.listdir(self.envdir)
        self.assertEqual(len(calls), 2)  # --list_content and the suite run
        for name in calls:
            with open(os.path.join(self.envdir, name)) as f:
                self.assertEqual(f.read(), "", name)

    def test_xml_summary_does_not_count(self):
        self.write_bin({"a_tests": {"stdout": ENTERING.format("a_tests"),
                                    "stderr": XML_REPORT, "status": 0}})
        result = self.run_runner()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary(), ["FAIL a_tests (no test report)"])

    def test_coloured_summary_does_not_count(self):
        # A summary in colour codes is not the whole-line summary: a binary
        # that prints it regardless of the option fails.
        self.write_bin({"a_tests": {"stdout": ENTERING.format("a_tests"),
                                    "stderr": NO_ERRORS_COLOURED, "status": 0}})
        result = self.run_runner()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary(), ["FAIL a_tests (no test report)"])

    def test_explicit_selectors_follow_the_same_rule(self):
        self.write_bin({
            "a_tests/case_one": passing(),
            "a_tests/case_two": {"stdout": ENTERING.format("a_tests"), "stderr": "", "status": 0},
            "!b_tests": {"stdout": "", "stderr": "", "status": 1},
        }, listing="", listing_status=1)
        result = self.run_runner("a_tests/case_one", "a_tests/case_two", "!b_tests")
        self.assertNotEqual(result.returncode, 0)
        # sort orders "!" by the locale
        self.assertEqual(sorted(self.summary()), [
            "FAIL !b_tests",
            "FAIL a_tests/case_two (no test report)",
            "PASS a_tests/case_one",
        ])
        self.assertIn("1 passed, 2 failed", result.stdout)

    def test_failed_listing_fails(self):
        self.write_bin({"a_tests": passing()}, listing="a_tests*\n", listing_status=1)
        result = self.run_runner()
        self.assertEqual(result.returncode, 1)
        self.assertIn("--list_content' failed", result.stderr)
        self.assertEqual(self.run_calls(), [])

    def test_empty_listing_fails(self):
        self.write_bin({"a_tests": passing()}, listing="Test setup error\n")
        result = self.run_runner()
        self.assertEqual(result.returncode, 1)
        self.assertIn("No unit test suites found", result.stderr)
        self.assertEqual(self.run_calls(), [])

    def test_bad_job_count_exits_2(self):
        self.write_bin({"a_tests": passing()})
        for jobs in ("0", "x", "-1", "2x"):
            with self.subTest(jobs=jobs):
                result = self.run_runner(jobs=jobs)
                self.assertEqual(result.returncode, 2)
        self.assertEqual(self.run_calls(), [])


    # Test cases left out with --exclude-cases

    def test_listed_case_is_left_out_and_the_other_cases_of_its_suite_run(self):
        self.write_cases_bin()
        result = self.run_runner(exclude=self.write_list("a_tests/case_two\n"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary(), ["PASS a_tests", "PASS b_tests"])
        self.assertEqual(self.entered_cases("a_tests"), ["case_one", "case_three"])
        self.assertEqual(self.entered_cases("b_tests"), ["b_case", "nested_tests/inner_case"])
        calls = self.run_calls()
        self.assertEqual(len(calls), 2)
        for call in calls:
            # The selector comes first, the disabling filter with it.
            self.assertTrue(call[0] in ("--run_test=a_tests", "--run_test=b_tests"), call)
            self.assertEqual(self.disablers(call), ["--run_test=!a_tests/case_two"])
        self.assertIn("a_tests/case_two", result.stdout)

    def test_listed_cases_are_left_out_of_explicit_selectors(self):
        self.write_cases_bin()
        result = self.run_runner("a_tests", "b_tests",
                                 exclude=self.write_list("a_tests/case_one\nb_tests/nested_tests/inner_case\n"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.entered_cases("a_tests"), ["case_two", "case_three"])
        self.assertEqual(self.entered_cases("b_tests"), ["b_case"])
        for call in self.run_calls():
            self.assertEqual(self.disablers(call),
                             ["--run_test=!a_tests/case_one", "--run_test=!b_tests/nested_tests/inner_case"])

    def test_without_a_list_nothing_is_left_out(self):
        self.write_cases_bin()
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.entered_cases("a_tests"), ["case_one", "case_two", "case_three"])
        for call in self.run_calls():
            self.assertEqual([a for a in call if a.startswith("--run_test")], [call[0]])
        # Explicit selectors still need no listing (it fails here).
        self.write_cases_bin(listing_status=1)
        result = self.run_runner("a_tests")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.entered_cases("a_tests"), ["case_one", "case_two", "case_three"])

    def test_listed_case_that_does_not_exist_fails(self):
        self.write_cases_bin()
        for entry in ("a_tests/no_such_case", "no_such_tests/case_one", "b_tests/case_one",
                      "b_tests/inner_case", "a_tests/case_one/more",
                      # a suite, not a test case
                      "a_tests", "b_tests/nested_tests"):
            with self.subTest(entry=entry):
                shutil.rmtree(self.argsdir); os.mkdir(self.argsdir)
                for selectors in ((), ("a_tests",)):
                    result = self.run_runner(*selectors, exclude=self.write_list("a_tests/case_two\n" + entry + "\n"))
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(entry, result.stderr)
                    self.assertEqual(self.run_calls(), [])

    def test_malformed_entry_fails(self):
        self.write_cases_bin()
        for entry in ("a_tests/*", "!a_tests/case_two", "+a_tests/case_two", "a_tests/case_two b_tests/b_case",
                      "/case_two", "a_tests/", "a_tests//case_two", "@label", "a_tests/case_one,case_two",
                      "a_tests/case_one:b_tests/b_case"):
            with self.subTest(entry=entry):
                result = self.run_runner(exclude=self.write_list(entry + "\n"))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(entry, result.stderr)
                self.assertEqual(self.run_calls(), [])

    def test_comments_and_blank_lines_are_ignored(self):
        self.write_cases_bin()
        text = ("# Test cases left out\n"
                "\n"
                "   \n"
                "\t\n"
                "  # an indented comment\n"
                "a_tests/case_two   # a comment after the entry\n"
                "  b_tests/b_case\t\n"
                "#a_tests/case_one\n"
                "a_tests/case_three")  # no newline at the end
        result = self.run_runner(exclude=self.write_list(text))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.entered_cases("a_tests"), ["case_one"])
        self.assertEqual(self.entered_cases("b_tests"), ["nested_tests/inner_case"])
        for call in self.run_calls():
            self.assertEqual(self.disablers(call), ["--run_test=!a_tests/case_two", "--run_test=!b_tests/b_case",
                                                    "--run_test=!a_tests/case_three"])

    def test_list_of_comments_only_leaves_nothing_out(self):
        self.write_cases_bin()
        result = self.run_runner(exclude=self.write_list("# nothing\n\n"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.entered_cases("a_tests"), ["case_one", "case_two", "case_three"])
        for call in self.run_calls():
            self.assertEqual(self.disablers(call), [])

    def test_missing_list_exits_2(self):
        self.write_cases_bin()
        result = self.run_runner(exclude=os.path.join(self.tmp, "no-such-list"))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("no-such-list", result.stderr)
        self.assertEqual(self.run_calls(), [])
        result = subprocess.run(["bash", SCRIPT, "--exclude-cases"], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_list_needs_the_listing(self):
        # The entries are checked against the listing, also with explicit
        # selectors; a failed listing fails the run.
        self.write_cases_bin(listing_status=1)
        result = self.run_runner("a_tests", exclude=self.write_list("a_tests/case_two\n"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("--list_content' failed", result.stderr)
        self.assertEqual(self.run_calls(), [])

if __name__ == "__main__":
    unittest.main()
