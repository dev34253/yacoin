"""Tests of the options of test/functional/test_runner.py for the sanitizer
runs.

With --sanitizer-logs DIR, the runner starts every test script with the
sanitizers' log_path set to DIR/<test directory name>, so every process the
script starts writes its reports to DIR/<test directory name>.<exe>.<pid>
instead of its stderr. A script with such a file fails, whatever its exit
status, and the report is printed with its output; a file that belongs to no
script fails the run. The scripts here are fakes that record their
environment and write report files as a sanitizer runtime would.

With --exclude-file FILE, the runner leaves out the scripts listed in FILE;
a listed name that is not one of its scripts fails the run.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.join(HERE, "..", "..", "..", "test", "functional", "test_runner.py")

spec = importlib.util.spec_from_file_location("test_runner", RUNNER)
test_runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test_runner)

SANITIZER_VARS = ("ASAN_OPTIONS", "LSAN_OPTIONS", "UBSAN_OPTIONS")

# A fake test script: records the sanitizer options it was started with in
# <tmpdir>.env, writes a report file for every name in its REPORTS (as the
# runtime does with log_path: <log_path>.<exe>.<pid>), then exits with its
# EXIT status.
FAKE_SCRIPT = r'''
import json, os, sys
tmpdir = [a for a in sys.argv if a.startswith("--tmpdir=")][0].split("=", 1)[1]
names = ("ASAN_OPTIONS", "LSAN_OPTIONS", "UBSAN_OPTIONS", "TSAN_OPTIONS")
with open(tmpdir + ".env", "w") as f:
    json.dump({n: os.environ.get(n) for n in names}, f)
log_path = [o for o in os.environ.get("ASAN_OPTIONS", "").split(":") if o.startswith("log_path=")]
for i, exe in enumerate(REPORTS):
    with open("%s.%s.%d" % (log_path[-1].split("=", 1)[1], exe, 100 + i), "w") as f:
        f.write("==%d==ERROR: a report from %s\n" % (100 + i, exe))
sys.exit(EXIT)
'''


class FunctionalRunnerSanitizerTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test_functional_runner.")
        self.addCleanup(shutil.rmtree, self.dir)
        self.tests_dir = os.path.join(self.dir, "src", "test", "functional") + "/"
        os.makedirs(self.tests_dir)
        self.tmpdir = os.path.join(self.dir, "tmp")
        os.makedirs(self.tmpdir)
        self.logs = os.path.join(self.dir, "sanitizer-logs")
        # The options a caller set before the runner.
        env = {"ASAN_OPTIONS": "detect_leaks=1", "LSAN_OPTIONS": "suppressions=/x/lsan",
               "TSAN_OPTIONS": "halt_on_error=0"}
        saved = {n: os.environ.get(n) for n in SANITIZER_VARS + ("TSAN_OPTIONS",)}
        for n in saved:
            os.environ.pop(n, None)
        os.environ.update(env)
        self.addCleanup(self.restore_environ, saved)

    @staticmethod
    def restore_environ(saved):
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    def fake(self, name, reports=(), exit_status=0):
        with open(self.tests_dir + name, "w") as f:
            f.write(FAKE_SCRIPT.replace("REPORTS", repr(list(reports))).replace("EXIT", str(exit_status)))

    def handle(self, test_list, sanitizer_logs):
        """Run test_list through the TestHandler; return {name: (status, stdout, stderr, env)}."""
        if sanitizer_logs:
            os.makedirs(sanitizer_logs, exist_ok=True)
        handler = test_runner.TestHandler(
            num_tests_parallel=2, tests_dir=self.tests_dir, tmpdir=self.tmpdir, test_list=list(test_list),
            flags=[], timeout_duration=float("inf"), use_term_control=False, sanitizer_logs=sanitizer_logs)
        results = {}
        with contextlib.redirect_stdout(io.StringIO()):
            for _ in test_list:
                result, testdir, stdout, stderr = handler.get_next()
                with open(testdir + ".env") as f:
                    env = json.load(f)
                results[result.name] = (result.status, stdout, stderr, env, testdir)
        return results

    def run_all(self, test_list, sanitizer_logs):
        """Run test_list through run_tests (one at a time, so without the cache
        script); return (exit status, output)."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as e:
            test_runner.run_tests(test_list=list(test_list), src_dir=os.path.join(self.dir, "src"),
                                  build_dir=self.dir, tmpdir=self.tmpdir, jobs=1, runs_ci=False,
                                  use_term_control=False, sanitizer_logs=sanitizer_logs)
        # Without the ANSI colour codes the runner prints by default.
        return e.exception.code, re.sub(r"\x1b\[[0-9;]*m", "", out.getvalue())

    def test_scripts_get_a_log_path_of_their_own_after_the_callers_options(self):
        self.fake("a_one.py")
        self.fake("a_two.py")
        results = self.handle(["a_one.py", "a_two.py"], self.logs)
        for name in ("a_one.py", "a_two.py"):
            status, _, _, env, testdir = results[name]
            self.assertEqual(status, "Passed")
            own = "log_path=%s:log_exe_name=1" % os.path.join(self.logs, os.path.basename(testdir))
            self.assertEqual(env["ASAN_OPTIONS"], "detect_leaks=1:" + own)
            self.assertEqual(env["LSAN_OPTIONS"], "suppressions=/x/lsan:" + own)
            self.assertEqual(env["UBSAN_OPTIONS"], own)
            # ThreadSanitizer's options are not touched.
            self.assertEqual(env["TSAN_OPTIONS"], "halt_on_error=0")
        self.assertNotEqual(results["a_one.py"][3]["ASAN_OPTIONS"], results["a_two.py"][3]["ASAN_OPTIONS"])

    def test_without_the_option_the_environment_is_unchanged(self):
        self.fake("a_one.py")
        status, _, _, env, _ = self.handle(["a_one.py"], None)["a_one.py"]
        self.assertEqual(status, "Passed")
        self.assertEqual(env, {"ASAN_OPTIONS": "detect_leaks=1", "LSAN_OPTIONS": "suppressions=/x/lsan",
                               "UBSAN_OPTIONS": None, "TSAN_OPTIONS": "halt_on_error=0"})

    def test_a_report_fails_a_script_that_passed_and_is_printed_with_it(self):
        self.fake("a_clean.py")
        self.fake("a_report.py", reports=["yacoind", "yacoin-cli"])
        results = self.handle(["a_clean.py", "a_report.py"], self.logs)
        self.assertEqual(results["a_clean.py"][0], "Passed")
        status, _, stderr, _, testdir = results["a_report.py"]
        self.assertEqual(status, "Failed")
        base = os.path.join(self.logs, os.path.basename(testdir))
        self.assertIn("Sanitizer report %s.yacoind.100:\n==100==ERROR: a report from yacoind\n" % base, stderr)
        self.assertIn("Sanitizer report %s.yacoin-cli.101:\n==101==ERROR: a report from yacoin-cli\n" % base, stderr)

    def test_a_report_fails_a_skipped_script(self):
        self.fake("a_skipped.py", exit_status=77)
        self.fake("a_skipped_report.py", reports=["yacoind"], exit_status=77)
        results = self.handle(["a_skipped.py", "a_skipped_report.py"], self.logs)
        self.assertEqual(results["a_skipped.py"][0], "Skipped")
        self.assertEqual(results["a_skipped_report.py"][0], "Failed")

    def test_a_failed_script_shows_its_report_too(self):
        self.fake("a_failed.py", reports=["yacoind"], exit_status=1)
        status, _, stderr, _, _ = self.handle(["a_failed.py"], self.logs)["a_failed.py"]
        self.assertEqual(status, "Failed")
        self.assertIn("==100==ERROR: a report from yacoind", stderr)

    def test_without_the_option_a_report_file_does_not_count(self):
        # The fake writes no file without a log_path; the script's own
        # status decides, as before.
        self.fake("a_one.py", reports=[])
        self.assertEqual(self.handle(["a_one.py"], None)["a_one.py"][0], "Passed")

    def test_the_run_fails_on_a_script_with_a_report(self):
        self.fake("a_clean.py")
        self.fake("a_report.py", reports=["yacoind"])
        status, out = self.run_all(["a_clean.py", "a_report.py"], self.logs)
        self.assertEqual(status, True)
        self.assertIn("a_report.py failed", out)
        self.assertIn("==100==ERROR: a report from yacoind", out)

    def test_the_run_passes_without_reports(self):
        self.fake("a_clean.py")
        status, _ = self.run_all(["a_clean.py"], self.logs)
        self.assertEqual(status, False)
        self.assertEqual(os.listdir(self.logs), [])

    def test_a_report_of_no_script_fails_the_run(self):
        # A process the runner itself started, or one that outlived its
        # script and reported after it was checked.
        self.fake("a_clean.py")

        def stray_report(*args, **kwargs):
            with open(os.path.join(self.logs, "create_cache.yacoind.7"), "w") as f:
                f.write("==7==ERROR: a stray report\n")
            return original(*args, **kwargs)
        original = test_runner.print_results
        test_runner.print_results = stray_report
        self.addCleanup(setattr, test_runner, "print_results", original)
        status, out = self.run_all(["a_clean.py"], self.logs)
        self.assertEqual(status, True)
        self.assertIn("Sanitizer report %s:\n==7==ERROR: a stray report\n"
                      % os.path.join(self.logs, "create_cache.yacoind.7"), out)

    def test_a_directory_with_files_is_refused(self):
        # Test directory names repeat between runs, so an old report would be
        # taken for the new run's.
        self.fake("a_clean.py")
        os.makedirs(self.logs)
        with open(os.path.join(self.logs, "a_clean_0.yacoind.5"), "w") as f:
            f.write("old\n")
        status, out = self.run_all(["a_clean.py"], self.logs)
        self.assertEqual(status, 1)
        self.assertIn("is not empty", out)
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, "a_clean_0.env")))

    def test_the_directory_is_created(self):
        self.fake("a_clean.py")
        status, _ = self.run_all(["a_clean.py"], self.logs)
        self.assertEqual(status, False)
        self.assertTrue(os.path.isdir(self.logs))


class FunctionalRunnerExcludeFileTests(unittest.TestCase):
    """--exclude-file FILE leaves out the scripts listed in FILE; a listed
    name that is not a script of the runner fails the run.

    main() runs on a tree of its own: a config.ini next to a copy of the
    runner's path, test lists of fake names, and run_tests replaced by a
    recorder of the scripts it would run."""

    SCRIPTS = ["wallet_a.py", "wallet_b.py", "wallet_b.py --opt", "mining_c.py"]

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test_functional_runner.")
        self.addCleanup(shutil.rmtree, self.dir)
        src = os.path.join(self.dir, "src")
        os.makedirs(os.path.join(src, "test", "functional"))
        with open(os.path.join(src, "test", "config.ini"), "w") as f:
            f.write("[environment]\nSRCDIR=%s\nBUILDDIR=%s\n[components]\nENABLE_BITCOIND=true\n" % (src, self.dir))
        self.list = os.path.join(self.dir, "excluded-scripts")
        self.ran = []
        patches = {"__file__": os.path.join(src, "test", "functional", "test_runner.py"),
                   "BASE_SCRIPTS": self.SCRIPTS[:2], "EXTENDED_SCRIPTS": self.SCRIPTS[2:],
                   "ALL_SCRIPTS": self.SCRIPTS[2:] + self.SCRIPTS[:2],
                   "run_tests": lambda **kwargs: self.ran.append(kwargs["test_list"])}
        for name, value in patches.items():
            self.addCleanup(setattr, test_runner, name, getattr(test_runner, name))
            setattr(test_runner, name, value)

    def write_list(self, text):
        with open(self.list, "w") as f:
            f.write(text)

    def main(self, *args):
        """Run main() with args; return (exit status or None, output)."""
        # The runner's temporary directory is named after the second it starts.
        argv = ["test_runner.py", "--tmpdirprefix=%s" % tempfile.mkdtemp(dir=self.dir)] + list(args)
        out = io.StringIO()
        status = None
        with unittest.mock.patch("sys.argv", argv), contextlib.redirect_stdout(out):
            try:
                test_runner.main()
            except SystemExit as e:
                status = e.code
        return status, re.sub(r"\x1b\[[0-9;]*m", "", out.getvalue())

    def test_the_listed_scripts_are_left_out(self):
        self.write_list("wallet_b.py\n")
        status, _ = self.main("--extended", "--exclude-file=%s" % self.list)
        self.assertIsNone(status)
        # Also the run of the script with an argument.
        self.assertEqual(self.ran, [["mining_c.py", "wallet_a.py"]])

    def test_without_the_option_nothing_is_left_out(self):
        status, _ = self.main("--extended")
        self.assertIsNone(status)
        self.assertEqual(self.ran, [self.SCRIPTS[2:] + self.SCRIPTS[:2]])

    def test_comments_and_blank_lines_are_ignored(self):
        self.write_list("# The scripts left out.\n\n  # indented\nwallet_a.py\n\n  mining_c.py   # a reason\n\t\n")
        status, _ = self.main("--extended", "--exclude-file", self.list)
        self.assertIsNone(status)
        self.assertEqual(self.ran, [["wallet_b.py --opt", "wallet_b.py"]])

    def test_an_empty_list_leaves_out_nothing(self):
        for text in ("", "# Only a comment.\n\n"):
            self.ran.clear()
            self.write_list(text)
            status, _ = self.main("--extended", "--exclude-file=%s" % self.list)
            self.assertIsNone(status)
            self.assertEqual(self.ran, [self.SCRIPTS[2:] + self.SCRIPTS[:2]])

    def test_a_name_the_runner_does_not_know_fails_the_run(self):
        self.write_list("wallet_a.py\nwallet_gone.py\n")
        status, out = self.main("--extended", "--exclude-file=%s" % self.list)
        self.assertEqual(status, 1)
        self.assertIn("ERROR! %s:2: 'wallet_gone.py' is not a test script of test_runner.py" % self.list, out)
        self.assertEqual(self.ran, [])

    def test_a_name_needs_its_py_suffix(self):
        # As in the test lists of the runner: the file name of the script.
        self.write_list("wallet_a\n")
        status, out = self.main("--extended", "--exclude-file=%s" % self.list)
        self.assertEqual(status, 1)
        self.assertIn("'wallet_a' is not a test script", out)
        self.assertEqual(self.ran, [])

    def test_a_name_with_arguments_fails_the_run(self):
        # One script name per line; the runs of a script are left out together.
        self.write_list("wallet_b.py --opt\n")
        status, out = self.main("--extended", "--exclude-file=%s" % self.list)
        self.assertEqual(status, 1)
        self.assertIn("'wallet_b.py --opt' is not a test script", out)

    def test_a_listed_script_that_was_not_selected_is_no_error(self):
        self.write_list("wallet_b.py\n")
        status, _ = self.main("--exclude-file=%s" % self.list, "wallet_a.py")
        self.assertIsNone(status)
        self.assertEqual(self.ran, [["wallet_a.py"]])

    def test_a_file_that_cannot_be_read_fails_the_run(self):
        missing = os.path.join(self.dir, "no-such-list")
        status, out = self.main("--extended", "--exclude-file=%s" % missing)
        self.assertEqual(status, 1)
        self.assertIn("ERROR! Cannot read the list of scripts to leave out", out)
        self.assertIn(missing, out)
        self.assertEqual(self.ran, [])


if __name__ == "__main__":
    unittest.main()
