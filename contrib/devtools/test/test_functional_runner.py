"""Tests of the options of test/functional/test_runner.py for the sanitizer
runs.

With --sanitizer-logs DIR, the runner starts every test script with the
sanitizers' log_path set to DIR/<test directory name>, so every process the
script starts writes its reports to DIR/<test directory name>.<exe>.<pid>
instead of its stderr. A script with such a file fails, whatever its exit
status, and the report is printed with its output; a file that belongs to no
script fails the run. The scripts here are fakes that record their
environment and write report files as a sanitizer runtime would.

With --exclude-file FILE, the runner leaves out the scripts listed in FILE,
and with the option more than once, those of every FILE; a listed name that
is not one of its scripts fails the run. With --include-file FILE, it runs
only the scripts listed in FILE.

With --chain CHAIN, the runner selects the scripts that set
self.chain = 'CHAIN' (regtest: also those without such a line), and builds
the block cache of CHAIN only.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import sys
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
        # status decides.
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

    def write_second_list(self, text):
        second = os.path.join(self.dir, "more-excluded-scripts")
        with open(second, "w") as f:
            f.write(text)
        return second

    def test_the_scripts_of_every_list_are_left_out(self):
        self.write_list("wallet_b.py\n")
        second = self.write_second_list("# Another list.\nmining_c.py\n")
        status, _ = self.main("--extended", "--exclude-file=%s" % self.list, "--exclude-file", second)
        self.assertIsNone(status)
        self.assertEqual(self.ran, [["wallet_a.py"]])

    def test_a_script_in_two_lists_is_no_error(self):
        self.write_list("wallet_b.py\n")
        second = self.write_second_list("wallet_b.py\n")
        status, _ = self.main("--extended", "--exclude-file=%s" % self.list, "--exclude-file=%s" % second)
        self.assertIsNone(status)
        self.assertEqual(self.ran, [["mining_c.py", "wallet_a.py"]])

    def test_a_name_the_runner_does_not_know_in_any_list_fails_the_run(self):
        good = self.write_second_list("wallet_a.py\n")
        self.write_list("wallet_gone.py\n")
        for lists in ((good, self.list), (self.list, good)):
            self.ran.clear()
            status, out = self.main("--extended", *["--exclude-file=%s" % path for path in lists])
            self.assertEqual(status, 1)
            self.assertIn("ERROR! %s:1: 'wallet_gone.py' is not a test script of test_runner.py" % self.list, out)
            self.assertEqual(self.ran, [])


class FunctionalRunnerIncludeFileTests(unittest.TestCase):
    """--include-file FILE runs only the scripts listed in FILE (the format
    of --exclude-file), every run of each, in the order of the runner's
    list; a listed name that is not a script of the runner, a list without
    a script and script names on the command line fail the run.

    main() runs on a tree of its own, as in FunctionalRunnerExcludeFileTests."""

    SCRIPTS = FunctionalRunnerExcludeFileTests.SCRIPTS
    setUp = FunctionalRunnerExcludeFileTests.setUp
    write_list = FunctionalRunnerExcludeFileTests.write_list
    main = FunctionalRunnerExcludeFileTests.main

    def test_only_the_listed_scripts_run(self):
        self.write_list("# The scripts to run.\n\nwallet_b.py  # a reason\n  wallet_a.py\n")
        for args in ([], ["--extended"]):
            self.ran.clear()
            status, out = self.main("--include-file=%s" % self.list, *args)
            self.assertIsNone(status, out)
            # Every run of a listed script, in the order of the runner's list.
            self.assertEqual(self.ran, [["wallet_b.py --opt", "wallet_a.py", "wallet_b.py"]])

    def test_the_other_selections_apply_after_it(self):
        self.write_list("wallet_b.py\nmining_c.py\n")
        excluded = os.path.join(self.dir, "excluded-scripts-2")
        with open(excluded, "w") as f:
            f.write("mining_c.py\n")
        status, _ = self.main("--include-file", self.list, "--exclude-file=%s" % excluded)
        self.assertIsNone(status)
        self.assertEqual(self.ran, [["wallet_b.py --opt", "wallet_b.py"]])

    def test_a_name_the_runner_does_not_know_fails_the_run(self):
        self.write_list("wallet_a.py\nwallet_gone.py\n")
        status, out = self.main("--include-file=%s" % self.list)
        self.assertEqual(status, 1)
        self.assertIn("ERROR! %s:2: 'wallet_gone.py' is not a test script of test_runner.py" % self.list, out)
        self.assertEqual(self.ran, [])

    def test_a_list_without_a_script_fails_the_run(self):
        for text in ("", "# Only a comment.\n\n"):
            self.ran.clear()
            self.write_list(text)
            status, out = self.main("--include-file=%s" % self.list)
            self.assertEqual(status, 1)
            self.assertIn("ERROR! %s lists no script to run" % self.list, out)
            self.assertEqual(self.ran, [])

    def test_script_names_on_the_command_line_fail_the_run(self):
        self.write_list("wallet_a.py\n")
        status, out = self.main("--include-file=%s" % self.list, "wallet_b.py")
        self.assertEqual(status, 1)
        self.assertIn("ERROR! --include-file is not taken with script names", out)
        self.assertEqual(self.ran, [])

    def test_a_file_that_cannot_be_read_fails_the_run(self):
        missing = os.path.join(self.dir, "no-such-list")
        status, out = self.main("--include-file=%s" % missing)
        self.assertEqual(status, 1)
        self.assertIn("ERROR! Cannot read the list of scripts to run", out)
        self.assertIn(missing, out)
        self.assertEqual(self.ran, [])


class FunctionalRunnerShardTests(unittest.TestCase):
    """--shard K/N runs the selected scripts whose position in the runner's
    list (ALL_SCRIPTS) modulo N is K-1, after every other selection.

    main() runs on a tree of its own, as in FunctionalRunnerExcludeFileTests."""

    EXTENDED = ["feature_x.py", "feature_y.py"]
    BASE = ["wallet_a.py", "wallet_b.py", "wallet_b.py --opt", "mining_c.py", "mining_d.py", "p2p_e.py",
            "p2p_f.py"]

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test_functional_runner.")
        self.addCleanup(shutil.rmtree, self.dir)
        src = os.path.join(self.dir, "src")
        os.makedirs(os.path.join(src, "test", "functional"))
        with open(os.path.join(src, "test", "config.ini"), "w") as f:
            f.write("[environment]\nSRCDIR=%s\nBUILDDIR=%s\n[components]\nENABLE_BITCOIND=true\n" % (src, self.dir))
        self.ran = []
        self.patch_lists(self.EXTENDED, self.BASE)
        for name, value in {"__file__": os.path.join(src, "test", "functional", "test_runner.py"),
                            "run_tests": lambda **kwargs: self.ran.append(kwargs["test_list"])}.items():
            self.addCleanup(setattr, test_runner, name, getattr(test_runner, name))
            setattr(test_runner, name, value)

    def patch_lists(self, extended, base):
        for name, value in {"EXTENDED_SCRIPTS": extended, "BASE_SCRIPTS": base,
                            "ALL_SCRIPTS": extended + base}.items():
            self.addCleanup(setattr, test_runner, name, getattr(test_runner, name))
            setattr(test_runner, name, value)

    def main(self, *args):
        """Run main() with args; return (exit status or None, output, the
        list of scripts run_tests got or None)."""
        argv = ["test_runner.py", "--tmpdirprefix=%s" % tempfile.mkdtemp(dir=self.dir)] + list(args)
        out = io.StringIO()
        status = None
        self.ran.clear()
        with unittest.mock.patch("sys.argv", argv), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            try:
                test_runner.main()
            except SystemExit as e:
                status = e.code
        ran = self.ran[0] if self.ran else None
        return status, re.sub(r"\x1b\[[0-9;]*m", "", out.getvalue()), ran

    def shards(self, n, *args):
        """The scripts of each of the n shards of a run with args."""
        result = []
        for k in range(1, n + 1):
            status, out, ran = self.main("--shard=%d/%d" % (k, n), *args)
            self.assertIn(status, (None, 0), out)
            result.append(ran or [])
        return result

    def assert_partition(self, shards, whole):
        joined = [script for shard in shards for script in shard]
        self.assertEqual(sorted(joined), sorted(whole))
        self.assertEqual(len(joined), len(set(joined)))

    def test_the_shards_partition_the_run(self):
        _, _, whole = self.main("--extended")
        self.assertEqual(whole, self.EXTENDED + self.BASE)
        for n in (1, 2, 3, len(whole), len(whole) + 3):
            self.assert_partition(self.shards(n, "--extended"), whole)

    def test_one_of_one_is_the_whole_run(self):
        for args in ([], ["--extended"], ["wallet_a.py", "p2p_f.py"]):
            self.assertEqual(self.main("--shard=1/1", *args)[2], self.main(*args)[2])

    def test_a_scripts_shard_is_its_position_in_the_runners_list_modulo_n(self):
        everything = self.EXTENDED + self.BASE
        for n in (2, 3):
            for k, shard in enumerate(self.shards(n, "--extended"), 1):
                self.assertEqual(shard, [s for i, s in enumerate(everything) if i % n == k - 1])

    def test_a_script_keeps_its_shard_when_named_alone_or_without_extended(self):
        full = self.shards(3, "--extended")
        for k, shard in enumerate(full, 1):
            for script in shard:
                self.assertEqual(self.main("--shard=%d/3" % k, script)[2], [script])
        # The base run: the same shard as in the extended run.
        for k, shard in enumerate(self.shards(3), 1):
            self.assertEqual(shard, [s for s in full[k - 1] if s in self.BASE])

    def test_the_shard_applies_after_the_other_selections(self):
        excluded = os.path.join(self.dir, "excluded-scripts")
        with open(excluded, "w") as f:
            f.write("mining_c.py\n")
        for args in (["--extended", "--exclude=wallet_a,p2p_e"],
                     ["--extended", "--exclude-file=%s" % excluded],
                     ["--extended", "--filter=wallet|p2p"],
                     ["--exclude=wallet_b", "--exclude-file=%s" % excluded, "--filter=_[a-e]"]):
            _, _, whole = self.main(*args)
            self.assertTrue(whole)
            for n in (2, 3):
                shards = self.shards(n, *args)
                self.assert_partition(shards, whole)
                for k, shard in enumerate(shards, 1):
                    self.assertTrue(all((self.EXTENDED + self.BASE).index(s) % n == k - 1 for s in shard))

    def test_a_new_script_lands_in_exactly_one_shard(self):
        self.patch_lists(self.EXTENDED, self.BASE[:3] + ["rpc_new.py"] + self.BASE[3:])
        shards = self.shards(2, "--extended")
        self.assertEqual(sum(shard.count("rpc_new.py") for shard in shards), 1)
        self.assert_partition(shards, self.EXTENDED + self.BASE + ["rpc_new.py"])

    def test_an_invalid_value_fails_before_any_script_runs(self):
        for value in ("0/2", "3/2", "1/0", "2", "a/b", "-1/2", "1/2/3", "", " 1/2", "1.0/2", "01/2", "1/02"):
            status, out, ran = self.main("--shard=%s" % value, "--extended")
            self.assertEqual(status, 1, value)
            self.assertIn("ERROR! --shard", out)
            self.assertIsNone(ran, value)

    def test_an_empty_shard_is_no_error(self):
        status, out, ran = self.main("--shard=2/2", "wallet_a.py")
        self.assertEqual(status, 0)
        self.assertIn("Shard 2/2 holds none of the 1 selected script(s); nothing to run.", out)
        self.assertIsNone(ran)
        # wallet_a.py is at position 2 of the runner's list.
        self.assertEqual(self.main("--shard=1/2", "wallet_a.py")[2], ["wallet_a.py"])

    def test_without_the_option_an_empty_selection_runs_nothing(self):
        status, out, ran = self.main("--filter=no_such_script")
        self.assertEqual(status, 0)
        self.assertIn("No valid test scripts specified", out)
        self.assertIsNone(ran)

    def test_a_named_script_outside_the_runners_list_fails_with_the_option(self):
        status, out, ran = self.main("--shard=1/2", "wallet_a.py", "wallet_gone.py")
        self.assertEqual(status, 1)
        self.assertIn("ERROR! Test 'wallet_gone.py' is not in the runner's list", out)
        self.assertIsNone(ran)
        # Without the option only a warning, and the other scripts run.
        status, out, ran = self.main("wallet_a.py", "wallet_gone.py")
        self.assertIsNone(status)
        self.assertIn("WARNING! Test 'wallet_gone.py' not found in full test list.", out)
        self.assertEqual(ran, ["wallet_a.py"])


class FunctionalRunnerChainTests(unittest.TestCase):
    """--chain CHAIN selects the scripts whose self.chain line names CHAIN
    (regtest: also the scripts without one), before --shard, and run_tests
    builds the block cache of CHAIN only.

    main() runs on a tree of its own, as in FunctionalRunnerExcludeFileTests,
    with script files whose text the runner reads."""

    SOURCES = {
        "feature_m.py": "class T(BitcoinTestFramework):\n    def set_test_params(self):\n        self.chain = 'main'\n",
        "wallet_r.py": "class T(BitcoinTestFramework):\n    def set_test_params(self):\n        self.num_nodes = 1\n",
        "mining_m.py": 'class T:\n    def set_test_params(self):\n        self.chain = "main"\n',
        "mempool_v.py": "class T:\n    def run_test(self):\n        chain = []\n        self.chain = chain\n",
        "p2p_s.py": "class T:\n    def run_test(self):\n        # self.chain = 'main' would select it\n        pass\n",
        "rpc_x.py": "class T(BitcoinTestFramework):\n    def set_test_params(self):\n        self.chain = 'regtest'\n",
    }
    EXTENDED = ["feature_m.py"]
    BASE = ["wallet_r.py", "mining_m.py", "mining_m.py --opt", "mempool_v.py", "p2p_s.py", "rpc_x.py"]

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test_functional_runner.")
        self.addCleanup(shutil.rmtree, self.dir)
        src = os.path.join(self.dir, "src")
        self.tests_dir = os.path.join(src, "test", "functional")
        os.makedirs(self.tests_dir)
        for name, text in self.SOURCES.items():
            with open(os.path.join(self.tests_dir, name), "w") as f:
                f.write(text)
        with open(os.path.join(src, "test", "config.ini"), "w") as f:
            f.write("[environment]\nSRCDIR=%s\nBUILDDIR=%s\n[components]\nENABLE_BITCOIND=true\n" % (src, self.dir))
        self.ran = []
        patches = {"__file__": os.path.join(self.tests_dir, "test_runner.py"),
                   "EXTENDED_SCRIPTS": self.EXTENDED, "BASE_SCRIPTS": self.BASE,
                   "ALL_SCRIPTS": self.EXTENDED + self.BASE,
                   "run_tests": lambda **kwargs: self.ran.append(kwargs)}
        for name, value in patches.items():
            self.addCleanup(setattr, test_runner, name, getattr(test_runner, name))
            setattr(test_runner, name, value)

    def main(self, *args):
        """Run main() with args; return (exit status or None, output, the
        arguments run_tests got or None)."""
        argv = ["test_runner.py", "--tmpdirprefix=%s" % tempfile.mkdtemp(dir=self.dir)] + list(args)
        out = io.StringIO()
        status = None
        self.ran.clear()
        with unittest.mock.patch("sys.argv", argv), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            try:
                test_runner.main()
            except SystemExit as e:
                status = e.code
        return status, re.sub(r"\x1b\[[0-9;]*m", "", out.getvalue()), self.ran[0] if self.ran else None

    def test_the_chain_comes_from_the_scripts_line(self):
        chains = {name: test_runner.script_chain(self.tests_dir, name) for name in self.SOURCES}
        self.assertEqual(chains, {"feature_m.py": "main", "wallet_r.py": "regtest", "mining_m.py": "main",
                                  "mempool_v.py": "regtest", "p2p_s.py": "regtest", "rpc_x.py": "regtest"})

    def test_main_selects_the_scripts_that_set_it(self):
        status, out, ran = self.main("--extended", "--chain=main")
        self.assertIsNone(status, out)
        # Also the run of the script with an argument.
        self.assertEqual(ran["test_list"], ["feature_m.py", "mining_m.py", "mining_m.py --opt"])
        self.assertEqual(ran["chain"], "main")

    def test_regtest_selects_the_other_scripts(self):
        status, out, ran = self.main("--chain", "regtest")
        self.assertIsNone(status, out)
        # Those without a line and the one that names regtest.
        self.assertEqual(ran["test_list"], ["wallet_r.py", "mempool_v.py", "p2p_s.py", "rpc_x.py"])
        self.assertEqual(ran["chain"], "regtest")

    def test_without_the_option_every_script_is_selected(self):
        status, out, ran = self.main("--extended")
        self.assertIsNone(status, out)
        self.assertEqual(ran["test_list"], self.EXTENDED + self.BASE)
        self.assertIsNone(ran["chain"])

    def test_the_chain_applies_with_the_other_selections_and_before_the_shard(self):
        excluded = os.path.join(self.dir, "excluded-scripts")
        with open(excluded, "w") as f:
            f.write("feature_m.py\n")
        status, out, ran = self.main("--extended", "--chain=main", "--exclude-file=%s" % excluded)
        self.assertIsNone(status, out)
        self.assertEqual(ran["test_list"], ["mining_m.py", "mining_m.py --opt"])
        # Positions in the runner's list: feature_m.py 0, mining_m.py 2, mining_m.py --opt 3.
        self.assertEqual(self.main("--extended", "--chain=main", "--shard=1/2")[2]["test_list"],
                         ["feature_m.py", "mining_m.py"])
        self.assertEqual(self.main("--extended", "--chain=main", "--shard=2/2")[2]["test_list"],
                         ["mining_m.py --opt"])
        self.assertEqual(self.main("--chain=main", "wallet_r.py", "mining_m.py")[2]["test_list"], ["mining_m.py"])

    def test_an_unknown_chain_fails_before_any_script_runs(self):
        status, out, ran = self.main("--extended", "--chain=nosuchchain")
        self.assertEqual(status, 2)
        self.assertIn("--chain", out)
        self.assertIsNone(ran)

    def test_a_selection_without_a_script_on_the_chain_fails_the_run(self):
        for args in (["--chain=main", "wallet_r.py", "p2p_s.py"], ["--chain=regtest", "feature_m.py"],
                     ["--chain=main", "--filter=wallet"]):
            status, out, ran = self.main(*args)
            self.assertEqual(status, 1, args)
            self.assertIn("ERROR! No selected script runs on", out)
            self.assertIsNone(ran)

    def test_a_script_on_an_unknown_chain_fails_the_run(self):
        with open(os.path.join(self.tests_dir, "p2p_s.py"), "w") as f:
            f.write("class T:\n    def set_test_params(self):\n        self.chain = 'testnet3'\n")
        for chain in ("regtest", "main"):
            status, out, ran = self.main("--chain=%s" % chain)
            self.assertEqual(status, 1)
            self.assertIn("ERROR! The test script p2p_s.py runs on chain 'testnet3', which is not one of main, regtest.",
                          out)
            self.assertIsNone(ran)
        # Without the option the runner does not read the scripts.
        self.assertIsNone(self.main()[0])

    def test_the_runners_chains_are_the_frameworks(self):
        functional = os.path.join(HERE, "..", "..", "..", "test", "functional")
        with unittest.mock.patch("sys.path", [functional] + sys.path):
            from test_framework.test_framework import CHAINS
        self.assertEqual(tuple(test_runner.RUNNER_CHAINS), tuple(CHAINS))

    def test_a_script_that_cannot_be_read_fails_the_run(self):
        os.remove(os.path.join(self.tests_dir, "p2p_s.py"))
        status, out, ran = self.main("--chain=regtest")
        self.assertEqual(status, 1)
        self.assertIn("ERROR! Cannot read the test script p2p_s.py", out)
        self.assertIsNone(ran)
        # Without the option the runner does not read the scripts.
        self.assertIsNone(self.main()[0])


class FunctionalRunnerCacheChainTests(unittest.TestCase):
    """run_tests builds the block cache with create_cache.py before running
    several scripts in parallel; with a chain, the cache of that chain only.
    create_cache.py and the scripts here are fakes that record their
    arguments."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test_functional_runner.")
        self.addCleanup(shutil.rmtree, self.dir)
        self.tests_dir = os.path.join(self.dir, "src", "test", "functional")
        os.makedirs(self.tests_dir)
        self.tmpdir = os.path.join(self.dir, "tmp")
        os.makedirs(self.tmpdir)
        self.cache_args = os.path.join(self.dir, "cache-args")
        with open(os.path.join(self.tests_dir, "create_cache.py"), "w") as f:
            f.write("import json, sys\nwith open(%r, 'w') as f:\n    json.dump(sys.argv[1:], f)\n" % self.cache_args)
        for name in ("a_script.py", "b_script.py"):
            with open(os.path.join(self.tests_dir, name), "w") as f:
                f.write("import sys\nsys.exit(0)\n")

    def run_tests(self, chain):
        """Return the arguments create_cache.py got, or None if it did not run."""
        if os.path.exists(self.cache_args):
            os.remove(self.cache_args)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as e:
            test_runner.run_tests(test_list=["a_script.py", "b_script.py"], src_dir=os.path.join(self.dir, "src"),
                                  build_dir=self.dir, tmpdir=self.tmpdir, jobs=2, runs_ci=False,
                                  use_term_control=False, chain=chain)
        self.assertEqual(e.exception.code, 0)
        if not os.path.exists(self.cache_args):
            return None
        with open(self.cache_args) as f:
            return json.load(f)

    def test_the_cache_of_the_chain_only(self):
        args = self.run_tests("regtest")
        self.assertIn("--cachechain=regtest", args)
        self.assertEqual(sum(a.startswith("--cachechain") for a in args), 1)

    def test_without_a_chain_the_cache_of_every_chain(self):
        args = self.run_tests(None)
        self.assertIsNotNone(args)
        self.assertFalse(any(a.startswith("--cachechain") for a in args))


class TreeExcludedScriptsTests(unittest.TestCase):
    def check_list(self, *path):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            try:
                names = test_runner.read_exclude_file(os.path.join(HERE, "..", "..", "..", *path))
            except SystemExit:
                self.fail(out.getvalue())
        known = {test.split()[0] for test in test_runner.ALL_SCRIPTS}
        self.assertTrue(set(names) <= known)
        return names

    def test_the_trees_list_names_scripts_of_the_runner(self):
        # The list the functional-tests-asan mode of the CI images passes;
        # checked here as well, so a stale entry fails before a build.
        self.check_list("test", "sanitizer_suppressions", "asan-excluded-scripts")

    def test_the_trees_regtest_list_names_scripts_of_either_chain(self):
        # The list the functional modes on the mainnet build leave out
        # (with --chain=regtest) and build-low-difficulty runs
        # (--include-file, without --chain): each entry is a script on main
        # or regtest, and the list names at least one.
        tests_dir = os.path.join(HERE, "..", "..", "..", "test", "functional")
        names = self.check_list("test", "functional", "regtest-excluded-scripts")
        self.assertTrue(names)
        for name in names:
            self.assertIn(test_runner.script_chain(tests_dir, name), ("main", "regtest"), name)

    def test_every_script_outside_the_regtest_list_runs_on_regtest(self):
        # The runs on the mainnet build select --chain=regtest; a script on
        # main that is not listed would run in no job.
        tests_dir = os.path.join(HERE, "..", "..", "..", "test", "functional")
        listed = set(self.check_list("test", "functional", "regtest-excluded-scripts"))
        on_main = sorted({test.split()[0] for test in test_runner.ALL_SCRIPTS
                          if test_runner.script_chain(tests_dir, test.split()[0]) != "regtest"} - listed)
        self.assertEqual(on_main, [])


if __name__ == "__main__":
    unittest.main()
