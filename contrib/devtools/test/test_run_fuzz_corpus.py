"""Tests of contrib/devtools/run-fuzz-corpus.py.

The fuzz binary is a fake: a shell script that prints its target names for
PRINT_ALL_FUZZ_TARGETS_AND_ABORT and otherwise, for the target in FUZZ, goes
through its arguments as libFuzzer does with input files: "Running: <file>",
then "Executed <file> in 0 ms". An input whose content starts with a keyword
makes it behave like a failing run instead:

  ABORT     a crash report, exit status 1
  REPORT    a sanitizer report, but exit status 0
  SKIP      the input is not run (no "Executed" line)
  EXIT      the process ends with status 0 before the input runs
  HANG      the process sleeps longer than the runner waits

Every call records FUZZ and its arguments, one per line.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import os
import shlex
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "run-fuzz-corpus.py")

FAKE_BIN = r"""#!/bin/sh
printf '%s\n' "FUZZ=${FUZZ-}" "$@" > "$(mktemp "$CALLS_DIR/call.XXXXXX")"
if [ -n "${PRINT_ALL_FUZZ_TARGETS_AND_ABORT+set}" ]; then
    printf '%s' "$LISTING"
    exit "$LISTING_STATUS"
fi
echo "INFO: Seed: 1" >&2
for arg in "$@"; do
    case "$arg" in -*) continue ;; esac
    echo "Running: $arg" >&2
    case "$(head -c 6 "$arg")" in
        ABORT*) echo "==1==ERROR: AddressSanitizer: deadly signal" >&2; exit 1 ;;
        REPORT) echo "x.cpp:1:2: runtime error: shift exponent 40 is too large" >&2 ;;
        SKIP*) continue ;;
        EXIT*) exit 0 ;;
        HANG*) sleep 30 ;;
    esac
    echo "Executed $arg in 0 ms" >&2
done
echo "*** NOTE: fuzzing was not performed, you have only" >&2
exit 0
"""


class RunFuzzCorpusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="run-fuzz-corpus-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = os.path.join(self.tmp, "fuzz")
        with open(self.bin, "w") as f:
            f.write(FAKE_BIN)
        os.chmod(self.bin, 0o755)
        self.corpus = os.path.join(self.tmp, "corpus")
        os.mkdir(self.corpus)
        self.logdir = os.path.join(self.tmp, "logs")
        self.calls_dir = os.path.join(self.tmp, "calls")
        os.mkdir(self.calls_dir)

    def add_inputs(self, target, *contents):
        d = os.path.join(self.corpus, target)
        os.makedirs(d, exist_ok=True)
        for i, content in enumerate(contents):
            with open(os.path.join(d, "input%02d" % i), "w") as f:
                f.write(content)

    def run_runner(self, targets, listing_status=0, listing=None, options=(), env=None):
        if listing is None:
            listing = "".join(t + "\n" for t in targets)
        environment = dict(os.environ, CALLS_DIR=self.calls_dir, LISTING=listing,
                           LISTING_STATUS=str(listing_status), **(env or {}))
        return subprocess.run(["python3", "-I", "-B", SCRIPT] + list(options) + [self.bin, self.corpus, self.logdir],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                              env=environment, timeout=120)

    def calls(self):
        """(FUZZ, arguments) of every call of the binary"""
        result = []
        for name in sorted(os.listdir(self.calls_dir)):
            with open(os.path.join(self.calls_dir, name)) as f:
                lines = f.read().splitlines()
            result.append((lines[0][len("FUZZ="):], lines[1:]))
        return result

    def target_calls(self):
        """target -> the input files of its calls, in order"""
        result = {}
        for fuzz, args in self.calls():
            if fuzz:
                result.setdefault(fuzz, []).extend(a for a in args if not a.startswith("-"))
        return result

    def summary(self):
        with open(os.path.join(self.logdir, "summary.txt")) as f:
            return f.read().splitlines()

    def test_every_input_of_every_target_runs_once(self):
        self.add_inputs("a_deserialize", "1", "2", "3")
        self.add_inputs("b_deserialize", "4")
        result = self.run_runner(["a_deserialize", "b_deserialize"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.target_calls()
        self.assertEqual(sorted(calls), ["a_deserialize", "b_deserialize"])
        self.assertEqual(sorted(calls["a_deserialize"]),
                         [os.path.join(self.corpus, "a_deserialize", "input%02d" % i) for i in range(3)])
        self.assertEqual(calls["b_deserialize"], [os.path.join(self.corpus, "b_deserialize", "input00")])
        self.assertEqual(self.summary(), ["PASS a_deserialize (3 inputs)", "PASS b_deserialize (1 inputs)"])
        self.assertIn("2 passed, 0 failed", result.stdout)
        self.assertTrue(os.path.isfile(os.path.join(self.logdir, "a_deserialize.log")))

    def test_inputs_are_only_run_with_explicit_limits(self):
        # Input files only, never a directory (libFuzzer would fuzz it), and
        # the time and memory limits per input; no option that mutates.
        self.add_inputs("a_deserialize", "1", "2")
        result = self.run_runner(["a_deserialize"], options=["--timeout", "7", "--rss-limit-mb", "1234"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        runs = [args for fuzz, args in self.calls() if fuzz]
        self.assertEqual(len(runs), 1)
        options = [a for a in runs[0] if a.startswith("-")]
        self.assertEqual(sorted(options), ["-rss_limit_mb=1234", "-timeout=7"])
        for arg in runs[0]:
            if not arg.startswith("-"):
                self.assertTrue(os.path.isabs(arg) and os.path.isfile(arg), arg)

    def test_default_limits(self):
        self.add_inputs("a_deserialize", "1")
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        runs = [args for fuzz, args in self.calls() if fuzz]
        self.assertEqual(sorted(a for a in runs[0] if a.startswith("-")), ["-rss_limit_mb=2048", "-timeout=30"])

    def test_listing_runs_without_a_target(self):
        self.add_inputs("a_deserialize", "1")
        result = self.run_runner(["a_deserialize"], env={"FUZZ": "a_deserialize"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        listings = [args for fuzz, args in self.calls() if not fuzz]
        self.assertEqual(listings, [[]])

    def test_many_inputs_are_run_in_batches(self):
        self.add_inputs("a_deserialize", *[str(i) for i in range(1203)])
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        runs = [args for fuzz, args in self.calls() if fuzz]
        self.assertGreater(len(runs), 1)
        inputs = self.target_calls()["a_deserialize"]
        self.assertEqual(len(inputs), 1203)
        self.assertEqual(len(set(inputs)), 1203)
        self.assertEqual(self.summary(), ["PASS a_deserialize (1203 inputs)"])

    def test_a_crash_fails_and_names_the_target(self):
        self.add_inputs("a_deserialize", "1", "2")
        self.add_inputs("b_deserialize", "3", "ABORT", "4")
        result = self.run_runner(["a_deserialize", "b_deserialize"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        summary = self.summary()
        self.assertEqual(summary[0], "PASS a_deserialize (2 inputs)")
        self.assertTrue(summary[1].startswith("FAIL b_deserialize"), summary)
        self.assertIn("exit status 1", summary[1])
        self.assertIn("1 passed, 1 failed", result.stdout)
        with open(os.path.join(self.logdir, "b_deserialize.log")) as f:
            self.assertIn("ERROR: AddressSanitizer", f.read())

    def test_a_report_with_exit_status_0_fails(self):
        self.add_inputs("a_deserialize", "1", "REPORT")
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(self.summary()[0].startswith("FAIL a_deserialize"), self.summary())
        self.assertIn("report", self.summary()[0])

    def test_an_input_that_did_not_run_fails(self):
        for content in ("SKIP", "EXIT"):
            with self.subTest(content=content):
                shutil.rmtree(self.corpus)
                self.add_inputs("a_deserialize", "1", content, "2")
                result = self.run_runner(["a_deserialize"])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertTrue(self.summary()[0].startswith("FAIL a_deserialize"), self.summary())
                self.assertIn("not run", self.summary()[0])

    def test_a_hanging_process_fails(self):
        self.add_inputs("a_deserialize", "HANG")
        result = self.run_runner(["a_deserialize"], options=["--timeout", "1"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(self.summary()[0].startswith("FAIL a_deserialize"), self.summary())
        self.assertIn("did not finish", self.summary()[0])

    def test_a_target_without_a_corpus_fails(self):
        self.add_inputs("a_deserialize", "1")
        result = self.run_runner(["a_deserialize", "b_deserialize"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("b_deserialize", result.stderr)
        self.assertEqual([c for c in self.calls() if c[0]], [])

    def test_an_empty_corpus_fails(self):
        self.add_inputs("a_deserialize", "1")
        os.mkdir(os.path.join(self.corpus, "b_deserialize"))
        result = self.run_runner(["a_deserialize", "b_deserialize"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("b_deserialize", result.stderr)
        self.assertEqual([c for c in self.calls() if c[0]], [])

    def test_a_corpus_without_a_target_fails(self):
        self.add_inputs("a_deserialize", "1")
        self.add_inputs("old_deserialize", "1")
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("old_deserialize", result.stderr)
        self.assertEqual([c for c in self.calls() if c[0]], [])

    def test_anything_but_a_file_in_a_corpus_fails(self):
        self.add_inputs("a_deserialize", "1")
        os.mkdir(os.path.join(self.corpus, "a_deserialize", "subdir"))
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("subdir", result.stderr)
        self.assertEqual([c for c in self.calls() if c[0]], [])

    def test_a_file_next_to_the_corpus_directories_fails(self):
        self.add_inputs("a_deserialize", "1")
        with open(os.path.join(self.corpus, "README"), "w") as f:
            f.write("x")
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("README", result.stderr)

    def test_a_failed_listing_fails(self):
        self.add_inputs("a_deserialize", "1")
        for status, listing in ((1, "a_deserialize\n"), (0, ""), (0, "a_deserialize\nnot a name\n"),
                                (0, "a_deserialize\na_deserialize\n")):
            with self.subTest(status=status, listing=listing):
                result = self.run_runner(["a_deserialize"], listing_status=status, listing=listing)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("list", result.stderr)
                self.assertEqual([c for c in self.calls() if c[0]], [])

    def test_bad_arguments_exit_2(self):
        self.add_inputs("a_deserialize", "1")
        for options in (["--jobs", "0"], ["--jobs", "x"], ["--timeout", "0"], ["--rss-limit-mb", "-1"]):
            with self.subTest(options=options):
                result = self.run_runner(["a_deserialize"], options=options)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        result = subprocess.run(["python3", "-I", "-B", SCRIPT, self.bin], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual([c for c in self.calls() if c[0]], [])

    def test_a_log_directory_with_other_files_is_refused(self):
        self.add_inputs("a_deserialize", "1")
        for name in ("README", "notes.txt", "build.log", "b_deserialize.log", "a_deserialize", "A_DESERIALIZE.log"):
            with self.subTest(name=name):
                shutil.rmtree(self.logdir, ignore_errors=True)
                os.makedirs(self.logdir)
                with open(os.path.join(self.logdir, "summary.txt"), "w") as f:
                    f.write("old\n")
                path = os.path.join(self.logdir, name)
                if name == "a_deserialize":
                    os.mkdir(path)
                else:
                    with open(path, "w") as f:
                        f.write("keep\n")
                result = self.run_runner(["a_deserialize"])
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(name, result.stderr)
                self.assertTrue(os.path.exists(path))
                self.assertTrue(os.path.exists(os.path.join(self.logdir, "summary.txt")))
                self.assertEqual([c for c in self.calls() if c[0]], [])
        # The corpus directory as the log directory: refused, nothing deleted.
        result = subprocess.run(["python3", "-I", "-B", SCRIPT, self.bin, self.corpus, self.corpus],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                env=dict(os.environ, CALLS_DIR=self.calls_dir, LISTING="a_deserialize\n",
                                         LISTING_STATUS="0"))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(os.listdir(os.path.join(self.corpus, "a_deserialize")), ["input00"])

    def test_a_file_as_the_log_directory_is_refused(self):
        self.add_inputs("a_deserialize", "1")
        with open(self.logdir, "w") as f:
            f.write("keep\n")
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        with open(self.logdir) as f:
            self.assertEqual(f.read(), "keep\n")

    def test_the_logs_of_an_earlier_run_are_replaced(self):
        self.add_inputs("a_deserialize", "1")
        os.makedirs(self.logdir)
        # old_deserialize.log is the log of a target an earlier run had.
        with open(os.path.join(self.logdir, "summary.txt"), "w") as f:
            f.write("PASS a_deserialize (3 inputs)\nFAIL old_deserialize: exit status 1 (log: x)\n")
        for name in ("a_deserialize.log", "old_deserialize.log"):
            with open(os.path.join(self.logdir, name), "w") as f:
                f.write("old\n")
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sorted(os.listdir(self.logdir)), ["a_deserialize.log", "summary.txt"])
        self.assertEqual(self.summary(), ["PASS a_deserialize (1 inputs)"])

    def test_a_missing_log_directory_is_created(self):
        self.add_inputs("a_deserialize", "1")
        self.logdir = os.path.join(self.tmp, "new", "logs")
        result = self.run_runner(["a_deserialize"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary(), ["PASS a_deserialize (1 inputs)"])

    def test_targets_run_in_parallel(self):
        # Each target's process waits until the other one has started.
        marker = os.path.join(self.tmp, "started")
        script = FAKE_BIN.replace('echo "INFO: Seed: 1" >&2',
                                  'touch "%s.$FUZZ"; n=0; while [ $(ls %s.* | wc -l) -lt 2 ] && [ $n -lt 50 ]; '
                                  'do sleep 0.1; n=$((n+1)); done; [ $n -lt 50 ] || exit 3'
                                  % (shlex.quote(marker), shlex.quote(marker)))
        with open(self.bin, "w") as f:
            f.write(script)
        self.add_inputs("a_deserialize", "1")
        self.add_inputs("b_deserialize", "2")
        result = self.run_runner(["a_deserialize", "b_deserialize"], options=["--jobs", "2"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
