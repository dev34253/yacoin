"""Tests of the test runner call of "make cov-functional" in Makefile.am.

The target runs test/functional/test_runner.py once: FTEST_JOBS scripts in
parallel on regtest (--chain=regtest) with the scripts of
test/functional/regtest-excluded-scripts left out, and
--timeout-factor=$(FTEST_TIMEOUT_FACTOR) passed to every script.
FTEST_SHARD=K/N passes --shard=K/N; without it the call has no --shard.

The coverage part of Makefile.am (between "if USE_LCOV" and its "endif")
is copied into a makefile of its own and printed with "make -n", so no
build, lcov or test runs.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MAKEFILE_AM = os.path.join(HERE, "..", "..", "..", "Makefile.am")
SELECT = "--chain=regtest --exclude-file=/s/test/functional/regtest-excluded-scripts"


def coverage_part():
    """The lines of Makefile.am between "if USE_LCOV" and its "endif"."""
    with open(MAKEFILE_AM, encoding="utf8") as f:
        lines = f.read().splitlines()
    start = lines.index("if USE_LCOV")
    end = lines.index("endif", start)
    return "\n".join(lines[start + 1:end]) + "\n"


@unittest.skipUnless(shutil.which("make"), "needs make")
class CovFunctionalRunnerCallsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test_coverage_makefile.")
        self.addCleanup(shutil.rmtree, self.dir)
        with open(os.path.join(self.dir, "Makefile"), "w") as f:
            f.write("abs_builddir = /b\nabs_top_builddir = /b\nabs_top_srcdir = /s\nall:\n\t@:\n" + coverage_part())

    def runner_calls(self, *variables):
        """The test_runner.py calls "make -n cov-functional" prints, each up
        to its output redirection."""
        out = subprocess.run(["make", "-n", "-s", "-C", self.dir, "cov-functional"] + list(variables),
                             check=True, capture_output=True, text=True).stdout.replace("\\\n", " ")
        return [" ".join(call.split()) for call in re.findall(r"(test/functional/test_runner\.py -j [^>]*)>", out)]

    def test_one_call_runs_every_script_with_the_timeout_factor(self):
        self.assertEqual(self.runner_calls(), [
            "test/functional/test_runner.py -j 4 %s --timeout-factor=4 --tmpdirprefix=/b/test/tmp" % SELECT,
        ])
        self.assertEqual(self.runner_calls("FTEST_SHARD="), self.runner_calls())

    def test_the_jobs_and_the_timeout_factor_can_be_set(self):
        self.assertEqual(self.runner_calls("FTEST_JOBS=2", "FTEST_TIMEOUT_FACTOR=1.5"), [
            "test/functional/test_runner.py -j 2 %s --timeout-factor=1.5 --tmpdirprefix=/b/test/tmp" % SELECT,
        ])

    def test_the_shard_reaches_the_call(self):
        calls = self.runner_calls("FTEST_SHARD=2/3")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].split().count("--shard=2/3"), 1, calls[0])
        self.assertEqual([c.replace(" --shard=2/3", "") for c in calls], self.runner_calls())


if __name__ == "__main__":
    unittest.main()
