"""Tests of the test runner calls of "make cov-functional" in Makefile.am.

The target runs test/functional/test_runner.py twice: the scripts in
parallel, then those of FTEST_SERIAL alone. FTEST_SHARD=K/N passes
--shard=K/N to both calls; without it neither call has --shard.

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

    def test_without_a_shard_neither_call_has_the_option(self):
        self.assertEqual(self.runner_calls(), [
            "test/functional/test_runner.py -j 4 --exclude=p2p_invalid_messages.py --tmpdirprefix=/b/test/tmp",
            "test/functional/test_runner.py -j 1 --keepcache --tmpdirprefix=/b/test/tmp p2p_invalid_messages.py",
        ])
        self.assertEqual(self.runner_calls("FTEST_SHARD="), self.runner_calls())

    def test_the_shard_reaches_both_calls(self):
        calls = self.runner_calls("FTEST_SHARD=2/3")
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(call.split().count("--shard=2/3"), 1, call)
        self.assertEqual([c.replace(" --shard=2/3", "") for c in calls], self.runner_calls())

    def test_the_serial_scripts_get_the_shard_too(self):
        calls = self.runner_calls("FTEST_SHARD=1/2", "FTEST_SERIAL=p2p_a.py p2p_b.py")
        self.assertEqual(len(calls), 2)
        self.assertIn("--exclude=p2p_a.py,p2p_b.py", calls[0].split())
        self.assertIn("--shard=1/2", calls[0].split())
        self.assertTrue(calls[1].endswith(" p2p_a.py p2p_b.py"), calls[1])
        self.assertIn("--shard=1/2", calls[1].split())


if __name__ == "__main__":
    unittest.main()
