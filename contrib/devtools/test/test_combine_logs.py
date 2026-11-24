"""Tests of test/functional/combine_logs.py: how it splits the test
framework's log and the nodes' debug.log files into events and orders the
events of all logs by time.

A line of test_framework.log that starts with the framework's time stamp
(YYYY-MM-DDTHH:MM:SS.ffffffZ) starts an event, and a line of a node's
debug.log that starts with the node's (YYYY-MM-DD HH:MM:SS, with .ffffff
under -logtimemicros and " (mocktime: YYYY-MM-DD HH:MM:SS)" when mock time
is set); any other line continues the event before it. The events of all
logs come in the order of their leading time stamps; events with the same
stamp in the order test, node0, node1, ..., and within a log in file order.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import collections
import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "..", "..", "test", "functional", "combine_logs.py")

spec = importlib.util.spec_from_file_location("combine_logs", SCRIPT)
combine_logs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combine_logs)

# The indent combine_logs.py puts before a continuation line
INDENT = " " * 35


class CombineLogsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="test_combine_logs.")
        self.addCleanup(shutil.rmtree, self.dir)

    def write(self, test_log, *node_logs):
        """A test directory with test_log as its test_framework.log and
        node_logs as node<i>/regtest/debug.log (None: no debug.log)."""
        with open(os.path.join(self.dir, "test_framework.log"), "w", encoding="utf-8") as f:
            f.write(test_log)
        for i, log in enumerate(node_logs):
            chain_dir = os.path.join(self.dir, "node%d" % i, "regtest")
            os.makedirs(chain_dir)
            if log is not None:
                with open(os.path.join(chain_dir, "debug.log"), "w", encoding="utf-8") as f:
                    f.write(log)

    def events(self):
        """read_logs' events as (source, event text), stderr captured."""
        with contextlib.redirect_stderr(io.StringIO()):
            return [(e.source, e.event) for e in combine_logs.read_logs(self.dir)]

    def plain(self):
        """print_logs_plain's output for the test directory, without colours."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            combine_logs.print_logs_plain(combine_logs.read_logs(self.dir), collections.defaultdict(str))
        return out.getvalue()

    def test_sources_interleaved_by_time(self):
        self.write("2026-11-23T10:00:00.100000Z TestFramework (INFO): Initializing test directory\n"
                   "2026-11-23T10:00:01.400000Z TestFramework (INFO): Nodes started\n"
                   "2026-11-23T10:00:02.000000Z TestFramework (INFO): Stopping nodes\n",
                   "2026-11-23 10:00:00.300000 Default data directory\n"
                   "2026-11-23 10:00:01.200000 init message: Done loading\n"
                   "2026-11-23 10:00:02.100000 Shutdown: done\n",
                   "2026-11-23 10:00:00.200000 Default data directory\n"
                   "2026-11-23 10:00:01.300000 init message: Done loading\n"
                   "2026-11-23 10:00:02.200000 Shutdown: done\n")
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:00.100000Z TestFramework (INFO): Initializing test directory"),
            ("node1", "2026-11-23 10:00:00.200000 Default data directory"),
            ("node0", "2026-11-23 10:00:00.300000 Default data directory"),
            ("node0", "2026-11-23 10:00:01.200000 init message: Done loading"),
            ("node1", "2026-11-23 10:00:01.300000 init message: Done loading"),
            ("test", "2026-11-23T10:00:01.400000Z TestFramework (INFO): Nodes started"),
            ("test", "2026-11-23T10:00:02.000000Z TestFramework (INFO): Stopping nodes"),
            ("node0", "2026-11-23 10:00:02.100000 Shutdown: done"),
            ("node1", "2026-11-23 10:00:02.200000 Shutdown: done"),
        ])

    def test_script_output_interleaved_by_time(self):
        self.write("2026-11-23T10:00:00.100000Z TestFramework (INFO): Initializing test directory\n"
                   "2026-11-23T10:00:02.000000Z TestFramework (INFO): Stopping nodes\n",
                   "2026-11-23 10:00:01.200000 init message: Done loading\n")
        output = subprocess.run([sys.executable, "-I", SCRIPT, self.dir], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True, check=True)
        self.assertEqual(output.stdout.splitlines(), [
            " test  2026-11-23T10:00:00.100000Z TestFramework (INFO): Initializing test directory ",
            " node0 2026-11-23 10:00:01.200000 init message: Done loading ",
            " test  2026-11-23T10:00:02.000000Z TestFramework (INFO): Stopping nodes ",
            "",
        ])
        self.assertEqual(output.stderr, "")

    def test_node_stamps_with_and_without_microseconds(self):
        self.write("2026-11-23T10:00:00.999998Z TestFramework (INFO): before\n"
                   "2026-11-23T10:00:01.000500Z TestFramework (INFO): after\n",
                   "2026-11-23 10:00:01 init message: Done loading\n",
                   "2026-11-23 10:00:00.999999 init message: Done loading\n")
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:00.999998Z TestFramework (INFO): before"),
            ("node1", "2026-11-23 10:00:00.999999 init message: Done loading"),
            ("node0", "2026-11-23 10:00:01 init message: Done loading"),
            ("test", "2026-11-23T10:00:01.000500Z TestFramework (INFO): after"),
        ])

    def test_mock_time_suffix(self):
        self.write("2026-11-23T10:00:02.500000Z TestFramework (INFO): before\n"
                   "2026-11-23T10:00:03.500000Z TestFramework (INFO): after\n",
                   "2026-11-23 10:00:03.000000 (mocktime: 2026-11-24 00:00:00) init message: Done loading\n"
                   "2026-11-23 10:00:04 (mocktime: 2026-11-22 00:00:00) Shutdown: done\n")
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:02.500000Z TestFramework (INFO): before"),
            ("node0", "2026-11-23 10:00:03.000000 (mocktime: 2026-11-24 00:00:00) init message: Done loading"),
            ("test", "2026-11-23T10:00:03.500000Z TestFramework (INFO): after"),
            ("node0", "2026-11-23 10:00:04 (mocktime: 2026-11-22 00:00:00) Shutdown: done"),
        ])

    def test_continuation_lines_stay_with_their_event(self):
        self.write("2026-11-23T10:00:01.000000Z TestFramework (ERROR): Assertion failed\n"
                   "Traceback (most recent call last):\n"
                   "AssertionError: not(1 == 2)\n"
                   "2026-11-23T10:00:03.000000Z TestFramework (INFO): Stopping nodes\n",
                   "2026-11-23 10:00:02.000000 ERROR: a message\n"
                   "  over two lines\n"
                   "2026-11-23 10:00:04.000000 Shutdown: done\n")
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:01.000000Z TestFramework (ERROR): Assertion failed\n" +
             INDENT + "Traceback (most recent call last):\n" +
             INDENT + "AssertionError: not(1 == 2)"),
            ("node0", "2026-11-23 10:00:02.000000 ERROR: a message\n" + INDENT + "  over two lines"),
            ("test", "2026-11-23T10:00:03.000000Z TestFramework (INFO): Stopping nodes"),
            ("node0", "2026-11-23 10:00:04.000000 Shutdown: done"),
        ])

    def test_equal_stamps_across_sources(self):
        self.write("2026-11-23T10:00:05.000000Z TestFramework (INFO): framework\n",
                   "2026-11-23 10:00:05.000000 node zero\n",
                   "2026-11-23 10:00:05 node one\n")
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:05.000000Z TestFramework (INFO): framework"),
            ("node0", "2026-11-23 10:00:05.000000 node zero"),
            ("node1", "2026-11-23 10:00:05 node one"),
        ])

    def test_equal_stamps_in_one_source_keep_file_order(self):
        self.write("2026-11-23T10:00:05.000000Z TestFramework (INFO): b first\n"
                   "2026-11-23T10:00:05.000000Z TestFramework (INFO): a second\n",
                   "2026-11-23 10:00:06.000000 b first\n"
                   "2026-11-23 10:00:06.000000 a second\n")
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:05.000000Z TestFramework (INFO): b first"),
            ("test", "2026-11-23T10:00:05.000000Z TestFramework (INFO): a second"),
            ("node0", "2026-11-23 10:00:06.000000 b first"),
            ("node0", "2026-11-23 10:00:06.000000 a second"),
        ])

    def test_empty_node_logs(self):
        self.write("2026-11-23T10:00:01.000000Z TestFramework (INFO): Stopping nodes\n",
                   "",
                   "\n\n",
                   "2026-11-23 10:00:00.000000 init message: Done loading\n")
        self.assertEqual(self.events(), [
            ("node2", "2026-11-23 10:00:00.000000 init message: Done loading"),
            ("test", "2026-11-23T10:00:01.000000Z TestFramework (INFO): Stopping nodes"),
        ])
        self.assertEqual(self.plain().splitlines(), [
            " node2 2026-11-23 10:00:00.000000 init message: Done loading ",
            " test  2026-11-23T10:00:01.000000Z TestFramework (INFO): Stopping nodes ",
        ])

    def test_node_without_debug_log(self):
        self.write("2026-11-23T10:00:01.000000Z TestFramework (INFO): Stopping nodes\n", None)
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:01.000000Z TestFramework (INFO): Stopping nodes"),
        ])

    def test_node_line_in_a_framework_event(self):
        self.write("2026-11-23T10:00:01.000000Z TestFramework (ERROR): Expected messages not found in the log:\n"
                   "2026-11-23 10:00:00.500000 init message: Done loading\n"
                   "2026-11-23T10:00:03.000000Z TestFramework (INFO): Stopping nodes\n",
                   "2026-11-23 10:00:02.000000 init message: Done loading\n")
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:01.000000Z TestFramework (ERROR): Expected messages not found in the log:\n" +
             INDENT + "2026-11-23 10:00:00.500000 init message: Done loading"),
            ("node0", "2026-11-23 10:00:02.000000 init message: Done loading"),
            ("test", "2026-11-23T10:00:03.000000Z TestFramework (INFO): Stopping nodes"),
        ])

    def test_date_at_start_of_a_node_continuation_line(self):
        self.write("2026-11-23T10:00:03.000000Z TestFramework (INFO): Stopping nodes\n",
                   "2026-11-23 10:00:01.000000 a message whose next line\n"
                   "2026-11-23 is not a log line\n"
                   "2026-11-23 10:00:04.000000 Shutdown: done\n")
        self.assertEqual(self.events(), [
            ("node0", "2026-11-23 10:00:01.000000 a message whose next line\n" +
             INDENT + "2026-11-23 is not a log line"),
            ("test", "2026-11-23T10:00:03.000000Z TestFramework (INFO): Stopping nodes"),
            ("node0", "2026-11-23 10:00:04.000000 Shutdown: done"),
        ])

    def test_framework_stamp_without_microseconds(self):
        self.write("2026-11-23T10:00:07Z TestFramework (INFO): no microseconds\n"
                   "2026-11-23T10:00:07.000001Z TestFramework (INFO): with microseconds\n",
                   "2026-11-23 10:00:07.000000 init message: Done loading\n")
        self.assertEqual(self.events(), [
            ("test", "2026-11-23T10:00:07.000000Z TestFramework (INFO): no microseconds"),
            ("node0", "2026-11-23 10:00:07.000000 init message: Done loading"),
            ("test", "2026-11-23T10:00:07.000001Z TestFramework (INFO): with microseconds"),
        ])


if __name__ == "__main__":
    unittest.main()
