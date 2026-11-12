"""The scan of a node's debug.log: the failure lines of -replayvalidation,
the markers of the reindex ("Reindexing finished") and of the end of the
start-up ("Done loading"), and the files of -loadblock the node imported
("Importing blocks file") or could not open. The log is read in chunks,
never whole."""

import codecs
import collections
import os
import re

Failure = collections.namedtuple("Failure", "height block check tx input error")

FAILURE_RE = re.compile(r"replayvalidation: failure height=(\d+) block=([0-9a-f]{64}) "
                        r"check=(\S+) tx=(\S+) input=(\S+) error=(.*)$")
REINDEX_FINISHED = "Reindexing finished"
IMPORTING_RE = re.compile(r"Importing blocks file (.*)\.\.\.$")
NOT_OPENED_RE = re.compile(r"Warning: Could not open blocks file (.*)$")
DONE_LOADING = "Done loading"
CHUNK = 1 << 20


class LogScanner:
    """Takes the log text in pieces of any size (feed) and collects the
    failures and markers of its complete lines; finish() takes a last line
    without a newline."""

    def __init__(self):
        self.failures = []
        self.reindex_finished = False
        self.done_loading = False
        self.imported = []
        self.not_opened = []
        self._partial = ""

    def feed(self, text):
        text = self._partial + text
        lines = text.split("\n")
        self._partial = lines.pop()
        for line in lines:
            self._line(line)

    def finish(self):
        if self._partial:
            self._line(self._partial)
            self._partial = ""

    def _line(self, line):
        line = line.rstrip("\r")
        if "replayvalidation: failure" in line:
            m = FAILURE_RE.search(line)
            if m:
                self.failures.append(Failure(int(m.group(1)), *m.group(2, 3, 4, 5, 6)))
        elif line.endswith(REINDEX_FINISHED):
            self.reindex_finished = True
        elif line.endswith(DONE_LOADING):
            self.done_loading = True
        elif "blocks file " in line:
            m = IMPORTING_RE.search(line)
            if m:
                self.imported.append(m.group(1))
            m = NOT_OPENED_RE.search(line)
            if m:
                self.not_opened.append(m.group(1))


class LogFollower:
    """Reads what was appended to a log file since the last poll()."""

    def __init__(self, path):
        self.path = path
        self.scanner = LogScanner()
        self._file = None
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def poll(self):
        if self._file is None:
            if not os.path.exists(self.path):
                return
            self._file = open(self.path, "rb")
        while True:
            data = self._file.read(CHUNK)
            if not data:
                return
            self.scanner.feed(self._decoder.decode(data))

    def finish(self):
        self.poll()
        self.scanner.feed(self._decoder.decode(b"", final=True))
        self.scanner.finish()
        if self._file is not None:
            self._file.close()
            self._file = None


def scan_file(path):
    """The LogScanner of a whole log file."""
    follower = LogFollower(path)
    follower.finish()
    return follower.scanner


def mark_main_chain(failures, rows):
    """(failure, on main chain) pairs; rows are the main chain's height
    rows (digest.Row), genesis first."""
    return [(f, f.height < len(rows) and rows[f.height].hash == f.block) for f in failures]


def counts(failures):
    """(number of failures, number of distinct blocks)."""
    return len(failures), len({f.block for f in failures})
