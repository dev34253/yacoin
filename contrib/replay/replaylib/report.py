"""The report files of a run or a digest, in one output directory:
  report.json     the report (see README.md)
  heights.tsv.gz  per height: block hash, mint, money supply, chain-record
                  digest, undo digest
  failures.tsv    the failure lines of -replayvalidation, with whether the
                  block is on the main chain
"""

import collections
import datetime
import gzip
import json
import os

from .digest import Row
from .logscan import Failure

HEIGHTS_HEADER = "height\thash\tmint\tmoneysupply\tchain\tundo\n"
FAILURES_HEADER = "height\tblock\tcheck\ttx\tinput\tmain\terror\n"

Loaded = collections.namedtuple("Loaded", "path report rows failures")


class ReportError(Exception):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write(out, rep, rows, marked_failures):
    """Writes report.json, heights.tsv.gz and failures.tsv into out;
    marked_failures are (failure, on main chain) pairs."""
    with open(os.path.join(out, "report.json"), "w") as f:
        json.dump(rep, f, indent=2, sort_keys=True)
        f.write("\n")
    # mtime 0 and no file name: the same rows give the same bytes.
    with open(os.path.join(out, "heights.tsv.gz"), "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(HEIGHTS_HEADER.encode())
            for start in range(0, len(rows), 10000):
                gz.write("".join("%d\t%s\t%d\t%d\t%s\t%s\n" % r for r in rows[start:start + 10000]).encode())
    with open(os.path.join(out, "failures.tsv"), "w") as f:
        f.write(FAILURES_HEADER)
        for fl, main in marked_failures:
            f.write("%d\t%s\t%s\t%s\t%s\t%d\t%s\n" % (fl.height, fl.block, fl.check, fl.tx, fl.input, main, fl.error))


def load(path):
    """The report in directory path (or of the report.json at path)."""
    if os.path.isdir(path):
        out = path
    elif os.path.basename(path) == "report.json":
        out = os.path.dirname(path) or "."
    else:
        raise ReportError("not a report directory or report.json: %s" % path)
    json_path = os.path.join(out, "report.json")
    try:
        with open(json_path) as f:
            rep = json.load(f)
    except (OSError, ValueError) as e:
        raise ReportError("cannot read %s: %s" % (json_path, e))
    rows = {}
    heights = os.path.join(out, "heights.tsv.gz")
    try:
        with gzip.open(heights, "rt") as f:
            if f.readline() != HEIGHTS_HEADER:
                raise ReportError("%s: unknown header" % heights)
            for line in f:
                h, block, mint, supply, chain_digest, undo = line.rstrip("\n").split("\t")
                rows[int(h)] = Row(int(h), block, int(mint), int(supply), chain_digest, undo)
    except (OSError, ValueError, EOFError) as e:
        raise ReportError("cannot read %s: %s" % (heights, e))
    failures = []
    failures_path = os.path.join(out, "failures.tsv")
    if os.path.exists(failures_path):
        failures = read_failures(failures_path)
    return Loaded(out, rep, rows, failures)


def read_failures(path):
    """The failures (logscan.Failure) of a failures.tsv file."""
    failures = []
    try:
        with open(path) as f:
            if f.readline() != FAILURES_HEADER:
                raise ReportError("%s: unknown header" % path)
            for line in f:
                h, block, check, tx, inp, _main, error = line.rstrip("\n").split("\t", 6)
                failures.append(Failure(int(h), block, check, tx, inp, error))
    except (OSError, ValueError) as e:
        raise ReportError("cannot read %s: %s" % (path, e))
    return failures
