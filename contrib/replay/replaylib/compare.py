"""The comparison of two reports.

Two reports are identical when both are complete, their tips, every
section and every height row agree and every failure of either report is
in the expected failures. Otherwise the comparison names the first height
where they differ (the lowest of: a row that differs or is in one report
only, a failure that is not expected), what differs there, the status if a
report is incomplete, the tips if they differ, and the sections that
differ.

Expected failures: a text file with one "block check tx input" entry per
line; "#" starts a comment. An entry matches a failure by block hash,
check, transaction and input.
"""

import re

from .digest import SECTION_ORDER

ROW_FIELDS = (("hash", "hash"), ("mint", "mint"), ("money_supply", "moneysupply"), ("chain", "chain"), ("undo", "undo"))
HASH_RE = re.compile(r"[0-9a-f]{64}")


class ExpectedFailuresError(Exception):
    pass


def load_expected(path):
    """The set of (block, check, tx, input) entries of an expected-failures
    file."""
    entries = set()
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise ExpectedFailuresError("cannot read %s: %s" % (path, e.strerror))
    for n, line in enumerate(lines, 1):
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        if len(fields) != 4:
            raise ExpectedFailuresError("%s line %d: expected 4 fields (block check tx input), found %d"
                                        % (path, n, len(fields)))
        block, check, tx, inp = fields
        if not HASH_RE.fullmatch(block):
            raise ExpectedFailuresError("%s line %d: block is not a hash: %s" % (path, n, block))
        if tx != "-" and not HASH_RE.fullmatch(tx):
            raise ExpectedFailuresError("%s line %d: tx is neither a hash nor -: %s" % (path, n, tx))
        if inp != "-" and not inp.isdigit():
            raise ExpectedFailuresError("%s line %d: input is neither a number nor -: %s" % (path, n, inp))
        entries.add((block, check, tx, inp))
    return entries


def _describe_row(a, b):
    if a is None:
        return "only in B"
    if b is None:
        return "only in A"
    parts = []
    for attr, label in ROW_FIELDS:
        va, vb = getattr(a, attr), getattr(b, attr)
        if va != vb:
            parts.append("%s (A %s, B %s)" % (label, va, vb))
    return ", ".join(parts)


def _describe_failure(side, f):
    return "unexpected failure in %s: block=%s check=%s tx=%s input=%s error=%s" % (
        side, f.block, f.check, f.tx, f.input, f.error)


def compare(a, b, expected):
    """The lines that describe how report.Loaded a and b differ; an empty
    list when they are identical."""
    first = None  # (height, order, text)
    for height in sorted(set(a.rows) | set(b.rows)):
        ra, rb = a.rows.get(height), b.rows.get(height)
        if ra != rb:
            first = (height, 0, _describe_row(ra, rb))
            break
    for side, rep in (("A", a), ("B", b)):
        for f in rep.failures:
            if (f.block, f.check, f.tx, f.input) in expected:
                continue
            cand = (f.height, 1, _describe_failure(side, f))
            if first is None or cand[:2] < first[:2]:
                first = cand
    lines = []
    if first is not None:
        lines.append("first difference at height %d: %s" % (first[0], first[2]))
    status_a, status_b = a.report.get("status"), b.report.get("status")
    if status_a != "complete" or status_b != "complete":
        lines.append("status: A %s, B %s" % (status_a, status_b))
    tip_a = a.report.get("tip") or {}
    tip_b = b.report.get("tip") or {}
    if tip_a != tip_b:
        lines.append("tip: A %s %s, B %s %s" % (tip_a.get("height"), tip_a.get("hash"),
                                               tip_b.get("height"), tip_b.get("hash")))
    sections_a = a.report.get("sections") or {}
    sections_b = b.report.get("sections") or {}
    names = list(SECTION_ORDER) + sorted((set(sections_a) | set(sections_b)) - set(SECTION_ORDER))
    differ = [n for n in names if sections_a.get(n) != sections_b.get(n)]
    if differ:
        lines.append("sections that differ: %s" % ", ".join(differ))
    return lines
