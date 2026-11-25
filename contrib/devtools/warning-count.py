#!/usr/bin/env python3
"""Counts the compiler warnings of a build log per class and per component.

Usage:
  warning-count.py LOG [--values FILE] [--markdown FILE] [--root DIR]
  warning-count.py --values FILE --check-values

Prints the number of emitted lines and of unique locations (a file, line,
column and class) of every warning class and every component. With --values
(JSON, class: unique locations) it exits with status 1 when a class has more
unique locations than its value or has no value, and lists that class's
locations; a class with fewer gets a note. Bad input exits with status 2.
--markdown appends the tables, without locations, to FILE.
"""

import argparse
import collections
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WARNING = re.compile(r"^(\S+?):(\d+):(?:(\d+):)? warning: (.*?)(?: \[(-W[^\]]+)\])?\s*$")
# The colour codes gcc prints on a terminal.
ESCAPES = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
COMPONENTS = ("src", "src/test", "src/wallet/test", "src/leveldb", "src/secp256k1", "src/univalue", "depends", "other")
SUBTREES = ("src/test", "src/wallet/test", "src/leveldb", "src/secp256k1", "src/univalue")

Warning = collections.namedtuple("Warning", "path line column cls component")


class InputError(Exception):
    def __init__(self, path, reason):
        super().__init__("%s: %s" % (path, reason))


def normalise(path, root):
    p = os.path.normpath(path)
    if os.path.isabs(p):
        r = os.path.normpath(root)
        if p.startswith(r.rstrip("/") + "/"):
            p = os.path.relpath(p, r)
    else:
        while p.startswith("../"):
            p = p[3:]
    parts = p.split("/")
    if "depends" in parts:
        p = "/".join(["depends"] + parts[parts.index("depends") + 1:])
    return p


def component(path):
    if path.startswith("depends/"):
        return "depends"
    for sub in SUBTREES:
        if path.startswith(sub + "/"):
            return sub
    return "src" if path.startswith("src/") else "other"


def parse_line(line, root):
    m = WARNING.match(ESCAPES.sub("", line.rstrip("\n")))
    if not m:
        return None
    path, number, column, text, flag = m.groups()
    p = normalise(path, root)
    cls = flag or "(no flag: %s)" % re.sub(r'"[^"]*"', '"X"', text)
    return Warning(p, int(number), int(column) if column else None, cls, component(p))


class Counts:
    def __init__(self):
        self.emitted = collections.Counter()            # per class
        self.component_emitted = collections.Counter()
        self.locations = {}                             # (path, line, column, class): component

    def add(self, w):
        self.emitted[w.cls] += 1
        self.component_emitted[w.component] += 1
        self.locations.setdefault((w.path, w.line, w.column, w.cls), w.component)

    def total_emitted(self):
        return sum(self.emitted.values())

    def unique_by_class(self):
        return dict(collections.Counter(key[3] for key in self.locations))

    def unique_by_component(self):
        return dict(collections.Counter(self.locations.values()))

    def locations_of(self, cls):
        keys = sorted((k for k in self.locations if k[3] == cls), key=lambda k: (k[0], k[1], k[2] or 0))
        return ["%s:%d" % (k[0], k[1]) + (":%d" % k[2] if k[2] is not None else "") for k in keys]


def count(lines, root):
    counts = Counts()
    for line in lines:
        w = parse_line(line, root)
        if w:
            counts.add(w)
    return counts


def read_log(path, root):
    try:
        with open(path, encoding="utf8", errors="replace") as f:
            return count(f, root)
    except OSError as e:
        raise InputError(path, e.strerror or str(e))


def load_values(path):
    def no_duplicates(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise InputError(path, "the class %s is there twice" % key)
            seen[key] = value
        return seen
    try:
        with open(path, encoding="utf8") as f:
            values = json.load(f, object_pairs_hook=no_duplicates)
    except OSError as e:
        raise InputError(path, e.strerror or str(e))
    except ValueError as e:
        raise InputError(path, "not valid JSON (%s)" % e)
    if not isinstance(values, dict):
        raise InputError(path, "not a JSON object of class: unique locations")
    for cls, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise InputError(path, "the value of %s is not a non-negative integer: %s" % (cls, json.dumps(value)))
    return values


def plural(n):
    return "%d unique location%s" % (n, "" if n == 1 else "s")


def check(counts, values):
    """(status per class, failures as (class, text), notes)"""
    unique = counts.unique_by_class()
    status, failures, notes = {}, [], []
    for cls in sorted(set(unique) | set(values)):
        n = unique.get(cls, 0)
        if cls not in values:
            status[cls] = "no value"
            failures.append((cls, "%s: %s, no recorded value" % (cls, plural(n))))
        elif n > values[cls]:
            status[cls] = "above"
            failures.append((cls, "%s: %s, recorded %d" % (cls, plural(n), values[cls])))
        elif n < values[cls]:
            status[cls] = "below"
            notes.append("%s: %s, recorded %d: lower the recorded value to %d" % (cls, plural(n), values[cls], n))
        else:
            status[cls] = "ok"
    return status, failures, notes


def table_rows(counts, values, status):
    unique = counts.unique_by_class()
    classes = sorted(set(unique) | set(values or {}), key=lambda c: (-unique.get(c, 0), c))
    by_component = counts.unique_by_component()
    components = sorted(COMPONENTS, key=lambda c: (-by_component.get(c, 0), COMPONENTS.index(c)))
    component_rows = [[c, counts.component_emitted[c], by_component.get(c, 0)] for c in components]
    class_rows = []
    for cls in classes:
        row = [cls, counts.emitted[cls], unique.get(cls, 0)]
        if values is not None:
            row += [values.get(cls, "-"), status[cls]]
        class_rows.append(row)
    return component_rows, class_rows


def text_table(header, rows):
    """Columns that hold a number are right-aligned."""
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    numeric = [any(isinstance(r[i], int) for r in rows) for i in range(len(header))]
    return "\n".join("  ".join(str(c).rjust(w) if num else str(c).ljust(w)
                               for c, w, num in zip(r, widths, numeric)).rstrip()
                     for r in [header] + rows)


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(out)


def report(log, counts, values):
    status, failures, notes = check(counts, values) if values is not None else ({}, [], [])
    component_rows, class_rows = table_rows(counts, values, status)
    class_header = ["class", "emitted", "unique"] + (["recorded", "status"] if values is not None else [])
    head = "warnings in %s: %d emitted, %s" % (log, counts.total_emitted(), plural(len(counts.locations)))
    text = [head, "", text_table(["component", "emitted", "unique"], component_rows), "",
            text_table(class_header, class_rows)]
    md_class_rows = [["`%s`" % r[0]] + r[1:4] + (["**%s**" % r[4] if r[4] in ("above", "no value") else r[4]]
                                                  if values is not None else []) for r in class_rows]
    md = ["### Compiler warnings", "", head, "",
          md_table(["component", "emitted", "unique"], [["`%s`" % r[0]] + r[1:] for r in component_rows]), "",
          md_table(class_header, md_class_rows)]
    if values is not None:
        if failures:
            text.append("")
            md += ["", "**Failed:**", ""]
            for cls, line in failures:
                text.append("FAIL  " + line)
                text += ["  " + loc for loc in counts.locations_of(cls)]
                md.append("- " + line)
        if notes:
            text.append("")
            md += ["", "To lower:", ""]
            text += ["NOTE  " + n for n in notes]
            md += ["- " + n for n in notes]
        verdict = "warning count: %d failure(s), %d to lower" % (len(failures), len(notes))
        text += ["", verdict]
        md += ["", verdict]
    return "\n".join(text), "\n".join(md), bool(failures)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], epilog="See the top of this script.")
    parser.add_argument("log", nargs="?", metavar="LOG", help="the build log")
    parser.add_argument("--values", metavar="FILE", help="the recorded values (JSON)")
    parser.add_argument("--check-values", action="store_true", help="only check the values file")
    parser.add_argument("--markdown", metavar="FILE", help="append the tables as Markdown to FILE")
    parser.add_argument("--root", default=REPO_ROOT, help="absolute paths are relative to this (default: %(default)s)")
    args = parser.parse_args(argv)
    if args.check_values and (args.values is None or args.log is not None):
        parser.error("--check-values takes --values FILE and no LOG")
    if not args.check_values and args.log is None:
        parser.error("LOG is required")
    try:
        values = load_values(args.values) if args.values is not None else None
        if args.check_values:
            print("%s: %d classes, %s" % (args.values, len(values), plural(sum(values.values()))))
            return 0
        counts = read_log(args.log, args.root)
        if values is not None and not counts.locations and sum(values.values()) > 0:
            raise InputError(args.log, "no warnings in the log, and the recorded values total %d" % sum(values.values()))
    except InputError as e:
        print("warning-count: error: %s" % e, file=sys.stderr)
        return 2
    text, md, failed = report(args.log, counts, values)
    print(text)
    if args.markdown:
        try:
            with open(args.markdown, "a", encoding="utf8") as f:
                f.write("\n" + md + "\n")
        except OSError as e:
            print("warning-count: error: %s" % InputError(args.markdown, e.strerror or str(e)), file=sys.stderr)
            return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
