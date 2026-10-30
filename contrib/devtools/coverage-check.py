#!/usr/bin/env python3
"""Checks line and branch coverage against the targets in coverage-targets.json.

Usage:
  coverage-check.py --unit FILE --all FILE [FILE...] [--functions FILE...]
                    [--root DIR] [--targets FILE] [--markdown FILE]
  coverage-check.py --unit FILE --all FILE [FILE...] --functions FILE...
                    [--root DIR] [--markdown FILE] --per-function SOURCE

--unit is the lcov 1.x tracefile of the unit tests, --all the tracefile of the
unit and functional tests together (several files are summed, as "lcov -a"
does). Several records of one file (one per test name) are merged: line counts
are summed per line, branch counts per (line, block, branch). Source paths are
made relative to --root (default: this repository; CI uses /src, where the
tree is mounted in the build image).

The target file holds a tolerance, the recorded overall values, the tiers and
one entry per file (or per named functions of a file). An entry has either a
target (a tier name or {metric: percent}) and a "met" flag, or recorded values
({metric: percent}). Metrics: unit_lines, unit_branches, all_lines,
all_branches. A metric with nothing instrumented counts as met.

The check fails (exit status 1) if an entry recorded as met is below its target
(no tolerance), or if a recorded value or an overall value (over all files
under src/) is more than the tolerance below the value recorded. It reports,
without failing, entries below their target, entries that meet their target
but are not recorded as met, and recorded values that rose by at least the
tolerance. Bad input (a missing or malformed file, an unknown key, a file or
function the tracefiles do not have) exits with status 2.

Function extents come from the JSON files the coverage make targets write next
to their tracefiles (coverage-functions.py): each function's first and last
line as gcov reports them. A function's coverage counts the lines and branches
inside its extent, so the lines of a lambda count in the enclosing function as
well as in the lambda's own row, and lines between functions count nowhere.
An entry with "functions" counts the lines of every function whose name
matches one of the names, each line once: the demangled name without return
type, parameter list, trailing qualifiers and ABI tags (ns::f(int) const ->
ns::f, double g<double>(double) -> g<double>; a lambda keeps the enclosing
function's name and parameters, e.g. ns::f(int)::{lambda(int)#1}::operator()).

--per-function SOURCE prints the coverage of every function of SOURCE instead
of the check. --markdown appends the table as Markdown to FILE (for example
$GITHUB_STEP_SUMMARY).
"""

import argparse
import collections
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_TARGETS = os.path.join(REPO_ROOT, "contrib", "devtools", "coverage-targets.json")

METRICS = ("unit_lines", "unit_branches", "all_lines", "all_branches")
METRIC_TEXT = {"unit_lines": "unit lines", "unit_branches": "unit branches",
               "all_lines": "all lines", "all_branches": "all branches"}
# Comparisons of percentages allow for floating point rounding only.
EPS = 1e-9


class InputError(Exception):
    pass


Stats = collections.namedtuple("Stats", "lines_hit lines_found branches_hit branches_found")
Function = collections.namedtuple("Function", "demangled start end")


class Coverage:
    """Line counts {line: count} and branch counts {(line, block, branch): count} of one file."""

    def __init__(self):
        self.lines = {}
        self.branches = {}

    def add(self, other):
        for line, count in other.lines.items():
            self.lines[line] = self.lines.get(line, 0) + count
        for key, count in other.branches.items():
            self.branches[key] = self.branches.get(key, 0) + count


def stats(cov, ranges=None):
    """Stats of a file, or of the lines inside the [start, end] ranges."""
    if ranges is None:
        def inside(line):
            return True
    else:
        ranges = list(ranges)

        def inside(line):
            return any(start <= line <= end for start, end in ranges)
    lines = [count for line, count in cov.lines.items() if inside(line)]
    branches = [count for (line, _, _), count in cov.branches.items() if inside(line)]
    return Stats(sum(1 for c in lines if c > 0), len(lines), sum(1 for c in branches if c > 0), len(branches))


def relative_path(path, root):
    path = os.path.normpath(path)
    if root:
        root = os.path.normpath(root)
        if os.path.isabs(path) and os.path.commonpath([path, root]) == root:
            return os.path.relpath(path, root)
    return path


def _ints(text, n, what, where):
    parts = text.split(",")
    try:
        values = [int(p) for p in parts[:n]]
    except ValueError:
        values = []
    if len(values) != n or len(parts) < n:
        raise InputError("%s: malformed %s record: %s" % (where, what, text))
    return values, parts[n:]


def parse_tracefile(path, root, files=None):
    """Adds the records of an lcov 1.x tracefile to files {relative path: Coverage}."""
    files = {} if files is None else files
    cur = None
    with open(path, encoding="utf8", errors="replace") as f:
        for number, line in enumerate(f, 1):
            line = line.rstrip("\n")
            where = "%s:%d" % (path, number)
            if line.startswith("SF:"):
                cur = files.setdefault(relative_path(line[3:], root), Coverage())
            elif line == "end_of_record":
                cur = None
            elif line.startswith("DA:"):
                if cur is None:
                    raise InputError("%s: DA record outside a file record" % where)
                (ln, count), _ = _ints(line[3:], 2, "DA", where)
                cur.lines[ln] = cur.lines.get(ln, 0) + count
            elif line.startswith("BRDA:"):
                if cur is None:
                    raise InputError("%s: BRDA record outside a file record" % where)
                (ln, block, branch), rest = _ints(line[5:], 3, "BRDA", where)
                if len(rest) != 1 or not (rest[0] == "-" or rest[0].isdigit()):
                    raise InputError("%s: malformed BRDA record: %s" % (where, line))
                key = (ln, block, branch)
                cur.branches[key] = cur.branches.get(key, 0) + (0 if rest[0] == "-" else int(rest[0]))
    return files


def read_tracefiles(paths, root):
    files = {}
    for path in paths:
        parse_tracefile(path, root, files)
    return files


# ---- function names ----

_OPERATOR_SYMBOLS = set("+-*/%^&|~!=<>,")
_IDENT = re.compile(r"[A-Za-z0-9_$]")
_QUALIFIERS = ("const", "volatile", "noexcept", "&&", "&")


def _strip_qualifiers(s):
    """s without trailing cv/ref qualifiers, if what is left ends with a parameter list."""
    t = re.sub(r"( \[clone [^\]]*\])+$", "", s).rstrip()
    while True:
        for q in _QUALIFIERS:
            if t.endswith(q):
                before = t[:-len(q)]
                if q[0].isalpha() and before and _IDENT.match(before[-1]):
                    continue
                t = before.rstrip()
                break
        else:
            break
    return t if t.endswith(")") else re.sub(r"( \[clone [^\]]*\])+$", "", s).rstrip()


def _split(demangled):
    """(index where the name starts, index where its parameter list starts) in demangled."""
    s = _strip_qualifiers(demangled.strip())
    head_end = len(s)
    if s.endswith(")"):
        depth = 0
        for i in range(len(s) - 1, -1, -1):
            if s[i] == ")":
                depth += 1
            elif s[i] == "(":
                depth -= 1
                if depth == 0:
                    head_end = i
                    break
    head = s[:head_end]
    # Top-level words of the head; operator names are single words, so their
    # brackets (operator<, operator->, operator()) do not count as nesting.
    starts, depth, i, start = [], 0, 0, 0
    while i < len(head):
        c = head[i]
        if (head.startswith("operator", i) and (i == 0 or head[i - 1] in ": ")
                and not _IDENT.match(head[i + 8:i + 9] or " ")):
            j = i + 8
            if head[j:j + 2] in ("()", "[]"):
                j += 2
            else:
                while j < len(head) and head[j] in _OPERATOR_SYMBOLS:
                    j += 1
            i = j
            continue
        if c in "(<[{":
            depth += 1
        elif c in ")>]}":
            depth -= 1
        elif c == " " and depth == 0:
            starts.append(start)
            start = i + 1
        i += 1
    starts.append(start)
    words = [head[a:b].strip() for a, b in zip(starts, starts[1:] + [len(head)])]
    # "operator bool", "operator new": the word after "operator" is part of the name.
    name_start = starts[-1]
    for k in range(len(words) - 1, -1, -1):
        if words[k] == "operator" or words[k].endswith("::operator"):
            name_start = starts[k]
            break
    return name_start, head_end


def function_name(demangled):
    """The name a target's "functions" list matches: no return type, parameters, qualifiers or ABI tags."""
    start, end = _split(demangled)
    return re.sub(r"\[abi:[^\]]*\]", "", demangled.strip()[start:end])


def display_name(demangled):
    """The demangled name without its return type."""
    start, _ = _split(demangled)
    return demangled.strip()[start:]


# ---- function extents ----

def load_extents(paths):
    """{relative path: [Function]} from the union of extents files, sorted by start line."""
    merged = {}
    for path in paths:
        with open(path, encoding="utf8") as f:
            try:
                data = json.load(f)
            except ValueError as e:
                raise InputError("%s: %s" % (path, e))
        if not isinstance(data, dict) or set(data) != {"version", "files"} or data["version"] != 1 \
                or not isinstance(data["files"], dict):
            raise InputError("%s: not a function extents file (version 1)" % path)
        for source, functions in data["files"].items():
            if not isinstance(functions, list):
                raise InputError("%s: %s: not a list" % (path, source))
            for fn in functions:
                if not isinstance(fn, dict) or set(fn) != {"demangled_name", "start_line", "end_line"} \
                        or not isinstance(fn["demangled_name"], str) \
                        or not all(isinstance(fn[k], int) and not isinstance(fn[k], bool) and fn[k] > 0
                                   for k in ("start_line", "end_line")) \
                        or fn["end_line"] < fn["start_line"]:
                    raise InputError("%s: %s: malformed function %r" % (path, source, fn))
                merged.setdefault(source, set()).add(Function(fn["demangled_name"], fn["start_line"],
                                                              fn["end_line"]))
    return {source: sorted(fns, key=lambda f: (f.start, -f.end, f.demangled)) for source, fns in merged.items()}


# ---- target file ----

class Targets:
    def __init__(self, tolerance, overall, tiers, entries):
        self.tolerance, self.overall, self.tiers, self.entries = tolerance, overall, tiers, entries


class Entry:
    def __init__(self, group, file, functions, tier, target, met, recorded):
        self.group, self.file, self.functions = group, file, functions
        self.tier, self.target, self.met, self.recorded = tier, target, met, recorded


def _is_percent(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 100


def _metrics(value, where):
    if not isinstance(value, dict) or not value:
        raise InputError("%s: expected a non-empty object of metrics" % where)
    for k, v in value.items():
        if k not in METRICS:
            raise InputError("%s: unknown metric %r (known: %s)" % (where, k, ", ".join(METRICS)))
        if not _is_percent(v):
            raise InputError("%s: %s must be a percentage (0 to 100), not %r" % (where, k, v))
    return {k: float(v) for k, v in value.items()}


def load_targets(path):
    with open(path, encoding="utf8") as f:
        try:
            data = json.load(f)
        except ValueError as e:
            raise InputError("%s: %s" % (path, e))
    if not isinstance(data, dict) or set(data) != {"tolerance", "overall", "tiers", "files"}:
        raise InputError("%s: expected exactly the keys tolerance, overall, tiers, files" % path)
    tolerance = data["tolerance"]
    if not _is_percent(tolerance):
        raise InputError("%s: tolerance must be a percentage, not %r" % (path, tolerance))
    overall = _metrics(data["overall"], path + ": overall")
    if not isinstance(data["tiers"], dict):
        raise InputError("%s: tiers must be an object" % path)
    tiers = {name: _metrics(value, "%s: tier %s" % (path, name)) for name, value in data["tiers"].items()}
    if not isinstance(data["files"], list):
        raise InputError("%s: files must be a list" % path)
    entries, seen = [], set()
    for n, e in enumerate(data["files"]):
        where = "%s: files[%d]" % (path, n)
        if not isinstance(e, dict):
            raise InputError("%s: expected an object" % where)
        unknown = set(e) - {"group", "file", "functions", "target", "met", "recorded"}
        if unknown:
            raise InputError("%s: unknown keys %s" % (where, ", ".join(sorted(unknown))))
        for k in ("group", "file"):
            if not isinstance(e.get(k), str) or not e[k]:
                raise InputError("%s: %s must be a non-empty string" % (where, k))
        functions = e.get("functions")
        if functions is not None:
            if not isinstance(functions, list) or not functions \
                    or not all(isinstance(f, str) and f for f in functions):
                raise InputError("%s: functions must be a non-empty list of names" % where)
        if ("target" in e) == ("recorded" in e):
            raise InputError("%s: needs either target and met, or recorded" % where)
        tier = target = met = recorded = None
        if "target" in e:
            if not isinstance(e.get("met"), bool):
                raise InputError("%s: an entry with a target needs met: true or false" % where)
            met = e["met"]
            if isinstance(e["target"], str):
                tier = e["target"]
                if tier not in tiers:
                    raise InputError("%s: unknown tier %r" % (where, tier))
                target = tiers[tier]
            else:
                target = _metrics(e["target"], where + ": target")
        else:
            if "met" in e:
                raise InputError("%s: met belongs to an entry with a target" % where)
            recorded = _metrics(e["recorded"], where + ": recorded")
        key = (e["file"], tuple(functions or ()), "target" if target else "recorded")
        if key in seen:
            raise InputError("%s: a second %s entry for %s" % (where, key[2], e["file"]))
        seen.add(key)
        entries.append(Entry(e["group"], e["file"], functions, tier, target, met, recorded))
    return Targets(float(tolerance), overall, tiers, entries)


# ---- the check ----

Row = collections.namedtuple("Row", "group file functions unit all target_text status failed")
OverallRow = collections.namedtuple("OverallRow", "metric hit found recorded status")
Report = collections.namedtuple("Report", "rows overall overall_stats failures notices")
FunctionRow = collections.namedtuple("FunctionRow", "name start end unit all")


def percent(hit, found):
    return 100.0 * hit / found if found else None


def metric_value(metric, unit, total):
    s = unit if metric.startswith("unit_") else total
    if metric.endswith("_lines"):
        return s.lines_hit, s.lines_found
    return s.branches_hit, s.branches_found


def _file_coverage(source, unit, total):
    if source not in unit:
        raise InputError("%s is not in the unit tracefile" % source)
    if source not in total:
        raise InputError("%s is not in the combined tracefile" % source)
    return unit[source], total[source]


def function_ranges(entry, extents):
    if entry.file not in extents:
        raise InputError("no function extents for %s (pass the extents files with --functions)" % entry.file)
    ranges = []
    for name in entry.functions:
        matched = [(f.start, f.end) for f in extents[entry.file] if function_name(f.demangled) == name]
        if not matched:
            raise InputError("%s: no function named %r in the function extents" % (entry.file, name))
        ranges += matched
    return ranges


def _fmt(value):
    return "%.1f" % value


def check(targets, unit, total, extents):
    rows, failures, notices = [], [], []
    tol = targets.tolerance
    for e in targets.entries:
        ucov, acov = _file_coverage(e.file, unit, total)
        ranges = function_ranges(e, extents) if e.functions else None
        us, as_ = stats(ucov, ranges), stats(acov, ranges)
        label = e.file + (" [%s]" % ", ".join(e.functions) if e.functions else "")
        failed = False
        if e.target is not None:
            below = []
            for metric, want in e.target.items():
                value = percent(*metric_value(metric, us, as_))
                if value is not None and value < want - EPS:
                    below.append("%s %s < %s" % (METRIC_TEXT[metric], _fmt(value), _fmt(want)))
            target_text = e.tier or ", ".join("%s >= %s" % (METRIC_TEXT[m], _fmt(v)) for m, v in e.target.items())
            if e.met and below:
                status, failed = "FAIL: below target", True
                failures.append("%s: recorded as met, but %s" % (label, "; ".join(below)))
            elif e.met:
                status = "met"
            elif below:
                status = "below target"
            else:
                status = "record as met"
                notices.append("%s: meets its target (%s); record as met" % (label, target_text))
        else:
            fell, rose = [], []
            for metric, rec in e.recorded.items():
                value = percent(*metric_value(metric, us, as_))
                if value is None:
                    continue
                if value < rec - tol - EPS:
                    fell.append("%s %s, recorded %s" % (METRIC_TEXT[metric], _fmt(value), _fmt(rec)))
                elif value >= rec + tol - EPS:
                    rose.append("%s %s, recorded %s" % (METRIC_TEXT[metric], _fmt(value), _fmt(rec)))
            target_text = ", ".join("%s %s recorded" % (METRIC_TEXT[m], _fmt(v)) for m, v in e.recorded.items())
            if fell:
                status, failed = "FAIL: fell", True
                failures.append("%s: fell more than %s points: %s" % (label, _fmt(tol), "; ".join(fell)))
            elif rose:
                status = "record the new value"
                notices.append("%s: rose: %s; record the new value" % (label, "; ".join(rose)))
            else:
                status = "ok"
        rows.append(Row(e.group, e.file, e.functions, us, as_, target_text, status, failed))

    # Overall: every file under src/ of the tracefiles.
    us, as_ = src_stats(unit), src_stats(total)
    overall_stats = {m: metric_value(m, us, as_) for m in METRICS}
    overall = []
    for metric, rec in targets.overall.items():
        hit, found = overall_stats[metric]
        value = percent(hit, found)
        status = "ok"
        if value is None:
            pass
        elif value < rec - tol - EPS:
            status = "FAIL: fell"
            failures.append("overall %s of src/: %s, more than %s points below the recorded %s"
                            % (METRIC_TEXT[metric], _fmt(value), _fmt(tol), _fmt(rec)))
        elif value >= rec + tol - EPS:
            status = "record the new value"
            notices.append("overall %s of src/: %s, recorded %s; record the new value"
                           % (METRIC_TEXT[metric], _fmt(value), _fmt(rec)))
        overall.append(OverallRow(metric, hit, found, rec, status))
    return Report(rows, overall, overall_stats, failures, notices)


def src_stats(files):
    """Stats summed over every file under src/."""
    parts = [stats(cov) for source, cov in files.items() if source.startswith("src/")]
    return Stats(*(sum(p[i] for p in parts) for i in range(4)))


def per_function(source, unit, total, extents):
    ucov, acov = _file_coverage(source, unit, total)
    if source not in extents:
        raise InputError("no function extents for %s (pass the extents files with --functions)" % source)
    return [FunctionRow(display_name(f.demangled), f.start, f.end, stats(ucov, [(f.start, f.end)]),
                        stats(acov, [(f.start, f.end)])) for f in extents[source]]


# ---- output ----

def cell(hit, found):
    if not found:
        return "- (0/0)"
    return "%s %% (%d/%d)" % (_fmt(percent(hit, found)), hit, found)


def stat_cells(unit, total):
    return [cell(unit.lines_hit, unit.lines_found), cell(unit.branches_hit, unit.branches_found),
            cell(total.lines_hit, total.lines_found), cell(total.branches_hit, total.branches_found)]


STAT_HEADER = ["unit lines", "unit branches", "all lines", "all branches"]


def text_table(header, rows):
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    out = []
    for r in [header, ["-" * w for w in widths]] + rows:
        out.append("  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip())
    return "\n".join(out)


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(out)


def check_tables(report):
    header = ["group", "file"] + STAT_HEADER + ["target", "status"]
    rows_text, rows_md = [], []
    for r in report.rows:
        stats_cells = stat_cells(r.unit, r.all)
        name = r.file + (" [%s]" % ", ".join(r.functions) if r.functions else "")
        rows_text.append([r.group, name] + stats_cells + [r.target_text, r.status])
        md_name = "`%s`" % r.file + (" (%s)" % ", ".join("`%s`" % f for f in r.functions) if r.functions else "")
        md_status = "**%s**" % r.status if r.failed else r.status
        rows_md.append([r.group, md_name] + stats_cells + [r.target_text, md_status])
    overall_lines = ["overall %s of src/: %s, recorded %s: %s" % (METRIC_TEXT[o.metric], cell(o.hit, o.found),
                                                                  _fmt(o.recorded), o.status)
                     for o in report.overall]
    text = [text_table(header, rows_text), ""] + overall_lines
    md = ["### Coverage", "", md_table(header, rows_md), ""] + ["- " + line for line in overall_lines]
    if report.failures:
        text += [""] + ["FAIL  " + f for f in report.failures]
        md += ["", "**Failed:**", ""] + ["- " + f for f in report.failures]
    if report.notices:
        text += [""] + ["NOTE  " + n for n in report.notices]
        md += ["", "To record:", ""] + ["- " + n for n in report.notices]
    verdict = "coverage check: %d failure(s), %d to record" % (len(report.failures), len(report.notices))
    return "\n".join(text + ["", verdict]), "\n".join(md + ["", verdict])


def function_tables(source, rows):
    header = ["lines"] + STAT_HEADER + ["function"]
    body = [["%d-%d" % (r.start, r.end)] + stat_cells(r.unit, r.all) + [r.name] for r in rows]
    md_body = [b[:-1] + ["`%s`" % b[-1]] for b in body]
    title = "Coverage per function of %s (lines inside each function's extent)" % source
    return (title + "\n\n" + text_table(header, body),
            "### " + title + "\n\n" + md_table(header, md_body))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], epilog="See the top of this script.")
    parser.add_argument("--unit", required=True, metavar="FILE", help="tracefile of the unit tests")
    parser.add_argument("--all", required=True, nargs="+", metavar="FILE",
                        help="tracefile(s) of the unit and functional tests together (summed)")
    parser.add_argument("--functions", nargs="+", default=[], metavar="FILE", help="function extents files")
    parser.add_argument("--root", default=REPO_ROOT, help="source paths are relative to this (default: %(default)s)")
    parser.add_argument("--targets", default=DEFAULT_TARGETS, metavar="FILE", help="default: %(default)s")
    parser.add_argument("--markdown", metavar="FILE", help="append the table as Markdown to FILE")
    parser.add_argument("--per-function", metavar="SOURCE", help="coverage per function of SOURCE instead")
    args = parser.parse_args(argv)
    try:
        unit = read_tracefiles([args.unit], args.root)
        total = read_tracefiles(args.all, args.root)
        extents = load_extents(args.functions)
        if args.per_function:
            source = relative_path(args.per_function, args.root) if os.path.isabs(args.per_function) \
                else os.path.normpath(args.per_function)
            text, md = function_tables(source, per_function(source, unit, total, extents))
            failed = False
        else:
            report = check(load_targets(args.targets), unit, total, extents)
            text, md = check_tables(report)
            failed = bool(report.failures)
    except (InputError, OSError) as e:
        print("coverage-check: error: %s" % e, file=sys.stderr)
        return 2
    print(text)
    if args.markdown:
        with open(args.markdown, "a", encoding="utf8") as f:
            f.write("\n" + md + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
