#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Coverage gate (task P0-04).

Reads an lcov tracefile (normally the merged mainnet + lowdiff report of
`build.sh --coverage-report`) and a TOML config
(contrib/testing/coverage-gates.toml), removes the excluded code from the
denominators and checks every gate's lines / functions / branches against
its minimum.

Exit codes: 0 all checks passed, 1 a check is below its minimum, 2 usage,
config or data error (including an exclusion that no longer finds its
target).

See contrib/testing/README.md, section "Coverage gate".
"""

import argparse
import math
import os
import re
import subprocess
import sys

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

METRICS = ("lines", "functions", "branches")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class GateError(Exception):
    """Config or data problem: exit code 2."""


# ------------------------------------------------------------- tracefile

class FileData:
    """Coverage data of one source file (one SF record)."""

    def __init__(self, path):
        self.path = path
        self.lines = {}      # line -> hit count
        self.branches = {}   # line -> {(block, branch): taken or None}
        self.functions = {}  # mangled name -> [start, end or None, hit count]


def parse_tracefile(path):
    """Parse an lcov 2.0 tracefile into {SF path: FileData}."""
    files = {}
    cur = None
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError as e:
        raise GateError("cannot read tracefile: %s" % e)
    with fh:
        for lineno, raw in enumerate(fh, 1):
            rec = raw.rstrip("\n")
            try:
                if rec.startswith("SF:"):
                    cur = files.setdefault(rec[3:], FileData(rec[3:]))
                elif rec == "end_of_record":
                    cur = None
                elif cur is None:
                    continue
                elif rec.startswith("DA:"):
                    parts = rec[3:].split(",")
                    ln = int(parts[0])
                    cur.lines[ln] = cur.lines.get(ln, 0) + int(parts[1])
                elif rec.startswith("FN:"):
                    start, rest = rec[3:].split(",", 1)
                    m = re.match(r"(\d+),(.*)$", rest)
                    end, name = (int(m.group(1)), m.group(2)) if m else (None, rest)
                    fn = cur.functions.setdefault(name, [int(start), end, 0])
                    fn[0], fn[1] = int(start), end
                elif rec.startswith("FNDA:"):
                    count, name = rec[5:].split(",", 1)
                    fn = cur.functions.setdefault(name, [None, None, 0])
                    fn[2] += int(count)
                elif rec.startswith("BRDA:"):
                    parts = rec[5:].split(",")
                    ln, block, taken = int(parts[0]), parts[1], parts[-1]
                    branch = ",".join(parts[2:-1])
                    taken = None if taken == "-" else int(taken)
                    br = cur.branches.setdefault(ln, {})
                    old = br.get((block, branch))
                    if old is None:
                        br[(block, branch)] = taken
                    elif taken is not None:
                        br[(block, branch)] = old + taken
            except (ValueError, IndexError):
                raise GateError("%s:%d: cannot parse record %r" % (path, lineno, rec))
    for fd in files.values():
        for name, fn in fd.functions.items():
            if fn[0] is None:
                raise GateError("%s: FNDA without FN for %s" % (fd.path, name))
    return files


def demangle(names):
    """Demangle C++ names with one c++filt call; returns {mangled: demangled}."""
    names = sorted(set(names))
    if not names:
        return {}
    try:
        out = subprocess.run(["c++filt"], input="\n".join(names) + "\n",
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise GateError("c++filt failed (binutils needed): %s" % e)
    result = out.split("\n")[:len(names)]
    if len(result) != len(names):
        raise GateError("c++filt returned %d names for %d" % (len(result), len(names)))
    return {m: " ".join(d.split()) for m, d in zip(names, result)}


# ------------------------------------------------------------ source text

def strip_code(text):
    """Return text with comments and string/char literals replaced by
    spaces (newlines kept), so that brackets and ';' can be counted."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(" " * (j - i))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def statement_extent(src_lines, start):
    """Lines (1-based, inclusive) of the statement that begins on line
    `start`: up to the ';' that ends it, or the '}' that closes its first
    '{' outside parentheses. A following 'else' is an error, because it
    would belong to the excluded statement."""
    code = strip_code("\n".join(src_lines[start - 1:]))
    depth = 0
    end = None
    i = 0
    while i < len(code):
        c = code[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0 and c == ";":
            end = i
            break
        elif depth == 0 and c == "{":
            braces = 0
            for j in range(i, len(code)):
                if code[j] == "{":
                    braces += 1
                elif code[j] == "}":
                    braces -= 1
                    if braces == 0:
                        end = j
                        break
            break
        i += 1
    if end is None:
        raise GateError("line %d: end of statement not found" % start)
    if re.match(r"\s*else\b", code[end + 1:]):
        raise GateError("line %d: the excluded statement has an 'else' arm; "
                        "exclude the arms separately" % start)
    return start, start + code.count("\n", 0, end)


# ---------------------------------------------------------------- config

def load_config(path):
    if tomllib is None:
        raise GateError("Python >= 3.11 is needed (tomllib)")
    try:
        with open(path, "rb") as fh:
            cfg = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise GateError("cannot read config %s: %s" % (path, e))
    settings = cfg.get("settings", {})
    if not isinstance(settings.get("exception_branches", False), bool):
        raise GateError("settings.exception_branches must be true or false")
    for i, ex in enumerate(cfg.get("exclude", [])):
        where = "exclude #%d (%s)" % (i + 1, ex.get("path", "?"))
        kind = ex.get("kind")
        allowed = {"kind", "path", "reason"} | {
            "file": set(),
            "function": {"functions"},
            "lines": {"match", "extent", "all"},
            "branches": {"match", "outcomes", "branches_on_line", "verified"},
        }.get(kind, set())
        if kind not in ("file", "function", "lines", "branches"):
            raise GateError("%s: kind must be file, function, lines or branches" % where)
        if not isinstance(ex.get("path"), str) or not ex.get("reason"):
            raise GateError("%s: path and reason are required" % where)
        unknown = set(ex) - allowed
        if unknown:
            raise GateError("%s: unknown keys %s" % (where, sorted(unknown)))
        if kind == "function" and not ex.get("functions"):
            raise GateError("%s: functions is required" % where)
        if kind in ("lines", "branches"):
            if not isinstance(ex.get("match"), str) or not ex["match"]:
                raise GateError("%s: match is required" % where)
            try:
                re.compile(ex["match"])
            except re.error as e:
                raise GateError("%s: match %r is not a valid regex: %s" % (where, ex["match"], e))
        if kind == "lines" and ex.get("extent", "line") not in ("line", "block"):
            raise GateError("%s: extent must be line or block" % where)
        if kind == "branches":
            outcomes = ex.get("outcomes")
            if (not isinstance(outcomes, list) or not outcomes or
                    not all(isinstance(o, str) and re.fullmatch(r"e?\d+,\d+", o) for o in outcomes)):
                raise GateError('%s: outcomes must be a list like ["0,1"] (block,branch)' % where)
            if not (isinstance(ex.get("branches_on_line"), int) and ex["branches_on_line"] > 0):
                raise GateError("%s: branches_on_line must be a positive integer" % where)
            if not isinstance(ex.get("verified", True), bool):
                raise GateError("%s: verified must be true or false" % where)
    names = set()
    gates = cfg.get("gate", [])
    if not gates:
        raise GateError("config has no [[gate]]")
    for gate in gates:
        name = gate.get("name")
        if not name or name in names:
            raise GateError("every gate needs a unique name (%r)" % name)
        names.add(name)
        unknown = set(gate) - {"name", "paths", "select_functions", "min"}
        if unknown:
            raise GateError("gate %s: unknown keys %s" % (name, sorted(unknown)))
        mins = gate.get("min")
        if not isinstance(mins, dict) or not mins or set(mins) - set(METRICS):
            raise GateError("gate %s: min must set some of %s" % (name, ", ".join(METRICS)))
        for metric, value in mins.items():
            if not isinstance(value, (int, float)) or not 0 <= value <= 100:
                raise GateError("gate %s: min.%s must be a number 0-100" % (name, metric))
        if gate.get("select_functions") and len(gate.get("paths", [])) != 1:
            raise GateError("gate %s: select_functions needs exactly one path" % name)
    return cfg


# ------------------------------------------------------------ evaluation

class Gate:
    def __init__(self, files, config, source_root):
        self.files = files
        self.config = config
        self.source_root = source_root
        self.exception_branches = config.get("settings", {}).get("exception_branches", False)
        names = [n for fd in files.values() for n in fd.functions]
        self.demangled = demangle(names)
        self.sources = {}
        self.log = []

    # -- helpers
    def find_file(self, path):
        hits = [sf for sf in self.files
                if sf == path or sf.endswith("/" + path)]
        if len(hits) != 1:
            raise GateError("%s: %s in the tracefile" % (
                path, "not found" if not hits else "ambiguous (%s)" % ", ".join(hits)))
        return self.files[hits[0]]

    def source(self, path):
        if path not in self.sources:
            full = os.path.join(self.source_root, path)
            try:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    self.sources[path] = fh.read().split("\n")
            except OSError as e:
                raise GateError("cannot read source %s: %s" % (full, e))
        return self.sources[path]

    def anchors(self, path, pattern, allow_many):
        regex = re.compile(pattern)
        hits = [i + 1 for i, text in enumerate(self.source(path)) if regex.search(text)]
        if not hits or (len(hits) > 1 and not allow_many):
            raise GateError("%s: match %r found %d lines%s" % (
                path, pattern, len(hits), "" if allow_many else " (expected exactly 1)"))
        return hits

    def match_functions(self, fd, entries, where):
        """{mangled: fn} of the functions in fd named by entries."""
        result = {}
        for entry in entries:
            want = " ".join(entry.split())
            found = False
            for mangled, fn in fd.functions.items():
                # ABI tags ("ToString[abi:cxx11](int)") are not part of
                # the names in the config.
                dem = re.sub(r"\[abi:\w+\]", "", self.demangled.get(mangled, mangled))
                base = dem.split("(", 1)[0]
                if (dem == want) if "(" in want else (base == want):
                    if fn[1] is None:
                        raise GateError("%s: %s has no end line (lcov >= 2.0 needed)" % (where, dem))
                    result[mangled] = fn
                    found = True
            if not found:
                raise GateError("%s: function %r not found (stale exclusion or gate?)" % (where, entry))
        return result

    def is_branch_counted(self, key):
        return self.exception_branches or not key[0].startswith("e")

    # -- exclusions
    def remove_lines(self, fd, lines):
        """Remove line and branch data on the given lines, and functions
        that lie entirely inside them. Returns (lines, branches, functions)
        removed."""
        nl = sum(1 for ln in lines if fd.lines.pop(ln, None) is not None)
        nb = 0
        for ln in lines:
            br = fd.branches.pop(ln, {})
            nb += sum(1 for k in br if self.is_branch_counted(k))
        nf = 0
        for mangled in [m for m, fn in fd.functions.items()
                        if fn[0] in lines and fn[1] is not None and fn[1] in lines]:
            del fd.functions[mangled]
            nf += 1
        return nl, nb, nf

    def apply_exclusions(self):
        for ex in self.config.get("exclude", []):
            kind, path = ex["kind"], ex["path"]
            where = "exclude %s %s" % (kind, path)
            if kind == "file":
                fd = self.find_file(path)
                nb = sum(1 for br in fd.branches.values() for k in br if self.is_branch_counted(k))
                self.note(where, "whole file", (len(fd.lines), nb, len(fd.functions)))
                del self.files[fd.path]
            elif kind == "function":
                fd = self.find_file(path)
                for mangled, fn in sorted(self.match_functions(fd, ex["functions"], where).items(),
                                          key=lambda kv: kv[1][0]):
                    if mangled not in fd.functions:
                        continue  # already removed with another variant
                    lines = set(range(fn[0], fn[1] + 1))
                    removed = self.remove_lines(fd, lines)
                    self.note(where, "%s (%d-%d)" % (self.demangled.get(mangled, mangled), fn[0], fn[1]),
                              removed)
            elif kind == "lines":
                fd = self.find_file(path)
                src = self.source(path)
                for anchor in self.anchors(path, ex["match"], ex.get("all", False)):
                    if ex.get("extent", "line") == "block":
                        try:
                            first, last = statement_extent(src, anchor)
                        except GateError as e:
                            raise GateError("%s: %s" % (where, e))
                    else:
                        first, last = anchor, anchor
                    removed = self.remove_lines(fd, set(range(first, last + 1)))
                    if removed[0] == 0:
                        raise GateError("%s: lines %d-%d have no line data (stale exclusion?)"
                                        % (where, first, last))
                    self.note(where, "lines %d-%d" % (first, last), removed)
            elif kind == "branches":
                # The outcomes are named by their (block, branch) ids. The
                # number of (non-exception) outcomes on the line guards
                # against ids that changed with the code or the compiler.
                fd = self.find_file(path)
                anchor = self.anchors(path, ex["match"], False)[0]
                br = fd.branches.get(anchor, {})
                normal = [k for k in br if not k[0].startswith("e")]
                if len(normal) != ex["branches_on_line"]:
                    raise GateError("%s: line %d has %d branch outcomes, config expects %d "
                                    "(stale exclusion? check the outcome ids)"
                                    % (where, anchor, len(normal), ex["branches_on_line"]))
                # verified = false: the ids could not be checked on data
                # because no test reaches the line. While nothing on the
                # line ran, which untaken outcome is removed does not change
                # the numbers; once something runs, the ids must be checked.
                if not ex.get("verified", True) and any(br[k] for k in normal):
                    raise GateError("%s: line %d now runs; check the outcome ids on the data "
                                    "and set verified = true" % (where, anchor))
                hits = 0
                for outcome in ex["outcomes"]:
                    key = tuple(outcome.split(","))
                    if key not in br:
                        raise GateError("%s: line %d has no branch outcome %s" % (where, anchor, outcome))
                    hits += 1 if br.pop(key) else 0
                self.note(where, "line %d outcome %s (%d ran)" % (anchor, " ".join(ex["outcomes"]), hits),
                          (0, len(ex["outcomes"]), 0))

    def note(self, where, what, removed):
        self.log.append((where, what, removed))

    # -- gates
    def select(self, gate):
        """Lists of (hit) for lines, functions, branches of a gate."""
        paths = gate.get("paths")
        fds = [self.find_file(p) for p in paths] if paths else list(self.files.values())
        lines, funcs, branches = [], [], []
        for fd in fds:
            sel = gate.get("select_functions")
            if sel:
                chosen = self.match_functions(fd, sel, "gate %s" % gate["name"])
                ranges = set()
                for fn in chosen.values():
                    ranges.update(range(fn[0], fn[1] + 1))
                fns = chosen.items()
            else:
                ranges = None
                fns = fd.functions.items()
            # Constructor/destructor variants (C1/C2, D0/D1/D2) share the
            # demangled name and start line: count them once.
            seen = {}
            for mangled, fn in fns:
                key = (self.demangled.get(mangled, mangled), fn[0])
                seen[key] = seen.get(key, False) or fn[2] > 0
            funcs.extend(seen.values())
            for ln, count in fd.lines.items():
                if ranges is None or ln in ranges:
                    lines.append(count > 0)
            for ln, br in fd.branches.items():
                if ranges is None or ln in ranges:
                    branches.extend(bool(t) for k, t in br.items() if self.is_branch_counted(k))
        return {"lines": lines, "functions": funcs, "branches": branches}

    def evaluate(self):
        results = []
        for gate in self.config["gate"]:
            data = self.select(gate)
            for metric in METRICS:
                if metric not in gate["min"]:
                    continue
                values = data[metric]
                if not values:
                    raise GateError("gate %s: no %s selected (stale config?)" % (gate["name"], metric))
                hit, total = sum(values), len(values)
                minimum = gate["min"][metric]
                results.append({
                    "gate": gate["name"], "metric": metric, "hit": hit, "total": total,
                    "pct": 100.0 * hit / total, "min": minimum,
                    "ok": 100 * hit >= minimum * total,
                })
        return results


def suggest(pct):
    """Ratchet rule: 0.5 to 1.5 points below the measured value; 100 stays."""
    if pct >= 100:
        return 100
    return max(0, math.floor(pct - 0.5))


def report(results, gate, args, out):
    if args.verbose:
        print("exclusions:", file=out)
        for where, what, (nl, nb, nf) in gate.log:
            print("  %-45s %-55s -%d lines -%d branches -%d functions"
                  % (where, what, nl, nb, nf), file=out)
    totals = [sum(r[i] for _, _, r in gate.log) for i in range(3)]
    print("excluded: %d lines, %d branches, %d functions (%d exclusion targets)%s"
          % (totals[0], totals[1], totals[2], len(gate.log),
             "" if gate.exception_branches else "; exception branches not counted"), file=out)
    print("%-28s %-10s %15s %7s %8s  %s" % ("gate", "metric", "covered", "%", "minimum", "result"), file=out)
    for r in results:
        line = "%-28s %-10s %15s %7.2f %8s  %s" % (
            r["gate"], r["metric"], "%d/%d" % (r["hit"], r["total"]), r["pct"],
            ("%g" % r["min"]), "ok" if r["ok"] else "FAIL")
        if args.suggest:
            s = suggest(r["pct"])
            line += "   suggest %d%s" % (s, "  <- raise" if s > r["min"] else "")
        print(line, file=out)
    failed = [r for r in results if not r["ok"]]
    if failed:
        print("coverage gate: %d of %d checks FAILED:" % (len(failed), len(results)), file=out)
        for r in failed:
            print("  %s %s %.2f%% < minimum %g%%" % (r["gate"], r["metric"], r["pct"], r["min"]), file=out)
    else:
        print("coverage gate: all %d checks passed" % len(results), file=out)
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tracefile", help="lcov tracefile, e.g. coverage-report/merged.info")
    parser.add_argument("--config", default=os.path.join(SCRIPT_DIR, "coverage-gates.toml"),
                        help="gate config (default: %(default)s)")
    parser.add_argument("--source-root", default=os.path.normpath(os.path.join(SCRIPT_DIR, "..", "..")),
                        help="checkout the tracefile was made from; config paths are relative "
                             "to it (default: %(default)s)")
    parser.add_argument("--verbose", action="store_true", help="list every exclusion and its effect")
    parser.add_argument("--suggest", action="store_true",
                        help="also print the minimum the ratchet rule gives for this data")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        files = parse_tracefile(args.tracefile)
        if not files:
            raise GateError("%s has no SF records" % args.tracefile)
        gate = Gate(files, config, args.source_root)
        gate.apply_exclusions()
        results = gate.evaluate()
    except GateError as e:
        print("coverage gate: error: %s" % e, file=sys.stderr)
        return 2
    return report(results, gate, args, sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
