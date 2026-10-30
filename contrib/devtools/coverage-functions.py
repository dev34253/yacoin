#!/usr/bin/env python3
"""Writes the extents (first and last line) of every function of a coverage build.

Usage: coverage-functions.py --gcov CMD --dir DIR --root ROOT --out FILE [--jobs N]

Runs "CMD -j -t" (gcov's JSON format on stdout) on every .gcno file under DIR,
in parallel, and writes the union of the functions it reports for the files
under ROOT/src/ to FILE: {"version": 1, "files": {"src/x.cpp": [{"demangled_name":
..., "start_line": ..., "end_line": ...}, ...]}}. Used by "make cov-unit" and
"make cov-functional"; coverage-check.py reads the result.

Source paths in the .gcno files are relative to the compile directory, which
gcov reports as current_working_directory; without it they are resolved
against DIR (the build's src/ directory), as geninfo's -b does. CMD is split
on spaces. gcov is given a link to each .gcno file in a directory of its own,
so it never reads the .gcda files (the extents come from the .gcno files
alone); it only warns about the missing counters. A gcov failure fails the
script and writes nothing.
"""

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile


class GcovError(Exception):
    pass


def extents_from_gcov(data, build_dir, root):
    """{path relative to root: {(demangled name, start line, end line)}} for files under root/src/."""
    try:
        files = data["files"]
        base = data.get("current_working_directory") or build_dir
        result = {}
        for f in files:
            path = os.path.normpath(os.path.join(base, f["file"]))
            rel = os.path.relpath(path, root)
            functions = [(fn["demangled_name"], int(fn["start_line"]), int(fn["end_line"])) for fn in f["functions"]]
            if rel.startswith("src" + os.sep):
                result.setdefault(rel, set()).update(functions)
        return result
    except (KeyError, TypeError, ValueError) as e:
        raise GcovError("unexpected gcov JSON output (%s: %s)" % (type(e).__name__, e))


def run_gcov(gcov, gcno, build_dir, root):
    with tempfile.TemporaryDirectory(prefix="coverage-functions.") as tmp:
        link = os.path.join(tmp, "notes.gcno")
        os.symlink(os.path.abspath(gcno), link)
        result = subprocess.run(gcov + ["-j", "-t", link], cwd=tmp, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode != 0:
        raise GcovError("%s: gcov failed (exit status %d): %s" % (gcno, result.returncode, result.stderr.strip()))
    try:
        data = json.loads(result.stdout)
    except ValueError as e:
        raise GcovError("%s: gcov printed no JSON (%s)" % (gcno, e))
    try:
        return extents_from_gcov(data, build_dir, root)
    except GcovError as e:
        raise GcovError("%s: %s" % (gcno, e))


def collect(gcov, gcno_files, build_dir, root, jobs):
    merged = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for part in pool.map(lambda g: run_gcov(gcov, g, build_dir, root), gcno_files):
            for path, functions in part.items():
                merged.setdefault(path, set()).update(functions)
    return merged


def to_json(merged):
    return {"version": 1, "files": {
        path: [{"demangled_name": d, "start_line": s, "end_line": e}
               for d, s, e in sorted(functions, key=lambda f: (f[1], -f[2], f[0]))]
        for path, functions in sorted(merged.items())}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--gcov", required=True, help="gcov command, split on spaces")
    parser.add_argument("--dir", required=True, help="the build's src/ directory")
    parser.add_argument("--root", required=True, help="the source tree")
    parser.add_argument("--out", required=True)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be a positive integer")
    build_dir, root = os.path.abspath(args.dir), os.path.abspath(args.root)
    gcno_files = sorted(os.path.join(d, n) for d, _, names in os.walk(build_dir) for n in names
                        if n.endswith(".gcno"))
    if not gcno_files:
        print("coverage-functions: no .gcno files under %s; is this an --enable-lcov build?" % build_dir,
              file=sys.stderr)
        return 1
    try:
        merged = collect(args.gcov.split(), gcno_files, build_dir, root, args.jobs)
    except (GcovError, OSError) as e:
        print("coverage-functions: error: %s" % e, file=sys.stderr)
        return 1
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf8") as f:
        json.dump(to_json(merged), f, separators=(",", ":"))
        f.write("\n")
    os.replace(tmp, args.out)
    print("coverage-functions: %d functions in %d files from %d .gcno files -> %s"
          % (sum(len(v) for v in merged.values()), len(merged), len(gcno_files), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
