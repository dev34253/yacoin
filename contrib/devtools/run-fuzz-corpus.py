#!/usr/bin/env python3
"""Runs every input of a fuzz corpus once through its target.

Usage: run-fuzz-corpus.py [--jobs N] [--timeout SECONDS] [--rss-limit-mb MB]
                          FUZZ_BIN CORPUS_DIR LOG_DIR

FUZZ_BIN is the libFuzzer binary of configure --enable-fuzz
(src/test/fuzz/fuzz); CORPUS_DIR holds one directory of input files per
target (test/fuzz/corpus/<target>/). The targets are those FUZZ_BIN lists
(PRINT_ALL_FUZZ_TARGETS_AND_ABORT). Every target needs a non-empty directory
of regular files, and every directory needs a target; otherwise nothing runs.

FUZZ_BIN gets the input files as arguments, so libFuzzer runs each of them
once and does not fuzz: no input is changed or added. A target passes when
every one of its inputs was run ("Executed <file>" in libFuzzer's output),
every process exited with status 0 and its output has no sanitizer or
libFuzzer report. Each input gets the time and memory limits of --timeout
(default 30 s) and --rss-limit-mb (default 2048), libFuzzer's -timeout and
-rss_limit_mb; a process that does not finish in time is killed. The
sanitizers' runtime options come from the environment.

Writes LOG_DIR/<target>.log per target and LOG_DIR/summary.txt. LOG_DIR is
created if missing. An existing one may hold only summary.txt and the logs
of the targets FUZZ_BIN lists or an earlier summary.txt names; these are
deleted first. Any other entry, and a LOG_DIR that is not a directory, is
refused before anything runs, and nothing in it is deleted.

Exits with status 1 if the listing fails, a target fails or the corpus does
not match the targets, 2 on bad arguments, including a refused LOG_DIR.
Used by the fuzz-corpus mode of the CI images (ci/containers/entrypoint.sh);
see doc/fuzzing.md.
"""

import argparse
import concurrent.futures
import os
import re
import signal
import subprocess
import sys

# Files per process, far below the argument length limit
BATCH_SIZE = 500
# What a sanitizer or libFuzzer prints when it reports
REPORT_PATTERNS = re.compile(r"ERROR: (AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|libFuzzer)"
                             r"|runtime error:|WARNING: (AddressSanitizer|LeakSanitizer)")
TARGET_NAME = re.compile(r"^[a-z0-9_]+$")
# A target's line in summary.txt
SUMMARY_LINE = re.compile(r"^(?:PASS|FAIL) ([a-z0-9_]+)[ :]")
LISTING_TIMEOUT = 60


def positive_int(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number: %r" % text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive: %r" % text)
    return value


def run(args, env, timeout):
    """(exit status or None if killed after timeout seconds, output)"""
    proc = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            universal_newlines=True, errors="replace", start_new_session=True)
    try:
        output, _ = proc.communicate(timeout=timeout)
        return proc.returncode, output
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        output, _ = proc.communicate()
        return None, output


def list_targets(fuzz_bin):
    env = dict(os.environ, PRINT_ALL_FUZZ_TARGETS_AND_ABORT="1")
    env.pop("FUZZ", None)
    proc = subprocess.run([fuzz_bin], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, errors="replace", timeout=LISTING_TIMEOUT)
    if proc.returncode != 0:
        raise RuntimeError("'%s' failed to list its targets (exit status %d):\n%s"
                           % (fuzz_bin, proc.returncode, proc.stderr))
    names = proc.stdout.splitlines()
    if not names:
        raise RuntimeError("'%s' listed no targets" % fuzz_bin)
    for name in names:
        if not TARGET_NAME.match(name):
            raise RuntimeError("'%s' listed '%s', which is not a target name" % (fuzz_bin, name))
    if len(set(names)) != len(names):
        raise RuntimeError("'%s' listed a target twice" % fuzz_bin)
    return sorted(names)


def corpus_inputs(corpus_dir, targets):
    """target -> sorted absolute paths of its inputs; a list of problems"""
    problems = []
    inputs = {}
    entries = sorted(os.listdir(corpus_dir))
    for entry in entries:
        path = os.path.join(corpus_dir, entry)
        if not os.path.isdir(path) or os.path.islink(path):
            problems.append("%s: not a corpus directory" % path)
        elif entry not in targets:
            problems.append("%s: no target named %s" % (path, entry))
    for target in targets:
        path = os.path.join(corpus_dir, target)
        if not os.path.isdir(path):
            problems.append("target %s has no corpus directory %s" % (target, path))
            continue
        files = []
        for name in sorted(os.listdir(path)):
            file_path = os.path.join(path, name)
            if os.path.isfile(file_path) and not os.path.islink(file_path):
                files.append(file_path)
            else:
                problems.append("%s: not a regular file" % file_path)
        if not files:
            problems.append("target %s has an empty corpus directory %s" % (target, path))
        inputs[target] = files
    return inputs, problems


def prepare_log_dir(log_dir, targets):
    """Creates log_dir, or empties one that holds only this script's files:
    summary.txt and the logs of the targets or of those an earlier summary.txt
    names. None, or why log_dir is refused"""
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        return None
    if not os.path.isdir(log_dir) or os.path.islink(log_dir):
        return "%s is not a directory" % log_dir

    def is_file(name):
        path = os.path.join(log_dir, name)
        return os.path.isfile(path) and not os.path.islink(path)

    names = set(targets)
    if is_file("summary.txt"):
        with open(os.path.join(log_dir, "summary.txt"), errors="replace") as f:
            names.update(m.group(1) for m in map(SUMMARY_LINE.match, f) if m)
    own = {"summary.txt"} | {name + ".log" for name in names}
    entries = sorted(os.listdir(log_dir))
    foreign = [e for e in entries if e not in own or not is_file(e)]
    if foreign:
        return "%s holds other files than logs of this script (%s)" % (log_dir, ", ".join(foreign[:5]))
    for entry in entries:
        os.remove(os.path.join(log_dir, entry))
    return None


def replay(fuzz_bin, target, files, args, log_path):
    """None if every input ran without a report, else the reason"""
    env = dict(os.environ, FUZZ=target)
    env.pop("PRINT_ALL_FUZZ_TARGETS_AND_ABORT", None)
    reason = None
    with open(log_path, "w") as log:
        for start in range(0, len(files), BATCH_SIZE):
            batch = files[start:start + BATCH_SIZE]
            command = [fuzz_bin, "-timeout=%d" % args.timeout, "-rss_limit_mb=%d" % args.rss_limit_mb] + batch
            status, output = run(command, env, args.timeout * (len(batch) + 1) + 10)
            log.write(output)
            executed = set(re.findall(r"^Executed (.+) in \d+ ms$", output, re.M))
            if status is None:
                reason = "the process did not finish in time and was killed"
            elif status != 0:
                reason = "exit status %d" % status
            elif REPORT_PATTERNS.search(output):
                reason = "a report in the output"
            elif not executed.issuperset(batch):
                not_run = [f for f in batch if f not in executed]
                reason = "%d inputs not run, first %s" % (len(not_run), not_run[0])
            if reason:
                return reason
    return None


def main():
    parser = argparse.ArgumentParser(description="Runs every input of a fuzz corpus once through its target.")
    parser.add_argument("--jobs", type=positive_int, default=os.cpu_count() or 1, help="targets in parallel")
    parser.add_argument("--timeout", type=positive_int, default=30, help="seconds per input (libFuzzer -timeout)")
    parser.add_argument("--rss-limit-mb", type=positive_int, default=2048,
                        help="memory limit in MB (libFuzzer -rss_limit_mb)")
    parser.add_argument("fuzz_bin")
    parser.add_argument("corpus_dir")
    parser.add_argument("log_dir")
    args = parser.parse_args()
    fuzz_bin = os.path.abspath(args.fuzz_bin)
    corpus_dir = os.path.abspath(args.corpus_dir)
    try:
        targets = list_targets(fuzz_bin)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    refused = prepare_log_dir(args.log_dir, targets)
    if refused:
        print("error: log directory refused: %s" % refused, file=sys.stderr)
        return 2
    if not os.path.isdir(corpus_dir):
        print("error: no corpus directory %s" % corpus_dir, file=sys.stderr)
        return 1
    inputs, problems = corpus_inputs(corpus_dir, targets)
    if problems:
        for problem in problems:
            print("error: %s" % problem, file=sys.stderr)
        return 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {t: pool.submit(replay, fuzz_bin, t, inputs[t], args, os.path.join(args.log_dir, t + ".log"))
                   for t in targets}
        results = {t: futures[t].result() for t in targets}
    lines = []
    for target in targets:
        if results[target] is None:
            lines.append("PASS %s (%d inputs)" % (target, len(inputs[target])))
        else:
            lines.append("FAIL %s: %s (log: %s)" % (target, results[target],
                                                   os.path.join(args.log_dir, target + ".log")))
    with open(os.path.join(args.log_dir, "summary.txt"), "w") as f:
        f.write("".join(line + "\n" for line in lines))
    print("\n".join(lines))
    failed = sum(1 for r in results.values() if r is not None)
    print("%d passed, %d failed (logs: %s)" % (len(targets) - failed, failed, args.log_dir))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
