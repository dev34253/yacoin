#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Replays the block history with a yacoind binary and compares the results.

  replay.py run [options] YACOIND SOURCE_BLOCKS OUT [-- NODE_ARGS...]
  replay.py run --up-to-height H --chain DATADIR [options] YACOIND SOURCE_BLOCKS OUT [-- NODE_ARGS...]
  replay.py run --snapshot SNAPSHOT --chain DATADIR [options] YACOIND SOURCE_BLOCKS OUT [-- NODE_ARGS...]
  replay.py snapshot RUN_OUT SNAPSHOT
  replay.py digest DATADIR OUT
  replay.py compare [--expected-failures FILE] REPORT_A REPORT_B

run      copies the block files of SOURCE_BLOCKS into OUT/datadir/blocks,
         imports them with YACOIND -reindex -replayvalidation=report on a node
         that makes no network connections, stops it and writes the report
         (OUT/report.json, OUT/heights.tsv.gz, OUT/failures.tsv); with
         --up-to-height H, the block files hold only the main-chain blocks
         0 to H of the chain of DATADIR; with --snapshot, the snapshot's
         databases are copied into OUT/datadir and the node gets the
         main-chain blocks above the snapshot with -loadblock instead
snapshot makes a read-only snapshot of the data directory of a complete run
digest   writes the report of the state of a stopped node's data directory
compare  prints "identical" (exit status 0) or where two reports differ
         (exit status 1)

Exit status 2: the command was refused or its input could not be read.
See README.md in this directory.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from replaylib import compare, digest, report, runner, snapshot  # noqa: E402


def log(msg):
    print("replay: %s" % msg, file=sys.stderr, flush=True)


def cmd_run(args, extra):
    try:
        rep = runner.run(args.yacoind, args.source, args.out, port=args.port, rpcport=args.rpcport,
                         dbcache=args.dbcache, stop_at_height=args.stop_at_height, extra=extra, log=log,
                         snapshot=args.snapshot, up_to_height=args.up_to_height, chain=args.chain)
    except runner.RunRefused as e:
        log(str(e))
        return 2
    except runner.Interrupted as e:
        log(str(e))
        return 128 + e.signum
    above = ""
    if rep.get("snapshot") and rep.get("blocks_above_snapshot") is not None:
        above = ", %d blocks above the snapshot at height %d" % (rep["blocks_above_snapshot"], rep["snapshot"]["height"])
    print("%s: tip %s %s, digest %s, %d failures in %d blocks%s" % (
        rep["status"], (rep["tip"] or {}).get("height"), (rep["tip"] or {}).get("hash"), rep["digest"],
        rep["failures"], rep["failure_blocks"], above))
    for reason in rep["incomplete_reasons"]:
        print("incomplete: %s" % reason)
    return 0 if rep["status"] == "complete" else 1


def cmd_snapshot(args, extra):
    try:
        meta = snapshot.make(args.run_out, args.snapshot, log=log)
    except snapshot.SnapshotRefused as e:
        log(str(e))
        return 2
    except snapshot.SnapshotFailed as e:
        log("snapshot: %s" % e)
        return 1
    print("snapshot at height %d %s, digest %s" % (meta["height"], meta["hash"], meta["digest"]))
    return 0


def cmd_digest(args, extra):
    try:
        rep = runner.digest_only(args.datadir, args.out)
    except runner.RunRefused as e:
        log(str(e))
        return 2
    except digest.DigestError as e:
        log("digest: %s" % e)
        return 1
    print("tip %d %s, digest %s" % (rep["tip"]["height"], rep["tip"]["hash"], rep["digest"]))
    return 0


def cmd_compare(args, extra):
    try:
        expected = compare.load_expected(args.expected_failures) if args.expected_failures else set()
        a = report.load(args.report_a)
        b = report.load(args.report_b)
    except (compare.ExpectedFailuresError, report.ReportError) as e:
        log(str(e))
        return 2
    lines = compare.compare(a, b, expected)
    if not lines:
        print("identical")
        return 0
    for line in lines:
        print(line)
    return 1


def parser():
    p = argparse.ArgumentParser(prog="replay.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command")
    sub.required = True

    r = sub.add_parser("run", help="replay the block files of a node with a yacoind binary")
    r.add_argument("yacoind", help="the yacoind binary")
    r.add_argument("source", help="directory with blk00000.dat, blk00001.dat, ... (a node's blocks/ directory)")
    r.add_argument("out", help="output directory; must not exist")
    r.add_argument("--snapshot", metavar="SNAPSHOT",
                   help="start from a copy of the snapshot and import the main-chain blocks above it with -loadblock")
    r.add_argument("--up-to-height", type=int, metavar="H",
                   help="give the node only the main-chain blocks 0 to H")
    r.add_argument("--chain", metavar="DATADIR",
                   help="a stopped node's data directory whose block index gives the main chain "
                        "(with --up-to-height or --snapshot)")
    r.add_argument("--stop-at-height", type=int, metavar="N", help="stop the node at height N (-stopatheight)")
    r.add_argument("--dbcache", type=int, metavar="MB", help="-dbcache of the node (default: the node's)")
    r.add_argument("--port", type=int, default=runner.DEFAULT_PORT,
                   help="-port of the node (default: %(default)s)")
    r.add_argument("--rpcport", type=int, default=runner.DEFAULT_RPCPORT,
                   help="-rpcport of the node (default: %(default)s)")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("snapshot", help="make a snapshot of the data directory of a complete run")
    s.add_argument("run_out", help="output directory of a complete run without --stop-at-height")
    s.add_argument("snapshot", help="snapshot directory; must not exist")
    s.set_defaults(func=cmd_snapshot)

    d = sub.add_parser("digest", help="write the report of a stopped node's data directory")
    d.add_argument("datadir", help="the node's data directory")
    d.add_argument("out", help="output directory; must not exist")
    d.set_defaults(func=cmd_digest)

    c = sub.add_parser("compare", help="compare two reports")
    c.add_argument("report_a", help="output directory (or report.json) of a run or digest")
    c.add_argument("report_b", help="the same of another")
    c.add_argument("--expected-failures", metavar="FILE",
                   help="file of expected failures; a failure listed there is not a difference")
    c.set_defaults(func=cmd_compare)
    return p


def main(argv):
    extra = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    args = parser().parse_args(argv)
    if extra and args.command != "run":
        log("node arguments after -- are only taken by run")
        return 2
    return args.func(args, extra)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
