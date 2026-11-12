# Replay

`replay.py` imports the block history from a node's block files into a new data directory with a given `yacoind` binary,
with `-reindex` and `-replayvalidation=report`, and writes a report of the resulting state. Two reports, from two builds
or from a build and a synced node, are compared with one command.

A snapshot replay starts from a snapshot, a read-only copy of the databases of a replay up to a height H, and imports
the main-chain blocks above H (see [Snapshot replay](#snapshot-replay)).

Requirements: Python 3.8 or newer, standard library only, on a Unix system (the run measures the node with `wait4`).
The script runs under `python3 -I`.

## Commands

### `run`

```
contrib/replay/replay.py run [--up-to-height H --chain DATADIR | --snapshot SNAPSHOT --chain DATADIR]
                             [--stop-at-height N] [--dbcache MB] [--port P] [--rpcport R]
                             YACOIND SOURCE_BLOCKS OUT [-- NODE_ARGS...]
```

Without `--snapshot` (a full replay):

1. Checks that `YACOIND` is executable, that `SOURCE_BLOCKS` holds `blk00000.dat`, that `OUT` does not exist and is not
   inside `SOURCE_BLOCKS`, that both ports are free and that no `NODE_ARGS` sets an option the script sets (below);
   otherwise it exits with status 2 and creates nothing.
2. Creates `OUT/datadir/blocks/` and copies `blk00000.dat`, `blk00001.dat`, … from `SOURCE_BLOCKS` into it, in number
   order up to the first missing number. Nothing else is taken from the source (no `rev` files, no index), and nothing
   in `SOURCE_BLOCKS` is written. With `--up-to-height H`, `OUT/datadir/blocks/` gets block files with only the
   main-chain blocks 0 to H of the chain instead (see [The chain](#the-chain)).
3. Writes `OUT/datadir/yacoin.conf` (a comment only) and starts

   ```
   YACOIND -datadir=OUT/datadir -conf=OUT/datadir/yacoin.conf -daemon=0 -reindex -replayvalidation=report
           -connect=0 -listen=0 -dnsseed=0 -discover=0 -upnp=0 -listenonion=0 -server=0 -disablewallet
           -printtoconsole=0 -port=P -rpcport=R [-dbcache=MB] [-stopatheight=N] NODE_ARGS...
   ```

   Without `NODE_ARGS`, the replay node makes no network connections and uses its own ports (defaults 17788 and 17789;
   `--port`, `--rpcport`). Every other setting is the node's default; `NODE_ARGS` after `--` are passed on unchanged,
   for example `-- -par=2`. Options in `NODE_ARGS` can make the node connect to other nodes or read and write files
   outside `OUT` (for example `-addnode`, `-seednode`, `-pid`). The options the script sets itself are refused after
   `--` (also in their `-no` form): `-datadir`, `-conf`, `-daemon`, `-reindex`, `-replayvalidation`, `-connect`,
   `-listen`, `-dnsseed`, `-discover`, `-upnp`, `-listenonion`, `-server`, `-disablewallet`, `-printtoconsole`,
   `-port`, `-rpcport`, `-dbcache`, `-stopatheight`, `-loadblock`.
4. Follows `OUT/datadir/debug.log`. When the node logs `Done loading`, the script sends it SIGTERM and waits for it to
   exit. With `--stop-at-height N` the node stops itself at height N (`-stopatheight`) and exits with status 1.
5. Computes the digest of `OUT/datadir` (as `digest` does), reads the failure lines of `-replayvalidation` from
   `debug.log`, makes the block-file check (below) on `OUT/datadir/blocks/blk*.dat` and writes the report files into
   `OUT`.

The run is **complete** when the node exited with status 0 (with `--stop-at-height N`: 0 or 1, and the tip is at height
N), `debug.log` has `Reindexing finished`, the digest could be computed, the block-file check passes and, with
`--up-to-height H`, the tip is at height H; otherwise it
is **incomplete**, with the reasons in the report (also when the node cannot be started: "cannot start the node: …").
The exit status is 0 for a complete run and 1 for an incomplete one.

The **block-file check** reads the block files the node was given and checks that every block of the block files is in
the block index with its data, and that no stored block lies above the tip (not with `--stop-at-height`, where the
blocks above N are stored but not connected). A record starts with the 4-byte marker that begins `blk00000.dat`,
followed by its size (80 to 1000000 bytes) and the block; anything else is skipped byte by byte. A block is matched
with the block index by its header fields (version, previous block, merkle root, time, bits, nonce). The reasons of an
incomplete run are "N blocks of the block files are not in the block index", "stored blocks above the tip, up to
height X" and, when the block index holds stored blocks, "no block records found in the block files".

If the script gets SIGINT, SIGTERM or SIGHUP while the node runs, it sends the node SIGTERM, waits for it to exit and
exits with status 128 plus the signal number, without a report. A signal the script was started with ignored (for
example SIGHUP under `nohup`) stays ignored. If the script is killed with SIGKILL, the node goes on running; stop it
by hand, for example with `pkill -TERM -f -- "-datadir=OUT/datadir"`.

The node's output is in `OUT/node-stdout.log` and `OUT/node-stderr.log`, its log in `OUT/datadir/debug.log`.

#### The chain

`--chain DATADIR` names a stopped node's data directory whose block index gives the main chain: the blocks from genesis
to the chainstate's best block, one per height. It is needed with `--up-to-height` and with `--snapshot`, and refused
(exit status 2) when a running node holds the lock of `DATADIR`, when its block index or chainstate cannot be read, when
its chain does not reach the heights the run needs, or when `OUT` is inside `DATADIR`. Nothing in `DATADIR` is written.

The script finds the main-chain block of each height it needs in the block files of `SOURCE_BLOCKS` by its header
fields and writes the records (marker, size and block, unchanged) into block files of its own, `blk00000.dat`,
`blk00001.dat`, …, in height order; a file ends before a record would bring it to 128 MiB. Blocks that are not on the
main chain are not written. When the block of a height is not in the source block files, or is there more than once
with different content, the run ends before the node starts: the report is incomplete and names the height.
`--up-to-height` is not taken with `--stop-at-height` or `--snapshot`.

With `--snapshot SNAPSHOT --chain DATADIR` (a snapshot replay):

1. Checks as above, and that `OUT` is not inside `SNAPSHOT`, that `SNAPSHOT` has a `snapshot.json` of a known format,
   that the chain of `DATADIR` holds the snapshot's block at its height H and goes above it, and that
   `--stop-at-height N`, if given, is above H and not above the chain's tip.
2. Writes the main-chain blocks from H + 1 to the chain's tip into `OUT/import/` (see [The chain](#the-chain)).
3. Copies the files of the snapshot into `OUT/datadir` (copies, never links), checking each against the snapshot's
   manifest. A file that is missing or differs ends the run before the node starts: the report is incomplete and
   names the file.
4. Starts

   ```
   YACOIND -datadir=OUT/datadir -conf=OUT/datadir/yacoin.conf -daemon=0 -replayvalidation=report
           -connect=0 -listen=0 -dnsseed=0 -discover=0 -upnp=0 -listenonion=0 -server=0 -disablewallet
           -printtoconsole=0 -port=P -rpcport=R [-dbcache=MB] [-stopatheight=N]
           -loadblock=OUT/import/blk00000.dat -loadblock=OUT/import/blk00001.dat …
           -loadblock=OUT/import/blk00000.dat -loadblock=OUT/import/blk00001.dat … NODE_ARGS...
   ```

   The node opens the copied block index, chainstate and token database and imports the blocks of the block files.
   The block files are given to the node twice: a block stored before its parent is imported in the
   second pass. Blocks still missing after that show in the block-file check.
5. Stops the node as above, computes the digest, makes the block-file check on `OUT/import/` and writes the same
   report files.

The snapshot run is **complete** when the node exited as above, `debug.log` has `Done loading`, an `Importing blocks
file` line for every `-loadblock` file and no `Could not open blocks file` line, the digest could be computed, the
block-file check passes and the tip is at height H or above.

### `snapshot`

```
contrib/replay/replay.py snapshot RUN_OUT SNAPSHOT
```

Makes the snapshot `SNAPSHOT` of the data directory of the full run in `RUN_OUT`, usually a run with
`--up-to-height`.

1. Refuses (exit status 2, nothing created) when `SNAPSHOT` exists or is inside `RUN_OUT`, when `RUN_OUT` has no
   `report.json`, or the report is not of a run, not complete, of a snapshot run, of a run with `--stop-at-height` or
   without a digest, when `RUN_OUT/failures.tsv` cannot be read or does not have the report's number of failures, when
   `RUN_OUT/datadir` lacks `blocks/`, `blocks/index/`, `chainstate/` or `tokens/`, and when a running node holds the
   lock of `RUN_OUT/datadir`.
2. Copies the databases of `RUN_OUT/datadir` into `SNAPSHOT`: `blocks/` (the `blk` and `rev` files and `blocks/index`),
   `chainstate/` and `tokens/`, nothing else, and records the size and SHA-256 of every file in a manifest.
3. Computes the digest of the copy, which must have the tip and digest of the run's report, and makes the block-file
   check on the copy's `blk` files, which must pass. Otherwise the command exits with status 1 and writes no
   `snapshot.json`; a directory without `snapshot.json` is not a snapshot.
4. Writes `SNAPSHOT/snapshot.json`: `format` (1), `height`, `hash`, `digest` and `sections` of the state, the run's
   `command`, `binary` (path and SHA-256), `source`, `up_to_height` and `chain`, its `failures`, `failure_blocks` and
   `failures_off_main_chain`, the run directory (`run`), the time it was made (`made`) and the `manifest`; copies the
   run's `report.json` and `failures.tsv` beside it; and makes every file and directory of `SNAPSHOT` read-only.

### `digest`

```
contrib/replay/replay.py digest DATADIR OUT
```

Writes the report files of the state in `DATADIR` into `OUT` (which must not exist), without the fields of a run. The
node of `DATADIR` must be stopped; the command refuses a data directory whose lock a running node holds, and a
chainstate that was not closed cleanly. Nothing in `DATADIR` is changed. Exit status 0; 1 when the digest cannot be
computed (including a data directory whose lock a running node holds); 2 when the command is refused (`DATADIR` is
not a directory, `OUT` exists).

The digest has these sections, each a record count and a SHA-256:

| Section | Content |
|---|---|
| `chain` | per height of the main chain, from genesis to the chainstate's best block: the block hash and the fields of its block index record (`blocks/index`); bookkeeping fields (file positions, status flags, writer version) are not part of the chain digest |
| `undo` | per height above genesis: the SHA-256 of the block's undo record in the `rev` files (the record's checksum is checked) |
| `coins` | every unspent-output record of the chainstate, key and value bytes as stored (the values without the chainstate's obfuscation), in key order |
| `tokens` | the token records (`A`) of the token database |
| `tokenindex` | the address records of the token database (`B`, `C`; present with `-tokenindex`) |

The overall digest is the SHA-256 over the sections' counts and digests. The databases are read by a LevelDB reader in
`replaylib/leveldb.py` (tables, write-ahead logs and the MANIFEST; uncompressed tables only).

### `compare`

```
contrib/replay/replay.py compare [--expected-failures FILE] REPORT_A REPORT_B
```

`REPORT_A` and `REPORT_B` are output directories of `run` or `digest` (or their `report.json`); any other path is an
error (exit status 2). Prints `identical` and
exits with status 0 when both reports are complete, their tips, every section and every height row agree, and neither
has a failure other than the expected failures (below). Otherwise it exits with status 1 and prints:

- `first difference at height H: …`: the lowest height with a row that differs (naming the columns, with both values),
  a row present in one report only, or a failure that is not expected;
- `status: …` when a report is incomplete, `tip: …` when the tips differ;
- `sections that differ: …`: the sections whose count or digest differs (a section such as `coins` is named without a
  height).

`compare` takes an optional file of expected failures (`--expected-failures`); a failure listed there is not a
difference. The file has one entry per line, `BLOCK CHECK TX INPUT` (the fields of the failure line, `-` where the line
has `-`); `#` starts a comment. An entry matches a failure by block hash, check, transaction and input. A malformed
line is an error (exit status 2).

## Report files

`report.json`:

| Field | Content |
|---|---|
| `format`, `kind` | report format version (1); `run` or `digest` |
| `mode`, `snapshot` | run: `full` or `snapshot`; the snapshot's `path`, `height`, `hash`, `digest` and `binary` (path and SHA-256 of the build that made it; null for a full run) |
| `blocks_above_snapshot` | snapshot run: the tip's height minus the snapshot's height H (null for a full run and without a digest); also in the summary line `run` prints |
| `status`, `incomplete_reasons` | `complete` or `incomplete`, and why |
| `start_time`, `end_time` | UTC |
| `datadir` | the data directory the digest was taken from |
| `tip` | `height` and `hash` of the chainstate's best block |
| `sections`, `digest`, `digest_error` | `count` and `sha256` per section; the overall digest; the error if there is no digest |
| `phases.digest_seconds` | time of the digest |
| `command` | run: the node's full command line |
| `binary` | run: `path` and `sha256` of `YACOIND` |
| `source`, `block_files` | run: `SOURCE_BLOCKS`; `count` and `bytes` of the block files the node was given |
| `up_to_height`, `chain` | run: `--up-to-height`, or null; the chain's `datadir` and the `height` and `hash` of its tip, or null without `--chain` |
| `block_file_check` | run: `blocks` (distinct blocks in the block files), `not_in_index` (of these, the blocks the block index does not hold with their data), `stored_above_tip` (the highest height of a stored block above the tip, or null); null when the check was not made |
| `stop_at_height` | run: `--stop-at-height`, or null |
| `exit_status`, `exit_signal` | run: the node's exit status, or the signal that ended it |
| `wall_seconds`, `cpu_seconds`, `user_seconds`, `system_seconds`, `peak_rss_kib` | run: the node process from start to exit (CPU time and peak resident memory from `wait4`) |
| `phases` | run: `copy_seconds`, `reindex_finished_seconds` and `done_loading_seconds` (from the node's start), `node_seconds`, `digest_seconds`, `block_file_check_seconds`; with `--chain`, `chain_seconds` (reading the chain) |
| `reindex_finished`, `done_loading` | run: whether `debug.log` has these lines |
| `failures`, `failure_blocks`, `failures_off_main_chain` | run: failure lines of `-replayvalidation`, the number of distinct blocks among them, and of failures whose block is not on the main chain at its height; a snapshot run's failures include those of the run the snapshot was made from |

`heights.tsv.gz`: one row per height of the main chain: `height`, `hash`, `mint`, `moneysupply` (from the block index
record), `chain` (the SHA-256 of the height's part of the `chain` section), `undo` (the undo record's SHA-256, `-` for
none).

`failures.tsv`: one row per failure line: `height`, `block`, `check`, `tx`, `input`, `main` (1 if the block is on the
main chain), `error`. A `digest` writes the header only.

## Comparing two builds

Run each build on the same block files, then compare the reports:

```
contrib/replay/replay.py run /path/to/build-a/yacoind /data/blocks-copy /data/replay-a
contrib/replay/replay.py run /path/to/build-b/yacoind /data/blocks-copy /data/replay-b
contrib/replay/replay.py compare /data/replay-a /data/replay-b
```

To compare a run with the node the block files came from, stop that
node, take its digest and compare:

```
contrib/replay/replay.py digest /data/node-datadir /data/node-digest
contrib/replay/replay.py compare /data/node-digest /data/replay-a
```

Both reports describe the state at their tip; when the node is ahead of the block files, replay to the same height with
`--stop-at-height`.

## Snapshot replay

A full replay is needed for a change to proof of work, hashing or block loading, and before each release. For a change
to block loading and before each release, that is a full run without `--up-to-height`, which gives the node the block
files as they are; for a change to proof of work or hashing, the full replay in two parts (below) suffices. For the
other consensus-critical changes a snapshot replay suffices.

A snapshot replay accepts and connects the main-chain blocks above H with the candidate build. The state up to H
(block index, chainstate, token database and undo data) is the snapshot's, made by the build that made the snapshot.

H is the tip of the chain minus a number of blocks, chosen for a snapshot replay to fit the time available. A snapshot
is made from a run up to H, with the stopped node the block files come from as the chain:

```
contrib/replay/replay.py run --up-to-height H --chain /data/node-datadir /path/to/build/yacoind /data/blocks-copy \
    /data/replay-to-h
contrib/replay/replay.py snapshot /data/replay-to-h /data/snapshot
```

A full replay in two parts: `run --up-to-height H` with build B, `snapshot`, then `run --snapshot` with the same build
B. Every main-chain block is accepted and connected by B, so the report of the snapshot run serves as B's full replay
of the main chain, and the snapshot is refreshed with it. For a change to block loading, and before a release, run a
full replay without `--up-to-height`: it gives the node the block files as they are. `snapshot` also takes a full run
without `--up-to-height`, at its tip.

The `snapshot` command checks the copy against the run's report (tip and digest) and its block files against its
block index; every snapshot run checks each file against the manifest while copying it. A snapshot is stored
read-only and never written to: each run works on its own copy. Deleting a snapshot needs write permission first:
`chmod -R u+w /data/snapshot && rm -rf /data/snapshot`.

Comparing two builds from the same snapshot, on the same block files:

```
contrib/replay/replay.py run --snapshot /data/snapshot --chain /data/node-datadir /path/to/build-a/yacoind \
    /data/blocks-copy /data/snap-a
contrib/replay/replay.py run --snapshot /data/snapshot --chain /data/node-datadir /path/to/build-b/yacoind \
    /data/blocks-copy /data/snap-b
contrib/replay/replay.py compare /data/snap-a /data/snap-b
```

A snapshot run's report compares with a full run's or a digest's as any two reports do. A snapshot run's failures
include those of the run the snapshot was made from, in its report and its `failures.tsv`.

## Block files

The source is the `blocks/` directory of a synced node, or a copy of it. Copy it while that node is stopped, or in two
passes: a first copy while it runs (for example with `rsync -a`), then stop the node, copy again (`rsync -a --delete`),
and start it. `run` reads only the `blk*.dat` files of the source.

## Resources

Disk: `OUT` holds a copy of the block files plus the databases the node rebuilds (`blocks/index`, `chainstate`,
`tokens`), the `rev` files and `debug.log`. A snapshot holds the block files and these databases; a snapshot run's
`OUT` holds a copy of the snapshot plus the block files in `OUT/import/`. The digest reads the block index, chainstate
and token databases into memory, the block-file check the block index, and `--chain` the block index of the chain.

Time and memory: one full replay of the main chain took about 65 hours of wall time and about 65 hours of CPU time,
with a peak memory of about 1.7 GB for the node (`peak_rss_kib`); the digest of the result took under two minutes and
about 1.5 GB of memory.
