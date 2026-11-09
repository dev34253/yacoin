# Replay

`replay.py` imports the block history from a node's block files into a new data directory with a given `yacoind` binary,
with `-reindex` and `-replayvalidation=report`, and writes a report of the resulting state. Two reports, from two builds
or from a build and a synced node, are compared with one command.

Requirements: Python 3.8 or newer, standard library only, on a Unix system (the run measures the node with `wait4`).
The script runs under `python3 -I`.

## Commands

### `run`

```
contrib/replay/replay.py run [--stop-at-height N] [--dbcache MB] [--port P] [--rpcport R]
                             YACOIND SOURCE_BLOCKS OUT [-- NODE_ARGS...]
```

1. Checks that `YACOIND` is executable, that `SOURCE_BLOCKS` holds `blk00000.dat`, that `OUT` does not exist and is not
   inside `SOURCE_BLOCKS`, that both ports are free and that no `NODE_ARGS` sets an option the script sets (below);
   otherwise it exits with status 2 and creates nothing.
2. Creates `OUT/datadir/blocks/` and copies `blk00000.dat`, `blk00001.dat`, … from `SOURCE_BLOCKS` into it, in number
   order up to the first missing number. Nothing else is taken from the source (no `rev` files, no index), and nothing
   in `SOURCE_BLOCKS` is written.
3. Writes `OUT/datadir/yacoin.conf` (a comment only) and starts

   ```
   YACOIND -datadir=OUT/datadir -conf=OUT/datadir/yacoin.conf -daemon=0 -reindex -replayvalidation=report
           -connect=0 -listen=0 -dnsseed=0 -discover=0 -upnp=0 -listenonion=0 -server=0 -disablewallet
           -printtoconsole=0 -port=P -rpcport=R [-dbcache=MB] [-stopatheight=N] NODE_ARGS...
   ```

   The replay node makes no network connections and uses its own ports (defaults 17788 and 17789; `--port`,
   `--rpcport`). Every other setting is the node's default; `NODE_ARGS` after `--` are passed on unchanged, for example
   `-- -par=2`. These options are set by the script; refused after `--` (also in their `-no` form): `-datadir`,
   `-conf`, `-daemon`, `-reindex`, `-replayvalidation`, `-connect`, `-listen`, `-dnsseed`, `-discover`, `-upnp`,
   `-listenonion`, `-server`, `-disablewallet`, `-printtoconsole`, `-port`, `-rpcport`, `-dbcache`, `-stopatheight`.
4. Follows `OUT/datadir/debug.log`. When the node logs `Done loading`, the script sends it SIGTERM and waits for it to
   exit. With `--stop-at-height N` the node stops itself at height N (`-stopatheight`) and exits with status 1.
5. Computes the digest of `OUT/datadir` (as `digest` does), reads the failure lines of `-replayvalidation` from
   `debug.log` and writes the report files into `OUT`.

The run is **complete** when the node exited with status 0 (with `--stop-at-height N`: 0 or 1, and the tip is at height
N), `debug.log` has `Reindexing finished` and the digest could be computed; otherwise it is **incomplete**, with the
reasons in the report (also when the node cannot be started: "cannot start the node: …"). The exit status is 0 for a
complete run and 1 for an incomplete one.

If the script gets SIGINT, SIGTERM or SIGHUP while the node runs, it sends the node SIGTERM, waits for it to exit and
exits with status 128 plus the signal number, without a report. A signal the script was started with ignored (for
example SIGHUP under `nohup`) stays ignored. If the script is killed with SIGKILL, the node goes on running; stop it
by hand, for example with `pkill -TERM -f -- "-datadir=OUT/datadir"`.

The node's output is in `OUT/node-stdout.log` and `OUT/node-stderr.log`, its log in `OUT/datadir/debug.log`.

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
| `status`, `incomplete_reasons` | `complete` or `incomplete`, and why |
| `start_time`, `end_time` | UTC |
| `datadir` | the data directory the digest was taken from |
| `tip` | `height` and `hash` of the chainstate's best block |
| `sections`, `digest`, `digest_error` | `count` and `sha256` per section; the overall digest; the error if there is no digest |
| `phases.digest_seconds` | time of the digest |
| `command` | run: the node's full command line |
| `binary` | run: `path` and `sha256` of `YACOIND` |
| `source`, `block_files` | run: `SOURCE_BLOCKS`; `count` and `bytes` of the copied block files |
| `stop_at_height` | run: `--stop-at-height`, or null |
| `exit_status`, `exit_signal` | run: the node's exit status, or the signal that ended it |
| `wall_seconds`, `cpu_seconds`, `user_seconds`, `system_seconds`, `peak_rss_kib` | run: the node process from start to exit (CPU time and peak resident memory from `wait4`) |
| `phases` | run: `copy_seconds`, `reindex_finished_seconds` and `done_loading_seconds` (from the node's start), `node_seconds`, `digest_seconds` |
| `reindex_finished`, `done_loading` | run: whether `debug.log` has these lines |
| `failures`, `failure_blocks`, `failures_off_main_chain` | run: failure lines of `-replayvalidation`, the number of distinct blocks among them, and of failures whose block is not on the main chain at its height |

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

## Block files

The source is the `blocks/` directory of a synced node, or a copy of it. Copy it while that node is stopped, or in two
passes: a first copy while it runs (for example with `rsync -a`), then stop the node, copy again (`rsync -a --delete`),
and start it. `run` reads only the `blk*.dat` files of the source.

## Resources

Disk: `OUT` holds a copy of the block files plus the databases the node rebuilds (`blocks/index`, `chainstate`,
`tokens`), the `rev` files and `debug.log`. The digest reads the block index, chainstate and token databases into
memory.
