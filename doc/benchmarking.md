# Benchmarking

`src/bench/bench_yacoin` measures how long a few pieces of the node take, the same way on every run, so the effect of a change can be
compared before and after it. Its framework (`src/bench/bench.h`) is a small one without a further dependency; a benchmark is a
function that runs its timed code in a `while (state.KeepRunning())` loop, registered with `BENCHMARK(name)`.

## Building

`./configure --enable-bench` adds the benchmark binary to the build; it is not built by default and not installed. It cannot be
combined with `--enable-fuzz`. The make target is relative to `src/`:

```sh
./configure --enable-bench
make -C src bench/bench_yacoin
```

The binary works on both builds, the main network's and `--enable-low-difficulty-for-development`.

## Running

```sh
src/bench/bench_yacoin                          # every benchmark, about 1 s each
src/bench/bench_yacoin -filter='HeaderHash.*'   # only the header hashing benchmarks
src/bench/bench_yacoin -list                    # the names of the benchmarks
```

| Option | Meaning |
|---|---|
| `-help` | Print the options and exit |
| `-list` | Print the names of the benchmarks `-filter` matches, one per line, and exit |
| `-filter=<regex>` | Run only the benchmarks whose whole name matches `<regex>` (ECMAScript syntax; default `.*`). A filter that matches no benchmark runs none and exits with status 0 |
| `-time=<seconds>` | Run each benchmark for about `<seconds>` (a positive number; default 1). Each benchmark runs its timed code at least once |

An unknown option, an invalid regular expression and a `-time` that is not a positive number stop the binary with a message and exit
status 2. The benchmarks run in the order of their names. Each prints one CSV line after a header line:

| Column | Meaning |
|---|---|
| `#Benchmark` | The name |
| `count` | How many runs of the timed code were timed |
| `min`, `max` | The shortest and the longest time of one run, in seconds. Short runs are timed in batches, and these are the times of a batch divided by its size |
| `average` | The time of all timed runs divided by `count`, in seconds |

Each benchmark checks its results. When a set-up or a check fails, the binary prints `error: benchmark <name> failed: <what>` on
stderr (after the benchmark's line for a check made after the timed runs), runs the other benchmarks and exits with status 1. Log
messages are off, except in `LogPrintfLoggingOn`. The benchmarks that need a data directory use a new temporary one, removed at exit.

## Benchmarks

| Name | What it calls and measures |
|---|---|
| `HeaderHashNFactor21` | Header hashing at N-factor 21 (the main network's): `CBlockHeader::CalculateHash()` of the header of main network block 1,911,210 (version 7). Each result must equal the block's hash |
| `HeaderHashNFactor4` | The same at N-factor 4 (the test networks'); each result must equal the header's hash at that N-factor |
| `CheckBlock1000Tx` | `CheckBlock()` of a block with 1000 transactions (below), without the proof-of-work check, with the merkle root check; must return true |
| `ConnectBlock1000Tx` | `ConnectBlock()` of the same block, through `TestBlockValidity()` with the genesis block as the previous block, without the proof-of-work check, for the block in the state it is in when it is connected (checked by `CheckBlock()` once): the contextual checks of the header and the block, then `ConnectBlock()` on a new coins view over the node's; must return true |
| `LogPrintfLoggingOn` | One `LogPrintf` call of a fixed short line with logging on: written to `debug.log` in the temporary data directory, with the default timestamps |
| `LogPrintfLoggingOff` | The same call with logging off |

The block benchmarks run on a node set up once per process (`src/bench/bench_util.cpp`): the main network's parameters and genesis
block as the only block, in-memory block, coins and token databases, a fixed mock time in 2026 and N-factor 21. The
genesis block index carries the main network's money supply of a recent epoch (the value `src/test/main_tests.cpp` pins), so the
reward and the size limit of the block are the main network's of that epoch. The block is at height 1 on the genesis block: a coinbase
that pays the block reward and 1000 transactions, each spending one P2PKH coin of the node's coins view to two P2PKH outputs, signed;
a version 7 proof-of-work header with the difficulty the node requires at that height. It is built once, without the miner, and the
set-up checks that it passes `TestBlockValidity()`.

`ci/containers/entrypoint.sh` runs every benchmark once in a short mode (`-time=0.01`) in the `unit-tests` mode, after the unit
tests, and prints the CPU model before it; a failed benchmark fails the CI job `unit-tests`.
