# Fuzzing

YACoin's fuzz targets are built into one [libFuzzer](https://llvm.org/docs/LibFuzzer.html) binary, `src/test/fuzz/fuzz`. Each target
feeds its input to one piece of code; the binary runs the target named by the `FUZZ` environment variable. A corpus of inputs for every
target is kept in `test/fuzz/corpus/<target>/`, and CI runs each of these inputs once through its target on every pull request commit
and every push to `master`. CI never fuzzes: new inputs are searched for on a developer's machine.

## Targets

The binary has 24 targets.

`src/test/fuzz/deserialize.cpp` holds 18 targets that each deserialise one object from a network stream: the first 4 bytes of an input
are the stream version, the rest is the object. Inputs over 1 MiB and inputs shorter than 4 bytes are ignored, and reading past the end
of an input ends the run.

| Target | Object |
|---|---|
| `block_deserialize`, `block_header_deserialize`, `block_locator_deserialize` | `CBlock`, `CBlockHeader`, `CBlockLocator` |
| `blockmerkleroot` | `CBlock`, then its merkle tree |
| `transaction_deserialize`, `txoutcompressor_deserialize` | `CTransaction`, `CTxOutCompressor` |
| `coins_deserialize`, `txundo_deserialize`, `blockundo_deserialize` | `Coin`, `CTxUndo`, `CBlockUndo` |
| `diskblockindex_deserialize` | `CDiskBlockIndex` |
| `addrman_deserialize`, `banentry_deserialize` | `CAddrMan`, `CBanEntry` |
| `netaddr_deserialize`, `service_deserialize`, `address_deserialize` | `CNetAddr`, `CService`, `CAddress` |
| `messageheader_deserialize`, `inv_deserialize`, `bloomfilter_deserialize` | `CMessageHeader` (and `IsValid()`), `CInv`, `CBloomFilter` |

Six targets, one file each in `src/test/fuzz/`, feed YACoin's own formats:

| Target | File | What the input is and what it feeds |
|---|---|---|
| `token_script` | `token_script.cpp` | An output script: the token script detection functions (`CScript::IsTokenScript()` and the `IsScript…Token()` functions), the functions that read a token amount from a script, and the token decoders (`TokenFromScript()` and the other `…FromScript()` functions, `ParseTokenScript()`, `GetTokenInfoFromScript()`); a decoded token is checked as the node checks one (`CheckNewToken()`, `CheckReissueToken()`, the token name checks) |
| `tokendb_record_deserialize` | `tokendb.cpp` | A record of the token database (`CTokensDB`), its key followed by its value; the key's first byte chooses the record kind (`A`, `B`, `C`, `U`, `Z`), other inputs are ignored |
| `addressindex_deserialize` | `addressindex.cpp` | An address index record, its key followed by its value: `a` (`CAddressIndexKey` and the amount) or `u` (`CAddressUnspentKey`, `CAddressUnspentValue`); the key is also read as each of the keys the index lookups seek to |
| `mempool_load` | `mempool_load.cpp` | A `mempool.dat` file, which `LoadMempool()` reads as the node does at start |
| `p2p_process_messages` | `process_messages.cpp` | The messages of one inbound peer, processed by `PeerLogicValidation::ProcessMessages()`. The first byte chooses whether the peer first completes the handshake (bit 0); then each message is a command byte (an index into the node's message types and one unknown command), a 2-byte little-endian payload size and the payload. The target frames each message with the main network's magic and its checksum. It sends every message type except headers, block, cmpctblock and blocktxn |
| `block_header_hash` | `block_header_hash.cpp` | A `CBlockHeader` in the input format of the `deserialize.cpp` targets, then its proof-of-work hash (`GetHash()`) and its SHA-256 hash. It hashes at the test networks' N-factor |

The token database and address index targets read records as `CDBWrapper` does (disk serialisation, the client version), without a
database. `mempool_load` and `p2p_process_messages` run on a node set up once per process (`src/test/fuzz/fuzz_util.cpp`): a temporary data
directory, removed at exit; the consensus values as the node sets them at start, with the test networks' N-factor; the main network's
genesis block as the only block, in-memory databases, a fixed mock time, and no threads. After each input the target puts the node's
state back: the mempool is emptied, and the P2P target gives each input a new peer and empties the node's address and ban lists.

`PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1 src/test/fuzz/fuzz` prints the names of all targets and exits. A missing or unknown `FUZZ` name
stops the binary with a message.

A new target is a `FUZZ_TARGET(name) { ... }` block (`src/test/fuzz/fuzz.h`) in a file of `src/test/fuzz/` listed in
`test_fuzz_fuzz_SOURCES` (`src/Makefile.test.include`); `FUZZ_TARGET_INIT(name, init)` also names a set-up function that runs once,
before the first input. A target needs its own corpus directory `test/fuzz/corpus/<name>/` with at least one input, or the corpus replay
fails.

## Building

`./configure --enable-fuzz` builds only the fuzz binary: no `yacoind`, `yacoin-cli`, GUI or `test_bitcoin`. It needs a compiler with
libFuzzer, such as clang (configure stops with a message otherwise); libFuzzer is linked into the fuzz binary only, and the C++ sources
of the node's libraries are built with the coverage instrumentation libFuzzer uses (`-fsanitize=fuzzer-no-link`; C sources, secp256k1
and univalue are not). The sanitizers come from the flags you pass.

The Ubuntu 22.04 CI image has clang 14. Its `fuzz-corpus` mode builds the binary and replays the corpus, as the CI job does:

```sh
./dev.sh container fuzz-corpus
```

It configures with `--enable-fuzz --with-asm=no`, `CC=clang CXX=clang++` and
`-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined` (the flags of the `unit-tests-asan` mode)
in `CFLAGS`, `CXXFLAGS` and `LDFLAGS`, against the depends of the test modes. `LDFLAGS` also has `-no-pie`: clang 14's
AddressSanitizer runtime fails at random at start in a position-independent executable under the address randomisation of current
Linux kernels, and configure runs test programs with these flags. The binary is
`build/docker-ubuntu.22.04/fuzz-corpus/src/test/fuzz/fuzz`, the logs of the replay are in
`build/docker-ubuntu.22.04/fuzz-corpus/fuzz-corpus-logs/`.

## Replaying the corpus

`contrib/devtools/run-fuzz-corpus.py <fuzz binary> test/fuzz/corpus <log dir>` runs every input of every target once and fails on a
crash, a sanitizer report, a timeout (30 s per input), running out of memory (2048 MB) or an input that did not run. It also fails when
a target has no corpus directory or an empty one, and when a directory names no target. The input files are passed to the binary as
arguments, so libFuzzer runs them and does not fuzz. The `fuzz-corpus` mode runs it with `ASAN_OPTIONS=detect_leaks=1` and
`UBSAN_OPTIONS=print_stacktrace=1`; the CI job `fuzz-corpus` runs that mode.

The script writes `<target>.log` per target and `summary.txt` into the log directory, which it creates if missing. An existing log
directory may hold only the logs of an earlier run (`summary.txt` and the logs of the targets the binary lists or that summary
names), which the script deletes first; it refuses one that holds anything else and deletes nothing in it.

## Fuzzing locally

Fuzz in the image the mode built, after one run of `./dev.sh container fuzz-corpus`, with a directory outside the checkout mounted for
what fuzzing finds, for example:

```sh
mkdir -p "$HOME/yacoin-fuzz"
docker run --rm -it -v "$PWD":/src -v "$HOME/yacoin-fuzz":/work -w /src --entrypoint bash yacoin-build-local:ubuntu.22.04
# in the container:
export PATH=/usr/lib/llvm-14/bin:$PATH ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1
fuzz=build/docker-ubuntu.22.04/fuzz-corpus/src/test/fuzz/fuzz
mkdir -p /work/new/coins_deserialize /work/crashes
FUZZ=coins_deserialize $fuzz -max_total_time=600 -artifact_prefix=/work/crashes/ \
    /work/new/coins_deserialize test/fuzz/corpus/coins_deserialize
```

libFuzzer writes the inputs it finds to the first directory and an input that crashes to `-artifact_prefix`, here both in
`$HOME/yacoin-fuzz`, outside the checkout. To add new inputs to the corpus, keep only those that reach new code:

```sh
FUZZ=coins_deserialize $fuzz -merge=1 test/fuzz/corpus/coins_deserialize /work/new/coins_deserialize
```

The container runs as root, so the files it writes (into the checkout too) belong to root; give them back afterwards, for example with
`docker run --rm -v "$PWD":/src --entrypoint chown yacoin-build-local:ubuntu.22.04 -R "$(id -u):$(id -g)" /src/test/fuzz/corpus`.

The file names are libFuzzer's (the SHA-1 of the content). Keep the corpus small: it is replayed on every pull request commit.
Every input added must replay without any report (`./dev.sh container fuzz-corpus`).

## A crash, a sanitizer report, a timeout or running out of memory

Treat it as a possible vulnerability: report it privately as [`SECURITY.md`](../SECURITY.md) describes, with the target, the input and
the report. Do not open a public issue or pull request about it, and do not commit the input. An input enters the corpus only after the
report has been handled, and once it replays without a report.
