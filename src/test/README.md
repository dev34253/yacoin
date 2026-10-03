### Compiling/running unit tests

Unit tests will be automatically compiled if dependencies were met in `./configure`
and tests weren't explicitly disabled.

After configuring, they can be run with `make check`.

To run the bitcoind tests manually, launch `src/test/test_bitcoin`.

To add more bitcoind tests, add `BOOST_AUTO_TEST_CASE` functions to the existing
.cpp files in the `test/` directory or add new .cpp files that
implement new BOOST_AUTO_TEST_SUITE sections.

To run the bitcoin-qt tests manually, launch `src/qt/test/test_bitcoin-qt`

To add more bitcoin-qt tests, add them to the `src/qt/test/` directory and
the `src/qt/test/test_main.cpp` file.

### Running individual tests

test_bitcoin has some built-in command-line arguments; for
example, to run just the getarg_tests verbosely:

    test_bitcoin --log_level=all --run_test=getarg_tests

... or to run just the doubledash test:

    test_bitcoin --run_test=getarg_tests/doubledash

Run `test_bitcoin --help` for the full list.

### Note on adding test cases

The sources in this directory are unit test cases.  Boost includes a
unit testing framework, and since bitcoin already uses boost, it makes
sense to simply use this framework rather than require developers to
configure some other framework (we want as few impediments to creating
unit tests as possible).

The build system is setup to compile an executable called `test_bitcoin`
that runs all of the unit tests.  The main source file is called
test_bitcoin.cpp. To add a new unit test file to our test suite you need 
to add the file to `src/Makefile.test.include`. The pattern is to create 
one test file for each class or source file for which you want to create 
unit tests.  The file naming convention is `<source_filename>_tests.cpp` 
and such files should wrap their tests in a test suite 
called `<source_filename>_tests`. For an example of this pattern, 
examine `uint256_tests.cpp`.

For further reading, I found the following website to be helpful in
explaining how the boost unit test framework works:
[http://www.alittlemadness.com/2009/03/31/c-unit-testing-with-boosttest/](http://www.alittlemadness.com/2009/03/31/c-unit-testing-with-boosttest/).

### Consensus test harness (P0-47)

Consensus unit tests (difficulty, trust, stake kernel, rewards) use the
harness in `consensus_harness.h`. It gives every test the same way to set the
consensus globals, build block-index chains and put blocks on disk, and it
restores everything when the test ends. Tests using it today:
`consensus_harness_tests` (the harness itself), `pow_tests/harness_*`,
`chain_trust_tests` (and `chain_trust_fork_choice_tests`,
`chain_trust_p2p_tests`, see below), `kernel_tests`, `reward_tests`.

**Why it is needed.** Without `AppInit`, `test_bitcoin` runs with
`nMainnetNewLogicBlockNumber = 0` and `nFactorAtHardfork = 0`: everything is
"post-fork from height 0", so the old retarget branch and the stake-modifier
code (`ComputeNextStakeModifier`, `CheckStakeModifierCheckpoints`) are never
reached (review A4 in `project/plans/phase0-review.md`). Several consensus
functions also read `chainActive`, `mapBlockIndex`, the mock time and the
genesis block on disk (review B7).

**Fixture.** Use `ConsensusTestingSetup` (a `TestingSetup` with a temporary
data directory, the real genesis on disk and `chainActive` at genesis) for
the suite or a single case:

```cpp
#include "test/consensus_harness.h"
using namespace consensus_harness;

BOOST_FIXTURE_TEST_CASE(my_test, ConsensusTestingSetup)
{
    globals.UseMainnetGlobals();         // fork 1,890,000, Nf 21, epoch 21000
    globals.SetMockTime(1400000000);     // GetTime()/GetAdjustedTime()
    chain.StartOnExistingGenesis();      // real genesis, on disk
    chain.AppendMany(9, 60, 0x1d00ffff); // 9 PoW blocks, 60 s apart
    chain.SetActiveTip(chain.Tip());     // chainActive -> this chain
    unsigned int nBits = GetNextTargetRequired(chain.Tip(), false);
}
```

The fixture members are destroyed before `TestingSetup`, the chain first:
`chainActive` and `mapBlockIndex` go back to what they were, then the
globals. This also happens when the test fails or throws.

**Globals** (`globals`, a `ScopedConsensusGlobals`; you can also create
your own for a narrower scope). It saves and restores
`nMainnetNewLogicBlockNumber`, `nTokenSupportBlockNumber`,
`nFactorAtHardfork`, `nEpochInterval`, `nDifficultyInterval`, `fTestNet`,
`nYac10HardforkTime` and the mock time. Setters: `SetNewLogicBlockNumber`,
`SetTokenSupportBlockNumber`, `SetNFactorAtHardfork`, `SetEpochInterval`
(sets both intervals, like `AppInit`), `SetDifficultyInterval`, `SetTestNet`,
`SetYac10HardforkTime`, `SetMockTime`. Presets (they do not change the mock
time):

| Preset | Fork height | Token height | N-factor | Epoch |
|---|---|---|---|---|
| `UseUnitTestGlobals()` | 0 | 0 | 0 | 21000 |
| `UseMainnetGlobals()` | 1,890,000 | 1,911,210 | 21 | 21000 |
| `UseFunctionalTestGlobals(h)` | `h` | 1,911,210 | 4 | 10 |

All presets set `fTestNet = false` and `nYac10HardforkTime = 1619048730`.
Every change is printed with `BOOST_TEST_MESSAGE` (run with
`--log_level=message` to see it; `test_bitcoin` does not write `debug.log`).

**Chains** (`chain`, a `TestChain`; create more with a different salt,
`TestChain other(1)`, so their synthetic hashes differ):

- `Append(BlockSpec)` on the tip, `Append(prev, BlockSpec)` for forks or,
  with `prev == nullptr` and `spec.nHeight`, a segment that starts above
  height 0; `AppendMany(n, spacing, nBits, fPoS, firstTime)`.
- `BlockSpec` sets `nTime`, `nBits`, `nVersion` (default 6), `nNonce`, merkle
  root, PoS flag, entropy bit, stake modifier and its "generated" flag,
  `hashProofOfStake`, `prevoutStake`, `nStakeTime` and optionally the hash.
  Without a hash a deterministic synthetic one is used.
- `bnChainTrust`, `nTimeMax` and `pskip` are computed like
  `AddToBlockIndex`; every entry is in `mapBlockIndex` (needed by
  `CalculateNextWorkRequired` and the stake-modifier selection).
- `StartOnExistingGenesis()` builds on the genesis that `TestingSetup` wrote
  to disk, so `GetNextTargetRequired` can read it (`pow.cpp:174`).
- `AppendBlock(block, fWriteToDisk)` adds an entry for a real `CBlock`
  (made like `AddToBlockIndex`); with `fWriteToDisk` the block goes to
  `blocks/blk09000.dat` via `WriteBlockToTestFile()` and
  `ReadBlockFromDisk` works on the entry.
- `SetActiveTip(pindex)`, `Tip()`, `AtHeight(h)`, `size()`.

Limits: the chain never touches `pindexBestHeader`, `setBlockIndexCandidates`
or the block-tree database, so do not mix it with `ProcessNewBlock` /
`ActivateBestChain` in the same test. For a segment that starts above height
0, `SetActiveTip()` leaves `chainActive.Genesis()` and all heights below the
segment null (it clears `chainActive` first), and node code that calls `GetAncestor()`
below the segment asserts; the first entry gets the `pprev == nullptr` trust.
A duplicate hash throws `std::runtime_error`.

**Index-chain CSV** (`LoadIndexChainCsv(istream, chain)`,
`LoadIndexChainCsvFile(path, chain)`) – the format in which index chains,
e.g. the mainnet segments of P0-09, are loaded:

```
# comment lines and blank lines are ignored; CRLF is accepted
height,hash,prev_hash,time,bits,version,nonce,merkle_root,flags,stake_modifier,hash_proof_of_stake,prevout_stake,stake_time
1889998,<64 hex>,,1600000000,0x1c0fffff,7,12,<64 hex>,4,0x1122334455667788,,,
```

- The first line names the columns, in any order; unknown columns are
  ignored. Required: `height`, `hash`, `time`, `bits`. Empty optional fields
  take the `BlockSpec` defaults.
- Integers are decimal or hex with `0x`; no sign, no spaces. Hashes are 64
  hex digits in RPC byte order. `flags` is `CBlockIndex::nFlags` (1 = PoS,
  2 = entropy bit, 4 = generated stake modifier). `prevout_stake` is
  `<txid>:<n>`.
- Heights must be consecutive. The first row links to `prev_hash` when that
  hash is already in `mapBlockIndex` (e.g. the genesis), otherwise it starts
  a segment; for later rows a given `prev_hash` must match the previous row.
- Any error throws `std::runtime_error` with `<name>:<line>: <reason>`.

### Compact encoding tests (P0-11)

`bignum_compact_tests.cpp` pins `CBigNum::SetCompact`/`GetCompact`
(`bignum.h`, OpenSSL MPI based) exactly, bugs included: every exponent 0–34,
the sign bit, zero, values ≥ 2^256 (exponents up to 255), `GetCompact`
normalisation and truncation, Bitcoin Core's `arith_uint256` compact tests
ported, and a sweep of 3840 compacts against `arith_uint256`. Behaviour the
replacement in Phase 4 must handle specially (full list in
`project/done/P0-11-compact-encoding-tests.md`):

- negative compacts give negative values (`arith_uint256`: magnitude plus
  `fNegative`);
- a sign bit with all kept mantissa bytes zero (e.g. `0x01800000`) gives a
  negative zero: `<= 0` is true, `GetCompact`/`getuint256` on it are
  undefined behaviour and are never called;
- values ≥ 2^256 are exact, there is no overflow flag; `getuint256()` takes
  them mod 2^256;
- `GetCompact` of |v| ≥ 2^2039 wraps the exponent byte (2^2040 →
  `0x00010000`).

### CBigNum golden vectors (P0-13)

`data/bignum_vectors.json.xz` holds 100,000 operations on the `CBigNum`
methods that production code uses (P0-12 audit, `project/plans/dead-code.md`
c)), with inputs and outputs as text, recorded from today's `CBigNum`
(OpenSSL 1.0.1k from `depends`, x86_64). It is the durable artefact of plan
0.2a: whatever replaces `CBigNum` in Phase 4, and the reference oracle of
P0-51/P0-26, must reproduce every vector; it needs no `CBigNum` to be read.
`bignum_vectors_tests.cpp` replays it:

- `replay` – runs every vector through `CBigNum` and compares (about 0.3 s
  in the mainnet build). Inputs are built and outputs formatted with raw
  OpenSSL calls, not with the methods under test. The first 20 differences
  are printed in full, then a count.
- `generator_reproduces_vectors` – the generator in the same file (own
  splitmix64 PRNG, seed `0x50302d3133`, integer arithmetic only) must give
  the embedded file byte for byte, so the committed file is exactly the
  output of the committed generator.

The build unpacks the file with `xz -dc` into
`<builddir>/src/test/data/bignum_vectors.json.xz.h` (one C string literal
per line; rule `%.json.xz.h` in `src/Makefile.test.include`), so `xz` is
needed to build the tests. `contrib/testing/bignum_vectors_check.py` checks
every vector with an independent Python model (no `CBigNum`, no OpenSSL;
see `contrib/testing/README.md`).

**Format.** One JSON object, one vector per line:

```
{"format":"yacoin-bignum-vectors","version":"1",
"generator":"src/test/bignum_vectors_tests.cpp","seed":"50302d3133",
"doc":"src/test/README.md",
"count":"100000",
"vectors":[
["int32","0","0"],
...
["cmp","-0","0","-1"],
...
]}
```

Every field is a string; a vector is `[op, input..., output]`. Numbers are
lowercase hex without leading zeros, with an optional `-`: `0`, `1d00ffff`,
`-80`. `-0` is the **negative zero** (OpenSSL sign flag set on a zero
magnitude, from `SetCompact`, P0-11); it is a value of its own (`-0 < 0`).

| op | inputs | output | `CBigNum` code |
|---|---|---|---|
| `int32` | integer in `int32_t` range | value | `CBigNum(int32_t)` |
| `int64` | integer in `int64_t` range | value | `CBigNum(int64_t)` |
| `uint256` | 0 ≤ n < 2^256 | value | `CBigNum(uint256)`, `setuint256` (both checked) |
| `get_uint256` | value, not `-0` | \|v\| mod 2^256 | `getuint256()` |
| `get_uint64` | value, not `-0` | \|v\| mod 2^64 | `getuint64()` |
| `set_compact` | 0 ≤ n < 2^32 | value, may be `-0` | `SetCompact` |
| `get_compact` | value, not `-0` | 32-bit compact | `GetCompact()` |
| `to_string` | value, `-0` allowed | decimal text | `ToString()` |
| `get_hex` | value, `-0` allowed | hex text | `GetHex()` |
| `add`, `sub` | two values, not `-0` | value | `a + b`, `a - b` |
| `mul` | two values, `-0` allowed | value | `a * b` and `a *= b` (both checked) |
| `div` | two values, not `-0` | value, or `error` if b = 0 | `a / b` and `a /= b` (both checked; `bignum_error`) |
| `shl` | value (not `-0`), 0 ≤ n ≤ 2048 | value | `a << n` |
| `cmp` | two values, `-0` allowed | `-1`, `0` or `1` | `<`, `<=`, `>`, `>=` (all four checked) |

`-0` is used only where production code can meet it (a `SetCompact` result
compared with `<= 0` or multiplied in the stake kernel) and in the text
methods; `GetCompact`/`getuint256`/`getuint64` of `-0` are undefined
behaviour (P0-10) and never appear. Unused methods (`%`, `>>`, `==`,
`SetHex`, `getvch`, …) have no vectors.

Behaviour a replacement has to reproduce (all in the vectors, checked by
the Python model): values are sign and magnitude, not two's complement;
division truncates toward zero (`-ff / 2 = -7f`); `getuint256`/`getuint64`
drop the sign and take the magnitude mod 2^n; `a * b` is an ordinary `0`
when either operand is zero, including `-0`; `ToString`/`GetHex` of `-0` are
`"0"`; `SetCompact` gives negative values and the negative zero for a set
sign bit (`0x01800000` → `-0`); `GetCompact` adds a zero byte when the top
bit is set and wraps the exponent byte for |v| ≥ 2^2039 (2^2047 →
`1008000`); `a << n` keeps the sign.

**Content.** About 35,500 adversarial vectors: integer-constructor limits;
every pair of 67 special values (0 and, with both signs: 1, 2, byte and
word boundaries, 2^k and 2^k − 1 for k = 31, 32, 63, 64, 256, 2^128,
2^255, `CENT`, `COIN`, 100 `COIN`, `MAX_MONEY`, 86400, the PoS hard limit,
both `powLimit` values, the compacts `0x1d00ffff` and `0x1e0fffff`,
2^256 + 1, 2^264) for `add`, `sub`, `mul`, `div`, `cmp`; shifts of them;
`-0` against all of them for `cmp` and `mul`; `set_compact` for
every exponent 0–255 with mantissas around the sign bit; `get_compact` of
±2^k and ±(2^k − 1) for k up to 2056. About 34,000 vectors from chains
shaped like the production expressions, each step a vector whose inputs are
the previous outputs: stake kernel (amount × weight / `COIN` / 86400, also
with negative weights, × target, compared with a hash), block and chain
trust (legacy `(1 << 256) / (target + 1)`, `powLimit / target`, × 2,
accumulated), retarget (`SetCompact` → `getuint256` → `uint256` × timespan
/ timespan, and the `pow.cpp:197` form), and the pre-fork reward bisection
(`mid^6 * limit > limit^6 * target`, mainnet and low-difficulty limits).
The remaining 30,400 are random operations on production-shaped operands
(`int64_t` amounts and times, compact-derived targets, 256-bit hashes,
products, ±2^k ± small, some random values up to 600 bits) drawn mostly
from a fixed pool, so that the file compresses (12.9 MB of JSON, 0.97 MB
with xz).

**Regenerating** (only when the format or the generator changes – the
vectors are meant to stay fixed; `test_bitcoin` path relative to the build
directory, the rest relative to the checkout):

```bash
YACOIN_BIGNUM_VECTORS_OUT=/tmp/bignum_vectors.json \
  src/test/test_bitcoin --run_test=bignum_vectors_tests/generator_reproduces_vectors
xz -9e -T1 -c /tmp/bignum_vectors.json > src/test/data/bignum_vectors.json.xz
contrib/testing/bignum_vectors_check.py src/test/data/bignum_vectors.json.xz
```

The first command fails its comparison as long as the binary still embeds
the old file; rebuild and run the suite again afterwards.

### CBigNum property tests (P0-27)

`bignum_property_tests.cpp` checks algebraic identities of `CBigNum` on
random inputs (1000 samples per case by default): values from 0 to about
1100 bits (about 2400 bits for the compact exponent wrap), half of them
negative, powers of two (and ±1) and byte patterns of 0x00/0xff runs that
provoke carries. The 11 cases cover `+`/`-`, `*`/`/` (with `int64_t`
operands as in `pow.cpp`), truncating division and `%`, shifts, ordering,
compact round trips (from values and from random encodings),
`getuint256`/`getuint64`/`setuint256`, agreement with `arith_uint256` below
2^256, and operations with a negative zero. Where an identity does not hold
for `CBigNum` the test pins what it does instead (all inputs stay in):

- `a >> n` of any negative `a` is an ordinary 0 (also for `n = 0`), so
  `(a << n) >> n == a` only for `a >= 0`;
- `/` truncates toward zero; `a % b` is in `[0, |b|)`, i.e. the truncated
  remainder plus `|b|` when that is negative;
- no operation on ordinary values gives a negative zero; with a negative
  zero `nz` (from `SetCompact`, e.g. `0x01800000`): `nz - 0`, `nz + nz` and
  `nz << n` stay negative zeros, `nz % x == |x|`, products, quotients,
  `nz >> n` and `-nz` are ordinary zeros, `x / nz` throws;
- `GetCompact` of a value of 256 or more MPI bytes wraps the exponent byte.

The random source is deterministic by default: each case uses its own
`FastRandomContext` seeded with SHA256(fixed base seed, case name), so a case
gives the same inputs whether it runs alone or with the others. Two
environment variables change that without touching the default run:

```bash
YACOIN_PROPERTY_SEED=random test_bitcoin --run_test=bignum_property_tests --log_level=message
YACOIN_PROPERTY_SEED=<64 hex digits> ...   # replay a seed
YACOIN_PROPERTY_ITERATIONS=20000 ...       # more samples per case
```

With `random` every case draws its own base seed; replaying the seed a case
printed reproduces that case. `--log_level=message` prints the seed, the
number of checks, the time and
how often each input class was generated per case. A failure message names
the line, the expression, the case, the iteration, the operands in hex and
the `YACOIN_PROPERTY_SEED` value that replays it; a case stops after 20
failures. Invalid variable values fail the case with a message. With the
default iteration count each case also checks that every input class it
needs was generated at least once.

### Chain trust tests (P0-16)

`chain_trust_tests.cpp` pins block trust, chain trust and their uses as they
are today, bugs included (review A5, A7, C8 in
`project/plans/phase0-review.md`). Three suites:

- `chain_trust_tests` (main params, synthetic `TestChain` entries): every
  reachable branch of `CBlockIndex::GetBlockTrust` (`chain.cpp:75-115`) –
  target <= 0, first entry, PoW (`powLimit / target`, doubled after PoS),
  PoS after PoW (`pprev` trust + 1), PoS after PoS (0), the switch time
  boundary, the legacy rules and the `fTestNet` switch; the fork-choice
  consequences of the PoS rules; `GetBlockProofEquivalentTime`; the RPC
  output (`getblockheader`, `blockToJSON`, `gettimechaininfo`). Values that
  depend on `powLimit` are pinned for each build.
- `chain_trust_fork_choice_tests` (regtest, real mined blocks through
  `ProcessNewBlock`): `bnChainTrust` from `AddToBlockIndex`, fork choice by
  trust (`CBlockIndexWorkComparator`: more trust wins, equal trust keeps the
  block received first) and `AcceptBlock`'s "at least the tip's trust" rule
  for unrequested blocks. Regtest (powLimit 2^255 - 1) keeps mining cheap;
  these cases create no `TestChain` entries because `CheckBlockIndex` walks
  `mapBlockIndex`.
- `chain_trust_p2p_tests` (main params, synthetic entries, one outbound test
  peer that receives `inv` messages through `ProcessMessages`): the trust
  comparisons in `net_processing.cpp` for block availability (438-456),
  block download (536) and outbound eviction (3113-3119). The header-sync
  comparisons (1481, 1507, 1583) are left to the functional test of P0-32.

Two pitfalls of `TestingSetup` these suites work around, useful for other
tests of the same kind:

- `TestingSetup` creates no token database (`ptokensdb` is null), and
  `DisconnectBlock` reads token undo data from it, so a reorg crashes. The
  regtest fixture installs an in-memory `CTokensDB` and removes it again.
- The test `CConnman` is never started, so its send-buffer limit is 0: every
  queued message sets the peer's `fPauseSend`, and `ProcessMessages` then
  skips the receive queue. The test peer clears `fPauseSend` before
  delivering a message. Only one test peer may exist at a time, because
  `CConnmanTest::ClearNodes()` empties the whole node list.

Current behaviour these tests pin (not fixed in Phase 0):

- PoW trust is `powLimit / target` with integer division, so a PoW block
  whose target is above `powLimit` has trust 0 under the new rules (1 under
  the legacy rules).
- The final `return CBigNum(0)` in `GetBlockTrust` (`chain.cpp:112`) is
  unreachable: a block is either PoS or PoW.
- `GetBlockProofEquivalentTime` divides a Yacoin trust difference by
  Bitcoin's `GetBlockProof` of the tip: a month of mainnet PoW blocks is
  "worth" 2 seconds (low-difficulty build: about 3.75 days), so the
  one-month check at `net_processing.cpp:1119` does not trigger for blocks
  of the new-rules era (only legacy PoS trust, about 2^32 per block, is big
  enough). The trust difference and its product with the spacing are
  taken mod 2^256 (a difference of 2^255 or 2^256 gives 0), the result
  saturates at +-INT64_MAX, and a tip whose `GetBlockProof` is 0 makes it
  throw `uint_error` (division by zero).
- `chaintrust`/`blocktrust` in the RPC are hex without leading zeros, so a
  value of 0 is the empty string; `gettimechaininfo` returns
  `bnChainTrust` as a JSON number holding only the low 64 bits, although
  its help says "string ... hexadecimal".

### Chain parameter snapshot (P0-20)

`chainparams_snapshot_tests.cpp` pins the chain parameters by value, so an
accidental change fails loudly. A deliberate change must update the test too.
It covers:

- `CMainParams` for each build, using `#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT`
  where the two differ: consensus params, the genesis block, message start,
  ports, base58 prefixes, fixed and DNS seeds, flags, `chainTxData` and all
  51 checkpoints.
- `CRegTestParams`.
- The base params, plus the fact that `-testnet` has base params but no
  chain params (`CreateChainParams("test")` throws).
- `nChainStartTime` and `nYac10HardforkTime`.
- The 26 stake-modifier checkpoints. They are read through
  `CheckStakeModifierCheckpoints` with the mainnet globals of the harness. A
  sweep over heights 0 to 2,000,000 also pins how many there are. With
  `fTestNet` the testnet table is used, which has height 0 only.

The unit-test globals are pinned in `consensus_harness_tests`. What a node
actually runs with (the framework values and the compiled-in `AppInit`
defaults) is only visible in `debug.log`;
`test/functional/feature_params_snapshot.py` pins it. The full table is in `project/plans/phase0-test-safety-net.md`,
section 0.2h.

`test_bitcoin_main.cpp`: the `StartShutdown()` stub now prints a message and
exits with failure. It used to exit 0, which meant a failed genesis `Yassert`
in a release build (without `_DEBUG`; with it, `Yassert` is `assert`) ended the run "successfully" with no test summary.

### Rewards and block size (P0-46)

`reward_tests.cpp` pins the block rewards and the reward-derived block size
limit (plan 0.2f, review B1/B2): `GetProofOfWorkReward` (pre-fork `CBigNum`
bisection on `nBits`, post-fork `double`), `GetMaxSize` (all three modes),
`GetProofOfStakeReward`, `GetCoinAge` (every path, inputs from a block
written with `WriteBlockToTestFile` and indexed in `pblocktree`), the
coinstake limit in `Consensus::CheckTxInputs`, `LoadBlockRewardAndHighestDiff`
(it only logs; the test captures the log, see below) and `getsubsidy`.

**Golden table** `data/reward_vectors.json` (embedded as
`data/reward_vectors.json.h`), written and checked by
`contrib/testing/reward_vectors.py` without `CBigNum` or node code (Python
integers for the bisection, `SetCompact` from P0-13's model, Python floats
– IEEE-754 doubles – for the post-fork forms). One JSON object, one row per
line, every value a string: decimal amounts, `nBits` as 8 hex digits.

| Table | Row | Replayed by |
|---|---|---|
| `prefork_pow` | `nBits`, reward with target limit `0x1e0fffff` (mainnet build), reward with `0x201fffff` (low-difficulty build), source, note | `golden_prefork_pow`: `GetProofOfWorkReward(nBits, 0, 0)` and at height 1 below the mainnet fork give the column of the build; the bisection copy of `bignum_consensus_tests.cpp` gives both |
| `postfork_pow` | money supply, reward, `LoadBlockRewardAndHighestDiff` reward, max size for `MAX_BLOCK_SIZE`, `MAX_BLOCK_SIZE_GEN`, `MAX_BLOCK_SIGOPS`, source, note | `golden_postfork_pow_and_max_size`: supply on the block before an epoch start (epoch 10, fork 10), the real functions and the logged reward |
| `epochs` | epoch, supply before it, then the same five values as `postfork_pow` (no source/note) | `golden_per_epoch`: 60 epochs on one chain, every height of each epoch |
| `pos` | coin age (coin-days), reward | `golden_pos`, with several `nBits`/`nTime` (both ignored) |

`source` is `boundary` (edge values), `sweep` (regular grids: exponents
0x01–0x22 × 4 mantissas, 16 mantissas for each exponent 0x1a–0x1e, 40
spread supplies) or `mainnet`. There are no `mainnet` rows yet: the mainnet
dump (P0-09) does not exist. P0-23 adds every distinct pre-fork `nBits` of
the dump with `reward_vectors.py --write --mainnet-nbits LIST` (one hex
value per line; added to the `mainnet` rows already in the file, and a
value that is already a boundary or sweep row becomes a `mainnet` row); the
test and the checker need no change for that. The
`epochs` table is a **model** (supply 10^14 plus 21,000 blocks × reward per
epoch, no PoS, no fees), not mainnet history; real per-epoch supplies come
with P0-23's replay.

**What the tests pin** (details in the task file
`project/done/P0-46-reward-and-block-size.md`):

- Pre-fork: target ≤ 0 (zero, negative zero, negative) and target 1 give
  `CENT`; a target at or above the limit gives 100 YAC; `nFees` is added
  after the 100 YAC cap.
- Post-fork: `nMoneySupply * 0.02 / 525960` of the block before the epoch
  start (first epoch: the block before the fork; a height beyond the tip
  reads the tip, `FindBlockByHeight`); **`nFees` is ignored**.
  `nHeight == 0` always means pre-fork, even with fork height 0, so
  `GetMaxSize(mode)` on an empty `chainActive` in unit tests gives 1000 /
  500 / 20000.
- Max size = reward × 1000 / `MIN_TX_FEE` = reward / 10 bytes; `_GEN` half
  of it; `_SIGOPS` max(size, 10^6) / 50; before the fork 10^6 / 500,000 /
  20,000.
- `postfork_double_equals_integer` (B2): on this target both `double`
  forms (multiply first in `GetProofOfWorkReward`, divide first in
  `LoadBlockRewardAndHighestDiff`) equal the integer
  `floor(nMoneySupply / 26,298,000)` for every supply up to `MAX_MONEY`.
  The forms are monotone, so the test checks every step point and the value
  below it (76 million steps; 0.3 s in the `-O2` build). A replacement may use the
  integer form; P0-53 runs this test on the other targets.
- `GetProofOfStakeReward` = `nCoinAge * 1,650,000 / 12,053` (5 % a year),
  truncated toward zero; `nBits`/`nTime` unused. Coin age counts per input
  in cent-seconds (truncated per input), skips inputs younger than 30 days
  (block time) and inputs missing from the view, fails on a time
  violation, without `-txindex`, on an index miss, a read error or a txid
  mismatch. `-printcoinage` prints the sums in hex.
- `LoadBlockRewardAndHighestDiff` takes the highest epoch block at or
  above the fork; if the fork is not an epoch multiple and the tip is still
  in the first epoch it logs "something wrong" and reward 0.
- `getsubsidy`: the target is used only before the fork; `yacoin-cli`
  converts the argument as JSON, so the hex must be quoted.

**Log capture.** `LogCapture` (in `reward_tests.cpp`) sets
`fPrintToConsole` and points the stdout file descriptor at a file in the
test data directory (`dup`/`dup2`), so a test can check what `LogPrintf`
wrote; it restores both when it ends. Do not call `BOOST_CHECK` while it
captures. `ScopedArg` sets a `-switch` for a scope (afterwards it is `"0"`,
`ArgsManager` cannot remove an argument), `ScopedValue` a global such as
`fDebug` or `fTxIndex`.
