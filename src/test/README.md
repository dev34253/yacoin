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
`chain_trust_p2p_tests`, see below), `kernel_tests`.

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
