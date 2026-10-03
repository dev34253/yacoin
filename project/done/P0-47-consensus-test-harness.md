# P0-47: Consensus test harness and global-state fixture

- Plan section: 0.2
- Depends on: P0-01
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-02
- Finished: 2026-10-03

## Goal

Give all consensus unit tests one way to build chains and set global state.

## Steps

1. Block-index / chainActive / mapBlockIndex builder with chosen heights, times, nBits, PoW/PoS flags and stake fields.
2. Explicit setters (and restore on teardown) for nMainnetNewLogicBlockNumber, nFactorAtHardfork, nEpochInterval/nDifficultyInterval, fTestNet, tokenSupportBlockNumber.
3. Mocktime helpers; temporary block files (genesis on disk for the retarget, blocks for ReadBlockFromDisk).
4. Loader that builds index chains from the P0-09 fixture.

## Acceptance criteria

- [x] Harness used by at least one test in pow, trust and kernel suites
  (`pow_tests/harness_*` ×2, `chain_trust_tests` ×2, `kernel_tests` ×3).
- [x] Globals are restored after each test (no cross-test leakage)
  (`consensus_harness_tests/globals_*`, `chain_builder_basic`).

## Notes

Review: A4, B7, D7.

## Detailed description

### Findings from reading the task (step 1)

- `tokenSupportBlockNumber` in the task is the `static const` default in
  `init.cpp:74` (1,911,210); the mutable global is `nTokenSupportBlockNumber`
  (`util.cpp:576`, set in `init.cpp:1145`). The harness sets the global. The
  same holds for `mainnetNewLogicBlockNumber` (`init.cpp:72`, 1,890,000) vs
  `nMainnetNewLogicBlockNumber` (`util.cpp:575`, set in `init.cpp:1144`).
  Both defaults are `static` in `init.cpp`, so the harness repeats the values
  with a reference to the source line.
- `nEpochInterval` and `nDifficultyInterval` are both set from
  `-epochinterval` in `init.cpp:858-859`; the harness offers one setter that
  sets both (as `AppInit` does) and one for `nDifficultyInterval` alone.
- `nYac10HardforkTime` (`util.cpp:578`) is a mutable global that decides
  `CBlockHeader::IsProofOfStake()` (`primitives/block.h:278`). Not in the
  task list, but it is consensus state, so the harness saves/restores it too.
- `CalculateNextWorkRequired` (`pow.cpp:54-58`) dereferences
  `mapBlockIndex.find(*pindexLast->phashBlock)` without an end check: every
  index entry with a hash that is passed to it must be in `mapBlockIndex`.
  The harness inserts all its entries.
- `GetNextTargetRequired044` (`pow.cpp:174-176`) reads
  `chainActive.Genesis()` from disk when `pindexLast->nHeight <=
  nDifficultyInterval + 1`; the result of `ReadBlockFromDisk` is ignored, only
  the genesis time is used. `TestingSetup` already writes the real genesis
  to a temporary datadir (`LoadGenesisBlock`); the harness can build chains
  on top of that on-disk genesis.
- `UnloadBlockIndex()` (`validation.cpp:4180`, called by `~TestingSetup`)
  deletes every `mapBlockIndex` entry. Harness entries are owned by the
  harness and must be removed from `mapBlockIndex` before that.
- `ComputeNextStakeModifier` (`kernel.cpp:189`) and
  `CheckStakeModifierCheckpoints` (`kernel.cpp:651`) return early when
  `chainActive.Tip()->nHeight + 1 >= nMainnetNewLogicBlockNumber` – with the
  unit-test value 0 always (review A4). Their behaviour depends on
  `chainActive`, not on the block passed in.
- Step 4 (loader for the P0-09 fixture): P0-08 (dump tool and format) and
  P0-09 (fixture) are not done, so there is no fixture format yet. The
  harness defines a small, documented CSV *index-chain* format with named
  columns and a loader for it; P0-08/P0-09 emit these columns (or extend the
  loader). A note is added to both task files. Tested with inline data.
- The acceptance criterion "used by at least one test in pow, trust and
  kernel suites": only `pow_tests` exists. This task adds `chain_trust_tests`
  and `kernel_tests` with a few harness-based tests that pin current
  behaviour; P0-16/P0-17/P0-18 extend them.
- Existing `pow_tests/get_next_work_one_third_highest_difficulty` points
  `chainActive` at stack-local entries and never resets it; `~TestingSetup`
  resets the tip, so there is no leak today. It is left unchanged (P0-14
  owns the pow tests).

### Scope

New test-only code in `src/test/`, nothing in the node/consensus sources:

- `src/test/consensus_harness.h/.cpp` – the harness:
  1. `ConsensusGlobals` – a snapshot of `nMainnetNewLogicBlockNumber`,
     `nTokenSupportBlockNumber`, `nFactorAtHardfork`, `nEpochInterval`,
     `nDifficultyInterval`, `fTestNet`, `nYac10HardforkTime` and the mock
     time; `ScopedConsensusGlobals` saves them on construction and restores
     them on destruction, with explicit setters and three presets:
     `UseUnitTestGlobals()` (0/0/0, epoch 21000, fTestNet false – what
     `test_bitcoin` has without `AppInit`), `UseMainnetGlobals()` (fork
     1,890,000, token 1,911,210, Nf 21, epoch 21000) and
     `UseFunctionalTestGlobals(forkHeight)` (epoch 10, Nf 4, fork height as
     given).
  2. `TestChain` – builds `CBlockIndex` chains: `Append(spec)` on its tip,
     `Append(prev, spec)` for forks, `AppendMany(n, ...)` for uniform runs,
     `StartOnExistingGenesis()` to build on the real on-disk genesis,
     `AppendBlock(block, writeToDisk)` for real `CBlock`s (hash =
     `block.GetHash()`, optionally written to a temporary block file so
     `ReadBlockFromDisk` works). Each entry gets height, `nTime`, `nBits`,
     `nVersion`, `nNonce`, merkle root, PoS flag, entropy bit, stake modifier
     (+generated flag), `hashProofOfStake`, `prevoutStake`, `nStakeTime`, a
     unique deterministic synthetic hash (or the given one), `pskip`,
     `nTimeMax` and `bnChainTrust = pprev->bnChainTrust + GetBlockTrust()`
     like `AddToBlockIndex` (`validation.cpp:2931-2934`). Entries are put in
     `mapBlockIndex`. `SetActiveTip(pindex)` sets `chainActive`. On
     destruction: `chainActive` back to the tip it had before the first
     `SetActiveTip`, own entries erased from `mapBlockIndex` and freed.
     `pindexBestHeader`, `setBlockIndexCandidates` and the block tree DB are
     never touched.
  3. `WriteBlockToTestFile(block)` – appends a block in the node's on-disk
     format (message start, size, block) to a dedicated file
     `blocks/blk09000.dat` in the test datadir (never the node's own
     `blk00000.dat`) and returns the `CDiskBlockPos`. The block-hash index in
     `pblocktree` is not written; `ReadBlockFromDisk` then recomputes the
     hash (`validation.cpp:866-870`, one log line), which is what we want to
     test anyway.
  4. `LoadIndexChainCsv(istream, chain)` / `LoadIndexChainCsvFile(path,
     chain)` – loader for the index-chain format (below).
  5. `ConsensusTestingSetup` – Boost fixture: `TestingSetup` (temporary
     datadir, genesis on disk, `chainActive` at genesis) plus a
     `ScopedConsensusGlobals globals` and a `TestChain chain` member,
     destroyed (chain first, then globals) before `TestingSetup`.
- `src/test/consensus_harness_tests.cpp` – tests of the harness itself.
- `src/test/pow_tests.cpp` – new harness-based tests (existing ones
  unchanged).
- `src/test/chain_trust_tests.cpp`, `src/test/kernel_tests.cpp` – new suites.
- `src/Makefile.test.include` – the new files.
- Docs: `src/test/README.md` (harness section), `doc/` not affected (no
  user-facing change), plan 0.1/0.2 wording if needed, notes in P0-08/P0-09
  task files, `CLAUDE.md`/`contrib/testing/README.md` unit-test counts.

Not done here: exhaustive pow/trust/kernel coverage (P0-14, P0-16, P0-17,
P0-18), the dump tool and real fixture (P0-08, P0-09), any change to
consensus or node code.

### Index-chain CSV format

```
# comment lines and blank lines are ignored
height,hash,prev_hash,time,bits,version,nonce,merkle_root,flags,stake_modifier,hash_proof_of_stake,prevout_stake,stake_time
0,<64 hex>,,1367991200,0x1e0fffff,1,...
```

- First non-comment line: column names, any order; unknown columns are
  ignored (so P0-08 can add more). Required: `height`, `hash`, `time`,
  `bits`. Optional: the rest (default 0 / null).
- Integers: decimal, or hex with `0x` prefix. Hashes: 64 hex digits, RPC
  byte order (as `uint256S`). `prevout_stake`: `<txid>:<n>`, empty = null.
  `flags` is `CBlockIndex::nFlags` (bit 0 PoS, bit 1 entropy, bit 2
  generated modifier).
- Rows must have strictly consecutive heights. The first row links to
  `prev_hash` if that hash is already in `mapBlockIndex`, otherwise it starts
  a segment (`pprev = nullptr`, height from the file). For later rows a given
  `prev_hash` must equal the previous row's hash.
- Errors throw `std::runtime_error` with the line number: missing required
  column, wrong field count, bad number/hash, gap in heights, `prev_hash`
  mismatch, duplicate hash.

### Behaviour (examples)

```cpp
BOOST_FIXTURE_TEST_CASE(x, ConsensusTestingSetup) {
    globals.UseMainnetGlobals();            // restored after the test
    globals.SetMockTime(1400000000);
    chain.StartOnExistingGenesis();         // real genesis, on disk
    chain.AppendMany(9, 60, 0x1d00ffff);    // 9 PoW blocks, 60 s apart
    chain.SetActiveTip(chain.Tip());        // chainActive -> harness chain
    GetNextTargetRequired(chain.Tip(), false);
}
```

### Edge cases

- Both build configurations: expected values are computed from
  `Params().GetConsensus()` (powLimit, initialHashTarget, genesis) or chosen
  so that they do not depend on them; no value differs between mainnet and
  low-difficulty builds except where explicitly `#ifdef`'d.
- Unit-test globals at 0 vs mainnet values: tests run both modes where the
  function's behaviour differs (stake modifier, checkpoints).
- Segments starting above height 0 (`pprev == nullptr`): `GetAncestor` below
  the segment and `chainActive.Genesis()` are null – documented limitation;
  `GetBlockTrust()` of the first entry uses `pprev == nullptr` rules.
- Hash collisions: synthetic hashes are SHA256d of a tag, a per-chain salt
  and a counter; inserting a hash that is already in `mapBlockIndex` throws.
- Restore when a test fails or throws: all restoration is in destructors.
- Restore order: chain before globals before `TestingSetup` (members are
  destroyed in reverse order, before the base class).
- Mock time: restored to the value at fixture start (not forced to 0),
  because other suites (e.g. `DoS_tests`) leave it set.
- Large heights (1.9 M) are fine: entries are allocated per block, chains
  for these tests are short.
- `fCheckBlockIndex` is on in tests: harness chains must not be mixed with
  `ProcessNewBlock`/`ActivateBestChain` in the same test (documented).
- Entropy bit, PoS flag and generated-modifier flag come from the spec
  (default 0/PoW/false), not from the hash as in `AddToBlockIndex`; tests
  that need the node's derivation use `AppendBlock(block)`, which uses the
  `CBlockIndex(header)` constructor and `block.GetStakeEntropyBit()`.
- `GetStakeModifierChecksum` `Yassert`s that a height-0 entry is the real
  genesis (`kernel.cpp:636-638`): kernel tests that reach height 0 use
  `StartOnExistingGenesis()`.
- Several `TestChain`s in one test: each restores `chainActive` in its
  destructor; they must be destroyed in reverse order of `SetActiveTip`
  (automatic for locals). `mapBlockIndex`/`chainActive` changes take
  `cs_main`.
- `nYac10HardforkTime`: presets set it to its compiled default
  (1,619,048,730).
- The "before/after" leakage tests rely on Boost running test cases in
  declaration order (the default; not with `--random`). The nested-guard
  test checks restoration independently of order.
- Loader: empty input (no header) → error; header only → no blocks;
  CRLF line endings accepted; trailing spaces not.

### How to test

| Criterion | Test | Expected |
|---|---|---|
| Globals set and restored | `consensus_harness_tests/globals_restored` (nested guard, presets, mocktime) | values restored to snapshot |
| No cross-test leakage | `consensus_harness_tests/globals_at_defaults_{before,after}` around a test that changes everything | defaults seen in both |
| Chain builder | `consensus_harness_tests/chain_builder_*` (heights, links, pskip, trust sum, mapBlockIndex, chainActive set/restored, forks) | as specified |
| Genesis/blocks on disk | `consensus_harness_tests/block_files` (`ReadBlockFromDisk` of real genesis and of an appended block) | read back, hash matches |
| Loader | `consensus_harness_tests/csv_loader_*` (valid data, segment, linking, every error) | as specified |
| pow suite uses harness | `pow_tests/harness_*`: post-fork retarget at an epoch boundary with genesis read from disk; pre-fork per-block retarget | pinned values, both configs |
| trust suite uses harness | `chain_trust_tests/*`: trust branches on a harness chain, `fTestNet` switch | pinned values |
| kernel suite uses harness | `kernel_tests/*`: checkpoint check and stake-modifier early return in unit vs mainnet mode | pinned behaviour |
| Nothing else changes | `build.sh --config mainnet --unit`; `--config lowdiff --unit --functional` | mainnet all pass (239 + new); lowdiff only the known P0-02 failure; 45/45 functional |

### Risks

- Consensus code is not touched (rule 1); only tests are added. The tests
  pin current behaviour, including A4 (early returns) and review A7 trust
  rules.
- A harness bug could leave dangling pointers in `chainActive` /
  `mapBlockIndex` and crash a later test – mitigated by the restore tests and
  the full unit run.
- Logging (rule 5): no daemon code changes. Harness actions are reported with
  `BOOST_TEST_MESSAGE` (visible with `--log_level=message`), since
  `test_bitcoin` disables `debug.log`.

## Implementation plan

1. **Harness header and globals** – `src/test/consensus_harness.h/.cpp`:
   `ConsensusGlobals` (struct + `Capture()`/`Apply()`), `ScopedConsensusGlobals`
   (ctor captures, dtor applies; setters `SetNewLogicBlockNumber`,
   `SetTokenSupportBlockNumber`, `SetNFactorAtHardfork`, `SetEpochInterval`
   (both intervals), `SetDifficultyInterval`, `SetTestNet`,
   `SetYac10HardforkTime`, `SetMockTime`; presets `UseUnitTestGlobals`,
   `UseMainnetGlobals`, `UseFunctionalTestGlobals(fork)`), named constants
   for the `init.cpp` defaults. Add to `Makefile.test.include`.
   *Verify:* compiles; `consensus_harness_tests/globals_*`.
2. **Chain builder** – `BlockSpec` (all fields, defaults), `TestChain`
   (`StartOnExistingGenesis`, `Append`, `Append(prev, …)`, `AppendMany`,
   `AppendBlock(block, fWriteToDisk)`, `Tip`, `operator[]`/`AtHeight`,
   `SetActiveTip`, `size`, dtor restore). Synthetic hash = SHA256d("P0-47
   TestChain", salt, counter); throws on duplicates. `LOCK(cs_main)` around
   `mapBlockIndex`/`chainActive` changes.
   *Verify:* `consensus_harness_tests/chain_builder_*`.
3. **Block files** – `WriteBlockToTestFile(block)` (file 9000, append,
   on-disk format of `WriteBlockToDisk`); used by `AppendBlock(…, true)`
   which sets `nFile`/`nDataPos`/`BLOCK_HAVE_DATA`.
   `AppendBlock` links to the entry of `block.hashPrevBlock` if that is in
   `mapBlockIndex`, otherwise starts a segment (same rule as the loader).
   *Verify:* `consensus_harness_tests/block_files` – `ReadBlockFromDisk`
   of the on-disk genesis via the harness chain, and of an appended block
   whose header is PoS by `CBlockHeader::IsProofOfStake()` rules
   (`nNonce == 0`, `nTime <= nYac10HardforkTime`, `nBits <= 0x1d00ffff`;
   skips the PoW check, so no grinding) with version 6 and a 2013 time
   (low N-factor, fast hash).
4. **CSV loader** – `LoadIndexChainCsv(std::istream&, TestChain&)`,
   `LoadIndexChainCsvFile(path, TestChain&)`; strict number/hash parsing.
   *Verify:* `consensus_harness_tests/csv_loader_*` (valid file incl. comments,
   CRLF, unknown column, optional columns; segment start at height
   1,889,998; linking to an existing hash; each error case).
5. **Fixture** – `ConsensusTestingSetup : TestingSetup { ScopedConsensusGlobals
   globals; TestChain chain; }` and leakage tests.
6. **Suite usage** (pin current behaviour; expected values computed from
   `Params()` or config-independent):
   - `pow_tests`: (a) post-fork epoch retarget with `SetEpochInterval(10)`
     on the on-disk genesis (`GetNextTargetRequired` at height 10 →
     `CalculateNextWorkRequired` with genesis time, `nMinEase` scan through
     `mapBlockIndex`); (b) the same chain at height 5 keeps the target;
     (c) pre-fork (`UseMainnetGlobals`) per-block retarget (old ppcoin
     branch) vs the formula; first/second block → `initialHashTarget`.
   - `chain_trust_tests`: trust per branch on a harness chain after
     `CONSECUTIVE_STAKE_SWITCH_TIME` (genesis 1, PoW powLimit/target, PoS
     after PoW prev+1, PoS after PoS 0, PoW after PoS ×2), accumulated
     `bnChainTrust`; legacy rules before the switch time and the `fTestNet`
     switch.
   - `kernel_tests`: `CheckStakeModifierCheckpoints` with unit globals
     (early return → true) vs mainnet globals (wrong checksum → false, right
     one → true) vs `fTestNet`; `ComputeNextStakeModifier` early return
     (outputs untouched) vs mainnet mode on a short chain (genesis →
     generated, modifier 0; same interval → not generated, last modifier).
7. **Build and run** both configurations (step 8), fix, re-review.
8. **Docs** – `src/test/README.md` (harness usage, CSV format, limits),
   `contrib/testing/README.md` and `CLAUDE.md` unit counts, plan 0.2 pointer,
   notes in P0-08/P0-09 (CSV columns) and P0-14/16/17/18 (suites exist).
   No `debug.log` logging (test-only code; `BOOST_TEST_MESSAGE` instead).

## Log

- 2026-10-02 – Step 0: picked up; dependency P0-01 is in done/; moved to inprogress/
- 2026-10-02 – Steps 1–2: task read against the code; findings and detailed
  description above (task names `tokenSupportBlockNumber`, the global is
  `nTokenSupportBlockNumber`; no P0-08/P0-09 format yet, so the harness
  defines the index-chain CSV format; trust and kernel suites do not exist
  yet and are created here).
- 2026-10-02 – Step 3: description review – self-review (no Agent tool).
  Applied: do not write the block-hash index (keeps `pblocktree`
  untouched, contradicted the scope); document spec-driven entropy/PoS
  flags; `GetStakeModifierChecksum` genesis `Yassert`; multiple chains and
  `cs_main`; `nYac10HardforkTime` preset value; test-order dependence of the
  leakage tests. Not applied: none.
- 2026-10-03 – Step 4–5: implementation plan written; plan review –
  self-review (no Agent tool). Applied: `AppendBlock` parent rule; exact
  conditions for the PoS-header disk test block (and low N-factor time so
  hashing stays fast). Checked: post-fork test path (height 9, epoch 10 →
  DAA → genesis read → `CalculateNextWorkRequired`) and pre-fork path need
  ≥ 3 blocks; no consensus file in the plan. Not applied: none.
- 2026-10-03 – Step 6: implemented `src/test/consensus_harness.{h,cpp}`,
  `consensus_harness_tests.cpp` (12 cases), 2 harness cases in
  `pow_tests.cpp`, new suites `chain_trust_tests.cpp` (2) and
  `kernel_tests.cpp` (3). Deviation from the plan: `TestChain` computes
  `pskip` itself (same pointer as `BuildSkip()`, checked by a test) because
  `BuildSkip()` asserts on segments that start above height 0; `AtHeight()`
  uses the same assert-free walk. No consensus or node source changed.
- 2026-10-03 – Step 7: `code-review` skill (medium) on the staged diff.
  One finding, applied: `CChain::SetTip` keeps stale slots below a segment
  start (the real genesis stayed `chainActive.Genesis()`), contrary to the
  docs. `SetActiveTip()` and the destructor now clear `chainActive` first;
  test added in `chain_builder_specs_forks_segments`. The fix is small and
  was re-checked by hand (self-review); no further findings.
- 2026-10-03 – Step 8: tests (`contrib/testing/build.sh --jobs 2`, image
  pinned P0-57):
  - mainnet: unit 258/258 passed (239 before + 19 new), exit 0;
  - lowdiff: unit 257/258 – the only failure is the known
    `pow_tests/get_next_work_pow_limit` (P0-02), exit 1 as expected;
    functional 45/45 (`ALL ... Passed`).
  All new tests pass in both configurations (expected values come from
  `Params()` or are `#ifdef`'d where they differ, e.g. the genesis stake
  modifier checksum 0x0e00670b / 0xfd11f4e7).
- 2026-10-03 – Step 9: docs – `src/test/README.md` (harness section, CSV
  format, limits), `CLAUDE.md` (harness bullet, counts 258/257),
  `contrib/testing/README.md` and the implement-task skill (counts), plan
  0.1 pointer, notes in P0-08, P0-09, P0-14, P0-16, P0-17, P0-18.
- 2026-10-03 – Step 10: documentation review – self-review (no Agent tool):
  checked every README/header statement against the code and the test runs
  (presets table, CSV example field count, default values, segment
  behaviour after the step-7 fix). Not applied: `project/plans/overview.md`
  keeps its historical 238/239 baseline (it records the state at review
  time, not today's count).
- 2026-10-03 – Step 11: committed d6577b6, pushed, PR https://github.com/dev34253/yacoin/pull/52
- Open points: P0-08 must emit (or adapt the loader to) the CSV columns;
  logging uses `BOOST_TEST_MESSAGE` only (test code, `debug.log` is off in
  `test_bitcoin`); the existing `pow_tests` were left unchanged (P0-14).
