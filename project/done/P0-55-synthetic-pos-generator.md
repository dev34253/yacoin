# P0-55: Synthetic PoS block generator (test-only)

- Plan section: 0.5
- Depends on: P0-47
- Size: L
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Create valid proof-of-stake blocks in tests to reach branches the real chain never hits.

## Steps

1. Test-only helper that grinds a valid coinstake on a pre-fork test chain using mocktime and a target near the PoS limit (~0>>30).
2. Use it for PoS trust branches (P0-32), kernel overflow and mutation cases (P0-18/P0-25).

## Acceptance criteria

- [x] Generator produces blocks accepted by CheckProofOfStake; used by at least one trust and one kernel test.

## Notes

No CreateCoinStake exists in this tree. Review: A9, C8.

## Detailed description

### Findings from reading the code (step 1)

- "No CreateCoinStake exists" – correct: no `CreateCoinStake`/coinstake
  builder anywhere in `src/` (grep); the wallet only has kernel display code
  (`kernelrecord.cpp`).
- `CheckProofOfStake` (`kernel.cpp:573-625`) needs `fTxIndex`, the tx index
  in `pblocktree` and the stake's block on disk; it checks the coinstake's
  input-0 signature (DoS 100) and `CheckStakeKernelHash` (DoS 1). It takes
  `nBits` as a parameter and does not check it against
  `GetNextTargetRequired`.
- The kernel (`kernel.cpp:436-571`): hash = SHA256d(modifier, blockFrom
  time, tx offset, txPrev time, prevout n, nTimeTx) ≤ target(nBits) ·
  coin-day weight, weight = value · min(nTimeTx − txPrev.nTime − 30 d,
  90 d) / COIN / 86400; the modifier is the first one generated at least a
  selection interval (761,920 s ≈ 8.8 d, computed from
  `GetStakeModifierSelectionInterval`) after blockFrom
  (`GetKernelStakeModifier`, `kernel.cpp:335-384`, file-static).
- **Era.** Everything that makes a PoS block meaningful only runs before the
  fork height `nMainnetNewLogicBlockNumber` (0 in unit tests): modifiers are
  computed only for `nHeight + 1 < fork` (`validation.cpp:2987`,
  `kernel.cpp:189`), `AcceptBlock` runs `CheckProofOfStake` only below it
  (`validation.cpp:3504`), PoS `nBits` use the per-block ppcoin retarget
  below it (`pow.cpp:191-207`), coinbase maturity is 500 below it
  (`consensus.cpp:49-59`). The generator therefore targets the **pre-fork
  era**: the fixture sets the fork height to the mainnet value 1,890,000
  (harness `SetNewLogicBlockNumber`), everything else stays at the unit-test
  globals (N-factor 0 keeps header hashing cheap). Post-fork PoS is out of
  scope (after the fork only the header rule classifies PoS, no kernel is
  checked; see review A4/P0-17).
- **A block is PoS by its header** (`block.h:271-288`): `nTime <=
  nYac10HardforkTime` (1619048730, 2021-04-21 23:45:30 UTC), `nNonce == 0`, `nBits <=
  0x1d03ffff` (the PoS limit `~0 >> 30`, `pow.cpp:21`), or one of two
  hard-coded mainnet hashes. The chain times therefore lie in 2020 (mock
  time), before the Yac 1.0 time and after `CONSECUTIVE_STAKE_SWITCH_TIME`
  (2014, new trust rules).
- **The first two PoS blocks of a chain can never be accepted.**
  `GetNextTargetRequired044` (`pow.cpp:108-127`) returns `initialHashTarget`
  for the first and second PoS block (no earlier PoS block found by
  `GetLastBlockIndex`); `initialHashTarget` is `~0>>20` (0x1e0fffff,
  mainnet), `~0>>8` (low difficulty) or `0x7fff…` (0x207fffff, regtest),
  all above 0x1d03ffff, so a block with the required `nBits` is not PoS by
  the header rule, and a block with PoS `nBits` fails `bad-diffbits`. On
  mainnet the two hard-coded hashes presumably are the first two PoS
  blocks (not checked against the chain). A
  synthetic chain needs the same help: the generator **marks two early PoW
  index entries as PoS** (`SeedProofOfStakeHistory`, test-only, emulating
  the two hard-coded mainnet blocks). After that the required PoS `nBits`
  is the PoS limit 0x1d03ffff (retarget from a regtest PoW `nBits`,
  capped). Pinned by a test (unseeded: the generated block is rejected).
- PoS blocks also need (`CheckBlock`, `validation.cpp:3160-3190`): empty
  coinbase output, coinstake at `vtx[1]` with `vout[0]` empty, coinstake
  time = block time, `nNonce == 0`, a block signature by the key of the
  coinstake's `vout[1]` P2PK script (`CheckBlockSignature`,
  `validation.cpp:4870-4930`); `ConnectBlock`/`CheckTxInputs`
  (`tx_verify.cpp:393-421`): stake input ≥ 500 blocks deep (coinbase),
  reward ≤ `GetProofOfStakeReward` − min fee + CENT.
- Regtest is the only cheap chain for PoW blocks (powLimit `0x7fff…`);
  `HeliopolisHardforkHeight` 0 forces block version 7, whose hash uses
  `nFactorAtHardfork` (0 in unit tests).
- The unit-test genesis has no stake modifier (it was loaded with fork
  height 0); with the pre-fork fork height `ComputeNextStakeModifier` for
  block 1 would fail ("no generation at genesis block"). The fixture gives
  the genesis entry the modifier a pre-fork node computes for it (0,
  generated; `kernel_tests/harness_genesis_stake_modifier_checksum`). The
  height-0 modifier checkpoint (mainnet table, also used on regtest) is not
  evaluated because the genesis is already loaded.

### Scope

Test-only code; no node/consensus code changes (CLAUDE.md rule 1).

- New `src/test/pos_generator.{h,cpp}`: fixture `PosChainSetup`
  (regtest `ConsensusTestingSetup` + pre-fork fork height + mock time +
  fixed key + genesis modifier) with:
  - `MinePowBlock(parent, nTime, nSalt)`, `Submit(block, fForce, pfNew, pfAccepted)`
    (sets mock time to the block time, `ProcessNewBlock`, returns the
    entry), `MinePowChain(n, nSpacing)` (PoW blocks on the tip, coinbase
    100 YAC to the fixed P2PK key);
  - `SeedProofOfStakeHistory(a, b)`;
  - `FindKernel(pindexPrev, stake, nBits, nTimeFrom, nMaxTries)` – grinds
    `nTimeTx` second by second, using a copy of the modifier walk and the
    node's `GetProofOfStakeHash`; then checks the result with the node's
    `CheckStakeKernelHash` (throws on mismatch);
  - `CreateCoinstake(kernel)` (P2PK out = stake value, reward 0, signed),
    `CreatePosBlock(pindexPrev, kernel, nSalt)` (nBits from the kernel; empty coinbase,
    coinstake, merkle root, block signature) and
    `GeneratePosBlock(pindexPrev, stake, nSalt, pkernel)` = all of it with
    `nBits = GetNextTargetRequired(pindexPrev, true)`.
- New `src/test/pos_generator_tests.cpp`: generator tests (unseeded
  rejection pin; seeded chain accepts generated PoS blocks via
  `ProcessNewBlock`/`ConnectBlock`, PoS on PoS, UTXO and index fields).
- `kernel_tests.cpp`: one case using it (`CheckProofOfStake` accepts;
  mutations: time, signature, harder `nBits`, min age).
- `chain_trust_tests.cpp`: one case using it (fork choice with real PoS
  blocks, review C8).
- Docs: `src/test/README.md` (generator section), test counts
  (CLAUDE.md, `contrib/testing/README.md`, skill, `doc/architecture.md`),
  `project/known-issues.md` (first-two-PoS-blocks rule; PoS-on-PoS is not
  activated alone, if confirmed), Makefile.test.include.

Not in scope: P0-18/P0-25's full kernel overflow/mutation matrix (they can
build on the generator), the functional-test PoS chain (P0-32: a Python
generator would need RPC support that does not exist), post-fork PoS.

### Behaviour

Example: `MinePowChain(505, 6 h)` from 2020-01-01; seed blocks 2 and 3;
block 1's coinbase (100 YAC) is 504 blocks deep and 126 days old (full 90
day weight, coin-day weight 9000), target 2^226 · 9000 ≈ 2^239, so about
2^17 kernel hashes (≈ 0.1 s) find a time; the PoS block at that time is
accepted by `ProcessNewBlock` and becomes the tip.

### Edge cases

- Both builds: regtest params do not depend on the build flag; the mainnet
  modifier-checkpoint table differs only at height 0 (not evaluated).
- Unit-test globals restored afterwards (harness guard); mock time reset.
- Determinism: fixed key, fixed times, RFC6979 signatures → same blocks and
  same number of kernel tries in every run (no flakiness).
- Grind bound: `nMaxTries` (default 2^22) – failure throws with the count.
- Kernel before min age / no modifier yet: `FindKernel` starts at
  max(nTimeFrom, blockFrom + 30 d) and throws if the walk finds no
  modifier.
- Fork blocks (pindexPrev not on the active chain): the modifier walk
  follows pindexPrev's ancestors (what `GetKernelStakeModifier`'s temporary
  chain does).
- Mock time must not go backwards between blocks below MTP; `Submit` sets
  it to max(current, block time).
- Seeded entries keep the `bnChainTrust` computed as PoW (documented;
  tests compare trust only after them).

### How to test

| Criterion | Test | Expected |
|---|---|---|
| Accepted by CheckProofOfStake | `kernel_tests/synthetic_pos_kernel`, `pos_generator_tests/*` | true, hash ≤ target, hash = generator's |
| Accepted by ProcessNewBlock/ConnectBlock | `pos_generator_tests/generated_pos_blocks_connect` | tip = PoS block, PoS flag, stake spent, coinstake in UTXO |
| Unseeded rule pinned | `pos_generator_tests/first_pos_blocks_need_seed` | required nBits = 0x207fffff, block rejected |
| Trust test | `chain_trust_fork_choice_tests/fork_choice_with_pos_blocks` | PoS fork wins by 1; T + 1 after PoW on both; reorg back over the PoS block |
| Kernel test | `kernel_tests/synthetic_pos_kernel` | mutations rejected with DoS 1 (kernel) / 100 (signature); non-coinstake false with DoS 0 |
| No regressions | `build.sh` mainnet unit; lowdiff unit + functional | 375 / 375 / 47 (after merging P0-48: 381 / 381 / 48) |
| Fast | unit.log timing of the new cases | each case ≤ a few seconds |

### Risks

- Consensus: none (test code only). The seed flags only change index
  entries of the test's own temporary chain.
- Runtime: ~500 regtest blocks per case through `ProcessNewBlock` with
  `fCheckBlockIndex`; measured and documented.
- The modifier-walk copy could drift from kernel.cpp; the generator
  re-checks every kernel with the node's `CheckStakeKernelHash`.

## Implementation plan

1. **`src/test/pos_generator.h/.cpp`** (namespace `synthetic_pos`), added
   to `BITCOIN_TESTS` in `src/Makefile.test.include` next to the harness.
   - Constants: `START_TIME` 1577836800 (2020-01-01), `BLOCK_SPACING`
     6 h, `POS_LIMIT_BITS` = `bnProofOfStakeHardLimit.GetCompact()`
     (0x1d03ffff, asserted), `DEFAULT_MAX_TRIES` 1 << 22.
   - `struct Kernel { COutPoint prevout; CTransaction txPrev; CBlockHeader
     headerFrom; uint32_t nTxPrevOffset;
     uint64_t nStakeModifier; int nStakeModifierHeight; int64_t nTime; unsigned int nBits; uint256
     hashProofOfStake, targetProofOfStake; uint64_t nTries; }`.
   - `struct PosChainSetup : ConsensusTestingSetup` (REGTEST): constructor
     sets fork height 1,890,000 via `globals`, mock time `START_TIME`, the
     fixed key (secret 32 × 0x55, compressed) and gives the genesis entry
     modifier (0, generated) under `cs_main`. Methods:
     `Script()`, `MinePowBlock(parent, nTime, nSalt)`,
     `Submit(block, fForce=true, pfNew=nullptr, pfAccepted=nullptr)`,
     `MinePowChain(n, nSpacing)` → tip, `SeedProofOfStakeHistory(a, b)`,
     `FindKernel(pindexPrev, prevout, nBits, nTimeFrom=0,
     nMaxTries=DEFAULT_MAX_TRIES)`, `CreateCoinstake(kernel, nReward=0)`,
     `CreatePosBlock(pindexPrev, kernel, nSalt=0)`,
     `GeneratePosBlock(pindexPrev, prevout, nSalt=0, pkernel=nullptr)`,
     `CoinbaseOutPoint(h)`.
   - Kernel grind: read txPrev + header + offset from the tx index exactly
     like `CheckProofOfStake`; modifier by a copy of the
     `GetKernelStakeModifier` walk along pindexPrev's ancestors; target =
     `CBigNum(nBits) * weight` as uint256; loop nTime from max(nTimeFrom,
     blockFrom + nStakeMinAge (the kernel accepts exactly the minimum age),
     txPrev.nTime, pindexPrev time + 1);
     `GetProofOfStakeHash` ≤ target → stop; then verify with
     `CheckStakeKernelHash` (throw `std::runtime_error` on mismatch).
     `BOOST_TEST_MESSAGE` logs tries, time, hash (CLAUDE.md rule 5 for
     test code: Boost messages, as the harness does).
   - Verify: compiles; used by step 2-4 tests.
2. **`src/test/pos_generator_tests.cpp`** (suite `pos_generator_tests`):
   - `first_pos_blocks_need_seed`: chain without seed; required PoS nBits
     = regtest initialHashTarget compact (0x207fffff); header with that
     nBits is not PoS; a generated block with 0x1d03ffff passes
     `CheckProofOfStake` and `CheckBlock` but `ProcessNewBlock` rejects it
     (not in mapBlockIndex, tip unchanged).
   - `generated_pos_blocks_connect`: 505 blocks, seed 2 and 3; required
     nBits = 0x1d03ffff; PoS block on block 1's coinbase accepted, tip, PoS
     flag, `hashProofOfStake` = kernel's, stake spent, coinstake output in
     `pcoinsTip`, `nMint` 0; a second PoS block (stake: block 2's
     coinbase) on it is stored but (PoS after PoS, trust 0) not activated
     – verify the comparator behaviour, then a PoW block on it activates
     both.
3. **`kernel_tests.cpp`**: `synthetic_pos_kernel` (no seed, 130 blocks at
   1-day spacing; nBits = PoS limit): accepted; hash ≤ target; target =
   weight · target(nBits); mutations: coinstake time +1 (re-signed; if the
   hash still meets the target, the test picks the next failing second –
   decided by the generator's own hash), bad scriptSig → DoS 100, nBits
   one step harder chosen so the found hash fails → DoS 1, time before
   min age → false.
4. **`chain_trust_tests.cpp`**: `fork_choice_with_pos_blocks` (fixture
   `PosChainSetup`) in `chain_trust_fork_choice_tests`: base; PoW A, then
   PoS B on base: B − A = 1, reorg to B; PoW on both: difference T + 1;
   two more PoW on A: reorg back to A (disconnects a coinstake).
5. Build both configurations, run all tests, measure the time of the new
   cases (`--log_level=test_suite` timings / `--report_level`).
6. Docs: `src/test/README.md` section "Synthetic PoS blocks (P0-55)",
   counts in CLAUDE.md, `contrib/testing/README.md`, skill,
   `doc/architecture.md`; known-issues entries; task file.

## Log

- 2026-10-03 – step 0: moved to inprogress (branch task/P0-55-synthetic-pos-generator).
- 2026-10-03 – step 1/2: code read, claims verified; detailed description written.
- 2026-10-03 – step 3: self-review (no Agent tool) of the description against
  the code. Added: reorg back over a PoS block (DisconnectBlock of a
  coinstake) to the trust test; checked `GetMinFee(0)` = 0 so a reward-0
  coinstake passes `CheckTxInputs`; PoS-on-PoS activation to be verified,
  not assumed.
- 2026-10-03 – step 4: implementation plan written.
- 2026-10-03 – step 5: self-review (no Agent tool) of the plan. Added: grind
  starts at max(pindexPrev time + 1, blockFrom + min age, txPrev time)
  so the found time is a valid block time; the harder-nBits mutation is
  derived from the found hash (deterministic, no lucky pass); the
  generator asserts block times ≤ `nYac10HardforkTime`; the modifier walk
  copy follows pindexPrev's ancestors and throws where the node's walk
  could continue on `chainActive` past a fork point (not reached here,
  noted in the code). No consensus impact (test code only).
- 2026-10-03 – step 6: implemented `src/test/pos_generator.{h,cpp}`,
  `pos_generator_tests.cpp` (2 cases), `kernel_tests/synthetic_pos_kernel`,
  `chain_trust_fork_choice_tests/fork_choice_with_pos_blocks`. The plan
  held; the first build failed on a missing `validation.h` include in
  `kernel_tests.cpp` (and `build.sh` exited 141 without the error, known
  issue). All four cases passed on the first run.
- 2026-10-03 – step 7: `code-review` skill on the staged diff (medium).
  Findings: (1) README cost paragraph still a placeholder – filled with the
  measured times; (2) the walk-copy comment wrongly said the node only
  walks further "past a fork point" – rewritten: the node continues with
  `chainActive.Next` above pindexPrev whenever pindexPrev is active;
  recorded in `project/known-issues.md` (not reachable with sane
  timestamps). Both applied.
- 2026-10-03 – step 8: `build.sh --config mainnet --unit`: exit 0,
  375/375; `--config lowdiff --unit --functional`: exit 0, 375/375 and
  47/47 (before merging master). New cases (mainnet / lowdiff):
  `first_pos_blocks_need_seed` 0.05 / 0.05 s, `generated_pos_blocks_connect`
  0.42 / 0.39 s, `synthetic_pos_kernel` 0.07 / 0.05 s,
  `fork_choice_with_pos_blocks` 0.21 / 0.21 s. Kernel tries (fixed key,
  deterministic): 19,342 (130-block chain), 37,923 and 217,886 (505-block
  chain).
- 2026-10-03 – step 9: docs: `src/test/README.md` "Synthetic
  proof-of-stake blocks (P0-55)", `doc/architecture.md`, counts in
  CLAUDE.md, `contrib/testing/README.md`, the skill; plan table row
  (`phase0-test-safety-net.md` 0.5); `project/known-issues.md`: a new chain
  cannot start PoS (first two PoS blocks), PoS on PoS is not activated
  alone, kernel modifier walk past pindexPrev, and the `build.sh` 141 note.
  The claim that the two hard-coded hashes are the first mainnet PoS
  blocks is marked "presumably" (not checked: the committed dump starts at
  height 500,040).
- 2026-10-03 – step 10: `code-review` skill as documentation review
  against code and results. Applied: wrong line ranges
  (`kernel.cpp:573-625`, `chain.cpp:96-97`, `block.h:271-288`,
  `kernel.cpp:335-384`, `build.sh:455-456`), `nYac10HardforkTime` date
  (2021-04-21 23:45:30 UTC), task file plan/description aligned with the
  built signatures (`Kernel` fields, `Submit`'s `pfAccepted`,
  `CreatePosBlock` without nBits, `GeneratePosBlock`'s `pkernel`, grind
  start without "+1"), How-to-test rows corrected, Log completed.
- 2026-10-03 – merged origin/master (P0-48, #77: 377 unit / 48 functional);
  counts set to 381 unit (377 + 4) and 48 functional.
- 2026-10-03 – step 8 after the merge: `build.sh --config mainnet --unit`
  exit 0, 381/381; `--config lowdiff --unit --functional` exit 0, 381/381
  and 48/48.
- 2026-10-03 – step 11: moved to done; committed, pushed, PR opened.
  Open points: PoS in the functional test of P0-32 (no Python generator;
  would need block submission of hand-built PoS blocks and the same seed
  problem – a new chain cannot start PoS); P0-18/P0-25 can extend
  `synthetic_pos_kernel` with overflow and further mutations; the two
  hard-coded PoS hashes were not checked against early mainnet heights.
