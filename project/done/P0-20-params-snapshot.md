# P0-20: Chain parameter and global-settings snapshot

- Plan section: 0.2h
- Depends on: P0-01
- Size: S
- Owner: Claude (subagent of owner session, laptop)
- Started: 2026-10-02
- Finished: 2026-10-03

## Goal

Make accidental parameter changes fail loudly, for all three parameter sets.

## Steps

1. Mainnet: powLimit, genesis, checkpoints, stake-modifier checkpoints, ports, message start, fork height 1,890,000, N-factor at fork 21.
2. Functional-test set: low-difficulty genesis, epochinterval 10, nFactorAtHardfork 4, per-test fork height.
3. Unit-test defaults: the globals left at 0 (document as-is).
4. CRegTestParams (same magic and port as main) for completeness.

## Acceptance criteria

- [x] Tests pass in both build configurations; parameter table added to the plan.

## Notes

Review: A3, A4.


## Detailed description

### Facts checked against the code (step 1)

- Mainnet (`CMainParams`, `src/chainparams.cpp:73-228`): powLimit
  `~uint256(0) >> 20` (compact `0x1e0fffff`), low-diff build `>> 3`
  (`0x201fffff`); initialHashTarget `>> 20` / `>> 8` (`0x2000ffff`);
  initialMoneySupply 0 / 1E14; genesis nonce 127357 / 127358, hash
  `0000060f…53e5` / `1ddf335e…8848` (Yasserted at `chainparams.cpp:130-134`),
  same merkle root `678b7641…244f`; message start `d9 e6 e7 e5`, P2P port
  7688; BIP65/BIP68/Heliopolis heights 1,890,000; 51 checkpoints (height 0 =
  the build's genesis, last 1,911,210; checkpoint 1,750,000 `d1806e1f…` has
  no leading zeros – recorded as is); `fMiningRequiresPeers` true / false;
  no DNS seeds (all `vSeeds` lines commented out).
  Fixed seeds: 7 IPv4 seeds on 7688 in the mainnet build, **none** in the
  low-diff build (`chainparamsseeds.h:10-22`).
- Fork height 1,890,000, token height 1,911,210 and N-factor 21 are not chain
  params: they are file-static defaults in `init.cpp:72-74,858-860,1144-1145`
  copied into the globals `nMainnetNewLogicBlockNumber`,
  `nTokenSupportBlockNumber`, `nFactorAtHardfork`, `nEpochInterval`
  (`util.cpp:575-581`). Unit tests cannot read the `init.cpp` statics; only
  `debug.log` shows the values a node really uses (`init.cpp:861,1146`).
  `nTokenSupportBlockNumber` was **not logged** at all before this task.
- Stake-modifier checkpoints: file-static `mapStakeModifierCheckpoints` in
  `kernel.cpp:33-65` (26 entries; height 0 differs per build:
  `0x0e00670b` / `0xfd11f4e7`), testnet table `kernel.cpp:68-71` (height 0
  only). Only observable through `CheckStakeModifierCheckpoints`
  (`kernel.cpp:649`), which returns true early unless the fork height is above
  the tip (review A4) – the P0-47 harness sets the globals.
- Functional-test set (review A3): the framework never passes `-regtest`
  (`self.chain = 'regtest'` is only a name, `test_framework.py:95`), writes
  `epochinterval=10` and `nFactorAtHardfork=4` to `yacoin.conf`
  (`util.py:323,347,353`) and passes `-testnetNewLogicBlockNumber=<block_fork_1_0>`
  (default 0, `test_node.py:100`, `test_framework.py:102`). **Correction to
  the task:** the cached 40-block chain is created with
  `epochinterval=20` (`test_framework.py:540`); the per-test datadirs then get
  10 (`test_framework.py:591,599`). Confirmed in an existing run:
  `cache/node0/debug.log` logs `Param nEpochInterval = 20`.
- `CRegTestParams` (`chainparams.cpp:233-314`): same message start and P2P
  port as main (A3), but RPC port 17687 and datadir `regtest`
  (`chainparamsbase.cpp:57-64`); powLimit `0x7fff…` (`0x207fffff`), genesis
  `08603b3b…4e2e`, nonce 127357, all fork heights 0, `nPowTargetTimespan` 10,
  `fPowAllowMinDifficultyBlocks` and `fPowNoRetargeting` true, mainnet fixed
  seeds (`pnSeed6_main`, so 7 in the mainnet build and 0 in the low-diff
  build); otherwise not affected by the low-diff flag. Extra finding: `-testnet` has base
  params (RPC port 17687, `testnet3`) but `CreateChainParams("test")` throws
  `Unknown chain test` (`chainparams.cpp:323-330`).
- Unit-test globals (A4): `nMainnetNewLogicBlockNumber`,
  `nTokenSupportBlockNumber`, `nFactorAtHardfork` 0 (zero-initialised, never
  set without `AppInit`); `nEpochInterval` = `nDifficultyInterval` = 21000;
  `fTestNet` false; `nYac10HardforkTime` 1619048730.
- The N-factor schedule by time (`primitives/block.h:173-202`) is P0-19, not
  this task.

### Scope

In scope (test and documentation only, plus one log line; the
`StartShutdown()` stub change in `test_bitcoin_main.cpp` was added after the
plan review, see Implementation plan 2a):
1. New unit-test file `src/test/chainparams_snapshot_tests.cpp` (added to
   `src/Makefile.test.include`) pinning, per build with
   `#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT` where the value differs:
   - main: network id, every `Consensus::Params` field (powLimit,
     initialHashTarget, initialMoneySupply, BIP65/68/Heliopolis heights,
     timespan, spacing, retarget flags, versionbits threshold/window and both
     deployments, stake min/max age, modifier interval, genesis hash),
     genesis block (hash, merkle root, nTime = `nChainStartTime`+20,
     nBits, nNonce, nVersion, one tx with tx nTime `nChainStartTime`),
     message start, P2P port, RPC port (base params), prune height, base58
     prefixes, fixed seeds (count, address bytes, ports), flags
     (consistency checks, require standard, mine on demand, mining requires
     peers), the full checkpoint table, `chainTxData`, `nChainStartTime`.
   - regtest: the same field list, with emphasis on "same magic and P2P port
     as main".
   - `CreateChainParams("test")` and an unknown name throw
     `std::runtime_error`.
   - `DifficultyAdjustmentInterval()` (main 21000; regtest 0 = 10 / 60),
     DNS seeds empty, base params (RPC port and data directory) for main
     (7687, ``), testnet (17687, `testnet3`) and regtest (17687, `regtest`).
   - stake-modifier checkpoints: for every one of the 26 heights,
     `CheckStakeModifierCheckpoints(h, v)` is true and `(h, v ^ 1)` false with
     mainnet globals (harness); the table size is pinned by a sweep over all
     heights 0 … 2,000,000: exactly the 26 pinned heights reject both 0 and
     0xffffffff (no checkpoint has either value); with `fTestNet` set, only
     height 0 does. (Extends the spot checks in `kernel_tests.cpp:26-41`.)
   - unit-test globals: already pinned by P0-47
     (`consensus_harness_tests.cpp:24-35`, `globals_at_defaults_*`), and
     the harness copies of the fork/N-factor/epoch defaults are pinned with
     literals there too (`:100-111`), so not duplicated; this task pins only
     `nChainStartTime` and `nYac10HardforkTime` (`time_constants`).
2. New functional test `test/functional/feature_params_snapshot.py` (added to
   `BASE_SCRIPTS`):
   - `setup_clean_chain = True` (only the genesis block: the cached chain
     was mined with fork height 0 and would be re-checked under pre-fork
     rules after the restart, `checkblocks=8`).
   - node started by the framework: the whole `debug.log` (start-up happens
     in `setup_nodes`, before `run_test`) reports
     `Param nEpochInterval = 10, nFactorAtHardfork = 4` and
     `Param nMainnetNewLogicBlockNumber = <block_fork_1_0>`; the test sets
     a non-zero `block_fork_1_0` (e.g. 7) to prove the per-test value is
     used; genesis via RPC (`getblockhash 0`, `getblock`) is the low-diff
     genesis (hash, merkle root, time, nonce, bits `201fffff`, version 1).
   - restart with the framework values removed – the existing
     `yacoin.conf` is edited in place (only the `epochinterval=` and
     `nFactorAtHardfork=` lines removed, so ports and `bind=` stay) and
     `-testnetNewLogicBlockNumber=` is filtered out of `node.args`
     (ArgsManager cannot unset an argument): `assert_debug_log` around the
     restart sees the compiled-in defaults 21000 / 21 / 1,890,000 /
     1,911,210.
3. One new always-on log line in `init.cpp` next to the existing one:
   `Param nTokenSupportBlockNumber = %d` (rule 5; makes the token height
   observable so step 2 can pin it). No value or behaviour changes.
4. Documentation: parameter table in
   `project/plans/phase0-test-safety-net.md` section 0.2h (and the 0.1
   table corrected for the cache epoch interval), `src/test/README.md`
   (new test file), CLAUDE.md counts, task file.

Out of scope: changing any parameter value or the regtest/testnet oddities
(recorded only); N-factor schedule (P0-19); stake-modifier computation
(P0-17); the functional cache's epoch interval 20 (recorded only).

### Behaviour

Any edit to a pinned value – e.g. a checkpoint hash, the port, the powLimit
shift, a stake-modifier checkpoint, `-epochinterval` default in `init.cpp`,
`epochinterval=10` in `util.py` – makes a unit or functional test fail with
a message naming the field. Example: changing `nDefaultPort = 7688` to 7689
fails `chainparams_snapshot_tests/main_consensus_params` in both builds
(regtest has its own `nDefaultPort = 7688`, pinned by `regtest_params`).

### Edge cases

- Both builds: values that differ (powLimit, initialHashTarget,
  initialMoneySupply, genesis nonce/hash/bits, checkpoint 0, stake checkpoint
  0, fixed seeds, fMiningRequiresPeers) are pinned per build; nothing is
  skipped in either build.
- `Params()` is global: the tests construct their own objects with
  `CreateChainParams()` for both chains instead of `SelectParams`, so no
  other test is affected. The base params (RPC port) need
  `CreateBaseChainParams()`, also without changing globals.
- Zero-length `pnSeed6_main` in the low-diff build: the test checks
  `FixedSeeds().empty()` there.
- Globals: harness `ScopedConsensusGlobals` restores everything (also
  `fTestNet` after the testnet sweep), so the order of test suites does not
  matter.
  `nMockTime` is not pinned (tests set it).
- In release builds a failed genesis `Yassert` only logs and calls
  `StartShutdown()` (`Yassert.h`, `main.cpp:138-160`), which the test stub
  turned into exit code 0 – so the hashes are compared explicitly and the
  stub now fails the run (plan step 2a). (The description review suspected
  the genesis hash depends on `fTestNet`; the code review showed it does
  not: the time schedule also gives N-factor 4 at the genesis time,
  `primitives/block.h:173-202`.)
- `CheckStakeModifierCheckpoints` uses `chainActive.Tip()`: with
  `ConsensusTestingSetup` the test sets it explicitly
  (`chain.StartOnExistingGenesis(); chain.SetActiveTip(...)`, as
  `kernel_tests.cpp:28-29`): genesis (height 0), and the mainnet
  fork height 1,890,000 makes it check the table.
- Functional: the restart must not change the P2P/RPC ports in the conf;
  debug.log is appended across restarts, so `assert_debug_log` around the
  restart sees only the new lines. A node with fork height 1,890,000 on the
  low-diff genesis must start (clean chain: only genesis, no mining).
  `stop_node` requires empty stderr. Python 3.12. The functional genesis
  check exists only in the low-diff build because functional tests only run
  there (the unit test pins both).
- One checkpoint (1,911,210) is written without `0x` in the source; the
  test compares `GetHex()` strings with literal hex, so the notation does
  not matter.

### How to test

| Acceptance criterion | Test / command | Expected |
|---|---|---|
| Tests pass in both builds | `build.sh --config mainnet --unit` | exit 0, 285/285 (277 + 8 new) |
| | `build.sh --config lowdiff --unit --functional` | exit 0, 285/285 unit, `ALL` 46/46 functional |
| Snapshot fails loudly | manual mutation check (local only, not committed): change one checkpoint hash, the port and a stake checkpoint, run the new suite | the named cases fail; revert |
| Parameter table in the plan | `project/plans/phase0-test-safety-net.md` 0.2h | table with all three sets + regtest |

Test levels: unit (both builds), functional (low-diff).

### Risks

- No consensus code changes. `init.cpp` gets one `LogPrintf`; it must not
  change any value or order of initialisation.
- Duplicated literal tables (checkpoints) in the test are intentional – the
  point is that two copies must be changed together.
- Functional test start-up with mainnet fork height on the low-diff genesis
  could take a different code path at start (pre-fork logic for block 1); we
  only start and stop, no mining.

## Implementation plan

1. **`init.cpp`:** add `LogPrintf("Param nTokenSupportBlockNumber = %d\n",
   nTokenSupportBlockNumber);` right after the existing
   `Param nMainnetNewLogicBlockNumber` line. Verify: builds; the functional
   test (step 4) sees the line.
2. **`src/test/chainparams_snapshot_tests.cpp`** (new; `BasicTestingSetup`
   for params, `ConsensusTestingSetup` for the stake checkpoints), added to
   `BITCOIN_TESTS` in `src/Makefile.test.include`. Test cases:
   - `main_consensus_params` – every `Consensus::Params` field,
     `DifficultyAdjustmentInterval()`, both deployments.
     Shared with regtest (`CheckSharedFields`): message start, P2P port,
     prune height, base58 prefixes, fixed seeds (bytes + ports per build),
     DNS seeds empty, flags, stake ages, deployments.
   - `main_genesis` – hash, merkle root, nTime, nBits, nNonce, nVersion,
     vtx size, tx nTime/version/hash.
   - `main_network_flags_and_tx_data` – `fMiningRequiresPeers`,
     `chainTxData`.
   - `main_checkpoints` – full table of 51 (height → hash), height 0 equals
     the build's genesis.
   - `regtest_params` – all of the above for regtest, including "same message
     start and P2P port as main".
   - `base_params_and_chain_names` – RPC port and data dir for main/test/regtest;
     `CreateChainParams("test")` and `("foo")` throw.
   - `stake_modifier_checkpoints` – 26 pinned values (accept v, reject v^1)
     with mainnet globals; sweep 0…2,000,000 finds exactly those heights;
     testnet table only height 0; `fTestNet` reset by the harness.
   - `time_constants` – `nChainStartTime` 1367991200 and
     `nYac10HardforkTime` 1619048730 as literals (the harness constants for
     fork height, token height, N-factor and epoch are already pinned with
     literals in `consensus_harness_tests.cpp:100-111`).
   The sweep collects
   the rejecting heights into a vector and checks once. Hashes are compared
   as `GetHex()` strings (readable failures). Fixed seeds are compared with
   literal bytes (the test does not include `chainparamsseeds.h`). Values
   that differ per build use `#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT`.
2a. **`src/test/test_bitcoin_main.cpp`:** the `StartShutdown()` stub calls
   `exit(EXIT_SUCCESS)`. A failed genesis `Yassert` (release build:
   `releaseModeAssertionfailure` → `StartShutdown()`, `main.cpp:138-160`)
   therefore ends `test_bitcoin` in the first `BasicTestingSetup` with exit
   code 0 and no Boost summary, and `build.sh`/CI report success. Change the
   stub to print a message to stderr and `exit(EXIT_FAILURE)`. Test-only
   code; no unit test calls `StartShutdown` today (all 277 report through
   Boost). Verify: unit tests pass in both builds; mutation run with the
   genesis nonce changed exits non-zero.
   Verify step 2 + 2a: unit tests in both builds; local mutation checks (not
   committed): (i) a checkpoint hash, the port and a stake checkpoint → the
   named cases fail; (ii) the genesis nonce → `test_bitcoin` exits non-zero;
   (iii) `-epochinterval` default in `init.cpp` → the functional test fails
   (run alone with `--functional-args`).
3. **`test/functional/feature_params_snapshot.py`** (new, `BASE_SCRIPTS`),
   1 node, `setup_clean_chain = True`, `block_fork_1_0 = 7`: read full
   `debug.log` for the framework values (full lines incl. `\n`, so 7 cannot
   match 70); check genesis via RPC (`getblockhash 0`, `getblock`: hash,
   merkle root, time, nonce, bits, version, `modifierchecksum` `fd11f4e7`,
   flags); `stop_node(0)`, remove two lines from
   `<datadir>/yacoin.conf` (not `node.bitcoinconf`, which points to a
   `bitcoin.conf`), filter `-testnetNewLogicBlockNumber=` out of
   `node.args`, `start_node(0)` inside `assert_debug_log` for the defaults
   (incl. the new token line) with `unexpected_msgs=['Failed stake modifier
   checkpoint']`; check the node still serves the same genesis. Verify:
   functional suite in lowdiff, 46/46.
4. **Docs:** parameter table in plan 0.2h (and 0.1 table: cache epoch 20),
   `src/test/README.md` (new file + what it pins), CLAUDE.md counts
   (unit 277 + new, functional 46), task file.
5. Tests per skill step 8 (both configurations via `build.sh`).

## Log

- 2026-10-02 Step 0: dependency P0-01 is done; moved to inprogress on
  `task/P0-20-params-snapshot` (from master 45eae1a), pushed.
- 2026-10-02 Step 1-2: facts checked (see Detailed description); corrections:
  the functional cache chain uses epochinterval 20, regtest seeds depend on
  the build, `nTokenSupportBlockNumber` is not logged, `-testnet` has no
  chain params.
- 2026-10-02 Step 3: description reviewed by a reviewer subagent. Applied:
  clean chain in the functional test; edit conf/args in place for the
  restart; `fTestNet`/silent-`Yassert` guard; full sweep to pin the stake
  checkpoint count; line-number fixes (CMainParams 73-228, util.py:353),
  cache is 40 blocks; regtest seeds per build; DNS seeds, data dirs, testnet
  RPC port, `DifficultyAdjustmentInterval()`, checkpoint 1,750,000 oddity.
  Not duplicated: unit-test globals are already pinned by
  `consensus_harness_tests` (P0-47); referenced instead.
- 2026-10-02 Step 4-5: plan written and reviewed by a reviewer subagent.
  Applied: the planned `!ShutdownRequested()` guard is useless in
  test_bitcoin (stubbed to `false`; `StartShutdown()` stub exits 0) – a
  failed genesis `Yassert` silently ends the unit run with exit 0, so the
  stub now fails (step 2a); sweep collects heights into a vector; conf path
  `yacoin.conf`, filter args by prefix, exact log lines,
  `unexpected_msgs` for the stake checkpoint failure, pin genesis
  `modifierchecksum`/flags over RPC; no `chainparamsseeds.h` include;
  mutation checks extended to genesis and a functional default. Not applied:
  making `build.sh` fail when `unit.log` has no Boost summary (also
  suggested) – the stub fix closes the hole for `StartShutdown`; left as an
  open point for P0-01/P0-03 owners. The harness-constant case was reduced
  to the two time constants, the rest is pinned by P0-47.
- 2026-10-02 Step 6: implemented (unit test file, stub, log line,
  functional test, runner entry).
- 2026-10-02 Step 7: the `code-review` skill ran in the wrong checkout (the
  session's primary directory; read-only, its findings were about an
  unrelated runbook and were discarded), so the staged diff was reviewed by
  a reviewer subagent instead. It verified every literal by script
  (checkpoints, stake checksums, seeds, compact/hex values) and found no
  correctness bug. Applied: wrong `fTestNet` comment and guard removed (the
  genesis hash does not depend on `fTestNet`); header comment lists all
  sources; duplicate `nChainStartTime` check removed; `main` variable
  renamed; bare `assert` in Python replaced; task-file names aligned with
  the code. Docs/counts follow in step 9.
- 2026-10-03 Step 8: `build.sh` (`--jobs 2`, shared work dir):
  mainnet `--unit` exit 0, 285/285 (277 + 8 new); lowdiff `--unit
  --functional` exit 0, 285/285 and functional `ALL` 46/46 (45 + 1). Local
  mutation checks (not committed): (i) checkpoint 15000 hash, main P2P port
  7689, stake checkpoint 30000, `-epochinterval` default 21001 → unit
  `main_consensus_params`, `main_checkpoints`, `stake_modifier_checkpoints`
  (and the existing `net_tests/cnode_listen_port`) failed, and
  `feature_params_snapshot.py` failed on the epoch line; (ii) low-diff
  genesis nonce 127359 → `test_bitcoin` stops in the first fixture with
  "StartShutdown() called" and exit 1 (before the stub change: exit 0, no
  summary). The mainnet run above was repeated after reverting the
  mutations (exit 0, 285/285); the final lowdiff run is logged below.
- 2026-10-03 Step 9: docs – plan 0.2h parameter table (+ 0.1 cache epoch),
  `src/test/README.md`, CLAUDE.md (counts, snapshot note),
  `contrib/testing/README.md` and the skill's expected counts, task file.
- 2026-10-03 Final runs on the committed code (mutations reverted): mainnet
  `--unit` exit 0, 285/285; lowdiff `--unit --functional` exit 0, 285/285,
  functional `ALL` 46/46 (`feature_params_snapshot.py` passed).
- 2026-10-03 Step 10: docs reviewed by a reviewer subagent; every row of the
  0.2h table matched the code. Applied: stale task-file statements (port
  mutation fails only `main_consensus_params`; harness constants; globals
  edge case; "not logged" now past tense; one `block.h` range; How-to-test
  counts; final runs logged); table: regtest header, initialHashTarget
  compacts, network ids/prune/flags/deployments row, precise
  stake-checkpoint condition, `nYac10HardforkTime` has no option, cache
  epoch wording; README wording and testnet checks; "release-build Yassert".
  Not applied: reflowing one ~110-character comment line in
  `chainparams_snapshot_tests.cpp:8` (cosmetic; avoids a code change after
  the final test runs).
- Open points: (1) `build.sh` does not fail when `unit.log` lacks the Boost
  summary – suggested for P0-01/P0-03; (2) the `Shutdown(void*)` stub in
  `test_bitcoin_main.cpp` still exits 0 (nothing calls it in tests);
  (3) recorded, not changed: `-testnet` has base params but no chain params
  (node start would throw "Unknown chain test"); checkpoint 1,750,000 has no
  leading zeros; the functional cache chain is mined with epochinterval 20;
  the code-review skill reviewed the session's primary directory instead of
  this checkout (tooling).
- 2026-10-03 Step 11: PR https://github.com/dev34253/yacoin/pull/59
