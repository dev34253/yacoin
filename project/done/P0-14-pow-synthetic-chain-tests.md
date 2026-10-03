# P0-14: Difficulty tests on synthetic chains

- Plan section: 0.2b
- Depends on: P0-02, P0-10, P0-47
- Size: L
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Cover every function in pow.cpp in pre-fork and post-fork mode.

## Steps

1. Using the P0-47 harness: GetLastBlockIndex, CalculateNextWorkRequired, GetNextTargetRequired044, GetNextTargetRequired, GetProofOfStakeLimit, ComputeMaxBits, ComputeMinWork, ComputeMinStake.
2. Pre-fork (old retarget branch pow.cpp:184-203) and post-fork (nMinEase scan over all post-fork blocks, genesis read from disk).
3. Timespans extremely fast/slow/on target; clamping; genesis and first blocks; epoch and fork boundaries.
4. CheckProofOfWork: hash == target, ±1; negative, overflowing, zero nBits.

## Acceptance criteria

- [x] pow.cpp: 100% functions – met (10/10, also 6/6 after the dead-code
  exclusions).
- [ ] ≥ 95% branches from unit tests – not reachable as measured: 77.20 %
  (gate method). Every reachable source-level branch is covered; 33 of the
  44 missing branch outcomes are in `LogPrintf`'s `format_error` handler,
  the other 11 are null-dereference paths and compiler temporary-cleanup
  branches (see *Coverage* below).

## Notes

Review: A4, B7.

- Harness (P0-47) is in `src/test/consensus_harness.h`; `pow_tests/harness_*` already show the post-fork epoch retarget (genesis on disk) and the pre-fork per-block retarget.

## Detailed description

Verified against the code (master 086a431): the task's line numbers are
right – old retarget branch `pow.cpp:184-203`, nMinEase scans
`pow.cpp:40-68`, genesis read `pow.cpp:172-178`. `GetNextTargetRequired044`
is file-static (reached only through `GetNextTargetRequired`),
`ComputeMaxBits` has no declaration in `pow.h` (non-static, so the test
declares it), `GetProofOfStakeLimit` is `inline` in pow.cpp (reached only
through `ComputeMinStake`), `bnProofOfStakeHardLimit` is a non-static global
without a header declaration (the test declares it `extern`). The task list
misses `GetProofOfStakeReward` (pow.cpp:237-250); it is already fully
covered by `reward_tests` (P0-46) and is not repeated here.
`coverage-gates.toml` excludes `ComputeMinWork`, `ComputeMinStake`,
`ComputeMaxBits`, `GetProofOfStakeLimit` as dead code (P0-50), so the gated
"functions 100 %" counts the other five functions; the task still pins the
four dead ones, so pow.cpp is at 100 % functions with and without the
exclusions.

**Scope.** Test-only. A new unit-test suite `src/test/pow_chain_tests.cpp`
(registered in `src/Makefile.test.include`), built on the P0-47 harness
(`ConsensusTestingSetup`, `ScopedConsensusGlobals`, `TestChain`, the real
genesis on disk). No change to `pow.cpp` or any other production code
(CLAUDE.md rule 1); the existing `pow_tests` cases stay as they are.
Documentation: test counts (CLAUDE.md, contrib/testing/README.md, the
implement-task skill), `src/test/README.md` (suite list if it has one),
known issues found, this task file. Not in scope: real mainnet data (P0-15),
`coverage-gates.toml` (P0-63 is editing it – suggested minimums go into the
report), CI workflow.

**Behaviour pinned (one test case per group):**

1. `GetLastBlockIndex`: nullptr → nullptr; a lone genesis → itself for both
   types; tip of the wanted type → tip; walks back over the other type to
   the nearest match; no block of the wanted type → the first block of the
   chain/segment (pprev == nullptr), whatever its type.
2. `CheckProofOfWork` (with the build's params and with a hand-made
   `Consensus::Params` whose powLimit is the same in both builds):
   hash == target → true; target + 1 → false; target − 1 → true; hash 0
   → true; nBits 0 (target 0) → false; negative nBits (sign bit, e.g.
   0x04923456, 0x01fedcba) → false; overflowing nBits (0xff123456) and
   nBits one step above powLimit → false; nBits == powLimit with hash
   == powLimit → true; non-normalised encodings of the same target
   (0x1e000fff ≡ 0x1d0fff00) behave like the normalised one.
3. `CalculateNextWorkRequired` (direct calls, synthetic chains):
   - timespan clamps: actual < nominal/4 (including 0 and negative) →
     nominal/4; actual > 4·nominal → 4·nominal; exactly nominal/4,
     nominal, 4·nominal unchanged; nominal follows `nDifficultyInterval`
     (21000 and 10);
   - nMinEase from chainActive (loop 1) and from pindexLast's own chain via
     mapBlockIndex (loop 2, e.g. a side chain whose blocks are not in
     chainActive), each limited to heights ≥ `nMainnetNewLogicBlockNumber`
     (harder blocks below the fork height are ignored);
   - `pindexLast` without `phashBlock`: loop 2 does not run (only
     chainActive counts);
   - PoS blocks' nBits count for nMinEase like PoW blocks (pinned as is);
   - nMinEase compares compact values numerically, not targets: a
     non-normalised nBits with a smaller target but a larger compact value
     does not lower nMinEase (pinned as is, unreachable on a valid chain –
     known issue);
   - cap 3·target(nMinEase): applies (result = cap) and does not apply;
     cap itself capped at powLimit (nMinEase = powLimit → cap = powLimit);
   - result = min(retarget, cap), exact values computed independently with
     `arith_uint256` and pinned as hex per build where powLimit matters.
4. `GetNextTargetRequired` (→ `GetNextTargetRequired044`), PoW and PoS:
   - nullptr → powLimit (PoW) / `bnProofOfStakeHardLimit` (PoS, 0x1d03ffff)
     compact; first and second block → initialHashTarget (both builds, both
     types), including PoS requests on a PoW-only chain (no PoS block →
     genesis → initialHashTarget);
   - pre-fork (mainnet globals, fork 1,890,000): per-block retarget with
     the spacing rule for PoW (60·(1 + hLast − hPrev), max 720 s → nInterval
     10080 … 840) and PoS (60 s), actual spacing fast / on target / slow /
     zero / negative; clamp to powLimit (PoW) and to the PoS hard limit
     (PoS); a very negative spacing makes the target negative and the
     compact result has the sign bit set (pinned, known issue);
   - fork boundary with mainnet numbers (segment chain around 1,890,000):
     next height 1,889,999 → pre-fork rule, 1,890,000 (a multiple of
     21000) → powLimit, 1,890,001 … → constant target; with a fork height
     that is not a multiple of the interval the first post-fork block keeps
     the target instead;
   - post-fork epochs: within an epoch the target of pindexLast (not of
     pindexPrev; for PoS too) is kept; at a boundary with
     `pindexLast->nHeight > nDifficultyInterval + 1` the window goes back
     nDifficultyInterval blocks, otherwise (first boundary) to the genesis
     from chainActive (read from disk; the read result is ignored, only the
     index time counts – also when the genesis is a synthetic entry whose
     read fails); first real mainnet post-fork retarget at 1,911,000 with
     mainnet globals; the window rule's off-by-one (with interval 2 the
     boundary at height 3 is not `> interval + 1` and takes the genesis, a
     3-block window); extremely fast/slow epochs hit the /4 and ×4 clamps
     and the 1/3 cap; epoch interval 10 and 21000.
5. Dead code (P0-50, still pinned until P0-59): `ComputeMaxBits` doubling
   per started day (nTime ≤ 0 → 2×, 1…86400 → 4×, 86401 → 8×), cap at the
   limit, a base above the limit → the limit; `ComputeMinWork` uses
   powLimit (per build), `ComputeMinStake` the PoS hard limit
   (`GetProofOfStakeLimit`).

**Edge cases.** Both builds (mainnet powLimit 0x1e0fffff /
initialHashTarget 0x1e0fffff; lowdiff 0x201fffff / 0x2000ffff): every
expected value that depends on them is pinned per build with
`#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT`, nothing skipped. Unit-test globals
(fork 0, epoch 21000) vs mainnet globals vs epoch 10; the globals and
chainActive are restored by the fixture. Long chains (21000+ entries for the
real 1,911,000 retarget) – kept to a few seconds. Not tested because they
are undefined behaviour or abort, documented instead: `pindexLast` with a
`phashBlock` that is not in mapBlockIndex (dereferences `end()`,
pow.cpp:57-58), first-boundary retarget with no genesis in chainActive
(`ReadBlockFromDisk(nullptr)`, pow.cpp:174-176), a window that runs past the
start of a segment (`Yassert` in a release build only logs and calls
`StartShutdown()`, main.cpp:138-160, then pow.cpp:181 dereferences the
null `pindexFirst`). The branches that only these cases reach are counted
as uncoverable.

**How to test.**
- Acceptance "pow.cpp 100 % functions, ≥ 95 % branches from unit tests":
  `build.sh --config mainnet --coverage --unit` and
  `build.sh --config lowdiff --coverage --unit`, then
  `build.sh --coverage-report`; read pow.cpp's numbers from the merged
  report (gate method: exception branches not counted) and, separately,
  with the dead-code exclusions. Uncoverable branches are listed in the log.
- Regression: `build.sh --config mainnet --unit` (345 + new),
  `build.sh --config lowdiff --unit --functional` (345 + new, 46/46).

**Risks.** None for consensus (no production change). Test-side: global
state (chainActive, mapBlockIndex, nDifficultyInterval) leaking into other
suites – the fixture restores it; the existing `pow_tests` cases set
chainActive to stack objects, the new suite does not.

## Implementation plan

1. Baseline: mainnet `--coverage --unit` on master to list pow.cpp's
   uncovered lines/branches (gcov data of `build-mainnet-cov`). Verify: list
   in the Log.
2. Create `src/test/pow_chain_tests.cpp`, suite `pow_chain_tests` with
   fixture `ConsensusTestingSetup`; add it to `src/Makefile.test.include`
   (alphabetical, next to `pow_tests.cpp`). Helpers in an anonymous
   namespace: `Target(nBits)` → arith_uint256 (independent of CBigNum),
   `Compact(arith_uint256)`, `ExpectedRetarget(nBits, actual, nominal)`
   with the /4 and ×4 clamps, per-build constants
   `POW_LIMIT`, `INITIAL_HASH_TARGET` under `#ifdef
   LOW_DIFFICULTY_FOR_DEVELOPMENT`, and `extern CBigNum
   bnProofOfStakeHardLimit;` / declaration of `ComputeMaxBits`.
3. Test cases, one per group of the description (verify each by building
   and running the suite in both configurations):
   `last_block_index`, `check_proof_of_work`,
   `calc_timespan_clamps`, `calc_min_ease_scans`, `calc_min_ease_quirks`,
   `calc_cap`, `next_target_first_blocks`, `pre_fork_pow`,
   `pre_fork_pos`, `pre_fork_negative_spacing`, `fork_boundary_mainnet`,
   `fork_boundary_not_multiple`, `post_fork_epochs`,
   `post_fork_window_off_by_one`, `post_fork_genesis_read_ignored`,
   `post_fork_mainnet_first_retarget` (21003-entry segment),
   `post_fork_pos_requests`, `dead_compute_max_bits`.
   Expected values: independent arith_uint256 formula where possible, plus
   the hex value pinned (per build where it depends on powLimit /
   initialHashTarget).
4. Run `build.sh --config mainnet --unit` and `--config lowdiff --unit`;
   fix test expectations only where the independent formula was wrong
   (never change pow.cpp).
5. Coverage: mainnet and lowdiff `--coverage --unit`, `--coverage-report`;
   record pow.cpp functions/branches (gate method and raw); list every
   remaining uncovered branch with the reason; add tests for any coverable
   one.
6. Code review (code-review skill on the staged diff), fix findings.
7. Full regression: mainnet `--unit`, lowdiff `--unit --functional`.
8. Docs: test counts in CLAUDE.md, contrib/testing/README.md, the
   implement-task skill; `src/test/README.md` (suite list / harness usage
   if listed); known issues (nMinEase compact compare, PoS nBits in the
   nMinEase scan, negative pre-fork target, log plural, window
   off-by-one); suggested gate minimums in the report (P0-63 owns the
   toml). Logging: none – no production code changes (rule 5 n/a).
9. Doc review, task to done, commit, push, PR, CI check.

## Coverage (measured 2026-10-03)

`build.sh --config mainnet --coverage --unit`, `--config lowdiff --coverage
--unit` (364/364 each), `build.sh --coverage-report` (merged, unit tests
only; the overall/kernel/crypter gates fail there only because the
functional tests were not part of this run). pow.cpp:

| Counting | Lines | Functions | Branches |
|---|---|---|---|
| Gate method (dead code excluded, no exception branches) | 104/104 = 100 % | 6/6 = 100 % | 149/193 = 77.20 % |
| Raw, dead code included (no exception branches) | 121/121 = 100 % | 10/10 = 100 % | 169/213 = 79.34 % |
| Before P0-14 (master, mainnet build, unit only, raw) | 94/121 | 6/10 | 124/213 = 58.2 % |

The 44 branch outcomes not taken (GCC 11, -O0):
- 33 in the `catch (tinyformat::format_error&)` handler of the `LogPrintf`
  macro (`util.h:167-176`) at pow.cpp:97 (12), 150 (12), 246 (9). GCC
  does not mark them as exception branches, but they only run when a
  format string is invalid; the format strings are fixed. Not reachable
  without changing code.
- pow.cpp:169 (1, `pindexFirst` null) and 179 (3, `Yassert` failing):
  only for a window longer than the chain, which then dereferences null
  (known issue). Not testable.
- pow.cpp:219 (3) and 245 (4): GCC's cleanup branches for the
  conditionally constructed temporaries (`CBigNum(0)`, the
  `"-printcreation"` string) in the short-circuit conditions. Both
  outcomes of every source-level condition on these lines are covered.

Without the `LogPrintf` handler branches the gate method gives 149/160 =
93.1 %, raw 169/180 = 93.9 %; all remaining outcomes are the unreachable
ones above. Suggested gate minimums for pow.cpp (ratchet rule, unit-only
numbers; with the functional tests merged they can only be higher):
lines 100, functions 100, branches 76 (from 95 / 100 / 69). Not edited
here: P0-63 owns `coverage-gates.toml` now. An exclusion of the
`LogPrintf` handler branches (kind "branches" on the LogPrintf lines)
would make the remaining gap visible as the 11 outcomes above.

## Log

- 2026-10-03 step 0: moved to inprogress (810b47d).
- 2026-10-03 steps 1-2: task verified against the code, detailed description written.
- 2026-10-03 step 3, self-review (no Agent tool) of the description against
  pow.cpp, bignum.h, consensus_harness.h: fixed the non-normalised example
  (0x01003456 decodes to 0, not 0x34; now 0x1e000fff ≡ 0x1d0fff00); added
  the window off-by-one at `nHeight > nDifficultyInterval + 1` (interval
  2); clarified that `Yassert` does not stop execution in release builds,
  so the short-window case is a null dereference and not testable. Checked
  that CBigNum::SetCompact (MPI based) treats the sign bit of the first
  mantissa byte as negative, so 0x04923456 and 0x01fedcba are negative.
- 2026-10-03 step 4: implementation plan written.
- 2026-10-03 step 5, self-review (no Agent tool) of the plan: feasible with
  the harness as is (segments for the mainnet heights, side chains via
  `Append(prev, …)`, a second `TestChain` for a different chainActive).
  Found while designing the cases: post-fork, pindexLast itself is part of
  the nMinEase scan, so the ×4 clamp is only visible when the cap is
  powLimit – the clamp test uses a pindexLast without `phashBlock` (also
  pins that loop 2 is skipped then). The models overflow 256 bits for
  targets near powLimit × 4 · nominal, so those cases are pinned as hex
  only. No consensus impact (test-only).
- 2026-10-03 step 6: `src/test/pow_chain_tests.cpp` (19 cases) added. First
  run: one wrong expectation of mine (a hash equal to the full powLimit with
  nBits 0x1e0fffff is *rejected*: the compact form truncates powLimit to 3
  mantissa bytes) – test corrected and the behaviour pinned. Then 364/364
  unit in both builds; suite runs in 0.3 s.
- 2026-10-03 step 7: code-review skill (medium) on the staged diff: no
  correctness findings. Applied: known-issues wording of the window
  off-by-one (interval ≤ 2) and the exact log text "(9 block  to go)";
  made the unit-globals branch of `next_target_first_blocks` discriminate
  between the post-fork "keep" rule and the pre-fork retarget.
- 2026-10-03 step 8: coverage runs (mainnet and lowdiff `--coverage
  --unit`, 364/364 each) and `--coverage-report`: see *Coverage*. The
  branch criterion (≥ 95 %) is not reachable without code changes; the gap
  is documented above instead of forcing it.
- 2026-10-03 step 9: docs: test counts 345 → 364 (CLAUDE.md,
  contrib/testing/README.md, implement-task skill), `src/test/README.md`
  (harness users), pointer comment in `pow_tests.cpp`, six entries in
  `project/known-issues.md` (five pow.cpp quirks, one `build.sh` exit 141).
- 2026-10-03 step 10, self-review (no Agent tool) of the docs against the
  code and the logs: counts match `unit.log` (364/364 both builds); the
  coverage table matches the merged tracefile (`gate.txt`, BRDA records);
  known-issues line numbers re-checked against pow.cpp/validation.cpp/
  main.cpp; the test list in the plan lacks `build_constants` (added as a
  guard for the per-build constants) – kept.
- 2026-10-03 handback before step 11: work committed and pushed on the task
  branch. Remaining: final regression (mainnet `--unit`, lowdiff `--unit
  --functional` – was running at handback), then Finished, `git mv` to
  done, open the PR, check CI.
- 2026-10-03: final regression on 791147b (`build.sh --jobs 2`): mainnet unit 364/364, exit 0; lowdiff unit 364/364 and functional 46/46, exit 0. The implementing subagent stopped at its turn limit while this run was going; the parent session confirmed the result, moved the task to done and opened the PR. The ≥ 95 % branch criterion stays open as an owner decision (gap documented above: 33 LogPrintf format_error branches, 4 null-dereference paths, 7 GCC cleanup branches).
