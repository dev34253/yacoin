# P0-02: Run unit tests in mainnet configuration and document the pow_tests failure

- Plan section: 0.1
- Depends on: P0-01
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-02
- Finished: 2026-10-03

## Goal

Close out the known pow_tests/get_next_work_pow_limit failure.

## Steps

1. Root cause (from review): with the low-difficulty powLimit (2^253) the retarget 0x0fffff·2055491/1260000 = 0x1e1a19f8 is not clamped; with mainnet powLimit (2^236) it is. Confirm by running the test in the mainnet configuration.
2. Ensure the CI configuration that runs unit tests either uses mainnet parameters or skips/adjusts this test under LOW_DIFFICULTY_FOR_DEVELOPMENT, without weakening the mainnet check.

## Acceptance criteria

- [x] Test passes in the mainnet configuration.
- [x] Unit suite green in the configuration(s) CI uses (shown locally with `build.sh`, the script CI will call; wiring it into CI is P0-03).

## Notes

Review: D10. Test: src/test/pow_tests.cpp:50-68; powLimit: chainparams.cpp:78,82.

## Detailed description

### Verified facts (step 1)

- Test: `src/test/pow_tests.cpp:44-68` (`get_next_work_pow_limit`; the task's
  "50-68" is the body). It uses `CreateChainParams(MAIN)`; the unit tests never
  run `AppInit`, so `nDifficultyInterval` = 21000 (`util.cpp:581`) and the
  nominal timespan is 21000 * 60 = 1,260,000 s. Actual timespan 2,055,491 s is
  within the 4x clamp (`pow.cpp:72-75`).
- `powLimit`: mainnet `~uint256(0) >> 20` (2^236-1, compact 0x1e0fffff,
  `chainparams.cpp:78`); low difficulty `~uint256(0) >> 3` (2^253-1, compact
  0x201fffff, `chainparams.cpp:82`). The task's "2^253" / "2^236" mean these
  values.
- `CalculateNextWorkRequired` (`pow.cpp:37-100`): new target =
  min(prev * actual / nominal, min(3 * highest-difficulty target, powLimit)).
  In `TestingSetup` the only block is the genesis, whose nBits is
  `powLimit.GetCompact()`, so the cap is `powLimit` in both configurations.
- Retarget of 0x1e0fffff: 0x0fffff * 256^27 * 2055491 / 1260000 =
  0x1a19f88114f7b5e1c4... -> compact **0x1e1a19f8** (computed independently in
  Python). Mainnet: above 2^236-1 -> clamped to 0x1e0fffff (test passes).
  Low difficulty: below 2^253-1 -> not clamped, result 0x1e1a19f8, so
  `BOOST_CHECK_EQUAL(nextWork, 0x1e0fffff)` and `nextWork < retargetWork` fail.
  This is a test-expectation issue, not a code bug.

### Scope

- Change only `src/test/pow_tests.cpp` (`get_next_work_pow_limit`) and docs.
- No change to `pow.cpp`, `chainparams.cpp` or any consensus code (CLAUDE.md
  rule 1). No CI change (`.github/workflows/` is P0-03).
- Docs that state "lowdiff 238/239 / exits 1 until P0-02": `CLAUDE.md`
  (Testing), `contrib/testing/README.md` (exit-code note, expected results),
  `.claude/skills/implement-task/SKILL.md` (step 8 passing criteria),
  `project/plans/phase0-test-safety-net.md` (0.1 table row, if it needs
  the outcome). Done task files (P0-01, P0-57) are historical records and stay.

### Behaviour

Not skipped, not weakened: the test asserts the exact result in each build.

- **Mainnet build** (no `LOW_DIFFICULTY_FOR_DEVELOPMENT`): unchanged
  assertions – `nextWork == 0x1e0fffff` and `nextWork < retargetWork`
  (clamped to `powLimit`).
- **Low-difficulty build**: the same input pins the actual result,
  `nextWork == 0x1e1a19f8` and `nextWork == retargetWork` (not clamped,
  because the low-difficulty `powLimit` is higher). In addition, the
  upper-bound clamp – the purpose of the test – is exercised with the
  low-difficulty limit: previous nBits = `powLimit.GetCompact()` (pinned as
  0x201fffff), same timespans -> `nextWork == 0x201fffff` and
  `nextWork < retargetWork`.
- A sanity check pins `powLimit.GetCompact()` per configuration
  (0x1e0fffff / 0x201fffff), so a silent change of the parameters fails
  loudly with a clear message instead of a confusing retarget mismatch.

### Edge cases

- Both build configurations (the whole point); coverage build (`-O0`) gives
  the same integer results.
- Unit-test globals: `nMainnetNewLogicBlockNumber` = 0 (zero-initialised
  global), `nDifficultyInterval` = 21000 – the expected values depend on
  them; they are documented in the test comment.
- The clamp check with prev = powLimit: 0x201fffff * 2055491 / 1260000 >
  2^253-1, CBigNum has no overflow (arbitrary precision); compact of the
  result has exponent 0x20 and is > 0x201fffff, so `<` on compacts is valid.
- Test isolation: each case gets a fresh `TestingSetup`; the later
  `get_next_work_one_third_highest_difficulty` case sets `chainActive` to
  stack blocks but runs after this case.

### How to test

| Criterion | Command | Expected |
|---|---|---|
| Test passes in mainnet config | `contrib/testing/build.sh --config mainnet --unit` | exit 0, 239/239 |
| Unit suite green in the configuration(s) CI will use | `contrib/testing/build.sh --config lowdiff --unit --functional` | exit 0, unit 239/239, functional 45/45 |
| Root cause confirmed | baseline run before the change | mainnet 239/239; lowdiff 238/239 with `nextWork` = 0x1e1a19f8 in `unit.log` |

CI itself is wired up in P0-03; this task shows green runs locally with the
same script CI will call.

### Risks

- None for consensus: only test code and docs change.
- Risk of hiding a regression in the low-difficulty build: mitigated by
  pinning exact values instead of skipping.

## Implementation plan

1. Baseline: run `build.sh --config mainnet --unit` and `--config lowdiff
   --unit` on the unchanged tree; record pass counts and the failing values
   from `unit.log` (confirms the root cause, step 1 of the task).
2. Edit `get_next_work_pow_limit` in `src/test/pow_tests.cpp`:
   - comment explaining the two `powLimit`s and the unit-test globals;
   - `BOOST_CHECK_EQUAL(powLimit.GetCompact(), 0x1e0fffff / 0x201fffff)`;
   - `#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT`: the existing two assertions
     unchanged; `#else`: `0x1e1a19f8` and `== retargetWork`, plus a second
     retarget from `powLimit.GetCompact()` asserting the clamp
     (`== 0x201fffff`, `< retargetWork`).
   - Check that `LOW_DIFFICULTY_FOR_DEVELOPMENT` reaches the test build
     (it comes from `config/bitcoin-config.h`, included via the headers; check
     with `grep` in the configured build).
   Verify: both builds compile; the test passes in both.
3. Code review (self-review, no Agent tool) of the staged diff.
4. Full test runs: mainnet unit; lowdiff unit + functional; both exit 0.
5. Docs: CLAUDE.md, contrib/testing/README.md, implement-task SKILL.md step 8,
   phase0 plan row 0.1 if useful; task file criteria and Log. No logging
   changes (test code only, no daemon behaviour change – rule 5 n/a).
6. Doc review (self-review), move task to done, commit, push, PR.

## Log

- 2026-10-02 Step 0: dependency P0-01 done; branch `task/P0-02-pow-tests-mainnet-config`; task moved to inprogress (f546eeb).
- 2026-10-02 Step 1: claims verified (see *Verified facts*). Task line refs are slightly off (test case starts at line 44; "2^253"/"2^236" mean 2^253-1/2^236-1). Retarget value 0x1e1a19f8 computed independently in Python.
- 2026-10-02 Steps 2-5: description and plan written. Reviews were self-reviews (no Agent tool): checked the cap logic in `pow.cpp:84-96`, that the genesis nBits is `powLimit.GetCompact()` (`chainparams.cpp:126`), that `LOW_DIFFICULTY_FOR_DEVELOPMENT` is a compiler flag (`configure.ac:240,244`) so it reaches the test build, and that the lowdiff clamp check compares compacts with the same exponent. Added after review: config-independent pin `retargetWork == 0x1e1a19f8` (guards the test arithmetic itself). Not applied: making the 0x1e0fffff-input case use `powLimit.GetCompact()` in both builds – that would change the mainnet case's documented input; the separate lowdiff clamp check covers it instead.
- 2026-10-03 Baseline (unchanged code, P0-01 image, `--jobs 2`): mainnet unit 239/239, exit 0; lowdiff unit 238/239, exit 1 – `check nextWork == 0x1e0fffff has failed [505027064 != 504365055]` (505027064 = 0x1e1a19f8) and `nextWork < retargetWork` failed. Root cause confirmed.
- 2026-10-03 Step 6: `get_next_work_pow_limit` pins powLimit compact, the retarget, and the result per build (`#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT`); mainnet assertions unchanged; lowdiff asserts 0x1e1a19f8 (not clamped) plus a clamp check from nBits = powLimit (0x201fffff). No change to `pow.cpp`/`chainparams.cpp`. No logging change (test code only, rule 5 n/a).
- 2026-10-03 Step 7: `code-review` skill (medium) on the staged diff: no findings (it confirmed the flag reaches the test, cap = powLimit in both builds, compact comparisons valid, no consensus change). Process note (log the test results before moving to done) handled here.
- 2026-10-03 Step 8: mainnet `--unit`: exit 0, 239/239 (22 s). lowdiff `--unit --functional`: exit 0, unit 239/239 (22 s), functional 45/45 `ALL ... Passed` (227 s).
- 2026-10-03 Steps 9-10: docs updated – CLAUDE.md (Testing), `contrib/testing/README.md` (exit-code note, expected results table), implement-task SKILL.md step 8 (lowdiff now exit 0, 239/239), phase0 plan 0.1 row. Done task files P0-01/P0-57 left as historical records. Doc self-review (no Agent tool): fixed CLAUDE.md wording ("commands above" pointed at the wrong block); all numbers checked against the runs above.
- 2026-10-03 Step 11: committed d76f422, pushed, PR https://github.com/dev34253/yacoin/pull/51.
