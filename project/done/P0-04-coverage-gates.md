# P0-04: Coverage gates (line and branch) in CI

- Plan section: 0.1, 0.10
- Depends on: P0-03, P0-50
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Fail CI when coverage of consensus code drops, using meaningful measures.

## Steps

1. Script reading lcov .info and checking per-file (and per-function-group) minimums from a config file.
2. Enable branch coverage for pow.cpp, chain.cpp, kernel.cpp and the reward functions in validation.cpp.
3. Exclude from denominators: dead code listed in P0-50 ([plans/dead-code.md](../plans/dead-code.md); its "gcov" column says which items are counted at all), dead fTestNet branches (list b there; they are branch-level), and kernel.cpp debug-logging blocks (fDebug / -printstakemodifier). If P0-59 has removed parts of the list, exclude only what is left.
4. Re-baseline thresholds from the merged CI numbers (not the single low-diff build); document how to ratchet them.

## Acceptance criteria

- [ ] CI fails when a gated file drops below its minimum.
- [ ] Thresholds config committed; later tasks raise it.

## Notes

Review: B11, C4, C5. Final targets: plan 0.10.

- `bignum.h` (P0-12): the target counts only the line ranges of the used
  methods listed in [plans/dead-code.md](../plans/dead-code.md) c) ("Used by
  production code" and "Used only inside `bignum.h`"). The unused methods are
  instantiated by `bignum_tests` in coverage builds, so a whole-file
  percentage would include them.

## Detailed description

### Facts checked (step 1)

- P0-03 records branch coverage already (`--rc branch_coverage=1`); the
  `.info` files of the image's lcov 2.0 mark exception branches with an
  `e` prefix in the block field (`BRDA:<line>,e<block>,…`; ~24,600 of
  ~73,000 branches in the lowdiff run of 2026-10-03 01:45). lcov 2.0's
  `no_exception_branch` drops all branch data with GCC 11 (P0-03 log), so
  the gate script filters them itself.
- `FN` records carry start **and** end line (`FN:<start>,<end>,<mangled>`),
  so a function's lines and branches can be selected by name.
- `fTestNet` uses: `chain.cpp:83`, `kernel.cpp:76,656`,
  `primitives/block.h:173` (+ `else` arm 200-203),
  `consensus/tx_verify.cpp:417`, `miner.cpp:854`, `protocol.h:21` – as in
  `dead-code.md` b). On `chain.cpp:83` the lowdiff data shows the dead
  operand as one never-taken outcome (`BRDA:83,0,1,0`).
- `kernel.cpp` debug logging: `if (fDebug …)` blocks at 169, 209, 218, 232,
  244, 287, 296, 320, 529 (`-printstakemodifier` ones are among them).
  They only call `LogPrintf` (296 also builds the selection-map string).
  Not excluded: `if (fPrintProofOfStake)` at 485 (logging only, but
  `fPrintProofOfStake` is also used in a non-logging condition at 370 and
  the task names only fDebug / -printstakemodifier).
- Reward functions in `validation.cpp`: `GetProofOfWorkReward` (918-979)
  and `LoadBlockRewardAndHighestDiff` (3677-3729) (P0-46 step 1-2;
  `GetProofOfStakeReward` is in `consensus/tx_verify.cpp`).
- P0-59 has not landed: the whole P0-50 list is still in the tree.
- `bignum.h` is unchanged since the P0-12 audit (last change 48637d7).

### Scope

Will be done:

- `contrib/testing/coverage_gate.py` (Python 3, stdlib + `c++filt`): reads
  an lcov tracefile and a TOML config, applies the exclusions, computes
  lines / functions / branches per gate and exits non-zero when a gate is
  below its minimum.
- `contrib/testing/coverage-gates.toml`: exclusions and gates with
  minimums (committed thresholds, task acceptance criterion 2).
- `build.sh --coverage-report` runs the gate on `merged.info` after writing
  the report (exit 1 on a failed gate, after the HTML and summaries are
  written); output also in `coverage-report/gate.txt`.
- `tests.yml`, `coverage report (merged)` job: the gate result goes to the
  job summary; the job (and so the run) fails when a gate fails; the
  merged artifact is still uploaded. Still only on `master` and by hand.
- Docs: `contrib/testing/README.md` (gate, config format, exclusions,
  ratchet procedure), plan 0.1/0.10 rows, `dead-code.md` (how P0-04 applies
  the list), CLAUDE.md if needed.

Will not be done: raising coverage (later tasks), excluding code not on
the P0-50 list or the task's kernel logging, gating on task branches on
every push (coverage jobs stay master/by hand), any source change in
`src/`.

### Exclusions (task step 3)

Applied to the merged tracefile before any number is computed, so they
reduce the overall numbers as well as the gated files:

| Kind | What | How the config names it |
|---|---|---|
| file | `pbkdf2.cpp`, `random_nonce.cpp`, `scrypt-generic.cpp` (+ their headers if they have data) | path |
| function | dead `scrypt.cpp` functions (list a), `ComputeMinWork`, `ComputeMinStake`, `ComputeMaxBits`, `GetProofOfStakeLimit` | demangled name (signature where overloaded, e.g. the `uint256 scrypt_hash` overload) |
| lines | `block.h` `else // is TestNet` arm; `kernel.cpp` `if (fDebug …)` blocks | regex anchor + extent `line` or `block` |
| branches | the "fTestNet is true" outcome of each dead `fTestNet` operand (`chain.cpp:83`, `kernel.cpp:76,656`, `block.h:173`, `tx_verify.cpp:417`, `miner.cpp:854`, `protocol.h:21`) | regex anchor + outcome id `"<block>,<branch>"` + `branches_on_line` guard (+ `verified = false` where no test reaches the line) |
| exception branches | all `e`-marked branches | global switch `exception_branches = false` |

- Anchors are regexes on the source text, not line numbers, so unrelated
  edits do not shift them; each anchor must match exactly one line (or
  every match with `all = true`). `block` extent: from the anchor line to
  the `;` that ends the statement, or the `}` that closes its first `{`,
  skipping comments and string/char literals; a block followed by `else`
  is an error (would hide the `else` arm).
- Branch exclusion removes the named outcome, whether it ran or not:
  unit tests set `fTestNet` on purpose through the consensus harness
  (`chain_trust_tests`, `kernel_tests`, `chainparams_snapshot_tests`,
  `consensus_harness_tests`), so a dead outcome can be covered and cannot
  be recognised by a zero count (first design, "remove N untaken
  outcomes", failed on `chain.cpp:83` with the real data – see Log). The
  ids come from a unit-test run without those suites (live outcomes ran,
  dead did not) and from the functional-test delta; `branches_on_line`
  fails the gate when the outcomes on the line change (code or compiler);
  `verified = false` marks ids that no data could confirm (line never
  reached) and fails the gate once the line runs.
- `main.cpp:74-75` (two unused globals, dead-code list "gcov: yes") have
  no line data in the lcov 2.0 tracefile; nothing to exclude (dead-code.md
  corrected).
- Every exclusion must find its target (file in the tracefile, function,
  anchor, branch data); otherwise the gate fails with "stale exclusion".
  This makes P0-59 (or any refactoring) update the config ("exclude only
  what is left") instead of silently excluding nothing.
- `bignum.h` (P0-12): the gate selects the "used" methods by demangled
  name instead of the line ranges in `dead-code.md` c) – the same set,
  robust to line shifts.

### Gates (task steps 1, 2; plan 0.10 table)

| Gate | Selection | Metrics |
|---|---|---|
| overall | all files | lines, functions, branches |
| `pow.cpp` | file | lines, functions, branches |
| `chain.cpp` trust | `CBlockIndex::GetBlockTrust` | lines, branches |
| `kernel.cpp` | file (debug logging excluded) | lines, functions, branches |
| reward functions | `GetProofOfWorkReward`, `LoadBlockRewardAndHighestDiff` | lines, branches |
| `bignum.h` used methods | used-method list | lines, functions, branches |
| `wallet/crypter.cpp` | file | lines, functions |
| `random.cpp` | file | lines, functions |

"Branches" always means non-exception branches. The gate's numbers
therefore differ from `summary.txt` (lcov's numbers, which keep the
exception branches and the excluded code); both are printed, the gate
decides. A function-group gate
counts the lines and branches between each selected function's start and
end line, and the selected functions for the functions metric.

### Thresholds (task step 4)

- From the merged numbers (CI `coverage report (merged)` and the local
  merged report of the same commit), per gate and metric: minimum =
  `floor(measured − 0.5)` percent, i.e. 0.5 to 1.5 points below the
  lower measurement (tolerates the small run-to-run variation of the
  multi-threaded functional tests); a measured 100 % stays 100.
- Ratchet: `coverage_gate.py --suggest` prints the minimum this rule gives
  for the current data and marks where it is higher than the config. A
  task that raises coverage raises the config in the same PR. Lowering a
  minimum needs a reason in the PR and the task log.

### Behaviour

```
$ contrib/testing/coverage_gate.py merged.info      # CI data of run 37102949023
excluded: 273 lines, 329 branches, 24 functions (33 exclusion targets); exception branches not counted
gate                         metric             covered       %  minimum  result
overall                      lines          25166/35749   70.40       69  ok
…
random.cpp                   functions            20/22   90.91       90  ok
coverage gate: all 20 checks passed
```
Exit 0 when all pass, 1 when a check fails (each failing check listed),
2 on usage, config or data errors (including stale exclusions).

### Edge cases

- Gate with zero lines/branches after selection: error (stale config).
- Function present only in one configuration (`#ifdef`): the merged
  tracefile has it; selection works on the merged file.
- `FN` without end line (older lcov): error with a clear message.
- Tracefile from another commit than the source tree: anchors may point to
  other lines; documented (always use the same commit; `build.sh` and CI
  do).
- `c++filt` missing: error. Python ≥ 3.11 (`tomllib`): image 3.12,
  runner 3.12; checked with a clear error.
- Paths: config paths are repo-relative (`src/pow.cpp`); `SF` paths are
  absolute (`/work/src/src/pow.cpp`); matched by path suffix, must be
  unique. Sources are read from `--source-root` (default: the checkout
  containing the script).
- Gate failure in CI: HTML and `merged.info` still uploaded, summary
  still written.
- Where the gate runs: only where the coverage jobs run (`master`, by
  hand). A task branch that lowers coverage is caught after the merge,
  or before it if the author starts the workflow by hand (the PR
  procedure in the README asks for that when a PR touches gated files).
  Owner question Q11.

### How to test

| Criterion | Test | Expected |
|---|---|---|
| CI fails when a gated file drops below its minimum | local: gate on the real merged `.info` with one minimum raised above the measured value; CI: one deliberately failing run, then fixed | exit 1 / job red, failing check named; then green |
| Thresholds config committed | `coverage-gates.toml` in the PR, values from the merged numbers | file present, log has the numbers |
| Exclusions correct | gate `--verbose` on the real data: per exclusion the removed lines/branches/functions; spot-check in the HTML | counts match the source (e.g. 1 branch per `fTestNet` operand) |
| Stale exclusion detected | config copy with a non-existent function/anchor | exit 2, message names it |
| Block extent | unit check of the parser on the kernel blocks (verbose output lists start-end per block) | ranges equal the `if (fDebug)` blocks |
| No regression | `build.sh --config mainnet --unit`; `--config lowdiff --unit --functional` | 327/327, 327/327, 46/46 |
| Workflow valid | actionlint | no new findings |

### Risks

- No source change in `src/`; no consensus impact.
- A too-tight minimum makes `master` red on noise: margin of ≥ 0.5 points
  and deterministic unit tests for the consensus files.
- Exclusions hide code: each is listed in the config with its reason and
  must match its target; a reviewer can see them in `--verbose` output.

## Implementation plan

1. `contrib/testing/coverage_gate.py`: tracefile parser (SF, FN with end
   line, FNDA, DA, BRDA incl. `e` blocks), demangling via one `c++filt`
   call, config loader with validation, exclusion engine (file, function,
   lines with `line`/`block` extent, branches with `dead = N`), gate
   evaluation, table output, `--verbose`, `--suggest`, exit codes 0/1/2.
   Verify: run against the local merged `.info`; unit tests in
   `contrib/testing/test_coverage_gate.py` (stdlib `unittest`, synthetic
   tracefile + source) for block extent, branch removal, exception
   branches, function groups, stale errors, exit codes; run in the report
   job before the gate.
2. `contrib/testing/coverage-gates.toml`: exclusions from `dead-code.md`
   a)/b) and the kernel logging blocks, gates from plan 0.10. Verify:
   `--verbose` shows each exclusion's effect; demangled names checked
   against the `.info`.
3. Thresholds from the merged numbers (local merged report and CI run on
   this branch), rule `floor(min − 0.5)`. Verify: gate passes on both.
4. `build.sh`: `coverage_report` runs the gate after the summaries, writes
   `gate.txt`, returns its exit code. Verify: local `--coverage-report`
   (pass) and with a raised minimum (fail, exit 1, HTML still written).
5. `tests.yml`: report job writes the gate output to the job summary even
   on failure; uploads `coverage-merged` with `if: !cancelled()`.
   Verify: actionlint; CI run by hand on the branch with a deliberately
   failing minimum in a temporary commit (red), then reverted (green).
6. Docs: README (Coverage gate section, ratchet), plan 0.1/0.10, dead-code
   note, CLAUDE.md coverage bullet if any. Logging: CLAUDE.md rule 5 is
   about daemon code – not applicable; the script prints all decisions.
7. Tests: mainnet unit, lowdiff unit + functional (no `src/` change, so
   this checks the build.sh edit doesn't break normal runs).

## Log

- 2026-10-03: moved to inprogress (fe9f539). Dependencies P0-03 and P0-50 are in `project/done/`.
- 2026-10-03: step 1 – facts checked against the code (see "Facts checked"); `dead-code.md` line numbers still match (bignum.h unchanged since the audit, block.h else arm 200-203, kernel/chain fTestNet lines). Started Tests run on the branch for current coverage numbers, and local coverage runs (mainnet, lowdiff, report).
- 2026-10-03: description review – self-review (no Agent tool), separate pass against the step-3 checklist. Applied: gate branch numbers vs. lcov `summary.txt` explained; where the gate runs (master/by hand only) made explicit as owner question Q11. Checked and kept: exception branches filtered in the gate only (lcov 2.0 `no_exception_branch` unusable, P0-03); `if (fPrintProofOfStake)` (kernel.cpp:485) not excluded – the task names fDebug/-printstakemodifier and the flag also has a non-logging use (370).
- 2026-10-03: plan review – self-review (no Agent tool). Applied: unit tests for the gate script (synthetic data) run in the report job; the failing CI demonstration as a temporary commit that is reverted. Order kept (thresholds need the measured data, so config before thresholds before CI). No consensus impact: no file in `src/` changes.
- 2026-10-03: CI Tests run 37102949023 (by hand on fe9f539 = master 52b220d's code, https://github.com/dev34253/yacoin/actions/runs/37102949023): all jobs green; merged lcov numbers 69.9 % lines (25174/36022), 77.0 % functions, 32.1 % branches – practically the P0-03 baseline (69.9/76.9/32.0). Artifact `coverage-merged` downloaded and used to develop the config.
- 2026-10-03: local coverage runs (same code): mainnet `--coverage --unit` 327/327; lowdiff `--coverage --unit --functional` 327/327 unit, 46/46 functional; `--coverage-report` merged 69.9 % (25195/36022) / 77.1 % / 32.1 %.
- 2026-10-03: implementation findings on the real data: (1) `main.cpp:74-75` (dead globals, "gcov: yes" in dead-code.md) have no line data in the tracefile – no exclusion, dead-code.md corrected. (2) The first branch-exclusion design ("remove N untaken outcomes; fewer untaken = the dead branch ran") failed on `chain.cpp:83`: the unit tests set `fTestNet` on purpose (consensus harness), so the dead outcome ran (`BRDA:83,0,1` = 8 in mainnet). Redesigned: the dead outcome is named by its id, guarded by `branches_on_line`; ids determined by experiment: a mainnet unit run (`build-mainnet-cov`, counters zeroed, captured to a scratch dir) without `chain_trust_tests`, `kernel_tests`, `chainparams_snapshot_tests`, `consensus_harness_tests` (291 cases, no errors): `chain.cpp:83` 0,1 = 0 (with `consensus_harness_tests` included it was 3, without any of them 0), `block.h:173` 0,0 = 291 / 0,1 = 0, `protocol.h:21` 0,0 = 0 / 0,1 = 2 → dead ids 0,1 / 0,1 / 0,0. `kernel.cpp:656`: not reached without those suites; in the CI data 0,0 = 8,000,008 (= 2 × the mainnet unit count, i.e. unit tests only) and 0,1 = 8,001,096 (+1,030 from the functional tests, which never set fTestNet) → dead 0,0. `kernel.cpp:76`, `tx_verify.cpp:417`, `miner.cpp:854`: no test reaches them (all outcomes `-`); ids chosen from GCC's pattern on the verified lines (ternary condition: 0,0 = true; second operand of `||`: 0,2 = true) and marked `verified = false` – the choice does not change the numbers while nothing on the line runs, and the gate stops once it does. (3) `CBigNum::ToString` demangles as `ToString[abi:cxx11]`; ABI tags are ignored when matching names. `CAutoBN_CTX::operator bignum_ctx*` added to the bignum.h used list (dead-code.md c) counts `CAutoBN_CTX` as used).
- 2026-10-03: gate on both merged tracefiles (CI / local): overall lines 70.40/70.46, functions 77.49/77.58, branches 48.52/48.57 (exception branches and exclusions removed: 273 lines, 329 branches, 24 functions); pow.cpp 89.42/83.33/62.69; GetBlockTrust lines 95.24, branches 83.08; kernel.cpp 44.70/53.85/30.07; rewards lines 93.65, branches 54.80; bignum.h used methods 92.83/100/78.29; crypter 73.43/94.12; random.cpp 85.80/90.91 (all other values identical in both runs). Minimums = `floor(lower − 0.5)`: overall 69/76/48, pow.cpp 88/82/62, GetBlockTrust 94/82, kernel.cpp 44/53/29, rewards 93/54, bignum.h 92/100/77, crypter 72/93, random.cpp 85/90.
- 2026-10-03: gate failing locally (acceptance criterion 1): kernel.cpp lines minimum temporarily 45 → `build.sh --coverage-report` exit 1, "coverage gate: 1 of 20 checks FAILED: kernel.cpp lines 44.70% < minimum 45%", report (`merged.info`, `html/`, `summary.txt`, `gate.txt`) still written; config restored, then exit 0 ("all 20 checks passed").
- 2026-10-03: code review (`code-review` skill, medium, staged diff): 2 findings, both applied – invalid `match` regex raised a traceback with exit 1 instead of a config error (exit 2) – now checked in `load_config`, test added; README exclusion table still named the dropped `main.cpp` exclusion – removed. Reviewer confirmed: tests 14/14, gate on real data exit 0, shell/workflow exit-code handling, parser merging, ctor dedupe, block extents on the real anchors. `test_coverage_gate.py` now 15/15; pyflakes clean; actionlint clean on `tests.yml`; shellcheck on build.sh only the existing SC2015 notes.
- 2026-10-03: tests (no `src/` change; checks that the build.sh edit keeps normal runs working): `build.sh --config mainnet --unit` exit 0, 327/327; `build.sh --config lowdiff --unit --functional` exit 0, 327/327 unit, 46/46 functional; `--coverage-report` with the committed config exit 0, all 20 checks passed.
- 2026-10-03: documentation review – self-review (no Agent tool), separate pass over README "Coverage gate", CLAUDE.md, plan 0.1/0.10, dead-code.md, P0-59, Q11 against the code and the runs. Applied: `all = true` only for `lines`; the fTestNet-id paragraph names all four suites and explains `verified = false`; "Usage" → "Quick start" (no Usage section); the run-to-run difference that motivates the margin quoted; real gate output in the task description. Nothing left out.
