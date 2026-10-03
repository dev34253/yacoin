# P0-63: Coverage gate on changes to gated files; two more logging exclusions

- Plan section: 0.1, 0.9
- Depends on: P0-04
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

A push that changes consensus code covered by the coverage gate is checked
before it is merged, without slowing down other pushes (open question Q11,
answered by the owner on 2026-10-03).

## Steps

1. `.github/workflows/tests.yml`: run the coverage jobs and "coverage report
   (merged)" (with the gate) also on pushes whose changes touch a gated file
   or the gate itself: the `paths` of the `[[gate]]` entries in
   `contrib/testing/coverage-gates.toml` (today `src/pow.cpp`, `src/chain.cpp`,
   `src/kernel.cpp`, `src/validation.cpp`, `src/consensus/tx_verify.cpp`,
   `src/consensus/consensus.cpp`, `src/bignum.h`, `src/wallet/crypter.cpp`,
   `src/random.cpp` – check the config), `contrib/testing/coverage-gates.toml`,
   `contrib/testing/coverage_gate.py` and `contrib/testing/build.sh`. Keep
   master and *Run workflow* as today. Choose a mechanism that sees the
   changed files of the push (e.g. a small job computing the matrix with
   `git diff` against the merge base with `master`, or `dorny/paths-filter`
   pinned by SHA) and document it.
2. `contrib/testing/coverage-gates.toml`: exclude the `if (fPrintProofOfStake)`
   logging in `kernel.cpp` (around line 485) and the `-printcreation`
   logging in `GetProofOfWorkReward` (validation.cpp), like the existing
   `fDebug` blocks; re-run the gate and ratchet the affected minimums with
   `--suggest`.
3. Docs: `contrib/testing/README.md` (CI table: when the coverage jobs run),
   `CLAUDE.md` CI bullet.

## Acceptance criteria

- [ ] A push that changes a gated file runs the coverage jobs and the gate; a
      docs-only push does not (show both runs).
- [ ] The two logging blocks are excluded; the gate passes; actionlint clean.

## Notes

Touches `.github/workflows/`: implement from a session whose token has the
`workflow` scope.

## Detailed description

**Scope.** CI and gate config only, no C++ change (CLAUDE.md rule 1):
`.github/workflows/tests.yml` (new `changes` job; matrix and the merged
job depend on it), `contrib/testing/coverage-gates.toml` (two exclusions,
ratcheted minimums), docs (`contrib/testing/README.md` CI and Coverage gate
sections, `CLAUDE.md` CI bullet, `doc/design-decisions.md` D-24,
`doc/architecture.md` CI row, plan 0.9 table row, Q11 note). Not done:
`pull_request` triggers, schedules (P0-44), changes to `coverage_gate.py`.

**Corrections to the task text** (checked against master 1f56719):
- `src/consensus/tx_verify.cpp` is not a gate path; it only has an
  `[[exclude]]` (fTestNet operand). The gated paths of today are
  `src/pow.cpp`, `src/chain.cpp`, `src/kernel.cpp`, `src/validation.cpp`,
  `src/consensus/consensus.cpp`, `src/bignum.h`, `src/wallet/crypter.cpp`,
  `src/random.cpp`.
- `kernel.cpp:485` `if (fPrintProofOfStake)` is right. The `-printcreation`
  logging is two statements in `GetProofOfWorkReward`
  (`validation.cpp:954` and `:971`, both `if (fDebug &&
  gArgs.GetBoolArg("-printcreation"))` without braces).
- `kernel.cpp:370` (`if (fPrintProofOfStake || (…))`) also reads the flag
  but chooses between `return error(…)` and `return false`; it is not a
  logging block and stays counted. `kernel.cpp:529` (`if (fDebug &&
  !fPrintProofOfStake)`) is already excluded by the `fDebug` rule.

**Behaviour.** A first job `changes` decides whether the coverage jobs
run and outputs `coverage=true|false`:
1. `master` or *Run workflow* → `true` (as today).
2. Otherwise the files changed **on the branch**: `git diff --name-only
   --no-renames $(git merge-base origin/master HEAD) HEAD` (checkout with
   full history, `filter: blob:none` so no file contents are downloaded).
   `true` if one of them is a *watched* file, else `false`.
3. Watched files: every `path` of a `[[gate]]` and of an `[[exclude]]` in
   the branch's `coverage-gates.toml` (read with Python `tomllib`), plus
   `contrib/testing/coverage-gates.toml`, `coverage_gate.py`,
   `test_coverage_gate.py` and `build.sh`. Exclusion paths are included
   because a change there can make an exclusion stale (gate exit 2 on
   master after the merge); the task's mention of `tx_verify.cpp` points
   the same way.
4. The step summary says which rule applied and lists the watched files
   that changed.

Branch diff, not push diff: with `cancel-in-progress`, a docs push right
after a gated push would cancel the gated run and skip coverage; with the
branch diff every run of a branch that changes a gated file runs the gate,
so the last run before the merge has checked it. A branch that only
changes docs, tests or other code stays on the two test jobs.

Example: a branch changing `src/pow.cpp` → 4 test jobs + merged report
with gate; a branch changing only `doc/*.md` → 2 test jobs, merged job
skipped.

**Edge cases.**
- No merge base / `origin/master` missing (unrelated history) → `true`
  (fail safe), with a notice.
- Config unreadable (TOML error, Python error) → `true` with a warning; the
  merged job then reports the config error (exit 2) itself. The unit and
  functional jobs still run.
- `grep` error (exit ≥ 2) → step fails rather than silently `false`.
- Renamed or deleted gated file: `--no-renames` lists old and new names.
- New gate path added on the branch: the toml changed → `true` anyway.
- Tag pushes: diff against the merge base like a branch.
- Branch behind master: the merge base excludes master's own changes.
- The `overall` gate has no `paths` (every file); it does not make every
  source file watched (owner answer Q11: other pushes stay fast). A
  branch that lowers overall coverage without touching a watched file is
  still caught on master only; documented.
- `tests.yml` itself is not watched (task list); a workflow change that
  affects the coverage jobs is checked with *Run workflow* (documented).
- `strategy.matrix` and job `if` may use `needs` → valid expression;
  checked with actionlint.
- If the `changes` job fails, the test jobs are skipped – visible as a
  failed run, not as green.

**Exclusions.** Two new `[[exclude]] kind = "lines"`, `extent = "block"`:
- `src/kernel.cpp`, `match = '^\s*if \(fPrintProofOfStake\)\s*$'` (exactly
  one line; not line 370) → the `if` line and its `{…}` block.
- `src/validation.cpp`, `match = '^\s*if \(fDebug && gArgs\.GetBoolArg\("-printcreation"\)\)'`,
  `all = true` → the two unbraced statements up to their `;`.
Both remove the `if` line's branches too (like the existing `fDebug`
rule). Then the gate is re-run on a merged report and the minimums of the
affected gates (`kernel.cpp`, `validation.cpp rewards`, and `overall`) are
ratcheted with `--suggest` (floor(measured − 0.5), only raised).

**How to test.**
| Criterion | Test | Expected |
|---|---|---|
| Gated push runs coverage + gate | push of the commit changing `coverage-gates.toml` | run has `changes` → coverage=true, 4 test jobs, merged job green |
| Docs-only push does not | push of a docs-only commit while the branch changes no watched file | `changes` → coverage=false, 2 test jobs, merged job skipped |
| Exclusions apply, gate passes | `coverage_gate.py merged.info --verbose --suggest` on a local merged report (mainnet-cov + lowdiff-cov) and the CI merged job | both new exclusions listed with removed lines, all checks pass |
| actionlint clean | `actionlint .github/workflows/tests.yml` | no findings |
| Tests | local coverage pair (mainnet `--unit`, lowdiff `--unit --functional`) + CI | 344/344 unit each, 46/46 functional |
| Gate script tests | `python3 contrib/testing/test_coverage_gate.py` | all pass (script unchanged) |

**Risks.** No consensus code. Risk of a wrong `changes` decision
(coverage skipped when it should run) → mitigated by fail-safe `true` on
errors and by master still running everything. The extra job adds ~10–20 s
before the test jobs start.

## Implementation plan

1. `tests.yml`: add job `changes` (checkout `fetch-depth: 0`,
   `filter: blob:none`; one bash step with an inline Python `tomllib`
   reader for the watched list, the merge-base diff, `grep -Fx`, output
   and step summary). `test`: `needs: changes`, matrix condition
   `needs.changes.outputs.coverage == 'true'`. `coverage-report`:
   `needs: [changes, test]`, same condition with `!cancelled()`. Update the
   header comment. Verify: actionlint; run the decision script locally on
   this branch (expect false before step 4, true after).
2. Commit 1 (workflow + task description/plan), push → run 1: expect
   coverage=false (branch changes no watched file).
3. Commit 2: docs (README CI + Coverage gate text, CLAUDE.md, D-24 update,
   architecture.md, plan 0.9 row, Q11 note) – docs only, push → run 2:
   the docs-only acceptance run (coverage=false).
4. `coverage-gates.toml`: the two exclusions (section c, renamed to
   "debug logging"), README exclusion table; run `coverage_gate.py
   --verbose --suggest` on the local merged report (local coverage pair of
   the unchanged C++ code); ratchet `kernel.cpp`, `validation.cpp rewards`,
   `overall` and any other `<- raise`; update the "Measured" comment.
   Commit 3, push → run 3: coverage=true, gate green; compare CI
   suggestions with local ones (take the lower if they differ, P0-04).
5. Task log, tick criteria, `git mv` to done, commit, push, PR.

Logging (rule 5): no daemon code changes; the `changes` job writes its
decision and the matched files to the job log and step summary.

## Log

- 2026-10-03 step 0: picked up, moved to inprogress (d79a564).
- 2026-10-03 steps 1–2: task checked against the code; corrections in
  "Detailed description" (tx_verify.cpp is exclusion-only; two
  `-printcreation` statements; kernel.cpp:370 not logging).
- 2026-10-03 step 3, self-review (no Agent tool) of the description:
  added the `overall`-gate edge case (no paths → not watched) and the
  fail-safe on config errors; chose the branch diff over the push diff
  because `cancel-in-progress` could otherwise skip a gated change.
- 2026-10-03 step 5, self-review (no Agent tool) of the plan: ordering
  chosen so that run 2 is a docs-only push on a branch that changes no
  watched file (with the branch diff, every push after the toml commit
  runs coverage – intended); the workflow itself is not watched (task
  list), so commit 1 does not trigger coverage. No consensus impact.
- 2026-10-03 step 6, commit 1: `changes` job in `tests.yml`; actionlint
  clean (with shellcheck); decision script extracted from the YAML and
  run locally: this branch → `coverage=false`; master / Run workflow →
  `true`; a throw-away local commit touching `src/bignum.h` → `true`
  (lists `src/bignum.h`); a broken `coverage-gates.toml` → `true` (fail
  safe).
- 2026-10-03 step 7, code review (`code-review` skill, medium) of commit 1:
  one finding (low) – the header said "on any error true", but a failing
  `git diff` or `grep` failed the job (and with it the test jobs). Fixed:
  both now answer `true` with a message, like the other errors.
- 2026-10-03 step 9, commit 2 (docs only): README "CI" (new rows and
  "When the coverage jobs run"), "Coverage gate" (where it runs, ratchet),
  `CLAUDE.md` CI bullet, D-24 update, `architecture.md` CI row, plan 0.9
  row, Q11 note. Self-review (no Agent tool) against the workflow: the
  watched list, branch-diff rule, fail-safe cases and the unwatched
  `overall` gate / `tests.yml` match the code; the `changes` job time is
  checked against run 1.
