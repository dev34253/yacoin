# P0-66: Faster task workflow – local test scope, no fixed sleeps, single-source test counts

- Plan section: 0.9
- Depends on: P0-64
- Size: S
- Priority: top – do before all other open tasks (owner, 2026-10-08)
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-08
- Finished: 2026-10-08

## Goal

Remove the waiting in the implement-task process that does not come from
compile time (P0-65 handles that). Measured on the last 20 task agents
(2026-10-07): agents run the full matrix locally (mainnet unit, lowdiff
unit + functional, often both coverage builds – 3–4 builds per task, the
coverage unit tests alone take ~9.5 min at -O0) and then wait for CI to run
the same again; they wait with fixed `sleep 600`/`sleep 1200` timers
(~2 h in total, each overshooting by up to 20 min); and every merged task
changes the test counts written in four files, so the next PR conflicts and
has to merge master, rebuild, re-test and re-run CI (P0-21: twice, ~40 min).

## Steps

1. **Local test scope** (implement-task skill, CLAUDE.md "Testing"):
   - While developing: build the affected configuration and run only the
     affected unit suites / functional tests. Add `build.sh --unit-args
     "ARGS"` (e.g. `--run_test=random_tests`) to make that easy.
   - Before the PR: one mainnet unit run and one lowdiff unit + functional
     run (the CLAUDE.md minimum). Coverage and the gate run in CI only
     (P0-63 already runs them when gated files change); run coverage locally
     only to get `--suggest` values when raising a gate, or to debug a gate
     failure.
   - CI results on the PR count as the full run; paste them into the PR.
2. **No fixed sleeps**: the skill says to wait for background builds and CI
   on a completion marker (Monitor / until-loop on the log's exit line or
   the run's status), never `sleep N`; give a ready-made snippet for both.
3. **Single-source test counts**: stop hard-coding the number of unit and
   functional tests in CLAUDE.md, `contrib/testing/README.md`, the skill and
   `doc/architecture.md`. Either drop the exact numbers ("all unit tests
   pass; the low-difficulty build has one known exception …") or keep them
   in exactly one file that the others link to. The PR/task log records the
   actual counts instead. Keep the known-failure notes that matter.
4. **Merging master**: the skill merges `origin/master` once, right before
   the final test run and the PR, not at every step.
5. Update the board docs (project/README.md "How to process a task") if the
   process changes there.

## Acceptance criteria

- `build.sh --unit-args` works (tested: one suite, an invalid argument
  fails clearly) and is documented in `--help` and the README.
- The skill and CLAUDE.md describe the reduced local scope, the
  completion-marker waiting, and when coverage runs locally; no rule of
  CLAUDE.md "Rules for every change" is weakened (tests still run before
  every commit; full CI must be green before merge).
- No exact test count left outside the single source (grep shows it).
- Documentation reviewed like code.

## Notes

- Touches `build.sh` like P0-65; keep the change to the option parsing and
  the unit-test call, so the two merge cleanly.
- Owner request 2026-10-08: these two tasks first, then the rest of the board.

## Detailed description

Verified against master 9e5809be: the counts 397 (unit) and 48
(functional) are written in `CLAUDE.md` (Testing, 3 places),
`contrib/testing/README.md` (port-slot paragraph, "Expected results" table
and its heading that lists every task since P0-02), the implement-task
skill (step 8) and `doc/architecture.md` (test-levels table). CI
(`.github/workflows/tests.yml`) runs unit (both configs) + functional
(lowdiff) on every push and coverage + gate when the branch changes a
watched file (P0-63), so CI already repeats the full matrix.
`build.sh --functional-args` exists; there is no way to pass arguments to
`test_bitcoin` (it is called with fixed `--log_level=test_suite
--report_level=short`).

**Scope.** Process documents and one `build.sh` option. No C++/Python
test or node code, no CI workflow change, no consensus impact.

1. `contrib/testing/build.sh --unit-args "ARGS"`: extra arguments for
   `test_bitcoin`, appended after the fixed ones (default none = full run).
   - Option parsing like `--functional-args` (value may start with `--`,
     may be empty), passed into the container with the other inner args.
   - `--unit-args` without `--unit` fails ("--unit-args needs --unit"),
     so a forgotten `--unit` does not silently build without testing.
   - Split on any whitespace (newlines too) into an array with
     `read -r -d '' -a` – no glob expansion,
     so Boost filters such as `--run_test=pow_tests/*` reach `test_bitcoin`
     unchanged.
   - The log line says the run is filtered: `unit tests (filtered:
     --unit-args "--run_test=random_tests"; not a full run)`.
   - Summary check unchanged: a filtered run must still report `N test
     cases out of N passed`; an invalid argument or a filter that matches
     nothing makes `test_bitcoin` exit non-zero (Boost "no test cases
     matching filter" / unknown argument) → build.sh exits 1.
   - Vector checkers still run (≈5 s; unchanged behaviour of `--unit`).
   - Only option parsing, the inner-args line and the unit-test call
     change (P0-65 changes the Docker/ccache parts of the same file).
2. Skill + CLAUDE.md: local test scope (targeted while developing; full
   mainnet unit + lowdiff unit+functional before the PR and before every
   commit per rule 2; coverage only in CI except for `--suggest` /
   debugging a gate failure; CI results on the PR are the full run and
   must be green before merge).
3. Waiting on completion markers, never `sleep N`; snippets for a
   background `build.sh` and for a CI run.
4. Test counts: removed everywhere (option "drop the exact numbers"); the
   PR and task Log record the actual counts. The known-exception notes
   (`pow_tests/get_next_work_pow_limit` pinned per build) stay. The
   README heading "Expected results (2026-10-03, after P0-02 … P0-21)"
   becomes "Expected results" (it was another per-task conflict source).
5. Merge `origin/master` once, right before the final test run.
6. `project/README.md` "How to process a task": final merge + test scope
   + CI green; remove P0-66 from "Priority".

**Rules not weakened (CLAUDE.md "Rules for every change").** Rule 2
keeps "run the tests locally before every commit; at minimum the unit
tests; functional for node/wallet/RPC/P2P/consensus" and gains "full CI
green before merge". Targeted runs are an addition for the edit–build
loop between commits, never a replacement for rule 2's runs. Rules 1, 3–7
are not touched.

**Edge cases.** `--unit-args ""` = full run; `--unit-args` as last
argument → "needs a value"; value with `*`; `--unit-args` with
`--coverage` (rejected after the code review: a partial report would feed
`--coverage-report` and its gate); `--unit-args` with `--coverage-report` (rejected because
`--unit` is rejected there); `--no-docker` path (same inner args).

**How to test.**
- `build.sh --config mainnet --unit --unit-args "--run_test=random_tests"`
  → exit 0, `unit.log` "N test cases out of N passed" with N = suite size.
- `--unit-args "--run_test=no_such_suite"` → exit 1, clear message.
- `--unit-args "--bogus_arg"` → exit 1.
- `--unit-args x` without `--unit` → exit 1 "needs --unit"; with
  `--coverage` → exit 1; `--unit-args` last → "needs a value"; `--help`
  lists it.
- Final: full mainnet `--unit`, lowdiff `--unit --functional` (after the
  one merge of origin/master); CI green on the PR.
- `grep -rnE` for the old counts in the four files + README → nothing.

**Risks.** Weakening the review/test rules by wording – checked rule by
rule in the doc review. Merge conflict with P0-65 in `build.sh` – kept to
the agreed lines.

## Implementation plan

1. `build.sh`: `UNIT_ARGS=""` default; parse `--unit-args` (`[ $# -ge 2 ]`);
   check "needs --unit"; add `--unit-args "$UNIT_ARGS"` to the inner args;
   in the unit step `read -r -d '' -a UNIT_ARGV <<< "$UNIT_ARGS"`, append to the
   `test_bitcoin` call, log filtered runs; `--help` text. Verify with the
   parsing tests (no build needed) and one filtered build run.
2. `contrib/testing/README.md`: option row, quick-start example, drop
   counts and the heading list.
3. `CLAUDE.md`: Testing section without counts, local scope, waiting,
   coverage locally; rule 2 + "full CI green before merge".
4. Skill: step 6 targeted tests; step 8 merge once + final runs, passing
   criteria without counts, coverage note, CI; new "Waiting" section with
   snippets; step 11 CI green + counts in PR.
5. `doc/architecture.md`: drop counts.
6. `project/README.md`: process step, Priority entry removed.
7. Code review (self-review, no Agent tool), final runs, doc review,
   commit, PR, wait for CI with the new snippet.

## Log

- 2026-10-08: moved to inprogress (1f4d39a1), branch
  `task/P0-66-faster-task-workflow` from master 9e5809be.
- 2026-10-08, steps 3 and 5 (description and plan review): self-review
  (no Agent tool). Added from it: `--unit-args` must not glob-expand
  (`read -ra` instead of an unquoted variable, Boost filters use `*`);
  `--unit-args` without `--unit` fails; do not repeat `--log_level` /
  `--report_level` (documented). Verified that `test_bitcoin` has no own
  `main` (`test_bitcoin_main.cpp` only defines `BOOST_TEST_MODULE`), so
  Boost's argument parser handles `--unit-args`.
- 2026-10-08, step 7 (code review): `code-review` skill (medium) on the
  staged diff of /home/user/wt/P0-66, 10 findings. Applied:
  (1) docs-only branches get no CI test jobs (P0-64) – skill says so;
  (3) the merge of `master` must not create an untested commit – skill
  merges with the work stashed (merge commit = master + step-0 move) or
  with `--no-commit`, and nothing is pushed before the final run;
  (4) a filtered run is now marked in the first line of `unit.log` too;
  (5) newlines in `--unit-args` are split, not dropped (`read -d ''`);
  (6) `--unit-args` with `--coverage` is rejected (a partial report would
  feed `--coverage-report` and its gate);
  (7, 8) both wait snippets have a deadline (`timeout`) and say what to
  do when it fires; the CI snippet handles an empty run list (`// empty`).
  Answered, not changed: (2) after the one merge, a `master` that moves on
  without a conflict is not re-tested on the branch – that is the point of
  step 4 of this task; `master`'s CI after the merge runs everything again
  (said in the skill). (9) No machine-checked minimum test count – the
  owner's option "drop the exact numbers" was chosen; the skill now gives
  a command to compare with `master`'s CI count; a CI-side check would be a
  separate task (open point). (10) `--functional-args` still glob-expands
  (unquoted) – out of scope: the change is kept to option parsing and the
  unit-test call so it merges cleanly with P0-65; a `*.py` pattern
  matching files in the build dir is unlikely.
- 2026-10-08, build.sh tests (mainnet build, work dir
  /root/.cache/yacoin-build-P0-66): `--unit-args "--run_test=random_tests"`
  → exit 0, 12/12 (log line and first line of `unit.log` say FILTERED);
  `"--run_test=random_tests,util_tests"` → 34/34; `"--run_test=pow_tests/*"`
  → 5/5 (the `*` reaches Boost unexpanded); `"--run_test=no_such_suite"` →
  exit 1, "Test setup error: no test cases matching filter…" printed;
  `"--bogus_arg"` → exit 1, "An unrecognized parameter in the argument
  bogus_arg" printed (the error grep gained these two Boost messages);
  `--unit-args x` without `--unit`, with `--coverage`, with
  `--coverage-report`, and without a value → exit 1 with a clear message.
  Wait snippets tested: the CI snippet on run 37713883280 (completed,
  printed URL and jobs), and against a SHA without a run (`timeout` → 124).
- 2026-10-08, step 8.1: merged origin/master once (9e5809be, already up to
  date) with the new recipe.
- 2026-10-08, step 10 (documentation review): `code-review` skill
  (medium) on the staged diff of /home/user/wt/P0-66 against origin/master,
  9 findings, all applied: the stash list is shared by all worktrees →
  merge recipe uses `git stash create` (SHA, not on the list) and was
  tested in a scratch repo, including a conflict; the merge commit
  question (rules 2/4) → the skill explains why the first merge commit adds
  no untested code and uses `--no-commit` when work is already committed;
  CI snippet stops when no run appears instead of polling `gh run view ""`
  for 3 h; rule 2 says "its CI run is green" (docs-only PRs have no test
  jobs, P0-64) and CLAUDE.md describes what CI runs exactly instead of
  "the full matrix"; this file's description updated to the built
  behaviour (`read -r -d ''`, `--coverage` rejected); CLAUDE.md example
  gained `--config`; the functional count is compared with `BASE_SCRIPTS`
  + `EXTENDED_SCRIPTS`. Grep for the old counts (397, 48) in CLAUDE.md,
  contrib/testing/README.md, the skill, doc/architecture.md and
  project/README.md: only `P0-48` task references remain.
- 2026-10-08, step 8.2 (final local run, after the merge, `--jobs 2`):
  mainnet `--unit` exit 0, 397/397 unit test cases, vector checkers ok;
  lowdiff `--unit --functional` exit 0, 397/397 unit test cases, 48/48
  functional (= `BASE_SCRIPTS` 48 + `EXTENDED_SCRIPTS` 0; `master`'s CI run
  37141454729 also reports 397). No coverage run locally (CI runs it:
  `build.sh` is a watched file).
- Open point: no machine check of the test counts any more (review
  finding 9); a CI step comparing the branch's counts with `master`'s
  would be a possible follow-up task.
