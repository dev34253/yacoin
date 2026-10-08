# P0-66: Faster task workflow – local test scope, no fixed sleeps, single-source test counts

- Plan section: 0.9
- Depends on: P0-64
- Size: S
- Priority: top – do before all other open tasks (owner, 2026-10-08)
- Owner:
- Started:
- Finished:

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
