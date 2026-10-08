---
name: implement-task
description: Implement one task from the yacoin project board (project/todo/P<phase>-<nn>-*.md) end to end – detailed description, reviewed plan, implementation, code review, tests, documentation, commit, push and pull request. Use when asked to implement, do, or work on a task such as "P0-14".
---

# Implement a project task

Input: a task id (e.g. `P0-14`) or the path of a task file. Work through the
steps **in order**; do not skip a step because the task looks small. Follow
`CLAUDE.md` throughout (consensus safety, tests before commit, logging,
documentation, task board).

Keep a running log in the task file's `## Log` section (date, step, result).

Findings outside the task (bugs, oddities, inconsistencies) are not fixed
unless they block the task or the modernisation goal
(`project/plans/overview.md`, "Scope and priorities"): record them in
`project/known-issues.md` (what, where, impact, found by). Only questions
that need an owner decision go into `project/open-questions.md`.

**Reviews (steps 3, 5, 7, 10):** use a reviewer subagent (Agent tool) when you
have one; give it the files to read and ask for concrete findings with
file:line evidence. If you are yourself running as a subagent and have no
Agent tool, do the review as a separate, deliberate pass: re-read the
material from scratch against the review checklist of that step, as a
critical reviewer would, and write "self-review (no Agent tool)" in the Log
and the PR. Treat all review output as advice: apply what is right, and write
down in the Log what you did not apply and why.

## 0. Pick up the task

1. Find the task file (`project/todo/`, or `project/inprogress/` if resuming).
2. Check that every task in its `Depends on` line is in `project/done/`. If
   not, stop and report which dependencies are missing.
3. Branch first: use the branch the session (or the parent agent) tells you
   to use; otherwise create `task/<id>-<slug>` from the latest `master`.
   Never commit or push directly to `master`.
4. On that branch, `git mv` the file to `project/inprogress/`, fill in
   `Owner` (e.g. "Claude (subagent of <session>)") and `Started`, commit
   that move on its own and push the branch.

## 1. Read the task carefully

Read the task file, the plan section named in its `Plan section` line (see
`project/plans/`; for Phase 0 `phase0-test-safety-net.md`), review findings
it cites (IDs such as C4 or B7 are in `project/plans/phase0-review.md`), and
the source files it names. Verify every factual claim in the task against the code (file:line).
Note anything that is wrong, outdated or ambiguous.

## 2. Write a detailed description

Add a `## Detailed description` section to the task file:

- **Scope:** exactly what will and will not be done; which files/areas change.
- **Behaviour:** what the result does, with concrete examples.
- **Edge cases:** inputs, states and environments that could break it
  (empty/large/negative values, missing files, concurrency, both build
  configurations, mainnet vs low-difficulty parameters, unit-test globals at
  0, Python 3.12, glibc ≥ 2.38, …).
- **How to test:** every acceptance criterion mapped to a concrete test or
  command and its expected result; which test levels apply (unit, functional,
  replay, manual).
- **Risks:** especially anything near consensus code (CLAUDE.md rule 1).

## 3. Review the description

Spawn a reviewer subagent on the description, the task file and the relevant
code: is it correct, complete, testable; are edge cases missing; does it stay
in scope? Incorporate the feedback you agree with; log the rest with reasons.

## 4. Implementation plan

Add a `## Implementation plan` section: ordered steps, files to create or
change, functions/tests to add, how each step is verified, and the logging and
documentation changes it needs. Keep each step small enough to review.

## 5. Review the plan

Spawn a reviewer subagent on the plan (with the description and code). Check
feasibility, missing steps, risky ordering, untestable steps, consensus
impact. Incorporate the feedback; log what you left out and why.

## 6. Implement

Implement the plan step by step. Match the surrounding code style. Add logging
per CLAUDE.md rule 5. Never change consensus behaviour unless the task says so
(rule 1). If the plan turns out wrong, update the plan section first, then the
code.

While developing, build only the configuration the change affects and run
only the affected tests (CLAUDE.md "Testing", *Local test scope*):

```bash
contrib/testing/build.sh --config mainnet --unit --unit-args "--run_test=pow_tests"
contrib/testing/build.sh --config lowdiff --functional --functional-args "-j2 feature_epoch.py"
```

Use your own `--work-dir` (and `--jobs` that leave room for other agents on
the same machine). Run builds in the background and wait for them as
described in "Waiting" below. The full runs come in step 8.

## 7. Code review

Stage the changes (`git add`) and run the `code-review` skill (medium or
higher) on the staged diff. Fix every finding or answer it explicitly in the
Log. After substantial fixes, review again. Once P0-58 is in `project/done/`,
also run the static analysis on the changed files (CLAUDE.md rule 3).

## 8. Run the tests until they all pass

Use `contrib/testing/build.sh` (see `contrib/testing/README.md`; in cloud
sessions start Docker first, see CLAUDE.md "Environment notes").

1. **Merge `master` once, now** – right before the final test run, not at
   every step. Your work is usually not committed yet (and `git merge`
   refuses to run over staged changes), so set it aside, merge, and bring
   it back:

   ```bash
   git fetch origin
   git add -A
   w=$(git stash create)   # your work as a commit; NOT on the stash list,
                           # which all worktrees of the repo share
   echo "work before merge: $w"          # keep this SHA in your notes
   [ -n "$w" ] && git reset -q --hard    # only once $w is set
   git merge --no-ff origin/master       # master + the step-0 move only
   [ -z "$w" ] || git stash apply "$w"   # resolve conflicts, then git add
   ```

   The merge commit changes no code relative to `master` (only the
   task-file move), so there is nothing in it for rule 2 to test that
   `master`'s CI has not; your work on top of it is tested by the final
   run before it is committed. Do not push until that run has passed. If
   the branch already holds work commits (e.g. a later merge because of a
   PR conflict; then the tree is clean), use `git merge --no-ff --no-commit
   origin/master` instead and commit the merge only after the final run
   passes (CLAUDE.md rules 2 and 4). Go back to step 7
   if resolving conflicts changed your diff. Merge again later only if
   GitHub reports a conflict on the PR, then repeat this step. (If `master`
   moves on without a conflict, `master`'s own CI after the merge runs
   everything again.)
2. **Final local run** – both configurations in full, even if CLAUDE.md
   rule 2 would allow less, plus any task-specific tests from the
   description:

   ```bash
   contrib/testing/build.sh --config mainnet --unit
   contrib/testing/build.sh --config lowdiff --unit --functional
   ```

   Do **not** run the coverage builds locally: CI runs coverage and the
   coverage gate (P0-63) on the PR whenever a watched file changes. Run
   `--coverage` locally only to get `coverage_gate.py --suggest` values
   when the task raises a gate minimum, or to debug a gate failure from CI.

**Passing means:**
- mainnet: exit code 0, `unit.log` reports `N test cases out of N passed`
  (`build.sh` checks this);
- lowdiff: exit code 0, `unit.log` reports `N test cases out of N passed`
  and `functional.log` ends with `ALL ... Passed`. A test whose expected
  value depends on the chain parameters pins the value for each build
  (`#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT`, as in `pow_tests`) – it is never
  skipped in one of them.
- The counts are not written down anywhere as a target (they changed with
  every task and made every PR conflict). Check them instead: the unit
  count must be `master`'s plus the test cases the task adds, where
  `master`'s is in its latest CI run –

  ```bash
  id=$(gh run list --repo dev34253/yacoin --branch master --workflow tests.yml \
         --status success -L1 --json databaseId -q '.[0].databaseId')
  gh run view "$id" --repo dev34253/yacoin --log |
      grep -E 'test cases out of [0-9]+ passed' | cut -f1,3
  ```

  – and the functional count (the `✓ Passed` rows of `functional.log`
  without the `ALL` row) must equal the number of entries in
  `BASE_SCRIPTS` + `EXTENDED_SCRIPTS` in `test_runner.py` (what runs by
  default; not `ALL_EXTENDED_SCRIPTS`); `git diff origin/master --
  test/functional/test_runner.py` shows what the task added. A lower count means tests were lost.

Fix and re-run until everything passes. If you changed code to make tests
pass, go back to step 7 for the new diff. Never skip, disable or weaken a
test. A flaky test is investigated, not re-run until green. Record the pass
counts per configuration in the Log.

## 9. Update documentation

Update everything the change affects, in the same branch: `doc/`,
`contrib/*/README.md`, RPC help, code comments, `CLAUDE.md`, plans, runbooks,
and the task file (tick acceptance criteria, Log). Document only what was
actually built and run.

## 10. Review the documentation

Spawn a reviewer subagent on the documentation changes: accurate against the
code and the test results, complete, consistent with other docs, readable.
Incorporate the feedback; log what you left out and why.

## 11. Commit, push and open a pull request

1. Fill in `Finished`, complete the Log, and `git mv` the task file to
   `project/done/` (in the same branch as the work).
2. Commit with a message that says what changed and why, the test results,
   and that code and docs were reviewed (and anything deliberately left as
   is). End it with the attribution lines the session requires.
3. Push the branch.
4. Open a pull request in **`dev34253/yacoin` against `master`** (never
   `yacoin/yacoin`; with `gh`: `gh pr create --repo dev34253/yacoin --base
   master`) with: summary, link to the task file, test results (pass
   counts), review notes, and open points. Use the repository's PR template
   if one exists. Add the PR link to the task Log.
5. Wait for CI on the PR (see "Waiting"). Its run is the full matrix (unit
   both configurations, functional, and coverage + gate when gated files
   changed): paste its result (run link, job conclusions, unit and
   functional pass counts) into the PR. A branch that changes only
   documentation (P0-64) gets no build or test jobs in CI – then say so in
   the PR; your local runs are the test record. If CI fails, fix, run rule
   2's local tests and step 7 for the fix, push, and wait again. The task
   is finished only when CI is green.
6. Report back – as a subagent, all of this in your single final message:
   task id, branch, commit SHAs, PR URL, pass counts per configuration,
   CI result, review findings not applied (and why), open points.

Never put the literal bracketed `skip ci` marker in a commit message: GitHub
then skips CI for that push.

## Waiting

Never wait with a fixed `sleep N`: it either wastes time or ends before the
work. Wait on a completion marker; a short poll interval inside a loop that
ends on the marker is fine.

**Background build.** Start it with the Bash tool's `run_in_background`
(the harness tells you when it exits) and append an exit line to its log:

```bash
contrib/testing/build.sh --config lowdiff --unit --functional \
    --work-dir "$WD" --jobs 2 > "$LOG" 2>&1; echo "build.sh exit $?" >> "$LOG"
```

To block on it from another command (e.g. with the Monitor tool), with a
deadline in case the build was killed and never writes the line:

```bash
timeout 3h bash -c 'until grep -q "^build.sh exit " "$0"; do sleep 20; done' "$LOG"
tail -n 30 "$LOG"
```

If `timeout` ends the loop (exit 124), check whether the build still runs
(`pgrep -af build.sh`, `docker ps`) instead of waiting again.

**CI run** (`gh` is preconfigured in cloud sessions; the GitHub MCP
`actions_*` tools are the alternative). Run this in the background too –
CI takes longer than one foreground tool call may:

```bash
sha=$(git rev-parse HEAD); repo=dev34253/yacoin
# 1. the run for this commit (none appears for a push whose commit message
#    carries the skip-ci marker – the deadline catches that)
id=$(timeout 10m bash -c 'until id=$(gh run list --repo "$0" --commit "$1" \
        --workflow tests.yml --json databaseId -q ".[0].databaseId // empty") &&
        [ -n "$id" ]; do sleep 15; done; echo "$id"' "$repo" "$sha")
[ -n "$id" ] || { echo "no CI run for $sha"; exit 1; }
# 2. until it has completed
timeout 3h bash -c 'until [ "$(gh run view "$0" --repo "$1" --json status \
        -q .status)" = completed ]; do sleep 60; done' "$id" "$repo"
gh run view "$id" --repo $repo --json conclusion,url,jobs \
    -q '.url, .conclusion, (.jobs[] | "\(.name): \(.conclusion)")'
```

A non-zero exit of `timeout` (124) means no run appeared or it did not
finish in time: look at the Actions page instead of starting another wait.

## When blocked

Stop and report instead of guessing when: a dependency is not done, the
build or Docker does not work, the task would need a consensus change the
plan does not allow, the task is wrong or ambiguous and needs an owner
decision, or reviewers disagree on something important. Write the blocker in
the Log, commit and push what is useful on the task branch, and report the
blocker with the options you see. If the task is too big, split it as
`project/README.md` describes (new task files in `todo/`) and do the first
part.
