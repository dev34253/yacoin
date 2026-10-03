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

## 7. Code review

Stage the changes (`git add`) and run the `code-review` skill (medium or
higher) on the staged diff. Fix every finding or answer it explicitly in the
Log. After substantial fixes, review again. Once P0-58 is in `project/done/`,
also run the static analysis on the changed files (CLAUDE.md rule 3).

## 8. Run the tests until they all pass

Use `contrib/testing/build.sh` (see `contrib/testing/README.md`; in cloud
sessions start Docker first, see CLAUDE.md "Environment notes"). Always run
both, even if CLAUDE.md rule 2 would allow less:

```bash
contrib/testing/build.sh --config mainnet --unit
contrib/testing/build.sh --config lowdiff --unit --functional
```

plus any task-specific tests from the description.

**Passing means:**
- mainnet: exit code 0, `unit.log` reports all test cases passed (327 today,
  plus any the task adds);
- lowdiff: exit code 0, `unit.log` reports all test cases passed (327
  today, plus any the task adds) and `functional.log` ends with `ALL ...
  Passed` (46 today, plus new ones). A test whose expected value depends on
  the chain parameters pins the value for each build (`#ifdef
  LOW_DIFFICULTY_FOR_DEVELOPMENT`, as in `pow_tests`) – it is never skipped
  in one of them.

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
5. Report back – as a subagent, all of this in your single final message:
   task id, branch, commit SHAs, PR URL, pass counts per configuration,
   review findings not applied (and why), open points.

## When blocked

Stop and report instead of guessing when: a dependency is not done, the
build or Docker does not work, the task would need a consensus change the
plan does not allow, the task is wrong or ambiguous and needs an owner
decision, or reviewers disagree on something important. Write the blocker in
the Log, commit and push what is useful on the task branch, and report the
blocker with the options you see. If the task is too big, split it as
`project/README.md` describes (new task files in `todo/`) and do the first
part.
