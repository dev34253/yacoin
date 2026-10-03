# Project board

This folder tracks the work to modernise Yacoin's dependencies (OpenSSL, Boost,
compiler) so it builds on current Linux distributions such as Ubuntu 24.04.

- `plans/` – the plans. Start with [`plans/overview.md`](plans/overview.md),
  then the detailed [`plans/phase0-test-safety-net.md`](plans/phase0-test-safety-net.md).
- [`plans/documentation-review.md`](plans/documentation-review.md) – review of the
  existing documentation (2026-10-03) and its follow-ups. The living
  documents are in `doc/`: [functional specification](../doc/functional-specification.md),
  [architecture](../doc/architecture.md), [design decisions](../doc/design-decisions.md).
- `runbooks/` – step-by-step operational guides (e.g. [mainnet node setup](runbooks/mainnet-node-setup.md)).
- `todo/` – tasks that have not been started.
- `inprogress/` – tasks someone is working on right now.
- `done/` – finished tasks.
- [`open-questions.md`](open-questions.md) – questions and decisions for the
  owner, collected while tasks are implemented; answer them there.
- [`known-issues.md`](known-issues.md) – findings recorded but deliberately not
  fixed (for after the modernisation unless they block it).

## How to process a task

Tasks are implemented with the `implement-task` skill
(`.claude/skills/implement-task/SKILL.md`), run by a subagent – see
`CLAUDE.md`. The skill covers the steps below plus the detailed description,
reviews, tests, documentation and pull request.

1. Pick a task from `todo/` whose dependencies (listed in the file) are all in `done/`.
2. Move it to `inprogress/` with `git mv` and commit that move on its own, so
   everyone can see the task is taken. Fill in `Owner` and `Started`.
3. Do the work on a branch. Keep one task per pull request where possible.
4. When every acceptance criterion is met, fill in `Finished`, add a short
   note under `Log` (what was done, PR link, anything surprising), and
   `git mv` the file to `done/` in the same pull request as the work.
5. If a task turns out to be too big, split it: create new task files in
   `todo/` with the next free numbers and link them from the original.

## Task file format

File name: `P<phase>-<number>-<short-slug>.md`, e.g. `P0-14-pow-synthetic-chain-tests.md`.

```
# P0-14: Title

- Plan section: 0.2b
- Depends on: P0-01, P0-10
- Size: S | M | L   (S ≈ under a day, M ≈ a few days, L ≈ a week or more)
- Owner:
- Started:
- Finished:

## Goal
## Steps
## Acceptance criteria
## Notes
## Detailed description   (added by the implement-task skill)
## Implementation plan    (added by the implement-task skill)
## Log
```
