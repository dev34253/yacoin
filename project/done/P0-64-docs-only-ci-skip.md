# P0-64: Skip builds and tests for documentation-only changes

- Plan section: 0.9
- Depends on: P0-63
- Size: S
- Owner: Claude (cloud session session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Documentation-only branches (and docs-only merges to master for the release
builds) should not need a full rebuild and test run (owner request,
2026-10-03).

## Detailed description

- `tests.yml`, job `changes`: a new step decides `tests`. On a branch (not
  master, not *Run workflow*) it lists every file changed since the merge base
  with `origin/master`; if all of them match `\.md$`, `^doc/`, `^project/`
  or `^\.claude/`, `tests=false` and the build/test matrix job and the
  coverage report job are skipped. Any error (no merge base, `git diff` or
  `grep` failure) and an empty change list answer `true` (fail safe). Like
  the coverage decision (P0-63) it looks at the whole branch, not only the
  latest push, so a docs push after a code push still runs the tests.
- `yacoinbuildmultiplatform.yml`: `paths-ignore` for the same patterns on
  pushes to master; path filters do not apply to tags.
- Manual flag: GitHub's built-in `[skip ci]` in the commit message (skips all
  workflows for that push) – documented, no code needed.
- Not covered: files outside those patterns that are documentation in
  practice (e.g. `COPYING`, `src/test/data/README.md` matches `*.md` so it is
  covered); a change to a workflow file itself always runs the tests.

## How to test

- Filter on sample lists: docs only → `grep` rc 1 (skip); docs + `src/pow.cpp`
  → rc 0 (run); missing file → rc 2 (run). Done locally.
- actionlint clean (ignoring the existing `actions/checkout@v3` warnings).
- CI on this branch: it changes workflow files, so the tests run (shows the
  "Run" path). The docs-only path is shown by the next docs-only branch.

## Log

- 2026-10-03: implemented directly in the cloud session (small workflow
  change; the session has the `workflow` scope). Filter tested locally;
  actionlint clean. Docs: `contrib/testing/README.md` (CI), `CLAUDE.md` (CI
  bullet). Reviewed: self-review of the workflow diff (fail-safe paths,
  regex escaping in YAML, coverage-report condition).
