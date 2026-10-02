# P0-44: CI skeleton: schedules, runner, artifacts, images

- Plan section: 0.9
- Depends on: P0-00, P0-03, P0-57
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Provide the CI structure other tasks add their jobs to.

## Steps

1. Workflow triggers for push, nightly and weekly/manual; self-hosted runner registration (per P0-00).
2. Per-push jobs on GitHub-hosted runners; long jobs (reindex, replay, soak) on the self-hosted runner from P0-07 (P0-00 decisions 1 and 6).
3. Artifact and fixture-cache conventions.
4. Use `dev34253/yacoin-build:ubuntu.24.04-gcc11-1` (P0-57, Docker Hub) pinned by digest; optionally mirror the images to GHCR or authenticate pulls – Docker Hub anonymous pulls hit rate limits.
5. Document how a task adds a job.

## Acceptance criteria

- [ ] Skeleton committed; a placeholder nightly and weekly job run successfully.
- [ ] Images pulled by digest from the mirror.

## Notes

Each job task (P0-24, P0-29, P0-37, P0-40, P0-43, P0-53) adds its own job. Review: D3, E5.

## Log

-
