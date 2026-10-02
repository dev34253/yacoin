# P0-44: CI skeleton: schedules, runner, artifacts, images

- Plan section: 0.9
- Depends on: P0-00, P0-03
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Provide the CI structure other tasks add their jobs to.

## Steps

1. Workflow triggers for push, nightly and weekly/manual; self-hosted runner registration (per P0-00).
2. Artifact and fixture-cache conventions.
3. Mirror dev34253/yacoin-build images to GHCR (or authenticate pulls) and pin by digest – Docker Hub anonymous pulls hit rate limits.
4. Document how a task adds a job.

## Acceptance criteria

- [ ] Skeleton committed; a placeholder nightly and weekly job run successfully.
- [ ] Images pulled by digest from the mirror.

## Notes

Each job task (P0-24, P0-29, P0-37, P0-40, P0-43, P0-53) adds its own job. Review: D3, E5.

## Log

-
