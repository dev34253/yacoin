# P0-34: Functional test: start/stop and shutdown

- Plan section: 0.5
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Catch thread shutdown and interruption regressions (Phase 2 Boost risk).

## Steps

1. Repeated start/stop; stop during sync, reindex and mining; SIGTERM; check clean exit and time limits.

## Acceptance criteria

- [ ] test/functional/feature_shutdown.py passes reliably (10/10 runs).

## Notes

-

## Log

-
