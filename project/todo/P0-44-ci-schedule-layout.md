# P0-44: CI schedule: per-push, nightly, weekly jobs

- Plan section: 0.9
- Depends on: P0-00, P0-03
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Organise all Phase 0 jobs by trigger.

## Steps

1. Per push: both builds, unit, functional, sampled replay, coverage + minimums.
2. Nightly: sanitizers, fuzzers, benchmarks, functional 3×.
3. Weekly/manual: full reindex + replay, cross-version network, long-running test.
4. Self-hosted runner setup if decided in P0-00.

## Acceptance criteria

- [ ] All jobs scheduled and documented; results visible in one place.

## Notes

-

## Log

-
