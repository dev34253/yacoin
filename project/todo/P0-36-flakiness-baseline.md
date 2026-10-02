# P0-36: Functional test flakiness baseline

- Plan section: 0.5
- Depends on: P0-03
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Know which tests are flaky before later phases change anything.

## Steps

1. Run the full functional suite 10×; record per-test pass rate and duration in a results file.
2. Repeat at Phase 0 exit (P0-45) including the new tests.

## Acceptance criteria

- [ ] Flakiness table committed; flaky tests have follow-up tasks.

## Notes

Review: D11.

## Log

-
