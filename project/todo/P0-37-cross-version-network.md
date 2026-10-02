# P0-37: Cross-version network test

- Plan section: 0.6
- Depends on: P0-06, P0-44, P0-54
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check baseline/old and candidate binaries agree on one network.

## Steps

1. Functional test starting low-difficulty builds of baseline, old releases (P0-54) and candidate; mine alternately; relay transactions.
2. Same tip, mutual acceptance, no misbehaviour disconnects.
3. Add the weekly job to the P0-44 skeleton.

## Acceptance criteria

- [ ] Test passes with candidate = baseline; documented how to point it at a new build.

## Notes

Release binaries are mainnet builds and can't join this network – hence P0-54. Review: E2.

## Log

-
