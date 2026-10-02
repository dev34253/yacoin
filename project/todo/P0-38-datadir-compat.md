# P0-38: Data directory compatibility test

- Plan section: 0.6
- Depends on: P0-06
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Check data directories (block index, chainstate, wallet) work in both directions between baseline and candidate.

## Steps

1. Create a datadir with the baseline; open with candidate; and the reverse.
2. Check chain state and wallet contents match.

## Acceptance criteria

- [ ] Test passes with candidate = baseline.

## Notes

-

## Log

-
