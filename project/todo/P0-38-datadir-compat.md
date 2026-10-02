# P0-38: Data directory compatibility test

- Plan section: 0.6
- Depends on: P0-06, P0-54
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Check data directories work both ways between baseline/old releases and candidate.

## Steps

1. Create a datadir with each; open with the other; compare chain state and wallet contents.
2. Fail on 'Failed stake modifier checkpoint' in debug.log (stored nStakeModifier/hashProofOfStake).

## Acceptance criteria

- [ ] Test passes with candidate = baseline.

## Notes

Review: A12.

## Log

-
