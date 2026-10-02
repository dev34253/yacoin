# P0-26: Differential harness against the reference oracle

- Plan section: 0.4
- Depends on: P0-13, P0-51
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Let Phase 4 compare old and new implementations function by function.

## Steps

1. Implement the oracle chosen in P0-51.
2. Harness running the same operations (and the consensus expressions from P0-12) through oracle and production code.
3. Document how Phase 4 plugs in each replacement function.

## Acceptance criteria

- [ ] Zero differences between oracle and current code on the golden vectors and on random inputs.

## Notes

Review: E1.

## Log

-
