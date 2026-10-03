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

Golden vectors and their format: P0-13 (`src/test/data/bignum_vectors.json.xz`, `src/test/README.md`); the `Execute()` dispatcher in `src/test/bignum_vectors_tests.cpp` maps each op to the `CBigNum` code and can be reused for the production side.

Review: E1.

## Log

-
