# P0-56: Mutation testing of consensus math

- Plan section: 0.4
- Depends on: P0-14, P0-16, P0-18, P0-46
- Size: L
- Owner:
- Started:
- Finished:

## Goal

Measure whether the tests actually detect changes in consensus math.

## Steps

1. Run a mutation tool (or scripted mutants) over pow.cpp, chain.cpp trust, kernel.cpp kernel/modifier and the reward functions.
2. Each surviving mutant gets a test or a written justification.

## Acceptance criteria

- [ ] Mutation report committed; no unjustified survivors.

## Notes

Review: C4.

## Log

-
