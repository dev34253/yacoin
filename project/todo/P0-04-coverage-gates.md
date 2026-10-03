# P0-04: Coverage gates (line and branch) in CI

- Plan section: 0.1, 0.10
- Depends on: P0-03, P0-50
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Fail CI when coverage of consensus code drops, using meaningful measures.

## Steps

1. Script reading lcov .info and checking per-file (and per-function-group) minimums from a config file.
2. Enable branch coverage for pow.cpp, chain.cpp, kernel.cpp and the reward functions in validation.cpp.
3. Exclude from denominators: dead code listed in P0-50 ([plans/dead-code.md](../plans/dead-code.md); its "gcov" column says which items are counted at all), dead fTestNet branches (list b there; they are branch-level), and kernel.cpp debug-logging blocks (fDebug / -printstakemodifier). If P0-59 has removed parts of the list, exclude only what is left.
4. Re-baseline thresholds from the merged CI numbers (not the single low-diff build); document how to ratchet them.

## Acceptance criteria

- [ ] CI fails when a gated file drops below its minimum.
- [ ] Thresholds config committed; later tasks raise it.

## Notes

Review: B11, C4, C5. Final targets: plan 0.10.

- `bignum.h` (P0-12): the target counts only the line ranges of the used
  methods listed in [plans/dead-code.md](../plans/dead-code.md) c) ("Used by
  production code" and "Used only inside `bignum.h`"). The unused methods are
  instantiated by `bignum_tests` in coverage builds, so a whole-file
  percentage would include them.

## Log

-
