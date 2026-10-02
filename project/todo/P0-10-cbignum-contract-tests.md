# P0-10: CBigNum contract tests incl. edge semantics

- Plan section: 0.2a
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Pin the CBigNum API behaviour used by the code (temporary tests, retired in Phase 4).

## Steps

1. Constructors for each integer width at 0, 1, -1, min, max; from uint256/uint160.
2. setuint64/getuint64, setint64, setuint256/getuint256 round-trips; getuint256/getuint64 return magnitude mod 2^n for large and negative values.
3. SetHex (0x prefix, whitespace, odd length, invalid characters), ToString(base), GetHex, getvch/setvch, MPI format, Serialize/Unserialize.
4. + - * / % (non-negative BN_nnmod), shifts (>> of negative gives 0), ++/--, comparisons; division truncates toward zero; division by zero behaviour recorded.

## Acceptance criteria

- [ ] src/test/bignum_tests.cpp passes.
- [ ] bignum.h (used methods) ≥ 90% line coverage from unit tests.

## Notes

Review: B10, C9.

## Log

-
