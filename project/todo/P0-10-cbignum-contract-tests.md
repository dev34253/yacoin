# P0-10: CBigNum contract tests: constructors, conversions, text, arithmetic

- Plan section: 0.2a
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Pin the behaviour of the CBigNum API used by the code.

## Steps

1. Constructors for each integer width at 0, 1, -1, min, max; from uint256/uint160.
2. setuint64/getuint64, setint64, setuint256/getuint256 round-trips, negative values.
3. SetHex (0x prefix, whitespace, odd length, invalid characters), ToString(base), GetHex, getvch/setvch, MPI format, Serialize/Unserialize.
4. + - * / %, shifts, ++/--, all comparisons; division by zero behaviour recorded.

## Acceptance criteria

- [ ] New test file src/test/bignum_tests.cpp passes.
- [ ] bignum.h line coverage from unit tests alone ≥ 90%.

## Notes

Test only through public methods so the tests can be reused against a replacement where the API stays.

## Log

-
