# P0-12: CBigNum >256-bit behaviour and unused-method audit

- Plan section: 0.2a
- Depends on: P0-10
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Cover the values arith_uint256 cannot represent and decide which CBigNum methods actually need replacing.

## Steps

1. Tests for products and shifts past 2^256, negative intermediate results, and the exact expressions used in kernel.cpp (bnCoinDayWeight * bnTargetPerCoinDay) and chain.cpp ((CBigNum(1)<<256)/(bnTarget+1)).
2. Audit callers of pow, mul_mod, pow_mod, inverse, gcd, isPrime, setuint160/getuint160, setBytes/getBytes; list unused ones.

## Acceptance criteria

- [ ] Over-256-bit tests pass and document current results.
- [ ] List of used vs unused methods in Log.

## Notes

-

## Log

-
