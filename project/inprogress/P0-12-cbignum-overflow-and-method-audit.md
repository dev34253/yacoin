# P0-12: CBigNum >256-bit behaviour and method audit

- Plan section: 0.2a
- Depends on: P0-10
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Cover the values arith_uint256 cannot represent and decide which methods need replacing.

## Steps

1. Tests for the exact large-value expressions: kernel bnCoinDayWeight * bnTargetPerCoinDay (up to ≈2^263), chain.cpp (CBigNum(1)<<256)/(bnTarget+1), reward bisection products mid^6·powLimit and limit^6·target (~400 bits).
2. Negative intermediates (e.g. negative coin-day weight when txPrev.nTime > nTimeBlockFrom).
3. Audit callers of pow, mul_mod, pow_mod, inverse, gcd, isPrime, randBignum, RandKBitBigum, generatePrime, bitSize, isOne, getint32, setuint160/getuint160, setBytes/getBytes, ToString/GetHex. Start from the preliminary grep list in [plans/dead-code.md](../plans/dead-code.md) c), confirm or correct it there, and settle the names grep could not attribute (ToString, GetHex, SetHex, getvch/setvch, ++/--).

## Acceptance criteria

- [ ] Large-value tests pass and document current results.
- [ ] Used/unused method list in Log; unused ones excluded from coverage targets.

## Notes

Review: B1, B10, D9.

## Log

-
