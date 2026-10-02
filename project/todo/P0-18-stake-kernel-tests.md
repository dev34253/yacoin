# P0-18: Stake kernel accept/reject, overflow and edge tests

- Plan section: 0.2d
- Depends on: P0-12, P0-17, P0-47
- Size: L
- Owner:
- Started:
- Finished:

## Goal

Pin CheckStakeKernelHash and CheckProofOfStake behaviour.

## Steps

1. Real PoS blocks from the fixture accepted.
2. One-field mutations (hash, time, amount, nBits, prevout) rejected; reasons recorded.
3. Overflow inputs (product > 2^256), negative coin-day weight, truncated targetProofOfStake (kernel.cpp:568) vs full-precision comparison (:526).

## Acceptance criteria

- [ ] kernel.cpp (excluding debug logging) ≥ 90% lines.
- [ ] Edge behaviour documented in Log.

## Notes

Highest-risk area for Phase 4. Review: B10, C3. Primary criterion is the full replay in P0-23.

## Log

-
