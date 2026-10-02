# P0-18: Stake kernel accept/reject and overflow tests

- Plan section: 0.2d
- Depends on: P0-17, P0-12
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Pin CheckStakeKernelHash and CheckProofOfStake behaviour.

## Steps

1. Real PoS blocks from the fixture must be accepted.
2. Mutate hash, time, amount, nBits by one: must be rejected; record the reason.
3. Constructed inputs where bnCoinDayWeight * bnTargetPerCoinDay exceeds 2^256; record current results.

## Acceptance criteria

- [ ] kernel.cpp ≥ 90% lines covered (from 17.9%).
- [ ] Overflow behaviour documented in Log.

## Notes

kernel.cpp:436-626. This is the highest-risk area for Phase 4.

## Log

-
