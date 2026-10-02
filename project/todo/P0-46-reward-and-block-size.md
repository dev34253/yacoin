# P0-46: Reward and block-size characterisation

- Plan section: 0.2f
- Depends on: P0-01, P0-47
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Pin the reward functions and the reward-derived block size limit.

## Steps

1. GetProofOfWorkReward pre-fork (CBigNum bisection, validation.cpp:918-979) and post-fork (double nInflation, validation.cpp:932).
2. GetMaxSize (consensus/consensus.cpp:26-27), GetProofOfStakeReward/GetCoinAge (consensus/tx_verify.cpp:415-422), LoadBlockRewardAndHighestDiff (validation.cpp:3714-3717, different evaluation order), getsubsidy.
3. Golden table: reward for every pre-fork nBits seen on mainnet (from the dump once P0-09 exists) plus boundary nBits; reward and max size per epoch.
4. Store vectors hex/decimal so P0-53 can run them on other targets.

## Acceptance criteria

- [ ] Reward functions 100% branch coverage.
- [ ] Golden table committed; replay of per-block rewards covered by P0-23.

## Notes

Second place where Phase 4 needs >256-bit arithmetic. Review: B1, B2.

## Log

-
