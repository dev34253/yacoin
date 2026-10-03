# P0-14: Difficulty tests on synthetic chains

- Plan section: 0.2b
- Depends on: P0-02, P0-10, P0-47
- Size: L
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Cover every function in pow.cpp in pre-fork and post-fork mode.

## Steps

1. Using the P0-47 harness: GetLastBlockIndex, CalculateNextWorkRequired, GetNextTargetRequired044, GetNextTargetRequired, GetProofOfStakeLimit, ComputeMaxBits, ComputeMinWork, ComputeMinStake.
2. Pre-fork (old retarget branch pow.cpp:184-203) and post-fork (nMinEase scan over all post-fork blocks, genesis read from disk).
3. Timespans extremely fast/slow/on target; clamping; genesis and first blocks; epoch and fork boundaries.
4. CheckProofOfWork: hash == target, ±1; negative, overflowing, zero nBits.

## Acceptance criteria

- [ ] pow.cpp: 100% functions, ≥ 95% branches from unit tests.

## Notes

Review: A4, B7.

- Harness (P0-47) is in `src/test/consensus_harness.h`; `pow_tests/harness_*` already show the post-fork epoch retarget (genesis on disk) and the pre-fork per-block retarget.

## Log

-
