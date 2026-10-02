# P0-14: Difficulty tests on synthetic chains

- Plan section: 0.2b
- Depends on: P0-02, P0-10
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Cover every function in pow.cpp with constructed block-index chains.

## Steps

1. Helper to build CBlockIndex chains with chosen times, nBits, PoW/PoS flags.
2. GetLastBlockIndex, CalculateNextWorkRequired, GetNextTargetRequired044, GetNextTargetRequired, GetProofOfStakeLimit, ComputeMaxBits, ComputeMinWork, ComputeMinStake.
3. Timespans extremely fast, extremely slow, exactly on target; clamping; genesis and first blocks; epoch and hardfork boundaries.
4. CheckProofOfWork: hash == target, ±1; negative, overflowing and zero nBits.

## Acceptance criteria

- [ ] pow.cpp: 100% of functions and ≥ 95% of lines covered by unit tests.

## Notes

-

## Log

-
