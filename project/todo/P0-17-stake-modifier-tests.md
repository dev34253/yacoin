# P0-17: Stake modifier tests with mainnet data

- Plan section: 0.2d
- Depends on: P0-09
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Cover stake-modifier computation using real block sequences.

## Steps

1. GetWeight, IsFixedModifierInterval, GetStakeModifierSelectionInterval(Section), SelectBlockFromCandidates, ComputeNextStakeModifier, GetKernelStakeModifier.
2. GetStakeModifierChecksum against every stake-modifier checkpoint (CheckStakeModifierCheckpoints).

## Acceptance criteria

- [ ] Computed modifiers and checksums match the fixture for all sampled blocks.

## Notes

kernel.cpp:74-386, 628-660.

## Log

-
