# P0-17: Stake modifier tests with mainnet data

- Plan section: 0.2d
- Depends on: P0-09, P0-47
- Size: L
- Owner:
- Started:
- Finished:

## Goal

Cover stake-modifier computation using real contiguous block sequences.

## Steps

1. Set mainnet globals via P0-47 (otherwise ComputeNextStakeModifier and CheckStakeModifierCheckpoints return early) and mocktime.
2. GetWeight, IsFixedModifierInterval, selection intervals, SelectBlockFromCandidates, ComputeNextStakeModifier, GetKernelStakeModifier (incl. GetAdjustedTime error vs false path).
3. GetStakeModifierChecksum against every stake-modifier checkpoint.

## Acceptance criteria

- [ ] Computed modifiers and checksums match the fixture for every block in the fixture segments.

## Notes

Review: A4, B7. kernel.cpp:74-386, 628-660.

## Log

-
