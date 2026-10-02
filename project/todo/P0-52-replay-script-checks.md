# P0-52: Script verification in the full replay

- Plan section: 0.3
- Depends on: P0-24
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Close or document the gap that reindex skips script checks below the last checkpoint.

## Steps

1. Add a test-only option to disable the below-checkpoint script skip (validation.cpp:1725) for the weekly reindex, or
2. if infeasible (time), document the residual risk and rely on script_tests and tx_valid/tx_invalid.

## Acceptance criteria

- [ ] Weekly replay verifies scripts for the whole chain, or the gap is documented and accepted in the plan.

## Notes

Review: B6.

## Log

-
