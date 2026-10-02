# P0-31: Functional test: difficulty across epochs

- Plan section: 0.5
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check difficulty adjustment end to end on regtest.

## Steps

1. Use -epochinterval to force several retargets; mine with controlled timestamps.
2. Compare getdifficulty and nBits at each retarget with stored expected values from the baseline.

## Acceptance criteria

- [ ] test/functional/feature_difficulty_epochs.py passes and is in test_runner.py.

## Notes

Existing related test: feature_epoch.py.

## Log

-
