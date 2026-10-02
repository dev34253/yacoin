# P0-31: Functional test: difficulty across epochs

- Plan section: 0.5
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check difficulty adjustment end to end on the functional-test network (low-difficulty main params).

## Steps

1. Force several retargets (epochinterval 10); mine with controlled timestamps; set the fork height explicitly.
2. Compare getdifficulty and nBits at each retarget with stored expected values.

## Acceptance criteria

- [ ] test/functional/feature_difficulty_epochs.py passes and is in test_runner.py.

## Notes

Related: feature_epoch.py. Review: A3.

## Log

-
