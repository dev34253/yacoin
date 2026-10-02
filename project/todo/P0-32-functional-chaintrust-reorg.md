# P0-32: Functional test: chain trust and reorgs

- Plan section: 0.5
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check fork choice by chain trust end to end.

## Steps

1. Build competing forks with different trust on separate nodes; reconnect; check the higher-trust chain wins.
2. getchaintips, invalidateblock/reconsiderblock; chaintrust values vs stored expected values.

## Acceptance criteria

- [ ] test/functional/feature_chaintrust_reorg.py passes and is in test_runner.py.

## Notes

-

## Log

-
