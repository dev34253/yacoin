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

1. Competing PoW forks with different trust; reconnect; higher trust wins; header sync and peer behaviour (net_processing trust comparisons).
2. getchaintips, invalidateblock/reconsiderblock; chaintrust vs stored values.
3. When P0-55 exists: add PoS-after-PoW, PoS-after-PoS and PoW-after-PoS trust cases.

## Acceptance criteria

- [ ] test/functional/feature_chaintrust_reorg.py passes and is in test_runner.py.

## Notes

Review: A5, C8.

## Log

-
