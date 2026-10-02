# P0-35: Functional test: sync from a stored chain

- Plan section: 0.5
- Depends on: P0-05, P0-48
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check headers-first sync between nodes using a stored chain.

## Steps

1. Stored functional-test chain fixture (or deterministic generation).
2. Node A serves it; node B syncs; compare tips, chaintrust and gettxoutsetinfo hash.

## Acceptance criteria

- [ ] test/functional/p2p_fixture_sync.py passes and is in test_runner.py.

## Notes

Review: D1.

## Log

-
