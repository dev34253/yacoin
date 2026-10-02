# P0-35: Functional test: sync from a stored chain

- Plan section: 0.5
- Depends on: P0-05
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check headers-first sync between nodes using a stored chain.

## Steps

1. Commit a stored regtest chain fixture (or generate deterministically).
2. Node A serves it; node B syncs; compare tips, chaintrust and UTXO hash.

## Acceptance criteria

- [ ] test/functional/p2p_fixture_sync.py passes and is in test_runner.py.

## Notes

-

## Log

-
