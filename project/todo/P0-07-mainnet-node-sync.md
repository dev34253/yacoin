# P0-07: Sync a mainnet node and keep its block data

- Plan section: 0.1, 0.3
- Depends on: P0-00, P0-01
- Size: L
- Owner:
- Started:
- Finished:

## Goal

Have a fully synced mainnet node built from the current code, with its block files preserved as a test input.

## Steps

1. Provision the host decided in P0-00.
2. Sync from the network with the mainnet build; record time taken, disk usage and peak memory (also feeds P0-41).
3. Snapshot blocks/ and chainstate/ at a recorded height; store per P0-05.

## Acceptance criteria

- [ ] A snapshot of mainnet block data at a known height is available with checksums.
- [ ] Tip hash, height and chaintrust at that height recorded.

## Notes

Longest lead time in Phase 0 – start early.

## Log

-
