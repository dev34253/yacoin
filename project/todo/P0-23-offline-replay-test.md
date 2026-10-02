# P0-23: Offline mainnet replay test

- Plan section: 0.3
- Depends on: P0-09, P0-15, P0-16, P0-18, P0-19, P0-46, P0-47
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Recompute every dumped value without running a node. Primary exit criterion for difficulty, trust, kernel, reward and header hash.

## Steps

1. Stream the full dump (opt-in via fixture download) and recompute: header hash, next target, running min nBits, block trust, chain trust, stake modifier and checksum, kernel result, block/PoS reward, max block size.
2. Same test on the in-repo fixture in normal CI.

## Acceptance criteria

- [ ] Full replay matches for every block, including every historical PoS block and stake modifier.
- [ ] Fixture replay runs in CI in < 5 minutes.

## Notes

Review: C3.

## Log

-
