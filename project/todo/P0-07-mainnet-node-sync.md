# P0-07: Sync a mainnet node and prepare block-data snapshots

- Plan section: 0.1, 0.3
- Depends on: P0-00, P0-01, P0-05
- Size: L
- Owner:
- Started:
- Finished:

## Goal

Have a fully synced mainnet node from the current code and reusable data-directory snapshots.

## Steps

1. Provision the self-hosted host from P0-00; configure addnode peers.
2. Sync with the mainnet build; record duration, disk usage, peak memory (feeds P0-41).
3. Snapshot blocks/ and chainstate/ at the tip; also make -stopatheight snapshots at chosen heights (before/after hardfork 1,890,000, a few PoS-era heights) for P0-25.
4. Store snapshots with checksums (P0-05).

## Acceptance criteria

- [ ] Tip snapshot and height snapshots available with checksums.
- [ ] Tip hash, height and chaintrust recorded.

## Notes

Longest lead time – start early. Review: D8, E3. Note -reindex-fast skips hash recomputation and is not a substitute for -reindex.

## Log

-
