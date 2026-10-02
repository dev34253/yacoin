# P0-41: System-level performance baseline

- Plan section: 0.7
- Depends on: P0-24, P0-07
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Record end-to-end performance numbers to compare later phases against.

## Steps

1. Full reindex time and peak memory (from P0-24).
2. Sync time from a local peer.
3. Startup and shutdown time.
4. RPC latency for getblocktemplate and getblock under load.
5. Same machine, median of 5 runs; record hardware.

## Acceptance criteria

- [ ] Baseline table committed; method documented so it can be repeated.

## Notes

Changes > 10% are flagged for review, not failed automatically.

## Log

-
