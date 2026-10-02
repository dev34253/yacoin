# P0-25: Mutated mainnet block rejection tests

- Plan section: 0.3
- Depends on: P0-06, P0-07, P0-09, P0-47
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check invalid variants of real blocks are rejected for the same reason as the baseline.

## Steps

1. Mutations of real PoW and PoS blocks: nBits ±1, shifted timestamp, tampered kernel, wrong stake modifier, wrong reward.
2. Submit against the -stopatheight snapshots from P0-07 (no deep invalidateblock reorgs), or at unit level via the P0-47 harness with on-disk block files.
3. Store expected rejection reasons as a fixture.

## Acceptance criteria

- [ ] Every mutation rejected; reasons match the baseline binary.

## Notes

Review: D5, D8.

## Log

-
