# P0-09: Produce full mainnet dump and sampled in-repo fixture

- Plan section: 0.3
- Depends on: P0-07, P0-08, P0-05
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Produce the golden data used by the replay and kernel tests.

## Steps

1. Run the dump tool on the P0-07 snapshot; store the full dump per P0-05.
2. Select a sample (a few thousand records): every retarget and epoch boundary ±N blocks, hardfork heights, a spread of PoS blocks, all checkpoints, stake-modifier checkpoints.
3. Commit the sample under src/test/data/.

## Acceptance criteria

- [ ] Full dump stored with checksum.
- [ ] Sample committed, small enough for normal CI (target < 5 MB compressed).

## Notes

-

## Log

-
