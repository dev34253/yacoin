# P0-55: Synthetic PoS block generator (test-only)

- Plan section: 0.5
- Depends on: P0-47
- Size: L
- Owner:
- Started:
- Finished:

## Goal

Create valid proof-of-stake blocks in tests to reach branches the real chain never hits.

## Steps

1. Test-only helper that grinds a valid coinstake on a pre-fork test chain using mocktime and a target near the PoS limit (~0>>30).
2. Use it for PoS trust branches (P0-32), kernel overflow and mutation cases (P0-18/P0-25).

## Acceptance criteria

- [ ] Generator produces blocks accepted by CheckProofOfStake; used by at least one trust and one kernel test.

## Notes

No CreateCoinStake exists in this tree. Review: A9, C8.

## Log

-
