# P0-23: Offline mainnet replay unit test

- Plan section: 0.3
- Depends on: P0-09, P0-15, P0-16, P0-18
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Replay every block's consensus values through the functions without running a node.

## Steps

1. Unit test that streams the full dump (opt-in, via fixture download) and recomputes next target, block trust, chain trust, stake modifier and kernel result.
2. Same test on the sampled fixture runs in normal CI.

## Acceptance criteria

- [ ] Full replay matches for every block.
- [ ] Sampled replay runs in CI in < 1 minute.

## Notes

-

## Log

-
