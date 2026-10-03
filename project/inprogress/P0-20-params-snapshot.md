# P0-20: Chain parameter and global-settings snapshot

- Plan section: 0.2h
- Depends on: P0-01
- Size: S
- Owner: Claude (subagent of owner session, laptop)
- Started: 2026-10-02
- Finished:

## Goal

Make accidental parameter changes fail loudly, for all three parameter sets.

## Steps

1. Mainnet: powLimit, genesis, checkpoints, stake-modifier checkpoints, ports, message start, fork height 1,890,000, N-factor at fork 21.
2. Functional-test set: low-difficulty genesis, epochinterval 10, nFactorAtHardfork 4, per-test fork height.
3. Unit-test defaults: the globals left at 0 (document as-is).
4. CRegTestParams (same magic and port as main) for completeness.

## Acceptance criteria

- [ ] Tests pass in both build configurations; parameter table added to the plan.

## Notes

Review: A3, A4.

## Log

-
