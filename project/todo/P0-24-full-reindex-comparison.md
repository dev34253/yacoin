# P0-24: Full reindex comparison

- Plan section: 0.3
- Depends on: P0-06, P0-07, P0-44, P0-48
- Size: M
- Owner:
- Started:
- Finished:

## Goal

End-to-end check that a candidate binary reaches exactly the same chain state.

## Steps

1. Script: copy block files; -reindex -checkblocks=0 -checklevel=4; compare tip, chaintrust, gettxoutsetinfo hash, state at each checkpoint with the baseline.
2. Fail if debug.log contains 'Failed stake modifier checkpoint' (validation.cpp:3763-3764 only logs).
3. Variant with -reindex-chainstate. Do not use -reindex-fast (skips hash recomputation).
4. Record duration (expected 24–48 h) and peak memory (feeds P0-41); add the weekly job to the P0-44 CI skeleton.

## Acceptance criteria

- [ ] Baseline vs itself: identical results.
- [ ] Weekly job scheduled on the self-hosted runner; runbook committed.

## Notes

Review: A12, D5, E3.

## Log

-
