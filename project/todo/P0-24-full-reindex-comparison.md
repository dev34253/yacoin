# P0-24: Full reindex comparison script

- Plan section: 0.3
- Depends on: P0-07
- Size: M
- Owner:
- Started:
- Finished:

## Goal

End-to-end check that a candidate binary reaches exactly the same chain state.

## Steps

1. Script: copy block files, run -reindex -checkblocks=0 -checklevel=4, then compare tip hash, chaintrust, gettxoutsetinfo hash_serialized and state at each checkpoint against the baseline.
2. Variant using -reindex-chainstate.
3. Record duration and peak memory (feeds P0-41).

## Acceptance criteria

- [ ] Baseline binary vs itself: identical results (proves the script).
- [ ] Runbook in contrib/testing/README.md.

## Notes

-

## Log

-
