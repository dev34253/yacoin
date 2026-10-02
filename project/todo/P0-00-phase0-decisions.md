# P0-00: Decide Phase 0 logistics

- Plan section: Open decisions
- Depends on: none
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Make the decisions the rest of Phase 0 depends on.

## Steps

1. Decide where a fully synced mainnet node runs and where its block data (and full dumps) are stored: CI runner, a server, or a cloud session with enough disk.
2. Decide whether test fixtures, the benchmark framework and new tests land in the dev34253 fork first or go straight upstream to yacoin/yacoin.
3. Decide whether wallets from old releases (v1.0.0, v1.1.0) must stay readable; this sets the scope of P0-30.
4. Decide which CI system runs the nightly/weekly jobs (GitHub Actions hosted vs self-hosted runner).

## Acceptance criteria

- [ ] Each decision is written into this file's Log section and, where relevant, into plans/phase0-test-safety-net.md.

## Notes

Blocks P0-07, P0-30, P0-44.

## Log

-
