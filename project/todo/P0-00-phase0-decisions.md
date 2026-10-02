# P0-00: Decide Phase 0 logistics and scope

- Plan section: Open decisions
- Depends on: none
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Make the decisions the rest of Phase 0 depends on.

## Steps

1. Host for a fully synced mainnet node, its block data, dumps and the weekly 24–48 h reindex. A self-hosted runner is required (GitHub-hosted runners have a 6 h job limit and small disks).
2. Peers for syncing: there are no DNS seeds (chainparams.cpp:139-140 commented out); list addnode peers, and check outbound port 7688 is allowed on the chosen host.
3. Whether fixtures, the benchmark framework and new tests land in the dev34253 fork first or go straight upstream to yacoin/yacoin.
4. Whether wallets from v1.0.0/v1.1.0 must stay readable (default: yes, P0-30).
5. Whether Qt is in Phase 0 scope or deferred: depends Qt 5.7.1 won't build with GCC 13, CI ships yacoin-qt, qt/explorer.cpp uses CBigNum.
6. CI system for nightly/weekly jobs and where Docker images are mirrored (GHCR vs Docker Hub).

## Acceptance criteria

- [ ] Each decision recorded in Log and reflected in plans/phase0-test-safety-net.md.

## Notes

Review: B9, E3, E5. Blocks P0-05, P0-07, P0-30, P0-44.

## Log

-
