# P0-00: Decide Phase 0 logistics and scope

- Plan section: Open decisions
- Depends on: none
- Size: S
- Owner: dev34253 (decisions), recorded by Claude
- Started: 2026-10-02
- Finished: 2026-10-02

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

- [x] Each decision recorded in Log and reflected in plans/phase0-test-safety-net.md.

## Notes

Review: B9, E3, E5. Blocks P0-05, P0-07, P0-30, P0-44.

## Log

Decisions (2026-10-02):

| # | Topic | Decision | Consequences |
|---|---|---|---|
| 1 | Mainnet node host | **Your own machine/server**, registered as a self-hosted GitHub Actions runner. | Cloud sessions cannot run it: outbound P2P to the seed nodes on port 7688 is blocked there (tested). Needs a few hundred GB disk, 8+ GB RAM (scrypt-jane at Nf 20–21 uses 256–512 MiB per hash), outbound 7688. Host details to be recorded in P0-07. |
| 2 | Sync peers | **7 fixed seeds + known reliable peers** via `addnode`. | Peer list (from you / the community) recorded in the P0-07 runbook. No DNS seeds exist. |
| 3 | Where work lands | **Fork first (dev34253/yacoin), upstream later** in reviewed batches. | PRs target dev34253/yacoin `master`; upstream proposals once a coherent piece is solid. |
| 4 | Old release wallets | **Yes – v1.0.0/v1.1.0 encrypted wallets must stay readable** and are tested. | P0-30 and P0-54 stay in scope. |
| 5 | Qt | **Deferred.** Phase 0 builds with `NO_QT=1`. | Qt (5.7.1 in depends, BIP70/TLS, `qt/explorer.cpp` CBigNum) becomes its own later phase; listed in plans/overview.md. |
| 6 | CI and images | **GitHub Actions + GHCR.** Hosted runners for per-push jobs, the self-hosted runner for long jobs; `dev34253/yacoin-build` images mirrored to ghcr.io and pinned by digest. | Implemented in P0-44. |
| 7 | Build OS (added 2026-10-02) | **Ubuntu 24.04**, with GCC 11 pinned for Phase 0. | New task P0-57. Update: the Dockerfile lives in dev34253/yacoin-build-ubuntu and is published to Docker Hub (owner decision, 2026-10-02). GCC 13 is a Phase 1 change, so the baseline compiler stays constant. |

Open follow-ups (owned by the named tasks, not blocking P0-00):
- Machine specs, runner registration and peer list → P0-07 / P0-44.
