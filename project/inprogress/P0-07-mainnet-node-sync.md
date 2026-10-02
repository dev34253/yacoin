# P0-07: Sync a mainnet node and prepare block-data snapshots

- Plan section: 0.1, 0.3
- Depends on: P0-00, P0-01, P0-05
- Size: L
- Owner: Claude (local Remote Control session on artman-X) for dev34253
- Started: 2026-10-02
- Finished:

## Goal

Have a fully synced mainnet node from the current code and reusable data-directory snapshots.

## Steps

1. Provision your own machine/server (P0-00 decision 1): few hundred GB disk, 8+ GB RAM, outbound TCP 7688; register it as a self-hosted runner (P0-44). Configure the 7 fixed seeds plus addnode entries for known reliable peers; record the peer list in the runbook.
2. Sync with the mainnet build; record duration, disk usage, peak memory (feeds P0-41).
3. Snapshot blocks/ and chainstate/ at the tip; also make -stopatheight snapshots at chosen heights (before/after hardfork 1,890,000, a few PoS-era heights) for P0-25.
4. Store snapshots with checksums (P0-05).

## Acceptance criteria

- [ ] Tip snapshot and height snapshots available with checksums.
- [ ] Tip hash, height and chaintrust recorded.

## Notes

Follow project/runbooks/mainnet-node-setup.md. Longest lead time – start early. Review: D8, E3. Note -reindex-fast skips hash recomputation and is not a substitute for -reindex.

## Log

2026-10-02 – machine check and setup (via the local Remote Control session):

| Item | Value |
|---|---|
| Host | laptop `artman-X`, Ubuntu 26.04, i5-8300H (4C/8T), 30 GiB RAM, Samsung 980 NVMe 500 GB (334 GB free) |
| Build | commit `a2c7838` (master), mainnet, image `dev34253/yacoin-build:ubuntu.22.04-1` (P0-57 image not yet published) |
| SHA256 yacoind | `b3c1f03017f89e0cb594f6d50fa2db7e0e3c7ef7bf8cd3e31d2b2f1b6f90e168` |
| SHA256 yacoin-cli | `4570863ed50721c73982bd5c00171b82be2bbdba8926f8083f7c4a2a70ad9e8f` |
| Service | `yacoind.service` active and enabled; datadir `/srv/yacoin/datadir`; `dbcache=4000`; RPC localhost only |
| Peers | 2 – seed 62.146.224.245 and 104.6.0.174 (seed 96.32.210.58 unreachable) |
| Network height (peers) | ≈ 1,964,615 |
| Progress at +7 min | ≈ 350k headers (header-first stage; block count flat at 1,155); ~295 MiB RSS, ~2 cores |

Runbook fixes applied from this run: script-based build (nested `sudo -i` quoting broke `CONFIG_SITE`), header-stage note, `getinfo` instead of the non-existent `getblockchaininfo`, `-dirty` version note.

Open: sync completion time, final datadir size, peak memory, laptop sleep/lid settings, tip snapshot, height snapshots.
