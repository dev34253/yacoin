# P0-06: Archive baseline binaries

- Plan section: 0.1
- Depends on: P0-01, P0-05, P0-08, P0-48
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Keep binaries that later phases are compared against, including the Phase 0 tooling.

## Steps

1. Build from the commit that contains the Phase 0 infrastructure (dump tool, gettxoutsetinfo, test hooks) but no consensus change.
2. Build both mainnet and low-difficulty variants of yacoind, yacoin-cli, test_bitcoin.
3. Store with commit hash, build image digest and SHA-256 sums (P0-05); helper to fetch them.
4. If later Phase 0 tasks add tooling the baseline needs, rebuild it before P0-45 and note it in Log.

## Acceptance criteria

- [ ] Baseline binaries downloadable and verified by checksum.
- [ ] Commit and build environment recorded.

## Notes

Review: D2.

## Log

-
