# P0-06: Archive baseline binaries

- Plan section: 0.1
- Depends on: P0-01
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Keep binaries built from the Phase 0 starting commit so later phases can be compared against them.

## Steps

1. Build yacoind, yacoin-cli and test_bitcoin (both configurations) from the starting commit.
2. Store them with the commit hash, build image digest and SHA-256 sums in the fixture storage (P0-05).
3. Add a helper that fetches them for cross-version tests.

## Acceptance criteria

- [ ] Baseline binaries downloadable and verified by checksum.
- [ ] Commit hash and build environment recorded.

## Notes

Used by P0-22, P0-25, P0-30, P0-37, P0-38.

## Log

-
