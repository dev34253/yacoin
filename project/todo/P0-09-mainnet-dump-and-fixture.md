# P0-09: Produce full mainnet dump and in-repo fixture

- Plan section: 0.3
- Depends on: P0-05, P0-07, P0-08
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Produce the golden data for replay, difficulty, kernel and reward tests.

## Steps

1. Run the dump tool on the tip snapshot; store the full dump (P0-05).
2. In-repo fixture: several contiguous segments (≥ 50k blocks each, enough for the 30-day stake age and modifier selection intervals) covering early PoS, the stake-switch time, pre-fork late chain and the fork boundary, plus all post-fork blocks (needed for nMinEase).
3. Include the matching block-index data needed to rebuild CBlockIndex chains in tests.
4. Measure the compressed size; if too large for the repo, keep the post-fork part in repo and segments in fixture storage.

## Acceptance criteria

- [ ] Full dump stored with checksum.
- [ ] Fixture available to CI; size and layout recorded in Log.

## Notes

Review: C2.

- Index data for the in-repo fixture: use the P0-47 index-chain CSV format (`src/test/README.md`), loaded with `LoadIndexChainCsvFile()` into a `TestChain`; segments start with `pprev == nullptr` at their first height.

## Log

-
