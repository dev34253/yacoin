# P0-32: Functional test: chain trust and reorgs

- Plan section: 0.5
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check fork choice by chain trust end to end.

## Steps

1. Competing PoW forks with different trust; reconnect; higher trust wins; header sync and peer behaviour (net_processing trust comparisons).
2. getchaintips, invalidateblock/reconsiderblock; chaintrust vs stored values.
3. When P0-55 exists: add PoS-after-PoW, PoS-after-PoS and PoW-after-PoS trust cases.
   (Owner 2026-10-03: Yacoin is PoW-only in the future; PoS matters only for
   validating the historical chain. P0-55's unit tests already cover these
   trust cases on synthetic pre-fork PoS blocks; a functional PoS generator is
   not needed – drop this step unless a historical-chain case requires it.)

## Acceptance criteria

- [ ] test/functional/feature_chaintrust_reorg.py passes and is in test_runner.py.

## Notes

Review: A5, C8.

- From P0-16: the unit tests in `src/test/chain_trust_tests.cpp` cover the
  trust comparisons in `net_processing.cpp` 438-456 (inv / block
  availability), 536 (block download) and 3113-3119 (`ConsiderEviction`),
  and fork choice by trust for PoW blocks on regtest. Not covered there and
  left to this task: the header-sync comparisons in `ProcessHeadersMessage`
  – 1481 (`m_last_block_announcement` for a header with more trust than the
  tip), 1507 (direct fetch when the headers reach at least the tip's trust)
  and 1583 (protecting an outbound peer whose best block has at least the
  tip's trust).

## Log

-
