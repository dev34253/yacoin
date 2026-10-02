# P0-47: Consensus test harness and global-state fixture

- Plan section: 0.2
- Depends on: P0-01
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-02
- Finished:

## Goal

Give all consensus unit tests one way to build chains and set global state.

## Steps

1. Block-index / chainActive / mapBlockIndex builder with chosen heights, times, nBits, PoW/PoS flags and stake fields.
2. Explicit setters (and restore on teardown) for nMainnetNewLogicBlockNumber, nFactorAtHardfork, nEpochInterval/nDifficultyInterval, fTestNet, tokenSupportBlockNumber.
3. Mocktime helpers; temporary block files (genesis on disk for the retarget, blocks for ReadBlockFromDisk).
4. Loader that builds index chains from the P0-09 fixture.

## Acceptance criteria

- [ ] Harness used by at least one test in pow, trust and kernel suites.
- [ ] Globals are restored after each test (no cross-test leakage).

## Notes

Review: A4, B7, D7.

## Log

- 2026-10-02 – Step 0: picked up; dependency P0-01 is in done/; moved to inprogress/
