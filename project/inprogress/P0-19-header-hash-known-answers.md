# P0-19: Block-header hash known-answer tests (scrypt-jane)

- Plan section: 0.2e
- Depends on: P0-01
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Pin the real proof-of-work hash path.

## Steps

1. CBlockHeader::GetHash() known answers for v<7 headers at every N-factor step in the primitives/block.h table (4…25), using timestamps at each step boundary.
2. v≥7 headers at nFactorAtHardfork 21 (mainnet), 4 (functional tests), 0 (unit tests).
3. Real mainnet headers from the fixture (after P0-09, via P0-23).
4. static_assert on packed header sizes (84 and 80 bytes; only the 84-byte v7 layout is `#pragma pack`ed).

## Acceptance criteria

- [ ] All known answers pass in both build configurations.
- [ ] Vectors stored hex in/out so P0-53 can run them on Windows/macOS.

## Notes

Replaces the original scrypt.cpp task: most of scrypt.cpp is dead code (P0-50). Review: A2, B4.

## Log

-
