# P0-08: Per-block consensus value dump tool

- Plan section: 0.1, 0.3
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Write a tool that writes, for every block, the consensus values later phases must reproduce.

## Steps

1. Implement as a hidden RPC or a standalone binary linked against libyacoin_server.
2. Per block: height, hash, nTime, nBits, PoW/PoS flag, next required target (GetNextTargetRequired), GetBlockTrust, accumulated chaintrust, stake modifier, modifier checksum, hashProofOfStake, kernel check result.
3. Output a stable, line-oriented format (CSV or JSON lines) that compresses well.

## Acceptance criteria

- [ ] Tool runs against a synced data directory and produces a complete dump.
- [ ] Format documented; a reader for C++ tests exists.

## Notes

-

## Log

-
