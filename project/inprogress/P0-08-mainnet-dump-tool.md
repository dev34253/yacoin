# P0-08: Per-block consensus value dump tool

- Plan section: 0.1, 0.3
- Depends on: P0-01, P0-07
- Size: M
- Owner: Claude (subagent of the local Remote Control session on artman-X) for dev34253
- Started: 2026-10-03
- Finished:

## Goal

Write the tool that records, for every block, everything later phases must reproduce, including the inputs needed to recompute it offline.

## Steps

1. Implement as a hidden RPC or a standalone binary linked against libyacoin_server.
2. Fields: height, hash, header hash and its N-factor, nTime, nBits, PoW/PoS, next required target, running min nBits since the fork, GetBlockTrust, accumulated chaintrust, stake modifier, modifier checksum, hashProofOfStake, kernel result.
3. Kernel inputs: blockFrom hash/time, txPrev.nTime, tx offset, prevout n, nValueIn, coinstake nTime, entropy bit / nFlags, prevoutStake.
4. Money: block reward, coinbase value, PoS reward and coin age, max block size, nMoneySupply.
5. Stable, line-oriented, compressible format (CSV or JSON lines) with a C++ reader for tests.

## Acceptance criteria

- [ ] Tool produces a complete dump from the P0-07 node.
- [ ] Format documented; C++ reader exists.

## Notes

Review: B7, C1.

- P0-47 defines the index-chain CSV format and loader used by the unit tests (`src/test/README.md`, *Index-chain CSV*: `height,hash,prev_hash,time,bits,version,nonce,merkle_root,flags,stake_modifier,hash_proof_of_stake,prevout_stake,stake_time`). Emit these column names (extra columns are ignored by the loader) or extend the loader.

## Log

- 2026-10-03 – step 0: picked up on branch `task/P0-08-mainnet-dump-tool`
  (from master 6859321). Dependencies: P0-01 is done; P0-07 is still in
  `inprogress/` (snapshots and checksums not finished), but the owner's
  answer to Q9 says P0-08 can start, and the parent session prepared a
  consistent tip snapshot of the node (height 1,964,617, tip
  `00000384e8e155597aad553e8609b27aec6321086fe6aeb029869f47dcce17bf`,
  taken with the node stopped, `/srv/yacoin/snapshots/p0-08-datadir/`),
  which is all this task needs from P0-07. Proceeding on that basis.
