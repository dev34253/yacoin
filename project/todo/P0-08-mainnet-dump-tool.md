# P0-08: Per-block consensus value dump tool

- Plan section: 0.1, 0.3
- Depends on: P0-01, P0-07
- Size: M
- Owner:
- Started:
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

-
