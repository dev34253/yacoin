# P0-16: Block trust and chain trust tests

- Plan section: 0.2c
- Depends on: P0-10
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Pin GetBlockTrust, accumulated trust and fork choice.

## Steps

1. GetBlockTrust for PoW and PoS, zero target, maximum target, before/after hardfork, including the (1<<256)/(target+1) path.
2. Accumulated bnChainTrust over a synthetic chain; CBlockIndexWorkComparator ordering (validation.cpp:116).
3. chaintrust hex formatting in getblock/getblockheader (rpc/blockchain.cpp:96,127).

## Acceptance criteria

- [ ] chain.cpp ≥ 95% lines covered.
- [ ] Real-chain trust values from the sampled fixture match (once P0-09 is done).

## Notes

bnChainTrust is not serialised, so there is no disk format to preserve.

## Log

-
