# P0-16: Block trust, chain trust and fork-choice tests

- Plan section: 0.2c
- Depends on: P0-10, P0-47
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Pin every trust branch and its uses in fork choice and P2P.

## Steps

1. GetBlockTrust branches: genesis = 1; PoW before CONSECUTIVE_STAKE_SWITCH_TIME = 1; PoW after = powLimit/target (×2 after PoS); PoS after PoW = pprev->GetBlockTrust()+1; PoS after PoS = 0; legacy PoS = (1<<256)/(target+1); fTestNet switch (chain.cpp:83).
2. Accumulated bnChainTrust; CBlockIndexWorkComparator (validation.cpp:116).
3. GetBlockProofEquivalentTime (chain.cpp:188-205) – pin, don't fix.
4. net_processing.cpp comparisons (438-456, 536, 1481, 1507, 1583, 3113-3119) via unit-level scenarios where practical.
5. chaintrust hex in getblock/getblockheader and gettimechaininfo's getuint64 truncation (rpc/blockchain.cpp:945).

## Acceptance criteria

- [ ] 100% of GetBlockTrust branches covered.
- [ ] Mainnet trust values are checked by P0-23 (not here).

## Notes

Review: A5, A7, C8, D6.

## Log

-
