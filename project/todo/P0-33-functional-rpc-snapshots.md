# P0-33: Functional test: RPC output snapshots

- Plan section: 0.5
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Detect unintended changes to RPC output, especially RPCs touched by CBigNum or OpenSSL.

## Steps

1. Deterministic chain; snapshot getblock, getblockheader, getdifficulty (incl. target field, rpc/blockchain.cpp:358), getmininginfo, getblocktemplate, getsubsidy, getwork (midstate and data – miner.cpp SHA256 internals), gettimechaininfo, calculatescrypthash.
2. Mask volatile fields; option to regenerate deliberately.

## Acceptance criteria

- [ ] test/functional/rpc_output_snapshots.py passes and is in test_runner.py.

## Notes

getblockchaininfo does not exist in this tree. Review: B5, C6.

## Log

-
