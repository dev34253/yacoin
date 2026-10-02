# P0-48: Port gettxoutsetinfo (UTXO set hash)

- Plan section: 0.1
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Provide a UTXO-set hash to compare chainstates; the RPC does not exist in this tree.

## Steps

1. Port GetUTXOStats and gettxoutsetinfo from Bitcoin Core 0.16, adapted to Yacoin's coins/token data.
2. Unit test on a small chain; functional test calling it.

## Acceptance criteria

- [ ] RPC returns a stable hash_serialized for identical chainstates.
- [ ] Included in the baseline binary (P0-06).

## Notes

Adds an RPC but no consensus change. Review: D1.

## Log

-
