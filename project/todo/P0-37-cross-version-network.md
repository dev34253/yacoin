# P0-37: Cross-version regtest network test

- Plan section: 0.6
- Depends on: P0-06
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check baseline and candidate binaries agree when running together.

## Steps

1. Functional test that starts baseline and candidate nodes (paths configurable), mines alternately, relays transactions.
2. Check same tip, mutual acceptance, no disconnects for misbehaviour.

## Acceptance criteria

- [ ] Test passes with candidate = baseline; documented how to point it at a new build.

## Notes

Similar to Bitcoin Core's feature_backwards_compatibility.py.

## Log

-
