# P0-25: Mutated mainnet block rejection tests

- Plan section: 0.3
- Depends on: P0-09, P0-06
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Check invalid variants of real blocks are rejected for the same reason as the baseline.

## Steps

1. Take real PoW and PoS blocks; mutate nBits ±1, shift timestamps, tamper with the kernel, wrong stake modifier.
2. Submit to a node (regtest with mainnet params or unit-level ProcessNewBlock) and record the rejection reason.
3. Store expected reasons as a fixture.

## Acceptance criteria

- [ ] Every mutation rejected; reasons match the baseline binary.

## Notes

-

## Log

-
