# P0-40: Microbenchmarks for affected code

- Plan section: 0.7
- Depends on: P0-39, P0-09
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Measure the code later phases will replace.

## Steps

1. CBigNum arithmetic, SetCompact/GetCompact, GetBlockTrust.
2. CheckProofOfWork, GetNextTargetRequired, CheckStakeKernelHash, ComputeNextStakeModifier.
3. scrypt_blockhash per N-factor.
4. AES encrypt/decrypt, key derivation, GetStrongRandBytes.
5. Block/transaction deserialisation, ConnectBlock on a stored block.

## Acceptance criteria

- [ ] All benchmarks run; baseline results (median of 5) committed.

## Notes

-

## Log

-
