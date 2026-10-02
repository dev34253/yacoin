# P0-40: Microbenchmarks for affected code

- Plan section: 0.7
- Depends on: P0-09, P0-39, P0-44
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Measure the code later phases will replace.

## Steps

1. Big-number ops, compact, GetBlockTrust; CheckProofOfWork, GetNextTargetRequired, CheckStakeKernelHash, ComputeNextStakeModifier; GetProofOfWorkReward (both branches).
2. CBlockHeader::GetHash per N-factor.
3. AES/KDF, GetStrongRandBytes; (de)serialisation; ConnectBlock on a stored block.
4. Add the nightly job to the P0-44 skeleton.

## Acceptance criteria

- [ ] Baseline results (median of 5) committed; nightly job runs.

## Notes

-

## Log

-
