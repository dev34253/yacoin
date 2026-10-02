# P0-19: scrypt and N-factor known-answer tests

- Plan section: 0.2e
- Depends on: P0-01
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Pin the proof-of-work hash and the N-factor schedule.

## Steps

1. Known-answer vectors for scrypt_hash, scrypt_salted_hash, scrypt_salted_multiround_hash, scrypt_blockhash at each N-factor in use.
2. N-factor by timestamp incl. minNfactor, maxNfactor and maxNfactorYc1dot0 (main.cpp:92 ff.).
3. scrypt_blockhash of sampled mainnet headers equals stored hash (after P0-09).

## Acceptance criteria

- [ ] scrypt.cpp ≥ 90% lines covered (from 7.3%).

## Notes

scanhash_scrypt is mining code; cover it if practical, otherwise note why not.

## Log

-
