# P0-21: Randomness tests and random_nonce.cpp decision

- Plan section: 0.2g
- Depends on: P0-01
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Pin the RNG API contracts before OpenSSL is removed from it.

## Steps

1. GetRand/GetRandInt ranges; GetStrongRandBytes no repeats across 1M calls; seeded FastRandomContext deterministic; Random_SanityCheck.
2. Loose chi-square test on byte distribution.
3. Determine whether random_nonce.cpp (0% covered) is used; test it or propose removal.

## Acceptance criteria

- [ ] random.cpp ≥ 90% lines covered.
- [ ] random_nonce.cpp status recorded.

## Notes

These tests catch broken generators, not weak ones; RNG changes in Phase 3 also need code review against Bitcoin Core.

## Log

-
