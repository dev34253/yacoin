# P0-21: Randomness API tests

- Plan section: 0.2i
- Depends on: P0-01
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Pin RNG API contracts before OpenSSL is removed from it.

## Steps

1. GetRand/GetRandInt ranges; GetStrongRandBytes no repeats across 1M calls; seeded FastRandomContext deterministic; Random_SanityCheck.
2. Loose chi-square on byte distribution.
3. Record random_nonce.cpp as dead code (uses rand(), only caller is dead scanhash_scrypt) on the P0-50 list.

## Acceptance criteria

- [ ] random.cpp ≥ 90% lines.

## Notes

Catches broken generators, not weak ones – Phase 3 RNG changes also need review against Bitcoin Core. Review: A8.

## Log

-
