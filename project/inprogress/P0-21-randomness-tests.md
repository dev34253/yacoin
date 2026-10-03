# P0-21: Randomness API tests

- Plan section: 0.2i
- Depends on: P0-01
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Pin RNG API contracts before OpenSSL is removed from it.

## Steps

1. GetRand/GetRandInt ranges; GetStrongRandBytes no repeats across 1M calls; seeded FastRandomContext deterministic; Random_SanityCheck.
2. Loose chi-square on byte distribution.
3. Record random_nonce.cpp as dead code (uses rand(), only caller is dead scanhash_scrypt) on the P0-50 list. Done by P0-50: [plans/dead-code.md](../plans/dead-code.md) a).

## Acceptance criteria

- [ ] random.cpp ≥ 90% lines.

## Notes

Catches broken generators, not weak ones – Phase 3 RNG changes also need review against Bitcoin Core. Review: A8.

## Log

- 2026-10-03 step 0: picked up; dependency P0-01 done; branch `task/P0-21-randomness-tests`.
