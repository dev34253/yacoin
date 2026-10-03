# P0-13: Implementation-neutral golden vectors

- Plan section: 0.2a
- Depends on: P0-12
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Produce vectors from today's CBigNum that any replacement or oracle must reproduce.

## Steps

1. Generator (test-only) running ~100k random and adversarial operations limited to the methods/expressions found in P0-12, plus compact encoding.
2. Hex in / hex out JSON (compressed) under src/test/data/; fixed seed.
3. Replay test.

## Acceptance criteria

- [ ] Vectors committed; replay test passes in < 30 s.
- [ ] Format independent of CBigNum (usable by the oracle in P0-51/P0-26).

## Notes

Review: C9.

## Log

-
