# P0-13: CBigNum golden-vector generator and test

- Plan section: 0.2a
- Depends on: P0-10
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Produce a large set of input/output vectors from today's CBigNum that any replacement must reproduce.

## Steps

1. Generator (test-only tool) running ~100k random and adversarial operations (boundaries, >256-bit, negatives, compact edge cases).
2. Write JSON (compressed) under src/test/data/; seed fixed so it is reproducible.
3. Unit test that replays the file and checks every result.

## Acceptance criteria

- [ ] Vectors committed; replay test passes and runs in < 30 s.

## Notes

Only include operations actually used by consensus code (see P0-12) plus compact encoding.

## Log

-
