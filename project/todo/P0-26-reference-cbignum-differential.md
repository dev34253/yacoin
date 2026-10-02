# P0-26: Frozen reference CBigNum and differential harness

- Plan section: 0.4
- Depends on: P0-13
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Keep a copy of today's CBigNum for tests so Phase 4 can compare old and new implementations directly.

## Steps

1. Copy bignum.h into src/test/ as a test-only reference class (still OpenSSL-backed in test builds).
2. Harness: run the same operations through reference and production implementation and compare.

## Acceptance criteria

- [ ] Harness runs against the current (identical) implementation with zero differences.
- [ ] Documented how Phase 4 plugs a new implementation in.

## Notes

Later removed once Phase 4 is verified.

## Log

-
