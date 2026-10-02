# P0-27: Property-based tests for big-number and compact encoding

- Plan section: 0.4
- Depends on: P0-10
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Catch classes of arithmetic errors with algebraic identities on random inputs.

## Steps

1. (a*b)/b == a, (a<<n)>>n == a, a+b-b == a, compact round-trips, ordering consistency.
2. Inputs include >256-bit and negative values; fixed seed with option to randomise.

## Acceptance criteria

- [ ] Tests pass and run in < 10 s.

## Notes

-

## Log

-
