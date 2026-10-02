# P0-27: Property-based tests for big-number and compact encoding

- Plan section: 0.4
- Depends on: P0-10
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Catch classes of arithmetic errors with identities on random inputs.

## Steps

1. (a*b)/b == a, (a<<n)>>n == a, a+b-b == a, compact round-trips, ordering consistency; inputs include >256-bit and negative values; fixed seed with a randomise option.

## Acceptance criteria

- [ ] Tests pass in < 10 s.

## Notes

-

## Log

-
