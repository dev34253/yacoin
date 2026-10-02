# P0-43: Nightly fuzzing with corpus retention

- Plan section: 0.8
- Depends on: P0-28, P0-44
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Run fuzzers continuously and keep inputs that find new paths.

## Steps

1. Nightly job per target in the sanitizer build; merge new corpus entries; report crashes.

## Acceptance criteria

- [ ] Job runs nightly; corpus grows; crashes reported.

## Notes

-

## Log

-
