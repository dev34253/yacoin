# P0-43: Nightly fuzzing job with corpus retention

- Plan section: 0.8, 0.9
- Depends on: P0-28, P0-44
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Run fuzzers continuously and keep inputs that find new paths.

## Steps

1. Scheduled job running each target for a fixed time in a sanitizer build.
2. Merge new corpus entries back into storage; report crashes as issues.

## Acceptance criteria

- [ ] Job runs nightly; corpus grows; crashes are reported.

## Notes

-

## Log

-
