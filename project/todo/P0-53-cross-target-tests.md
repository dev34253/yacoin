# P0-53: Run tests on Windows and macOS builds

- Plan section: 0.6
- Depends on: P0-01, P0-19, P0-44, P0-46, P0-49
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Make sure shipped targets compute the same consensus values.

## Steps

1. Run test_bitcoin for the mingw build under wine.
2. Run the known-answer suites (header hash, reward/max size, token names, compact encoding) on the macOS build (GitHub macOS runner).
3. Add the nightly job to the P0-44 skeleton.

## Acceptance criteria

- [ ] All known-answer suites pass on Linux, Windows and macOS builds.

## Notes

Review: B2, B3, B4, C7.

## Log

-
