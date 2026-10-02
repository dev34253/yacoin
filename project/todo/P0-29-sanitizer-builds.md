# P0-29: ASan and UBSan builds running unit and functional tests

- Plan section: 0.4
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Find memory errors and undefined behaviour (e.g. signed overflow in int64 timespans in pow.cpp/kernel.cpp).

## Steps

1. Add --sanitizers option to the build script (address,undefined).
2. Run unit and functional suites; triage every report into fix-later notes or suppressions with justification.

## Acceptance criteria

- [ ] Both suites run under sanitizers; all reports triaged and recorded in Log.

## Notes

Do not change consensus behaviour in Phase 0; record findings.

## Log

-
