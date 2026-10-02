# P0-29: ASan and UBSan builds running unit and functional tests

- Plan section: 0.4
- Depends on: P0-01, P0-44
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Find memory errors and undefined behaviour (e.g. signed overflow in int64 timespans).

## Steps

1. Implement --sanitizers=address,undefined in the build script.
2. Run unit and functional suites; triage every report (fix-later note or justified suppression).
3. Add the nightly job to the P0-44 skeleton.

## Acceptance criteria

- [ ] Both suites run under sanitizers nightly; all reports triaged in Log.

## Notes

Record findings; no consensus changes in Phase 0.

## Log

-
