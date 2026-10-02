# P0-03: CI jobs for unit, functional and coverage

- Plan section: 0.1, 0.9
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Run unit and functional tests on every push and publish coverage reports.

## Steps

1. Add a GitHub Actions workflow using the P0-01 script: mainnet build → unit tests; lowdiff build → functional tests (test_runner.py -j4).
2. Collect lcov after unit and after unit+functional; exclude /usr, depends, test, leveldb, secp256k1, univalue, bench.
3. Upload HTML reports and .info files as artifacts; print the summary in the job log.

## Acceptance criteria

- [ ] Workflow runs on push and is green (apart from known failures tracked in tasks).
- [ ] Coverage HTML is downloadable from each run.

## Notes

Baseline: 56.7% unit, 75.7% unit+functional lines.

## Log

-
