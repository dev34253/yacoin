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

1. GitHub Actions workflow using the P0-01 script: unit tests in the configuration chosen in P0-01; functional tests (test_runner.py -j4) in the low-diff configuration.
2. Collect lcov per configuration; define and document how the two .info files are merged (different #ifdef line maps) or reported separately.
3. Exclude /usr, depends, test, leveldb, secp256k1, univalue, bench.
4. Upload HTML and .info files as artifacts; print summaries in the log.

## Acceptance criteria

- [ ] Workflow runs on push and is green apart from known failures tracked in tasks.
- [ ] Coverage HTML downloadable from each run; merge method documented.

## Notes

Review: C5.

## Log

-
