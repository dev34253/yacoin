# P0-28: New fuzz targets and seed corpus

- Plan section: 0.4
- Depends on: P0-09
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Extend test_bitcoin_fuzzy with consensus-math targets.

## Steps

1. Targets: compact decode, CBigNum operations, CheckProofOfWork, difficulty on fuzzed block-index sequences, stake kernel check.
2. Seed corpus from mainnet fixture values; store corpus in the repo or fixture storage.
3. Document how to run with libFuzzer or AFL.

## Acceptance criteria

- [ ] Each target runs for 10 minutes without crashes in a sanitizer build.
- [ ] Corpus committed or stored.

## Notes

Existing targets in src/test/test_bitcoin_fuzzy.cpp are all deserialisation.

## Log

-
