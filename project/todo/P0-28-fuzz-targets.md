# P0-28: libFuzzer harness and consensus fuzz targets

- Plan section: 0.4
- Depends on: P0-09, P0-29
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Fuzz the consensus math with sanitizers.

## Steps

1. Add a LLVMFuzzerTestOneInput entry point (test_bitcoin_fuzzy.cpp:256-270 is AFL stdin-only), keeping AFL support.
2. Targets: compact decode, big-number ops, CheckProofOfWork, difficulty on fuzzed index sequences, stake kernel, reward function, token-name validation.
3. Seed corpus from fixture values; store corpus (P0-05).

## Acceptance criteria

- [ ] Each target runs 10 minutes without findings in the sanitizer build, or findings are triaged.
- [ ] Corpus stored.

## Notes

Review: D5.

## Log

-
