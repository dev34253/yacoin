# P0-02: Triage pow_tests/get_next_work_pow_limit failure

- Plan section: 0.1
- Depends on: P0-01
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Find out why pow_tests/get_next_work_pow_limit fails (expected 0x1e0fffff, got 0x1e1a19f8; second check nextWork < retargetWork also fails).

## Steps

1. Run test_bitcoin in the mainnet configuration.
2. If it passes there: make the test skip or use different expectations under LOW_DIFFICULTY_FOR_DEVELOPMENT, or ensure unit tests always run in the mainnet configuration.
3. If it also fails there: investigate pow.cpp CalculateNextWorkRequired against the test's assumptions; record whether the test or the code is wrong (do not change consensus code in Phase 0).

## Acceptance criteria

- [ ] Root cause written in Log.
- [ ] Unit suite is green in the configuration CI uses for it, without weakening the check for the mainnet case.

## Notes

Test: src/test/pow_tests.cpp:50-68. Low-difficulty switches: chainparams.cpp:77,120,129,157.

## Log

-
