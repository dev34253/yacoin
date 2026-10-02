# P0-02: Run unit tests in mainnet configuration and document the pow_tests failure

- Plan section: 0.1
- Depends on: P0-01
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-02
- Finished:

## Goal

Close out the known pow_tests/get_next_work_pow_limit failure.

## Steps

1. Root cause (from review): with the low-difficulty powLimit (2^253) the retarget 0x0fffff·2055491/1260000 = 0x1e1a19f8 is not clamped; with mainnet powLimit (2^236) it is. Confirm by running the test in the mainnet configuration.
2. Ensure the CI configuration that runs unit tests either uses mainnet parameters or skips/adjusts this test under LOW_DIFFICULTY_FOR_DEVELOPMENT, without weakening the mainnet check.

## Acceptance criteria

- [ ] Test passes in the mainnet configuration.
- [ ] Unit suite green in the configuration(s) CI uses.

## Notes

Review: D10. Test: src/test/pow_tests.cpp:50-68; powLimit: chainparams.cpp:78,82.

## Log

-
