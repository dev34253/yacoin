# P0-04: Per-file coverage minimums in CI

- Plan section: 0.1, 0.10
- Depends on: P0-03
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Fail CI when coverage of key files drops below an agreed level, and ratchet the levels up as Phase 0 progresses.

## Steps

1. Write a small script that reads the lcov .info file and checks per-file minimums from a config file.
2. Start with current values (kernel.cpp 17.9%, pow.cpp 76.9%, bignum.h 73.7%, chain.cpp 76.2%, crypter.cpp 73.4%, scrypt.cpp 7.3%, random.cpp 85.8%, overall 75.7%).
3. Document how to raise a threshold when a task improves coverage.

## Acceptance criteria

- [ ] CI fails if any listed file drops below its minimum.
- [ ] Thresholds file lives in the repo and is updated by later tasks.

## Notes

Final targets are in plan section 0.10.

## Log

-
