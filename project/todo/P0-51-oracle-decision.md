# P0-51: Decide and validate the post-OpenSSL reference oracle

- Plan section: 0.4
- Depends on: P0-13
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Choose an oracle that survives OpenSSL's removal.

## Steps

1. Option a: pimpl reference with BIGNUM* (BN_new) and libcrypto as a test-only dependency until Phase 4 is verified.
2. Option b (preferred): boost::multiprecision::cpp_int as an independent header-only oracle; check its C++ standard requirement against the project's C++11 setting and the Boost version.
3. Validate the chosen oracle against the P0-13 golden vectors.

## Acceptance criteria

- [ ] Decision and rationale in Log and in the plan.
- [ ] Oracle reproduces all golden vectors.

## Notes

An OpenSSL-backed CBigNum copy can't compile against OpenSSL ≥ 1.1. Review: E1, B8.

## Log

-
