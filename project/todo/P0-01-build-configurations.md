# P0-01: Scripted mainnet and low-difficulty build configurations

- Plan section: 0.1
- Depends on: P0-57
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Have reproducible mainnet and low-difficulty builds with optional coverage and sanitizer instrumentation.

## Steps

1. Script (e.g. contrib/testing/build.sh) running inside the Ubuntu 24.04 / GCC 11 image from P0-57 (`dev34253/yacoin-build:ubuntu.24.04-gcc11-1`): depends with NO_QT=1 (Qt deferred, P0-00 decision 5), then configure and build.
2. Options: --config mainnet|lowdiff, --coverage (sets both CFLAGS and CXXFLAGS so scrypt-jane C code is instrumented), --sanitizers (filled in by P0-29).
3. Build out-of-tree so the checkout stays clean.
4. Measure test_bitcoin runtime in both configurations (TestChain100Setup brute-forces blocks; mainnet powLimit may be slow) and record it.
5. Document usage, including the HTTPS proxy/CA variables needed in restricted environments, in contrib/testing/README.md.

## Acceptance criteria

- [ ] Both configurations build from a clean checkout with one command each.
- [ ] The source tree has no untracked or modified files after a build.
- [ ] Unit-test runtime per configuration recorded in Log, with a recommendation for which configuration(s) CI runs unit tests in.

## Notes

Review: C4, E4.

## Log

-
