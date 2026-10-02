# P0-01: Scripted mainnet and low-difficulty build configurations

- Plan section: 0.1
- Depends on: none
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Have two reproducible builds: one with mainnet parameters (for unit tests and mainnet replay) and one with --enable-low-difficulty-for-development (for functional tests), both with optional coverage instrumentation.

## Steps

1. Write a script (e.g. contrib/testing/build.sh) that runs inside dev34253/yacoin-build:ubuntu.22.04-1: builds depends (NO_QT=1), then configures and builds yacoin.
2. Options: --config mainnet|lowdiff, --coverage, --sanitizers (placeholder for P0-29).
3. Build out-of-tree (copy or separate build dir) so the source checkout stays clean.
4. Document usage in contrib/testing/README.md, including the HTTPS proxy/CA variables needed in restricted environments.

## Acceptance criteria

- [ ] Both configurations build from a clean checkout with one command each.
- [ ] test_bitcoin, yacoind and yacoin-cli are produced for both.
- [ ] The source tree has no untracked or modified files after a build.

## Notes

Reference build: depends + CONFIG_SITE configure, CXXFLAGS='-O0 -g --coverage' for coverage builds.

## Log

-
