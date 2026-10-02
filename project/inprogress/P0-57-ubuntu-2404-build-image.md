# P0-57: Ubuntu 24.04 build image (GCC 11 pinned)

- Plan section: 0.1
- Depends on: none
- Size: M
- Owner: Claude (cloud session)
- Started: 2026-10-02
- Finished:

## Goal

Move all Phase 0 builds to Ubuntu 24.04 (P0-00 decision 7) without changing the compiler the baseline is measured with. The image's Dockerfile lives in the repo so it is reproducible and reviewable (the current dev34253/yacoin-build images have no Dockerfile in the repo).

## Steps

1. Add `contrib/docker/ubuntu-24.04/Dockerfile` (+ `entrypoint.sh`) based on `ubuntu:24.04`, with the package list of the 22.04 image (build-essential, libtool, autotools-dev, automake, pkg-config, bsdmainutils, curl, git, ca-certificates, python3, gperf, zip, unzip, python3-setuptools, g++-multilib) plus `gcc-11`/`g++-11`, `lcov`, `zstd`. No Qt packages (Qt deferred).
2. Make GCC 11 the compiler (`update-alternatives` or `CC=gcc-11 CXX=g++-11` in the environment, also honoured by `depends`). GCC 13 stays installed but unused until Phase 1.
3. Check `depends` builds on 24.04 (watch for Python 3.12 removing `distutils`, newer autotools/`config.guess`, and host tools such as `bison`/`perl` versions); fix only build-host issues, never package versions.
4. Build and push to `ghcr.io/dev34253/yacoin-build:ubuntu-24.04-gcc11`; record the image digest.
5. Validate: mainnet and low-difficulty builds; unit and functional suites give the same results as the 22.04 baseline (functional 45/45; unit 238/239 with the known low-difficulty `pow_tests` case, or 239/239 in the mainnet configuration).

## Acceptance criteria

- [ ] Dockerfile and entrypoint committed; image published to GHCR and pinned by digest.
- [ ] `depends` + yacoin build succeeds in the image for both configurations.
- [ ] Test results identical to the 22.04 baseline (differences explained in Log).
- [ ] P0-01 and the runbook use this image.

## Notes

Phase 1 adds a GCC 13 variant of the same Dockerfile (`ubuntu-24.04-gcc13`) and fixes the code until it builds. The 22.04 image stays available as a reference until Phase 0 exit.

## Log

-
