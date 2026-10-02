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

1. Add `Dockerfile.ubuntu.24.04-gcc11` to dev34253/yacoin-build-ubuntu (owner decision; originally planned as `contrib/docker/ubuntu-24.04/Dockerfile` here) based on `ubuntu:24.04`, with the package list of the 22.04 image (build-essential, libtool, autotools-dev, automake, pkg-config, bsdmainutils, curl, git, ca-certificates, python3, gperf, zip, unzip, python3-setuptools, g++-multilib) plus `gcc-11`/`g++-11`, `lcov`, `zstd`. No Qt packages (Qt deferred).
2. Make GCC 11 the compiler (`update-alternatives` or `CC=gcc-11 CXX=g++-11` in the environment, also honoured by `depends`). GCC 13 stays installed but unused until Phase 1.
3. Check `depends` builds on 24.04 (watch for Python 3.12 removing `distutils`, newer autotools/`config.guess`, and host tools such as `bison`/`perl` versions); fix only build-host issues, never package versions.
4. Publish via that repo's workflow to Docker Hub as `dev34253/yacoin-build:ubuntu.24.04-gcc11-1`; record the image digest.
5. Validate: mainnet and low-difficulty builds; unit and functional suites give the same results as the 22.04 baseline (functional 45/45; unit 238/239 with the known low-difficulty `pow_tests` case, or 239/239 in the mainnet configuration).

## Acceptance criteria

- [ ] Dockerfile committed; image published to Docker Hub and pinned by digest.
- [x] `depends` + yacoin build succeeds in the image for both configurations.
- [x] Test results identical to the 22.04 baseline (differences explained in Log).
- [x] P0-01 and the runbook use this image.

## Notes

Phase 1 adds a GCC 13 variant of the same Dockerfile (`ubuntu-24.04-gcc13`) and fixes the code until it builds. The 22.04 image stays available as a reference until Phase 0 exit.

## Log

2026-10-02 (Claude, cloud session):

Build-host fixes needed on Ubuntu 24.04 (all behaviour-neutral, in dev34253/yacoin):
- `depends/patches/libevent/glibc-2.36-arc4random.patch` + `libevent.mk` – glibc ≥ 2.36 has `arc4random` but not `arc4random_addrandom` (backport of the libevent ≥ 2.1.12 fix). First tried forcing `ac_cv_func_arc4random=no`; that clashes with glibc's `arc4random_buf` declaration.
- `src/util.cpp` – drop unused `#include "strlcpy.h"` (glibc ≥ 2.38 fortified `strlcpy` clashes at -O2).
- Aligned with the independent GCC 13 session (yacoin-build-ubuntu PR #1): `#else` variant of the libevent patch, `lockedpool.cpp` `<stdexcept>`, `xcb_proto.mk` py-compile no-op (Qt only). Our tree now contains that session's patch byte-for-byte.
- Functional tests on Python 3.12: raw regex strings and `datetime.fromtimestamp(ts, timezone.utc)` (stderr warnings counted as failures).
- `wallet_dump.py`/`wallet_encryption.py`: pre-existing encryptwallet shutdown race fixed with `TestNode.node_encrypt_wallet()` (flaked once under load).

Validation with the exact image (`dev34253/yacoin-build:ubuntu.24.04-gcc11-1`, local build of 6a96f51) on commit 54cf95a + test fixes:

| Check | 22.04 baseline | 24.04 / GCC 11 |
|---|---|---|
| depends (NO_QT=1) | ok | ok |
| mainnet build | – | ok, 644 warnings |
| low-diff + coverage build | ok | ok, 644 warnings |
| unit, mainnet | – | 239/239 |
| unit, low-diff | 238/239 (pow_tests) | 238/239 (same case, same values) |
| functional | 45/45 | 45/45 (clean run) |
| line coverage unit / total | 56.7% / 75.7% | 53.2% / 75.6% (lcov 2.0 counts differently: 44,243 vs 59,121 lines) |

Notes: binaries built on 24.04 need glibc ≥ 2.38 (dev/CI only). Qt not tested in this image. The yacoin-build-ubuntu workflow republishes all image tags on every branch push.

Image: Dockerfile pushed to dev34253/yacoin-build-ubuntu branch `claude/ubuntu-2404-gcc11` (6a96f51); publishing run 37065216122 – digest pending.
