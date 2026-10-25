# Local developer build

`dev.sh` in the repository root wraps a fast build and test loop for regular
development on Linux (tested on Ubuntu 22.04, 8 cores). It always builds
against the pinned libraries from `depends/`, never system libraries, so local
builds use the same dependency versions as the CI and release builds.

Everything it creates stays inside the repository and is ignored by git:

| Path | Contents |
|---|---|
| `depends/x86_64-pc-linux-gnu/` | Built dependencies (shared by all variants) |
| `build/<variant>/` | Out-of-tree build directories (`build/<host>/<variant>/` for a non-default `DEV_HOST`) |
| `.devbuild/ccache/` | Compiler cache (one directory, separate entries per variant) |
| `.devbuild/tmp/` | Temporary data directories of unit and functional tests |
| `.devbuild/logs/` | Logs, including one log per unit test suite |

## One-time setup

Install the host tools (needs sudo):

```sh
sudo apt install build-essential autoconf automake libtool bison bsdmainutils ccache pkg-config python3 curl
```

Build the dependencies once. Later runs reuse `depends/built/` unless a
package version changes.

```sh
./dev.sh depends        # without Qt, enough for yacoind and all tests
./dev.sh depends qt     # only needed for yacoin-qt
```

Some upstream download hosts accept the connection but never send data, and
depends then waits indefinitely (seen with samba.org for ccache). Stop the
build, download that file from the depends mirror into `depends/sources/`,
and run `./dev.sh depends` again; depends checks the package hash. For example:

```sh
curl -fL -o depends/sources/ccache-3.3.4.tar.bz2 \
    https://bitcoincore.org/depends-sources/ccache-3.3.4.tar.bz2
```

## Building in the CI containers

`depends/` does not build with gcc 14 or newer (Boost 1.64). On such a host, or to run what a CI job runs, use the CI build images. They need
only Docker; `./dev.sh container` builds the image from `ci/containers/` (Docker caches it after the first time) and runs one mode of it
with this checkout mounted:

```sh
./dev.sh container unit-tests                # ubuntu.22.04 image: test_bitcoin, all suites in parallel
./dev.sh container functional-tests          # ubuntu.22.04 image: low-difficulty build, functional tests serially
./dev.sh container ubuntu.16.04 unit-tests   # the same in another image
./dev.sh container build                     # release build, as the CI release jobs (see below)
./dev.sh container windows                   # Windows release build; macos for macOS
```

Images: `ubuntu.16.04`, `ubuntu.18.04`, `ubuntu.20.04`, `ubuntu.22.04` (default), `ubuntu.24.04-gcc11`, `windows`, `macos`. Modes of the
Ubuntu images: `build` (default), `build-low-difficulty`, `unit-tests`, `functional-tests`, `cov-unit` (22.04 only); `windows` and `macos`
only build.

- The test modes build out of tree in `build/docker-<image>/<mode>/`, which is recreated on every run, against their own depends without Qt
  in `build/docker-<image>/depends/`. Unit test logs are in `build/docker-<image>/unit-tests/unit-test-logs/`, functional test data in
  `build/docker-<image>/functional-tests/test/tmp/`.
- The `build` mode does what the CI release jobs do: depends with Qt into `depends/<host>/` (for Linux the prefix `./dev.sh depends` uses),
  configure in the source tree, and `make install` into `release-root/`. Because it configures in place, out-of-tree builds (`dev.sh`
  and the test modes) refuse the tree afterwards until `make distclean`. Run release builds in a separate clone, for example
  `git clone . ../yacoin-release && ../yacoin-release/dev.sh container build`.
- Depends packages, depends sources and ccache data are kept in `.devbuild/container-cache/` per image, so only the first run of an image
  builds depends. Measured on 8 cores: the first `./dev.sh container unit-tests` takes about 13 minutes on an idle machine (40 with
  other builds running), the second 1-2 minutes (all compiles from ccache).
- The container runs as root, as in CI; afterwards `ci/containers/run.sh` gives the files it wrote back to you (with rootless Docker or
  Podman they are yours already). Run one container per checkout at a time.
- `JOBS` sets the parallelism (default: all CPUs, 4 for `windows` and `macos`); `BUILDVERSION`, `CCACHE_MAXSIZE` (default 5G) and
  `CCACHE_COMPRESS` are passed on as well. Only values you set are passed on, not `dev.sh`'s own defaults for its host builds.
- Options of `ci/containers/run.sh` (`--help`) go before the image, for example `./dev.sh container --no-cache unit-tests` or
  `--src <dir>` for another tree.
- CI runs these images, built from `ci/containers/`, under tags that name the files they were built from:
  `ci/containers/image-tag.sh <image>` prints the tag (`ghcr.io/dev34253/yacoin-build:<image>-<hash>`). Images built on `master` are
  published under it, so `docker pull "$(ci/containers/image-tag.sh ubuntu.22.04)"` gets the image CI uses for this checkout once
  `master` has it; `./dev.sh container` builds it locally instead.
- `ci/containers/README.md` describes the images, how CI builds and publishes them, the image checks (`check.sh`) and the comparison
  with the images on Docker Hub (`parity.sh`).

## Build variants

| Variant | Purpose | Configuration |
|---|---|---|
| `dev` | Unit tests, TDD loop | Mainnet consensus, no GUI, `-O1 -g` |
| `func` | Functional tests | `dev` plus `--enable-low-difficulty-for-development` (as in CI) |
| `release` | Check before a PR | Mainnet, default optimisation |
| `asan` | Memory and UB checks | `dev` plus AddressSanitizer, LeakSanitizer and UBSan |

The unit tests assume mainnet consensus parameters (for example `pow_tests`),
so they fail on the low-difficulty build. The functional tests need it.

All variants use one ccache directory. Because they're built with `-g`, ccache
keys entries on the build directory, so variants don't share cached objects
and debug info always points at the variant's own build directory. The first
build of each variant is therefore a cold build. The `asan` variant builds
secp256k1 without its x86_64 assembly, which doesn't compile under ASan.

## Commands

```sh
./dev.sh build dev                  # build everything in build/dev
./dev.sh build dev test/test_bitcoin  # build one make target
./dev.sh unit                       # all unit test suites, in parallel
./dev.sh unit pow_tests coins_tests # selected suites
./dev.sh check                      # upstream "make check" (serial)
./dev.sh ftest                      # all functional tests, 4 in parallel
./dev.sh ftest feature_tokens.py    # selected functional tests
./dev.sh asan                       # unit tests under ASan/LSan/UBSan
./dev.sh all                        # build dev, unit, ftest, build release
./dev.sh ccache-stats
```

A variant is configured automatically on first use; `./dev.sh configure
<variant>` reconfigures it. `./dev.sh all` runs every step even when one
fails, and ends with a PASS/FAIL summary.

Out-of-tree builds don't work if the source tree itself was configured in
place (`./configure` in the repository root). `dev.sh` stops with a message
in that case; run `make distclean` in the repository root once.

### TDD loop

1. Write or change a test in `src/test/`.
2. `./dev.sh unit <suite>` rebuilds only `test_bitcoin` and runs that suite.
3. Change the code until it passes, then run `./dev.sh unit` for all suites.
4. Before a PR: `./dev.sh all` and `./dev.sh asan`.

### Unit tests in parallel

`./dev.sh unit` lists the Boost test suites and runs each in its own process
(`UNIT_JOBS`, default: `JOBS`). The test fixtures create their data
directories under the temp directory, so every process gets its own `TMPDIR`.
The suites don't use network ports or other shared state. Results are the
same as a serial run. Per-suite logs and `summary.txt` are written to
`.devbuild/logs/unit-<variant>/` (`unit-dev` or `unit-asan`), so `unit` and
`asan` can run at the same time.

### Functional tests

`./dev.sh ftest` runs `FTEST_JOBS` scripts in parallel (default 4;
`FTEST_JOBS=1` for a serial run). Each script gets its own data directory under
`.devbuild/tmp/` and its own ports, and the runner builds the shared chain cache
once before starting the scripts.

Two runner invocations on the same build directory at the same time do
interfere: each run without `--keepcache` deletes `build/func/test/cache`
while the other may be copying it, and both number their scripts' port seeds
from 0. For a second, concurrent run, set `TEST_RUNNER_PORT_MIN` to a range the
first doesn't use (the default base is 11000 and a run uses 10000 ports, so
e.g. `TEST_RUNNER_PORT_MIN=22000`) and pass `--keepcache`. A script run
directly (`test/functional/<script>.py --configfile=build/func/test/config.ini`)
keeps its cache in `test/cache` and takes its port seed from its process id,
so it only needs `TEST_RUNNER_PORT_MIN` to stay clear of a runner's ports.

## Code coverage

Needs `lcov` (`sudo apt install lcov`; Ubuntu 22.04 ships lcov 1.15, which
works with gcc 11). `gcov` must match the compiler version.

```sh
./dev.sh cov
```

The unit tests need mainnet consensus and the functional tests need the
low-difficulty build, so no single build can run both. `./dev.sh cov` uses
two coverage builds (`--enable-lcov`, `-O0 -g`):

| Build | Runs | Make target |
|---|---|---|
| `build/cov-unit` | `test_bitcoin` (all unit tests) | `make cov-unit` |
| `build/cov-func` | All functional tests (serially unless `FTEST_JOBS` is set) | `make cov-functional` |

Each target zeroes the counters, records a baseline (so files that are never
executed still count), runs the tests, and keeps the coverage even if tests
fail. It then removes vendored and test code (leveldb, secp256k1, univalue, ctaes,
`src/test`, `src/wallet/test`) and writes an HTML report. `./dev.sh cov`
then merges both results and writes line, function and branch coverage to
`.devbuild/coverage/`:

- `unit/index.html`
- `functional/index.html`
- `total/index.html`, with both merged

Notes:

- The merged report combines two builds. Lines that exist in only one build
  (inside `LOW_DIFFICULTY_FOR_DEVELOPMENT` blocks) only have that build's
  counts. Branches are merged by position, so on the few lines whose
  conditions differ between the builds the merged branch numbers are only
  approximate. Line and function coverage aren't affected.
- Only lcov 1.x is supported, and configure checks for it. lcov 2.x rejects
  filter patterns that match nothing and has renamed the branch-coverage option.
- With both builds cached, a full run takes about 27 minutes on 8 cores:
  unit coverage about 5½ minutes, functional coverage about 21 minutes. Most
  of that was the functional tests run serially (about 20 minutes at `-O0`,
  measured before they ran in parallel and lost a 10 s sleep per node
  connection; not re-measured since) and
  `transaction_tests/test_big_transaction` (about 3 minutes). Building both
  `-O0` variants from scratch adds about 13 minutes.
- To keep that time down, lcov captures run `geninfo` in parallel
  (`contrib/devtools/coverage-capture.sh`), the baseline is captured while
  the tests run, and the unit test suites run in parallel
  (`contrib/devtools/run-unit-suites.sh`, the runner `./dev.sh unit` uses).
  `COV_JOBS` sets the number of processes (default: all cores), e.g.
  `make cov-unit COV_JOBS=4`.
- Branch coverage excludes exception edges
  (`geninfo_no_exception_branch=1`). Without that, C++ branch numbers are
  mostly noise.
- Assembly (`scrypt-x86_64.S`) and the vendored libraries aren't measured.
- Nodes that the functional tests kill with SIGKILL don't write their
  counters, so code that only those nodes ran is under-reported.
- The targets also work without `dev.sh`: configure a build with
  `--enable-lcov` and run `make cov-unit` or `make cov-functional` in it.
  With depends, make re-runs configure by itself when `configure.ac` or a
  `Makefile.am` changed, and that re-run only finds the depends libraries if
  `CONFIG_SITE` is set for make too, or if the build was configured with
  `--prefix=$PWD/depends/<host>`. `dev.sh` exports `CONFIG_SITE` for this
  reason.

## Reference timings

Ubuntu 22.04, 8 cores, 15 GB RAM.

| Step | Time |
|---|---|
| `depends` without Qt (first run, including downloads) | 4 min 14 s |
| Configure one variant | 48 s |
| Clean build of a variant, cold ccache | 6 min 52 s – 7 min 55 s |
| Rebuild of a variant after reconfiguring it, warm ccache | 67 s |
| Rebuild `test_bitcoin` after changing one source file | 7 s |
| All unit tests, serial | 29 s |
| All unit tests, parallel (`./dev.sh unit`) | 15 s |
| All functional tests, serial (`FTEST_JOBS=1 ./dev.sh ftest`) | 4 min 20 s |
| All functional tests, 4 in parallel (`./dev.sh ftest`) | 73 s |

The parallel unit test time is bounded by `transaction_tests/test_big_transaction`
(about 17 s at `-O1`).

## Baseline test results (v1.11.0, 9706af8b)

- Unit tests (`dev`): 53 of 53 suites, 239 test cases pass.
- Functional tests (`func`): 45 of 45 pass.
- Sanitizers (`asan`): 49 of 53 suites pass. Findings:
  - `checkqueue_tests`: stack-use-after-scope in `test_CheckQueueControl_Locks`
    (test code, `checkqueue_tests.cpp:422`).
  - `DoS_tests`: `CNode` objects created by the test are never freed (leak).
  - `accounting_tests`, `wallet_tests`: small leaks inside Berkeley DB
    (`__os_malloc`).
  - No UBSan findings.
- Unit test files present but not compiled: `blockencodings`, `main`,
  `merkle`, `miner`, `policyestimator`, `versionbits`.

## Notes

- `aclocal.m4` and the libtool and automake helper files under `build-aux/`
  are generated by `autogen.sh` with the local autotools versions and are not
  tracked by git.
- The ccache shipped by depends is used, always with the cache in
  `.devbuild/ccache/` (a `CCACHE_DIR` from the environment is ignored);
  `./dev.sh ccache-stats` queries it.
- Environment overrides:
  - `DEV_HOST`: depends target triplet, default `x86_64-pc-linux-gnu`. Other
    hosts build in `build/<host>/<variant>/`.
  - `JOBS`: make jobs, default the number of cores.
  - `UNIT_JOBS`: parallel unit test suites, default `JOBS`.
  - `FTEST_JOBS`: parallel functional test scripts, default 4 in `ftest`
    and 1 in `cov`.
