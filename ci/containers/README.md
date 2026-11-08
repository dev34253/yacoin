# YaCoin Build Environment

This directory holds the definitions of the Docker build images that CI uses. CI runs each image under a tag computed from the files that go
into it, `ghcr.io/dev34253/yacoin-build:<image>-<hash>` (`image-tag.sh`; see [GitHub Actions](#github-actions)). The base images are pinned by digest, the macOS toolchain inputs and the lcov release of the Ubuntu 22.04 image are pinned and checked, and
the entrypoints create the ccache config before the build.

| File | What it is |
|---|---|
| `Dockerfile.<image>` | One image each: `ubuntu.16.04`, `ubuntu.22.04`, `windows`, `macos` |
| `entrypoint.sh`, `entrypoint.windows.sh`, `entrypoint.macos.sh` | What the images run: the Linux modes, and the Windows and macOS release builds |
| `image-tag.sh` | Prints an image's tag, or with `--inputs` the files its hash covers |
| `test-image-tag.sh` | Tests of `image-tag.sh` and of the workflow's use of the tags |
| `run.sh` | Builds an image from these files and runs a mode on a source tree (`./dev.sh container` calls it) |
| `check.sh` | The image checks: lint, image tags, digest pins, `dev.sh`'s shared cache (no Docker), `docker build`, smoke tests, ccache config, and an opt-in two-build cache test |
| `parity.sh` | Compares an image built from here with the one on Docker Hub (`dev34253/yacoin-build:<image>-2`) and runs its modes on a clean clone |

```bash
./dev.sh container unit-tests                  # ubuntu.22.04 image, unit-tests mode, on this checkout
ci/containers/run.sh windows                    # the Windows release build
ci/containers/check.sh                          # all images: lint, tag, static, devsh, build, smoke, ccache
ci/containers/image-tag.sh ubuntu.22.04         # the tag CI runs the ubuntu.22.04 image under
ci/containers/check.sh --steps cache windows    # slow: two builds with one cache
ci/containers/parity.sh ubuntu.22.04            # image parity, then build, unit-tests and functional-tests
```

`run.sh` tags the images `yacoin-build-local:<image>` (`LOCAL_REPO` changes the name) and labels them `org.yacoin.build-local=1`, so
leftover images can be removed with `docker image prune -a --filter label=org.yacoin.build-local=1` (`-a` also removes the tagged
`yacoin-build-local:*` images). It mounts the source tree at `/src` and a
cache directory at `/cache` (default `<src>/.devbuild/container-cache`), runs the container as root as CI does, and (except under rootless
Docker or Podman) gives the files it wrote back to the caller afterwards.

## Available Build Environments

### Ubuntu Builds
- `Dockerfile.ubuntu.16.04` - Ubuntu 16.04 build environment
- `Dockerfile.ubuntu.22.04` - Ubuntu 22.04 build environment, with lcov 2.6 for the coverage modes (from the release tarball of
  [linux-test-project/lcov](https://github.com/linux-test-project/lcov/releases), checked against its SHA-256; Ubuntu 22.04 ships 1.14),
  and clang 14 with libFuzzer and LLVM 14 (`llvm-symbolizer`) from Ubuntu's archive for the `fuzz-corpus` mode

### Cross-Platform Builds
- `Dockerfile.windows` - Windows cross-compilation environment
- `Dockerfile.macos` - macOS cross-compilation environment using osxcross

## Usage

To build YaCoin for a specific platform:

```bash
# For Ubuntu 22.04
docker build -f Dockerfile.ubuntu.22.04 -t yacoin-build:ubuntu22.04 .
docker run -v /path/to/yacoin/source:/src yacoin-build:ubuntu22.04

# For macOS cross-compilation
docker build -f Dockerfile.macos -t yacoin-build:macos .
docker run -v /path/to/yacoin/source:/src yacoin-build:macos

# For Windows cross-compilation
docker build -f Dockerfile.windows -t yacoin-build:windows .
docker run -v /path/to/yacoin/source:/src yacoin-build:windows
```

## Linux image modes, jobs and cache

The Linux images (`Dockerfile.ubuntu.*`) share `entrypoint.sh`. It takes an
optional mode as its argument:

| Mode | What it does |
|---|---|
| `build` (default) | Release build: depends, configure with glibc back-compat, make, `make install` into `/src/release-root` |
| `build-low-difficulty` | The release build with `--enable-low-difficulty-for-development` (mainnet proof-of-work limits relaxed, for miner tests), then all unit test suites of its `src/test/test_bitcoin` in parallel (`contrib/devtools/run-unit-suites.sh`, logs in `/src/build/docker-<image>/build-low-difficulty/unit-test-logs`) |
| `unit-tests` | Builds `test_bitcoin` and `bench_yacoin` (`--enable-bench`, mainnet consensus), runs all unit test suites in parallel (`contrib/devtools/run-unit-suites.sh`), then prints the CPU model and runs every benchmark once in a short mode (`bench_yacoin -time=0.01`); a failed benchmark fails the mode. See `doc/benchmarking.md` |
| `unit-tests-asan` | `unit-tests` under AddressSanitizer, LeakSanitizer and UBSan, with the sanitizer flags of `dev.sh`'s `asan` variant (`-fsanitize=address,undefined -fno-sanitize-recover=undefined`, `--with-asm=no`, mainnet consensus) and `-g1` instead of `-g`: `-g1` keeps symbolized stack traces with file and line; the generated code is unchanged (objects compared after `objcopy --strip-debug`). `SANITIZE=address` builds with AddressSanitizer and LeakSanitizer only, `SANITIZE=undefined` with UBSan only (`-fsanitize=undefined -fno-sanitize-recover=undefined`); unset, with both; any other value stops the mode before the build. The suites run with `ASAN_OPTIONS=detect_leaks=1`, `LSAN_OPTIONS=suppressions=/src/test/sanitizer_suppressions/lsan` and `UBSAN_OPTIONS=print_stacktrace=1`, so any report that is not suppressed fails its suite and the mode. The test cases listed in `/src/test/sanitizer_suppressions/asan-excluded-cases` are left out of every suite (`run-unit-suites.sh --exclude-cases`), as by `./dev.sh asan`, whatever `SANITIZE` says. Ubuntu 22.04 image only; the others refuse it |
| `unit-tests-tsan` | `unit-tests` under ThreadSanitizer (`-fsanitize=thread -fno-omit-frame-pointer`, mainnet consensus); the suites run with `TSAN_OPTIONS=suppressions=/src/test/sanitizer_suppressions/tsan:halt_on_error=0:second_deadlock_stack=1` and address randomisation off (`setarch -R`), so any report that is not suppressed fails its suite and the mode. Needs `docker run --security-opt seccomp=unconfined`, see below. Ubuntu 22.04 image only; the others refuse it |
| `fuzz-corpus` | Builds the libFuzzer binary `src/test/fuzz/fuzz` with clang 14 (`--enable-fuzz --with-asm=no`, mainnet consensus) under AddressSanitizer, LeakSanitizer and UBSan (the flags of `unit-tests-asan`, and `-no-pie`: clang 14's AddressSanitizer runtime fails at random at start in a position-independent executable on current kernels), then runs every input of `/src/test/fuzz/corpus/<target>/` once through its target (`contrib/devtools/run-fuzz-corpus.py`, logs in `/src/build/docker-<image>/fuzz-corpus/fuzz-corpus-logs`) with `ASAN_OPTIONS=detect_leaks=1` and `UBSAN_OPTIONS=print_stacktrace=1`; any report fails the mode. It never fuzzes; see `doc/fuzzing.md`. Ubuntu 22.04 image only; the others refuse it |
| `functional-tests` | Low-difficulty build, then all functional test scripts, the extended ones too, `FTEST_JOBS` (default 4) in parallel (`test_runner.py -j "$FTEST_JOBS" --extended`). With `FTEST_SHARD=K/N` only shard K of N of the scripts (`test_runner.py --shard K/N`: the scripts whose position in the runner's list, counted from 0, modulo N is K-1) |
| `functional-tests-asan` | `functional-tests` under AddressSanitizer, LeakSanitizer and UBSan (`FTEST_SHARD` as there): the low-difficulty build with the flags of `unit-tests-asan` (both sanitizers; `SANITIZE` does not apply), and both sanitizer runtimes linked into `yacoind` and `yacoin-cli` (`-static-libasan -static-libubsan`; as two shared libraries, UBSan's reports would ignore `log_path`). The scripts run with the runtime options of `unit-tests-asan` plus `print_suppressions=0` and `handle_segv=0` (a segmentation fault ends the process with the signal, as in `functional-tests`), and the runner's `--sanitizer-logs`: every process a script starts writes its reports to `/src/build/docker-<image>/functional-tests-asan/sanitizer-logs/<script's test directory>.<executable>.<pid>` instead of its stderr. A script with a report fails and the runner prints the report with it, whatever the script's own outcome (also for a process whose stderr or exit status the script expects to differ, or that it kills); after the runner the mode prints every report file and fails if there is one. The scripts listed in `/src/test/sanitizer_suppressions/asan-excluded-scripts` are left out (`test_runner.py --exclude-file`). Ubuntu 22.04 image only; the others refuse it |
| `cov-unit` | Coverage build (`--enable-lcov`, `-O0`) and `make cov-unit`. Needs lcov 2.6 or newer, so it only works in the Ubuntu 22.04 image |
| `cov-functional` | Low-difficulty coverage build and `make cov-functional`: the functional test scripts `FTEST_JOBS` (default 4) in parallel, then `p2p_invalid_messages.py` alone. With `FTEST_SHARD=K/N` (passed to make) both runs take only shard K of N of the scripts. Needs lcov 2.6 or newer (Ubuntu 22.04 image only) |

```bash
image=$(ci/containers/image-tag.sh ubuntu.22.04)    # pullable once CI on master has published it
docker run -v /path/to/yacoin:/src "$image" unit-tests
docker run -v /path/to/yacoin:/src -v /path/to/cache:/cache "$image" cov-unit
docker run -v /path/to/yacoin:/src -v /path/to/cache:/cache "$image" cov-functional
docker run -v /path/to/yacoin:/src -e SANITIZE=undefined "$image" unit-tests-asan    # one leg of CI's unit-tests-asan
docker run -v /path/to/yacoin:/src -e FTEST_SHARD=2/2 "$image" functional-tests-asan  # one shard of CI's functional-tests-asan
```

`run.sh` and `./dev.sh container` pass `SANITIZE` and `FTEST_SHARD` on to the container, e.g.
`FTEST_SHARD=1/2 ./dev.sh container functional-tests-asan`.

- The test modes build out of tree in
  `/src/build/docker-<image>/<mode>`, which is recreated on every run, and
  refuse a tree that was configured in place (run `make distclean` there).
- The test modes install depends without Qt into their own prefix,
  `/src/build/docker-<image>/depends`, so they never replace the depends a
  host build (`dev.sh`) or another image uses. The release build modes
  (`build`, `build-low-difficulty`) install into the usual
  `/src/depends/x86_64-pc-linux-gnu` and share their depends packages and
  ccache directory in `/cache`.
- Run one container per source tree at a time: modes share the tree's
  `autogen.sh` output, and the release build modes configure it in place.
- `JOBS` sets the parallelism (default: the CPUs available to the container,
  including a `--cpus` limit), e.g. `-e JOBS=4`. On hosts with many cores but
  little memory, set `JOBS` to stay safe.
- The test modes give their depends packages separate ids (`HOST_ID_SALT`),
  because built packages contain their install prefix. So they never reuse
  cache entries or work dirs of the release build, and vice versa.
- If a directory is mounted at `/cache`, built depends packages, ccache data
  (per image; separate for the release build and the test modes) and depends
  source tarballs (shared) are kept there between
  runs. That saves the roughly 12 minutes of rebuilding depends. Use one
  container per image cache at a time. Cache statistics are printed at the
  end of every run, also when it fails.
- Files written to `/src` and `/cache` are owned by root.
- `run.sh` starts the sanitizer modes (`unit-tests-asan`, `unit-tests-tsan`,
  `fuzz-corpus`, `functional-tests-asan`) with `CCACHE_DISABLE=1`, as the CI
  jobs do: their objects never match the cached ones and would only evict
  them.
- gcc 11's ThreadSanitizer runtime stops at start ("unexpected memory
  mapping") under the address randomisation of current kernels, so
  `unit-tests-tsan` runs the suites under `setarch -R`. Docker's default
  seccomp filter refuses that; start the container with
  `--security-opt seccomp=unconfined` (`run.sh` and the CI job do, for this
  mode only). Without it the mode stops before the build with a message.

## Windows and macOS images, cache

The cross images (`Dockerfile.windows`, `Dockerfile.macos`) do one thing, the
release build (depends, configure, make, `make install` into
`/src/release-root`), and take no mode argument. Like the Linux images, they
keep built depends packages, depends source tarballs and ccache data in
`/cache` if a directory is mounted there (under `/cache/windows` or
`/cache/macos`), print the cache statistics at the end of every run, and stop
at the first failing step. `JOBS` sets the parallelism (default 4).

```bash
docker run -v /path/to/yacoin:/src -v /path/to/cache:/cache "$(ci/containers/image-tag.sh windows)"
```

Ubuntu 16.04 and 18.04 are end of life. The 16.04 image is built because the
release matrix uses it; the Windows and macOS images are based on 18.04.

## macOS Build Notes

The macOS build uses the osxcross toolchain to cross-compile from Ubuntu 18.04. It downloads the macOS 10.11 SDK and builds binaries compatible
with macOS 10.8+. osxcross is pinned to the commit of the published `macos-2` image (`OSXCROSS_COMMIT`), and the SDK tarball is checked
against the hash of the one in that image.

## GitHub Actions

Every job of `.github/workflows/yacoinbuildmultiplatform.yml` runs an image built from this directory. The local action
`.github/actions/yacoin-build-image` provides it. The workflow runs on every pull request commit, and on pushes only to `master`,
to `scratch/` branches and to tags; `.github/workflows/depends-sources.yml` runs the same way, without tags, when the depends recipes
change, and on demand. A branch without a pull request therefore gets CI only as a `scratch/` branch.

How a job gets its image:

1. `image-tag.sh` computes the tag `ghcr.io/<owner>/yacoin-build:<image>-<hash>` (`<owner>`: the repository owner, `dev34253`). `<hash>`
   is the first 12 hex digits of a SHA-256 over `Dockerfile.<image>` and every file it COPYs or ADDs (the entrypoint), their contents
   and their mode as git records it;
   `image-tag.sh --inputs <image>` lists them, and the job log shows them. Any change to these files gives a new tag; other files here
   (the scripts, this README) do not.
2. The job asks the GitHub Container Registry whether the tag exists (`registry-state.sh` in the action: the registry API, so "missing"
   and "error" are told apart) and pulls it if so. The release job of each image (`build-ubuntu-1604`, `build-ubuntu-2204`,
   `build-windows`, `build-macos`) logs in first with the job's token (`packages: write`); the other jobs ask anonymously, which needs
   the package to be public.
3. If the tag is missing, the job builds the image with `docker buildx`. The layer cache is the tag `<image>-buildcache` in the same
   registry repository (`ghcr.io/<owner>/yacoin-build:<image>-buildcache`, `mode=max`); every build reads it, and a failed read (no cache
   yet, or an anonymous read of a private package) only means a build without cache. A pull request that changes an image therefore
   builds and tests that image.
4. On a push to `master`, the release job of each image then checks again that the tag is still missing and pushes it, and writes
   the layer cache. On `master` any registry error fails the job instead of leading to a build and a push over an existing tag. Other
   branches, tags and pull requests never write to the registry and fall back to a local build on a registry error (the log says why),
   so the registry only holds images and caches built from `master`.

The action pins `docker/setup-buildx-action` and `docker/build-push-action` by commit; the registry login is `docker login`.

Nothing outside this repository changes what CI builds with: a tag names the files it was built from, and a new image definition is a
reviewed change here. `check.sh` (step `tag`, also `test-image-tag.sh` on its own, which `build-ubuntu-1604` runs first) checks the tags
and that every `docker run` in the workflow runs a tagged image of this directory.

The unit tests run in four jobs: `unit-tests` on the mainnet build, `build-ubuntu-1604-low-difficulty` (the `build-low-difficulty`
mode) on the low-difficulty build, so a test that only passes with the mainnet parameters fails in CI, and `unit-tests-asan` and
`unit-tests-tsan` (the modes of the same names of the Ubuntu 22.04 image) on the mainnet build, under AddressSanitizer, LeakSanitizer
and UBSan and under ThreadSanitizer. `unit-tests-asan` runs as two legs of a matrix, one per sanitizer (`SANITIZE=address`:
AddressSanitizer with LeakSanitizer; `SANITIZE=undefined`: UBSan); each builds `test_bitcoin` with its sanitizer only and runs every
suite. Both legs read the same left-out lists, which are unchanged. Each job uploads its unit test logs when it fails (`unit-test-logs`,
`unit-test-logs-low-difficulty`, `unit-test-logs-asan-<sanitizer>`, `unit-test-logs-tsan`, kept 14 days).

The functional tests run in two jobs on the low-difficulty build: `functional-tests`, and `functional-tests-asan` (the mode of the same
name) under AddressSanitizer, LeakSanitizer and UBSan. `functional-tests-asan` runs as two legs of a matrix, each building `yacoind`
and `yacoin-cli` and running one shard of the scripts (`FTEST_SHARD=<leg>/<number of legs>`); a script's shard follows from its
position in the runner's list, so the legs together run every script once and a new script needs no workflow change. Each job uploads
the logs of its failed scripts when it fails (`functional-test-logs`, `functional-test-logs-asan-<shard>`; the latter also holds the
sanitizer report files, kept 14 days). `test-image-tag.sh` also checks that the sanitizer jobs (`unit-tests-asan`, `unit-tests-tsan`,
`functional-tests-asan`) run their modes with ccache off, the legs and shards above, that `functional-tests-asan` restores the
`functional-tests` cache and saves none, and that only the `unit-tests-tsan` container runs without the seccomp filter.

The `fuzz-corpus` job runs the mode of the same name of the Ubuntu 22.04 image: every input of the fuzz corpus once through its target
under AddressSanitizer, LeakSanitizer and UBSan. It replays the committed corpus only and never fuzzes, and uploads its logs when it
fails (`fuzz-corpus-logs`, kept 14 days). `test-image-tag.sh` checks that it runs with ccache off, restores the `functional-tests` cache
and saves none, and that the workflow has 15 jobs.

The jobs also keep the depends packages, depends sources and ccache in the GitHub Actions cache, one per job kind and image
(`release-<image>-…`, `low-difficulty-<image>-…`, `unit-tests-<image>-…`, `functional-tests-<image>-…`, keyed by the depends
definitions). Only pushes to `master` save them; the release jobs (including `build-ubuntu-1604-low-difficulty`) build from scratch there.
Other runs restore the newest matching cache; the low-difficulty job falls back to the 16.04 release cache if it has none of its own.
The coverage jobs (`coverage-unit`, `coverage-functional-1`, `coverage-functional-2`) and the sanitizer jobs (`unit-tests-asan`,
`unit-tests-tsan`, `fuzz-corpus`, `functional-tests-asan`), every leg included, restore the
`functional-tests-<image>-…` cache for their depends packages (the same image, packages and prefix) and never save one; they build
with ccache off, since their `-O0` or sanitizer objects never match the cached ones. `coverage-functional-1` and `-2` run shard 1/2 and
2/2 of the functional tests (`FTEST_SHARD`), each with its own artifact per attempt and its own outputs. `coverage-report` downloads
the artifact of the attempt each coverage job last ran in, merges the unit tracefile with both shards' tracefiles, and runs
`contrib/devtools/coverage-check.py` with every function extents file.
