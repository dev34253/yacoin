# YaCoin Build Environment

This directory holds the definitions of the Docker build images that CI uses. CI runs each image under a tag computed from the files that go
into it, `ghcr.io/dev34253/yacoin-build:<image>-<hash>` (`image-tag.sh`; see [GitHub Actions](#github-actions)). The base images are pinned by digest, the macOS toolchain inputs and the lcov release of the Ubuntu 22.04 image are pinned and checked, and
the entrypoints create the ccache config before the build.

| File | What it is |
|---|---|
| `Dockerfile.<image>` | One image each: `ubuntu.16.04`, `ubuntu.22.04`, `windows`, `macos` |
| `entrypoint.sh`, `entrypoint.windows.sh`, `entrypoint.macos.sh` | What the images run: the Linux modes, and the Windows and macOS release builds |
| `image-tag.sh` | Prints an image's tag, or with `--inputs` the files its hash covers |
| `test-image-tag.sh` | Tests of `image-tag.sh`, of the workflow's use of the tags, of the workflow's jobs and caches, and of `all-jobs-passed.sh` |
| `all-jobs-passed.sh` | The result of the CI job `all-jobs-passed`: passes only when every job it needs passed |
| `run.sh` | Builds an image from these files and runs a mode on a source tree (`./dev.sh container` calls it) |
| `check.sh` | The image checks: lint (also: every `uses:` under `.github/` names a local action or a published action by full commit SHA with its version in a comment), image tags, digest pins, `dev.sh`'s shared cache (no Docker), `docker build`, smoke tests, ccache config, and an opt-in two-build cache test |
| `parity.sh` | Compares an image built from here with the image CI uses for the same image definition (`image-tag.sh`'s tag, published from `master`) and runs its modes on a clean clone |

```bash
./dev.sh container unit-tests                  # ubuntu.22.04 image, unit-tests mode, on this checkout
ci/containers/run.sh windows                    # the Windows release build
ci/containers/check.sh                          # all images: lint, tag, static, devsh, build, smoke, ccache
ci/containers/image-tag.sh ubuntu.22.04         # the tag CI runs the ubuntu.22.04 image under
ci/containers/check.sh --steps cache windows    # slow: two builds with one cache
ci/containers/parity.sh ubuntu.22.04            # parity with the image CI uses, then build, unit-tests and functional-tests
```

`run.sh` tags the images with a name of the clone's own, `yacoin-build-local-<directory name>-<checksum of its physical path>:<image>`
(`run.sh --print-tag <image>` prints it; `LOCAL_REPO` sets another name), so clones never retag each other's images. It labels them
`org.yacoin.build-local=1` and `org.yacoin.build-local.tree=<clone>`:

```bash
docker image ls --filter label=org.yacoin.build-local=1                                        # the local images of all clones
docker image rm -f $(docker image ls -q --filter label=org.yacoin.build-local.tree=/path/to/clone) # those of one clone, e.g. a deleted one
docker image prune -a --filter label=org.yacoin.build-local=1                                  # all of them that no container uses
```

It mounts the source tree at `/src` and a cache directory at `/cache` (default: `$DEV_CACHE/container/<key>`, see
[below](#linux-image-modes-jobs-and-cache)), runs the container as root as CI does, and (except under rootless Docker or Podman) gives
the files it wrote back to the caller afterwards.

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

To build YaCoin for a specific platform, or to run a test mode, use `./dev.sh container` or `run.sh`:

```bash
./dev.sh container [options] [image] [mode]    # this checkout, image ubuntu.22.04 and mode build by default
ci/containers/run.sh [options] <image> [mode]  # mode build by default; --src <dir> for another tree
ci/containers/run.sh --help                    # the images, modes and options
ci/containers/run.sh --print-tag ubuntu.22.04  # this clone's tag of the image
```

Both build the image and run the mode in it; `--no-image-build` runs the existing local image without building it first.

## Linux image modes, jobs and cache

The Linux images (`Dockerfile.ubuntu.*`) share `entrypoint.sh`. It takes an
optional mode as its argument:

| Mode | What it does |
|---|---|
| `build` (default) | Release build: depends, configure with glibc back-compat, make, `make install` into `/src/release-root` |
| `build-low-difficulty` | The release build with `--enable-low-difficulty-for-development` (mainnet proof-of-work limits relaxed, for miner tests), then all unit test suites of its `src/test/test_bitcoin` in parallel (`contrib/devtools/run-unit-suites.sh`, logs in `/src/build/docker-<image>/build-low-difficulty/unit-test-logs`), then the functional test scripts listed in `/src/test/functional/regtest-excluded-scripts` on that build, `FTEST_JOBS` (default 4) in parallel (`test_runner.py --include-file`; data and logs in `/src/build/docker-<image>/build-low-difficulty/test/tmp`); a listed name that is not a script of the runner fails the mode |
| `unit-tests` | Builds `test_bitcoin` and `bench_yacoin` (`--enable-bench`, mainnet consensus), runs all unit test suites in parallel (`contrib/devtools/run-unit-suites.sh`), then prints the CPU model and runs every benchmark once in a short mode (`bench_yacoin -time=0.01`); a failed benchmark fails the mode. See `doc/benchmarking.md` |
| `unit-tests-asan` | `unit-tests` under AddressSanitizer, LeakSanitizer and UBSan, with the sanitizer flags of `dev.sh`'s `asan` variant (`-fsanitize=address,undefined -fno-sanitize-recover=undefined`, `--with-asm=no`, mainnet consensus) and `-g1` instead of `-g`: `-g1` keeps symbolized stack traces with file and line; the generated code is the same as with `-g` (objects compared after `objcopy --strip-debug`). `SANITIZE=address` builds with AddressSanitizer and LeakSanitizer only, `SANITIZE=undefined` with UBSan only (`-fsanitize=undefined -fno-sanitize-recover=undefined`); unset, with both; any other value stops the mode before the build. The suites run with `ASAN_OPTIONS=detect_leaks=1`, `LSAN_OPTIONS=suppressions=/src/test/sanitizer_suppressions/lsan` and `UBSAN_OPTIONS=print_stacktrace=1`, so any report that is not suppressed fails its suite and the mode. The test cases listed in `/src/test/sanitizer_suppressions/asan-excluded-cases` are left out of every suite (`run-unit-suites.sh --exclude-cases`), as by `./dev.sh asan`, whatever `SANITIZE` says. Ubuntu 22.04 image only; the others refuse it |
| `unit-tests-tsan` | `unit-tests` under ThreadSanitizer (`-fsanitize=thread -fno-omit-frame-pointer`, mainnet consensus); the suites run with `TSAN_OPTIONS=suppressions=/src/test/sanitizer_suppressions/tsan:halt_on_error=0:second_deadlock_stack=1` and address randomisation off (`setarch -R`), so any report that is not suppressed fails its suite and the mode. Needs `docker run --security-opt seccomp=unconfined`, see below. Ubuntu 22.04 image only; the others refuse it |
| `fuzz-corpus` | Builds the libFuzzer binary `src/test/fuzz/fuzz` with clang 14 (`--enable-fuzz --with-asm=no`, mainnet consensus) under AddressSanitizer, LeakSanitizer and UBSan (the sanitizer flags of `unit-tests-asan`, and `-no-pie`: clang 14's AddressSanitizer runtime fails at random at start in a position-independent executable on current kernels), then runs every input of `/src/test/fuzz/corpus/<target>/` once through its target (`contrib/devtools/run-fuzz-corpus.py`, logs in `/src/build/docker-<image>/fuzz-corpus/fuzz-corpus-logs`) with `ASAN_OPTIONS=detect_leaks=1` and `UBSAN_OPTIONS=print_stacktrace=1`; any report fails the mode. It never fuzzes; see `doc/fuzzing.md`. Ubuntu 22.04 image only; the others refuse it |
| `functional-tests` | Mainnet consensus build (`-O1`), then the functional test scripts, the extended ones too, `FTEST_JOBS` (default 4) in parallel, on regtest, but those listed in `/src/test/functional/regtest-excluded-scripts`, which `build-low-difficulty` runs (`test_runner.py -j "$FTEST_JOBS" --extended --chain=regtest --exclude-file`). With `FTEST_SHARD=K/N` only shard K of N of the scripts (`test_runner.py --shard K/N`: the scripts whose position in the runner's list, counted from 0, modulo N is K-1) |
| `functional-tests-asan` | `functional-tests` under AddressSanitizer, LeakSanitizer and UBSan (`FTEST_SHARD` as there): the mainnet consensus build with the flags of `unit-tests-asan` (both sanitizers; `SANITIZE` does not apply), and both sanitizer runtimes linked into `yacoind` and `yacoin-cli` (`-static-libasan -static-libubsan`; as two shared libraries, UBSan's reports would ignore `log_path`). The scripts run with the runtime options of `unit-tests-asan` plus `print_suppressions=0` and `handle_segv=0` (a segmentation fault ends the process with the signal, as in `functional-tests`), and the runner's `--sanitizer-logs`: every process a script starts writes its reports to `/src/build/docker-<image>/functional-tests-asan/sanitizer-logs/<script's test directory>.<executable>.<pid>` instead of its stderr. A script with a report fails and the runner prints the report with it, whatever the script's own outcome (also for a process whose stderr or exit status the script expects to differ, or that it kills); after the runner the mode prints every report file and fails if there is one. The scripts listed in `/src/test/sanitizer_suppressions/asan-excluded-scripts` are left out as well (a second `test_runner.py --exclude-file`). Ubuntu 22.04 image only; the others refuse it |
| `cov-unit` | Coverage build (`--enable-lcov`, `-O0`) and `make cov-unit`. Needs lcov 2.6 or newer, so it only works in the Ubuntu 22.04 image |
| `cov-functional` | The coverage build of `cov-unit` and `make cov-functional`: the functional test scripts of `functional-tests` but the extended ones, `FTEST_JOBS` (default 4) in parallel, with `--timeout-factor` from `FTEST_TIMEOUT_FACTOR`. With `FTEST_SHARD=K/N` (passed to make) the run takes only shard K of N of the scripts. Needs lcov 2.6 or newer (Ubuntu 22.04 image only) |

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
  runs. That saves the roughly 12 minutes of rebuilding depends. Cache
  statistics are printed at the end of every run, also when it fails.
- `run.sh`'s default cache is `$DEV_CACHE/container/<key>` (`DEV_CACHE` as for
  `dev.sh`, default `${XDG_CACHE_HOME:-$HOME/.cache}/yacoin-dev`; `<key>` a
  hash of the files under `depends/` of the source tree that git does not
  ignore, `CONTAINER_CACHE` in `./dev.sh cache`), so clones with the same
  recipes share it and other recipes get their own. `--cache DIR` mounts
  another, `--no-cache` none.
- One container at a time builds depends with a cache: `run.sh` holds a lock
  on it (`<cache>/run.lock`) from the start of a run until the container
  prints its first line after the depends build (or to its end), and a second
  run on that cache waits until then. After that the runs share the cache
  through ccache only, which handles parallel use itself.
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
with macOS 10.8+. osxcross is pinned to one commit (`OSXCROSS_COMMIT`), and the SDK tarball is checked against its SHA-256
(`sha256sum -c` in `Dockerfile.macos`).

## GitHub Actions

Every job of `.github/workflows/yacoinbuildmultiplatform.yml` that runs docker runs an image built from this directory. The local action
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

The workflows and the action pin every published action they use (`actions/checkout`, `actions/cache`, `actions/upload-artifact`,
`actions/download-artifact`, `docker/setup-buildx-action`, `docker/build-push-action`) by commit, with its version in a comment;
`check.sh lint` checks that every `uses:` under `.github/` does. The registry login is `docker login`.

Nothing outside this repository changes what CI builds with: a tag names the files it was built from, and a new image definition is a
reviewed change here. `check.sh` (step `tag`, also `test-image-tag.sh` on its own, which `build-ubuntu-1604` runs first) checks the tags
and that every `docker run` in the workflow runs a tagged image of this directory.

The unit tests run in four jobs: `unit-tests` on the mainnet build, `build-ubuntu-1604-low-difficulty` (the `build-low-difficulty`
mode) on the low-difficulty build, so a test that only passes with the mainnet parameters fails in CI, and `unit-tests-asan` and
`unit-tests-tsan` (the modes of the same names of the Ubuntu 22.04 image) on the mainnet build, under AddressSanitizer, LeakSanitizer
and UBSan and under ThreadSanitizer. `unit-tests-asan` runs as two legs of a matrix, one per sanitizer (`SANITIZE=address`:
AddressSanitizer with LeakSanitizer; `SANITIZE=undefined`: UBSan); each builds `test_bitcoin` with its sanitizer only and runs every
suite. Both legs read the same left-out lists. Each job uploads its unit test logs when it fails (`unit-test-logs`,
`unit-test-logs-low-difficulty`, `unit-test-logs-asan-<sanitizer>`, `unit-test-logs-tsan`, kept 14 days).

The functional tests run in two jobs on the mainnet build, on regtest: `functional-tests`, and `functional-tests-asan` (the mode of the
same name) under AddressSanitizer, LeakSanitizer and UBSan. The scripts listed in `test/functional/regtest-excluded-scripts` run in
`build-ubuntu-1604-low-difficulty` instead, on its build, after its unit tests; it uploads the logs of its failed scripts when one
fails (`functional-test-logs-low-difficulty`, kept 14 days). `functional-tests-asan` runs as two legs of a matrix, each building `yacoind`
and `yacoin-cli` and running one shard of the scripts (`FTEST_SHARD=<leg>/<number of legs>`); a script's shard follows from its
position in the runner's list, so the legs together run every script once and a new script needs no workflow change. Each job uploads
the logs of its failed scripts when it fails (`functional-test-logs`, `functional-test-logs-asan-<shard>`; the latter also holds the
sanitizer report files, kept 14 days). `test-image-tag.sh` also checks that the sanitizer jobs (`unit-tests-asan`, `unit-tests-tsan`,
`functional-tests-asan`) run their modes with ccache off, the legs and shards above, that `functional-tests-asan` restores the
`functional-tests` depends entry and saves none, and that only the `unit-tests-tsan` container runs without the seccomp filter.

The `fuzz-corpus` job runs the mode of the same name of the Ubuntu 22.04 image: every input of the fuzz corpus once through its target
under AddressSanitizer, LeakSanitizer and UBSan. It replays the committed corpus only and never fuzzes, and uploads its logs when it
fails (`fuzz-corpus-logs`, kept 14 days). `test-image-tag.sh` checks that it runs with ccache off, restores the `functional-tests`
depends entry and saves none, and that the workflow has 17 jobs.

The jobs also keep the depends packages, depends sources and ccache in the GitHub Actions cache: a ccache entry per job kind and
image, and a depends entry per depends kind and image (the low-difficulty job shares the 16.04 release job's); the kinds are
`release`, `low-difficulty`, `unit-tests` and `functional-tests`. The depends entry holds the depends packages and
sources, keyed `<kind>-depends-<image>-<tag hash>-<depends hash>` (the content hash in the image tag and a hash of the depends definitions,
`depends/packages/*.mk`, `patches/`, `Makefile`, `funcs.mk`, `hosts/*.mk` and `builders/*.mk`), and is restored by that exact key only.
The ccache entry is keyed `<kind>-ccache-<image>-<tag hash>-<commit>`; a restoring run takes the newest entry of its kind and image tag. The
ccache is limited to 250 MB in the build jobs and to 1 GB in `unit-tests` and `functional-tests` (`CCACHE_MAXSIZE`).
`build-ubuntu-1604-low-difficulty` uses the `release` depends entry of `ubuntu.16.04` (the same packages) and a ccache entry of its own.
Only pushes to `master` save the entries, each one whose key is missing; after the saving jobs, `prune-caches` keeps the newest entry
per kind, image, entry type and cache version and deletes the others. On a push to `master` the build jobs (`build-ubuntu-1604`,
`build-ubuntu-1604-low-difficulty`, `build-ubuntu-2204`, `build-windows`, `build-macos`) only look up their keys (`lookup-only`) and
build without a restored cache; they save the entries pull request runs restore. On a tag push they start without a cache. The other
jobs with a cache step restore on every run. The coverage jobs (`coverage-unit`, `coverage-functional-1`, `coverage-functional-2`) and
the sanitizer jobs (`unit-tests-asan`, `unit-tests-tsan`, `fuzz-corpus`, `functional-tests-asan`), every leg included, restore the
`functional-tests-depends-…` entry (the same image, packages and prefix) and never save one; they build with ccache off, since their
`-O0` or sanitizer objects never match the cached ones. `test-image-tag.sh` checks these keys, paths and conditions, that only the
build jobs' restores set `lookup-only`, and that `prune-caches` runs only on a push to `master`, runs no docker and is the one job with
`actions: write`; planted copies of the workflow, each with one change, must fail their named check. `coverage-functional-1` and `-2`
run shard 1/2 and 2/2 of the functional tests (`FTEST_SHARD`), each with its own artifact per attempt and its own outputs.
`coverage-report` downloads the artifact of the attempt each coverage job last ran in, merges the unit tracefile with both shards'
tracefiles, and runs `contrib/devtools/coverage-check.py` with every function extents file.

The last job, `all-jobs-passed`, needs every other job of the workflow and runs whatever their results are (`if: ${{ always() }}`).
It passes only when every needed job's result is `success`; `prune-caches` may also be `skipped` when the run is not a push to `master`.
Any other result (`failure`, `cancelled`, `skipped` or any other value) fails it, so it is the one check that says whether the whole
run passed. `all-jobs-passed.sh` here gets the needed jobs' results (`toJSON(needs)`) and whether the run is a push to `master`
through `env:`, prints each job's result and decides, using jq; it fails on empty or malformed input too. `test-image-tag.sh` tests
the script with planted results (so running it locally needs jq), and checks that the workflow's jobs are plain keys at two spaces
with `jobs:` as the last top-level key, that the workflow uses no `continue-on-error`, and that `all-jobs-passed` needs every other
job, runs always and is written as the check expects; planted copies of the workflow (a job left out of `needs`, a job added without
an entry, a misspelt entry, another `if:`, a commented or quoted job key, among others) must fail.
