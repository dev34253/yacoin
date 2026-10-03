# Test builds

`build.sh` builds YaCoin reproducibly for testing: the `depends` libraries and
YaCoin itself are built inside the pinned build image, out of tree, so the git
checkout is never modified (task P0-01).

## Quick start

```bash
# mainnet parameters, run the unit tests
contrib/testing/build.sh --config mainnet --unit

# low-difficulty parameters (needed by the functional tests), all tests
contrib/testing/build.sh --config lowdiff --unit --functional

# coverage of both configurations, then the merged report (see "Coverage")
contrib/testing/build.sh --config mainnet --coverage --unit
contrib/testing/build.sh --config lowdiff --coverage --unit --functional
contrib/testing/build.sh --coverage-report
```

Requirements: `git`, `bash`, `python3`, `flock` (util-linux) and Docker
(with `--no-docker`: the build image's toolchain instead of Docker). In
Claude Code cloud sessions start the Docker daemon first (`dockerd &`). The
first run downloads and builds the `depends` libraries (OpenSSL 1.0.1k,
Boost 1.64, BDB 4.8, libevent, miniupnpc, zeromq; Qt is not built) – about
10–15 minutes in total on a 4-core cloud machine (depends about 4 minutes),
longer on slower machines; later runs reuse the cache and only rebuild what
changed.

## Options

| Option | Meaning |
|---|---|
| `--config mainnet\|lowdiff` | Chain parameters. `lowdiff` adds `--enable-low-difficulty-for-development`. Default `mainnet`. |
| `--coverage` | `-O0 -g --coverage -fprofile-update=atomic` in `CFLAGS` and `CXXFLAGS` (the scrypt-jane C code is instrumented too), `--coverage` in `LDFLAGS`. With `--unit`/`--functional` also writes an lcov report to `<builddir>/coverage/` (see "Coverage"). |
| `--coverage-report` | No build and no tests: merges the reports of the mainnet and lowdiff `--coverage` runs in this work dir into `WORK_DIR/coverage-report/`. Rejects `--config`, `--coverage`, `--unit`, `--functional`, `--clean`, `--reconfigure` and `--sanitizers`; `--jobs` (lcov `--parallel`), `--image`, `--work-dir` and `--no-docker` work. |
| `--sanitizers LIST` | `-fsanitize=LIST`, e.g. `address,undefined`. Implemented but not yet validated – sanitizer runs are task P0-29. |
| `--unit` | Run `src/test/test_bitcoin`. |
| `--functional` | Run `test/functional/test_runner.py` (requires `--config lowdiff`). |
| `--functional-args "ARGS"` | Arguments for `test_runner.py`, replacing the default `-j4`; e.g. `"-j4 wallet_dump.py"`. |
| `--jobs N` | Parallel make jobs (default: CPU count). |
| `--reconfigure` | Force `configure` to run again. It also re-runs automatically when the configure arguments (including `CFLAGS`/`CXXFLAGS`) change; the build dir is then cleaned (`make clean`) so every object is rebuilt with the new flags. `--reconfigure` alone does not clean. A build dir created before this behaviour existed has no record of its arguments, so its first run cleans and rebuilds once. |
| `--clean` | Delete the source copy and this configuration's build directory first; the `depends` cache is kept. Because every file is copied again with a new time, other configurations' build dirs also rebuild completely on their next run. |
| `--image IMAGE` | Build image. Default: the pinned P0-57 image `dev34253/yacoin-build@sha256:…` (Ubuntu 24.04, GCC 11). Also `YACOIN_BUILD_IMAGE`. |
| `--no-docker` | Build on the current machine, e.g. when already running inside the build image in CI. |
| `--work-dir DIR` | Where everything is built. Default `$YACOIN_WORK_DIR` or `~/.cache/yacoin-build`. Must be a dedicated directory: not inside the checkout, not containing it, not `/` or `$HOME`. |

The exit code is non-zero if the build or any requested test run fails.
All unit tests pass in both configurations; tests whose results depend on
the chain parameters (e.g. `pow_tests/get_next_work_pow_limit`, task P0-02)
check the exact value for each configuration.

## What it does

1. Takes a lock on `WORK_DIR/.lock` – only one run per work directory at a
   time; use different work directories for parallel runs.
2. Mirrors the checkout (tracked and untracked, non-ignored files, so
   uncommitted changes are included) to `WORK_DIR/src` with
   `sync_tree.py`: files changed in the checkout since the last run are
   copied (with the current time, so make always rebuilds what depends on
   them), files deleted or renamed are removed, and
   files that the build regenerates in the copy (`autogen.sh` rewrites some
   tracked files such as `aclocal.m4` and `build-aux/*`) are left alone
   unless you change them in the checkout.
3. Passes the commit id as `BUILD_GIT_COMMIT` (with `-dirty` when there are
   modified, deleted or untracked files) to `share/genbuild.sh`, so it ends up
   in the version string (`yacoind -version`).
4. Builds `depends` for `x86_64-pc-linux-gnu` with `NO_QT=1`, caching sources
   and built packages in `WORK_DIR/depends-cache`.
5. Runs `autogen.sh` when needed and configures in
   `WORK_DIR/build-<config>[-cov][-san-…]` with
   `--prefix=<src>/depends/x86_64-pc-linux-gnu`, so automatic `configure`
   re-runs keep using the `depends` libraries. Different configurations can
   coexist; `configure` re-runs when its arguments change.
6. Builds, then runs the requested tests. Logs: `WORK_DIR/depends.log`,
   `WORK_DIR/autogen.log`, `<builddir>/{configure,make,unit,functional}.log`.
   Datadirs and node logs of **failed** functional tests are kept in
   `<builddir>/functional-tmp/` (the test framework deletes those of passing
   tests; the directory is emptied at the start of each functional run).

The work directory must not be inside another git work tree (e.g. a
dotfiles repository in `$HOME`): `share/genbuild.sh` would then pick up that
repository's commit for the version string.

Binaries end up in `<builddir>/src/` (`yacoind`, `yacoin-cli`,
`test/test_bitcoin`). They need glibc ≥ 2.38 (Ubuntu 24.04 or newer), so they
are for testing, not release.

## Expected results (2026-10-03, after P0-02, P0-10, P0-47, P0-12, P0-16 and P0-11)

| Configuration | Unit tests | Functional tests |
|---|---|---|
| `mainnet` | 306/306 | – (not supported) |
| `lowdiff` | 306/306 | 45/45 |

`pow_tests/get_next_work_pow_limit` expects a different result per
configuration because `powLimit` differs: mainnet clamps the retarget to
`powLimit` (0x1e0fffff), low difficulty does not (0x1e1a19f8) and checks the
clamp from its own `powLimit` (0x201fffff) instead.

## Coverage

`--coverage` together with `--unit` and/or `--functional` (task P0-03):

1. Before the tests: `lcov --zerocounters` on the build dir (so repeated
   runs do not add up) and a zero baseline (`lcov --capture --initial`), so
   source files that no test runs show up with 0 % instead of being left
   out.
2. After the tests – also when they failed; the exit code still reports the
   failure – capture the counters and add the baseline.
   Both captures read `<builddir>/src` and leave out what is not YaCoin code
   under test: `/usr/*`, `*/depends/*`, `*/test/*` (unit-test sources and
   test data), `src/leveldb`, `src/secp256k1`, `src/univalue`, `src/bench`
   and files generated in the build dirs.
3. Write `<builddir>/coverage/coverage.info`, `html/` (genhtml) and
   `summary.txt` (lines, functions, branches), and print the summary.
   `lcov.log` has the lcov output.

Branch coverage is recorded (`--rc branch_coverage=1`). It includes the
branches GCC generates for C++ exception handling, which inflate the branch
count: lcov 2.0's `--rc no_exception_branch=1` would drop them, but with
GCC 11's gcov output it drops *all* branch data (tested), so filtering is
left to the coverage gates (P0-04).
The counters are updated atomically (`-fprofile-update=atomic`): YaCoin and
its tests are multi-threaded, and with plain counters lcov 2.0 rejected the
data (a negative branch count in `crypto/sha256.cpp`).
lcov and genhtml come from the build image (lcov 2.0); with `--no-docker`
they must be installed, with the same gcov as the compiler.

`--coverage-report` merges the two configurations into
`WORK_DIR/coverage-report/{merged.info,summary.txt,html/}` and prints all
three summaries. It needs `build-mainnet-cov/coverage/coverage.info` and
`build-lowdiff-cov/coverage/coverage.info` in the work dir.

**How the two configurations are merged.** gcov records coverage per line
of the *original* source file, not of the preprocessed code, so both builds
use the same file names and line numbers. Code inside `#ifdef` /
`#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT` is compiled – and instrumented – in
one build only. The merge (`lcov --add-tracefile` of both files) is the
**union**: a line, function or branch is in the denominator if it exists in
at least one build, and it counts as covered if it ran in at least one; hit
counts are added. The per-configuration reports stay available next to the
merged one, so it is visible what one configuration alone covers. The
merged numbers are the ones coverage gates use (P0-04). The paths in the
`.info` files are absolute (`/work/...` under Docker), so only merge files
produced the same way (all with Docker, or all with `--no-docker` in the
same work dir).

## CI

`.github/workflows/tests.yml` runs on every push to any branch (and by hand
via *Run workflow*). The two test jobs run on every push; the coverage
jobs and the merged report run only on `master` and when the workflow is
started by hand (*Run workflow* on any branch), because the `-O0` coverage
jobs take about twice as long. Each job runs `build.sh` with Docker on a
GitHub-hosted `ubuntu-24.04` runner, in the pinned image, with the work dir
in `$RUNNER_TEMP/yacoin-build`:

| Job | Runs | Command (`build.sh` options) | Time (2026-10-03) |
|---|---|---|---|
| unit (mainnet) | every push | `--config mainnet --unit` | ~8 min |
| unit + functional (lowdiff) | every push | `--config lowdiff --unit --functional` | ~12–14 min |
| coverage (mainnet) | master, by hand | `--config mainnet --coverage --unit` | ~15 min |
| coverage (lowdiff) | master, by hand | `--config lowdiff --coverage --unit --functional` | ~16–19 min |
| coverage report (merged) | master, by hand | `--coverage-report`, after the jobs above (also when a test job failed; it fails itself if a coverage job uploaded no report) | ~1 min |

- The `-O2` jobs test the optimised build; the coverage jobs (`-O0`)
  measure coverage. All jobs of a run start in parallel (times above
  exclude waiting for a runner).
- Artifacts of each run: `coverage-mainnet`, `coverage-lowdiff` and
  `coverage-merged` (`.info`, `summary.txt`, `html/` – open
  `html/index.html`), and, when a job fails, `logs-mainnet`, `logs-lowdiff`,
  `logs-mainnet-cov` or `logs-lowdiff-cov` (build and test logs, datadirs of
  failed functional tests). The coverage summaries are
  also in the run's summary page and in the job logs.
- `depends-cache` (downloaded sources and built packages) is cached with
  `actions/cache`, keyed on the image digest and the contents of
  `depends/`; the cache is saved by jobs that succeed.
- The image is pulled from Docker Hub with a few retries; anonymous pulls
  can hit Docker Hub's rate limit (`429 Too Many Requests`). If all retries
  fail, re-run the job. Mirroring the image to GHCR is task P0-44, as are
  schedules, the self-hosted runner and long-running jobs.
- When the image digest changes, update both `DEFAULT_IMAGE` in `build.sh`
  and `YACOIN_BUILD_IMAGE` in the workflow.
- Both workflows (this one and the older `yacoinbuildmultiplatform.yml`,
  which builds the release binaries for all platforms) have a
  `concurrency` group per workflow and branch with `cancel-in-progress`: a
  newer push to the same branch cancels the older run, so runners are not
  tied up by superseded commits.
- The release-build workflow runs only on pushes to `master`, on tags and
  by hand (*Run workflow*), no longer on every push to every branch: its 8
  jobs (15–25 min each) do not run tests, and on task branches they kept
  the runners busy. Its jobs are otherwise unchanged.

## Restricted networks (proxy and CA)

In environments where outbound HTTPS goes through a proxy that re-signs TLS
(for example Claude Code cloud sessions), `depends` downloads inside the
container need the proxy and its CA certificate:

- If `HTTPS_PROXY`/`https_proxy` is set, the container runs with
  `--network host` and gets `HTTPS_PROXY`, `https_proxy`, `NO_PROXY`,
  `no_proxy`.
- The CA bundle is taken from `YACOIN_CA_BUNDLE`, or `/root/.ccr/ca-bundle.crt`
  when that exists and `HTTPS_PROXY` (upper case) is set, and is mounted as
  `SSL_CERT_FILE` / `CURL_CA_BUNDLE`.

In cloud sessions Docker is installed but not started: run `dockerd &` first.
Docker Hub may answer `429 Too Many Requests` for anonymous pulls; wait and
retry.

## Files

The container runs as the calling user (`--user $(id -u):$(id -g)`), so files
in the work directory are not owned by root.
