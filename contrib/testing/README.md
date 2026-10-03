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

# coverage build (C and C++ instrumented, -O0)
contrib/testing/build.sh --config lowdiff --coverage --unit --functional
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
| `--coverage` | `-O0 -g --coverage` in `CFLAGS` and `CXXFLAGS` (the scrypt-jane C code is instrumented too), `--coverage` in `LDFLAGS`. |
| `--sanitizers LIST` | `-fsanitize=LIST`, e.g. `address,undefined`. Implemented but not yet validated – sanitizer runs are task P0-29. |
| `--unit` | Run `src/test/test_bitcoin`. |
| `--functional` | Run `test/functional/test_runner.py` (requires `--config lowdiff`). |
| `--functional-args "ARGS"` | Arguments for `test_runner.py`, replacing the default `-j4`; e.g. `"-j4 wallet_dump.py"`. |
| `--jobs N` | Parallel make jobs (default: CPU count). |
| `--reconfigure` | Force `configure` to run again (it also re-runs automatically when the configure arguments change). |
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

## Expected results (2026-10-02, after P0-02)

| Configuration | Unit tests | Functional tests |
|---|---|---|
| `mainnet` | 239/239 | – (not supported) |
| `lowdiff` | 239/239 | 45/45 |

`pow_tests/get_next_work_pow_limit` expects a different result per
configuration because `powLimit` differs: mainnet clamps the retarget to
`powLimit` (0x1e0fffff), low difficulty does not (0x1e1a19f8) and checks the
clamp from its own `powLimit` (0x201fffff) instead.

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
