# YaCoin Build Environment

This repository contains Docker configurations for building YaCoin on multiple platforms.

## Available Build Environments

### Ubuntu Builds
- `Dockerfile.ubuntu.16.04` - Ubuntu 16.04 build environment
- `Dockerfile.ubuntu.18.04` - Ubuntu 18.04 build environment  
- `Dockerfile.ubuntu.20.04` - Ubuntu 20.04 build environment
- `Dockerfile.ubuntu.22.04` - Ubuntu 22.04 build environment
- `Dockerfile.ubuntu.24.04-gcc11` - Ubuntu 24.04 build environment with GCC 11 pinned (same compiler as 22.04; needs a YaCoin source tree with the glibc 2.36/2.38 build fixes). Published as `dev34253/yacoin-build:ubuntu.24.04-gcc11-2`.

### Cross-Platform Builds
- `Dockerfile.windows` - Windows cross-compilation environment
- `Dockerfile.macos` - macOS cross-compilation environment using osxcross

## Usage

To build YaCoin for a specific platform:

```bash
# For Ubuntu 20.04
docker build -f Dockerfile.ubuntu.20.04 -t yacoin-build:ubuntu20.04 .
docker run -v /path/to/yacoin/source:/src yacoin-build:ubuntu20.04

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
| `unit-tests` | Builds `test_bitcoin` and runs all unit test suites in parallel (`contrib/devtools/run-unit-suites.sh`) |
| `functional-tests` | Low-difficulty build, then the functional tests serially (`test_runner.py -j 1`) |
| `cov-unit` | Coverage build (`--enable-lcov`, `-O0`) and `make cov-unit`. Needs lcov 1.x, so it only works in the Ubuntu 22.04 image |

```bash
docker run -v /path/to/yacoin:/src dev34253/yacoin-build:ubuntu.22.04-2 unit-tests
docker run -v /path/to/yacoin:/src -v /path/to/cache:/cache dev34253/yacoin-build:ubuntu.22.04-2 cov-unit
```

- The test modes need a YaCoin tree that contains PR #114 (`contrib/devtools/`
  and the `cov-unit` target). They build out of tree in
  `/src/build/docker-<image>/<mode>`, which is recreated on every run, and
  refuse a tree that was configured in place (run `make distclean` there).
- The test modes install depends without Qt into their own prefix,
  `/src/build/docker-<image>/depends`, so they never replace the depends a
  host build (`dev.sh`) or another image uses. The `build` mode installs into
  the usual `/src/depends/x86_64-pc-linux-gnu`, as before.
- Run one container per source tree at a time: modes share the tree's
  `autogen.sh` output, and `build` configures it in place.
- `JOBS` sets the parallelism (default: the CPUs available to the container,
  including a `--cpus` limit), e.g. `-e JOBS=4`. The `-1` images always used
  4; on hosts with many cores but little memory, set `JOBS` to stay safe.
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

## Windows and macOS images, cache

The cross images (`Dockerfile.windows`, `Dockerfile.macos`) do one thing, the
release build (depends, configure, make, `make install` into
`/src/release-root`), and take no mode argument. Like the Linux images, they
keep built depends packages, depends source tarballs and ccache data in
`/cache` if a directory is mounted there (under `/cache/windows` or
`/cache/macos`), print the cache statistics at the end of every run, and stop
at the first failing step. `JOBS` sets the parallelism (default 4).

```bash
docker run -v /path/to/yacoin:/src -v /path/to/cache:/cache dev34253/yacoin-build:windows-2
```

Image tags: the images are published as `-2` (e.g. `ubuntu.22.04-2`,
`windows-2`, `macos-2`); the `-1` images stay as they were, so existing CI
jobs keep working until they switch.

Ubuntu 16.04 and 18.04 are end of life (and the Windows and macOS images are
based on 18.04). They are still built, because the release matrix uses them;
dropping them needs a separate decision.

## macOS Build Notes

The macOS build uses the osxcross toolchain to cross-compile from Ubuntu 18.04. It downloads the macOS 10.11 SDK and builds binaries compatible with macOS 10.8+. For detailed instructions, see `instructions-macos.md`.

## GitHub Actions

The repository includes a GitHub Actions workflow (`dockerpush.yml`) that builds and pushes the Docker images for all supported platforms when changes are pushed to `master` (or when started manually from the Actions tab). Pushes to other branches do not publish images.

`docker-check.yml` builds the Linux images on pull requests that change a Linux Dockerfile or `entrypoint.sh`, without pushing. It also runs shellcheck on the entrypoint and a short smoke test of each image.