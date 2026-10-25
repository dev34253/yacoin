# YaCoin Build Environment

This directory holds the definitions of the Docker build images that CI uses (published on Docker Hub as `dev34253/yacoin-build:<image>-2`).
The base images are pinned by digest, the macOS toolchain inputs are pinned and checked, and the entrypoints create the ccache config before
the build.

| File | What it is |
|---|---|
| `Dockerfile.<image>` | One image each: `ubuntu.16.04`, `ubuntu.18.04`, `ubuntu.20.04`, `ubuntu.22.04`, `ubuntu.24.04-gcc11`, `windows`, `macos` |
| `entrypoint.sh`, `entrypoint.windows.sh`, `entrypoint.macos.sh` | What the images run: the Linux modes, and the Windows and macOS release builds |
| `run.sh` | Builds an image from these files and runs a mode on a source tree (`./dev.sh container` calls it) |
| `check.sh` | The image checks: lint, digest pins, `docker build`, smoke tests, ccache config, and an opt-in two-build cache test |
| `parity.sh` | Compares an image built from here with the published one and runs its modes on a clean clone |

```bash
./dev.sh container unit-tests                  # ubuntu.22.04 image, unit-tests mode, on this checkout
ci/containers/run.sh windows                    # the Windows release build
ci/containers/check.sh                          # all images: lint, static, build, smoke, ccache
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
| `build-low-difficulty` | The release build with `--enable-low-difficulty-for-development` (mainnet proof-of-work limits relaxed, for miner tests) |
| `unit-tests` | Builds `test_bitcoin` and runs all unit test suites in parallel (`contrib/devtools/run-unit-suites.sh`) |
| `functional-tests` | Low-difficulty build, then the functional tests serially (`test_runner.py -j 1`) |
| `cov-unit` | Coverage build (`--enable-lcov`, `-O0`) and `make cov-unit`. Needs lcov 1.x, so it only works in the Ubuntu 22.04 image |

```bash
docker run -v /path/to/yacoin:/src dev34253/yacoin-build:ubuntu.22.04-2 unit-tests
docker run -v /path/to/yacoin:/src -v /path/to/cache:/cache dev34253/yacoin-build:ubuntu.22.04-2 cov-unit
```

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
`windows-2`, `macos-2`).

Ubuntu 16.04 and 18.04 are end of life (and the Windows and macOS images are
based on 18.04). They are built because the release matrix uses them.

## macOS Build Notes

The macOS build uses the osxcross toolchain to cross-compile from Ubuntu 18.04. It downloads the macOS 10.11 SDK and builds binaries compatible
with macOS 10.8+. osxcross is pinned to the commit of the published `macos-2` image (`OSXCROSS_COMMIT`), and the SDK tarball is checked
against the hash of the one in that image.

## GitHub Actions

The CI workflow `.github/workflows/yacoinbuildmultiplatform.yml` runs the published `-2` images. No workflow builds the images from these
files; `check.sh` runs the image checks locally.
