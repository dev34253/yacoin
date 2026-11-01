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
| `check.sh` | The image checks: lint, image tags, digest pins, `docker build`, smoke tests, ccache config, and an opt-in two-build cache test |
| `parity.sh` | Compares an image built from here with the one on Docker Hub (`dev34253/yacoin-build:<image>-2`) and runs its modes on a clean clone |

```bash
./dev.sh container unit-tests                  # ubuntu.22.04 image, unit-tests mode, on this checkout
ci/containers/run.sh windows                    # the Windows release build
ci/containers/check.sh                          # all images: lint, tag, static, build, smoke, ccache
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
  [linux-test-project/lcov](https://github.com/linux-test-project/lcov/releases), checked against its SHA-256; Ubuntu 22.04 ships 1.14)

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
| `build-low-difficulty` | The release build with `--enable-low-difficulty-for-development` (mainnet proof-of-work limits relaxed, for miner tests) |
| `unit-tests` | Builds `test_bitcoin` and runs all unit test suites in parallel (`contrib/devtools/run-unit-suites.sh`) |
| `functional-tests` | Low-difficulty build, then all functional test scripts, the extended ones too, `FTEST_JOBS` (default 4) in parallel (`test_runner.py -j "$FTEST_JOBS" --extended`) |
| `cov-unit` | Coverage build (`--enable-lcov`, `-O0`) and `make cov-unit`. Needs lcov 2.6 or newer, so it only works in the Ubuntu 22.04 image |
| `cov-functional` | Low-difficulty coverage build and `make cov-functional`: the functional test scripts `FTEST_JOBS` (default 4) in parallel, then `p2p_invalid_messages.py` alone. Needs lcov 2.6 or newer (Ubuntu 22.04 image only) |

```bash
image=$(ci/containers/image-tag.sh ubuntu.22.04)    # pullable once CI on master has published it
docker run -v /path/to/yacoin:/src "$image" unit-tests
docker run -v /path/to/yacoin:/src -v /path/to/cache:/cache "$image" cov-unit
docker run -v /path/to/yacoin:/src -v /path/to/cache:/cache "$image" cov-functional
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
`.github/actions/yacoin-build-image` provides it:

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

The jobs also keep the depends packages, depends sources and ccache in the GitHub Actions cache, one per job kind and image
(`release-<image>-…`, `low-difficulty-<image>-…`, `unit-tests-<image>-…`, `functional-tests-<image>-…`, keyed by the depends
definitions). Only pushes to `master` save them; the release jobs (including `build-ubuntu-1604-low-difficulty`) build from scratch there.
Other runs restore the newest matching cache; the low-difficulty job falls back to the 16.04 release cache if it has none of its own.
The coverage jobs (`coverage-unit`, `coverage-functional`) restore the `functional-tests-<image>-…` cache for their depends packages
(the same image, packages and prefix) and never save one; they build with ccache off, since their `-O0` objects never match the
cached ones. `coverage-report` merges their tracefiles and runs `contrib/devtools/coverage-check.py`.
