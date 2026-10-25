#!/bin/bash
# Entrypoint of the Linux yacoin-build images.
#
# Usage (the YaCoin source tree is mounted at /src):
#   docker run -v <yacoin>:/src [-v <cache>:/cache] [-e JOBS=n] IMAGE [MODE]
#
# Modes:
#   build             release build (default): depends, configure with glibc
#                     back-compat, make, make install into /src/release-root
#   unit-tests        build test_bitcoin (mainnet consensus) and run all unit
#                     test suites in parallel
#   functional-tests  low-difficulty build, then the functional tests serially
#   cov-unit          coverage build (--enable-lcov, -O0) and "make cov-unit";
#                     needs lcov 1.x (Ubuntu 22.04 image only)
#
# The test modes build out of tree in /src/build/docker-<image>/<mode>, which
# is recreated on every run. If a cache dir is mounted at /cache, depends
# packages, depends sources and ccache data are kept there between runs, per
# image (only one container per image should use the cache at a time).
#
# Environment: JOBS (default: number of CPUs), BUILDVERSION (passed through
# to the version string). SRC_DIR and CACHE_DIR override /src and /cache.
set -euo pipefail

MODE="${1:-build}"
SRC="${SRC_DIR:-/src}"
CACHE="${CACHE_DIR:-/cache}"
IMAGE="${YACOIN_BUILD_IMAGE:-unknown}"
HOST_TRIPLET=x86_64-pc-linux-gnu

die() { echo "error: $*" >&2; exit 1; }

# CPUs available to this container: nproc, limited by a cgroup v2 CPU quota
# (docker run --cpus), which nproc doesn't see.
available_cpus() {
    local n quota="" period="" cpus
    n=$(nproc)
    if [[ -r /sys/fs/cgroup/cpu.max ]]; then                      # cgroup v2
        read -r quota period < /sys/fs/cgroup/cpu.max
        [[ "$quota" == max ]] && quota=""
    elif [[ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]]; then       # cgroup v1
        quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
        period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
        (( quota > 0 )) || quota=""
    fi
    if [[ -n "$quota" && "$period" -gt 0 ]]; then
        cpus=$(( (quota + period - 1) / period ))
        if (( cpus >= 1 && cpus < n )); then n=$cpus; fi
    fi
    echo "$n"
}
JOBS="${JOBS:-$(available_cpus)}"

case "$MODE" in
    build|unit-tests|functional-tests|cov-unit) ;;
    *) echo "unknown mode '$MODE' (build, unit-tests, functional-tests, cov-unit)" >&2; exit 2 ;;
esac
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "JOBS must be a positive integer"

cd "$SRC"
echo "== yacoin-build ($IMAGE): $MODE in $SRC with $JOBS jobs =="

# Checks before the long depends build.
if [[ "$MODE" != build ]]; then
    # Out-of-tree configure refuses a source tree that was configured in place.
    [[ ! -f "$SRC/config.status" ]] ||
        die "$SRC was configured in place (e.g. by the build mode); run 'make distclean' in it first"
fi
if [[ "$MODE" == unit-tests ]]; then
    [[ -x contrib/devtools/run-unit-suites.sh ]] ||
        die "this YaCoin tree has no contrib/devtools/run-unit-suites.sh (needs master after PR #114)"
fi
if [[ "$MODE" == cov-unit ]]; then
    grep -q '^cov-unit:' Makefile.am ||
        die "this YaCoin tree has no cov-unit target (needs master after PR #114)"
    lcov --version 2>/dev/null | grep -q 'version 1\.' ||
        die "cov-unit needs lcov 1.x; use the Ubuntu 22.04 image"
fi

# For genbuild.sh, which runs git on the mounted tree.
git config --global --get-all safe.directory 2>/dev/null | grep -qx "$SRC" ||
    git config --global --add safe.directory "$SRC"

# The release build installs depends into the tree's usual prefix, as before.
# The test modes install a no-Qt depends into a prefix of their own, per
# image, so they never replace the libraries a host build (dev.sh) or another
# image's build is linked against. (x86_64_linux_prefix is the depends make
# variable for this host's install prefix.)
depends_args=(-C depends -j"$JOBS" HOST="$HOST_TRIPLET")
# depends keeps one cached tarball per package and deletes the others when it
# caches a new one, so the release and test builds get separate cache dirs.
if [[ "$MODE" == build ]]; then
    DEPENDS_PREFIX="$SRC/depends/$HOST_TRIPLET"
    cache_kind=depends-built
else
    cache_kind=depends-built-tests
    [[ -d "$CACHE" ]] || depends_args+=(BASE_CACHE="$SRC/build/docker-$IMAGE/depends-built")
    # A path component named "depends", so the coverage filter "*/depends/*"
    # removes these headers from reports.
    DEPENDS_PREFIX="$SRC/build/docker-$IMAGE/depends"
    # Built packages contain their install prefix (.la and .pc files), but
    # depends' package ids don't include it. A separate salt gives these
    # packages their own ids, and so their own cache entries and work dirs.
    salt="prefix:$DEPENDS_PREFIX"
    depends_args+=(NO_QT=1 x86_64_linux_prefix="$DEPENDS_PREFIX"
                   HOST_ID_SALT="$salt" BUILD_ID_SALT="$salt")
fi

# Optional caches, namespaced per image: depends packages are only keyed by
# compiler version strings, and ccache entries can't be shared across
# compilers anyway. Source tarballs are hash-checked, so they are shared.
if [[ -d "$CACHE" ]]; then
    echo "== Using cache in $CACHE/$IMAGE =="
    mkdir -p "$CACHE/$IMAGE/$cache_kind" "$CACHE/depends-sources" "$CACHE/$IMAGE/ccache"
    depends_args+=(BASE_CACHE="$CACHE/$IMAGE/$cache_kind" SOURCES_PATH="$CACHE/depends-sources")
    export CCACHE_DIR="$CACHE/$IMAGE/ccache"
fi
# depends builds its own ccache and configure uses it.
export CCACHE_BASEDIR="$SRC" CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-5G}"

# Cache statistics on every exit, including failed runs, to show whether a
# slow run used the cache.
print_cache_stats() {
    local status=$?
    if [[ -n "${CCACHE_DIR:-}" && -x "$DEPENDS_PREFIX/native/bin/ccache" ]]; then
        "$DEPENDS_PREFIX/native/bin/ccache" -s | grep -E 'cache hit|cache miss|cache size' || true
    fi
    (( status == 0 )) || echo "== Failed ($MODE, exit status $status) ==" >&2
}
trap print_cache_stats EXIT

echo "== Building dependencies =="
# The depends packages run their own configure scripts; they must not read
# the config.site meant for yacoind.
env -u CONFIG_SITE make "${depends_args[@]}"

echo "== Generating the build system =="
./autogen.sh

# Exported so that configure re-runs started by make also find the depends.
export CONFIG_SITE="$DEPENDS_PREFIX/share/config.site"

if [[ "$MODE" == build ]]; then
    echo "== Building yacoin =="
    ./configure --enable-glibc-back-compat --enable-reduce-exports LDFLAGS=-static-libstdc++ --prefix=/
    make -j"$JOBS"
    make install DESTDIR="$SRC/release-root"
else
    builddir="$SRC/build/docker-$IMAGE/$MODE"
    echo "== Configuring in $builddir =="
    rm -rf "$builddir"; mkdir -p "$builddir"
    flags=(--without-gui --disable-man --enable-ccache)
    case "$MODE" in
        unit-tests) flags+=("CXXFLAGS=-O1 -g" "CFLAGS=-O1 -g") ;;
        functional-tests) flags+=(--enable-low-difficulty-for-development "CXXFLAGS=-O1 -g" "CFLAGS=-O1 -g") ;;
        cov-unit) flags+=(--enable-lcov "CXXFLAGS=-O0 -g" "CFLAGS=-O0 -g") ;;
    esac
    (cd "$builddir" && "$SRC/configure" "${flags[@]}")
    export TMPDIR="$builddir/test/tmp"; mkdir -p "$TMPDIR"
    case "$MODE" in
        unit-tests)
            make -C "$builddir/src" -j"$JOBS" test/test_bitcoin
            contrib/devtools/run-unit-suites.sh "$builddir/src/test/test_bitcoin" \
                "$builddir/unit-test-logs" "$JOBS"
            ;;
        functional-tests)
            # The functional tests only run yacoind and yacoin-cli.
            make -C "$builddir/src" -j"$JOBS" yacoind yacoin-cli
            # The runner reads ../config.ini relative to its own path.
            mkdir -p "$builddir/test/functional"
            ln -sf "$SRC/test/functional/test_runner.py" "$builddir/test/functional/test_runner.py"
            "$builddir/test/functional/test_runner.py" -j 1 --tmpdirprefix="$TMPDIR"
            ;;
        cov-unit)
            make -C "$builddir" -j"$JOBS" COV_JOBS="$JOBS" cov-unit
            echo "== Coverage report: $builddir/test_bitcoin.coverage/index.html =="
            ;;
    esac
fi

echo "== Done ($MODE) =="
