#!/bin/bash
# Entrypoint of the macOS yacoin-build image (cross-compiles with osxcross).
#
# Usage (the YaCoin source tree is mounted at /src):
#   docker run -v <yacoin>:/src [-v <cache>:/cache] [-e JOBS=n] IMAGE
#
# Release build: depends, configure, make, make install into /src/release-root.
# If a cache dir is mounted at /cache, depends packages, depends sources and
# ccache data are kept there between runs (only one container should use the
# cache at a time).
#
# Environment: JOBS (default 4), BUILDVERSION (passed through to the version
# string). SRC_DIR and CACHE_DIR override /src and /cache.
set -euo pipefail

SRC="${SRC_DIR:-/src}"
CACHE="${CACHE_DIR:-/cache}"
IMAGE="${YACOIN_BUILD_IMAGE:-macos}"
HOST_TRIPLET=x86_64-apple-darwin15
DEPENDS_PREFIX="$SRC/depends/$HOST_TRIPLET"
JOBS="${JOBS:-4}"

[[ $# -eq 0 ]] || { echo "this image takes no arguments" >&2; exit 2; }
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "error: JOBS must be a positive integer" >&2; exit 1; }

echo "== Building yacoin for macOS in $SRC with $JOBS jobs =="
cd "$SRC"

# For genbuild.sh, which runs git on the mounted tree.
git config --global --get-all safe.directory 2>/dev/null | grep -qx "$SRC" ||
    git config --global --add safe.directory "$SRC"

depends_args=(-C depends -j"$JOBS" HOST="$HOST_TRIPLET")
if [[ -d "$CACHE" ]]; then
    echo "== Using cache in $CACHE/$IMAGE =="
    mkdir -p "$CACHE/$IMAGE/depends-built" "$CACHE/depends-sources" "$CACHE/$IMAGE/ccache"
    depends_args+=(BASE_CACHE="$CACHE/$IMAGE/depends-built" SOURCES_PATH="$CACHE/depends-sources")
    export CCACHE_DIR="$CACHE/$IMAGE/ccache"
fi
# depends builds its own ccache and configure uses it. The compiler is the
# depends clang (native_cctools); ccache identifies it by size and mtime, which
# stay the same as long as that package comes from the same cache.
export CCACHE_BASEDIR="$SRC" CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-5G}"

# Cache statistics on every exit, including failed runs, to show whether a
# slow run used the cache.
print_cache_stats() {
    local status=$?
    if [[ -n "${CCACHE_DIR:-}" && -x "$DEPENDS_PREFIX/native/bin/ccache" ]]; then
        "$DEPENDS_PREFIX/native/bin/ccache" -s | grep -E 'cache hit|cache miss|cache size' || true
    fi
    (( status == 0 )) || echo "== Failed (exit status $status) ==" >&2
}
trap print_cache_stats EXIT

echo "== Building dependencies for macOS =="
# The depends packages run their own configure scripts; they must not read
# the config.site meant for yacoind.
env -u CONFIG_SITE make "${depends_args[@]}"

echo "== Building yacoin for macOS =="
./autogen.sh
# Exported so that configure re-runs started by make also find the depends.
export CONFIG_SITE="$DEPENDS_PREFIX/share/config.site"
./configure LDFLAGS=-static-libstdc++ --prefix=/
make -j"$JOBS"
make install DESTDIR="$SRC/release-root"

echo "== Build completed. Executables are in release-root/bin directory =="
