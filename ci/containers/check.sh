#!/usr/bin/env bash
# Image checks, run locally. Derived from docker-check.yml of
# dev34253/yacoin-build-ubuntu (copy in source-workflows/), which ran them on
# pull requests there.
#
# Usage: ci/containers/check.sh [--steps LIST] [image...]
#
# Steps (default: lint,static,build,smoke,ccache; all images by default):
#   lint    bash -n and shellcheck --severity=warning on the scripts here
#   static  every Dockerfile pins its base image by digest and sets
#           YACOIN_BUILD_IMAGE to its own name
#   build   docker build of each image (tagged yacoin-build-local:<image>)
#   smoke   tools present, unknown modes and arguments rejected, test modes
#           stop early on a tree without the scripts and targets they need
#   ccache  the entrypoint creates the ccache config before anything runs
#           ccache, with an empty /cache and with none (a stub source tree
#           makes this quick)
#   cache   slow (two release builds per image): build a clean clone of HEAD
#           twice with one cache dir, cleaning the tree in between; the second
#           build must take every depends package from the cache and get
#           ccache hits (the "cross" job of docker-check.yml)
#
# The shellcheck binary comes from the host if installed, otherwise from Ubuntu 22.04's
# package in a throwaway container. CHECK_WORKDIR keeps the work files.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=run.sh
source "$HERE/run.sh"

steps=lint,static,build,smoke,ccache
while [[ $# -gt 0 ]]; do
    case "$1" in
        --steps) steps="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        -*) echo "unknown option '$1'" >&2; exit 2 ;;
        *) break ;;
    esac
done
if [[ $# -gt 0 ]]; then
    images=("$@")
else
    mapfile -t images < <(cd "$HERE" && ls Dockerfile.* | sed 's/^Dockerfile\.//')
fi
for image in "${images[@]}"; do
    [[ -f "$HERE/Dockerfile.$image" ]] || { echo "unknown image '$image'" >&2; exit 2; }
done
has_step() { [[ ",$steps," == *",$1,"* ]]; }
is_cross() { [[ "$1" == windows || "$1" == macos ]]; }

work="${CHECK_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/yacoin-check.XXXXXX")}"
mkdir -p "$work"; work="$(cd "$work" && pwd)"
failures=()
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures+=("$*"); }

# The pinned base of the 22.04 image, so the fallback is as reproducible as it.
shellcheck_cmd() {
    if command -v shellcheck >/dev/null; then
        shellcheck "$@"
    else
        local base
        base=$(sed -n 's/^FROM //p' "$HERE/Dockerfile.ubuntu.22.04")
        docker run --rm -v "$HERE:/w:ro" -w /w "$base" bash -c \
            'apt-get update -qq && apt-get install -y -qq shellcheck >/dev/null 2>&1 && shellcheck "$@"' _ "$@"
    fi
}

step_lint() {
    local f scripts=(entrypoint.sh entrypoint.windows.sh entrypoint.macos.sh run.sh parity.sh check.sh)
    for f in "${scripts[@]}"; do
        bash -n "$HERE/$f" && pass "lint: bash -n $f" || fail "lint: bash -n $f"
    done
    (cd "$HERE" && shellcheck_cmd -x --severity=warning "${scripts[@]}") &&
        pass "lint: shellcheck ${scripts[*]}" || fail "lint: shellcheck"
}

step_static() {
    local image df from env
    for image in "${images[@]}"; do
        df="$HERE/Dockerfile.$image"
        # Every FROM line, so a later multi-stage build is checked too.
        while read -r from; do
            [[ "$from" =~ ^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}( |$) ]] &&
                pass "static: $image: FROM $from" ||
                fail "static: $image: base image not pinned by digest (FROM $from)"
        done < <(sed -n 's/^FROM[[:space:]]\{1,\}//p' "$df")
        env=$(sed -n 's/^ENV YACOIN_BUILD_IMAGE=//p' "$df")
        [[ "$env" == "$image" ]] && pass "static: $image: YACOIN_BUILD_IMAGE=$env" ||
            fail "static: $image: YACOIN_BUILD_IMAGE is '$env'"
    done
}

step_build() {
    local image
    for image in "${images[@]}"; do
        if build_image "$image" > "$work/build-$image.log" 2>&1; then
            pass "build: $image"
        else
            tail -n 20 "$work/build-$image.log"; fail "build: $image (log: $work/build-$image.log)"
        fi
    done
}

# expect_status <want> <description> <command...>: also keeps the output in $work/out.txt.
expect_status() {
    local want="$1" what="$2" status=0; shift 2
    "$@" > "$work/out.txt" 2>&1 || status=$?
    if [[ "$status" == "$want" ]]; then pass "$what"; else cat "$work/out.txt"; fail "$what (exit status $status, want $want)"; fi
}

step_smoke() {
    local image tag mode fake="$work/fake-src"
    rm -rf "$fake"; mkdir -p "$fake"; printf 'all:\n' > "$fake/Makefile.am"
    for image in "${images[@]}"; do
        tag="$LOCAL_REPO:$image"
        # shellcheck disable=SC2016 # expanded inside the container
        expect_status 0 "smoke: $image: environment and tools" docker run --rm -e WANT="$image" --entrypoint bash "$tag" -c '
            set -e
            test "$YACOIN_BUILD_IMAGE" = "$WANT"
            bison --version | head -1
            bash -n "$(ls /entrypoint*.sh)"
            if [ "$YACOIN_BUILD_IMAGE" = ubuntu.22.04 ]; then lcov --version; fi'
        if is_cross "$image"; then
            expect_status 2 "smoke: $image: an argument is rejected" docker run --rm "$tag" build
            continue
        fi
        # An unknown mode must be rejected before anything is built.
        expect_status 2 "smoke: $image: unknown mode rejected" docker run --rm "$tag" no-such-mode
        # The test modes must stop early, with a clear message, on a tree
        # without the scripts and targets they need.
        for mode in unit-tests cov-unit; do
            expect_status 1 "smoke: $image: $mode stops on a tree without its scripts" \
                docker run --rm -v "$fake:/src" "$tag" "$mode"
            grep -q 'error: ' "$work/out.txt" || fail "smoke: $image: $mode gave no 'error: ' message"
        done
    done
}

# A stub source tree: depends is a no-op and autogen.sh, the step after it and
# before the first compile, records whether the ccache config exists, then
# stops the run.
make_ccache_stub() {
    local d="$1"
    rm -rf "$d"; mkdir -p "$d/depends"
    printf 'all:\n\t@true\n' > "$d/depends/Makefile"
    # shellcheck disable=SC2016 # expanded inside the container
    printf '%s\n' '#!/bin/bash' \
        'f="${CCACHE_CONFIGPATH:-${CCACHE_DIR:-$HOME/.ccache}/ccache.conf}"' \
        'if [ -f "$f" ]; then echo "present $f"; else echo "missing $f"; fi > /src/ccache-conf-state' \
        'exit 1' > "$d/autogen.sh"
    chmod +x "$d/autogen.sh"
}

# ccache 3.3.4 creates its config on first use; parallel first compiles on an
# empty cache race for it and fail with "ccache.conf: No such file or
# directory". The entrypoint must create it before anything runs ccache.
step_ccache() {
    local image tag stub="$work/ccache-stub" cache="$work/ccache-cache" state
    for image in "${images[@]}"; do
        tag="$LOCAL_REPO:$image"
        for with_cache in yes no; do
            make_ccache_stub "$stub"
            local mounts=(-v "$stub:/src")
            if [[ $with_cache == yes ]]; then
                docker run --rm -v "$work:/w" --entrypoint rm "$tag" -rf /w/ccache-cache
                mkdir -p "$cache"; mounts+=(-v "$cache:/cache")
            fi
            docker run --rm "${mounts[@]}" "$tag" > "$work/ccache-$image.log" 2>&1 || true
            state=$(cat "$stub/ccache-conf-state" 2>/dev/null || echo "autogen.sh did not run")
            if [[ "$state" == present* ]]; then
                pass "ccache: $image: config created before the build (/cache: $with_cache; $state)"
            else
                tail -n 5 "$work/ccache-$image.log"
                fail "ccache: $image: no ccache config before the build (/cache: $with_cache; $state)"
            fi
        done
    done
    # The container wrote as root.
    docker run --rm -v "$work:/w" --entrypoint rm "$LOCAL_REPO:${images[0]}" -rf /w/ccache-stub /w/ccache-cache
}

step_cache() {
    local image src="$work/cache-src" cache b hits misses
    for image in "${images[@]}"; do
        cache="$work/cache-$image"
        rm -rf "$src"; git clone -q --no-local "$ROOT" "$src"
        git -C "$src" checkout -q --detach "$(git -C "$ROOT" rev-parse HEAD)"
        echo "== cache: $image, first build (empty cache) =="
        if ! "$HERE/run.sh" --no-image-build --src "$src" --cache "$cache" --name "yacoin-check-$image-1" \
                "$image" > "$work/cache-$image-run1.log" 2>&1; then
            tail -n 30 "$work/cache-$image-run1.log"; fail "cache: $image: first build"; continue
        fi
        git -C "$src" clean -xdfq
        [[ -z "$(git -C "$src" status --porcelain)" ]] || { fail "cache: $image: tree not clean"; continue; }
        echo "== cache: $image, second build (warm cache) =="
        if ! "$HERE/run.sh" --no-image-build --src "$src" --cache "$cache" --name "yacoin-check-$image-2" \
                "$image" > "$work/cache-$image-run2.log" 2>&1; then
            tail -n 30 "$work/cache-$image-run2.log"; fail "cache: $image: second build"; continue
        fi
        local log="$work/cache-$image-run2.log" ok=1 ext=""
        [[ "$image" != windows ]] || ext=.exe
        for b in yacoind yacoin-cli yacoin-qt; do [[ -s "$src/release-root/bin/$b$ext" ]] || ok=0; done
        grep -q "^== Using cache in /cache/$image ==" "$log" || ok=0
        # depends prints these only when it builds or downloads a package; a
        # run from the cache only copies the packages.
        if grep -E '^(Fetching|Extracting|Building) [A-Za-z0-9_+.-]+' "$log"; then ok=0; fi
        grep -q '^copying packages:' "$log" || ok=0
        if grep -q 'Checksum mismatch' "$log"; then ok=0; fi
        # ccache prints running totals, so compare the two runs.
        tot() { awk -v re="$1" '$0 ~ re {s += $NF} END {print s + 0}' "$2"; }
        hits=$(( $(tot '^cache hit \\((direct|preprocessed)\\)' "$log") - $(tot '^cache hit \\((direct|preprocessed)\\)' "$work/cache-$image-run1.log") ))
        misses=$(( $(tot '^cache miss' "$log") - $(tot '^cache miss' "$work/cache-$image-run1.log") ))
        echo "  second build: $hits ccache hits, $misses misses"
        # A few misses are expected (e.g. clientversion.cpp uses __DATE__).
        (( hits > 0 && hits * 10 >= (hits + misses) * 9 )) || ok=0
        if (( ok )); then pass "cache: $image: second build used the cache"; else fail "cache: $image: second build did not use the cache"; fi
    done
}

for s in lint static build smoke ccache cache; do
    if has_step "$s"; then echo "== $s =="; "step_$s"; fi
done
echo "== ${#failures[@]} failure(s) =="
printf '  %s\n' "${failures[@]}"
if (( ${#failures[@]} == 0 )) && [[ -z "${CHECK_WORKDIR:-}" ]]; then rm -rf "$work"; fi
(( ${#failures[@]} == 0 ))
