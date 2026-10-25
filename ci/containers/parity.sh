#!/usr/bin/env bash
# Parity test: an image built from the Dockerfiles in this directory must
# provide the same build environment as the published reference image, and
# its modes must pass on a clean checkout.
#
# Usage: ci/containers/parity.sh [options] <image>...
#
# For each image:
#   1. builds yacoin-build-local:<image> from this directory (run.sh);
#   2. compares it with dev34253/yacoin-build:<image>-2 (REFERENCE_REPO,
#      REFERENCE_SUFFIX): image config (entrypoint, env, workdir, user), OS
#      release, compilers and build tools, the toolchains that are not dpkg
#      packages (osxcross, macOS SDK), and the installed package list;
#   3. runs the modes, each on its own clean clone of HEAD, with one cache
#      directory that starts empty.
#
# Exit status 0 only if every image matches and every mode passes. Package
# names and every tool version must match exactly. Package versions may
# differ (the Ubuntu archives keep publishing updates); they are listed, and
# --strict-versions makes a difference fail.
#
# Options:
#   --modes LIST       comma-separated modes, or "none" (default per image:
#                      what CI runs on it, plus unit-tests on ubuntu.22.04)
#   --workdir DIR      where clones, caches and logs go (default: a new
#                      directory under ${TMPDIR:-/tmp}); kept if a mode fails
#   --keep             keep the workdir also when everything passes
#   --strict-versions  fail on package version differences
#   --no-image-build   compare the existing local image
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=run.sh
source "$HERE/run.sh"
# sort and join must agree on the order.
export LC_ALL=C
REFERENCE_REPO="${REFERENCE_REPO:-dev34253/yacoin-build}"
REFERENCE_SUFFIX="${REFERENCE_SUFFIX:--2}"

modes_opt="" workdir="" keep=0 strict=0 image_build=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --modes) modes_opt="$2"; shift 2 ;;
        --workdir) workdir="$2"; shift 2 ;;
        --keep) keep=1; shift ;;
        --strict-versions) strict=1; shift ;;
        --no-image-build) image_build=0; shift ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        -*) echo "unknown option '$1'" >&2; exit 2 ;;
        *) break ;;
    esac
done
[[ $# -ge 1 ]] || { echo "usage: $0 [options] <image>..." >&2; exit 2; }

default_modes() {
    case "$1" in
        ubuntu.16.04) echo build,unit-tests ;;
        ubuntu.22.04) echo build,unit-tests,functional-tests ;;
        *) echo build ;;
    esac
}

# Everything in one bash call, so the image needs nothing but bash. Each line
# is "<item>: <value>"; tools that are not installed say "absent".
# shellcheck disable=SC2016 # expanded inside the container
PROBE='
. /etc/os-release; echo "os: $PRETTY_NAME"
v() { local name=$1; shift
      if command -v "$1" >/dev/null 2>&1; then echo "$name: $("$@" 2>&1 | head -n1)"; else echo "$name: absent"; fi; }
for t in gcc g++ cc c++ cpp gcov; do v "$t" "$t" --version; done
v python3 python3 --version
v autoconf autoconf --version
v automake automake --version
v libtoolize libtoolize --version
v pkg-config pkg-config --version
v make make --version
v bison bison --version
v ccache ccache --version
v lcov lcov --version
v git git --version
v curl curl --version
v cmake cmake --version
v clang clang --version
for t in gcc g++; do
    v "mingw-$t-posix" "x86_64-w64-mingw32-$t-posix" --version
    command -v "x86_64-w64-mingw32-$t" >/dev/null &&
        echo "mingw-$t default: $(readlink -f "$(command -v "x86_64-w64-mingw32-$t")")"
done
v darwin-clang x86_64-apple-darwin15-clang --version
v darwin-ld x86_64-apple-darwin15-ld -v
if [ -d /opt/osxcross ]; then
    echo "osxcross commit: $(git -C /opt/osxcross rev-parse HEAD 2>&1)"
    for f in /opt/osxcross/tarballs/*; do echo "osxcross tarball: $(sha256sum "$f")"; done
    echo "osxcross target/bin: $(ls /opt/osxcross/target/bin | wc -l) files"
    echo "osxcross SDK: $(ls /opt/osxcross/target/SDK)"
fi
'

probe() { docker run --rm --entrypoint bash "$1" -c "$PROBE"; }
packages() {
    docker run --rm --entrypoint dpkg-query "$1" -W -f '${binary:Package} ${Version}\n' | sort
}
config() {
    docker image inspect "$1" --format \
        'entrypoint={{json .Config.Entrypoint}}
cmd={{json .Config.Cmd}}
env={{json .Config.Env}}
workdir={{.Config.WorkingDir}}
user={{.Config.User}}'
}

# compare <what> <reference file> <local file>: prints the result, returns 1 on a difference.
compare() {
    if diff -u --label "reference $1" --label "local $1" "$2" "$3" > "$2.diff"; then
        echo "  $1: same ($(wc -l < "$2") lines)"
    else
        echo "  $1: DIFFERENT"; sed 's/^/    /' "$2.diff"; return 1
    fi
}

compare_image() {
    local image="$1" ref="$REFERENCE_REPO:$1$REFERENCE_SUFFIX" loc="$LOCAL_REPO:$1" d="$2" ok=0
    echo "== $image: $loc against $ref =="
    docker image inspect "$ref" >/dev/null 2>&1 || docker pull -q "$ref" >/dev/null
    config "$ref" > "$d/config.ref"; config "$loc" > "$d/config.local"
    compare config "$d/config.ref" "$d/config.local" || ok=1
    probe "$ref" > "$d/tools.ref"; probe "$loc" > "$d/tools.local"
    compare tools "$d/tools.ref" "$d/tools.local" || ok=1
    packages "$ref" > "$d/packages.ref"; packages "$loc" > "$d/packages.local"
    cut -d' ' -f1 "$d/packages.ref" > "$d/names.ref"; cut -d' ' -f1 "$d/packages.local" > "$d/names.local"
    compare "package names" "$d/names.ref" "$d/names.local" || ok=1
    # Versions of the packages both images have.
    join "$d/packages.ref" "$d/packages.local" | awk '$2 != $3 {print "    " $1 ": " $2 " -> " $3}' > "$d/versions.diff"
    if [[ -s "$d/versions.diff" ]]; then
        echo "  package versions: $(wc -l < "$d/versions.diff") differ (reference -> local)"
        cat "$d/versions.diff"
        (( strict == 0 )) || ok=1
    else
        echo "  package versions: same"
    fi
    # Informational: the entrypoint is expected to change in this repository.
    local e
    e=$(docker image inspect "$loc" --format '{{index .Config.Entrypoint 0}}')
    if [[ "$(docker run --rm --entrypoint sha256sum "$ref" "$e" | cut -d' ' -f1)" == \
          "$(docker run --rm --entrypoint sha256sum "$loc" "$e" | cut -d' ' -f1)" ]]; then
        echo "  $e: same as the reference"
    else
        echo "  $e: differs from the reference (expected where this repository changed it)"
    fi
    return "$ok"
}

# check_mode <image> <mode> <src> <log>: checks what the mode must leave behind.
check_mode() {
    local image="$1" mode="$2" src="$3" log="$4" b ext=""
    case "$mode" in
        build)
            [[ "$image" != windows ]] || ext=.exe
            for b in yacoind yacoin-cli yacoin-qt; do
                [[ -s "$src/release-root/bin/$b$ext" ]] || { echo "    missing release-root/bin/$b$ext"; return 1; }
            done
            echo "    release-root/bin: yacoind$ext yacoin-cli$ext yacoin-qt$ext" ;;
        unit-tests)
            grep -E '^[0-9]+ passed, 0 failed' "$log" | sed 's/^/    unit test suites: /' | grep . ||
                { echo "    no '<n> passed, 0 failed' line"; return 1; } ;;
        functional-tests)
            local n
            n=$(grep -cE '^[A-Za-z0-9_.-]+\.py[^|]*\|.*Passed' "$log" || true)
            grep -qE '^ALL +\|.*Passed' "$log" || { echo "    the runner did not report ALL passed"; return 1; }
            echo "    functional tests: $n passed" ;;
        cov-unit)
            [[ -f "$src/build/docker-$image/cov-unit/test_bitcoin.coverage/index.html" ]] ||
                { echo "    no coverage report"; return 1; } ;;
    esac
}

run_modes() {
    local image="$1" d="$2" mode status=0 start rc list
    IFS=, read -ra list <<< "$3"
    for mode in "${list[@]}"; do
        local src="$d/src-$mode" log="$d/$mode.log"
        rm -rf "$src"
        git clone -q --no-local "$ROOT" "$src"
        git -C "$src" checkout -q --detach "$(git -C "$ROOT" rev-parse HEAD)"
        echo "== $image: $mode on a clean clone of $(git -C "$src" rev-parse --short HEAD) (log: $log) =="
        start=$SECONDS rc=0
        "$HERE/run.sh" --no-image-build --src "$src" --cache "$d/cache" \
            --name "yacoin-parity-$image-$mode" "$image" "$mode" > "$log" 2>&1 || rc=$?
        echo "  $mode: exit status $rc after $(( (SECONDS - start) / 60 )) min $(( (SECONDS - start) % 60 )) s"
        if (( rc != 0 )); then
            tail -n 30 "$log" | sed 's/^/    | /'; status=1
        elif ! check_mode "$image" "$mode" "$src" "$log"; then
            status=1
        fi
        grep -E '^cache (hit|miss)' "$log" | sed 's/^/    ccache /' || true
    done
    return "$status"
}

[[ -n "$workdir" ]] || workdir="$(mktemp -d "${TMPDIR:-/tmp}/yacoin-parity.XXXXXX")"
mkdir -p "$workdir"; workdir="$(cd "$workdir" && pwd)"
overall=0 summary=()
for image in "$@"; do
    [[ -f "$HERE/Dockerfile.$image" ]] || { echo "unknown image '$image'" >&2; exit 2; }
    d="$workdir/$image"; mkdir -p "$d"
    (( image_build == 0 )) || build_image "$image" > "$d/image-build.log" 2>&1 ||
        { echo "== $image: docker build failed (log: $d/image-build.log) =="; tail -n 20 "$d/image-build.log"
          overall=1; summary+=("FAIL  $image: docker build"); continue; }
    if compare_image "$image" "$d"; then summary+=("PASS  $image: image parity"); else summary+=("FAIL  $image: image parity"); overall=1; fi
    modes="${modes_opt:-$(default_modes "$image")}"
    if [[ "$modes" != none ]]; then
        if run_modes "$image" "$d" "$modes"; then summary+=("PASS  $image: modes $modes"); else summary+=("FAIL  $image: modes $modes"); overall=1; fi
    fi
done
echo "== Summary =="
printf '  %s\n' "${summary[@]}"
if (( overall == 0 && keep == 0 )); then rm -rf "$workdir"; else echo "Work directory: $workdir"; fi
exit "$overall"
