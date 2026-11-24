#!/usr/bin/env bash
# Builds a yacoin-build image from the Dockerfiles in this directory and runs
# one mode of it on a YaCoin source tree, the way CI runs these images.
# See ci/containers/README.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

usage() {
    cat <<EOF
Usage: ci/containers/run.sh [options] <image> [mode]
       ./dev.sh container [options] [image] [mode]   (image defaults to ubuntu.22.04)

  image   $(cd "$HERE" && ls Dockerfile.* | sed 's/^Dockerfile\.//' | tr '\n' ' ')
  mode    Linux images: build (default), build-low-difficulty, unit-tests,
          unit-tests-asan, unit-tests-tsan, fuzz-corpus, functional-tests,
          functional-tests-asan, cov-unit, cov-functional
          windows, macos: build (the only mode)

Options:
  --src DIR         source tree mounted at /src (default: $ROOT)
  --cache DIR       cache mounted at /cache (default: one per set of depends
                    inputs of the source tree, \$DEV_CACHE/container/<key>;
                    DEV_CACHE defaults to \${XDG_CACHE_HOME:-\$HOME/.cache}/yacoin-dev,
                    as for dev.sh)
  --no-cache        mount no cache
  --name NAME       container name (default: yacoin-build-<image>-<mode>-<id>,
                    unique per run)
  --cpus N          CPU limit of the container (docker run --cpus)
  --no-image-build  run the existing local image instead of building it first
  --print-tag IMAGE print the local tag of the image and exit

The image is tagged $LOCAL_REPO:<image> (this clone's own name; LOCAL_REPO
sets another). JOBS, FTEST_JOBS, FTEST_SHARD, SANITIZE, BUILDVERSION,
CCACHE_MAXSIZE and CCACHE_COMPRESS are passed to the container if set.
One run at a time builds depends with a cache: a run holds a lock on it
(<cache>/run.lock) until the container prints its first line after the
depends build, or to its end; another run waits. The
container runs as root, as in CI; afterwards the files it wrote are given back
to the caller (not needed and not done with rootless Docker or Podman, where
container root already is the caller). The unit-tests-tsan mode runs with
--security-opt seccomp=unconfined, as in CI: it turns address randomisation
off for its tests, which Docker's default seccomp filter refuses. The
sanitizer modes (unit-tests-asan, unit-tests-tsan, fuzz-corpus,
functional-tests-asan) get CCACHE_DISABLE=1, as in CI, so their objects do
not evict the cache.
EOF
}

# The repository name of this clone's images: its directory name, made a
# valid repository name, and a checksum of its physical path, so clones
# (also with one directory name) never retag each other's images and one
# clone keeps its name through a symlink.
local_repo_default() {
    local root name
    root="$(cd "$ROOT" && pwd -P)"
    name="$(basename "$root" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')"
    name="${name#-}"; name="${name:0:40}"; name="${name%-}"
    echo "yacoin-build-local-${name:+$name-}$(printf '%s' "$root" | cksum | cut -d' ' -f1)"
}

# Shared with parity.sh and check.sh.
LOCAL_REPO="${LOCAL_REPO:-$(local_repo_default)}"
LOCAL_LABEL=org.yacoin.build-local=1

build_image() {
    local image="$1"
    [[ -f "$HERE/Dockerfile.$image" ]] || { echo "unknown image '$image'" >&2; exit 2; }
    docker build --label "$LOCAL_LABEL" --label "org.yacoin.build-local.tree=$(cd "$ROOT" && pwd -P)" \
        -f "$HERE/Dockerfile.$image" -t "$LOCAL_REPO:$image" "$HERE"
}

# The default cache of a source tree: one per set of its depends inputs (the
# content of the files under depends/ that git does not ignore; dev.sh's
# CONTAINER_CACHE), under dev.sh's cache. A tree that is not a git checkout
# gets one of its own.
default_cache() {
    local tree inputs
    tree="$(cd "$1" && pwd -P)"
    if [[ "$(git -C "$tree" rev-parse --show-toplevel 2>/dev/null)" == "$tree" ]]; then
        inputs=$(cd "$tree" && git ls-files -z -co --exclude-standard -- depends | xargs -0 -r sha256sum -- 2>/dev/null) || true
    else
        inputs="tree $tree"
    fi
    echo "${DEV_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/yacoin-dev}/container/$(printf '%s\n' "$inputs" | sha256sum | cut -c1-16)"
}

# The image's first line after its depends build (the entrypoints print it):
# from there on a run uses the cache only through ccache.
depends_done_line() {
    case "$1" in
        windows) echo "== Building yacoin ==" ;;
        macos) echo "== Building yacoin for macOS ==" ;;
        *) echo "== Generating the build system ==" ;;
    esac
}

# relay <fd> <line>: copies stdin to stdout; at <line> it releases the lock
# on <fd> (and so for the docker client, which shares that lock) and copies
# the rest unread, byte for byte. A last line without a newline is copied
# too.
relay() {
    local line
    while IFS= read -r line; do
        printf '%s\n' "$line"
        if [[ "$line" == "$2" ]]; then flock -u "$1"; exec cat; fi
    done
    printf '%s' "$line"
}

# Globals, not locals of main: the EXIT trap reads them after main is gone.
src="" cache="" no_cache=0 name="" image="" owner="" cidfile="" cpus=""

# True if root in a container is the calling user on the host (rootless
# Docker, Podman): then the files the container writes already belong to the
# caller, and a chown would hand them to a subordinate uid instead.
container_root_is_caller() {
    local out
    # Captured first: grep -q at the end of a pipe may exit before the command
    # has written everything, which pipefail turns into a no.
    out=$(docker --version 2>/dev/null) || out=""
    grep -qi podman <<< "$out" && return 0
    out=$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null) || out=""
    grep -q rootless <<< "$out"
}

# On any exit, including Ctrl-C: remove the container this run started
# (docker run may be killed without stopping it), by the id docker wrote to
# the cidfile, so a container of another run is never touched. Then give the
# root-owned files back.
cleanup() {
    local status=$?
    if [[ -s "$cidfile" ]]; then docker rm -f "$(cat "$cidfile")" >/dev/null 2>&1 || true; fi
    rm -f "$cidfile"
    if [[ -n "$owner" && "$owner" != 0:0 ]] && ! container_root_is_caller; then
        local mounts=(-v "$src:/src") dirs=(/src)
        [[ $no_cache -eq 1 ]] || { mounts+=(-v "$cache:/cache"); dirs+=(/cache); }
        docker run --rm "${mounts[@]}" --entrypoint chown "$LOCAL_REPO:$image" -R "$owner" "${dirs[@]}" || true
    fi
    return "$status"
}

main() {
    local image_build=1
    src="$ROOT"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --src) src="$2"; shift 2 ;;
            --cache) cache="$2"; shift 2 ;;
            --no-cache) no_cache=1; shift ;;
            --name) name="$2"; shift 2 ;;
            --cpus) [[ -n "${2:-}" ]] || { echo "--cpus needs a value" >&2; exit 2; }; cpus="$2"; shift 2 ;;
            --no-image-build) image_build=0; shift ;;
            --print-tag)
                [[ -n "${2:-}" && -f "$HERE/Dockerfile.$2" ]] || { echo "unknown image '${2:-}'" >&2; exit 2; }
                echo "$LOCAL_REPO:$2"; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            -*) echo "unknown option '$1'" >&2; usage >&2; exit 2 ;;
            *) break ;;
        esac
    done
    [[ $# -ge 1 && $# -le 2 ]] || { usage >&2; exit 2; }
    image="$1"
    local mode="${2:-build}"
    [[ -f "$HERE/Dockerfile.$image" ]] || { echo "unknown image '$image'" >&2; usage >&2; exit 2; }
    local args=()
    case "$image" in
        windows|macos)
            # The cross images take no arguments and only do the release build.
            [[ "$mode" == build ]] || { echo "the $image image only has the build mode" >&2; exit 2; } ;;
        *) args=("$mode") ;;
    esac
    command -v docker >/dev/null 2>&1 ||
        { echo "docker is not installed or not on PATH; see doc/developer-build.md" >&2; exit 1; }
    src="$(cd "$src" && pwd)"
    [[ $no_cache -eq 1 || -n "$cache" ]] || cache="$(default_cache "$src")"
    # Unique per run, so two trees (or two runs) never share a name.
    name="${name:-yacoin-build-$image-$mode-$(printf '%s' "$src" | cksum | cut -d' ' -f1)-$$}"

    if (( image_build )); then
        build_image "$image"
    elif ! docker image inspect "$LOCAL_REPO:$image" >/dev/null 2>&1; then
        echo "There is no local image $LOCAL_REPO:$image; run without --no-image-build to build it." >&2
        exit 1
    fi

    mkdir -p "${TMPDIR:-/tmp}"
    cidfile="$(mktemp -u "${TMPDIR:-/tmp}/yacoin-build-cid.XXXXXX")"
    local run=(docker run --rm --init --name "$name" --cidfile "$cidfile" -v "$src:/src") lock=""
    [[ -z "$cpus" ]] || run+=(--cpus "$cpus")
    if [[ $no_cache -eq 0 ]]; then
        mkdir -p "$cache"
        cache="$(cd "$cache" && pwd -P)"
        run+=(-v "$cache:/cache")
        echo "Cache: $cache" >&2
        # Two depends builds on one cache would remove each other's cached
        # packages: one run at a time holds the lock until its depends build
        # is done (relay).
        exec {lock}>> "$cache/run.lock"
        flock -n "$lock" || { echo "Waiting for another container's depends build on $cache" >&2; flock "$lock"; }
    fi
    # The ThreadSanitizer mode turns address randomisation off (setarch -R,
    # see entrypoint.sh), which Docker's default seccomp filter refuses. As
    # in CI the sanitizer modes build without ccache: their objects never
    # match the cached ones and would only evict them.
    [[ "$mode" != unit-tests-tsan ]] || run+=(--security-opt seccomp=unconfined)
    case "$mode" in unit-tests-asan|unit-tests-tsan|fuzz-corpus|functional-tests-asan) run+=(-e CCACHE_DISABLE=1) ;; esac
    local v
    for v in JOBS FTEST_JOBS FTEST_SHARD SANITIZE BUILDVERSION CCACHE_MAXSIZE CCACHE_COMPRESS; do
        [[ -z "${!v:-}" ]] || run+=(-e "$v")
    done

    owner="$(id -u):$(id -g)"
    trap cleanup EXIT
    # ${args[@]+...}: an empty array is "unbound" under set -u in bash < 4.4.
    if [[ -z "$lock" ]]; then
        "${run[@]}" "$LOCAL_REPO:$image" ${args[@]+"${args[@]}"}
    else
        local status
        set +e
        "${run[@]}" "$LOCAL_REPO:$image" ${args[@]+"${args[@]}"} | relay "$lock" "$(depends_done_line "$image")"
        status="${PIPESTATUS[0]}"
        set -e
        return "$status"
    fi
}

# Only run when executed, so that other scripts can source build_image.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
