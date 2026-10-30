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
          functional-tests, cov-unit, cov-functional
          windows, macos: build (the only mode)

Options:
  --src DIR         source tree mounted at /src (default: $ROOT)
  --cache DIR       cache mounted at /cache (default: <src>/.devbuild/container-cache)
  --no-cache        mount no cache
  --name NAME       container name (default: yacoin-build-<image>-<mode>-<id>,
                    unique per run)
  --no-image-build  run the existing local image instead of building it first

The image is tagged $LOCAL_REPO:<image>. JOBS, BUILDVERSION, CCACHE_MAXSIZE
and CCACHE_COMPRESS are passed to the container if set. The container runs as
root, as in CI; afterwards the files it wrote are given back to the caller
(not needed and not done with rootless Docker or Podman, where container root
already is the caller).
EOF
}

# Shared with parity.sh and check.sh.
LOCAL_REPO="${LOCAL_REPO:-yacoin-build-local}"
LOCAL_LABEL=org.yacoin.build-local=1

build_image() {
    local image="$1"
    [[ -f "$HERE/Dockerfile.$image" ]] || { echo "unknown image '$image'" >&2; exit 2; }
    docker build --label "$LOCAL_LABEL" -f "$HERE/Dockerfile.$image" -t "$LOCAL_REPO:$image" "$HERE"
}

# Globals, not locals of main: the EXIT trap reads them after main is gone.
src="" cache="" no_cache=0 name="" image="" owner="" cidfile=""

# True if root in a container is the calling user on the host (rootless
# Docker, Podman): then the files the container writes already belong to the
# caller, and a chown would hand them to a subordinate uid instead.
container_root_is_caller() {
    docker --version 2>/dev/null | grep -qi podman && return 0
    docker info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -q rootless
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
            --no-image-build) image_build=0; shift ;;
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
    [[ $no_cache -eq 1 || -n "$cache" ]] || cache="$src/.devbuild/container-cache"
    # Unique per run, so two trees (or two runs) never share a name.
    name="${name:-yacoin-build-$image-$mode-$(printf '%s' "$src" | cksum | cut -d' ' -f1)-$$}"

    (( image_build == 0 )) || build_image "$image"

    mkdir -p "${TMPDIR:-/tmp}"
    cidfile="$(mktemp -u "${TMPDIR:-/tmp}/yacoin-build-cid.XXXXXX")"
    local run=(docker run --rm --init --name "$name" --cidfile "$cidfile" -v "$src:/src")
    if [[ $no_cache -eq 0 ]]; then
        mkdir -p "$cache"
        cache="$(cd "$cache" && pwd)"
        run+=(-v "$cache:/cache")
    fi
    local v
    for v in JOBS BUILDVERSION CCACHE_MAXSIZE CCACHE_COMPRESS; do
        [[ -z "${!v:-}" ]] || run+=(-e "$v")
    done

    owner="$(id -u):$(id -g)"
    trap cleanup EXIT
    # ${args[@]+...}: an empty array is "unbound" under set -u in bash < 4.4.
    "${run[@]}" "$LOCAL_REPO:$image" ${args[@]+"${args[@]}"}
}

# Only run when executed, so that other scripts can source build_image.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
