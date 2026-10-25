#!/usr/bin/env bash
# Prints the tag of a yacoin-build image: <repo>:<image>-<hash>, where <hash>
# is computed from every file that goes into the image: its Dockerfile and
# each file the Dockerfile COPYs or ADDs from this directory (the build
# context). The same files always give the same tag; a change to any of them
# gives a new one. CI runs and publishes the images under these tags.
#
# Usage: ci/containers/image-tag.sh [--repo REPO] <image>
#        ci/containers/image-tag.sh --inputs <image>
#
#   --repo REPO  repository part of the tag (default ghcr.io/dev34253/yacoin-build)
#   --inputs     print the files the hash is computed from instead, one per
#                line, relative to this directory: Dockerfile.<image> first,
#                then the copied files sorted
#
# <hash>: the first 12 hex digits of the SHA-256 of one line per input, in
# the order --inputs prints them: its mode as git records it (100755 or
# 100644), and its "sha256sum" line (hash and name).
# COPY and ADD sources must be plain file names in this directory; globs,
# URLs, directories, --from, heredocs, the JSON form and the escape directive
# are rejected, so that no input can be missed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO=ghcr.io/dev34253/yacoin-build

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '8,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }

sha256() {
    if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# The inputs of an image, see --inputs.
image_inputs() {
    local df="Dockerfile.$1" line kw n prev_continues=0 continues src
    local -a words sources=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        # The escape directive would change the continuation character.
        [[ ! "$line" =~ ^[[:space:]]*#[[:space:]]*escape[[:space:]]*= ]] ||
            die "$df: the escape parser directive is not supported: $line"
        # Comment lines and empty lines are dropped before continuations are
        # joined: they never continue an instruction, and inside a continued
        # instruction they do not end it.
        [[ ! "$line" =~ ^[[:space:]]*(#|$) ]] || continue
        # A line ending in a backslash continues the instruction on the next.
        continues=0; [[ "$line" =~ \\[[:space:]]*$ ]] && continues=1
        if (( prev_continues )); then prev_continues=$continues; continue; fi
        prev_continues=$continues
        read -r -a words <<< "$line"
        (( ${#words[@]} > 0 )) || continue
        kw="${words[0]^^}"
        [[ "$kw" == COPY || "$kw" == ADD ]] || continue
        (( ! continues )) || die "$df: $kw over several lines is not supported: $line"
        words=("${words[@]:1}")
        while (( ${#words[@]} > 0 )) && [[ "${words[0]}" == --* ]]; do
            [[ "${words[0]}" != --from=* ]] || die "$df: $kw --from is not supported: $line"
            words=("${words[@]:1}")
        done
        n=${#words[@]}
        (( n >= 2 )) || die "$df: $kw needs a source and a destination: $line"
        [[ "${words[0]}" != \[* ]] || die "$df: the JSON form of $kw is not supported: $line"
        for src in "${words[@]:0:n-1}"; do
            case "$src" in
                *'<<'*) die "$df: heredocs are not supported: $line" ;;
                *://*) die "$df: $kw from a URL is not supported: $line" ;;
                *[*?[]*) die "$df: globs are not supported: $line" ;;
                /*|..|../*|*/..|*/../*) die "$df: $src is outside the build context: $line" ;;
            esac
            [[ -f "$HERE/$src" ]] || die "$df: $src is not a file in $HERE: $line"
            sources+=("$src")
        done
    done < "$HERE/$df"
    echo "$df"
    (( ${#sources[@]} == 0 )) || printf '%s\n' "${sources[@]}" | LC_ALL=C sort -u
}

main() {
    local list=0 image hash
    local -a inputs
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --repo) [[ $# -ge 2 ]] || usage; REPO="$2"; shift 2 ;;
            --inputs) list=1; shift ;;
            -h|--help) usage ;;
            -*) echo "unknown option '$1'" >&2; usage ;;
            *) break ;;
        esac
    done
    [[ $# -eq 1 ]] || usage
    image="$1"
    [[ "$image" =~ ^[A-Za-z0-9._-]+$ && -f "$HERE/Dockerfile.$image" ]] ||
        { echo "unknown image '$image'" >&2; exit 2; }
    # Not "mapfile < <(...)": a failure there would not stop the script.
    local out
    out=$(image_inputs "$image")
    mapfile -t inputs <<< "$out"
    if (( list )); then printf '%s\n' "${inputs[@]}"; return; fi
    # One line per input: its mode as git records it (100755 if executable,
    # else 100644; not the bits a umask changes), its SHA-256 and its name.
    local f mode lines=""
    for f in "${inputs[@]}"; do
        mode=100644; [[ ! -x "$HERE/$f" ]] || mode=100755
        lines+="$mode $(cd "$HERE" && sha256 -- "$f")"$'\n'
    done
    hash=$(printf '%s' "$lines" | sha256 | cut -c1-12)
    echo "$REPO:$image-$hash"
}

main "$@"
