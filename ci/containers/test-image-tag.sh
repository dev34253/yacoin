#!/usr/bin/env bash
# Tests of image-tag.sh and of the CI workflow's use of its tags. Quick, no
# Docker needed.
#
# Usage: ci/containers/test-image-tag.sh
#
#   - the same files give the same tag, from any directory and locale;
#   - the inputs of each image are its Dockerfile and every file it COPYs or
#     ADDs (parsed here independently of image-tag.sh), and nothing else;
#   - changing any input changes the tag, changing any other file does not;
#   - what image-tag.sh cannot hash (globs, URLs, --from, missing files,
#     directories, line continuations, heredocs) is an error, not a wrong tag;
#   - every docker run in .github/workflows/ runs an image tagged by
#     image-tag.sh, for an image defined here, and the workflow leaves the
#     ccache config to the entrypoints.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TAG="$HERE/image-tag.sh"

failures=()
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures+=("$*"); }
check() { local what="$1"; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }

work="$(mktemp -d "${TMPDIR:-/tmp}/yacoin-tag-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

mapfile -t images < <(cd "$HERE" && ls Dockerfile.* | sed 's/^Dockerfile\.//')
(( ${#images[@]} > 0 )) || { echo "no Dockerfiles in $HERE" >&2; exit 1; }

# The files a Dockerfile COPYs or ADDs, parsed here without image-tag.sh: the
# words of each COPY/ADD instruction without its options and its destination.
copied_files() {
    awk 'toupper($1) == "COPY" || toupper($1) == "ADD" {
             for (i = 2; i < NF; i++) if ($i !~ /^--/) print $i
         }' "$1" | LC_ALL=C sort -u
}

# tag_of <dir> <image>: the tag computed by a copy of image-tag.sh in <dir>.
tag_of() { "$1/image-tag.sh" "$2"; }

echo "== image-tag.sh on the images here =="
for image in "${images[@]}"; do
    if ! t1=$("$TAG" "$image"); then fail "$image: image-tag.sh failed"; continue; fi
    t2=$(cd / && LC_ALL=C "$TAG" "$image")
    t3=$(cd "$work" && LC_ALL=en_US.UTF-8 "$TAG" "$image" 2>/dev/null)
    check "$image: same tag on every run, from any directory and locale ($t1)" \
        test "$t1" = "$t2" -a "$t1" = "$t3"
    check "$image: tag is ghcr.io/dev34253/yacoin-build:$image-<12 hex digits>" \
        grep -qxE "ghcr\.io/dev34253/yacoin-build:${image//./\\.}-[0-9a-f]{12}" <<< "$t1"
    t4=$("$TAG" --repo registry.example/owner/name "$image")
    check "$image: --repo changes only the repository" test "$t4" = "registry.example/owner/name:${t1#*:}"

    mapfile -t inputs < <("$TAG" --inputs "$image")
    check "$image: the first input is Dockerfile.$image" test "${inputs[0]:-}" = "Dockerfile.$image"
    want=("Dockerfile.$image")
    mapfile -t -O 1 want < <(copied_files "$HERE/Dockerfile.$image")
    check "$image: the inputs are the Dockerfile and its COPY/ADD sources (${want[*]})" \
        test "${inputs[*]}" = "${want[*]}"
    (( ${#want[@]} > 1 )) || fail "$image: the Dockerfile copies no file (the parse above found nothing)"
done

echo "== changing a file =="
mutable="$work/containers"
cp -a "$HERE" "$mutable"
declare -A before
for image in "${images[@]}"; do before[$image]=$(tag_of "$mutable" "$image"); done
# Every file here: an input of some images, or of none.
mapfile -t files < <(cd "$HERE" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
for f in "${files[@]}"; do
    [[ "$f" != image-tag.sh ]] || continue
    cp -a "$mutable/$f" "$work/saved"
    printf '\n' >> "$mutable/$f"
    for image in "${images[@]}"; do
        after=$(tag_of "$mutable" "$image")
        if "$TAG" --inputs "$image" | grep -qxF "$f"; then
            check "$image: changing its input $f changes the tag" test "$after" != "${before[$image]}"
        else
            check "$image: changing $f (not an input) keeps the tag" test "$after" = "${before[$image]}"
        fi
    done
    cp -a "$work/saved" "$mutable/$f"
done
# A change of content only, size unchanged, is seen too.
image=${images[0]}
sed -i '1s/^./X/' "$mutable/Dockerfile.$image"
check "$image: an edit that keeps the size changes the tag" test "$(tag_of "$mutable" "$image")" != "${before[$image]}"

echo "== Dockerfiles image-tag.sh must parse or reject =="
synth="$work/synth"
mkdir -p "$synth/sub"
cp "$HERE/image-tag.sh" "$synth/"
printf 'a\n' > "$synth/a.sh"; printf 'b\n' > "$synth/b.sh"; printf 'c\n' > "$synth/c.txt"; printf 'd\n' > "$synth/sub/d"
cat > "$synth/Dockerfile.multi" <<'EOF'
FROM scratch
# COPY not-a-file.sh /x
RUN echo one && \
    echo copy two
copy --chmod=755 b.sh a.sh /opt/
  ADD --chown=0:0 c.txt /c.txt
COPY sub/d /d
COPY a.sh /again
EOF
check "multi: options, lower case, indentation, comments, RUN continuations and duplicates" \
    test "$("$synth/image-tag.sh" --inputs multi | tr '\n' ' ')" = "Dockerfile.multi a.sh b.sh c.txt sub/d "
reject() {
    local name="$1" line="$2" status=0
    printf 'FROM scratch\n%s\n' "$line" > "$synth/Dockerfile.$name"
    "$synth/image-tag.sh" "$name" > "$work/out" 2>&1 || status=$?
    check "rejected ($name): $line" test "$status" = 1
    grep -q 'error: ' "$work/out" || fail "$name: no 'error: ' message"
}
reject glob 'COPY *.sh /x/'
reject url 'ADD https://example.org/f /f'
reject from 'COPY --from=builder /x /x'
reject missing 'COPY nosuch.sh /x'
reject directory 'COPY sub /sub'
reject outside 'COPY ../x /x'
reject absolute 'COPY /etc/passwd /x'
reject continuation 'COPY a.sh \'
reject heredoc 'COPY <<EOF /x'
reject json 'COPY ["a.sh", "/x"]'
reject nodest 'COPY a.sh'
status=0; "$TAG" no-such-image > /dev/null 2>&1 || status=$?
check "an unknown image exits with status 2" test "$status" = 2
status=0; "$TAG" > /dev/null 2>&1 || status=$?
check "no image exits with status 2" test "$status" = 2

echo "== the workflow uses the tags =="
for wf in "$ROOT"/.github/workflows/*.yml; do
    name=${wf#"$ROOT"/}
    # Shell lines joined across their backslash continuations.
    joined=$(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$wf")
    # Commands, not comments that mention docker run.
    runs=$(grep -cE '^[[:space:]]*docker run ' <<< "$joined" || true)
    tagged=$(grep -E '^[[:space:]]*docker run ' <<< "$joined" | grep -c '"\$IMAGE_TAG"' || true)
    check "$name: all $runs docker runs run \"\$IMAGE_TAG\"" test "$runs" = "$tagged"
    check "$name: no image named directly (yacoin-build:<tag>)" \
        bash -c '! grep -nE "yacoin-build:[A-Za-z0-9\$]" "$1"' _ "$wf"
    while read -r image; do
        check "$name: IMAGE $image is defined here (Dockerfile.$image)" test -f "$HERE/Dockerfile.$image"
    done < <(sed -n 's/^ *IMAGE: *//p' "$wf" | LC_ALL=C sort -u)
    check "$name: leaves the ccache config to the entrypoints" bash -c '! grep -n "ccache\.conf" "$1"' _ "$wf"
done
action="$ROOT/.github/actions/yacoin-build-image/action.yml"
check "the image action computes the tag with image-tag.sh" grep -q 'ci/containers/image-tag.sh' "$action"
for wf in "$ROOT"/.github/workflows/*.yml; do
    jobs=$(grep -cE '^[[:space:]]*docker run ' "$wf" || true)
    steps=$(grep -c 'uses: ./.github/actions/yacoin-build-image' "$wf" || true)
    check "${wf#"$ROOT"/}: one image step per job that runs docker ($steps for $jobs)" test "$jobs" = "$steps"
done

echo "== ${#failures[@]} failure(s) =="
if (( ${#failures[@]} )); then printf '  %s\n' "${failures[@]}"; exit 1; fi
