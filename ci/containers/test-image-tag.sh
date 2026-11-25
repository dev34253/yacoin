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
#     ccache config to the entrypoints;
#   - only the docker runs of the unit-tests-tsan mode turn Docker's seccomp
#     filter off (the mode needs it, see entrypoint.sh), and they do;
#   - the sanitizer jobs run their modes (unit-tests-asan, unit-tests-tsan,
#     fuzz-corpus, functional-tests-asan), with ccache off; the warnings job
#     runs its mode with ccache on;
#   - unit-tests-asan runs one leg per sanitizer (SANITIZE),
#     functional-tests-asan and the coverage-functional-<n> jobs one shard
#     each (FTEST_SHARD), and coverage-report merges every shard;
#   - the caches: every save runs only on a push to master, with no run id
#     or attempt in its key; the jobs that save keep a depends entry
#     (<kind>-depends-<image tag>-<depends hash>, exact key only) and a
#     ccache entry (<kind>-ccache-<image tag>-<commit>), each saved under
#     the key its restore looked up and only without an exact hit; the build
#     jobs restore nothing on a tag push and, on a push to master, only look
#     up their keys (lookup-only), while no other job's cache step sets
#     lookup-only; build-ubuntu-1604-low-difficulty
#     uses the depends entry of build-ubuntu-1604; the sanitizer and coverage
#     jobs (fuzz-corpus, functional-tests-asan, unit-tests-asan,
#     unit-tests-tsan, coverage-unit, coverage-functional-<n>) restore the
#     functional-tests depends entry and save none; the warnings job
#     restores the functional-tests depends entry, saves none and keeps a
#     ccache entry of its own (warnings-ccache-<image tag>-<commit>, saved
#     only on a push to master without an exact hit); prune-caches runs only
#     on a push to master, runs no docker, needs every job that saves a cache
#     and is the one job with actions: write;
#   - all-jobs-passed.sh passes only when every needed job succeeded (and
#     prune-caches succeeded or, outside a push to master, was skipped), and
#     fails on any other result and on empty, malformed or missing input;
#   - the workflow's jobs are plain keys at two spaces under jobs:, the last
#     top-level key; the workflow holds no continue-on-error; all-jobs-passed
#     needs every other job, runs always and is written as expected. Planted
#     copies of the workflow, each with one change, must fail their named
#     check;
#   - the workflow has 18 jobs.
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
declare -A before inputs_of
for image in "${images[@]}"; do
    before[$image]=$(tag_of "$mutable" "$image")
    # Searched as a whole: grep -q at the end of a pipe may exit before
    # image-tag.sh has written everything, which pipefail turns into a no.
    inputs_of[$image]=$("$TAG" --inputs "$image")
done
# Every file here: an input of some images, or of none.
mapfile -t files < <(cd "$HERE" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
for f in "${files[@]}"; do
    [[ "$f" != image-tag.sh ]] || continue
    cp -a "$mutable/$f" "$work/saved"
    printf '\n' >> "$mutable/$f"
    for image in "${images[@]}"; do
        after=$(tag_of "$mutable" "$image")
        if grep -qxF "$f" <<< "${inputs_of[$image]}"; then
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
cp -a "$HERE/Dockerfile.$image" "$mutable/Dockerfile.$image"
# The file mode as git records it (executable or not) is hashed; the bits a
# umask changes are not, so a checkout gives the same tag everywhere.
entry=$("$TAG" --inputs "$image" | sed -n 2p)
cp -a "$mutable/$entry" "$work/saved"
if [[ -x "$mutable/$entry" ]]; then chmod a-x "$mutable/$entry"; else chmod a+x "$mutable/$entry"; fi
check "$image: switching the executable bit of its input $entry changes the tag" \
    test "$(tag_of "$mutable" "$image")" != "${before[$image]}"
cp -a "$work/saved" "$mutable/$entry"; chmod g+w,o+w "$mutable/$entry"
check "$image: group and other write bits on $entry keep the tag" \
    test "$(tag_of "$mutable" "$image")" = "${before[$image]}"
cp -a "$work/saved" "$mutable/$entry"

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
# A comment never continues onto the next line, even if it ends in a
# backslash; inside a continued instruction a comment line is dropped and the
# instruction goes on (as docker build parses it).
cat > "$synth/Dockerfile.comments" <<'END'
FROM scratch
# a comment that ends in a backslash \
COPY a.sh /a
RUN echo one \
# a comment inside the RUN \

  COPY nosuch.sh /not-a-copy
  # indented comment \
COPY b.sh /b
END
check "comments: a comment ending in a backslash does not hide the next COPY" \
    test "$("$synth/image-tag.sh" --inputs comments 2>&1 | tr '\n' ' ')" = "Dockerfile.comments a.sh b.sh "
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
reject escape '# escape=`'
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
    n=0
    while read -r run; do
        n=$((n + 1)); container="docker run $n"
        [[ ! "$run" =~ --name[[:space:]]+([^[:space:]]+) ]] || container=${BASH_REMATCH[1]}
        if [[ "$run" =~ \"\$IMAGE_TAG\"[[:space:]]+unit-tests-tsan[[:space:]]*$ ]]; then
            check "$name: $container (unit-tests-tsan) turns the seccomp filter off" \
                test "${run/ --security-opt seccomp=unconfined /}" != "$run"
        else
            check "$name: $container keeps the seccomp filter" test "${run/seccomp/}" = "$run"
        fi
        if [[ "$run" =~ \"\$IMAGE_TAG\"[[:space:]]+(unit-tests-asan|unit-tests-tsan|fuzz-corpus|functional-tests-asan)[[:space:]]*$ ]]; then
            check "$name: $container (${BASH_REMATCH[1]}) runs with ccache off" \
                test "${run/ -e CCACHE_DISABLE=1 /}" != "$run"
        fi
        if [[ "$run" =~ \"\$IMAGE_TAG\"[[:space:]]+warnings[[:space:]]*$ ]]; then
            check "$name: $container (warnings) runs with ccache on" test "${run/CCACHE_DISABLE/}" = "$run"
        fi
    done < <(grep -E '^[[:space:]]*docker run ' <<< "$joined" || true)
done
# The sanitizer jobs run their modes.
wf="$ROOT/.github/workflows/yacoinbuildmultiplatform.yml"
joined=$(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$wf")
for mode in unit-tests-asan unit-tests-tsan fuzz-corpus functional-tests-asan warnings; do
    check "${wf#"$ROOT"/}: a docker run of the $mode mode" \
        grep -qE '^[[:space:]]*docker run .*"\$IMAGE_TAG"[[:space:]]+'"$mode"'[[:space:]]*$' <<< "$joined"
done
# job_text_of <workflow> <job>: the text of a job, from its name to the next job.
job_text_of() { awk -v name="  $2:" '$0 == name { on = 1; print; next } on && /^  [A-Za-z0-9_-]+:$/ { exit } on' "$1"; }
job_text() { job_text_of "$wf" "$1"; }
# passes_var <var> <mode> <job text>: the job's docker run of <mode>, joined
# across its continuation lines, passes <var> to the container (-e <var>).
passes_var() {
    local joined_job
    joined_job=$(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' <<< "$3")
    grep -qE '^[[:space:]]*docker run .* -e '"$1"'( | .* )"\$IMAGE_TAG"[[:space:]]+'"$2"'[[:space:]]*$' <<< "$joined_job"
}
# unit-tests-asan: a leg per sanitizer, which the mode gets as SANITIZE.
job=$(job_text unit-tests-asan)
check "${wf#"$ROOT"/}: unit-tests-asan has the legs address and undefined" \
    grep -qx ' *sanitize: \[address, undefined\]' <<< "$job"
check "${wf#"$ROOT"/}: unit-tests-asan passes the leg's SANITIZE" \
    grep -qx ' *SANITIZE: \${{ matrix.sanitize }}' <<< "$job"
check "${wf#"$ROOT"/}: unit-tests-asan passes SANITIZE to the container" passes_var SANITIZE unit-tests-asan "$job"
# functional-tests-asan: shard K of the legs' number, as FTEST_SHARD.
job=$(job_text functional-tests-asan)
check "${wf#"$ROOT"/}: functional-tests-asan has a leg per shard" grep -qx ' *shard: \[1, 2\]' <<< "$job"
check "${wf#"$ROOT"/}: functional-tests-asan passes the leg's FTEST_SHARD" \
    grep -qx ' *FTEST_SHARD: \${{ matrix.shard }}/\${{ strategy.job-total }}' <<< "$job"
check "${wf#"$ROOT"/}: functional-tests-asan passes FTEST_SHARD to the container" \
    passes_var FTEST_SHARD functional-tests-asan "$job"
# coverage-functional-<k>: shard k of 2, each with its own artifact; the
# report needs and merges both.
for k in 1 2; do
    job=$(job_text "coverage-functional-$k")
    check "${wf#"$ROOT"/}: coverage-functional-$k runs shard $k/2" grep -qx " *FTEST_SHARD: $k/2" <<< "$job"
    check "${wf#"$ROOT"/}: coverage-functional-$k passes FTEST_SHARD to the container" \
        passes_var FTEST_SHARD cov-functional "$job"
    check "${wf#"$ROOT"/}: coverage-functional-$k names its artifact per shard and attempt" \
        grep -qx " *COVERAGE_ARTIFACT: coverage-functional-$k-\\\${{ github.run_attempt }}" <<< "$job"
done
job=$(job_text coverage-report)
check "${wf#"$ROOT"/}: coverage-report needs the unit job and both shards" \
    grep -qx ' *needs: \[coverage-unit, coverage-functional-1, coverage-functional-2\]' <<< "$job"
for k in 1 2; do
    check "${wf#"$ROOT"/}: coverage-report merges shard $k" grep -q "coverage/functional-$k/functional_test_coverage.info" <<< "$job"
    check "${wf#"$ROOT"/}: coverage-report checks the functions of shard $k" \
        grep -q "coverage/functional-$k/functional_test_functions.json" <<< "$job"
done

echo "== all-jobs-passed.sh =="
passed="$HERE/all-jobs-passed.sh"
check "all-jobs-passed.sh: jq is installed (the script needs it)" test -n "$(command -v jq)"
# needs_json <job>=<result>...: the needs context of these jobs as toJSON(needs) gives it.
needs_json() {
    local kv sep="" out="{"
    for kv in "$@"; do out+="$sep\"${kv%%=*}\": {\"result\": \"${kv#*=}\", \"outputs\": {}}"; sep=", "; done
    echo "$out}"
}
# verdict <exit code> <case> <MASTER_PUSH> <NEEDS_JSON> [<line>]: the script
# exits with <exit code> for these inputs (- leaves a variable unset) and
# prints <line>; a failure prints an ::error:: line. The output stays in out.
verdict() {
    local code="$1" what="$2" master="$3" needs="$4" line="${5:-}" status=0
    local cmd=(env -i PATH="$PATH")
    [[ "$master" == - ]] || cmd+=(MASTER_PUSH="$master")
    [[ "$needs" == - ]] || cmd+=(NEEDS_JSON="$needs")
    out=$("${cmd[@]}" "$passed" 2>&1) || status=$?
    check "all-jobs-passed.sh: $what: exit $code" test "$status" = "$code"
    if [[ -n "$line" ]]; then check "all-jobs-passed.sh: $what: prints '$line'" grep -qxF "$line" <<< "$out"; fi
    if [[ "$code" != 0 ]]; then check "all-jobs-passed.sh: $what: prints an error" grep -q '^::error::' <<< "$out"; fi
}
# input_error <case> <MASTER_PUSH> <NEEDS_JSON> <text>: the script exits 1
# for these inputs with an ::error:: line that holds <text>.
input_error() {
    verdict 1 "$1" "$2" "$3"
    check "all-jobs-passed.sh: $1: the error says '$4'" \
        awk -v t="$4" 'index($0, "::error::") == 1 && index($0, t) { f = 1 } END { exit !f }' <<< "$out"
}
all_ok=$(needs_json job-a=success job-b=success prune-caches=success)
verdict 0 "every job success" false "$all_ok" "3 of 3 needed jobs passed"
verdict 0 "every job success, push to master" true "$all_ok" "ok   job-b: success"
verdict 0 "every job success, multi-line JSON" false \
    $'{\n  "job-a": {\n    "result": "success",\n    "outputs": {}\n  },\n  "job-b": {\n    "result": "success",\n    "outputs": {}\n  }\n}' \
    "2 of 2 needed jobs passed"
verdict 1 "one job failure" false "$(needs_json job-a=success job-b=failure prune-caches=success)" "FAIL job-b: failure"
verdict 1 "one job failure, named in the error" false "$(needs_json job-a=success job-b=failure prune-caches=success)" \
    "::error::1 of 3 needed jobs did not pass: job-b"
verdict 1 "one job cancelled" false "$(needs_json job-a=success job-b=cancelled prune-caches=success)" "FAIL job-b: cancelled"
verdict 1 "one job skipped" false "$(needs_json job-a=success job-b=skipped prune-caches=success)" "FAIL job-b: skipped"
verdict 0 "prune-caches skipped, not a push to master" false "$(needs_json job-a=success job-b=success prune-caches=skipped)" \
    "ok   prune-caches: skipped (not a push to master)"
verdict 1 "prune-caches skipped, push to master" true "$(needs_json job-a=success job-b=success prune-caches=skipped)" \
    "FAIL prune-caches: skipped"
verdict 1 "prune-caches failure" false "$(needs_json job-a=success job-b=success prune-caches=failure)" \
    "FAIL prune-caches: failure"
verdict 1 "prune-caches cancelled" false "$(needs_json job-a=success prune-caches=cancelled)" "FAIL prune-caches: cancelled"
verdict 0 "matrix job success" false "$(needs_json job-a=success matrix-job=success)" "ok   matrix-job: success"
verdict 1 "matrix job failure" false "$(needs_json job-a=success matrix-job=failure)" "FAIL matrix-job: failure"
verdict 1 "unknown result" false "$(needs_json job-a=success job-b=nosuchresult)" "FAIL job-b: nosuchresult"
verdict 1 "two jobs not passed" false "$(needs_json job-a=failure job-b=cancelled)" \
    "::error::2 of 2 needed jobs did not pass: job-a, job-b"
object="not one non-empty JSON object"
no_result="no result for a needed job"
input_error "empty object" false '{}' "$object"
input_error "empty array" false '[]' "$object"
verdict 1 "malformed JSON" false '{"job-a": {"result": "success"'
verdict 1 "not JSON" false 'not json'
input_error "two objects" false "$(needs_json job-a=success) $(needs_json job-b=success)" "$object"
input_error "a job without result" false '{"job-a": {"outputs": {}}}' "$no_result"
input_error "a null result" false '{"job-a": {"result": null, "outputs": {}}}' "$no_result"
input_error "a job that is not an object" false '{"job-a": "success"}' "$no_result"
input_error "a result with a line break" false '{"job-a": {"result": "success\nFAIL", "outputs": {}}}' "$no_result"
input_error "a last result ending in a line break" false \
    '{"job-a": {"result": "success", "outputs": {}}, "job-b": {"result": "success\n", "outputs": {}}}' "$no_result"
input_error "a job id with a space" false '{"job a": {"result": "success", "outputs": {}}}' "$no_result"
input_error "a job id ending in a line break" false '{"job-a\n": {"result": "success", "outputs": {}}}' "$no_result"
input_error "NEEDS_JSON empty" false '' "NEEDS_JSON is empty or unset"
input_error "NEEDS_JSON unset" false - "NEEDS_JSON is empty or unset"
input_error "MASTER_PUSH unset" - "$all_ok" "not true or false"
input_error "MASTER_PUSH not true or false" yes "$all_ok" "not true or false"

echo "== the workflow's caches =="
# The cache steps of a workflow, read without a YAML parser from the layout
# the workflow is written in (jobs at two spaces, steps at "      - ", their
# keys at eight, the keys under with: and env: at ten). One tab-separated
# line per fact:
#   J <job> env <name> <value>     a variable of the job's env:
#   J <job> if <condition>         the job's if:
#   J <job> needs <job>            a job in the job's needs: (a flow list
#                                  [a, b], a single job or a block list)
#   J <job> perm <line>            a line of the job's permissions:
#   W perm <line>                  a line of the workflow's permissions:
#   C <job> <n> <field> <value>    the n-th actions/cache step of the job:
#                                  uses, id, if, keyraw, key, path, rkey,
#                                  lookup (its lookup-only input, as written)
# key, path and rkey (the restore-keys) are resolved as the runner would:
# ${{ env.V }} from the job's env: and the $GITHUB_ENV lines of earlier
# steps; ${{ steps.<id>.outputs.cache-primary-key }} as the key of that
# step; ${{ steps.<id>.outputs.tag }} of the image action as <tag:IMAGE>,
# IMAGE being the action's resolved image input; in a run: block, $V from a
# shell assignment earlier in the block, the step's env:, the job's env: or
# the $GITHUB_ENV lines of earlier steps (a $GITHUB_ENV line sets nothing
# for the rest of its own block). ${V##*:} of <tag:IMAGE> gives <tagid:IMAGE>
# (the image-<hash> part of the tag). $GITHUB_* and $RUNNER_* stay as they
# are, other ${{ }} expressions too; anything else that does not resolve
# becomes {unresolved:V}. A multi-line if: is {multiline}.
cache_records() {
    awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function indent_of(s) { match(s, /^ */); return RLENGTH }
    function keyname(s) { s = trim(s); sub(/:.*/, "", s); return s }
    function value(s,   k) { s = trim(s); k = keyname(s); return trim(substr(s, length(k) + 2)) }
    function expr(s,   out, i, j, e, v, name) {
        out = ""
        while ((i = index(s, "${{")) > 0) {
            out = out substr(s, 1, i - 1); s = substr(s, i)
            j = index(s, "}}")
            if (j == 0) break
            e = trim(substr(s, 4, j - 4)); v = substr(s, 1, j + 1); s = substr(s, j + 2)
            if (e ~ /^env\.[A-Za-z_][A-Za-z0-9_]*$/) {
                name = substr(e, 5)
                if (name in genv) v = genv[name]
                else if (name in jenv) v = expr(jenv[name])
                else v = "{unresolved:" e "}"
            } else if (e ~ /^steps\.[A-Za-z0-9_-]+\.outputs\.cache-primary-key$/) {
                name = e; sub(/^steps\./, "", name); sub(/\..*/, "", name)
                v = (name in key_of) ? key_of[name] : "{unresolved:" e "}"
            } else if (e ~ /^steps\.[A-Za-z0-9_-]+\.outputs\.tag$/) {
                name = e; sub(/^steps\./, "", name); sub(/\..*/, "", name)
                v = (name in tag_of) ? tag_of[name] : "{unresolved:" e "}"
            }
            out = out v
        }
        return out s
    }
    function cut_tag(v) {
        if (v ~ /^<tag:[^>]*>$/) return "<tagid:" substr(v, 6)
        if (v ~ /[<{$]/) return "{" v "##*:}"
        sub(/^.*:/, "", v); return v
    }
    function shell(s,   out, m, name, cut, v) {
        out = ""
        while (match(s, /\$(\{[A-Za-z_][A-Za-z0-9_]*(##\*:)?\}|[A-Za-z_][A-Za-z0-9_]*)/)) {
            out = out substr(s, 1, RSTART - 1)
            m = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
            name = m; sub(/^\$\{?/, "", name); sub(/\}$/, "", name)
            cut = sub(/##\*:$/, "", name)
            if (name in sh) v = sh[name]
            else if (name in senv) v = expr(senv[name])
            else if (name in jenv) v = expr(jenv[name])
            else if (name in genv) v = genv[name]
            else if (name ~ /^(GITHUB|RUNNER)_/) v = "$" name
            else v = "{unresolved:" name "}"
            out = out (cut ? cut_tag(v) : v)
        }
        return out s
    }
    function run_line(t,   name, v) {
        t = trim(t)
        if (t ~ /^echo "[A-Za-z_][A-Za-z0-9_]*=.*" >> "\$GITHUB_ENV"$/) {
            t = substr(t, 7); sub(/" >> "\$GITHUB_ENV"$/, "", t)
            name = t; sub(/=.*/, "", name)
            pend[name] = shell(substr(t, length(name) + 2))
        } else if (t ~ /^[A-Za-z_][A-Za-z0-9_]*=/) {
            name = t; sub(/=.*/, "", name)
            sh[name] = shell(substr(t, length(name) + 2))
        }
    }
    function out(f, v) { printf "C\t%s\t%d\t%s\t%s\n", job, n, f, v }
    function end_step(   i, k) {
        if (!instep) return
        if (uses ~ /yacoin-build-image$/ && sid != "") tag_of[sid] = "<tag:" expr(w["image"]) ">"
        if (uses ~ /^actions\/cache/) {
            n++
            out("uses", uses); out("id", sid); out("if", sif); out("keyraw", w["key"])
            k = expr(w["key"]); out("key", k)
            if (sid != "") key_of[sid] = k
            if ("path" in w) out("path", expr(w["path"]))
            for (i = 1; i <= npath; i++) out("path", expr(paths[i]))
            if ("restore-keys" in w) out("rkey", expr(w["restore-keys"]))
            for (i = 1; i <= nrkey; i++) out("rkey", expr(rkeys[i]))
            if ("lookup-only" in w) out("lookup", w["lookup-only"])
        }
        for (k in pend) genv[k] = pend[k]
        split("", pend); split("", sh); split("", senv); split("", w)
        npath = nrkey = 0; uses = sid = sif = ""; instep = 0
    }
    function new_job(name) {
        end_step()
        job = name; n = 0; jsec = ""
        split("", jenv); split("", genv); split("", key_of); split("", tag_of)
        printf "J\t%s\tname\t%s\n", job, job
    }
    /^jobs:[ ]*$/ { injobs = 1; next }
    !injobs {
        if ($0 ~ /^permissions:/) wperm = 1
        else if ($0 ~ /^[^ ]/) wperm = 0
        else if (wperm && trim($0) != "") printf "W\tperm\t%s\n", trim($0)
        next
    }
    /^  [A-Za-z0-9_-]+:[ ]*$/ { new_job(keyname($0)); next }
    {
        line = $0; ind = indent_of(line)
        if (blk != "") {
            if (trim(line) == "" || ind > blkind) {
                if (blk == "run") run_line(line)
                else if (blk == "path") paths[++npath] = trim(line)
                else if (blk == "restore-keys") rkeys[++nrkey] = trim(line)
                next
            }
            blk = ""
        }
        if (trim(line) == "" || trim(line) ~ /^#/) next
        if (ind == 4) {
            end_step()
            jsec = keyname(line)
            if (jsec == "if") printf "J\t%s\tif\t%s\n", job, value(line)
            if (jsec == "needs" && value(line) != "") {
                v = value(line)
                if (v ~ /^\[.*\]$/) v = substr(v, 2, length(v) - 2)
                nn = split(v, items, ",")
                for (i = 1; i <= nn; i++) printf "J\t%s\tneeds\t%s\n", job, trim(items[i])
            }
            next
        }
        if (jsec == "needs" && ind == 6 && trim(line) ~ /^- /) {
            printf "J\t%s\tneeds\t%s\n", job, trim(substr(trim(line), 3)); next
        }
        if (jsec == "env" && ind == 6) { jenv[keyname(line)] = value(line); printf "J\t%s\tenv\t%s\t%s\n", job, keyname(line), value(line); next }
        if (jsec == "permissions" && ind == 6) { printf "J\t%s\tperm\t%s\n", job, trim(line); next }
        if (jsec != "steps") next
        if (line ~ /^      - /) { end_step(); instep = 1; line = "        " substr(line, 9); ind = 8 }
        if (ind == 8) {
            k = keyname(line); v = value(line); ssec = k
            if (v ~ /^[|>]/) { blk = (k == "run") ? "run" : "other"; blkind = 8; if (k == "if") sif = "{multiline}"; next }
            if (k == "uses") uses = v
            else if (k == "id") sid = v
            else if (k == "if") sif = v
            else if (k == "run") run_line(v)
            next
        }
        if (ind == 10 && ssec == "with") {
            k = keyname(line); v = value(line)
            if (v ~ /^[|>]/) { blk = k; blkind = 10 } else w[k] = v
            next
        }
        if (ind == 10 && ssec == "env") { senv[keyname(line)] = value(line); next }
    }
    END { end_step() }
    ' "$1"
}

# The hashFiles call of the depends key: every depends build input.
depends_hash="\${{ hashFiles('depends/packages/*.mk', 'depends/patches/**', 'depends/Makefile', 'depends/funcs.mk', 'depends/hosts/*.mk', 'depends/builders/*.mk') }}"
# The event that saves caches.
master_push="github.event_name == 'push' && github.ref == 'refs/heads/master'"

# cache_checks <workflow>: the checks of the workflow's caches.
cache_checks() {
    local recs job n m i id ok key kind image dir want fs_key fs_paths saves combined restores savers needed
    local -A dkind=([build-ubuntu-1604]=release [build-ubuntu-1604-low-difficulty]=release [build-ubuntu-2204]=release
                    [build-windows]=release [build-macos]=release [unit-tests]=unit-tests [functional-tests]=functional-tests)
    local -A ckind=([build-ubuntu-1604]=release [build-ubuntu-1604-low-difficulty]=low-difficulty [build-ubuntu-2204]=release
                    [build-windows]=release [build-macos]=release [unit-tests]=unit-tests [functional-tests]=functional-tests)
    local build_jobs=(build-ubuntu-1604 build-ubuntu-1604-low-difficulty build-ubuntu-2204 build-windows build-macos)
    local restore_jobs=(fuzz-corpus functional-tests-asan unit-tests-asan unit-tests-tsan coverage-unit coverage-functional-1
                        coverage-functional-2)
    # Jobs that restore the functional-tests depends entry and keep a ccache
    # entry of their own kind, named after the job.
    local own_ccache_jobs=(warnings)
    recs=$(cache_records "$1")
    # field <job> <n> <field>: the values of a field of the job's n-th cache step.
    field() { awk -F'\t' -v j="$1" -v n="$2" -v f="$3" '$1 == "C" && $2 == j && $3 == n && $4 == f { print $5 }' <<< "$recs"; }
    # steps_of <job> <uses regex>: the numbers of the job's cache steps.
    steps_of() { awk -F'\t' -v j="$1" -v u="$2" '$1 == "C" && $2 == j && $4 == "uses" && $5 ~ u { print $3 }' <<< "$recs"; }
    # step_id <job> <id>: the number of the job's cache step with that id.
    step_id() { awk -F'\t' -v j="$1" -v i="$2" '$1 == "C" && $2 == j && $4 == "id" && $5 == i { print $3 }' <<< "$recs"; }
    # saves_of <job> <id>: the job's save steps that save the key of step <id>.
    saves_of() {
        awk -F'\t' -v j="$1" -v k="\${{ steps.$2.outputs.cache-primary-key }}" \
            '$1 == "C" && $2 == j && $4 == "keyraw" && $5 == k { print $3 }' <<< "$recs"
    }
    job_env() { awk -F'\t' -v j="$1" -v v="$2" '$1 == "J" && $2 == j && $3 == "env" && $4 == v { print $5 }' <<< "$recs"; }
    jobs_of() { awk -F'\t' '$1 == "J" && $3 == "name" { print $2 }' <<< "$recs"; }

    # Saves: only on a push to master, keys without the run.
    for job in $(jobs_of); do
        mapfile -t saves < <(steps_of "$job" '^actions/cache/save@')
        mapfile -t combined < <(steps_of "$job" '^actions/cache@')
        (( ${#saves[@]} + ${#combined[@]} )) || continue
        ok=1
        (( ${#combined[@]} == 0 )) || ok=0
        for n in "${saves[@]}"; do
            key=$(field "$job" "$n" keyraw)
            id=$(sed -n 's/^\${{ steps\.\([A-Za-z0-9_-]*\)\.outputs\.cache-primary-key }}$/\1/p' <<< "$key")
            want="\${{ success() && $master_push && steps.$id.outputs.cache-hit != 'true' }}"
            if [[ "$id" == ccache && ( "$job" == unit-tests || "$job" == functional-tests ) ]]; then
                [[ "$(field "$job" "$n" if)" == "$want" || "$(field "$job" "$n" if)" == "${want/success()/!cancelled()}" ]] || ok=0
            else
                [[ -n "$id" && "$(field "$job" "$n" if)" == "$want" ]] || ok=0
            fi
        done
        check "$job: the cache save runs only on a push to master" test "$ok" = 1
        ok=1
        for n in "${saves[@]}" "${combined[@]}"; do
            key=$(field "$job" "$n" key)
            [[ -n "$key" && ! "$key" =~ run_id|run_attempt|run_number|GITHUB_RUN_|\{unresolved ]] || ok=0
        done
        check "$job: the saved key holds no run id or attempt" test "$ok" = 1
    done

    # The jobs that save: a depends entry and a ccache entry, each saved
    # under the key its restore looked up, when that restore had no exact hit.
    for job in "${!dkind[@]}"; do
        image=$(job_env "$job" IMAGE)
        dir=depends-built; [[ "${dkind[$job]}" == release ]] || dir=depends-built-tests
        for id in depends ccache; do
            n=$(step_id "$job" "$id"); ok=1
            mapfile -t saves < <(saves_of "$job" "$id")
            if [[ -z "$n" || "$(field "$job" "$n" uses)" != actions/cache/restore@* || ${#saves[@]} != 1 ]]; then
                ok=0
            else
                [[ "$(field "$job" "${saves[0]}" if)" == *" && steps.$id.outputs.cache-hit != 'true' }}" ]] || ok=0
                [[ "$(field "$job" "${saves[0]}" path)" == "$(field "$job" "$n" path)" ]] || ok=0
            fi
            check "$job: the $id save is skipped on an exact restore" test "$ok" = 1
        done
        n=$(step_id "$job" depends)
        check "$job: the depends entry holds $image/$dir and depends-sources" \
            test "$(field "$job" "${n:-0}" path)" = "\$RUNNER_TEMP/yacoin-cache/$image/$dir"$'\n'"\$RUNNER_TEMP/yacoin-cache/depends-sources"
        n=$(step_id "$job" ccache)
        kind=${ckind[$job]}
        check "$job: the ccache entry holds $image/ccache" \
            test "$(field "$job" "${n:-0}" path)" = "\$RUNNER_TEMP/yacoin-cache/$image/ccache"
        check "$job: the ccache key holds the image tag and the commit" \
            test "$(field "$job" "${n:-0}" key)|$(field "$job" "${n:-0}" rkey)" = \
                 "$kind-ccache-<tagid:$image>-\$GITHUB_SHA|$kind-ccache-<tagid:$image>-"
    done

    # Every depends restore: the image tag and the depends inputs, exact key only.
    for job in "${!dkind[@]}" "${restore_jobs[@]}" "${own_ccache_jobs[@]}"; do
        kind=${dkind[$job]:-functional-tests}
        image=$(job_env "$job" IMAGE)
        n=$(step_id "$job" depends)
        check "$job: the depends key holds the image tag" \
            test "$(field "$job" "${n:-0}" key)|$(field "$job" "${n:-0}" rkey)" = "$kind-depends-<tagid:$image>-$depends_hash|"
    done

    # The build jobs restore nothing on a tag push.
    for job in "${build_jobs[@]}"; do
        mapfile -t restores < <(steps_of "$job" '^actions/cache/restore@')
        ok=1; (( ${#restores[@]} == 2 )) || ok=0
        for n in "${restores[@]}"; do
            [[ "$(field "$job" "$n" if)" == "\${{ !startsWith(github.ref, 'refs/tags/') }}" ]] || ok=0
        done
        check "$job: the cache restore is skipped on a tag push" test "$ok" = 1
    done

    # On a push to master the build jobs' restores only look up their keys;
    # on any other run they restore.
    for job in "${build_jobs[@]}"; do
        mapfile -t restores < <(steps_of "$job" '^actions/cache/restore@')
        ok=1; (( ${#restores[@]} == 2 )) || ok=0
        for n in "${restores[@]}"; do
            [[ "$(field "$job" "$n" lookup)" == "\${{ $master_push }}" ]] || ok=0
        done
        check "$job: the cache restore downloads nothing on a push to master" test "$ok" = 1
    done
    ok=1
    while IFS=$'\t' read -r job n; do
        [[ " ${build_jobs[*]} " == *" $job "* && "$(field "$job" "$n" uses)" == actions/cache/restore@* ]] || ok=0
    done < <(awk -F'\t' '$1 == "C" && $4 == "lookup" { print $2 "\t" $3 }' <<< "$recs")
    check "only the build jobs' cache restores set lookup-only" test "$ok" = 1

    # The sanitizer and coverage jobs restore the functional-tests depends
    # entry, with its paths, and save none.
    n=$(saves_of functional-tests depends)
    fs_key=$(field functional-tests "${n:-0}" key); fs_paths=$(field functional-tests "${n:-0}" path)
    for job in "${restore_jobs[@]}"; do
        check "$job: runs the ubuntu.22.04 image" test "$(job_env "$job" IMAGE)" = ubuntu.22.04
        mapfile -t restores < <(steps_of "$job" '^actions/cache')
        ok=0
        if (( ${#restores[@]} == 1 )); then
            n=${restores[0]}
            [[ "$(field "$job" "$n" uses)" != actions/cache/restore@* || -z "$fs_key" ||
               "$(field "$job" "$n" key)" != "$fs_key" || "$(field "$job" "$n" path)" != "$fs_paths" ]] || ok=1
        fi
        check "$job: restores the functional-tests depends entry and nothing else" test "$ok" = 1
        check "$job: saves no cache" test -z "$(steps_of "$job" '^actions/cache(/save)?@')"
    done

    # The jobs with a ccache entry of their own: the functional-tests depends
    # entry, restored only, and their ccache entry, saved under the key its
    # restore looked up when that restore had no exact hit.
    for job in "${own_ccache_jobs[@]}"; do
        image=$(job_env "$job" IMAGE)
        check "$job: runs the ubuntu.22.04 image" test "$image" = ubuntu.22.04
        n=$(step_id "$job" depends); ok=0
        [[ -z "$n" || "$(field "$job" "$n" uses)" != actions/cache/restore@* || -z "$fs_key" ||
           "$(field "$job" "$n" key)" != "$fs_key" || "$(field "$job" "$n" path)" != "$fs_paths" ]] || ok=1
        check "$job: restores the functional-tests depends entry" test "$ok" = 1
        check "$job: saves no depends entry" test -z "$(saves_of "$job" depends)"
        n=$(step_id "$job" ccache)
        check "$job: the ccache entry holds $image/ccache" \
            test "$(field "$job" "${n:-0}" path)" = "\$RUNNER_TEMP/yacoin-cache/$image/ccache"
        check "$job: the ccache key holds the image tag and the commit" \
            test "$(field "$job" "${n:-0}" key)|$(field "$job" "${n:-0}" rkey)" = \
                 "$job-ccache-<tagid:$image>-\$GITHUB_SHA|$job-ccache-<tagid:$image>-"
        mapfile -t saves < <(steps_of "$job" '^actions/cache(/save)?@')
        ok=0
        if [[ -n "$n" && "$(field "$job" "$n" uses)" == actions/cache/restore@* && ${#saves[@]} == 1 &&
              "$(field "$job" "${saves[0]}" keyraw)" == "\${{ steps.ccache.outputs.cache-primary-key }}" &&
              "$(field "$job" "${saves[0]}" if)" == *" && steps.ccache.outputs.cache-hit != 'true' }}" &&
              "$(field "$job" "${saves[0]}" path)" == "$(field "$job" "$n" path)" ]]; then
            ok=1
        fi
        check "$job: saves the ccache entry only, skipped on an exact restore" test "$ok" = 1
    done

    # One key, one path list (the paths are part of the entry's version).
    ok=$(awk -F'\t' '$1 == "C" && $4 == "key" { key[$2 SUBSEP $3] = $5 }
                     $1 == "C" && $4 == "path" { p[$2 SUBSEP $3] = p[$2 SUBSEP $3] "|" $5 }
                     END { r = 1
                           for (s in key) { if (key[s] in seen && seen[key[s]] != p[s]) r = 0; seen[key[s]] = p[s] }
                           print r }' <<< "$recs")
    check "the cache steps of one key have one path list" test "$ok" = 1
    ok=1
    # The depends restore and the depends save of both jobs.
    for i in step_id saves_of; do
        n=$("$i" build-ubuntu-1604 depends); m=$("$i" build-ubuntu-1604-low-difficulty depends)
        [[ -n "$n" && -n "$m" &&
           "$(field build-ubuntu-1604 "$n" key)" == "$(field build-ubuntu-1604-low-difficulty "$m" key)" &&
           "$(field build-ubuntu-1604 "$n" path)" == "$(field build-ubuntu-1604-low-difficulty "$m" path)" ]] || ok=0
    done
    check "build-ubuntu-1604-low-difficulty: the depends entry is that of build-ubuntu-1604" test "$ok" = 1

    # prune-caches: the job that deletes cache entries.
    job=$(job_text_of "$1" prune-caches)
    ok=0
    if [[ -n "$job" && "$(awk -F'\t' '$1 == "J" && $2 == "prune-caches" && $3 == "if" { print $4 }' <<< "$recs")" == \
          "\${{ !cancelled() && $master_push }}" ]]; then
        grep -qE 'docker|actions/checkout' <<< "$job" || ok=1
    fi
    check "prune-caches runs only on a push to master and runs no docker" test "$ok" = 1
    savers=$(awk -F'\t' '$1 == "C" && $4 == "uses" && $5 ~ /^actions\/cache(\/save)?@/ { print $2 }' <<< "$recs" | LC_ALL=C sort -u)
    needed=$(awk -F'\t' '$1 == "J" && $2 == "prune-caches" && $3 == "needs" { print $4 }' <<< "$recs" | LC_ALL=C sort -u)
    check "prune-caches needs every job that saves a cache and nothing else" test -n "$savers" -a "$needed" = "$savers"
    check "prune-caches is the one job with actions: write" test \
        "$(awk -F'\t' '($1 == "J" && $3 == "perm" && $4 ~ /^actions: *write/) { print $2 }
                       ($1 == "W" && $3 ~ /^actions: *write/) { print "(workflow)" }' <<< "$recs" | sort -u)" = prune-caches
}

cache_checks "$wf"

# all-jobs-passed as written, without its comments, blank lines and the
# entries of its needs: block.
aggregate_job="  all-jobs-passed:
    needs:
    if: \${{ always() }}
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803  # v6.1.0
        with:
          persist-credentials: false
      - name: results of the needed jobs
        env:
          NEEDS_JSON: \${{ toJSON(needs) }}
          MASTER_PUSH: \${{ $master_push }}
        run: ci/containers/all-jobs-passed.sh"
layout="the workflow's jobs are plain keys at two spaces"

# aggregate_checks <workflow>: the checks of the workflow's jobs and of
# all-jobs-passed, the job that needs every other job.
aggregate_checks() {
    local recs line bad others needed text
    recs=$(cache_records "$1")
    # Every line at two spaces under jobs: is a job key the checks here read,
    # and jobs: is the last top-level key: no line after it starts in
    # column 0 but blank lines and comments.
    bad=$(awk '/^jobs:[ ]*$/ { on = 1; next }
               on && /^[^ #]/ { print; next }
               on && /^  [^ ]/ && !/^  #/ && !/^  [A-Za-z0-9_-]+:$/' "$1")
    if [[ -z "$bad" ]]; then
        pass "$layout"
    else
        while IFS= read -r line; do fail "$layout: $line"; done <<< "$bad"
    fi
    check "the workflow holds no continue-on-error" test -z "$(grep -F continue-on-error "$1" || true)"
    others=$(awk -F'\t' '$1 == "J" && $3 == "name" && $2 != "all-jobs-passed" { print $2 }' <<< "$recs" | LC_ALL=C sort)
    needed=$(awk -F'\t' '$1 == "J" && $2 == "all-jobs-passed" && $3 == "needs" { print $4 }' <<< "$recs" | LC_ALL=C sort)
    check "all-jobs-passed needs every other job and nothing else" test "$needed" = "$others"
    check "all-jobs-passed runs always" \
        test "$(awk -F'\t' '$1 == "J" && $2 == "all-jobs-passed" && $3 == "if" { print $4 }' <<< "$recs")" = "\${{ always() }}"
    text=$(job_text_of "$1" all-jobs-passed | awk '{ t = $0; sub(/^[ \t]+/, "", t) } t == "" || t ~ /^#/ { next }
                                                   inneeds && /^      - / { next } { inneeds = ($0 == "    needs:"); print }')
    check "all-jobs-passed is written as expected" test "$text" = "$aggregate_job"
}

echo "== the workflow's jobs and all-jobs-passed =="
aggregate_checks "$wf"

# plant <check> <job> <sed script>: a copy of the workflow with the script
# applied to one job's lines must fail <check>.
plant() {
    local want="$1" job="$2" script="$3" range copy="$work/planted.yml" out
    range=$(awk -v name="  $job:" '$0 == name { s = NR; next }
                                   s && /^  [A-Za-z0-9_-]+:$/ { print s "," NR - 1; done = 1; exit }
                                   END { if (s && !done) print s ",$" }' "$wf")
    if [[ -z "$range" ]]; then fail "planted ($want): the workflow has no job $job"; return; fi
    sed -e "$range{" -e "$script" -e "}" "$wf" > "$copy"
    if cmp -s "$wf" "$copy"; then fail "planted ($want): the copy is unchanged"; return; fi
    out=$(cache_checks "$copy"; aggregate_checks "$copy") || true
    check "planted copy of $job fails: $want" grep -qxF "FAIL  $want" <<< "$out"
}
plant "build-windows: the cache save runs only on a push to master" build-windows \
    "/steps\.ccache\.outputs\.cache-hit/s/ && github\.event_name == 'push' && [^&]* && / \&\& /"
plant "unit-tests: the cache save runs only on a push to master" unit-tests \
    "/if: .*steps\.depends\.outputs\.cache-hit/d"
plant "build-ubuntu-2204: the cache save runs only on a push to master" build-ubuntu-2204 \
    "/steps\.depends\.outputs\.cache-hit/s/&& \(github\.event_name == 'push' && [^&]*\) &&/\&\& !(\1) \&\&/"
plant "functional-tests-asan: the cache save runs only on a push to master" functional-tests-asan \
    "s|actions/cache/restore@|actions/cache@|"
plant "functional-tests: the cache save runs only on a push to master" functional-tests \
    "/steps\.depends\.outputs\.cache-hit/s/success()/!cancelled()/"
plant "unit-tests: the saved key holds no run id or attempt" unit-tests \
    "/KEY_CCACHE=/s/\" >> /-\${{ github.run_id }}\" >> /"
plant "functional-tests: the depends save is skipped on an exact restore" functional-tests \
    "s/ && steps\.depends\.outputs\.cache-hit != 'true'//"
plant "build-macos: the depends key holds the image tag" build-macos \
    "/KEY_DEPENDS=/s/\$image_key/\$IMAGE/"
plant "build-ubuntu-1604: the depends key holds the image tag" build-ubuntu-1604 \
    "s/^\( *\)image_key=\(.*\)$/\1echo \"KEY_IMAGE=\2\" >> \"\$GITHUB_ENV\"/; /KEY_DEPENDS=/s/\$image_key/\$KEY_IMAGE/"
plant "build-ubuntu-1604-low-difficulty: the cache restore is skipped on a tag push" build-ubuntu-1604-low-difficulty \
    "/^        id: ccache$/{n;d}"
plant "build-ubuntu-1604: the cache restore downloads nothing on a push to master" build-ubuntu-1604 \
    "/^        id: ccache$/,/^      - /{/^ *lookup-only:/d}"
plant "build-ubuntu-2204: the cache restore downloads nothing on a push to master" build-ubuntu-2204 \
    "/^        id: depends$/,/^      - /s/^\( *lookup-only:\).*/\1 true/"
plant "build-macos: the cache restore downloads nothing on a push to master" build-macos \
    "/lookup-only:/s/ && github\.ref == 'refs\/heads\/master'//"
plant "only the build jobs' cache restores set lookup-only" unit-tests \
    "/^          key: \${{ env\.KEY_DEPENDS }}$/a\          lookup-only: \${{ $master_push }}"
plant "fuzz-corpus: restores the functional-tests depends entry and nothing else" fuzz-corpus \
    "s|/depends-built-tests$|/depends-built|"
plant "build-ubuntu-1604-low-difficulty: the depends entry is that of build-ubuntu-1604" build-ubuntu-1604-low-difficulty \
    "s|/depends-built$|/depends-built-tests|"
plant "build-ubuntu-1604-low-difficulty: the depends entry is that of build-ubuntu-1604" build-ubuntu-1604-low-difficulty \
    "s/release-depends-/low-difficulty-depends-/"
plant "prune-caches is the one job with actions: write" build-ubuntu-1604 \
    "/^      contents: read$/a\      actions: write"
plant "prune-caches runs only on a push to master and runs no docker" prune-caches \
    "s/^    if: .*/    if: \${{ !cancelled() }}/"
plant "prune-caches needs every job that saves a cache and nothing else" prune-caches "/^    needs: /s/, warnings\]/]/"
plant "prune-caches needs every job that saves a cache and nothing else" prune-caches "/^    needs: /s/\]/, coverage-unit]/"
plant "warnings: the cache save runs only on a push to master" warnings \
    "/steps\.ccache\.outputs\.cache-hit/s/ && github\.event_name == 'push' && [^&]* && / \&\& /"
plant "warnings: the ccache key holds the image tag and the commit" warnings "s/warnings-ccache-/functional-tests-ccache-/"
plant "warnings: restores the functional-tests depends entry" warnings "s/functional-tests-depends-/warnings-depends-/"
plant "warnings: saves no depends entry" warnings \
    "s/key: \${{ steps\.ccache\.outputs\.cache-primary-key }}/key: \${{ steps.depends.outputs.cache-primary-key }}/"
plant "warnings: saves the ccache entry only, skipped on an exact restore" warnings \
    "s/ && steps\.ccache\.outputs\.cache-hit != 'true'//"
new_job='  new-job:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo'
plant "all-jobs-passed needs every other job and nothing else" all-jobs-passed "/^      - unit-tests$/d"
plant "all-jobs-passed needs every other job and nothing else" fuzz-corpus "/^  fuzz-corpus:$/i\\$new_job"
plant "all-jobs-passed needs every other job and nothing else" all-jobs-passed \
    "s/^      - functional-tests$/      - functional-test/"
plant "all-jobs-passed runs always" all-jobs-passed "s/^    if: .*/    if: \${{ !cancelled() }}/"
plant "all-jobs-passed runs always" all-jobs-passed "/^    if: /d"
plant "all-jobs-passed is written as expected" all-jobs-passed "/MASTER_PUSH:/s/ && github\.ref == 'refs\/heads\/master'//"
plant "all-jobs-passed is written as expected" all-jobs-passed \
    "/^      - name: results of the needed jobs$/a\        if: \${{ false }}"
plant "the workflow holds no continue-on-error" build-ubuntu-2204 "/^    timeout-minutes: 60$/a\    continue-on-error: true"
plant "the workflow holds no continue-on-error" build-ubuntu-2204 "/^    timeout-minutes: 60$/a\    \"continue-on-error\": true"
plant "the workflow holds no continue-on-error" build-ubuntu-2204 "/^    timeout-minutes: 60$/a\    continue-on-error : true"
plant "the workflow holds no continue-on-error" build-ubuntu-2204 \
    "/^      - uses: actions\/checkout@[0-9a-f]\{40\}  # v6\.1\.0$/a\      - { run: echo, continue-on-error: true }"
plant "$layout:   new-job:  # x" fuzz-corpus "/^  fuzz-corpus:$/i\\${new_job/new-job:/new-job:  # x}"
plant "$layout:   \"new-job\":" fuzz-corpus "/^  fuzz-corpus:$/i\\${new_job/new-job:/\"new-job\":}"
# A quoted scalar continued at column 0, then a commented job key.
continued='  new-job:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "echo\nx"\n  hidden-job:  # x\n    runs-on: ubuntu-latest'
plant "$layout: x\"" fuzz-corpus "/^  fuzz-corpus:$/i\\$continued"
plant "$layout:   hidden-job:  # x" fuzz-corpus "/^  fuzz-corpus:$/i\\$continued"

# A job added or removed is a deliberate change of this number.
jobs=$(awk '/^jobs:$/ { on = 1; next } on && /^  [A-Za-z0-9_-]+:$/ { n++ } END { print n + 0 }' "$wf")
check "${wf#"$ROOT"/}: 18 jobs ($jobs)" test "$jobs" = 18
action="$ROOT/.github/actions/yacoin-build-image/action.yml"
check "the image action computes the tag with image-tag.sh" grep -q 'ci/containers/image-tag.sh' "$action"
for wf in "$ROOT"/.github/workflows/*.yml; do
    jobs=$(grep -cE '^[[:space:]]*docker run ' "$wf" || true)
    steps=$(grep -c 'uses: ./.github/actions/yacoin-build-image' "$wf" || true)
    check "${wf#"$ROOT"/}: one image step per job that runs docker ($steps for $jobs)" test "$jobs" = "$steps"
done

echo "== ${#failures[@]} failure(s) =="
if (( ${#failures[@]} )); then printf '  %s\n' "${failures[@]}"; exit 1; fi
