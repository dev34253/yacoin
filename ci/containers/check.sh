#!/usr/bin/env bash
# Image checks, run locally.
#
# Usage: ci/containers/check.sh [--steps LIST] [image...]
#
# Steps (default: lint,tag,static,devsh,build,smoke,ccache; all images by
# default):
#   lint    bash -n and shellcheck --severity=warning on the scripts here,
#           no grep -q at the end of a pipe in them (pipefail and SIGPIPE),
#           and every uses: under .github/ names a local action or a
#           published action by full commit SHA with its version in a comment
#           (first on planted copies, each with its expected result)
#   tag     test-image-tag.sh: the image tags (image-tag.sh), the CI
#           workflow's use of them, its jobs and caches, and
#           all-jobs-passed.sh (needs jq)
#   static  every Dockerfile pins its base image by digest and sets
#           YACOIN_BUILD_IMAGE to its own name
#   devsh   dev.sh's shared cache, on copies of dev.sh and depends/ (no
#           Docker, a stub make): the default path (XDG_CACHE_HOME, HOME),
#           DEV_CACHE, the help, one depends prefix for two copies, a new one
#           after a recipe change (untracked recipe files too) but not for
#           ignored files under depends/,
#           the arguments depends gets, ccache.conf created, two depends runs
#           one after the other, a repeated run skipping make unless its
#           inputs (Qt) changed, a build directory of another prefix refused,
#           container passing the mode to run.sh, and run.sh adding the
#           seccomp option for unit-tests-tsan only and CCACHE_DISABLE=1 for
#           the sanitizer modes (unit-tests-asan, unit-tests-tsan,
#           fuzz-corpus, functional-tests-asan) only and passing SANITIZE
#           and FTEST_SHARD on when set (stub docker), cov running both
#           coverage targets in one build and every functional test script
#           whatever FTEST_SHARD says, ftest running the scripts on regtest
#           with the regtest list left out, the variants func and cov-func
#           refused, build passing its target to make in src/ (src/<path>
#           as <path>, with one line on stderr; other targets unchanged; none
#           for the whole build directory) and make's error and exit status
#           for an unknown target, the help saying the target is relative to
#           src/, asan's
#           sanitizer options (the suppression file, the caller's own options
#           kept) and its list of test cases left out, which unit does not
#           pass; depends skipping make unless its stamp's inputs changed
#           (every line of the compilers' versions, ar, ranlib, strip, the
#           tools of another host, the make arguments, and DEBUG,
#           HOST_ID_SALT, BUILD_ID_SALT, NO_WALLET, NO_UPNP and NO_QT from
#           the environment; not JOBS or the copy's path),
#           one set of paths for every spelling of DEV_CACHE (trailing slash,
#           symlink, .., not yet created), a refused build directory naming
#           the untracked files under depends/; container and run.sh (stub
#           docker): a tag and label of each copy's own (also for one
#           directory name at two paths; the same through a symlink;
#           LOCAL_REPO wins), --print-tag, one container cache per set of
#           depends inputs under DEV_CACHE for two copies (an ignored file
#           keeps it; an untracked file, a recipe change and a tree outside
#           git change it), the same for run.sh alone and dev.sh cache,
#           --cache, --no-cache, --cpus, --no-image-build without the image,
#           the cache lock (depends phases one after the other; released at
#           the image's line after its depends build, which each entrypoint
#           prints once, or held to the end without it), and docker run's
#           output and exit status passed on
#   build   docker build of each image (tagged with this clone's tag,
#           run.sh --print-tag <image>)
#   smoke   tools present, unknown modes and arguments rejected, the modes
#           that run tests stop early on a tree without the scripts,
#           targets and files they need, the Linux release build modes
#           (build, build-low-difficulty), the sanitizer modes
#           (unit-tests-asan, unit-tests-tsan, functional-tests-asan) and the
#           coverage modes (cov-unit, cov-functional; 22.04 image) configure
#           with their flags (unit-tests-asan also with SANITIZE=address and
#           undefined, and rejects other values; -g1 in unit-tests-asan and
#           functional-tests-asan), the functional modes and cov-functional
#           configure without the low-difficulty parameters,
#           build-low-difficulty, unit-tests and the unit
#           sanitizer modes run the unit test suites of their build with JOBS
#           (the sanitizer modes with their runtime options and nothing else
#           does, unit-tests-tsan with address randomisation off) and fail when
#           one fails or the build made no test_bitcoin, unit-tests-asan
#           leaves the test cases of its list out (the other modes do not;
#           with SANITIZE=address and undefined the same suites, list and
#           options),
#           unit-tests then runs bench_yacoin -time=0.01 (the others do not)
#           and fails when it fails or the build made no bench_yacoin,
#           the sanitizer modes stop on a tree without their suppression
#           file (unit-tests-asan and functional-tests-asan also without
#           their lists, functional-tests-asan with a runner without
#           --sanitizer-logs or --exclude-file) and are refused by the
#           images other than 22.04, unit-tests-tsan stops when it
#           cannot turn address randomisation off (this case assumes the
#           engine's default seccomp profile), fuzz-corpus (22.04 image,
#           refused by the others) configures with clang, --enable-fuzz and
#           its sanitizer flags, runs the corpus replay with JOBS and its
#           runtime options, fails when the replay fails or the build made no
#           fuzz binary and stops on a tree without a corpus, the functional
#           modes build yacoind and yacoin-cli only and run the test runner
#           with --extended and FTEST_JOBS (with FTEST_SHARD also --shard;
#           a malformed FTEST_SHARD or a runner without --shard stops them
#           before the build; cov-functional passes FTEST_SHARD to make and
#           stops on a target without it or a tree without the regtest list)
#           and fail when it fails, and
#           functional-tests-asan runs it with the sanitizers' options, a
#           directory for their reports and its list of scripts left out and
#           fails on a report there even when every script passed; the
#           functional modes run it with --chain=regtest and the regtest list
#           left out, and stop before the build on a tree without that list
#           or with a runner without --chain or --exclude-file;
#           build-low-difficulty then runs the scripts of the regtest list
#           with FTEST_JOBS (test_runner.py --include-file), fails when the
#           runner fails and stops before the build on a tree without the
#           list or with a runner without --include-file
#   ccache  the entrypoint creates the ccache config before anything runs
#           ccache, with an empty /cache and with none (a stub source tree
#           makes this quick)
#   cache   slow (two release builds per image, any image): build a clean
#           clone of HEAD twice with one cache dir and CI's CCACHE_COMPRESS=1
#           CCACHE_MAXSIZE=1G, cleaning the tree in between. The first starts
#           on an empty cache; the second must report the cache, take every
#           depends package from it, compile src/ through the depends ccache
#           with at least 90% hits, and take at most half the time ("cross"
#           job of docker-check.yml, extended)
#
# The shellcheck binary comes from the host if installed, otherwise from Ubuntu 22.04's
# package in a throwaway container. CHECK_WORKDIR keeps the work files.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=run.sh
source "$HERE/run.sh"

steps=lint,tag,static,devsh,build,smoke,ccache
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
mkdir -p "$work"; work="$(cd "$work" && pwd -P)"
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
    local f scripts=(entrypoint.sh entrypoint.windows.sh entrypoint.macos.sh run.sh parity.sh check.sh
                     image-tag.sh test-image-tag.sh all-jobs-passed.sh)
    for f in "${scripts[@]}"; do
        bash -n "$HERE/$f" && pass "lint: bash -n $f" || fail "lint: bash -n $f"
    done
    (cd "$HERE" && shellcheck_cmd -x --severity=warning "${scripts[@]}") &&
        pass "lint: shellcheck ${scripts[*]}" || fail "lint: shellcheck"
    # Under pipefail, grep -q at the end of a pipe may exit on the first
    # match, the command before it gets SIGPIPE and the pipe reads as no
    # match. A pipe continued on the next line counts too; comments do not.
    local piped
    piped=$(cd "$HERE" && awk '
        FNR == 1 { prev = "" }
        { line = $0; if (prev ~ /(^|[^|])\|[[:space:]]*$/) line = "|" line; prev = $0 }
        $0 !~ /^[[:space:]]*#/ &&
        line ~ /(^|[^|])\|[[:space:]]*grep[[:space:]]+(-[A-Za-z]+[[:space:]]+)*(-[A-Za-z]*q|--quiet|--silent)/ {
            print FILENAME ":" FNR ": " $0
        }' "${scripts[@]}")
    if [[ -z "$piped" ]]; then
        pass "lint: no grep -q at the end of a pipe"
    else
        while read -r f; do fail "lint: grep -q at the end of a pipe (capture the output first): $f"; done <<< "$piped"
    fi
    lint_uses
}

# unpinned_uses <dir>: prints every line of the *.yml and *.yaml files under
# <dir> that holds uses: as a key and names neither a local action
# (uses: ./<path>) nor a published action by full commit with its version in
# a comment (uses: <owner>/<repo>[/<path>]@<40 hex>  # v<version>, with an
# optional "- " before it), as "<file>:<line>: <rule>: <line>", the file
# relative to the parent of <dir>. Comment lines are skipped; any other form
# (quoted, flow) is reported. A <dir> without such files is reported too.
UNPINNED_USES="uses: must be a local action (./...) or owner/repo[/path]@<40-hex commit>  # <version>"
unpinned_uses() {
    local base name f n line files=0
    local comment='^[[:space:]]*#'
    local key="(^|[^A-Za-z0-9_-])[\"']?uses[\"']?[[:space:]]*:"
    local item='^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+'
    local local_action="$item"'\./[^[:space:]#]+[[:space:]]*$'
    local pinned="$item"'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}[[:space:]]+# v[0-9][0-9A-Za-z.+-]*[[:space:]]*$'
    base=$(dirname "$1") name=$(basename "$1")
    while IFS= read -r -d '' f; do
        files=$((files + 1)) n=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            n=$((n + 1))
            [[ ! "$line" =~ $comment && "$line" =~ $key ]] || continue
            [[ "$line" =~ $local_action || "$line" =~ $pinned ]] ||
                echo "$f:$n: $UNPINNED_USES: ${line#"${line%%[![:space:]]*}"}"
        done < "$base/$f"
    done < <(cd "$base" && find "$name" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | LC_ALL=C sort -z)
    (( files > 0 )) || echo "$name: no *.yml or *.yaml files"
}

# lint_uses_plant <want> <file> <line>...: a copy of .github in $work with one
# workflow <file> whose steps are the lines; the rule must report line <want>
# of it (0: nothing).
lint_uses_plant() {
    local want="$1" file="$2" dir="$work/uses-plant/.github" out expect=""
    shift 2
    rm -rf "$dir"; mkdir -p "$dir/workflows"
    printf '%s\n' 'on: push' 'jobs:' '  build:' '    runs-on: ubuntu-latest' '    steps:' "$@" > "$dir/workflows/$file"
    out=$(unpinned_uses "$dir")
    local label line
    for line in "$@"; do [[ -n "${label:-}" || "$line" != *uses* ]] || label="${line#"${line%%[![:space:]]*}"}"; done
    if (( want > 0 )); then
        expect=$(sed -n "${want}p" "$dir/workflows/$file")
        expect=".github/workflows/$file:$want: $UNPINNED_USES: ${expect#"${expect%%[![:space:]]*}"}"
    fi
    if [[ "$out" != "$expect" ]]; then
        fail "lint: uses: planted '$label' in $file gives '$out', want '${expect:-nothing}'"
    elif (( want > 0 )); then
        pass "lint: uses: planted '$label' in $file fails: $out"
    else
        pass "lint: uses: planted '$label' in $file passes"
    fi
}

lint_uses() {
    local sha=d23441a48e516b6c34aea4fa41551a30e30af803 out f
    lint_uses_plant 6 unpinned.yml '      - uses: actions/checkout@v6'
    lint_uses_plant 6 short.yml '      - uses: actions/checkout@d23441a  # v6.1.0'
    lint_uses_plant 6 no-version.yml "      - uses: actions/checkout@$sha"
    lint_uses_plant 6 branch-comment.yml "      - uses: actions/checkout@$sha  # main"
    lint_uses_plant 0 pinned.yml "      - uses: actions/checkout@$sha  # v6.1.0"
    lint_uses_plant 0 pinned-key.yml '      - name: checkout' "        uses: actions/checkout@$sha  # v6.1.0"
    lint_uses_plant 0 pinned-path.yml '      - uses: actions/cache/save@caa296126883cff596d87d8935842f9db880ef25  # v5.1.0'
    lint_uses_plant 0 local.yml '      - uses: ./.github/actions/yacoin-build-image'
    lint_uses_plant 0 comment.yml '      # uses: actions/checkout@v6' '      - run: echo'
    lint_uses_plant 6 flow.yml '      - { uses: actions/checkout@v6 }'
    lint_uses_plant 6 quoted.yml "      - uses: \"actions/checkout@$sha\"  # v6.1.0"
    lint_uses_plant 7 unpinned-key.yaml '      - name: checkout' '        uses: actions/checkout@v6'
    rm -rf "$work/uses-plant"; mkdir -p "$work/uses-plant/.github"
    out=$(unpinned_uses "$work/uses-plant/.github")
    [[ "$out" == ".github: no *.yml or *.yaml files" ]] && pass "lint: uses: a directory without workflows is reported" ||
        fail "lint: uses: a directory without workflows gives '$out'"
    out=$(unpinned_uses "$ROOT/.github")
    if [[ -z "$out" ]]; then
        pass "lint: every uses: under .github/ names a local action or a published action by full commit SHA with its version in a comment"
    else
        while IFS= read -r f; do fail "lint: $f"; done <<< "$out"
    fi
}

step_tag() {
    "$HERE/test-image-tag.sh" > "$work/tag.log" 2>&1 && pass "tag: test-image-tag.sh" ||
        { grep '^FAIL' "$work/tag.log"; fail "tag: test-image-tag.sh (log: $work/tag.log)"; }
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

# A copy of dev.sh and the tracked files of depends/ in its own git index.
make_devsh_copy() {
    rm -rf "$1"; mkdir -p "$1"
    (cd "$ROOT" && git ls-files -z -- dev.sh depends | tar --null -T - -c) | tar -x -C "$1"
    git -C "$1" init -q && git -C "$1" add -A
}

# dev_cache <copy> [env...]: the cache paths of dev.sh in <copy> (dev.sh cache).
dev_cache() {
    local d="$1"; shift
    env -u DEV_CACHE -u XDG_CACHE_HOME "$@" "$d/dev.sh" cache 2>&1 || echo "dev.sh cache failed"
}
# depends_prefix <copy> <cache>: the depends prefix of dev.sh in <copy>.
depends_prefix() { dev_cache "$1" DEV_CACHE="$2" | sed -n 's/^DEPENDS_PREFIX=//p'; }

# The stub docker of the devsh cases: records "build" and "run" in
# $STUB_DOCKER, fails "image inspect" when STUB_NO_IMAGE is set, and runs
# $STUB_RUN as the container of a run with a container id file (not of the
# chown after it).
write_stub_docker() {
    cat > "$1" <<'EOF'
#!/bin/bash
case "${1:-}" in
    build) echo "$*" >> "${STUB_DOCKER:-/dev/null}" ;;
    image) [[ -z "${STUB_NO_IMAGE:-}" ]] || exit 1 ;;
    run)
        echo "$*" >> "${STUB_DOCKER:-/dev/null}"
        if [[ -n "${STUB_RUN:-}" && " $* " == *" --cidfile "* ]]; then exec "$STUB_RUN"; fi ;;
esac
EOF
    chmod +x "$1"
}

# The container of the lock cases (STUB_RUN): prints STUB_START_LINE, logs
# "dstart <STUB_ID>" and "dend <STUB_ID>" to STUB_EVENTS around a depends
# phase of STUB_DEPENDS_TIME seconds, prints STUB_MARKER, logs "rest <id>";
# with STUB_WAIT_FOR it then waits up to STUB_WAIT_TENTHS tenths of a second
# for "dstart <STUB_WAIT_FOR>" and logs "met <id>" if it comes. Then it logs
# "end <id>", prints the bytes of STUB_TAIL_FILE and exits STUB_STATUS.
write_stub_container() {
    cat > "$1" <<'EOF'
#!/bin/bash
ev() { echo "$1 ${STUB_ID:-}" >> "${STUB_EVENTS:-/dev/null}"; }
[[ -z "${STUB_START_LINE:-}" ]] || echo "$STUB_START_LINE"
ev dstart; sleep "${STUB_DEPENDS_TIME:-0}"; ev dend
[[ -z "${STUB_MARKER:-}" ]] || echo "$STUB_MARKER"
ev rest
if [[ -n "${STUB_WAIT_FOR:-}" ]]; then
    for (( i = 0; i < ${STUB_WAIT_TENTHS:-0}; i++ )); do
        if grep -qx "dstart $STUB_WAIT_FOR" "$STUB_EVENTS"; then ev met; break; fi
        sleep 0.1
    done
fi
ev end
[[ -z "${STUB_TAIL_FILE:-}" ]] || cat "$STUB_TAIL_FILE"
exit "${STUB_STATUS:-0}"
EOF
    chmod +x "$1"
}

# wait_for <line> <file>: waits up to 20 s for the line in the file.
wait_for() {
    local i
    for (( i = 0; i < 200; i++ )); do
        if grep -qx -- "$1" "$2" 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    return 1
}

# make_container_copy <dir>: a copy as make_devsh_copy, with run.sh and empty
# Dockerfiles of two images.
make_container_copy() {
    make_devsh_copy "$1"
    mkdir -p "$1/ci/containers"
    cp "$HERE/run.sh" "$1/ci/containers/"
    : > "$1/ci/containers/Dockerfile.ubuntu.22.04"; : > "$1/ci/containers/Dockerfile.macos"
}

# devsh_depends_ran <tree> <depends argument> [NAME=VALUE...]: "yes" if
# dev.sh depends in <tree> ran make, "no" if it skipped it (stub tools in
# $tools, the stub make, the cache $cs, the make log $slog of devsh_stamp).
devsh_depends_ran() {
    local tree="$1" arg="$2" before; shift 2
    before=$(grep -c '^start' "$slog" 2>/dev/null) || before=0
    env -u DEBUG -u HOST_ID_SALT -u BUILD_ID_SALT -u NO_WALLET -u NO_UPNP -u NO_QT -u DEV_HOST \
        PATH="$tools:$bin:$PATH" STUB_LOG="$slog" STUB_MAKE_SLEEP=0 DEV_CACHE="$cs" "$@" \
        "$tree/dev.sh" depends ${arg:+"$arg"} > "$work/devsh/s/out.txt" 2>&1 || { echo "failed"; return; }
    if [[ "$(grep -c '^start' "$slog")" != "$before" ]]; then echo yes; else echo no; fi
}

# The depends stamp, the spellings of DEV_CACHE and the refusal of a build
# directory (a copy with stub tools printing the versions in $tools/v).
devsh_stamp() {
    local bin="$1" s="$work/devsh/s/s" s2="$work/devsh/s/other/s" cs="$work/devsh/s/cache"
    local tools="$work/devsh/s/tools" slog="$work/devsh/s/make.log" t v got want spelling out
    rm -rf "$work/devsh/s"; make_devsh_copy "$s"; make_devsh_copy "$s2"; mkdir -p "$tools/v"
    for t in gcc g++ ar ranlib strip x86_64-w64-mingw32-{gcc,g++,ar,ranlib,strip}; do
        # shellcheck disable=SC2016 # expanded by the stub
        printf '%s\n' '#!/bin/bash' 'cat "${0%/*}/v/${0##*/}"' > "$tools/$t"; chmod +x "$tools/$t"
        printf '%s (stub) 1.0\nCopyright line 1\n' "$t" > "$tools/v/$t"
    done
    got=$(devsh_depends_ran "$s" "")
    [[ "$got" == yes ]] || fail "devsh: the first depends run in s: $got"
    # Nothing that changes the packages changed: make is skipped.
    got="$(devsh_depends_ran "$s" "") $(devsh_depends_ran "$s" "" JOBS=3) $(devsh_depends_ran "$s2" "")"
    [[ "$got" == "no no no" ]] && pass "devsh: depends skips make when nothing changed, with another JOBS and in another copy" ||
        fail "devsh: depends ran make (again, with another JOBS, in another copy): $got"
    got="$(devsh_depends_ran "$s" qt) $(devsh_depends_ran "$s" "")"
    [[ "$got" == "yes yes" ]] && pass "devsh: depends runs make after another Qt choice" ||
        fail "devsh: depends with Qt and then without ran make: $got"
    # Every line of a compiler's version counts; the binutils too.
    for t in gcc g++ ar ranlib strip; do
        if [[ $t == g* ]]; then
            printf '%s (stub) 1.0\nCopyright line 2\n' "$t" > "$tools/v/$t"
        else
            printf '%s (stub) 2.0\nCopyright line 1\n' "$t" > "$tools/v/$t"
        fi
        got=$(devsh_depends_ran "$s" "")
        [[ "$got" == yes ]] && pass "devsh: depends runs make after a new $t version" ||
            fail "devsh: depends after a new $t version ran make: $got"
    done
    # The tools of another host.
    got="$(devsh_depends_ran "$s" "" DEV_HOST=x86_64-w64-mingw32) $(devsh_depends_ran "$s" "" DEV_HOST=x86_64-w64-mingw32)"
    printf '%s (stub) 2.0\n' x86_64-w64-mingw32-ar > "$tools/v/x86_64-w64-mingw32-ar"
    got+=" $(devsh_depends_ran "$s" "" DEV_HOST=x86_64-w64-mingw32)"
    [[ "$got" == "yes no yes" ]] && pass "devsh: depends for another host runs make after a new version of its ar" ||
        fail "devsh: depends for another host ran make (first, again, after a new ar): $got"
    # DEBUG, HOST_ID_SALT, BUILD_ID_SALT, NO_WALLET, NO_UPNP and NO_QT from
    # the environment, set, set empty and unset again.
    for v in DEBUG HOST_ID_SALT BUILD_ID_SALT NO_WALLET NO_UPNP NO_QT; do
        got="$(devsh_depends_ran "$s" "" "$v=1") $(devsh_depends_ran "$s" "" "$v=") $(devsh_depends_ran "$s" "")"
        [[ "$got" == "yes yes yes" ]] && pass "devsh: depends runs make when $v is set, set empty and unset" ||
            fail "devsh: depends with $v set, set empty and unset ran make: $got"
    done
    # A make argument added to dev.sh's list.
    sed -i 's|base_download_dir="\$w/download")|base_download_dir="$w/download" V=1)|' "$s/dev.sh"
    if grep -qF 'base_download_dir="$w/download" V=1)' "$s/dev.sh"; then
        got=$(devsh_depends_ran "$s" "")
        [[ "$got" == yes ]] && pass "devsh: depends runs make after a new make argument" ||
            fail "devsh: depends after a new make argument ran make: $got"
    else
        fail "devsh: no make argument list to add to in dev.sh"
    fi
    cp "$ROOT/dev.sh" "$s/dev.sh"
    # Spellings of one cache give the same paths.
    local link="$work/devsh/s/cache-link" new="$work/devsh/s/new/cache"
    ln -s "$cs" "$link"
    want=$(dev_cache "$s" DEV_CACHE="$cs")
    for spelling in "$cs/" "$cs//" "$link" "$link/" "$cs/x/.."; do
        got=$(dev_cache "$s" DEV_CACHE="$spelling")
        [[ "$got" == "$want" ]] && pass "devsh: DEV_CACHE=$spelling gives the paths of DEV_CACHE=$cs" ||
            fail "devsh: DEV_CACHE=$spelling gives: $got (want: $want)"
    done
    want=$(dev_cache "$s" DEV_CACHE="$new"); got=$(dev_cache "$s" DEV_CACHE="$new/")
    [[ "$got" == "$want" && "$want" == *"DEV_CACHE=$new"* && ! -e "$new" ]] &&
        pass "devsh: DEV_CACHE=$new/ (not yet created) gives the paths of DEV_CACHE=$new" ||
        fail "devsh: DEV_CACHE=$new/ gives: $got (want: $want)"
    # A build directory configured against DEV_CACHE=<c> builds with <c>/.
    local p; p=$(depends_prefix "$s" "$cs")
    mkdir -p "$s/build/dev"; : > "$s/build/dev/Makefile"; echo "CPPFLAGS=-I$p/include" > "$s/build/dev/config.status"
    rm -f "$slog"
    if PATH="$bin:$PATH" STUB_LOG="$slog" STUB_MAKE_SLEEP=0 DEV_CACHE="$cs/" "$s/dev.sh" build dev > "$work/devsh/s/out.txt" 2>&1 &&
            grep -q "^start -C $s/build/dev " "$slog"; then
        pass "devsh: a build directory configured with DEV_CACHE=<c> builds with DEV_CACHE=<c>/"
    else
        fail "devsh: a build directory configured with DEV_CACHE=<c> with DEV_CACHE=<c>/: $(cat "$work/devsh/s/out.txt")"
    fi
    # The refusal names the files under depends/ that git does not track,
    # but not the ignored ones.
    echo "CPPFLAGS=-I$cs/depends/0000000000000000/x86_64-pc-linux-gnu/include" > "$s/build/dev/config.status"
    : > "$s/depends/untracked-example.txt"; mkdir -p "$s/depends/work"; : > "$s/depends/work/ignored-example.txt"
    expect_status 1 "devsh: a build directory of other dependencies is refused" env DEV_CACHE="$cs" "$s/dev.sh" build dev
    out=$(cat "$work/out.txt")
    [[ "$out" == *"depends/untracked-example.txt"* && "$out" != *ignored-example* ]] &&
        pass "devsh: the refusal names the untracked file under depends/ and not the ignored one" ||
        fail "devsh: the refusal says: $out"
}

# devsh_container_run <LOCAL_REPO or ""> <tree> [args...]: dev.sh container
# <args> in <tree> with the stub docker; sets ct_build (the tag docker build
# got), ct_line (the docker run), ct_run (its image, the word before the
# mode unit-tests) and ct_mount (the host directory at /cache).
devsh_container_run() {
    local repo_env=(-u LOCAL_REPO) tree="$2"
    [[ -z "$1" ]] || repo_env=("LOCAL_REPO=$1")
    shift 2
    rm -f "$dlog"
    env "${repo_env[@]}" PATH="$bin:$PATH" STUB_DOCKER="$dlog" DEV_CACHE="$cache" "$tree/dev.sh" container "$@" \
        > "$work/devsh/c/out.txt" 2>&1 || true
    ct_build=$(sed -n 's/^build .* -t \([^ ]*\) .*/\1/p' "$dlog" 2>/dev/null) || ct_build=""
    ct_line=$(grep -m1 -- '--cidfile' "$dlog" 2>/dev/null) || ct_line="no docker run"
    ct_run=""
    if [[ "$ct_line" =~ \ ([^ ]+)\ unit-tests$ ]]; then ct_run="${BASH_REMATCH[1]}"; fi
    ct_mount=$(sed -n 's/.* -v \([^ ]*\):\/cache .*/\1/p' <<< "$ct_line")
}

# devsh_lock_run <tree> <id> <image> [NAME=VALUE...]: dev.sh container
# --no-image-build <image> in <tree>, with the stub container.
devsh_lock_run() {
    local tree="$1" id="$2" image="$3"; shift 3
    env -u LOCAL_REPO PATH="$bin:$PATH" STUB_RUN="$stubc" STUB_EVENTS="$ev" STUB_ID="$id" DEV_CACHE="$cache" "$@" \
        "$tree/dev.sh" container --no-image-build "$image"
}

# The image tags, the container cache and its lock, --cpus, --print-tag and
# --no-image-build (copies of dev.sh, depends/ and run.sh; a stub docker).
devsh_container() {
    local bin="$1" d="$work/devsh/c" dlog="$work/devsh/c/docker.log" cache="$work/devsh/c/cache"
    local x="$work/devsh/c/x/clone" y="$work/devsh/c/y/clone" link="$work/devsh/c/link" z="$work/devsh/c/z"
    local re='^[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*:ubuntu\.22\.04$' got want bx rx by ry bline mx out
    local ct_build ct_line ct_run ct_mount
    rm -rf "$d"; make_container_copy "$x"; make_container_copy "$y"; ln -s "$x" "$link"
    # Each copy builds and runs a tag of its own, also when the two have
    # one directory name; the same copy, also through a symlink, keeps it.
    devsh_container_run "" "$x" unit-tests; bx="$ct_build" rx="$ct_run" mx="$ct_mount"
    bline=$(grep -m1 '^build ' "$dlog" 2>/dev/null) || bline="no docker build"
    devsh_container_run "" "$y" unit-tests; by="$ct_build" ry="$ct_run"
    if [[ "$bx" == "$rx" && "$by" == "$ry" && "$bx" =~ $re && "$by" =~ $re && "$bx" != "$by" &&
          "${bx%-*}" == "${by%-*}" ]]; then
        pass "devsh: two copies with one directory name build and run tags of their own ($bx, $by)"
    else
        fail "devsh: x built $bx and ran $rx, y built $by and ran $ry"
    fi
    [[ " $bline " == *" --label org.yacoin.build-local=1 "* &&
       " $bline " == *" --label org.yacoin.build-local.tree=$x "* ]] &&
        pass "devsh: the image is labelled with its copy" || fail "devsh: the image is built with: $bline"
    got=$(env -u LOCAL_REPO "$x/ci/containers/run.sh" --print-tag ubuntu.22.04 2>&1) || true
    [[ "$got" == "$bx" ]] && pass "devsh: run.sh --print-tag prints the copy's tag" ||
        fail "devsh: run.sh --print-tag prints: $got (built: $bx)"
    devsh_container_run "" "$x" unit-tests; got="$ct_build $ct_run"
    devsh_container_run "" "$link" unit-tests; got+=" $ct_build $ct_run"
    [[ "$got" == "$bx $bx $bx $bx" ]] && pass "devsh: a copy keeps its tag, also through a symlink" ||
        fail "devsh: the copy again and through a symlink built and ran: $got (first: $bx)"
    devsh_container_run my-images "$x" unit-tests
    [[ "$ct_build $ct_run" == "my-images:ubuntu.22.04 my-images:ubuntu.22.04" ]] &&
        pass "devsh: LOCAL_REPO set by the caller names the image" ||
        fail "devsh: with LOCAL_REPO=my-images the image built and run: $ct_build $ct_run"
    # One cache per set of depends inputs under DEV_CACHE, the same for
    # two copies; another one after a change of the inputs.
    devsh_container_run "" "$y" unit-tests
    want=$(env DEV_CACHE="$cache" "$x/dev.sh" cache 2>&1 | sed -n 's/^CONTAINER_CACHE=//p')
    [[ "$mx" =~ ^$cache/container/[0-9a-f]{16}$ && "$ct_mount" == "$mx" && "$want" == "$mx" ]] &&
        pass "devsh: two copies with one DEV_CACHE mount one container cache, dev.sh cache's CONTAINER_CACHE ($mx)" ||
        fail "devsh: the copies mount $mx and $ct_mount, dev.sh cache says CONTAINER_CACHE=$want"
    local m0
    make_container_copy "$z"
    devsh_container_run "" "$z" unit-tests; m0="$ct_mount"
    mkdir -p "$z/depends/work"; : > "$z/depends/work/ignored-example.txt"
    devsh_container_run "" "$z" unit-tests
    [[ "$ct_mount" == "$m0" && "$m0" == "$mx" ]] && pass "devsh: an ignored file under depends/ keeps the container cache" ||
        fail "devsh: an ignored file under depends/ changed the container cache from $m0 to $ct_mount (x: $mx)"
    : > "$z/depends/untracked-example.txt"
    devsh_container_run "" "$z" unit-tests
    [[ "$ct_mount" != "$m0" && "$ct_mount" =~ ^$cache/container/[0-9a-f]{16}$ ]] &&
        pass "devsh: an untracked file under depends/ gives another container cache" ||
        fail "devsh: with an untracked file under depends/ the container cache is $ct_mount (before: $m0)"
    rm "$z/depends/untracked-example.txt"; echo "# changed" >> "$z/depends/packages/zlib.mk"
    devsh_container_run "" "$z" unit-tests
    [[ "$ct_mount" != "$m0" && "$ct_mount" =~ ^$cache/container/[0-9a-f]{16}$ ]] &&
        pass "devsh: a recipe change gives another container cache" ||
        fail "devsh: after a recipe change the container cache is $ct_mount (before: $m0)"
    rm -rf "$z/.git"
    devsh_container_run "" "$z" unit-tests
    [[ "$ct_mount" != "$m0" && "$ct_mount" =~ ^$cache/container/[0-9a-f]{16}$ ]] &&
        pass "devsh: a tree that is not a git checkout gets a container cache of its own" ||
        fail "devsh: a tree that is not a git checkout mounts $ct_mount"
    # run.sh alone mounts the cache dev.sh names, under DEV_CACHE or its
    # default.
    rm -f "$dlog"
    env -u LOCAL_REPO -u DEV_CACHE PATH="$bin:$PATH" STUB_DOCKER="$dlog" XDG_CACHE_HOME="$d/xdg" \
        "$x/ci/containers/run.sh" --no-image-build ubuntu.22.04 unit-tests > "$d/out.txt" 2>&1 || true
    got=$(sed -n 's/.* -v \([^ ]*\):\/cache .*/\1/p' "$dlog" 2>/dev/null | head -n 1)
    want=$(env -u DEV_CACHE XDG_CACHE_HOME="$d/xdg" "$x/dev.sh" cache 2>&1 | sed -n 's/^CONTAINER_CACHE=//p')
    [[ -n "$want" && "$got" == "$want" && "$want" == "$d/xdg/yacoin-dev/container/"* ]] &&
        pass "devsh: run.sh alone mounts dev.sh's container cache ($got)" ||
        fail "devsh: run.sh alone mounts $got, dev.sh cache says CONTAINER_CACHE=$want"
    devsh_container_run "" "$x" --cache "$d/own" unit-tests; got="$ct_mount"
    devsh_container_run "" "$x" --no-cache unit-tests
    [[ "$got" == "$d/own" && "$ct_run" == "$bx" && "$ct_line" != *":/cache"* ]] &&
        pass "devsh: --cache DIR mounts DIR, --no-cache no cache" ||
        fail "devsh: --cache mounts $got; --no-cache runs: $ct_line"
    # --cpus reaches docker run.
    devsh_container_run "" "$x" --cpus 4 unit-tests; got="$ct_line"
    devsh_container_run "" "$x" unit-tests
    [[ " $got " == *" --cpus 4 "* && "$got" == *" $bx unit-tests" && "$ct_line" != *--cpus* ]] &&
        pass "devsh: container --cpus 4 runs: $got" || fail "devsh: container --cpus 4 runs: $got; without: $ct_line"
    expect_status 2 "devsh: run.sh --cpus without a value exits 2" env -u LOCAL_REPO "$x/ci/containers/run.sh" --cpus
    grep -q -- "--cpus needs a value" "$work/out.txt" || fail "devsh: run.sh --cpus says: $(cat "$work/out.txt")"
    expect_status 2 "devsh: run.sh --cpus with an empty value exits 2" \
        env -u LOCAL_REPO "$x/ci/containers/run.sh" --cpus "" ubuntu.22.04
    grep -q -- "--cpus needs a value" "$work/out.txt" || fail "devsh: run.sh --cpus \"\" says: $(cat "$work/out.txt")"
    expect_status 2 "devsh: run.sh --print-tag of an unknown image exits 2" \
        env -u LOCAL_REPO "$x/ci/containers/run.sh" --print-tag no-such-image
    grep -q "unknown image 'no-such-image'" "$work/out.txt" ||
        fail "devsh: run.sh --print-tag no-such-image says: $(cat "$work/out.txt")"
    rm -f "$dlog"
    expect_status 1 "devsh: container --no-image-build without the image fails" \
        env -u LOCAL_REPO PATH="$bin:$PATH" STUB_DOCKER="$dlog" STUB_NO_IMAGE=1 DEV_CACHE="$cache" \
        "$x/dev.sh" container --no-image-build unit-tests
    out=$(cat "$work/out.txt")
    [[ "$out" == *"$bx"*"without --no-image-build"* ]] && ! grep -q -- '--cidfile' "$dlog" 2>/dev/null &&
        pass "devsh: container --no-image-build without the image names it and starts nothing" ||
        fail "devsh: container --no-image-build without the image says: $out"
    devsh_lock "$bin"
}

# The lock of a container cache: held for the depends phase of a run (until
# the image's line after its depends build), or for the whole run without
# that line; docker run's output and exit status come through.
devsh_lock() {
    local bin="$1" ev="$work/devsh/c/events" stubc="$work/devsh/c/container" px status
    local gen="== Generating the build system ==" mac="== Building yacoin for macOS =="
    write_stub_container "$stubc"
    # Two copies with one depends key: the second waits for the first's
    # depends phase.
    rm -f "$ev"
    devsh_lock_run "$x" x unit-tests STUB_DEPENDS_TIME=2 STUB_MARKER="$gen" > "$d/x.out" 2>&1 & px=$!
    wait_for "dstart x" "$ev" || fail "devsh: the first locked run did not start"
    devsh_lock_run "$y" y unit-tests STUB_MARKER="$gen" > "$d/y.out" 2>&1 || fail "devsh: the second locked run failed"
    wait "$px" || fail "devsh: the first locked run failed"
    got=$(tr '\n' ' ' < "$ev")
    [[ "$got" == "dstart x dend x "*"dstart y"* ]] && grep -q "Waiting" "$d/y.out" &&
        pass "devsh: two runs on one container cache run their depends phases one after the other: $got" ||
        fail "devsh: two runs on one container cache: $got"
    # After the line, the next run starts its depends phase while the first
    # still runs.
    rm -f "$ev"
    devsh_lock_run "$x" x unit-tests STUB_MARKER="$gen" STUB_WAIT_FOR=y STUB_WAIT_TENTHS=200 > "$d/x.out" 2>&1 & px=$!
    wait_for "rest x" "$ev" || fail "devsh: the first run did not get past its depends phase"
    devsh_lock_run "$y" y unit-tests STUB_MARKER="$gen" > "$d/y.out" 2>&1 || fail "devsh: the second run failed"
    wait "$px" || fail "devsh: the first run failed"
    got=$(tr '\n' ' ' < "$ev")
    [[ " $got " == *" met x "* ]] && pass "devsh: after its depends phase a run lets the next one start: $got" ||
        fail "devsh: after the depends phase of the first run: $got"
    # Without the line the lock is held until the run ends.
    rm -f "$ev"
    devsh_lock_run "$x" x unit-tests STUB_WAIT_FOR=y STUB_WAIT_TENTHS=25 > "$d/x.out" 2>&1 & px=$!
    wait_for "rest x" "$ev" || fail "devsh: the first run without the line did not get past its depends phase"
    devsh_lock_run "$y" y unit-tests > "$d/y.out" 2>&1 || fail "devsh: the second run failed"
    wait "$px" || fail "devsh: the first run failed"
    got=$(tr '\n' ' ' < "$ev")
    [[ "$got" == *"end x dstart y"* && " $got " != *" met x "* ]] &&
        pass "devsh: a run without the line after its depends build holds the lock to its end: $got" ||
        fail "devsh: a run without the line after its depends build: $got"
    # macOS: its start line is not the line after the depends build.
    rm -f "$ev"
    devsh_lock_run "$x" x macos STUB_START_LINE="== Building yacoin for macOS in /src with 4 jobs ==" \
        STUB_DEPENDS_TIME=2 STUB_MARKER="$mac" > "$d/x.out" 2>&1 & px=$!
    wait_for "dstart x" "$ev" || fail "devsh: the first macos run did not start"
    devsh_lock_run "$y" y macos STUB_MARKER="$mac" > "$d/y.out" 2>&1 || fail "devsh: the second macos run failed"
    wait "$px" || fail "devsh: the first macos run failed"
    got=$(tr '\n' ' ' < "$ev")
    [[ "$got" == "dstart x dend x "*"dstart y"* ]] &&
        pass "devsh: the macos start line keeps the lock: $got" || fail "devsh: two macos runs: $got"
    # The output, byte for byte, and the exit status of docker run.
    printf 'after \\ -e %%s \r\n\0last line without a newline' > "$d/tail"
    { printf '%s\n' "== start ==" "$gen"; cat "$d/tail"; } > "$d/want.out"
    status=0
    env -u LOCAL_REPO PATH="$bin:$PATH" STUB_RUN="$stubc" STUB_START_LINE="== start ==" STUB_MARKER="$gen" \
        STUB_TAIL_FILE="$d/tail" STUB_STATUS=3 DEV_CACHE="$cache" \
        "$x/ci/containers/run.sh" --no-image-build ubuntu.22.04 unit-tests > "$d/run.out" 2> "$d/run.err" || status=$?
    [[ "$status" == 3 ]] && cmp -s "$d/want.out" "$d/run.out" &&
        pass "devsh: run.sh passes the output and exit status 3 of docker run on" ||
        fail "devsh: run.sh exits $status with the output: $(od -c "$d/run.out" | head -n 5)"
    printf 'after \\ -e %%s \r\nlast line without a newline' > "$d/tail"
    { printf '%s\n' "== start =="; cat "$d/tail"; } > "$d/want.out"
    status=0
    env -u LOCAL_REPO PATH="$bin:$PATH" STUB_RUN="$stubc" STUB_START_LINE="== start ==" STUB_TAIL_FILE="$d/tail" \
        DEV_CACHE="$cache" "$x/ci/containers/run.sh" --no-image-build ubuntu.22.04 unit-tests \
        > "$d/run.out" 2> "$d/run.err" || status=$?
    [[ "$status" == 0 ]] && cmp -s "$d/want.out" "$d/run.out" &&
        pass "devsh: run.sh passes the output of docker run on without the line after the depends build" ||
        fail "devsh: run.sh without the line exits $status with the output: $(od -c "$d/run.out" | head -n 5)"
    # Each entrypoint prints that line once, after its depends build.
    local f m mk n
    for f in "entrypoint.sh:$gen" "entrypoint.windows.sh:== Building yacoin ==" "entrypoint.macos.sh:$mac"; do
        mk=$(grep -n -m1 'make "${depends_args\[@\]}"' "$HERE/${f%%:*}" | cut -d: -f1)
        m=$(grep -n -- "^ *echo \"${f#*:}\"\$" "$HERE/${f%%:*}" | cut -d: -f1 | tr '\n' ' ')
        n=$(wc -w <<< "$m")
        [[ -n "$mk" && "$n" == 1 && "${m% }" -gt "$mk" ]] &&
            pass "devsh: ${f%%:*} prints '${f#*:}' once, after its depends build" ||
            fail "devsh: ${f%%:*}: depends build at line ${mk:-none}, '${f#*:}' at line(s) ${m:-none}"
    done
}

step_devsh() {
    local a="$work/devsh/a" b="$work/devsh/other/b" c="$work/devsh/cache" out want got pa pb
    make_devsh_copy "$a"; make_devsh_copy "$b"
    got=$(dev_cache "$a" HOME="$work/home" XDG_CACHE_HOME="$work/xdg")
    [[ "$got" == *"DEV_CACHE=$work/xdg/yacoin-dev"* ]] && pass "devsh: default cache under XDG_CACHE_HOME" ||
        fail "devsh: default cache under XDG_CACHE_HOME: $got"
    got=$(dev_cache "$a" HOME="$work/home")
    [[ "$got" == *"DEV_CACHE=$work/home/.cache/yacoin-dev"* && "$got" == *"CCACHE_DIR=$work/home/.cache/yacoin-dev/ccache"* ]] &&
        pass "devsh: default cache under HOME" || fail "devsh: default cache under HOME: $got"
    out=$(env DEV_CACHE="$c" "$a/dev.sh" 2>&1) || true
    [[ "$out" == *"$c"* ]] && pass "devsh: the help shows the cache" || fail "devsh: the help does not show $c"
    pa=$(depends_prefix "$a" "$c")
    pb=$(depends_prefix "$b" "$c")
    want="^$c/depends/[0-9a-f]{16}/x86_64-pc-linux-gnu\$"
    [[ "$pa" =~ $want && "$pa" == "$pb" ]] && pass "devsh: DEV_CACHE, one depends prefix for two copies ($pa)" ||
        fail "devsh: depends prefixes: $pa and $pb"
    mkdir -p "$b/depends/work" "$b/depends/built"; : > "$b/depends/work/x"; : > "$b/depends/built/x"
    pb=$(depends_prefix "$b" "$c")
    [[ -n "$pb" && "$pa" == "$pb" ]] && pass "devsh: ignored files under depends/ keep the prefix" ||
        fail "devsh: ignored files under depends/ changed the prefix to $pb"
    # A recipe file not yet added to git counts, also when it changes.
    local pn
    mkdir -p "$b/depends/patches/miniupnpc"; echo "a" > "$b/depends/patches/miniupnpc/new.patch"
    pn=$(depends_prefix "$b" "$c")
    echo "b" > "$b/depends/patches/miniupnpc/new.patch"
    pb=$(depends_prefix "$b" "$c")
    [[ "$pn" =~ $want && "$pb" =~ $want && "$pn" != "$pa" && "$pb" != "$pn" ]] &&
        pass "devsh: an untracked patch, and a change to it, give a new prefix" ||
        fail "devsh: an untracked patch gave the prefixes $pn and then $pb (tracked only: $pa)"
    echo "# changed" >> "$b/depends/packages/zlib.mk"
    pb=$(depends_prefix "$b" "$c")
    [[ "$pa" != "$pb" && "$pb" =~ $want ]] && pass "devsh: a recipe change gives a new prefix ($pb)" ||
        fail "devsh: a recipe change gave the prefix $pb"
    # A stub make records its arguments and the start and end of its run,
    # writes the config.site of the prefix it gets, and fails as make does
    # on the target named by STUB_NO_RULE. (b has other
    # recipes now, so both runs build.)
    local bin="$work/devsh/bin" log="$work/devsh/make.log"
    mkdir -p "$bin"; rm -f "$log"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s
' '#!/bin/bash' 'echo "start $*" >> "$STUB_LOG"; sleep "${STUB_MAKE_SLEEP:-1}"; echo "end" >> "$STUB_LOG"' \
        '[[ -z ${STUB_NO_RULE:-} || " $* " != *" $STUB_NO_RULE "* ]] ||' \
        '    { echo "make: *** No rule to make target '\''$STUB_NO_RULE'\''.  Stop." >&2; exit 2; }' \
        'for x in "$@"; do [[ $x != *_prefix=* ]] || { mkdir -p "${x#*=}/share"; : > "${x#*=}/share/config.site"; }; done' \
        > "$bin/make"
    chmod +x "$bin/make"
    PATH="$bin:$PATH" STUB_LOG="$log" DEV_CACHE="$c" "$a/dev.sh" depends > "$work/devsh/a.log" 2>&1 & local pid=$!
    PATH="$bin:$PATH" STUB_LOG="$log" DEV_CACHE="$c" "$b/dev.sh" depends > "$work/devsh/b.log" 2>&1 || fail "devsh: depends in b"
    wait "$pid" || fail "devsh: depends in a"
    got=$(sed 's/ .*//' "$log" 2>/dev/null | tr '\n' ' ')
    [[ "$got" == "start end start end " ]] && pass "devsh: two depends runs one after the other" ||
        fail "devsh: two depends runs overlap or did not run: $got"
    got=$(grep -m1 "^start -C $a/depends " "$log" || echo "no run in a")
    local arg ok=1
    for arg in "x86_64_linux_prefix=$pa" "BASE_CACHE=${pa%/*}/built" "SOURCES_PATH=$c/depends/sources" \
               "base_build_dir=${pa%/*}/work/build" NO_QT=1; do
        [[ " $got " == *" $arg "* ]] || { fail "devsh: depends gets no $arg: $got"; ok=0; }
    done
    (( ok == 0 )) || pass "devsh: depends builds into the cache: ${got#start }"
    [[ -f "$c/ccache/ccache.conf" ]] && pass "devsh: ccache.conf created" || fail "devsh: no $c/ccache/ccache.conf"
    # A run with the same inputs as the last successful one leaves the prefix
    # alone (depends would unpack it again); another Qt choice runs make.
    local runs
    runs=$(grep -c '^start' "$log")
    PATH="$bin:$PATH" STUB_LOG="$log" DEV_CACHE="$c" "$a/dev.sh" depends > "$work/devsh/a.log" 2>&1 || fail "devsh: second depends in a"
    [[ "$(grep -c '^start' "$log")" == "$runs" ]] && pass "devsh: a second depends run with the same inputs skips make" ||
        fail "devsh: a second depends run with the same inputs ran make"
    PATH="$bin:$PATH" STUB_LOG="$log" DEV_CACHE="$c" "$a/dev.sh" depends qt > "$work/devsh/a.log" 2>&1 || fail "devsh: depends qt in a"
    got=$(tail -n 2 "$log" | head -n 1)
    [[ "$(grep -c '^start' "$log")" == $((runs + 1)) && " $got " != *" NO_QT=1 "* ]] &&
        pass "devsh: depends qt after depends runs make" || fail "devsh: depends qt after depends did not run make: $got"
    # A build directory configured against another prefix is refused.
    mkdir -p "$a/build/dev"; : > "$a/build/dev/Makefile"; echo "CPPFLAGS=-I$a/depends/x86_64-pc-linux-gnu/include" > "$a/build/dev/config.status"
    expect_status 1 "devsh: a build directory of another prefix is refused" env DEV_CACHE="$c" "$a/dev.sh" build dev
    grep -q 'rm -rf build/dev' "$work/out.txt" || fail "devsh: the refusal does not say to remove build/dev"
    # container passes the mode to run.sh, and run.sh starts the container
    # with ccache disabled (as the CI jobs) for the sanitizer modes
    # (unit-tests-asan, unit-tests-tsan, fuzz-corpus, functional-tests-asan)
    # only, and
    # with Docker's seccomp filter off for unit-tests-tsan only (a stub docker
    # that records its arguments; run.sh and an image's Dockerfile copied
    # into a).
    mkdir -p "$a/ci/containers"
    cp "$HERE/run.sh" "$a/ci/containers/"; : > "$a/ci/containers/Dockerfile.ubuntu.22.04"
    write_stub_docker "$bin/docker"
    local dlog="$work/devsh/docker.log" mode tag
    tag=$(env -u LOCAL_REPO "$a/ci/containers/run.sh" --print-tag ubuntu.22.04 2>/dev/null) || tag="(no --print-tag)"
    for mode in unit-tests-tsan unit-tests-asan fuzz-corpus functional-tests-asan unit-tests functional-tests build-low-difficulty; do
        rm -f "$dlog"
        PATH="$bin:$PATH" STUB_DOCKER="$dlog" DEV_CACHE="$c" env -u LOCAL_REPO "$a/dev.sh" container --no-image-build \
            --no-cache "$mode" > "$work/devsh/a.log" 2>&1 || fail "devsh: container $mode in a"
        got=$(grep -m1 -- '--cidfile' "$dlog" 2>/dev/null || echo "no docker run")
        if [[ "$got" != *" $tag $mode" ]]; then
            fail "devsh: container $mode runs: $got"
        elif [[ $mode == unit-tests-tsan && " $got " == *" --security-opt seccomp=unconfined "* &&
                " $got " == *" -e CCACHE_DISABLE=1 "* ]]; then
            pass "devsh: container $mode runs the image with the seccomp filter off and ccache disabled: $got"
        elif [[ $mode == *-asan || $mode == fuzz-corpus ]] && [[ "$got" != *seccomp* && " $got " == *" -e CCACHE_DISABLE=1 "* ]]; then
            pass "devsh: container $mode runs the image with the seccomp filter on and ccache disabled: $got"
        elif [[ $mode != *-[at]san && "$got" != *seccomp* && "$got" != *CCACHE_DISABLE* ]]; then
            pass "devsh: container $mode runs the image with the seccomp filter on and ccache enabled: $got"
        else
            fail "devsh: container $mode runs: $got"
        fi
    done
    # run.sh passes SANITIZE and FTEST_SHARD on to the container when set.
    local v
    for v in SANITIZE FTEST_SHARD; do
        rm -f "$dlog"
        PATH="$bin:$PATH" STUB_DOCKER="$dlog" DEV_CACHE="$c" env -u SANITIZE -u FTEST_SHARD "$a/dev.sh" container \
            --no-image-build --no-cache unit-tests-asan > "$work/devsh/a.log" 2>&1 || fail "devsh: container without $v"
        got=$(grep -m1 -- '--cidfile' "$dlog" 2>/dev/null || echo "no docker run")
        [[ " $got " != *" -e $v "* ]] || fail "devsh: container passes $v although it is not set: $got"
        rm -f "$dlog"
        PATH="$bin:$PATH" STUB_DOCKER="$dlog" DEV_CACHE="$c" env "$v=1/2" "$a/dev.sh" container \
            --no-image-build --no-cache unit-tests-asan > "$work/devsh/a.log" 2>&1 || fail "devsh: container with $v"
        got=$(grep -m1 -- '--cidfile' "$dlog" 2>/dev/null || echo "no docker run")
        [[ " $got " == *" -e $v "* ]] && pass "devsh: container passes $v when it is set: $got" ||
            fail "devsh: container does not pass $v: $got"
    done
    # cov runs both coverage targets in one build, and every functional test
    # script, also with an FTEST_SHARD in the environment (the stub make
    # records the arguments; a configured build directory, so cov only runs
    # make).
    mkdir -p "$a/build/cov"; : > "$a/build/cov/Makefile"
    rm -f "$log"
    PATH="$bin:$PATH" STUB_LOG="$log" DEV_CACHE="$c" FTEST_SHARD=1/2 "$a/dev.sh" cov > "$work/devsh/a.log" 2>&1 || true
    got=$(grep -m1 ' cov-functional$' "$log" || echo "no make cov-functional")
    [[ " $got " == *" FTEST_SHARD= "* ]] && pass "devsh: cov runs make cov-functional with FTEST_SHARD empty: ${got#start }" ||
        fail "devsh: cov with FTEST_SHARD=1/2 in the environment runs: $got"
    got=$(grep -E ' cov-(unit|functional)$' "$log" | sed 's/^start -C \([^ ]*\) .* \(cov-[a-z]*\)$/\1 \2/' | tr '\n' ' ')
    [[ "$got" == "$a/build/cov cov-unit $a/build/cov cov-functional " ]] &&
        pass "devsh: cov runs both coverage targets in build/cov" || fail "devsh: cov runs: $got"
    # ftest runs the scripts on regtest, but those of the regtest list, on
    # the dev build (a runner that records its arguments); dev.sh has no
    # variant with the low-difficulty parameters.
    mkdir -p "$a/build/dev/test/functional" "$a/test/functional"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/bash' 'echo "$*" > "$STUB_ENV.args"' > "$a/build/dev/test/functional/test_runner.py"
    chmod +x "$a/build/dev/test/functional/test_runner.py"
    rm -f "$a/build/dev/config.status"
    : > "$a/test/functional/wallet_x.py"
    local select="--chain=regtest --exclude-file=$a/test/functional/regtest-excluded-scripts" ftest_args
    # Without a named script the list is left out, also when an option's
    # separate value names a script or is no option; a named script (with or
    # without .py, or as a path) runs as given.
    for ftest_args in "--failfast -j 2" "--filter wallet" "--exclude wallet_x.py --shard 1/2" \
                      "--tmpdirprefix /tmp/x" "wallet_x.py" "wallet_x" "test/functional/wallet_x.py -j 2"; do
        rm -f "$work/devsh/ftest.args"
        # shellcheck disable=SC2086 # the arguments are split on purpose
        PATH="$bin:$PATH" STUB_LOG="$log" STUB_ENV="$work/devsh/ftest" DEV_CACHE="$c" "$a/dev.sh" ftest $ftest_args \
            > "$work/devsh/a.log" 2>&1 || fail "devsh: ftest $ftest_args in a"
        got=$(cat "$work/devsh/ftest.args" 2>/dev/null || echo "the runner did not run")
        want="$select $ftest_args"
        [[ $ftest_args != *wallet_x* || $ftest_args == --exclude* ]] || want="--chain=regtest $ftest_args"
        [[ "$got" == *" $want" ]] && pass "devsh: ftest $ftest_args runs: test_runner.py $got" ||
            fail "devsh: ftest $ftest_args runs: test_runner.py $got (want ... $want)"
    done
    for v in func cov-func; do
        expect_status 2 "devsh: the variant $v is refused" env DEV_CACHE="$c" "$a/dev.sh" build "$v"
    done
    # build passes a target to make in build/<variant>/src: a target given as
    # src/<path> is built as <path> with one line on stderr, every other one
    # goes to make unchanged, and make's error for an unknown target and its
    # exit status come through.
    local err="$work/devsh/err.log" tgt what
    for tgt in src/test/test_bitcoin test/test_bitcoin src/ ""; do
        rm -f "$log"; what="build dev${tgt:+ $tgt}"
        PATH="$bin:$PATH" STUB_LOG="$log" DEV_CACHE="$c" "$a/dev.sh" build dev ${tgt:+"$tgt"} > "$work/devsh/a.log" 2> "$err" ||
            fail "devsh: $what in a"
        got=$(grep "^start -C $a/build/dev[/ ]" "$log" || echo "no make run")
        out=$(cat "$work/devsh/a.log" "$err")
        case "$tgt" in
            src/?*) want="start -C $a/build/dev/src -j[0-9]+ ${tgt#src/}" ;;
            ?*) want="start -C $a/build/dev/src -j[0-9]+ $tgt" ;;
            *) want="start -C $a/build/dev -j[0-9]+" ;;
        esac
        if [[ ! "$got" =~ ^$want$ ]]; then
            fail "devsh: $what runs: $got (want $want)"
        elif [[ $tgt == src/?* ]]; then
            [[ "$(wc -l < "$err")" == 1 && "$(cat "$err")" == *"relative to src/"*" ${tgt#src/}" &&
                "$(grep -c -- "$tgt" "$log")" == 0 && "$(grep -c -- "${tgt#src/}" <<< "$out")" == 1 ]] &&
                pass "devsh: $what runs ${got#start } and says so: $(cat "$err")" ||
                fail "devsh: $what runs ${got#start }, with the output: $out"
        else
            [[ ! -s "$err" ]] && pass "devsh: $what runs ${got#start }" ||
                fail "devsh: $what runs ${got#start }, with on stderr: $(cat "$err")"
        fi
    done
    expect_status 2 "devsh: build dev with an unknown target fails as make does" \
        env PATH="$bin:$PATH" STUB_LOG="$log" STUB_NO_RULE=no/such/target DEV_CACHE="$c" "$a/dev.sh" build dev no/such/target
    grep -q "No rule to make target 'no/such/target'" "$work/out.txt" ||
        fail "devsh: build dev no/such/target does not name the target: $(cat "$work/out.txt")"
    out=$(env DEV_CACHE="$c" "$a/dev.sh" 2>&1) || true
    got=$(awk '/^  build /{p=1; print; next} p && /^      /{print; next} {p=0}' <<< "$out" | tr -s ' \n' '  ')
    [[ "$got" == *"relative to src/"*"test/test_bitcoin"* ]] && pass "devsh: the help says build's target is relative to src/" ||
        fail "devsh: the help's build entry: $got"
    # asan runs the suites with the tree's LeakSanitizer suppressions and its
    # default options, and keeps the caller's own (a configured build
    # directory, the stub make, and a runner that records its environment).
    mkdir -p "$a/build/asan" "$a/contrib/devtools"; : > "$a/build/asan/Makefile"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/bash' 'printf "%s\n" "$ASAN_OPTIONS" "$LSAN_OPTIONS" "$UBSAN_OPTIONS" > "$STUB_ENV"' \
        'echo "$*" > "$STUB_ENV.args"' > "$a/contrib/devtools/run-unit-suites.sh"
    chmod +x "$a/contrib/devtools/run-unit-suites.sh"
    local supp="suppressions=$a/test/sanitizer_suppressions/lsan" envlog="$work/devsh/asan-env"
    rm -f "$envlog"
    PATH="$bin:$PATH" STUB_LOG="$log" STUB_ENV="$envlog" DEV_CACHE="$c" \
        env -u ASAN_OPTIONS -u LSAN_OPTIONS -u UBSAN_OPTIONS "$a/dev.sh" asan > "$work/devsh/a.log" 2>&1 || fail "devsh: asan in a"
    got=$(tr '\n' ' ' < "$envlog" 2>/dev/null || echo "the runner did not run")
    [[ "$got" == "detect_leaks=1 $supp print_stacktrace=1 " ]] &&
        pass "devsh: asan runs the suites with the suppressions and the default options" ||
        fail "devsh: asan runs the suites with: $got"
    # asan leaves the test cases of the tree's list out (an option of the
    # runner, before the binary), also with selectors; unit does not.
    local excl="--exclude-cases $a/test/sanitizer_suppressions/asan-excluded-cases"
    got=$(cat "$envlog.args" 2>/dev/null || echo "the runner did not run")
    [[ "$got" == "$excl $a/build/asan/src/test/test_bitcoin "* ]] &&
        pass "devsh: asan runs: run-unit-suites.sh $got" || fail "devsh: asan runs: run-unit-suites.sh $got"
    rm -f "$envlog.args"
    PATH="$bin:$PATH" STUB_LOG="$log" STUB_ENV="$envlog" DEV_CACHE="$c" "$a/dev.sh" asan a_tests b_tests/b_case \
        > "$work/devsh/a.log" 2>&1 || fail "devsh: asan with selectors in a"
    got=$(cat "$envlog.args" 2>/dev/null || echo "the runner did not run")
    [[ "$got" == "$excl $a/build/asan/src/test/test_bitcoin "*" a_tests b_tests/b_case" ]] &&
        pass "devsh: asan with selectors runs: run-unit-suites.sh $got" ||
        fail "devsh: asan with selectors runs: run-unit-suites.sh $got"
    rm -f "$envlog.args" "$a/build/dev/config.status"
    PATH="$bin:$PATH" STUB_LOG="$log" STUB_ENV="$envlog" DEV_CACHE="$c" "$a/dev.sh" unit a_tests \
        > "$work/devsh/a.log" 2>&1 || fail "devsh: unit in a"
    got=$(cat "$envlog.args" 2>/dev/null || echo "the runner did not run")
    [[ "$got" == "$a/build/dev/src/test/test_bitcoin "*" a_tests" ]] &&
        pass "devsh: unit runs: run-unit-suites.sh $got" || fail "devsh: unit runs: run-unit-suites.sh $got"
    rm -f "$envlog"
    PATH="$bin:$PATH" STUB_LOG="$log" STUB_ENV="$envlog" DEV_CACHE="$c" ASAN_OPTIONS=detect_leaks=0 \
        LSAN_OPTIONS=verbosity=1 UBSAN_OPTIONS=halt_on_error=1 "$a/dev.sh" asan > "$work/devsh/a.log" 2>&1 ||
        fail "devsh: asan in a with the caller's options"
    got=$(tr '\n' ' ' < "$envlog" 2>/dev/null || echo "the runner did not run")
    [[ "$got" == "detect_leaks=1:detect_leaks=0 verbosity=1:$supp print_stacktrace=1:halt_on_error=1 " ]] &&
        pass "devsh: asan keeps the caller's options and adds the suppressions" ||
        fail "devsh: asan with the caller's options runs the suites with: $got"
    devsh_stamp "$bin"
    devsh_container "$bin"
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
        # An unknown mode must be rejected before anything is built, with
        # the list of the modes.
        expect_status 2 "smoke: $image: unknown mode rejected" docker run --rm "$tag" no-such-mode
        grep -q 'unit-tests-asan' "$work/out.txt" || fail "smoke: $image: the mode list does not name unit-tests-asan"
        grep -q 'unit-tests-tsan' "$work/out.txt" || fail "smoke: $image: the mode list does not name unit-tests-tsan"
        grep -q 'fuzz-corpus' "$work/out.txt" || fail "smoke: $image: the mode list does not name fuzz-corpus"
        grep -q 'functional-tests-asan' "$work/out.txt" || fail "smoke: $image: the mode list does not name functional-tests-asan"
        # The modes that run tests must stop early, with a clear message, on
        # a tree without the scripts and targets they need.
        for mode in unit-tests unit-tests-asan unit-tests-tsan fuzz-corpus functional-tests functional-tests-asan build-low-difficulty cov-unit cov-functional; do
            expect_status 1 "smoke: $image: $mode stops on a tree without its scripts" \
                docker run --rm -v "$fake:/src" "$tag" "$mode"
            grep -q 'error: ' "$work/out.txt" || fail "smoke: $image: $mode gave no 'error: ' message"
        done
        # The release build modes configure in place with these flags (a
        # stub tree whose configure records its arguments and stops).
        local args stub="$work/configure-stub" want_low has_low
        for mode in build build-low-difficulty; do
            make_configure_stub "$stub" "$tag"
            docker run --rm -v "$stub:/src" "$tag" "$mode" > "$work/out.txt" 2>&1 || true
            args=$(cat "$stub/configure-args" 2>/dev/null || echo "configure did not run")
            want_low=0 has_low=0
            [[ $mode != build-low-difficulty ]] || want_low=1
            [[ " $args " != *" --enable-low-difficulty-for-development "* ]] || has_low=1
            if [[ " $args " == *" --enable-glibc-back-compat "* && " $args " == *" LDFLAGS=-static-libstdc++ "* &&
                  $want_low == "$has_low" ]]; then
                pass "smoke: $image: $mode configures with: $args"
            else
                tail -n 5 "$work/out.txt"; fail "smoke: $image: $mode configure arguments: $args"
            fi
        done
        # build-low-difficulty runs every unit test suite of the test_bitcoin
        # it built in the tree, JOBS at a time, logs to its own directory,
        # and fails when a suite fails or the build made no test_bitcoin.
        # Then it runs the scripts of the regtest list in the tree,
        # FTEST_JOBS at a time, and fails when the runner fails.
        local want_args="/src/src/test/test_bitcoin /src/build/docker-$image/build-low-difficulty/unit-test-logs 3"
        local want_runner ftest_jobs
        for ftest_jobs in "" 2; do
            want_runner="-j ${ftest_jobs:-4} --tmpdirprefix=/src/build/docker-$image/build-low-difficulty/test/tmp"
            want_runner+=" --include-file=/src/test/functional/regtest-excluded-scripts"
            make_unit_stub "$stub" "$tag" 0
            docker run --rm -v "$stub:/src" -e JOBS=3 ${ftest_jobs:+-e FTEST_JOBS="$ftest_jobs"} "$tag" build-low-difficulty \
                > "$work/out.txt" 2>&1 && status=0 || status=$?
            args=$(cat "$stub/suites-args" 2>/dev/null || echo "run-unit-suites.sh did not run")
            if [[ $status == 0 && "$args" == "$want_args" ]]; then
                pass "smoke: $image: build-low-difficulty runs: run-unit-suites.sh $args"
            else
                tail -n 5 "$work/out.txt"
                fail "smoke: $image: build-low-difficulty (exit status $status) runs: run-unit-suites.sh $args"
            fi
            args=$(cat "$stub/runner-args" 2>/dev/null || echo "test_runner.py did not run")
            [[ "$args" == "$want_runner" ]] &&
                pass "smoke: $image: build-low-difficulty (FTEST_JOBS=${ftest_jobs:-unset}) runs: test_runner.py $args" ||
                fail "smoke: $image: build-low-difficulty (FTEST_JOBS=${ftest_jobs:-unset}) runs: test_runner.py $args (want $want_runner)"
        done
        make_unit_stub "$stub" "$tag" 0 4
        expect_status 4 "smoke: $image: build-low-difficulty fails when a functional test fails" \
            docker run --rm -v "$stub:/src" "$tag" build-low-difficulty
        make_unit_stub "$stub" "$tag" 0
        rm "$stub/test/functional/regtest-excluded-scripts"
        expect_status 1 "smoke: $image: build-low-difficulty stops on a tree without its list of scripts" \
            docker run --rm -v "$stub:/src" "$tag" build-low-difficulty
        grep -q 'error: .*test/functional/regtest-excluded-scripts' "$work/out.txt" ||
            fail "smoke: $image: build-low-difficulty without its list gave no 'error: ' message"
        [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: build-low-difficulty configured without its list"
        make_unit_stub "$stub" "$tag" 0
        printf '#!/bin/sh\n# --chain --exclude-file\nexit 0\n' > "$stub/test/functional/test_runner.py"
        expect_status 1 "smoke: $image: build-low-difficulty stops on a runner without --include-file" \
            docker run --rm -v "$stub:/src" "$tag" build-low-difficulty
        grep -q -- "error: .*--include-file" "$work/out.txt" ||
            fail "smoke: $image: build-low-difficulty with a runner without --include-file gave no 'error: ' message naming it"
        [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: build-low-difficulty configured with a runner without --include-file"
        make_unit_stub "$stub" "$tag" 3
        expect_status 3 "smoke: $image: build-low-difficulty fails when a unit test suite fails" \
            docker run --rm -v "$stub:/src" "$tag" build-low-difficulty
        [[ -f "$stub/suites-args" ]] || fail "smoke: $image: the failing run did not reach run-unit-suites.sh"
        make_unit_stub "$stub" "$tag" 0
        rm "$stub/src/test/test_bitcoin"
        expect_status 1 "smoke: $image: build-low-difficulty stops when the build made no test_bitcoin" \
            docker run --rm -v "$stub:/src" "$tag" build-low-difficulty
        grep -q 'error: the build made no src/test/test_bitcoin' "$work/out.txt" ||
            fail "smoke: $image: a build without test_bitcoin gave no 'error: ' message"
        [[ ! -f "$stub/suites-args" ]] || fail "smoke: $image: run-unit-suites.sh ran without test_bitcoin"
        # functional-tests configures out of tree with -O1, without the
        # low-difficulty parameters.
        make_configure_stub "$stub" "$tag"
        docker run --rm -v "$stub:/src" "$tag" functional-tests > "$work/out.txt" 2>&1 || true
        args=$(cat "$stub/configure-args" 2>/dev/null || echo "configure did not run")
        if [[ " $args " == *" CXXFLAGS=-O1 -g "* && " $args " == *" CFLAGS=-O1 -g "* &&
              " $args " == *" --without-gui --disable-man --enable-ccache "* &&
              " $args " != *" --enable-low-difficulty-for-development "* && " $args " != *-fsanitize* ]]; then
            pass "smoke: $image: functional-tests configures with: $args"
        else
            tail -n 5 "$work/out.txt"; fail "smoke: $image: functional-tests configure arguments: $args"
        fi
        # Without the regtest list the runner would fail after the build, and
        # a runner without the options would pass them on to every script;
        # the functional modes stop before the build.
        local option other func_mode
        local list_modes=(functional-tests)
        [[ "$image" != ubuntu.22.04 ]] || list_modes+=(functional-tests-asan)
        for func_mode in "${list_modes[@]}"; do
            make_runner_stub "$stub" "$tag" 0
            rm "$stub/test/functional/regtest-excluded-scripts"
            expect_status 1 "smoke: $image: $func_mode stops on a tree without the regtest list" \
                docker run --rm -v "$stub:/src" "$tag" "$func_mode"
            grep -q 'error: .*test/functional/regtest-excluded-scripts' "$work/out.txt" ||
                fail "smoke: $image: $func_mode without the regtest list gave no 'error: ' message"
            [[ ! -f "$stub/make-goals" ]] || fail "smoke: $image: $func_mode built without the regtest list"
            for option in --chain --exclude-file; do
                other="--sanitizer-logs --exclude-file"
                [[ $option != --exclude-file ]] || other="--sanitizer-logs --chain"
                make_runner_stub "$stub" "$tag" 0
                printf '#!/bin/sh\n# %s\nexit 0\n' "$other" > "$stub/test/functional/test_runner.py"
                expect_status 1 "smoke: $image: $func_mode stops on a runner without $option" \
                    docker run --rm -v "$stub:/src" "$tag" "$func_mode"
                grep -q -- "error: .*$option" "$work/out.txt" ||
                    fail "smoke: $image: $func_mode with a runner without $option gave no 'error: ' message naming it"
                [[ ! -f "$stub/make-goals" ]] || fail "smoke: $image: $func_mode built with a runner without $option"
            done
        done
        # The sanitizer modes run in the 22.04 image only; the others refuse
        # them before the build.
        local unconfined=(--security-opt seccomp=unconfined) opts=()
        local unit_modes=(unit-tests unit-tests-asan unit-tests-tsan)
        if [[ "$image" != ubuntu.22.04 ]]; then
            unit_modes=(unit-tests)
            for mode in unit-tests-asan unit-tests-tsan fuzz-corpus functional-tests-asan; do
                opts=()
                [[ $mode != unit-tests-tsan ]] || opts=("${unconfined[@]}")
                if [[ $mode == functional-tests-asan ]]; then make_runner_stub "$stub" "$tag" 0; else make_tests_stub "$stub" "$tag" 0; fi
                expect_status 1 "smoke: $image: $mode is refused (22.04 image only)" \
                    docker run --rm ${opts[@]+"${opts[@]}"} -v "$stub:/src" "$tag" "$mode"
                grep -q "error: $mode .*Ubuntu 22.04 image" "$work/out.txt" ||
                    fail "smoke: $image: the refusal of $mode gave no 'error: ' message naming the 22.04 image"
                [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: $mode configured in this image"
            done
        fi
        if [[ "$image" == ubuntu.22.04 ]]; then
            # unit-tests-asan configures out of tree with the sanitizer
            # flags of dev.sh's asan variant and -g1, secp256k1 without
            # assembly, mainnet consensus; SANITIZE=address or undefined
            # builds with that sanitizer only (unset: both).
            local san="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
            local leg legsan
            for leg in "" address undefined; do
                case $leg in
                    address) legsan="-fsanitize=address -fno-omit-frame-pointer" ;;
                    undefined) legsan="-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined" ;;
                    *) legsan="$san" ;;
                esac
                make_configure_stub "$stub" "$tag"
                docker run --rm -v "$stub:/src" ${leg:+-e SANITIZE="$leg"} "$tag" unit-tests-asan > "$work/out.txt" 2>&1 || true
                args=$(cat "$stub/configure-args" 2>/dev/null || echo "configure did not run")
                if [[ " $args " == *" --with-asm=no "* && " $args " == *" CXXFLAGS=-O1 -g1 $legsan "* &&
                      " $args " == *" CFLAGS=-O1 -g1 $legsan "* && " $args " == *" LDFLAGS=$legsan "* &&
                      " $args " == *" --without-gui --disable-man --enable-ccache "* &&
                      " $args " != *" --enable-low-difficulty-for-development "* ]]; then
                    pass "smoke: $image: unit-tests-asan (SANITIZE=${leg:-unset}) configures with: $args"
                else
                    tail -n 5 "$work/out.txt"; fail "smoke: $image: unit-tests-asan (SANITIZE=${leg:-unset}) configure arguments: $args"
                fi
            done
            # Any other value stops the mode before the build.
            for leg in thread address,undefined; do
                make_configure_stub "$stub" "$tag"
                expect_status 1 "smoke: $image: unit-tests-asan rejects SANITIZE=$leg" \
                    docker run --rm -v "$stub:/src" -e SANITIZE="$leg" "$tag" unit-tests-asan
                grep -q 'error: SANITIZE' "$work/out.txt" || fail "smoke: $image: SANITIZE=$leg gave no 'error: SANITIZE' message"
                [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: unit-tests-asan configured with SANITIZE=$leg"
            done
            # functional-tests-asan: the flags of unit-tests-asan (both
            # sanitizers; SANITIZE does not apply), mainnet consensus, with
            # both sanitizer runtimes linked into the binaries.
            make_configure_stub "$stub" "$tag"
            docker run --rm -v "$stub:/src" -e SANITIZE=address "$tag" functional-tests-asan > "$work/out.txt" 2>&1 || true
            args=$(cat "$stub/configure-args" 2>/dev/null || echo "configure did not run")
            if [[ " $args " == *" --with-asm=no "* && " $args " == *" CXXFLAGS=-O1 -g1 $san "* &&
                  " $args " == *" CFLAGS=-O1 -g1 $san "* && " $args " == *" LDFLAGS=$san -static-libasan -static-libubsan "* &&
                  " $args " == *" --without-gui --disable-man --enable-ccache "* &&
                  " $args " != *" --enable-low-difficulty-for-development "* ]]; then
                pass "smoke: $image: functional-tests-asan configures with: $args"
            else
                tail -n 5 "$work/out.txt"; fail "smoke: $image: functional-tests-asan configure arguments: $args"
            fi
            # unit-tests-tsan configures out of tree with ThreadSanitizer and
            # mainnet consensus. Its test runs need the seccomp filter off
            # (see the entrypoint), as run.sh and the CI job start it.
            san="-fsanitize=thread -fno-omit-frame-pointer"
            make_configure_stub "$stub" "$tag"
            docker run --rm "${unconfined[@]}" -v "$stub:/src" "$tag" unit-tests-tsan > "$work/out.txt" 2>&1 || true
            args=$(cat "$stub/configure-args" 2>/dev/null || echo "configure did not run")
            if [[ " $args " == *" CXXFLAGS=-O1 -g $san "* && " $args " == *" CFLAGS=-O1 -g $san "* &&
                  " $args " == *" LDFLAGS=-fsanitize=thread "* &&
                  " $args " == *" --without-gui --disable-man --enable-ccache "* &&
                  " $args " != *" --enable-low-difficulty-for-development "* ]]; then
                pass "smoke: $image: unit-tests-tsan configures with: $args"
            else
                tail -n 5 "$work/out.txt"; fail "smoke: $image: unit-tests-tsan configure arguments: $args"
            fi
            smoke_fuzz_corpus "$image" "$tag" "$stub"
        fi
        # The out-of-tree unit test modes run every suite of the test_bitcoin
        # they built, JOBS at a time, logs in their build directory, and fail
        # when a suite fails or the build made no test_bitcoin. The sanitizer
        # modes set their sanitizers' runtime options (the tree's
        # suppressions), and only they do; unit-tests-tsan runs the suites
        # with address randomisation off.
        local env_got pers_got want_env bench_got
        for mode in "${unit_modes[@]}"; do
            opts=()
            [[ $mode != unit-tests-tsan ]] || opts=("${unconfined[@]}")
            case $mode in
                unit-tests-asan)
                    want_env="ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=suppressions=/src/test/sanitizer_suppressions/lsan"
                    want_env+=" UBSAN_OPTIONS=print_stacktrace=1 TSAN_OPTIONS=" ;;
                unit-tests-tsan)
                    want_env="ASAN_OPTIONS= LSAN_OPTIONS= UBSAN_OPTIONS= TSAN_OPTIONS=suppressions=/src/test/sanitizer_suppressions/tsan"
                    want_env+=":halt_on_error=0:second_deadlock_stack=1" ;;
                *) want_env="ASAN_OPTIONS= LSAN_OPTIONS= UBSAN_OPTIONS= TSAN_OPTIONS=" ;;
            esac
            want_args="/src/build/docker-$image/$mode/src/test/test_bitcoin /src/build/docker-$image/$mode/unit-test-logs 3"
            # unit-tests-asan, and only it, leaves the test cases of the
            # tree's list out.
            [[ $mode != unit-tests-asan ]] ||
                want_args="--exclude-cases /src/test/sanitizer_suppressions/asan-excluded-cases $want_args"
            make_tests_stub "$stub" "$tag" 0
            docker run --rm ${opts[@]+"${opts[@]}"} -v "$stub:/src" -e JOBS=3 "$tag" "$mode" > "$work/out.txt" 2>&1 &&
                status=0 || status=$?
            args=$(cat "$stub/suites-args" 2>/dev/null || echo "run-unit-suites.sh did not run")
            env_got=$(cat "$stub/suites-env" 2>/dev/null || echo "run-unit-suites.sh did not run")
            [[ "$env_got" == "$want_env" ]] && pass "smoke: $image: $mode runs the suites with: $env_got" ||
                fail "smoke: $image: $mode runs the suites with: $env_got (want $want_env)"
            if [[ $mode == unit-tests-tsan ]]; then
                # ADDR_NO_RANDOMIZE (0x0040000) in the runner's personality.
                pers_got=$(cat "$stub/suites-personality" 2>/dev/null || echo "run-unit-suites.sh did not run")
                [[ "$pers_got" =~ ^[0-9a-f]+$ ]] && (( (16#$pers_got & 16#0040000) != 0 )) &&
                    pass "smoke: $image: $mode runs the suites with address randomisation off (personality $pers_got)" ||
                    fail "smoke: $image: $mode runs the suites with the personality: $pers_got"
            fi
            if [[ $status == 0 && "$args" == "$want_args" ]]; then
                pass "smoke: $image: $mode runs: run-unit-suites.sh $args"
            else
                tail -n 5 "$work/out.txt"
                fail "smoke: $image: $mode (exit status $status) runs: run-unit-suites.sh $args"
            fi
            # unit-tests, and only it, then runs the benchmarks once in their
            # short mode, after printing the CPU model.
            bench_got=$(cat "$stub/bench-args" 2>/dev/null || echo "bench_yacoin did not run")
            if [[ $mode == unit-tests ]]; then
                if [[ "$bench_got" == "-time=0.01" ]] && grep -q '^CPU: ' "$work/out.txt"; then
                    pass "smoke: $image: $mode prints the CPU model and runs: bench_yacoin $bench_got"
                else
                    tail -n 5 "$work/out.txt"; fail "smoke: $image: $mode runs: bench_yacoin $bench_got"
                fi
                make_tests_stub "$stub" "$tag" 0
                expect_status 4 "smoke: $image: $mode fails when a benchmark fails" \
                    docker run --rm -v "$stub:/src" -e STUB_BENCH_STATUS=4 "$tag" "$mode"
                make_tests_stub "$stub" "$tag" 0 no-bench
                expect_status 1 "smoke: $image: $mode stops when the build made no bench_yacoin" \
                    docker run --rm -v "$stub:/src" "$tag" "$mode"
                grep -q 'error: the build made no .*src/bench/bench_yacoin' "$work/out.txt" ||
                    fail "smoke: $image: $mode without bench_yacoin gave no 'error: ' message"
                [[ ! -f "$stub/suites-args" ]] || fail "smoke: $image: $mode ran run-unit-suites.sh without bench_yacoin"
            else
                [[ "$bench_got" == "bench_yacoin did not run" ]] && pass "smoke: $image: $mode runs no benchmark" ||
                    fail "smoke: $image: $mode runs: bench_yacoin $bench_got"
            fi
            make_tests_stub "$stub" "$tag" 3
            expect_status 3 "smoke: $image: $mode fails when a unit test suite fails" \
                docker run --rm ${opts[@]+"${opts[@]}"} -v "$stub:/src" "$tag" "$mode"
            [[ -f "$stub/suites-args" ]] || fail "smoke: $image: the failing $mode run did not reach run-unit-suites.sh"
            make_tests_stub "$stub" "$tag" 0 no-binary
            expect_status 1 "smoke: $image: $mode stops when the build made no test_bitcoin" \
                docker run --rm ${opts[@]+"${opts[@]}"} -v "$stub:/src" "$tag" "$mode"
            grep -q 'error: the build made no .*src/test/test_bitcoin' "$work/out.txt" ||
                fail "smoke: $image: $mode without test_bitcoin gave no 'error: ' message"
            [[ ! -f "$stub/suites-args" ]] || fail "smoke: $image: $mode ran run-unit-suites.sh without test_bitcoin"
        done
        # Each sanitizer of unit-tests-asan alone runs the same suites with
        # the same list of test cases left out and the same runtime options.
        if [[ "$image" == ubuntu.22.04 ]]; then
            want_args="--exclude-cases /src/test/sanitizer_suppressions/asan-excluded-cases"
            want_args+=" /src/build/docker-$image/unit-tests-asan/src/test/test_bitcoin /src/build/docker-$image/unit-tests-asan/unit-test-logs 3"
            want_env="ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=suppressions=/src/test/sanitizer_suppressions/lsan"
            want_env+=" UBSAN_OPTIONS=print_stacktrace=1 TSAN_OPTIONS="
            for leg in address undefined; do
                make_tests_stub "$stub" "$tag" 0
                docker run --rm -v "$stub:/src" -e JOBS=3 -e SANITIZE="$leg" "$tag" unit-tests-asan > "$work/out.txt" 2>&1 &&
                    status=0 || status=$?
                args=$(cat "$stub/suites-args" 2>/dev/null || echo "run-unit-suites.sh did not run")
                env_got=$(cat "$stub/suites-env" 2>/dev/null || echo "run-unit-suites.sh did not run")
                if [[ $status == 0 && "$args" == "$want_args" && "$env_got" == "$want_env" ]]; then
                    pass "smoke: $image: unit-tests-asan (SANITIZE=$leg) runs: run-unit-suites.sh $args, with: $env_got"
                else
                    tail -n 5 "$work/out.txt"
                    fail "smoke: $image: unit-tests-asan (SANITIZE=$leg, exit status $status) runs: run-unit-suites.sh $args, with: $env_got"
                fi
            done
        fi
        # Without the suppression file every suite would fail on reading it;
        # the mode stops before the build instead.
        if [[ "$image" == ubuntu.22.04 ]]; then
            for mode in unit-tests-asan unit-tests-tsan functional-tests-asan; do
                local supp=lsan
                opts=()
                [[ $mode != unit-tests-tsan ]] || { supp=tsan; opts=("${unconfined[@]}"); }
                if [[ $mode == functional-tests-asan ]]; then make_runner_stub "$stub" "$tag" 0; else make_tests_stub "$stub" "$tag" 0; fi
                rm "$stub/test/sanitizer_suppressions/$supp"
                expect_status 1 "smoke: $image: $mode stops on a tree without its suppression file" \
                    docker run --rm ${opts[@]+"${opts[@]}"} -v "$stub:/src" "$tag" "$mode"
                grep -q "error: .*test/sanitizer_suppressions/$supp" "$work/out.txt" ||
                    fail "smoke: $image: $mode without the suppression file gave no 'error: ' message"
                [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: $mode configured without the suppression file"
            done
            # Without its list the runner would fail after the build; the
            # mode stops before it.
            make_tests_stub "$stub" "$tag" 0
            rm "$stub/test/sanitizer_suppressions/asan-excluded-cases"
            expect_status 1 "smoke: $image: unit-tests-asan stops on a tree without its list of test cases left out" \
                docker run --rm -v "$stub:/src" "$tag" unit-tests-asan
            grep -q 'error: .*test/sanitizer_suppressions/asan-excluded-cases' "$work/out.txt" ||
                fail "smoke: $image: unit-tests-asan without its list gave no 'error: ' message"
            [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: unit-tests-asan configured without its list"
            # The same for functional-tests-asan and its list of scripts.
            make_runner_stub "$stub" "$tag" 0
            rm "$stub/test/sanitizer_suppressions/asan-excluded-scripts"
            expect_status 1 "smoke: $image: functional-tests-asan stops on a tree without its list of scripts left out" \
                docker run --rm -v "$stub:/src" "$tag" functional-tests-asan
            grep -q 'error: .*test/sanitizer_suppressions/asan-excluded-scripts' "$work/out.txt" ||
                fail "smoke: $image: functional-tests-asan without its list gave no 'error: ' message"
            [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: functional-tests-asan configured without its list"
            # A runner without the options for the sanitizer reports and the
            # list would pass them on to every script; the mode stops before
            # the build.
            for option in --sanitizer-logs --exclude-file; do
                other="--chain --exclude-file"
                [[ $option != --exclude-file ]] || other="--chain --sanitizer-logs"
                make_runner_stub "$stub" "$tag" 0
                printf '#!/bin/sh\n# %s\nexit 0\n' "$other" > "$stub/test/functional/test_runner.py"
                expect_status 1 "smoke: $image: functional-tests-asan stops on a runner without $option" \
                    docker run --rm -v "$stub:/src" "$tag" functional-tests-asan
                grep -q -- "error: .*$option" "$work/out.txt" ||
                    fail "smoke: $image: functional-tests-asan with a runner without $option gave no 'error: ' message naming it"
                [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: functional-tests-asan configured with a runner without $option"
            done
            # Docker's default seccomp filter refuses to turn address
            # randomisation off: the mode stops before the build with its own
            # message, not with ThreadSanitizer's at the first suite.
            make_tests_stub "$stub" "$tag" 0
            expect_status 1 "smoke: $image: unit-tests-tsan stops when it cannot turn address randomisation off" \
                docker run --rm -v "$stub:/src" "$tag" unit-tests-tsan
            grep -q 'error: .*seccomp=unconfined' "$work/out.txt" ||
                fail "smoke: $image: unit-tests-tsan under the seccomp filter gave no 'error: ' message naming the option"
            [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: unit-tests-tsan configured under the seccomp filter"
        fi
        # The functional modes build only yacoind and yacoin-cli and run
        # the scripts on regtest, but those of the regtest list, the extended
        # ones too, FTEST_JOBS (default 4) at a time, and fail when the
        # runner fails. functional-tests-asan (22.04 image) runs them with
        # the sanitizers' runtime options, a directory for their reports and
        # its list of scripts left out, and only it does.
        local want ftest_jobs status func_modes=(functional-tests) goals logs want_opts has_opts
        local excluded="/src/test/sanitizer_suppressions/asan-excluded-scripts"
        local regtest_excluded="/src/test/functional/regtest-excluded-scripts"
        [[ "$image" != ubuntu.22.04 ]] || func_modes+=(functional-tests-asan)
        for mode in "${func_modes[@]}"; do
            logs="/src/build/docker-$image/$mode/sanitizer-logs"
            for ftest_jobs in "" 2; do
                make_runner_stub "$stub" "$tag" 0
                want="${ftest_jobs:-4}"
                docker run --rm -v "$stub:/src" ${ftest_jobs:+-e FTEST_JOBS="$ftest_jobs"} "$tag" "$mode" \
                    > "$work/out.txt" 2>&1 && status=0 || status=$?
                args=$(cat "$stub/runner-args" 2>/dev/null || echo "test_runner.py did not run")
                goals=$(tr '\n' ' ' < "$stub/make-goals" 2>/dev/null || echo "make did not run")
                # The regtest options (4 + 8) for both, the sanitizer options
                # (1 + 2) for functional-tests-asan only.
                want_opts=12 has_opts=0
                [[ $mode != functional-tests-asan ]] || want_opts=15
                [[ " $args " != *" --sanitizer-logs=$logs "* ]] || has_opts=$(( has_opts + 1 ))
                [[ " $args " != *" --exclude-file=$excluded "* ]] || has_opts=$(( has_opts + 2 ))
                [[ " $args " != *" --chain=regtest "* ]] || has_opts=$(( has_opts + 4 ))
                [[ " $args " != *" --exclude-file=$regtest_excluded "* ]] || has_opts=$(( has_opts + 8 ))
                if [[ $status == 0 && " $args " == *" -j $want "* && " $args " == *" --extended "* &&
                      " $args " != *" --shard"* && $goals == "yacoind yacoin-cli " && $want_opts == "$has_opts" ]]; then
                    pass "smoke: $image: $mode (FTEST_JOBS=${ftest_jobs:-unset}) builds $goals and runs: test_runner.py $args"
                else
                    tail -n 5 "$work/out.txt"
                    fail "smoke: $image: $mode (FTEST_JOBS=${ftest_jobs:-unset}, exit status $status) builds $goals and runs: test_runner.py $args"
                fi
            done
            if [[ $mode == functional-tests-asan ]]; then
                want_env="ASAN_OPTIONS=detect_leaks=1:handle_segv=0"
                want_env+=" LSAN_OPTIONS=suppressions=/src/test/sanitizer_suppressions/lsan:print_suppressions=0"
                want_env+=" UBSAN_OPTIONS=print_stacktrace=1 TSAN_OPTIONS="
            else
                want_env="ASAN_OPTIONS= LSAN_OPTIONS= UBSAN_OPTIONS= TSAN_OPTIONS="
            fi
            env_got=$(cat "$stub/runner-env" 2>/dev/null || echo "test_runner.py did not run")
            [[ "$env_got" == "$want_env" ]] && pass "smoke: $image: $mode runs the scripts with: $env_got" ||
                fail "smoke: $image: $mode runs the scripts with: $env_got (want $want_env)"
            # FTEST_SHARD=K/N runs shard K of N of the scripts.
            make_runner_stub "$stub" "$tag" 0
            docker run --rm -v "$stub:/src" -e FTEST_SHARD=2/3 "$tag" "$mode" > "$work/out.txt" 2>&1 && status=0 || status=$?
            args=$(cat "$stub/runner-args" 2>/dev/null || echo "test_runner.py did not run")
            [[ $status == 0 && " $args " == *" --shard=2/3 "* && " $args " == *" --extended "* ]] &&
                pass "smoke: $image: $mode (FTEST_SHARD=2/3) runs: test_runner.py $args" ||
                { tail -n 5 "$work/out.txt"; fail "smoke: $image: $mode (FTEST_SHARD=2/3, exit status $status) runs: test_runner.py $args"; }
            # A runner without the option would pass it on to every script.
            make_runner_stub "$stub" "$tag" 0
            printf '#!/bin/sh\n# --sanitizer-logs --exclude-file --chain\nexit 0\n' > "$stub/test/functional/test_runner.py"
            expect_status 1 "smoke: $image: $mode with FTEST_SHARD stops on a runner without --shard" \
                docker run --rm -v "$stub:/src" -e FTEST_SHARD=1/2 "$tag" "$mode"
            grep -q -- 'error: .*--shard' "$work/out.txt" ||
                fail "smoke: $image: $mode with a runner without --shard gave no 'error: ' message naming it"
            [[ ! -f "$stub/make-goals" ]] || fail "smoke: $image: $mode built with a runner without --shard"
            # Exit status 3 is the runner's own; the entrypoint's errors exit 1.
            make_runner_stub "$stub" "$tag" 3
            expect_status 3 "smoke: $image: $mode fails when a script fails" \
                docker run --rm -v "$stub:/src" "$tag" "$mode"
            [[ -f "$stub/runner-args" ]] || fail "smoke: $image: the failing $mode run did not reach test_runner.py"
            expect_status 1 "smoke: $image: $mode rejects FTEST_JOBS=0" \
                docker run --rm -v "$stub:/src" -e FTEST_JOBS=0 "$tag" "$mode"
            grep -q 'error: FTEST_JOBS' "$work/out.txt" || fail "smoke: $image: FTEST_JOBS=0 gave no 'error: FTEST_JOBS' message"
            local shard
            for shard in 0/2 3/2 1/0 2 a/b 01/2; do
                make_runner_stub "$stub" "$tag" 0
                expect_status 1 "smoke: $image: $mode rejects FTEST_SHARD=$shard" \
                    docker run --rm -v "$stub:/src" -e FTEST_SHARD="$shard" "$tag" "$mode"
                grep -q 'error: FTEST_SHARD' "$work/out.txt" ||
                    fail "smoke: $image: FTEST_SHARD=$shard gave no 'error: FTEST_SHARD' message"
                [[ ! -f "$stub/make-goals" ]] || fail "smoke: $image: $mode built with FTEST_SHARD=$shard"
            done
        done
        if [[ "$image" == ubuntu.22.04 ]]; then
            # A sanitizer report fails functional-tests-asan although every
            # script passed (a runner that missed it), and is printed with its
            # file name; with a failed script the runner's status stays.
            local report="==42==ERROR: AddressSanitizer: a report from the stub"
            for status in 0 3; do
                make_runner_stub "$stub" "$tag" "$status" "$report"
                expect_status $(( status ? status : 1 )) \
                    "smoke: $image: functional-tests-asan fails on a sanitizer report (runner exit status $status)" \
                    docker run --rm -v "$stub:/src" "$tag" functional-tests-asan
                grep -q -- "-- a_script_1.yacoind.42 --" "$work/out.txt" && grep -qF "$report" "$work/out.txt" ||
                    fail "smoke: $image: functional-tests-asan did not print the report with its file name"
            done
            # functional-tests does not look for reports, also not for one
            # where functional-tests-asan would.
            make_runner_stub "$stub" "$tag" 0 "$report"
            expect_status 0 "smoke: $image: functional-tests does not look for sanitizer reports" \
                docker run --rm -v "$stub:/src" "$tag" functional-tests
            [[ -f "$stub/build/docker-$image/functional-tests/sanitizer-logs/a_script_1.yacoind.42" ]] ||
                fail "smoke: $image: the functional-tests run left no report in its build directory"
        fi
        # The out-of-tree configure left root-owned build directories.
        docker run --rm -v "$work:/w" --entrypoint rm "$tag" -rf "/w/${stub##*/}"
        # The coverage modes configure out of tree with lcov and -O0 (lcov
        # 2.6, which they need, is in the 22.04 image only).
        [[ "$image" == ubuntu.22.04 ]] || continue
        for mode in cov-unit cov-functional; do
            make_configure_stub "$stub" "$tag"
            printf 'cov-unit:\ncov-functional:\n' > "$stub/Makefile.am"
            docker run --rm -v "$stub:/src" "$tag" "$mode" > "$work/out.txt" 2>&1 || true
            args=$(cat "$stub/configure-args" 2>/dev/null || echo "configure did not run")
            if [[ " $args " == *" --enable-lcov "* && " $args " == *" CXXFLAGS=-O0 -g "* &&
                  " $args " != *" --enable-low-difficulty-for-development "* ]]; then
                pass "smoke: $image: $mode configures with: $args"
            else
                tail -n 5 "$work/out.txt"; fail "smoke: $image: $mode configure arguments: $args"
            fi
        done
        # cov-functional passes FTEST_SHARD (empty when unset) and
        # FTEST_JOBS to "make cov-functional"; with FTEST_SHARD set it stops
        # before the build on a tree whose target does not take it.
        local shard got
        for shard in "" 2/3; do
            make_cov_stub "$stub" "$tag"
            docker run --rm -v "$stub:/src" ${shard:+-e FTEST_SHARD="$shard"} "$tag" cov-functional \
                > "$work/out.txt" 2>&1 && status=0 || status=$?
            got=$(cat "$stub/make-vars" 2>/dev/null || echo "make cov-functional did not run")
            [[ $status == 0 && "$got" == "FTEST_SHARD=$shard FTEST_JOBS=4" ]] &&
                pass "smoke: $image: cov-functional (FTEST_SHARD=${shard:-unset}) runs make cov-functional with: $got" ||
                { tail -n 5 "$work/out.txt"; fail "smoke: $image: cov-functional (FTEST_SHARD=${shard:-unset}, exit status $status) runs make with: $got"; }
        done
        make_cov_stub "$stub" "$tag"
        printf 'cov-functional:\n' > "$stub/Makefile.am"
        expect_status 1 "smoke: $image: cov-functional with FTEST_SHARD stops on a target without it" \
            docker run --rm -v "$stub:/src" -e FTEST_SHARD=1/2 "$tag" cov-functional
        grep -q 'error: .*FTEST_SHARD' "$work/out.txt" ||
            fail "smoke: $image: cov-functional with a target without FTEST_SHARD gave no 'error: ' message naming it"
        [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: cov-functional configured with a target without FTEST_SHARD"
        # Without the regtest list the target would fail after the build; the
        # mode stops before it.
        make_cov_stub "$stub" "$tag"
        rm "$stub/test/functional/regtest-excluded-scripts"
        expect_status 1 "smoke: $image: cov-functional stops on a tree without the regtest list" \
            docker run --rm -v "$stub:/src" "$tag" cov-functional
        grep -q 'error: .*test/functional/regtest-excluded-scripts' "$work/out.txt" ||
            fail "smoke: $image: cov-functional without the regtest list gave no 'error: ' message"
        [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: cov-functional configured without the regtest list"
        # The out-of-tree configure left root-owned build directories.
        docker run --rm -v "$work:/w" --entrypoint rm "$tag" -rf "/w/${stub##*/}"
    done
}

# The fuzz-corpus mode (22.04 image): configures out of tree with clang,
# --enable-fuzz and the sanitizer flags of unit-tests-asan, position-dependent
# programs, mainnet consensus; runs the corpus replay on the fuzz binary it built with JOBS and
# the sanitizers' runtime options; fails when the replay fails or the build
# made no fuzz binary, and stops before the build on a tree without a corpus.
# smoke_fuzz_corpus <image> <tag> <stub dir>
smoke_fuzz_corpus() {
    local image="$1" tag="$2" stub="$3" args site cxx env_got status want
    local san="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
    local build="/src/build/docker-$image/fuzz-corpus"
    make_fuzz_stub "$stub" "$tag" 0
    docker run --rm -v "$stub:/src" -e JOBS=3 "$tag" fuzz-corpus > "$work/out.txt" 2>&1 && status=0 || status=$?
    args=$(cat "$stub/configure-args" 2>/dev/null || echo "configure did not run")
    if [[ " $args " == *" --enable-fuzz "* && " $args " == *" --with-asm=no "* &&
          " $args " == *" CXXFLAGS=-O1 -g $san "* && " $args " == *" CFLAGS=-O1 -g $san "* &&
          " $args " == *" LDFLAGS=$san -no-pie "* && " $args " == *" --without-gui --disable-man --enable-ccache "* &&
          " $args " != *" --enable-low-difficulty-for-development "* ]]; then
        pass "smoke: $image: fuzz-corpus configures with: $args"
    else
        tail -n 5 "$work/out.txt"; fail "smoke: $image: fuzz-corpus configure arguments: $args"
    fi
    # The depends config.site names the compilers; the mode's site file reads
    # it first and then names clang, which is the image's clang 14.
    site=$(tr '\n' ' ' < "$stub/configure-site" 2>/dev/null || echo "configure did not run")
    cxx=$(cat "$stub/configure-cxx" 2>/dev/null || echo "configure did not run")
    want="ac_site_file='/src/build/docker-$image/depends/share/config.site' . \"\$ac_site_file\" CC=clang CXX=clang++ "
    [[ "$site" == "$want" && "$cxx" == /usr/lib/llvm-14/bin/clang++ ]] &&
        pass "smoke: $image: fuzz-corpus configures with the site file: $site(clang++: $cxx)" ||
        fail "smoke: $image: fuzz-corpus configures with the site file: $site(clang++: $cxx; want $want)"
    args=$(cat "$stub/runner-args" 2>/dev/null || echo "run-fuzz-corpus.py did not run")
    want="--jobs 3 $build/src/test/fuzz/fuzz /src/test/fuzz/corpus $build/fuzz-corpus-logs"
    [[ $status == 0 && "$args" == "$want" ]] && pass "smoke: $image: fuzz-corpus runs: run-fuzz-corpus.py $args" ||
        { tail -n 5 "$work/out.txt"; fail "smoke: $image: fuzz-corpus (exit status $status) runs: run-fuzz-corpus.py $args"; }
    env_got=$(cat "$stub/runner-env" 2>/dev/null || echo "run-fuzz-corpus.py did not run")
    want="ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS= UBSAN_OPTIONS=print_stacktrace=1 TSAN_OPTIONS="
    [[ "$env_got" == "$want" ]] && pass "smoke: $image: fuzz-corpus runs the corpus with: $env_got" ||
        fail "smoke: $image: fuzz-corpus runs the corpus with: $env_got (want $want)"
    make_fuzz_stub "$stub" "$tag" 3
    expect_status 3 "smoke: $image: fuzz-corpus fails when the corpus replay fails" \
        docker run --rm -v "$stub:/src" "$tag" fuzz-corpus
    [[ -f "$stub/runner-args" ]] || fail "smoke: $image: the failing fuzz-corpus run did not reach run-fuzz-corpus.py"
    make_fuzz_stub "$stub" "$tag" 0 no-binary
    expect_status 1 "smoke: $image: fuzz-corpus stops when the build made no fuzz binary" \
        docker run --rm -v "$stub:/src" "$tag" fuzz-corpus
    grep -q 'error: the build made no .*src/test/fuzz/fuzz' "$work/out.txt" ||
        fail "smoke: $image: fuzz-corpus without a fuzz binary gave no 'error: ' message"
    [[ ! -f "$stub/runner-args" ]] || fail "smoke: $image: fuzz-corpus ran run-fuzz-corpus.py without a fuzz binary"
    make_fuzz_stub "$stub" "$tag" 0
    rm -r "$stub/test/fuzz/corpus"
    expect_status 1 "smoke: $image: fuzz-corpus stops on a tree without a corpus" \
        docker run --rm -v "$stub:/src" "$tag" fuzz-corpus
    grep -q 'error: .*test/fuzz/corpus' "$work/out.txt" ||
        fail "smoke: $image: fuzz-corpus without a corpus gave no 'error: ' message"
    [[ ! -f "$stub/configure-args" ]] || fail "smoke: $image: fuzz-corpus configured without a corpus"
}

# A stub source tree for the release build modes: depends and autogen.sh are
# no-ops, configure records its arguments in /src/configure-args and fails.
make_configure_stub() {
    local d="$1" tag="$2"
    # Written as root by the previous run.
    [[ ! -e "$d" ]] || docker run --rm -v "$work:/w" --entrypoint rm "$tag" -rf "/w/${d##*/}"
    mkdir -p "$d/depends"
    printf 'all:\n\t@true\n' > "$d/depends/Makefile"
    printf '#!/bin/sh\nexit 0\n' > "$d/autogen.sh"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/configure-args' 'exit 1' > "$d/configure"
    # The early checks of the unit test modes need the unit test runner, the
    # sanitizer modes their suppression files, unit-tests-asan its list of
    # test cases left out, functional-tests-asan its list of scripts left
    # out and a functional test runner with the options for the sanitizer
    # reports and the lists, the functional modes and build-low-difficulty
    # the regtest list and a runner with --chain, --exclude-file and
    # --include-file.
    mkdir -p "$d/contrib/devtools" "$d/test/sanitizer_suppressions" "$d/test/functional"
    printf '#!/bin/sh\nexit 1\n' > "$d/contrib/devtools/run-unit-suites.sh"
    # fuzz-corpus: its replay script and corpus.
    printf '#!/bin/sh\nexit 1\n' > "$d/contrib/devtools/run-fuzz-corpus.py"
    mkdir -p "$d/test/fuzz/corpus"
    printf '#!/bin/sh\n# --sanitizer-logs --exclude-file --chain --include-file\nexit 1\n' > "$d/test/functional/test_runner.py"
    : > "$d/test/sanitizer_suppressions/lsan"
    : > "$d/test/sanitizer_suppressions/tsan"
    : > "$d/test/sanitizer_suppressions/asan-excluded-cases"
    : > "$d/test/sanitizer_suppressions/asan-excluded-scripts"
    : > "$d/test/functional/regtest-excluded-scripts"
    chmod +x "$d/autogen.sh" "$d/configure" "$d/contrib/devtools/run-unit-suites.sh" "$d/contrib/devtools/run-fuzz-corpus.py"
}

# A stub source tree for fuzz-corpus: depends, autogen.sh, configure and make
# are no-ops; configure records its arguments in /src/configure-args, the
# site file it gets in /src/configure-site and the clang++ on its PATH in
# /src/configure-cxx, and leaves src/test/fuzz/fuzz in the build directory
# (not with "no-binary"); contrib/devtools/run-fuzz-corpus.py records its
# arguments in /src/runner-args and the sanitizer options it gets in
# /src/runner-env, then exits with <status>.
# make_fuzz_stub <dir> <tag> <status> [no-binary]
make_fuzz_stub() {
    local d="$1" tag="$2" bin=""
    make_configure_stub "$d" "$tag"
    [[ "${4:-}" == no-binary ]] ||
        bin='printf "#!/bin/sh\nexit 1\n" > src/test/fuzz/fuzz; chmod +x src/test/fuzz/fuzz'
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/configure-args' 'cat "$CONFIG_SITE" > /src/configure-site' \
        'command -v clang++ > /src/configure-cxx' 'mkdir -p src/test/fuzz' \
        'printf "test/fuzz/fuzz:\n" > src/Makefile' "$bin" > "$d/configure"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/runner-args' \
        'echo "ASAN_OPTIONS=${ASAN_OPTIONS:-} LSAN_OPTIONS=${LSAN_OPTIONS:-} UBSAN_OPTIONS=${UBSAN_OPTIONS:-} TSAN_OPTIONS=${TSAN_OPTIONS:-}" > /src/runner-env' \
        "exit $3" > "$d/contrib/devtools/run-fuzz-corpus.py"
    chmod +x "$d/configure"
}

# A stub source tree for the out-of-tree unit test modes (unit-tests,
# unit-tests-asan, unit-tests-tsan): depends, autogen.sh, configure and make
# are no-ops, configure leaves src/test/test_bitcoin (not with "no-binary")
# and src/bench/bench_yacoin (not with "no-binary" or "no-bench") in the
# build directory, and contrib/devtools/run-unit-suites.sh records its
# arguments in /src/suites-args, the sanitizer options it gets in
# /src/suites-env and its personality in /src/suites-personality, then exits
# with <status>. bench_yacoin records its arguments in /src/bench-args and
# exits with STUB_BENCH_STATUS (default 0).
# make_tests_stub <dir> <tag> <status> [no-binary|no-bench]
make_tests_stub() {
    local d="$1" tag="$2" bin="" bench=""
    make_configure_stub "$d" "$tag"
    [[ "${4:-}" == no-binary ]] ||
        bin='printf "#!/bin/sh\nexit 1\n" > src/test/test_bitcoin; chmod +x src/test/test_bitcoin'
    [[ "${4:-}" == no-binary || "${4:-}" == no-bench ]] ||
        bench='printf "#!/bin/sh\necho \"\$@\" > /src/bench-args\nexit \${STUB_BENCH_STATUS:-0}\n" > src/bench/bench_yacoin; chmod +x src/bench/bench_yacoin'
    # configure runs in the build directory and leaves a src/Makefile there.
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/configure-args' 'mkdir -p src/test src/bench' \
        'printf "test/test_bitcoin bench/bench_yacoin:\n" > src/Makefile' "$bin" "$bench" > "$d/configure"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/suites-args' \
        'echo "ASAN_OPTIONS=${ASAN_OPTIONS:-} LSAN_OPTIONS=${LSAN_OPTIONS:-} UBSAN_OPTIONS=${UBSAN_OPTIONS:-} TSAN_OPTIONS=${TSAN_OPTIONS:-}" > /src/suites-env' \
        'cat /proc/self/personality > /src/suites-personality' \
        "exit $3" > "$d/contrib/devtools/run-unit-suites.sh"
    chmod +x "$d/configure"
}

# A stub source tree for build-low-difficulty: depends, autogen.sh, configure,
# make and make install are no-ops, src/test/test_bitcoin exists,
# contrib/devtools/run-unit-suites.sh records its arguments in
# /src/suites-args and exits with <status>, and
# test/functional/test_runner.py records its arguments in /src/runner-args
# and exits with <runner status> (default 0).
# make_unit_stub <dir> <tag> <status> [runner status]
make_unit_stub() {
    local d="$1" tag="$2"
    make_configure_stub "$d" "$tag"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/configure-args' 'printf "all:\ninstall:\n" > Makefile' > "$d/configure"
    mkdir -p "$d/src/test"
    printf '#!/bin/sh\nexit 1\n' > "$d/src/test/test_bitcoin"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/suites-args' "exit $3" > "$d/contrib/devtools/run-unit-suites.sh"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' '# Takes --include-file.' 'echo "$@" > /src/runner-args' "exit ${4:-0}" \
        > "$d/test/functional/test_runner.py"
    chmod +x "$d/configure" "$d/src/test/test_bitcoin" "$d/contrib/devtools/run-unit-suites.sh" \
        "$d/test/functional/test_runner.py"
}

# A stub source tree for the functional modes: depends, autogen.sh and
# configure are no-ops, the build records the targets it was asked for in
# /src/make-goals (any other target fails), and test/functional/test_runner.py
# records its arguments in /src/runner-args and the sanitizer options it gets
# in /src/runner-env, writes <report> (if given) to a file of the directory
# its --sanitizer-logs option names, as a sanitizer runtime would (without the
# option, of <build directory>/sanitizer-logs, where the entrypoint looks for
# reports in functional-tests-asan), and exits with <status>.
# make_runner_stub <dir> <tag> <status> [report]
make_runner_stub() {
    local d="$1" tag="$2"
    make_configure_stub "$d" "$tag"
    # configure runs in the build directory and leaves a src/Makefile there.
    # shellcheck disable=SC2016 # expanded by the stub and make
    printf '%s\n' '#!/bin/sh' 'mkdir -p src' \
        'printf "yacoind yacoin-cli:\n\t@echo \$@ >> /src/make-goals\n" > src/Makefile' > "$d/configure"
    mkdir -p "$d/test/functional"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' '# Takes --sanitizer-logs, --exclude-file, --chain, --include-file and --shard.' 'echo "$@" > /src/runner-args' \
        'echo "ASAN_OPTIONS=${ASAN_OPTIONS:-} LSAN_OPTIONS=${LSAN_OPTIONS:-} UBSAN_OPTIONS=${UBSAN_OPTIONS:-} TSAN_OPTIONS=${TSAN_OPTIONS:-}" > /src/runner-env' \
        "report='${4:-}'" \
        'for a in "$@"; do case "$a" in --sanitizer-logs=*) dir="${a#*=}" ;; --tmpdirprefix=*) tmp="${a#*=}" ;; esac; done' \
        '[ -n "${dir:-}" ] || dir="${tmp%/test/tmp}/sanitizer-logs"' \
        'if [ -n "$report" ]; then mkdir -p "$dir" && echo "$report" > "$dir/a_script_1.yacoind.42"; fi' \
        "exit $3" > "$d/test/functional/test_runner.py"
    chmod +x "$d/configure" "$d/test/functional/test_runner.py"
}

# A stub source tree for cov-functional: depends, autogen.sh and configure are
# no-ops, Makefile.am has the target with FTEST_SHARD, and the configured
# build's "make cov-functional" records FTEST_SHARD and FTEST_JOBS in
# /src/make-vars.
# make_cov_stub <dir> <tag>
make_cov_stub() {
    local d="$1" tag="$2"
    make_configure_stub "$d" "$tag"
    printf 'FTEST_SHARD ?=\ncov-functional:\n' > "$d/Makefile.am"
    # shellcheck disable=SC2016 # expanded by the stub and make
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/configure-args' \
        'printf "cov-functional:\n\t@echo FTEST_SHARD=\$(FTEST_SHARD) FTEST_JOBS=\$(FTEST_JOBS) > /src/make-vars\n" > Makefile' \
        > "$d/configure"
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

# One release build (the default mode) with CI's ccache settings; prints how
# long it took. run_build <image> <src> <cache> <n>
run_build() {
    local start=$SECONDS
    echo "== cache: $1, build $4 =="
    CCACHE_COMPRESS=1 CCACHE_MAXSIZE=1G "$HERE/run.sh" --no-image-build --src "$2" --cache "$3" \
        --name "yacoin-check-$1-$4" "$1" > "$work/cache-$1-run$4.log" 2>&1 || return 1
    echo "$(( SECONDS - start ))" > "$work/cache-$1-run$4.seconds"
}

# Two release builds of a clean clone of HEAD with one cache dir, the tree
# cleaned in between (CI's master and pull request runs). The first starts on
# an empty cache, so it also exercises the ccache config race. The second must
# report the cache, take every depends package from it, compile through the
# depends ccache with nearly only hits, and take at most half the time.
step_cache() {
    local image src="$work/cache-src" cache b hits misses t1 t2 tag log log1 ok ext ccache_bin
    for image in "${images[@]}"; do
        cache="$work/cache-$image" tag="$LOCAL_REPO:$image"
        log1="$work/cache-$image-run1.log" log="$work/cache-$image-run2.log"
        if [[ -e "$cache" ]]; then docker run --rm -v "$work:/w" --entrypoint rm "$tag" -rf "/w/${cache##*/}"; fi
        if [[ -e "$src" ]]; then docker run --rm -v "$work:/w" --entrypoint rm "$tag" -rf /w/cache-src; fi
        git clone -q --no-local "$ROOT" "$src"
        git -C "$src" checkout -q --detach "$(git -C "$ROOT" rev-parse HEAD)"
        run_build "$image" "$src" "$cache" 1 || { tail -n 30 "$log1"; fail "cache: $image: first build (empty cache)"; continue; }
        pass "cache: $image: first build on an empty cache ($(cat "$work/cache-$image-run1.seconds") s)"
        git -C "$src" clean -xdfq
        [[ -z "$(git -C "$src" status --porcelain)" ]] || { fail "cache: $image: tree not clean"; continue; }
        run_build "$image" "$src" "$cache" 2 || { tail -n 30 "$log"; fail "cache: $image: second build"; continue; }
        t1=$(cat "$work/cache-$image-run1.seconds") t2=$(cat "$work/cache-$image-run2.seconds") ok=1 ext=""
        [[ "$image" != windows ]] || ext=.exe
        for b in yacoind yacoin-cli yacoin-qt; do
            [[ -s "$src/release-root/bin/$b$ext" ]] || { echo "  missing release-root/bin/$b$ext"; ok=0; }
        done
        grep -q "^== Using cache in /cache/$image ==" "$log" || { echo "  no 'Using cache in /cache/$image'"; ok=0; }
        # depends prints these only when it builds or downloads a package; a
        # run from the cache only copies the packages.
        if grep -E '^(Fetching|Extracting|Building) [A-Za-z0-9_+.-]+' "$log"; then echo "  depends rebuilt packages"; ok=0; fi
        grep -q '^copying packages:' "$log" || { echo "  depends copied no packages from the cache"; ok=0; }
        if grep -q 'Checksum mismatch' "$log"; then echo "  a cached depends package failed its checksum"; ok=0; fi
        [[ -n "$(ls -A "$cache/$image/depends-built" 2>/dev/null)" ]] || { echo "  no depends packages in /cache/$image/depends-built"; ok=0; }
        # src/ compiles through the ccache that depends built.
        grep -qE '^CCACHE = /src/depends/[^ ]*/native/bin/ccache$' "$src/src/Makefile" ||
            { echo "  src/ is not built with the depends ccache"; ok=0; }
        # CCACHE_COMPRESS=1 reached ccache: its cached objects are gzip files.
        local obj
        obj=$(find "$cache/$image/ccache" -name '*.o' -type f -print -quit 2>/dev/null)
        [[ -n "$obj" && "$(head -c 2 "$obj" | od -An -tx1 | tr -d ' ')" == 1f8b ]] ||
            { echo "  no compressed objects in /cache/$image/ccache"; ok=0; }
        ccache_bin=$(sed -n 's/^CCACHE = //p' "$src/src/Makefile")
        echo "  ccache -s after the second build (CCACHE_DIR=/cache/$image/ccache, CCACHE_MAXSIZE=1G):"
        docker run --rm -v "$src:/src" -v "$cache:/cache" -e CCACHE_DIR="/cache/$image/ccache" -e CCACHE_MAXSIZE=1G \
            --entrypoint "$ccache_bin" "$tag" -s | sed 's/^/    /'
        # ccache prints running totals, so compare the two runs.
        tot() { awk -v re="$1" '$0 ~ re {s += $NF} END {print s + 0}' "$2"; }
        hits=$(( $(tot '^cache hit \\((direct|preprocessed)\\)' "$log") - $(tot '^cache hit \\((direct|preprocessed)\\)' "$log1") ))
        misses=$(( $(tot '^cache miss' "$log") - $(tot '^cache miss' "$log1") ))
        echo "  first build: $(tot '^cache hit \\((direct|preprocessed)\\)' "$log1") hits, $(tot '^cache miss' "$log1") misses, $t1 s"
        echo "  second build: $hits hits, $misses misses, $t2 s"
        # A few misses are expected (e.g. clientversion.cpp uses __DATE__).
        (( hits > 0 && hits * 10 >= (hits + misses) * 9 )) || { echo "  too few ccache hits"; ok=0; }
        (( t2 * 2 <= t1 )) || { echo "  the second build was not at least twice as fast"; ok=0; }
        if (( ok )); then pass "cache: $image: second build used the depends and ccache caches ($hits hits, $misses misses, $t1 s -> $t2 s)"
        else fail "cache: $image: second build did not use the cache as expected"; fi
    done
}

for s in lint tag static devsh build smoke ccache cache; do
    if has_step "$s"; then echo "== $s =="; "step_$s"; fi
done
echo "== ${#failures[@]} failure(s) =="
printf '  %s\n' "${failures[@]}"
if (( ${#failures[@]} == 0 )) && [[ -z "${CHECK_WORKDIR:-}" ]]; then rm -rf "$work"; fi
(( ${#failures[@]} == 0 ))
