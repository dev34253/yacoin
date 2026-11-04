#!/usr/bin/env bash
# Image checks, run locally.
#
# Usage: ci/containers/check.sh [--steps LIST] [image...]
#
# Steps (default: lint,tag,static,devsh,build,smoke,ccache; all images by
# default):
#   lint    bash -n and shellcheck --severity=warning on the scripts here, and
#           no grep -q at the end of a pipe in them (pipefail and SIGPIPE)
#   tag     test-image-tag.sh: the image tags (image-tag.sh) and the CI
#           workflow's use of them
#   static  every Dockerfile pins its base image by digest and sets
#           YACOIN_BUILD_IMAGE to its own name
#   devsh   dev.sh's shared cache, on copies of dev.sh and depends/ (no
#           Docker, a stub make): the default path (XDG_CACHE_HOME, HOME),
#           DEV_CACHE, the help, one depends prefix for two copies, a new one
#           after a recipe change (untracked recipe files too) but not for
#           ignored files under depends/,
#           the arguments depends gets, ccache.conf created, two depends runs
#           one after the other, a repeated run skipping make unless its
#           inputs (Qt) changed, a build directory of another prefix refused
#   build   docker build of each image (tagged yacoin-build-local:<image>)
#   smoke   tools present, unknown modes and arguments rejected, the modes
#           that run tests stop early on a tree without the scripts and
#           targets they need, the Linux release build modes (build,
#           build-low-difficulty) and the coverage modes (cov-unit,
#           cov-functional; 22.04 image) configure with their flags,
#           build-low-difficulty runs the unit test suites of its build
#           with JOBS and fails when one fails, and functional-tests runs
#           the test runner with --extended and FTEST_JOBS
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
    local f scripts=(entrypoint.sh entrypoint.windows.sh entrypoint.macos.sh run.sh parity.sh check.sh
                     image-tag.sh test-image-tag.sh)
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
    # and writes the config.site of the prefix it gets. (b has other
    # recipes now, so both runs build.)
    local bin="$work/devsh/bin" log="$work/devsh/make.log"
    mkdir -p "$bin"; rm -f "$log"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s
' '#!/bin/bash' 'echo "start $*" >> "$STUB_LOG"; sleep 1; echo "end" >> "$STUB_LOG"' \
        'for x in "$@"; do [[ $x != x86_64_linux_prefix=* ]] || { mkdir -p "${x#*=}/share"; : > "${x#*=}/share/config.site"; }; done' \
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
        # The modes that run tests must stop early, with a clear message, on
        # a tree without the scripts and targets they need.
        for mode in unit-tests build-low-difficulty cov-unit cov-functional; do
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
        local want_args="/src/src/test/test_bitcoin /src/build/docker-$image/build-low-difficulty/unit-test-logs 3"
        make_unit_stub "$stub" "$tag" 0
        docker run --rm -v "$stub:/src" -e JOBS=3 "$tag" build-low-difficulty \
            > "$work/out.txt" 2>&1 && status=0 || status=$?
        args=$(cat "$stub/suites-args" 2>/dev/null || echo "run-unit-suites.sh did not run")
        if [[ $status == 0 && "$args" == "$want_args" ]]; then
            pass "smoke: $image: build-low-difficulty runs: run-unit-suites.sh $args"
        else
            tail -n 5 "$work/out.txt"
            fail "smoke: $image: build-low-difficulty (exit status $status) runs: run-unit-suites.sh $args"
        fi
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
        # The functional-tests mode runs every script, the extended ones
        # too, FTEST_JOBS (default 4) at a time, and fails when the runner
        # fails.
        local want ftest_jobs status
        for ftest_jobs in "" 2; do
            make_runner_stub "$stub" "$tag" 0
            want="${ftest_jobs:-4}"
            docker run --rm -v "$stub:/src" ${ftest_jobs:+-e FTEST_JOBS="$ftest_jobs"} "$tag" functional-tests \
                > "$work/out.txt" 2>&1 && status=0 || status=$?
            args=$(cat "$stub/runner-args" 2>/dev/null || echo "test_runner.py did not run")
            if [[ $status == 0 && " $args " == *" -j $want "* && " $args " == *" --extended "* ]]; then
                pass "smoke: $image: functional-tests (FTEST_JOBS=${ftest_jobs:-unset}) runs: test_runner.py $args"
            else
                tail -n 5 "$work/out.txt"
                fail "smoke: $image: functional-tests (FTEST_JOBS=${ftest_jobs:-unset}, exit status $status) runs: test_runner.py $args"
            fi
        done
        # Exit status 3 is the runner's own; the entrypoint's errors exit 1.
        rm -f "$stub/runner-args"
        make_runner_stub "$stub" "$tag" 3
        expect_status 3 "smoke: $image: functional-tests fails when a script fails" \
            docker run --rm -v "$stub:/src" "$tag" functional-tests
        [[ -f "$stub/runner-args" ]] || fail "smoke: $image: the failing run did not reach test_runner.py"
        expect_status 1 "smoke: $image: functional-tests rejects FTEST_JOBS=0" \
            docker run --rm -v "$stub:/src" -e FTEST_JOBS=0 "$tag" functional-tests
        grep -q 'error: FTEST_JOBS' "$work/out.txt" || fail "smoke: $image: FTEST_JOBS=0 gave no 'error: FTEST_JOBS' message"
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
            want_low=0 has_low=0
            [[ $mode != cov-functional ]] || want_low=1
            [[ " $args " != *" --enable-low-difficulty-for-development "* ]] || has_low=1
            if [[ " $args " == *" --enable-lcov "* && " $args " == *" CXXFLAGS=-O0 -g "* &&
                  $want_low == "$has_low" ]]; then
                pass "smoke: $image: $mode configures with: $args"
            else
                tail -n 5 "$work/out.txt"; fail "smoke: $image: $mode configure arguments: $args"
            fi
        done
        # The out-of-tree configure left root-owned build directories.
        docker run --rm -v "$work:/w" --entrypoint rm "$tag" -rf "/w/${stub##*/}"
    done
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
    # The early check of build-low-difficulty needs the unit test runner.
    mkdir -p "$d/contrib/devtools"
    printf '#!/bin/sh\nexit 1\n' > "$d/contrib/devtools/run-unit-suites.sh"
    chmod +x "$d/autogen.sh" "$d/configure" "$d/contrib/devtools/run-unit-suites.sh"
}

# A stub source tree for build-low-difficulty: depends, autogen.sh, configure,
# make and make install are no-ops, src/test/test_bitcoin exists, and
# contrib/devtools/run-unit-suites.sh records its arguments in
# /src/suites-args and exits with <status>.
# make_unit_stub <dir> <tag> <status>
make_unit_stub() {
    local d="$1" tag="$2"
    make_configure_stub "$d" "$tag"
    printf '%s\n' '#!/bin/sh' 'printf "all:\ninstall:\n" > Makefile' > "$d/configure"
    mkdir -p "$d/src/test"
    printf '#!/bin/sh\nexit 1\n' > "$d/src/test/test_bitcoin"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/suites-args' "exit $3" > "$d/contrib/devtools/run-unit-suites.sh"
    chmod +x "$d/configure" "$d/src/test/test_bitcoin" "$d/contrib/devtools/run-unit-suites.sh"
}

# A stub source tree for the functional-tests mode: depends, autogen.sh,
# configure and the build are no-ops, and test/functional/test_runner.py
# records its arguments in /src/runner-args and exits with <status>.
# make_runner_stub <dir> <tag> <status>
make_runner_stub() {
    local d="$1" tag="$2"
    make_configure_stub "$d" "$tag"
    # configure runs in the build directory and leaves a src/Makefile there.
    printf '%s\n' '#!/bin/sh' 'mkdir -p src' 'printf "yacoind yacoin-cli:\n" > src/Makefile' > "$d/configure"
    mkdir -p "$d/test/functional"
    # shellcheck disable=SC2016 # expanded by the stub
    printf '%s\n' '#!/bin/sh' 'echo "$@" > /src/runner-args' "exit $3" > "$d/test/functional/test_runner.py"
    chmod +x "$d/configure" "$d/test/functional/test_runner.py"
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
