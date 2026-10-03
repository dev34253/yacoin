#!/usr/bin/env bash
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Reproducible YaCoin builds for testing (task P0-01).
#
# Builds the depends libraries and YaCoin inside the pinned build image, out of
# tree, so the git checkout is never modified. See contrib/testing/README.md.
#
#   contrib/testing/build.sh --config mainnet --unit
#   contrib/testing/build.sh --config lowdiff --coverage --unit --functional
#   contrib/testing/build.sh --coverage-report

set -euo pipefail

DEFAULT_IMAGE="dev34253/yacoin-build@sha256:b7365321bd98ce7297c30bc2eb555f56407548d4cea1836cfbd4b806ba934f7a"
HOST_TRIPLET="x86_64-pc-linux-gnu"

usage() {
    cat <<'EOF'
Usage: contrib/testing/build.sh [options]

Build options:
  --config mainnet|lowdiff  Chain parameters: mainnet (default) or
                            --enable-low-difficulty-for-development (needed
                            by the functional tests).
  --coverage                Instrument C and C++ code for gcov/lcov (-O0).
                            With --unit/--functional, also writes an lcov
                            report to <builddir>/coverage/ (task P0-03).
  --coverage-report         Do not build: merge the coverage reports of the
                            mainnet and lowdiff --coverage runs in this work
                            dir into WORK_DIR/coverage-report/.
  --sanitizers LIST         Build with -fsanitize=LIST (e.g. address,undefined).
  --jobs N                  Parallel jobs (default: number of CPUs).
  --reconfigure             Re-run configure even if the build dir exists.
  --clean                   Delete the source copy and build dir first
                            (the depends cache is kept).

Test options:
  --unit                    Run the unit tests (src/test/test_bitcoin).
  --functional              Run the functional tests (needs --config lowdiff).
  --functional-args "ARGS"  Arguments for test_runner.py, replacing the
                            default -j4 (e.g. "-j4 wallet_dump.py").

Environment options:
  --image IMAGE             Build image (default: pinned P0-57 image).
  --no-docker               Run directly on this machine (e.g. already inside
                            the build image in CI).
  --work-dir DIR            Work directory for the source copy, build dirs and
                            depends cache (default: $YACOIN_WORK_DIR or
                            ~/.cache/yacoin-build).
  -h, --help                Show this help.

The checkout is mirrored (tracked and untracked, non-ignored files) to
WORK_DIR/src and built in WORK_DIR/build-<config>[-cov][-san-<list>]. Only one run
per work dir at a time (a lock enforces this). Proxy and CA
settings are passed into the container when HTTPS_PROXY / YACOIN_CA_BUNDLE
are set (see README.md).
EOF
}

log() { echo "== $(date -u +%H:%M:%S) $*"; }
die() { echo "error: $*" >&2; exit 1; }
# need_arg OPTION VALUE: fail clearly when an option is missing its value.
need_arg() { [ -n "${2:-}" ] && [ "${2#--}" = "$2" ] || die "$1 needs a value"; }

# ---------------------------------------------------------------- arguments
CONFIG=mainnet
COVERAGE=0
COVERAGE_REPORT=0
CONFIG_SET=0
SANITIZERS=""
JOBS=""
RECONFIGURE=0
CLEAN=0
RUN_UNIT=0
RUN_FUNCTIONAL=0
FUNCTIONAL_ARGS="-j4"
IMAGE="${YACOIN_BUILD_IMAGE:-$DEFAULT_IMAGE}"
USE_DOCKER=1
IN_CONTAINER=0
WORK_DIR="${YACOIN_WORK_DIR:-$HOME/.cache/yacoin-build}"

while [ $# -gt 0 ]; do
    case "$1" in
        --config) need_arg "$1" "${2:-}"; CONFIG="$2"; CONFIG_SET=1; shift 2 ;;
        --coverage) COVERAGE=1; shift ;;
        --coverage-report) COVERAGE_REPORT=1; shift ;;
        --sanitizers) need_arg "$1" "${2:-}"; SANITIZERS="$2"; shift 2 ;;
        --jobs) need_arg "$1" "${2:-}"; JOBS="$2"; shift 2 ;;
        --reconfigure) RECONFIGURE=1; shift ;;
        --clean) CLEAN=1; shift ;;
        --unit) RUN_UNIT=1; shift ;;
        --functional) RUN_FUNCTIONAL=1; shift ;;
        --functional-args) [ $# -ge 2 ] || die "$1 needs a value"; FUNCTIONAL_ARGS="$2"; shift 2 ;;
        --image) need_arg "$1" "${2:-}"; IMAGE="$2"; shift 2 ;;
        --no-docker) USE_DOCKER=0; shift ;;
        --work-dir) need_arg "$1" "${2:-}"; WORK_DIR="$2"; shift 2 ;;
        --in-container) IN_CONTAINER=1; USE_DOCKER=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

case "$CONFIG" in
    mainnet|lowdiff) ;;
    *) die "--config must be mainnet or lowdiff, not '$CONFIG'" ;;
esac
if [ "$RUN_FUNCTIONAL" = 1 ] && [ "$CONFIG" != lowdiff ]; then
    die "--functional needs --config lowdiff (functional tests use the low-difficulty genesis)"
fi
case "$SANITIZERS" in
    ""|*[!a-z,]*) [ -z "$SANITIZERS" ] || die "--sanitizers takes a comma-separated list such as address,undefined" ;;
esac

if [ "$COVERAGE_REPORT" = 1 ] &&
   { [ "$CONFIG_SET$COVERAGE$RUN_UNIT$RUN_FUNCTIONAL$CLEAN$RECONFIGURE" != 000000 ] || [ -n "$SANITIZERS" ]; }; then
    die "--coverage-report does not build or test; run it on its own after the --coverage runs"
fi

BUILD_NAME="build-$CONFIG"
[ "$COVERAGE" = 1 ] && BUILD_NAME="$BUILD_NAME-cov"
[ -n "$SANITIZERS" ] && BUILD_NAME="$BUILD_NAME-san-${SANITIZERS//,/-}"

# ------------------------------------------------------------- host side
if [ "$IN_CONTAINER" = 0 ]; then
    REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
    git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "$REPO is not a git checkout"
    # Resolve symlinks before the checks, and create nothing until they pass.
    WORK_DIR="$(realpath -m "$WORK_DIR")"
    HOME_REAL="$(realpath -m "$HOME")"
    case "$WORK_DIR/" in
        "$REPO"/*) die "--work-dir must be outside the checkout ($REPO)" ;;
    esac
    case "$REPO/" in
        "$WORK_DIR"/*) die "--work-dir must not contain the checkout ($REPO); use a dedicated directory" ;;
    esac
    [ "$WORK_DIR" != / ] && [ "$WORK_DIR" != "$HOME_REAL" ] || die "--work-dir must be a dedicated directory, not $WORK_DIR"
    mkdir -p "$WORK_DIR"

    # 5: one run per work dir at a time (the lock is held until this script,
    # or the docker client it execs, exits).
    exec 9>"$WORK_DIR/.lock"
    flock -n 9 || die "another build.sh run is using $WORK_DIR (lock $WORK_DIR/.lock)"

    if [ "$CLEAN" = 1 ]; then
        log "clean: removing $WORK_DIR/src and $WORK_DIR/$BUILD_NAME"
        rm -rf "${WORK_DIR:?}/src" "${WORK_DIR:?}/${BUILD_NAME:?}"
    fi

    # Version information for share/genbuild.sh (the copy has no .git).
    # "-dirty" if anything that gets copied differs from HEAD (modified,
    # deleted or untracked-but-not-ignored files).
    BUILD_GIT_COMMIT="$(git -C "$REPO" rev-parse --short=12 HEAD)"
    git -C "$REPO" update-index -q --refresh >/dev/null 2>&1 || true
    if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=normal)" ]; then
        BUILD_GIT_COMMIT="$BUILD_GIT_COMMIT-dirty"
    fi
    export BUILD_GIT_COMMIT

    # Mirror the checkout: copy what changed since the last run, remove what
    # was deleted; files regenerated by autogen.sh are otherwise left alone.
    log "syncing checkout $REPO ($BUILD_GIT_COMMIT) to $WORK_DIR/src"
    python3 "$REPO/contrib/testing/sync_tree.py" "$REPO" "$WORK_DIR/src"

    INNER_ARGS=(--in-container --config "$CONFIG" --functional-args "$FUNCTIONAL_ARGS")
    [ "$COVERAGE" = 1 ] && INNER_ARGS+=(--coverage)
    [ "$COVERAGE_REPORT" = 1 ] && INNER_ARGS+=(--coverage-report)
    [ -n "$SANITIZERS" ] && INNER_ARGS+=(--sanitizers "$SANITIZERS")
    [ -n "$JOBS" ] && INNER_ARGS+=(--jobs "$JOBS")
    [ "$RECONFIGURE" = 1 ] && INNER_ARGS+=(--reconfigure)
    [ "$RUN_UNIT" = 1 ] && INNER_ARGS+=(--unit)
    [ "$RUN_FUNCTIONAL" = 1 ] && INNER_ARGS+=(--functional)

    if [ "$USE_DOCKER" = 0 ]; then
        exec "$WORK_DIR/src/contrib/testing/build.sh" "${INNER_ARGS[@]}" --work-dir "$WORK_DIR"
    fi

    command -v docker >/dev/null || die "docker not found (use --no-docker inside the build image)"
    # --init: forward Ctrl-C/SIGTERM to the build so it stops together with
    # this script (and the lock is not released while the build still runs).
    DOCKER_ARGS=(run --rm --init -v "$WORK_DIR:/work" -w /work -e BUILD_GIT_COMMIT
                 --user "$(id -u):$(id -g)" -e HOME=/tmp --entrypoint /bin/bash)
    # Restricted networks (e.g. cloud sessions): pass the proxy and CA bundle.
    if [ -n "${HTTPS_PROXY:-}${https_proxy:-}" ]; then
        DOCKER_ARGS+=(--network host -e HTTPS_PROXY -e https_proxy -e NO_PROXY -e no_proxy)
    fi
    CA_BUNDLE="${YACOIN_CA_BUNDLE:-}"
    if [ -z "$CA_BUNDLE" ] && [ -f /root/.ccr/ca-bundle.crt ] && [ -n "${HTTPS_PROXY:-}" ]; then
        CA_BUNDLE=/root/.ccr/ca-bundle.crt
    fi
    if [ -n "$CA_BUNDLE" ]; then
        DOCKER_ARGS+=(-v "$CA_BUNDLE:/etc/yacoin-ca.crt:ro"
                      -e SSL_CERT_FILE=/etc/yacoin-ca.crt -e CURL_CA_BUNDLE=/etc/yacoin-ca.crt)
    fi
    log "image $IMAGE"
    exec docker "${DOCKER_ARGS[@]}" "$IMAGE" \
        /work/src/contrib/testing/build.sh "${INNER_ARGS[@]}" --work-dir /work
fi

# -------------------------------------------------------- container side
SRC="$WORK_DIR/src"
BUILD="$WORK_DIR/$BUILD_NAME"
CACHE="$WORK_DIR/depends-cache"
JOBS="${JOBS:-$(nproc)}"
cd "$SRC"

# ------------------------------------------------------------- coverage
# lcov 2.0 (build image). Branch coverage is recorded for P0-04. It includes
# the branches GCC adds for C++ exception handling: lcov 2.0's
# no_exception_branch option drops *all* branch data of GCC 11's gcov
# output, so filtering them is left to P0-04.
LCOV_OPTS=(--rc branch_coverage=1 --parallel "$JOBS")
# Not part of the coverage numbers (task P0-03 step 3): system headers,
# depends, test code, bundled libraries, benchmarks, and files generated in
# the build dirs. They are left out while capturing: besides being faster,
# this avoids lcov 2.0's "mismatched end line" error for the Boost.Test
# case functions in src/test (GCC 11 reports their end line before their
# start). "unused" is ignored because not every build compiles every
# excluded directory (src/secp256k1 is built without --coverage).
COVERAGE_CAPTURE=(--directory "$BUILD/src" --ignore-errors unused)
for pattern in '/usr/*' '*/depends/*' '*/test/*' '*/src/leveldb/*' \
               '*/src/secp256k1/*' '*/src/univalue/*' '*/src/bench/*' \
               "$WORK_DIR/build-*"; do
    COVERAGE_CAPTURE+=(--exclude "$pattern")
done

# coverage_start: before the tests – reset the counters (repeated runs in
# one build dir must not add up) and record a zero baseline of every
# instrumented file, so files no test runs show as 0 % instead of missing.
coverage_start() {
    command -v lcov >/dev/null && command -v genhtml >/dev/null ||
        die "--coverage with tests needs lcov and genhtml (they are in the build image)"
    rm -rf "$BUILD/coverage"
    mkdir -p "$BUILD/coverage"
    log "coverage: reset counters, record baseline (log: $BUILD/coverage/lcov.log)"
    lcov --zerocounters --directory "$BUILD" > "$BUILD/coverage/lcov.log" 2>&1 ||
        { tail -n 20 "$BUILD/coverage/lcov.log"; die "lcov --zerocounters failed"; }
    lcov "${LCOV_OPTS[@]}" --capture --initial "${COVERAGE_CAPTURE[@]}" \
        --output-file "$BUILD/coverage/baseline.info" >> "$BUILD/coverage/lcov.log" 2>&1 ||
        { tail -n 20 "$BUILD/coverage/lcov.log"; die "lcov baseline capture failed"; }
}

# coverage_html INFO DIR TITLE: HTML report and text summary next to INFO.
coverage_html() {
    genhtml "${LCOV_OPTS[@]}" --title "$3" --legend --output-directory "$2/html" "$1" \
        >> "$2/lcov.log" 2>&1 ||
        { tail -n 20 "$2/lcov.log"; die "genhtml failed (log: $2/lcov.log)"; }
    lcov "${LCOV_OPTS[@]}" --summary "$1" 2>&1 | grep -E "^ *(lines|functions|branches)" > "$2/summary.txt" ||
        die "lcov --summary failed for $1"
}

# coverage_finish: after the tests – capture, add the baseline, write
# coverage.info, html/ and summary.txt to <builddir>/coverage/.
coverage_finish() {
    local dir="$BUILD/coverage"
    log "coverage: capture"
    lcov "${LCOV_OPTS[@]}" --capture "${COVERAGE_CAPTURE[@]}" --output-file "$dir/tests.info" \
        >> "$dir/lcov.log" 2>&1 ||
        { tail -n 20 "$dir/lcov.log"; die "lcov capture failed (log: $dir/lcov.log)"; }
    lcov "${LCOV_OPTS[@]}" --add-tracefile "$dir/baseline.info" --add-tracefile "$dir/tests.info" \
        --output-file "$dir/coverage.info" >> "$dir/lcov.log" 2>&1 ||
        { tail -n 20 "$dir/lcov.log"; die "lcov merge with baseline failed"; }
    rm -f "$dir/baseline.info" "$dir/tests.info"
    coverage_html "$dir/coverage.info" "$dir" "YaCoin $CONFIG (${BUILD_GIT_COMMIT:-unknown})"
    log "coverage $CONFIG: $dir/coverage.info, html/, summary.txt"
    cat "$dir/summary.txt"
}

# coverage_report: merge the two configurations. gcov records lines of the
# original source file, so both builds use the same line numbers; lines in
# #ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT blocks exist in one build only. The
# merge is the union: a line counts if it is instrumented in either build
# and as hit if it ran in either; hit counts are added.
coverage_report() {
    local out="$WORK_DIR/coverage-report" c f args=()
    command -v lcov >/dev/null && command -v genhtml >/dev/null ||
        die "--coverage-report needs lcov and genhtml (they are in the build image)"
    for c in mainnet lowdiff; do
        f="$WORK_DIR/build-$c-cov/coverage/coverage.info"
        [ -f "$f" ] || die "missing $f – run build.sh --config $c --coverage with tests first"
        args+=(--add-tracefile "$f")
    done
    rm -rf "$out"
    mkdir -p "$out"
    log "coverage report: merging mainnet and lowdiff into $out"
    lcov "${LCOV_OPTS[@]}" "${args[@]}" --output-file "$out/merged.info" > "$out/lcov.log" 2>&1 ||
        { tail -n 20 "$out/lcov.log"; die "lcov merge failed (log: $out/lcov.log)"; }
    coverage_html "$out/merged.info" "$out" "YaCoin mainnet + lowdiff (${BUILD_GIT_COMMIT:-unknown})"
    for c in mainnet lowdiff; do
        f="$WORK_DIR/build-$c-cov/coverage/summary.txt"
        echo "$c:"
        if [ -f "$f" ]; then cat "$f"; else echo "  (no summary.txt)"; fi
    done
    echo "merged (mainnet + lowdiff):"
    cat "$out/summary.txt"
}

if [ "$COVERAGE_REPORT" = 1 ]; then
    coverage_report
    exit 0
fi

log "compiler: $(g++ --version | head -n1)"
log "depends (NO_QT=1, cache $CACHE)"
mkdir -p "$CACHE/sources" "$CACHE/built"
make -C depends -j"$JOBS" HOST="$HOST_TRIPLET" NO_QT=1 \
    SOURCES_PATH="$CACHE/sources" BASE_CACHE="$CACHE/built" > "$WORK_DIR/depends.log" 2>&1 ||
    { tail -n 40 "$WORK_DIR/depends.log"; die "depends build failed (log: $WORK_DIR/depends.log)"; }

if [ ! -x "$SRC/configure" ] || [ "$SRC/configure.ac" -nt "$SRC/configure" ]; then
    log "autogen"
    ./autogen.sh > "$WORK_DIR/autogen.log" 2>&1 ||
        { tail -n 20 "$WORK_DIR/autogen.log"; die "autogen.sh failed"; }
fi

# --prefix=<depends prefix> makes configure load its share/config.site on its
# own, so automatic re-runs (config.status --recheck) keep the depends paths.
CONFIGURE_ARGS=(--with-gui=no --prefix="$SRC/depends/$HOST_TRIPLET")
[ "$CONFIG" = lowdiff ] && CONFIGURE_ARGS+=(--enable-low-difficulty-for-development)
OPT="-O2 -g"
LDEXTRA=""
if [ "$COVERAGE" = 1 ]; then
    # Atomic counters: the node and the tests are multi-threaded, and plain
    # counters lose updates and can even end up negative (lcov 2.0 then
    # refuses the data, e.g. for crypto/sha256.cpp).
    OPT="-O0 -g --coverage -fprofile-update=atomic"
    LDEXTRA="--coverage"
fi
if [ -n "$SANITIZERS" ]; then
    OPT="$OPT -fsanitize=$SANITIZERS -fno-omit-frame-pointer"
    LDEXTRA="$LDEXTRA -fsanitize=$SANITIZERS"
fi

mkdir -p "$BUILD"
cd "$BUILD"
# Re-run configure when asked, when there is no Makefile yet, or when the
# configure arguments changed since the last run in this build dir.
CONFIGURE_ID="${CONFIGURE_ARGS[*]} CFLAGS=$OPT CXXFLAGS=$OPT LDFLAGS=$LDEXTRA"
PREVIOUS_ID="$(cat .configure-args 2>/dev/null || true)"
if [ "$RECONFIGURE" = 1 ] || [ ! -f Makefile ] || [ "$PREVIOUS_ID" != "$CONFIGURE_ID" ]; then
    # make does not rebuild objects when only CFLAGS/CXXFLAGS change, so
    # changed arguments in an existing build dir need a clean build.
    NEED_CLEAN=0
    [ -f Makefile ] && [ "$PREVIOUS_ID" != "$CONFIGURE_ID" ] && NEED_CLEAN=1
    log "configure $BUILD_NAME: ${CONFIGURE_ARGS[*]} CFLAGS/CXXFLAGS='$OPT'"
    rm -f .configure-args
    CONFIG_SITE="$SRC/depends/$HOST_TRIPLET/share/config.site" \
        "$SRC/configure" "${CONFIGURE_ARGS[@]}" \
        CFLAGS="$OPT" CXXFLAGS="$OPT" LDFLAGS="$LDEXTRA" > configure.log 2>&1 ||
        { tail -n 30 configure.log; die "configure failed (log: $BUILD/configure.log)"; }
    if [ "$NEED_CLEAN" = 1 ]; then
        log "configure arguments changed: make clean"
        make clean > make-clean.log 2>&1 ||
            { tail -n 20 make-clean.log; die "make clean failed (log: $BUILD/make-clean.log)"; }
    fi
    echo "$CONFIGURE_ID" > .configure-args
fi

log "make -j$JOBS"
make -j"$JOBS" > make.log 2>&1 ||
    { grep -E " error:|\*\*\*" make.log | head -n 30; die "build failed (log: $BUILD/make.log)"; }
log "built: $BUILD/src/yacoind, yacoin-cli, test/test_bitcoin ($(grep -c ' warning:' make.log) compiler warnings)"

STATUS=0
WANT_COVERAGE=0
if [ "$COVERAGE" = 1 ] && [ "$RUN_UNIT$RUN_FUNCTIONAL" != 00 ]; then
    WANT_COVERAGE=1
    coverage_start
fi

if [ "$RUN_UNIT" = 1 ]; then
    log "unit tests"
    start=$(date +%s)
    if (cd src && ./test/test_bitcoin --log_level=test_suite --report_level=short) > unit.log 2>&1; then
        rc=0
    else
        rc=$?
    fi
    log "unit tests finished in $(( $(date +%s) - start )) s (exit $rc, log: $BUILD/unit.log)"
    grep -E "test cases? out of|assertions out of|error: in" unit.log | head -n 20 || true
    [ "$rc" = 0 ] || STATUS=1
fi

if [ "$RUN_FUNCTIONAL" = 1 ]; then
    # test_runner.py reads test/config.ini relative to its own location.
    cp test/config.ini "$SRC/test/config.ini"
    # Keep test datadirs and logs in the build dir (the container's /tmp is
    # discarded); older runs are removed first.
    rm -rf "${BUILD:?}/functional-tmp"
    mkdir -p "$BUILD/functional-tmp"
    log "functional tests ($FUNCTIONAL_ARGS)"
    start=$(date +%s)
    # shellcheck disable=SC2086
    if python3 "$SRC/test/functional/test_runner.py" --tmpdirprefix="$BUILD/functional-tmp" \
            $FUNCTIONAL_ARGS > functional.log 2>&1; then
        rc=0
    else
        rc=$?
    fi
    log "functional tests finished in $(( $(date +%s) - start )) s (exit $rc, log: $BUILD/functional.log)"
    grep -E "✖ Failed|^ALL" functional.log || true
    [ "$rc" = 0 ] || echo "failed tests keep their datadirs and logs under $BUILD/functional-tmp"
    [ "$rc" = 0 ] || STATUS=1
fi

# Captured even when tests failed; the exit code still reports the failure.
[ "$WANT_COVERAGE" = 1 ] && coverage_finish

exit "$STATUS"
