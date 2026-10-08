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
                            dir into WORK_DIR/coverage-report/, then run the
                            coverage gate (P0-04; exit 1 if a gate fails).
  --sanitizers LIST         Build with -fsanitize=LIST (e.g. address,undefined).
  --jobs N                  Parallel jobs (default: number of CPUs).
  --reconfigure             Re-run configure even if the build dir exists.
  --clean                   Delete the source copy and build dir first
                            (the depends cache is kept).
  --no-ccache               Compile without the compiler cache (task P0-65).

Test options:
  --unit                    Run the unit tests (src/test/test_bitcoin).
  --functional              Run the functional tests (needs --config lowdiff).
  --functional-args "ARGS"  Arguments for test_runner.py, replacing the
                            default -j4 (e.g. "-j4 wallet_dump.py").

Environment variables:
  TEST_RUNNER_PORT_MIN      Use this port base for the functional tests
                            instead of a port slot (1024-55535).
  YACOIN_PORT_LOCK_DIR      Directory of the port slot locks (default
                            /tmp/yacoin-build-ports).
  YACOIN_CCACHE_DIR         Compiler cache shared by all work dirs (default
                            ~/.cache/yacoin-ccache).
  YACOIN_CCACHE_MAXSIZE     Size limit of the compiler cache (default 5G).

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
per work dir at a time (a lock enforces this). With --functional the run
claims one of 10 port slots (preferred: a hash of the work dir), so runs in
different work dirs can test at the same time. Proxy and CA
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
PORT_MIN=""
USE_CCACHE=1
CCACHE_DIR_ARG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --config) need_arg "$1" "${2:-}"; CONFIG="$2"; CONFIG_SET=1; shift 2 ;;
        --coverage) COVERAGE=1; shift ;;
        --coverage-report) COVERAGE_REPORT=1; shift ;;
        --sanitizers) need_arg "$1" "${2:-}"; SANITIZERS="$2"; shift 2 ;;
        --jobs) need_arg "$1" "${2:-}"; JOBS="$2"; shift 2 ;;
        --reconfigure) RECONFIGURE=1; shift ;;
        --clean) CLEAN=1; shift ;;
        --no-ccache) USE_CCACHE=0; shift ;;
        --unit) RUN_UNIT=1; shift ;;
        --functional) RUN_FUNCTIONAL=1; shift ;;
        --functional-args) [ $# -ge 2 ] || die "$1 needs a value"; FUNCTIONAL_ARGS="$2"; shift 2 ;;
        --image) need_arg "$1" "${2:-}"; IMAGE="$2"; shift 2 ;;
        --no-docker) USE_DOCKER=0; shift ;;
        --work-dir) need_arg "$1" "${2:-}"; WORK_DIR="$2"; shift 2 ;;
        --in-container) IN_CONTAINER=1; USE_DOCKER=0; shift ;;
        --port-min) need_arg "$1" "${2:-}"; PORT_MIN="$2"; shift 2 ;;  # internal
        --ccache-dir) need_arg "$1" "${2:-}"; CCACHE_DIR_ARG="$2"; shift 2 ;;  # internal
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
CCACHE_MAXSIZE="${YACOIN_CCACHE_MAXSIZE:-5G}"
[[ "$CCACHE_MAXSIZE" =~ ^[0-9]+(\.[0-9]+)?([kMGT]i?)?$ ]] ||
    die "YACOIN_CCACHE_MAXSIZE must be a size such as 5G, 500M or 0 (no limit), not '$CCACHE_MAXSIZE'"
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

# ------------------------------------------------------------ port slots
# Functional tests bind p2p ports PORT_MIN + [0, 12 * tests] and rpc ports
# 5000 higher (test_framework/util.py p2p_port/rpc_port: seed * 12 + node;
# test_runner.py gives the tests of one run the seeds 0..tests-1 and
# create_cache.py the seed "tests"). Every run uses the
# same seeds, so two runs at the same time need different PORT_MIN values
# (with --network host they share the ports of this machine; task P0-61).
# Slot k: PORT_MIN = 11000 + 10000 * (k / 5) + 1000 * (k % 5), i.e. p2p
# 11000-15999 / rpc 16000-20999 for slots 0-4 and 21000-25999 / 26000-30999
# for slots 5-9: 1000 ports each (runs of up to 83 tests), disjoint, and
# below the Linux ephemeral port range (32768).
PORT_SLOTS=10
PORT_SLOT_WIDTH=1000
slot_port_min() { echo $(( 11000 + 10000 * ($1 / 5) + PORT_SLOT_WIDTH * ($1 % 5) )); }

# claim_port_slot: hold one slot's lock on fd 8 for the rest of the run
# (inherited by exec docker, like the work dir lock) and set PORT_MIN.
# Preferred slot: a hash of the work dir; if another run holds it, the next
# free one; if all are held, wait for the preferred one.
claim_port_slot() {
    local dir="${YACOIN_PORT_LOCK_DIR:-/tmp/yacoin-build-ports}" first i k f
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" || die "cannot create the port slot lock dir $dir (YACOIN_PORT_LOCK_DIR)"
        # Shared by all users of this machine; lock files are opened read-only.
        chmod 1777 "$dir" 2>/dev/null || true
    fi
    first=$(( $(printf '%s' "$WORK_DIR" | cksum | cut -d' ' -f1) % PORT_SLOTS ))
    for i in $(seq 0 $((PORT_SLOTS - 1))); do
        k=$(( (first + i) % PORT_SLOTS ))
        f="$dir/slot-$k.lock"
        [ -e "$f" ] || (umask 000; : >> "$f") 2>/dev/null || true
        [ -r "$f" ] || continue
        { exec 8<"$f"; } 2>/dev/null || continue
        if flock -n 8; then
            PORT_SLOT=$k
            break
        fi
        exec 8<&-
    done
    if [ -z "$PORT_SLOT" ]; then
        f="$dir/slot-$first.lock"
        [ -r "$f" ] || die "no usable port slot lock in $dir (set YACOIN_PORT_LOCK_DIR or TEST_RUNNER_PORT_MIN)"
        log "all $PORT_SLOTS port slots are in use; waiting for slot $first ($f)"
        exec 8<"$f"
        flock 8
        PORT_SLOT=$first
    fi
    PORT_MIN="$(slot_port_min "$PORT_SLOT")"
    [ "$PORT_SLOT" = "$first" ] || log "port slot $first is in use by another run; using slot $PORT_SLOT"
    log "functional test ports: slot $PORT_SLOT, p2p $PORT_MIN-$((PORT_MIN + PORT_SLOT_WIDTH - 1)), rpc $((PORT_MIN + 5000))-$((PORT_MIN + 5000 + PORT_SLOT_WIDTH - 1)) (lock $dir/slot-$PORT_SLOT.lock)"
}

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

    # Compiler cache (task P0-65), shared by all work dirs: every work dir
    # is mounted at /work, so the paths ccache hashes are the same in all
    # of them. Inside the checkout it would be mirrored into the work dir.
    if [ "$USE_CCACHE" = 1 ]; then
        CCACHE_HOST_DIR="$(realpath -m "${YACOIN_CCACHE_DIR:-$HOME/.cache/yacoin-ccache}")"
        case "$CCACHE_HOST_DIR/" in
            "$REPO"/*) die "YACOIN_CCACHE_DIR must be outside the checkout ($REPO)" ;;
        esac
        mkdir -p "$CCACHE_HOST_DIR" && [ -w "$CCACHE_HOST_DIR" ] ||
            die "compiler cache $CCACHE_HOST_DIR (YACOIN_CCACHE_DIR) is not writable; use --no-ccache or another dir"
    fi

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

    INNER_ARGS=(--in-container --functional-args "$FUNCTIONAL_ARGS")
    [ "$USE_CCACHE" = 1 ] || INNER_ARGS+=(--no-ccache)
    if [ "$RUN_FUNCTIONAL" = 1 ]; then
        PORT_SLOT=""
        if [ -n "${TEST_RUNNER_PORT_MIN:-}" ]; then
            case "$TEST_RUNNER_PORT_MIN" in
                *[!0-9]*) die "TEST_RUNNER_PORT_MIN must be a number, not '$TEST_RUNNER_PORT_MIN'" ;;
            esac
            if [ "$TEST_RUNNER_PORT_MIN" -lt 1024 ] || [ "$TEST_RUNNER_PORT_MIN" -gt 55535 ]; then
                die "TEST_RUNNER_PORT_MIN must be between 1024 and 55535 (p2p and rpc ports use up to 10000 above it)"
            fi
            PORT_MIN="$TEST_RUNNER_PORT_MIN"
            log "functional test ports: TEST_RUNNER_PORT_MIN=$PORT_MIN from the environment (no port slot)"
        else
            claim_port_slot
        fi
        INNER_ARGS+=(--port-min "$PORT_MIN")
    fi
    # --coverage-report covers both configurations and rejects --config.
    if [ "$COVERAGE_REPORT" = 1 ]; then
        INNER_ARGS+=(--coverage-report)
    else
        INNER_ARGS+=(--config "$CONFIG")
    fi
    [ "$COVERAGE" = 1 ] && INNER_ARGS+=(--coverage)
    [ -n "$SANITIZERS" ] && INNER_ARGS+=(--sanitizers "$SANITIZERS")
    [ -n "$JOBS" ] && INNER_ARGS+=(--jobs "$JOBS")
    [ "$RECONFIGURE" = 1 ] && INNER_ARGS+=(--reconfigure)
    [ "$RUN_UNIT" = 1 ] && INNER_ARGS+=(--unit)
    [ "$RUN_FUNCTIONAL" = 1 ] && INNER_ARGS+=(--functional)

    if [ "$USE_DOCKER" = 0 ]; then
        [ "$USE_CCACHE" = 1 ] && INNER_ARGS+=(--ccache-dir "$CCACHE_HOST_DIR")
        exec "$WORK_DIR/src/contrib/testing/build.sh" "${INNER_ARGS[@]}" --work-dir "$WORK_DIR"
    fi

    command -v docker >/dev/null || die "docker not found (use --no-docker inside the build image)"
    # --init: forward Ctrl-C/SIGTERM to the build so it stops together with
    # this script (and the lock is not released while the build still runs).
    DOCKER_ARGS=(run --rm --init -v "$WORK_DIR:/work" -w /work -e BUILD_GIT_COMMIT
                 --user "$(id -u):$(id -g)" -e HOME=/tmp --entrypoint /bin/bash)
    if [ "$USE_CCACHE" = 1 ]; then
        DOCKER_ARGS+=(-v "$CCACHE_HOST_DIR:/ccache" -e YACOIN_CCACHE_MAXSIZE="$CCACHE_MAXSIZE")
        INNER_ARGS+=(--ccache-dir /ccache)
    fi
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
# output, so the coverage gate (P0-04, coverage_gate.py) leaves them out.
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

    # Coverage gate (task P0-04): exclusions and minimums in
    # contrib/testing/coverage-gates.toml. The report above is written
    # either way; the exit code of the gate becomes the exit code of the run.
    log "coverage gate: $out/gate.txt"
    python3 "$SRC/contrib/testing/coverage_gate.py" --source-root "$SRC" --verbose --suggest \
        "$out/merged.info" > "$out/gate.txt" 2>&1 || GATE_RC=$?
    cat "$out/gate.txt"
}

if [ "$COVERAGE_REPORT" = 1 ]; then
    GATE_RC=0
    coverage_report
    exit "$GATE_RC"
fi

log "compiler: $(g++ --version | head -n1)"

# Compiler cache (task P0-65). configure puts the ccache from depends in
# front of CC/CXX; these settings apply to configure's compile tests and
# make. The compiler's -v output (version and configuration) is part of
# every hash, so objects of another GCC are never reused; headers are
# hashed by content. No CCACHE_BASEDIR: it would rewrite the paths given to
# the compiler (__FILE__, debug info, .gcno) – the fixed /work mount makes
# the paths equal in every work dir instead.
if [ "$USE_CCACHE" = 1 ] && [ -n "$CCACHE_DIR_ARG" ]; then
    export CCACHE_DIR="$CCACHE_DIR_ARG" CCACHE_MAXSIZE CCACHE_COMPRESS=1
    export CCACHE_COMPILERCHECK='%compiler% -v'
    unset CCACHE_DISABLE
    log "ccache: dir $CCACHE_DIR, max size $CCACHE_MAXSIZE, compressed"
else
    export CCACHE_DISABLE=1
    log "ccache: off"
fi
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

# ccache_stats: "hits misses" summed over ccache -s (3.3 format: "cache
# hit (direct)", "cache hit (preprocessed)", "cache miss").
ccache_stats() {
    "$CCACHE_BIN" -s 2>/dev/null | awk '
        /^cache hit \((direct|preprocessed)\)/ { h += $NF }
        /^cache miss/ { m += $NF }
        END { print h + 0, m + 0 }'
}
CCACHE_BIN=""
rm -f ccache.log ccache-summary.txt
if [ -z "${CCACHE_DISABLE:-}" ]; then
    CCACHE_BIN="$(sed -n 's/^CCACHE = //p' Makefile | head -n 1)"
    if [ -z "$CCACHE_BIN" ] || [ ! -x "$CCACHE_BIN" ]; then
        log "ccache: not used by configure (no CCACHE in the Makefile)"
        CCACHE_BIN=""
    fi
fi
[ -n "$CCACHE_BIN" ] && read -r CC_HITS0 CC_MISSES0 < <(ccache_stats)

log "make -j$JOBS"
make -j"$JOBS" > make.log 2>&1 ||
    { grep -E " error:|\*\*\*" make.log | head -n 30; die "build failed (log: $BUILD/make.log)"; }
if [ -n "$CCACHE_BIN" ]; then
    # The difference of the shared counters: compiles of other runs using
    # the same cache at the same time are counted too.
    "$CCACHE_BIN" -s > ccache.log 2>&1 || true
    read -r CC_HITS1 CC_MISSES1 < <(ccache_stats)
    CC_HITS=$(( CC_HITS1 - CC_HITS0 )) CC_MISSES=$(( CC_MISSES1 - CC_MISSES0 ))
    CC_RATE="n/a"
    [ $(( CC_HITS + CC_MISSES )) -gt 0 ] &&
        CC_RATE="$(awk -v h="$CC_HITS" -v m="$CC_MISSES" 'BEGIN { printf "%.1f %%", 100 * h / (h + m) }')"
    CC_SIZE="$(sed -n 's/^cache size *//p; s/^max cache size *//p' ccache.log | paste -sd/ | sed 's|/| / |')"
    CC_SUMMARY="ccache $BUILD_NAME: $CC_HITS hits, $CC_MISSES misses ($CC_RATE hit rate), cache $CC_SIZE"
    echo "$CC_SUMMARY" > ccache-summary.txt
    log "$CC_SUMMARY (log: $BUILD/ccache.log)"
fi
log "built: $BUILD/src/yacoind, yacoin-cli, test/test_bitcoin ($(grep -c ' warning:' make.log) compiler warnings)"

# run_vector_checkers: the independent Python models of the golden vector
# files (P0-13, P0-46, P0-19, P0-22); they use no node code, so they do not
# depend on the configuration. Output in <builddir>/vectors.log; 1 on a mismatch.
run_vector_checkers() {
    local rc=0 checker out
    : > vectors.log
    for checker in "bignum_vectors_check.py" "reward_vectors.py --check" "header_hash_vectors.py --check" "crypter_vectors.py --check"; do
        echo "== $checker" >> vectors.log
        # shellcheck disable=SC2086
        if out="$(python3 "$SRC/contrib/testing/"$checker 2>&1)"; then
            echo "$out" >> vectors.log
            log "vector check $checker: ok ($(echo "$out" | tail -n 1 | cut -c1-100))"
        else
            echo "$out" >> vectors.log
            log "vector check $checker: FAILED (log: $BUILD/vectors.log)"
            echo "$out" | tail -n 10
            rc=1
        fi
    done
    return "$rc"
}

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
    # test_bitcoin can end early with status 0 (e.g. exit() in node code):
    # require Boost's summary with every test case passed (task P0-61, Q8).
    if ! grep -qE "^ *([0-9]+) test cases? out of \1 passed$" unit.log; then
        echo "unit tests: no 'N test cases out of N passed' summary in $BUILD/unit.log (test_bitcoin ended early or not every test case passed)"
        STATUS=1
    fi
    run_vector_checkers || STATUS=1
fi

if [ "$RUN_FUNCTIONAL" = 1 ]; then
    # test_runner.py reads test/config.ini relative to its own location.
    cp test/config.ini "$SRC/test/config.ini"
    # Keep test datadirs and logs in the build dir (the container's /tmp is
    # discarded); older runs are removed first.
    rm -rf "${BUILD:?}/functional-tmp"
    mkdir -p "$BUILD/functional-tmp"
    # Port base of this run's slot (claimed on the host side, see above).
    [ -n "$PORT_MIN" ] && export TEST_RUNNER_PORT_MIN="$PORT_MIN"
    log "functional tests ($FUNCTIONAL_ARGS, TEST_RUNNER_PORT_MIN=${TEST_RUNNER_PORT_MIN:-11000})"
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
