#!/usr/bin/env bash
# Local developer build and test helper for yacoind.
#
# Always builds against the pinned libraries from depends/ (never system
# libraries), so local builds use the same dependency versions as CI.
# Build output and test data stay inside .devbuild/ and build/; the compiler
# cache and the built dependencies are in one cache directory that all
# checkouts share (DEV_CACHE). See doc/developer-build.md for the workflow.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Not HOST: some shells (e.g. tcsh) export HOST as the machine's hostname.
DEFAULT_HOST=x86_64-pc-linux-gnu
DEV_HOST="${DEV_HOST:-$DEFAULT_HOST}"
# What the caller set, before the defaults below: "container" passes only
# these on, so the images keep their own (CI's) defaults.
CALLER_JOBS="${JOBS:-}" CALLER_CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-}"
JOBS="${JOBS:-$(nproc)}"

# The cache shared by all checkouts: ccache, the depends sources, and per set
# of depends inputs (key) the built packages, depends' work area and the
# install prefix. Packages contain their install prefix, so checkouts with the
# same recipes share one prefix at one path, and other recipes get their own.
DEV_CACHE="${DEV_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/yacoin-dev}"
[[ "$DEV_CACHE" == /* ]] || DEV_CACHE="$PWD/$DEV_CACHE"
# The content of the files under depends/ that git does not ignore (tracked
# or not, so a recipe or patch not yet added counts), and the host. Not a git
# checkout: a key of its own, nothing shared.
depends_key() {
    local inputs
    if [[ "$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" == "$(cd "$ROOT" && pwd -P)" ]]; then
        inputs=$(cd "$ROOT" && git ls-files -z -co --exclude-standard -- depends | xargs -0 -r sha256sum -- 2>/dev/null) || true
    else
        inputs="tree $ROOT"
    fi
    printf '%s\nhost %s\n' "$inputs" "$DEV_HOST" | sha256sum | cut -c1-16
}
# A path component named "depends", so the coverage filter "*/depends/*"
# removes the dependency headers from reports.
DEPENDS_DIR="$DEV_CACHE/depends/$(depends_key)"
DEPENDS_PREFIX="$DEPENDS_DIR/$DEV_HOST"
# Builds for other hosts get their own directories, so a variant is never
# silently reused for a different host.
if [[ "$DEV_HOST" == "$DEFAULT_HOST" ]]; then
    BUILD_ROOT="$ROOT/build"
else
    BUILD_ROOT="$ROOT/build/$DEV_HOST"
fi
# Exported rather than set only for the initial configure: make re-runs
# configure by itself when configure changes (e.g. after autogen), and that
# re-run must also see the depends settings. cmd_depends removes it again.
export CONFIG_SITE="$DEPENDS_PREFIX/share/config.site"
DEVBUILD="$ROOT/.devbuild"

# The shared ccache, even if the environment points CCACHE_DIR elsewhere.
# With -g, ccache includes the build directory in the cache key, with the
# debug prefix map applied (variant_flags): variants get their own entries,
# while the same variant in another checkout gets the same ones. Coverage
# builds keep entries per checkout, as ccache also keys them on the path of
# their .gcda files.
export CCACHE_DIR="$DEV_CACHE/ccache"
export CCACHE_BASEDIR="$ROOT"
export CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-10G}"
# Temporary test data stays inside the checkout.
export TMPDIR="$DEVBUILD/tmp"

usage() {
    cat <<EOF
Usage: ./dev.sh <command> [args]

  depends [qt]            Build the pinned dependencies (NO_QT unless "qt")
  configure <variant>     (Re)configure build/<variant>
  build <variant> [tgt]   Build build/<variant> (optionally one make target)
  unit [suite...]         Build test_bitcoin (dev) and run unit test suites;
                          no suites = all suites, in parallel (UNIT_JOBS)
  check                   Full "make check" on build/dev (serial, as upstream)
  ftest [test...]         Functional tests on build/func, FTEST_JOBS in
                          parallel (default 4)
  asan [suite...]         Build and run unit tests with ASan + UBSan
  cov                     Unit, functional and combined coverage reports
                          (needs lcov 2.6+) in .devbuild/coverage/, then cov-check
  cov-check [args]        Check .devbuild/coverage/ against the targets in
                          contrib/devtools/coverage-targets.json; args go to
                          coverage-check.py (e.g. --per-function src/init.cpp)
  all                     dev build, unit, ftest and release build; runs every
                          step and prints a summary
  ccache-stats            Show ccache statistics
  cache                   Print the paths of the shared cache
  container [options] [image] [mode]
                          Build a CI image from ci/containers/ and run a mode
                          in it on this checkout (default: ubuntu.22.04 build;
                          options: ci/containers/run.sh --help)

Variants: dev (mainnet consensus, no GUI, -O1 -g), func (dev + low difficulty),
          release (default optimisation),
          asan (dev + AddressSanitizer/UndefinedBehaviorSanitizer),
          cov-unit and cov-func (coverage builds used by "cov")

Cache shared by all checkouts (ccache and the built dependencies; DEV_CACHE
sets it, removing the directory clears it):
  $DEV_CACHE
EOF
}

log() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }

timed() {
    local start=$SECONDS
    "$@"
    log "$1 ${2:-} finished in $((SECONDS - start))s"
}

ensure_dirs() {
    mkdir -p "$CCACHE_DIR" "$TMPDIR" "$DEVBUILD/logs"
    # ccache 3.3.4 creates its config on first use, and parallel first
    # compiles on an empty cache race for it ("ccache.conf: No such file or
    # directory"). An empty file means the defaults.
    [[ -e "$CCACHE_DIR/ccache.conf" ]] || touch "$CCACHE_DIR/ccache.conf"
}

cmd_cache() {
    printf '%s=%s\n' DEV_CACHE "$DEV_CACHE" CCACHE_DIR "$CCACHE_DIR" SOURCES_PATH "$DEV_CACHE/depends/sources" \
        DEPENDS_DIR "$DEPENDS_DIR" DEPENDS_PREFIX "$DEPENDS_PREFIX"
}

cmd_depends() {
    ensure_dirs  # TMPDIR is used by the package builds
    # depends' make variable for the install prefix: <arch>_<os>_prefix.
    local canon os
    canon=$("$ROOT/depends/config.sub" "$DEV_HOST")
    case "$canon" in
        *linux*) os=linux ;; *darwin*) os=darwin ;; *mingw32*) os=mingw32 ;; *) os="${canon#*-*-}" ;;
    esac
    local w="$DEPENDS_DIR/work"
    local args=(-C "$ROOT/depends" -j"$JOBS" HOST="$DEV_HOST" "${canon%%-*}_${os}_prefix=$DEPENDS_PREFIX"
                BASE_CACHE="$DEPENDS_DIR/built" SOURCES_PATH="$DEV_CACHE/depends/sources"
                base_build_dir="$w/build" base_staging_dir="$w/staging" base_download_dir="$w/download")
    [[ "${1:-}" == qt ]] || args+=(NO_QT=1)
    # One depends build at a time in the cache: the prefix is depends' work
    # area while it builds, and the sources are shared by all keys.
    local lock="$DEV_CACHE/depends.lock" fd
    exec {fd}>> "$lock"
    flock -n "$fd" || { log "Waiting for another depends build ($lock)"; flock "$fd"; }
    # Even with nothing to build, depends removes the prefix and unpacks it
    # again, under the builds of other checkouts with the same recipes. So
    # make is skipped when the last successful run had the same inputs: the
    # Qt choice and the compilers whose versions are in depends' build ids
    # (the recipes are in the key). A skipped run does not recheck the cached
    # packages; removing the stamp (or the cache) forces a full run.
    local stamp="$DEPENDS_DIR/depends.stamp" inputs t v
    inputs="qt: ${1:-}"$'\n'
    for t in gcc g++ "$DEV_HOST-gcc" "$DEV_HOST-g++"; do
        v=$("$t" --version 2>/dev/null) || v=""
        inputs+="$t: ${v%%$'\n'*}"$'\n'
    done
    if [[ -f "$DEPENDS_PREFIX/share/config.site" && "$(cat "$stamp" 2>/dev/null)"$'\n' == "$inputs" ]]; then
        log "Dependencies up to date in $DEPENDS_PREFIX"
        return
    fi
    rm -f "$stamp"
    # The depends packages run their own configure scripts with their own
    # settings; they must not read the config.site meant for yacoind.
    env -u CONFIG_SITE make "${args[@]}"
    printf '%s' "$inputs" > "$stamp"
}

# A build directory configured against another prefix (other recipes, or
# the prefix inside the checkout) would mix two sets of libraries.
check_prefix() {
    [[ ! -f "$1/config.status" ]] || grep -qF -- "$DEPENDS_PREFIX/" "$1/config.status" || {
        echo "${1#"$ROOT"/} was configured against other dependencies than $DEPENDS_PREFIX." >&2
        echo "Remove it (rm -rf ${1#"$ROOT"/}) to build it again." >&2
        exit 1
    }
}

# Runs autogen.sh when configure or the helper files it needs are missing.
# The helpers in build-aux/ aren't tracked by git, so a clone that already
# has a configure script can still be missing them.
# Also reruns it when the autotools inputs changed since the last run, because
# new build directories use configure and the Makefile.in files directly.
# Compares content, not timestamps, so a branch switch alone doesn't trigger it.
# Only tracked files are hashed (including the secp256k1 and univalue
# subprojects), so files that autogen.sh itself generates (aclocal.m4
# included) don't change it. Git pathspec wildcards also match across
# directories. Without git (e.g. a source tarball) the hash is constant, so
# autogen only runs when files are missing.
autotools_inputs_sum() {
    (cd "$ROOT" && git ls-files -z -- '*configure.ac' '*Makefile.am' 'src/Makefile*.include' \
        '*.m4' 2>/dev/null | xargs -0 -r cat 2>/dev/null |
        sha256sum | cut -d' ' -f1) || true
}

ensure_autogen() {
    local sum stamp="$DEVBUILD/autogen.sum"
    sum=$(autotools_inputs_sum)
    if [[ ! -x "$ROOT/configure" || ! -f "$ROOT/aclocal.m4" ||
          ! -f "$ROOT/build-aux/install-sh" || ! -f "$ROOT/build-aux/ltmain.sh" ||
          "$(cat "$stamp" 2>/dev/null)" != "$sum" ]]; then
        (cd "$ROOT" && ./autogen.sh)
        echo "$sum" > "$stamp"
    fi
}

# Sets the configure arguments for a build variant in the array "flags".
variant_flags() {
    local san="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
    # Debug info names paths relative to the checkout (gdb finds the sources
    # when started in it), so other checkouts can share the cached objects.
    flags=(--without-gui --disable-man --enable-ccache "CPPFLAGS=-fdebug-prefix-map=$ROOT=.")
    # Unit tests run on the mainnet build (CI also runs them on the
    # low-difficulty one), while the functional tests need the low-difficulty
    # build, as in CI.
    case "$1" in
        dev)
            flags+=("CXXFLAGS=-O1 -g" "CFLAGS=-O1 -g") ;;
        func)
            flags+=(--enable-low-difficulty-for-development
                    "CXXFLAGS=-O1 -g" "CFLAGS=-O1 -g") ;;
        release)
            ;;
        asan)
            # secp256k1's x86_64 field assembly needs more registers than are
            # left under ASan, so build it in plain C (passed to its configure).
            flags+=(--with-asm=no
                    "CXXFLAGS=-O1 -g $san" "CFLAGS=-O1 -g $san" "LDFLAGS=$san") ;;
        # Coverage builds: -O0 so lines and branches map exactly to the source.
        cov-unit)
            flags+=(--enable-lcov "CXXFLAGS=-O0 -g" "CFLAGS=-O0 -g") ;;
        cov-func)
            flags+=(--enable-lcov --enable-low-difficulty-for-development
                    "CXXFLAGS=-O0 -g" "CFLAGS=-O0 -g") ;;
        *) echo "unknown variant: $1" >&2; exit 2 ;;
    esac
}

cmd_configure() {
    local variant="${1:?variant required}"
    # Validate the variant before creating anything.
    local flags
    variant_flags "$variant"
    [[ -f "$CONFIG_SITE" ]] || { echo "Run ./dev.sh depends first" >&2; exit 1; }
    if [[ -f "$ROOT/config.status" ]]; then
        echo "The source tree was configured in place, which blocks out-of-tree builds." >&2
        echo "Run 'make distclean' in $ROOT first." >&2
        exit 1
    fi
    local dir="$BUILD_ROOT/$variant"
    check_prefix "$dir"
    ensure_dirs
    ensure_autogen
    mkdir -p "$dir"
    (cd "$dir" && "$ROOT/configure" "${flags[@]}")
    # The functional test runner reads ../config.ini relative to its own path,
    # so give each out-of-tree build its own runner that points at its config.
    mkdir -p "$dir/test/functional"
    ln -sf "$ROOT/test/functional/test_runner.py" "$dir/test/functional/test_runner.py"
}

cmd_build() {
    local variant="${1:?variant required}"
    local dir="$BUILD_ROOT/$variant"
    ensure_dirs
    check_prefix "$dir"
    [[ -f "$dir/Makefile" ]] || cmd_configure "$variant"
    # Nothing in "make all" depends on test/config.ini, so changes to
    # test/config.ini.in would otherwise only reach it on a reconfigure.
    make -s -C "$dir" test/config.ini
    if [[ -n "${2:-}" ]]; then
        make -C "$dir/src" -j"$JOBS" "$2"
    else
        make -C "$dir" -j"$JOBS"
    fi
}

# Runs Boost test suites as separate parallel processes (see the script).
# Logs are per variant, so e.g. unit and asan can run at the same time.
run_unit_suites() {
    local variant="$1" bin="$2"; shift 2
    "$ROOT/contrib/devtools/run-unit-suites.sh" "$bin" "$DEVBUILD/logs/unit-$variant" \
        "${UNIT_JOBS:-$JOBS}" "$@"
}

cmd_unit() {
    cmd_build dev test/test_bitcoin
    run_unit_suites dev "$BUILD_ROOT/dev/src/test/test_bitcoin" "$@"
}

cmd_check() {
    cmd_build dev
    make -C "$BUILD_ROOT/dev" check
}

cmd_ftest() {
    cmd_build func
    "$BUILD_ROOT/func/test/functional/test_runner.py" -j "${FTEST_JOBS:-4}" --tmpdirprefix="$TMPDIR" "$@"
}

cmd_asan() {
    cmd_build asan test/test_bitcoin
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1}" \
        run_unit_suites asan "$BUILD_ROOT/asan/src/test/test_bitcoin" "$@"
}

# Unit test coverage (mainnet build) and functional test coverage
# (low-difficulty build), then both merged and checked against the targets
# (cmd_cov_check). The Makefile targets capture coverage even when tests fail,
# so all reports are written either way.
cmd_cov() {
    local out="$DEVBUILD/coverage" status=0 v
    ensure_dirs
    # Only configure here: the make targets build what they need.
    for v in cov-unit cov-func; do
        check_prefix "$BUILD_ROOT/$v"
        [[ -f "$BUILD_ROOT/$v/Makefile" ]] || cmd_configure "$v"
    done
    make -s -C "$BUILD_ROOT/cov-func" test/config.ini
    # Delete old reports here too, not only in the make targets: if make fails
    # before a recipe runs, an old report must not be shown as this run's.
    # A report that exists after make comes from this run, even if tests failed.
    rm -rf "$BUILD_ROOT/cov-unit/test_bitcoin.coverage" "$BUILD_ROOT/cov-unit/test_bitcoin_coverage.info" \
        "$BUILD_ROOT/cov-unit/test_bitcoin_functions.json" \
        "$BUILD_ROOT/cov-func/functional_test.coverage" "$BUILD_ROOT/cov-func/functional_test_coverage.info" \
        "$BUILD_ROOT/cov-func/functional_test_functions.json"
    make -C "$BUILD_ROOT/cov-unit" -j"$JOBS" COV_JOBS="$JOBS" cov-unit || status=1
    # FTEST_JOBS, if set, replaces the Makefile's number of parallel scripts.
    make -C "$BUILD_ROOT/cov-func" -j"$JOBS" COV_JOBS="$JOBS" ${FTEST_JOBS:+FTEST_JOBS="$FTEST_JOBS"} cov-functional || status=1
    # Use the lcov and genhtml settings configure and Makefile.am chose, so the
    # merged report matches the per-build reports. Read after make, which may
    # have regenerated the Makefile.
    local mk="$BUILD_ROOT/cov-unit/Makefile" lcov genhtml
    read -ra lcov <<< "$(sed -n 's/^LCOV = //p' "$mk") $(sed -n 's/^LCOV_OPTS = //p' "$mk")"
    read -ra genhtml <<< "$(sed -n 's/^GENHTML = //p' "$mk") $(sed -n 's/^LCOV_OPTS = //p' "$mk") $(sed -n 's/^GENHTML_OPTS = //p' "$mk")"
    rm -rf "$out"; mkdir -p "$out"
    local parts=() src_dir src_info src_functions part
    for part in unit functional; do
        if [[ $part == unit ]]; then
            src_dir="$BUILD_ROOT/cov-unit/test_bitcoin.coverage"
            src_info="$BUILD_ROOT/cov-unit/test_bitcoin_coverage.info"
            src_functions="$BUILD_ROOT/cov-unit/test_bitcoin_functions.json"
        else
            src_dir="$BUILD_ROOT/cov-func/functional_test.coverage"
            src_info="$BUILD_ROOT/cov-func/functional_test_coverage.info"
            src_functions="$BUILD_ROOT/cov-func/functional_test_functions.json"
        fi
        if [[ -f "$src_info" && -d "$src_dir" ]]; then
            cp -r "$src_dir" "$out/$part"; cp "$src_info" "$out/$part.info"; parts+=("$part")
        else
            echo "No $part coverage report was produced." >&2; status=1
        fi
        # The function extents, for the per-function numbers of cov-check.
        if [[ -f "$src_functions" ]]; then cp "$src_functions" "$out/${part}_functions.json"; fi
    done
    # Both builds record the same absolute source paths, so lcov merges them
    # per file. See doc/developer-build.md for the limits of this merge.
    if [[ ${#parts[@]} -eq 2 ]]; then
        "${lcov[@]}" -q -a "$out/unit.info" -a "$out/functional.info" -o "$out/total.info"
        "${genhtml[@]}" -q "$out/total.info" -o "$out/total"
        parts+=(total)
    fi
    for part in "${parts[@]}"; do
        log "Coverage: $part (${out#"$ROOT"/}/$part/index.html)"
        "${lcov[@]}" --summary "$out/$part.info" 2>&1 | grep -E '^ +(lines|functions|branches)' || true
    done
    if [[ -f "$out/total.info" ]]; then
        log "Coverage check"
        cmd_cov_check || status=1
    fi
    [[ "$status" -eq 0 ]] || { echo "Tests failed, a report is missing or the coverage check failed; see ${BUILD_ROOT#"$ROOT"/}/cov-*/*.log" >&2; return 1; }
}

# Checks the reports of "cov" against contrib/devtools/coverage-targets.json
# (contrib/devtools/coverage-check.py); arguments go to the script.
# shellcheck disable=SC2120 # cmd_cov passes none, the command line may
cmd_cov_check() {
    local out="$DEVBUILD/coverage" functions=() f
    [[ -f "$out/unit.info" && -f "$out/total.info" ]] ||
        { echo "No coverage reports in ${out#"$ROOT"/}; run ./dev.sh cov first" >&2; return 1; }
    for f in "$out/unit_functions.json" "$out/functional_functions.json"; do
        [[ ! -f "$f" ]] || functions+=("$f")
    done
    python3 -I -B "$ROOT/contrib/devtools/coverage-check.py" --unit "$out/unit.info" --all "$out/total.info" \
        ${functions[@]+--functions "${functions[@]}"} "$@"
}

# Builds a CI image from ci/containers/ and runs one of its modes on this
# checkout, with the cache in .devbuild/container-cache (ci/containers/run.sh).
# Options go to run.sh. The image can be left out: a first argument that is
# a mode is a mode. JOBS and CCACHE_MAXSIZE are passed on only if the caller
# set them, not dev.sh's own defaults.
cmd_container() {
    local opts=() image=ubuntu.22.04
    while [[ "${1:-}" == -* ]]; do
        case "$1" in
            --src|--cache|--name) opts+=("$1" "${2:?$1 needs a value}"); shift 2 ;;
            *) opts+=("$1"); shift ;;
        esac
    done
    case "${1:-}" in
        ""|build|build-low-difficulty|unit-tests|functional-tests|cov-unit|cov-functional) ;;
        *) image="$1"; shift ;;
    esac
    local env_args=(-u JOBS -u CCACHE_MAXSIZE)
    [[ -z "$CALLER_JOBS" ]] || env_args+=("JOBS=$CALLER_JOBS")
    [[ -z "$CALLER_CCACHE_MAXSIZE" ]] || env_args+=("CCACHE_MAXSIZE=$CALLER_CCACHE_MAXSIZE")
    env "${env_args[@]}" "$ROOT/ci/containers/run.sh" ${opts[@]+"${opts[@]}"} "$image" "$@"
}

# Runs every step even if an earlier one fails, then prints a summary. Each
# step runs as its own dev.sh process: inside an "if", bash ignores set -e in
# functions, so calling the functions directly would hide failures.
cmd_all() {
    local steps=("build dev" "unit" "ftest" "build release") step status=0 summary=()
    for step in "${steps[@]}"; do
        # shellcheck disable=SC2086 # step is split into command and arguments
        if "$ROOT/dev.sh" $step; then
            summary+=("PASS  $step")
        else
            summary+=("FAIL  $step"); status=1
        fi
    done
    log "Summary"
    printf '  %s\n' "${summary[@]}"
    return "$status"
}

case "${1:-}" in
    cache) cmd_cache ;;
    depends|configure|build|unit|check|ftest|asan|cov|cov-check|all|container)
        c="${1//-/_}"; shift; timed "cmd_$c" "$@" ;;
    # configure picks up the pinned ccache built by depends, so query that one.
    ccache-stats) "$DEPENDS_PREFIX/native/bin/ccache" -s ;;
    *) usage; exit 1 ;;
esac
