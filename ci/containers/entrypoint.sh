#!/bin/bash
# Entrypoint of the Linux yacoin-build images.
#
# Usage (the YaCoin source tree is mounted at /src):
#   docker run -v <yacoin>:/src [-v <cache>:/cache] [-e JOBS=n] IMAGE [MODE]
#
# Modes:
#   build             release build (default): depends, configure with glibc
#                     back-compat, make, make install into /src/release-root
#   build-low-difficulty
#                     the release build with --enable-low-difficulty-for-development,
#                     then all unit test suites of its test_bitcoin in parallel
#                     (logs in /src/build/docker-<image>/build-low-difficulty/
#                     unit-test-logs, recreated on every run)
#   unit-tests        build test_bitcoin and bench_yacoin (mainnet consensus,
#                     --enable-bench), run all unit test suites in parallel,
#                     then print the CPU model and run every benchmark once in
#                     its short mode (bench_yacoin -time=0.01)
#   unit-tests-asan   unit-tests under AddressSanitizer, LeakSanitizer and
#                     UBSan (the sanitizer flags of dev.sh's asan variant,
#                     with -g1 instead of -g), with the LeakSanitizer
#                     suppressions of test/sanitizer_suppressions/lsan; any
#                     report fails its suite. SANITIZE=address builds with
#                     AddressSanitizer and LeakSanitizer only,
#                     SANITIZE=undefined with UBSan only; unset, with both.
#                     The test cases listed in
#                     test/sanitizer_suppressions/asan-excluded-cases are
#                     left out, with each choice. Ubuntu 22.04 image only
#   unit-tests-tsan   unit-tests under ThreadSanitizer, with the suppressions
#                     of test/sanitizer_suppressions/tsan; any report fails
#                     its suite. The suites run with address randomisation
#                     off (setarch -R), which needs the container started
#                     with --security-opt seccomp=unconfined (run.sh and the
#                     CI job do); Ubuntu 22.04 image only
#   fuzz-corpus       build the libFuzzer binary src/test/fuzz/fuzz with clang
#                     (--enable-fuzz) under AddressSanitizer, LeakSanitizer
#                     and UBSan, then run every input of the corpus in
#                     test/fuzz/corpus/<target>/ once through its target
#                     (contrib/devtools/run-fuzz-corpus.py, logs in
#                     /src/build/docker-<image>/fuzz-corpus/fuzz-corpus-logs);
#                     any report fails the mode. Ubuntu 22.04 image only
#   functional-tests  low-difficulty build, then all functional test scripts,
#                     the extended ones too, FTEST_JOBS in parallel; with
#                     FTEST_SHARD=K/N only shard K of N of them
#                     (test_runner.py --shard)
#   functional-tests-asan
#                     functional-tests under AddressSanitizer, LeakSanitizer
#                     and UBSan (the flags and runtime options of
#                     unit-tests-asan with both sanitizers; FTEST_SHARD as in
#                     functional-tests); every process a script starts writes
#                     its reports to <builddir>/sanitizer-logs/<script's test
#                     directory>.<executable>.<pid>. A script with a report
#                     fails, and any report fails the mode, whatever the
#                     scripts' outcome; the reports are printed at the end.
#                     The scripts listed in
#                     test/sanitizer_suppressions/asan-excluded-scripts are
#                     left out. Ubuntu 22.04 image only
#   cov-unit          coverage build (--enable-lcov, -O0) and "make cov-unit";
#                     needs lcov 2.6 or newer (Ubuntu 22.04 image only)
#   cov-functional    low-difficulty coverage build and "make cov-functional"
#                     (functional test scripts FTEST_JOBS in parallel; with
#                     FTEST_SHARD=K/N only shard K of N of them); needs
#                     lcov 2.6 or newer
#
# The test modes build out of tree in /src/build/docker-<image>/<mode>, which
# is recreated on every run. If a cache dir is mounted at /cache, depends
# packages, depends sources and ccache data are kept there between runs, per
# image (only one container per image should use the cache at a time).
#
# Environment: JOBS (default: number of CPUs), BUILDVERSION (passed through
# to the version string), FTEST_JOBS (functional-tests, functional-tests-asan,
# cov-functional: functional test scripts in parallel, default 4: the CI
# runners' vCPUs and the number the run times were measured with; a fixed
# default, so a local run schedules the scripts as CI does whatever its CPU
# count), FTEST_SHARD (the same modes: K/N runs shard K of N of the scripts;
# unset: all), SANITIZE (unit-tests-asan: address or undefined; unset: both).
# SRC_DIR and CACHE_DIR override /src and /cache.
set -euo pipefail

MODE="${1:-build}"
SRC="${SRC_DIR:-/src}"
CACHE="${CACHE_DIR:-/cache}"
IMAGE="${YACOIN_BUILD_IMAGE:-unknown}"
HOST_TRIPLET=x86_64-pc-linux-gnu
# unit-tests: the time per benchmark of its short run, in seconds; runs
# each benchmark once or a few times
BENCH_TIME=0.01

die() { echo "error: $*" >&2; exit 1; }

# CPUs available to this container: nproc, limited by a cgroup v2 CPU quota
# (docker run --cpus), which nproc doesn't see.
available_cpus() {
    local n quota="" period="" cpus
    n=$(nproc)
    if [[ -r /sys/fs/cgroup/cpu.max ]]; then                      # cgroup v2
        read -r quota period < /sys/fs/cgroup/cpu.max
        [[ "$quota" == max ]] && quota=""
    elif [[ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]]; then       # cgroup v1
        quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
        period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
        (( quota > 0 )) || quota=""
    fi
    if [[ -n "$quota" && "$period" -gt 0 ]]; then
        cpus=$(( (quota + period - 1) / period ))
        if (( cpus >= 1 && cpus < n )); then n=$cpus; fi
    fi
    echo "$n"
}
JOBS="${JOBS:-$(available_cpus)}"

case "$MODE" in
    build|build-low-difficulty|unit-tests|unit-tests-asan|unit-tests-tsan|fuzz-corpus|functional-tests|functional-tests-asan|cov-unit|cov-functional) ;;
    *) echo "unknown mode '$MODE' (build, build-low-difficulty, unit-tests, unit-tests-asan, unit-tests-tsan, fuzz-corpus, functional-tests, functional-tests-asan, cov-unit, cov-functional)" >&2; exit 2 ;;
esac
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "JOBS must be a positive integer"
[[ "${FTEST_JOBS:-4}" =~ ^[1-9][0-9]*$ ]] || die "FTEST_JOBS must be a positive integer"
if [[ -n "${FTEST_SHARD:-}" ]]; then
    [[ "$FTEST_SHARD" =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] && (( BASH_REMATCH[1] <= BASH_REMATCH[2] )) ||
        die "FTEST_SHARD must be K/N with 1 <= K <= N, not '$FTEST_SHARD'"
fi

cd "$SRC"
echo "== yacoin-build ($IMAGE): $MODE in $SRC with $JOBS jobs =="

# The release build modes configure in the source tree and install into
# /src/release-root; the others build out of tree.
release=0
[[ "$MODE" != build && "$MODE" != build-low-difficulty ]] || release=1

# Checks before the long depends build.
if (( ! release )); then
    # Out-of-tree configure refuses a source tree that was configured in place.
    [[ ! -f "$SRC/config.status" ]] ||
        die "$SRC was configured in place (e.g. by the build mode); run 'make distclean' in it first"
fi
if [[ "$MODE" == unit-tests || "$MODE" == unit-tests-asan || "$MODE" == unit-tests-tsan || "$MODE" == build-low-difficulty ]]; then
    [[ -x contrib/devtools/run-unit-suites.sh ]] ||
        die "this YaCoin tree has no contrib/devtools/run-unit-suites.sh (needs master after PR #114)"
fi
# LeakSanitizer fails every run when its suppression file can't be read, and
# run-unit-suites.sh when its list of test cases to leave out can't.
lsan_suppressions="$SRC/test/sanitizer_suppressions/lsan"
asan_excluded_cases="$SRC/test/sanitizer_suppressions/asan-excluded-cases"
if [[ "$MODE" == unit-tests-asan ]]; then
    # The mode, its runtime options and the tests are verified with this
    # image's compiler (gcc 11) only.
    [[ "$IMAGE" == ubuntu.22.04 ]] || die "unit-tests-asan runs only in the Ubuntu 22.04 image (this is $IMAGE)"
    [[ -f "$lsan_suppressions" ]] || die "this YaCoin tree has no test/sanitizer_suppressions/lsan"
    [[ -f "$asan_excluded_cases" ]] || die "this YaCoin tree has no test/sanitizer_suppressions/asan-excluded-cases"
    [[ "${SANITIZE:-}" =~ ^(|address|undefined)$ ]] ||
        die "SANITIZE must be address, undefined or unset (both), not '$SANITIZE'"
fi
# test_runner.py fails after the build when it can't read its list of scripts
# to leave out; the mode checks for it first.
asan_excluded_scripts="$SRC/test/sanitizer_suppressions/asan-excluded-scripts"
if [[ "$MODE" == functional-tests-asan ]]; then
    [[ "$IMAGE" == ubuntu.22.04 ]] || die "functional-tests-asan runs only in the Ubuntu 22.04 image (this is $IMAGE)"
    [[ -f "$lsan_suppressions" ]] || die "this YaCoin tree has no test/sanitizer_suppressions/lsan"
    [[ -f "$asan_excluded_scripts" ]] || die "this YaCoin tree has no test/sanitizer_suppressions/asan-excluded-scripts"
    # Without the options the runner would pass them on to every script,
    # which would all fail on them after the build.
    runner_src=$(cat test/functional/test_runner.py 2>/dev/null) || runner_src=""
    for option in --sanitizer-logs --exclude-file; do
        grep -q -- "$option" <<< "$runner_src" ||
            die "this YaCoin tree's test/functional/test_runner.py has no $option option"
    done
fi
# Without them the runner would pass --shard on to every script, and make
# would run every script in each shard.
if [[ -n "${FTEST_SHARD:-}" ]]; then
    case "$MODE" in
        functional-tests|functional-tests-asan)
            runner_src=$(cat test/functional/test_runner.py 2>/dev/null) || runner_src=""
            grep -q -- --shard <<< "$runner_src" ||
                die "this YaCoin tree's test/functional/test_runner.py has no --shard option (FTEST_SHARD)" ;;
        cov-functional)
            grep -q FTEST_SHARD Makefile.am ||
                die "this YaCoin tree's cov-functional target takes no FTEST_SHARD" ;;
    esac
fi
# ThreadSanitizer fails every run when its suppression file can't be read.
tsan_suppressions="$SRC/test/sanitizer_suppressions/tsan"
if [[ "$MODE" == unit-tests-tsan ]]; then
    # The mode, its runtime options and the tests are verified with this
    # image's compiler (gcc 11) only.
    [[ "$IMAGE" == ubuntu.22.04 ]] || die "unit-tests-tsan runs only in the Ubuntu 22.04 image (this is $IMAGE)"
    [[ -f "$tsan_suppressions" ]] || die "this YaCoin tree has no test/sanitizer_suppressions/tsan"
    # gcc 11's ThreadSanitizer runtime stops at start ("unexpected memory
    # mapping") under the address randomisation of current kernels, so the
    # suites run with it turned off for their processes. Docker's default
    # seccomp filter refuses that. The personality is read back, since an
    # older setarch (util-linux 2.27) ignores the refusal.
    personality=$(setarch "$(uname -m)" -R cat /proc/self/personality 2>/dev/null) || personality=""
    [[ "$personality" =~ ^[0-9a-f]+$ ]] && (( (16#$personality & 16#0040000) != 0 )) ||
        die "unit-tests-tsan cannot turn address randomisation off (setarch -R); start the container with --security-opt seccomp=unconfined"
fi
# The fuzz binary is built with this image's clang 14 (its libFuzzer and
# sanitizer runtimes; llvm-symbolizer for the stack traces).
fuzz_corpus="$SRC/test/fuzz/corpus"
llvm_bin=/usr/lib/llvm-14/bin
if [[ "$MODE" == fuzz-corpus ]]; then
    [[ "$IMAGE" == ubuntu.22.04 ]] || die "fuzz-corpus runs only in the Ubuntu 22.04 image (this is $IMAGE)"
    [[ -x contrib/devtools/run-fuzz-corpus.py ]] || die "this YaCoin tree has no contrib/devtools/run-fuzz-corpus.py"
    [[ -d "$fuzz_corpus" ]] || die "this YaCoin tree has no fuzz corpus in test/fuzz/corpus"
    [[ -x "$llvm_bin/clang++" ]] || die "this image has no clang in $llvm_bin"
fi
if [[ "$MODE" == cov-unit || "$MODE" == cov-functional ]]; then
    grep -q "^$MODE:" Makefile.am ||
        die "this YaCoin tree has no $MODE target"
    lcov_version=$(lcov --version 2>/dev/null) || lcov_version=""
    grep -Eq 'version (2\.([6-9]|[1-9][0-9])|[3-9]|[1-9][0-9])' <<< "$lcov_version" ||
        die "$MODE needs lcov 2.6 or newer; use the Ubuntu 22.04 image"
fi

# For genbuild.sh, which runs git on the mounted tree. The list is captured
# first, as grep -q at the end of a pipe under pipefail can read as no match.
safe_dirs=$(git config --global --get-all safe.directory 2>/dev/null) || safe_dirs=""
grep -qx "$SRC" <<< "$safe_dirs" ||
    git config --global --add safe.directory "$SRC"

# The release builds install depends into the tree's usual prefix. The test
# modes install a no-Qt depends into a prefix of their own, per
# image, so they never replace the libraries a host build (dev.sh) or another
# image's build is linked against. (x86_64_linux_prefix is the depends make
# variable for this host's install prefix.)
depends_args=(-C depends -j"$JOBS" HOST="$HOST_TRIPLET")
# depends keeps one cached tarball per package and deletes the others when it
# caches a new one, so the release and test builds get separate cache dirs.
if (( release )); then
    DEPENDS_PREFIX="$SRC/depends/$HOST_TRIPLET"
    cache_kind=depends-built
else
    cache_kind=depends-built-tests
    [[ -d "$CACHE" ]] || depends_args+=(BASE_CACHE="$SRC/build/docker-$IMAGE/depends-built")
    # A path component named "depends", so the coverage filter "*/depends/*"
    # removes these headers from reports.
    DEPENDS_PREFIX="$SRC/build/docker-$IMAGE/depends"
    # Built packages contain their install prefix (.la and .pc files), but
    # depends' package ids don't include it. A separate salt gives these
    # packages their own ids, and so their own cache entries and work dirs.
    salt="prefix:$DEPENDS_PREFIX"
    depends_args+=(NO_QT=1 x86_64_linux_prefix="$DEPENDS_PREFIX"
                   HOST_ID_SALT="$salt" BUILD_ID_SALT="$salt")
fi

# Optional caches, namespaced per image: depends packages are only keyed by
# compiler version strings, and ccache entries can't be shared across
# compilers anyway. Source tarballs are hash-checked, so they are shared.
if [[ -d "$CACHE" ]]; then
    echo "== Using cache in $CACHE/$IMAGE =="
    mkdir -p "$CACHE/$IMAGE/$cache_kind" "$CACHE/depends-sources" "$CACHE/$IMAGE/ccache"
    depends_args+=(BASE_CACHE="$CACHE/$IMAGE/$cache_kind" SOURCES_PATH="$CACHE/depends-sources")
    export CCACHE_DIR="$CACHE/$IMAGE/ccache"
fi
# depends builds its own ccache and configure uses it.
export CCACHE_BASEDIR="$SRC" CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-5G}"

# ccache 3.3.4 (built by depends) creates its config file on first use, and
# the compilers make starts in parallel on an empty cache race for it: one
# fails to open the file, another creates it, and the first then stops with
# "ccache: error: <dir>/ccache.conf: No such file or directory". Create the
# file before anything runs ccache; an empty file means the defaults.
ccache_conf="${CCACHE_CONFIGPATH:-${CCACHE_DIR:-$HOME/.ccache}/ccache.conf}"
mkdir -p "$(dirname "$ccache_conf")"
[[ -e "$ccache_conf" ]] || : > "$ccache_conf"

# Cache statistics on every exit, including failed runs, to show whether a
# slow run used the cache. With CCACHE_DISABLE set they would only show the
# restored cache's old counters, so they are left out.
print_cache_stats() {
    local status=$?
    if [[ -n "${CCACHE_DIR:-}" && -z "${CCACHE_DISABLE:-}" && -x "$DEPENDS_PREFIX/native/bin/ccache" ]]; then
        "$DEPENDS_PREFIX/native/bin/ccache" -s | grep -E 'cache hit|cache miss|cache size' || true
    fi
    (( status == 0 )) || echo "== Failed ($MODE, exit status $status) ==" >&2
}
trap print_cache_stats EXIT

echo "== Building dependencies =="
# The depends packages run their own configure scripts; they must not read
# the config.site meant for yacoind.
env -u CONFIG_SITE make "${depends_args[@]}"

echo "== Generating the build system =="
./autogen.sh

# Exported so that configure re-runs started by make also find the depends.
export CONFIG_SITE="$DEPENDS_PREFIX/share/config.site"

if (( release )); then
    echo "== Building yacoin =="
    flags=(--enable-glibc-back-compat --enable-reduce-exports LDFLAGS=-static-libstdc++ --prefix=/)
    [[ "$MODE" != build-low-difficulty ]] || flags+=(--enable-low-difficulty-for-development)
    ./configure "${flags[@]}"
    make -j"$JOBS"
    make install DESTDIR="$SRC/release-root"
    if [[ "$MODE" == build-low-difficulty ]]; then
        # The unit tests also have to pass with the low-difficulty
        # parameters; the release make builds test_bitcoin in the tree.
        echo "== Running the unit tests =="
        [[ -x src/test/test_bitcoin ]] || die "the build made no src/test/test_bitcoin (configured without tests?)"
        contrib/devtools/run-unit-suites.sh "$SRC/src/test/test_bitcoin" \
            "$SRC/build/docker-$IMAGE/$MODE/unit-test-logs" "$JOBS"
    fi
else
    builddir="$SRC/build/docker-$IMAGE/$MODE"
    echo "== Configuring in $builddir =="
    rm -rf "$builddir"; mkdir -p "$builddir"
    flags=(--without-gui --disable-man --enable-ccache)
    case "$MODE" in
        unit-tests) flags+=(--enable-bench "CXXFLAGS=-O1 -g" "CFLAGS=-O1 -g") ;;
        unit-tests-asan|functional-tests-asan)
            # The sanitizer flags of dev.sh's asan variant. secp256k1's
            # x86_64 field assembly needs more registers than are left under
            # ASan, so it is built in plain C, with either sanitizer. -g1
            # keeps symbolized stack traces with file and line; the generated
            # code is the same as with -g (objects compared after objcopy
            # --strip-debug).
            case "$MODE:${SANITIZE:-}" in
                unit-tests-asan:address) san="-fsanitize=address -fno-omit-frame-pointer" ;;
                unit-tests-asan:undefined) san="-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined" ;;
                *) san="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined" ;;
            esac
            ldflags="$san"
            if [[ "$MODE" == functional-tests-asan ]]; then
                # The per-script report files (see below) need every kind of
                # report in them. gcc links the AddressSanitizer and UBSan
                # runtimes as two shared libraries, and then UBSan's reports
                # ignore log_path and go to stderr. Linked into the
                # binaries, the two runtimes share one report file.
                ldflags+=" -static-libasan -static-libubsan"
                flags+=(--enable-low-difficulty-for-development)
            fi
            flags+=(--with-asm=no "CXXFLAGS=-O1 -g1 $san" "CFLAGS=-O1 -g1 $san" "LDFLAGS=$ldflags") ;;
        unit-tests-tsan)
            san="-fsanitize=thread -fno-omit-frame-pointer"
            flags+=("CXXFLAGS=-O1 -g $san" "CFLAGS=-O1 -g $san" "LDFLAGS=-fsanitize=thread") ;;
        fuzz-corpus)
            # The sanitizer flags of unit-tests-asan, with clang. Programs
            # are linked position dependent (-no-pie, also configure's test
            # programs): clang 14's AddressSanitizer runtime fails at random
            # at start in a position-independent one under the address
            # randomisation of current kernels. The depends config.site sets
            # the compilers, so a site file that reads it and then names
            # clang takes its place. (The depends file finds its prefix from
            # its own path, ac_site_file.)
            san="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
            flags+=(--enable-fuzz --with-asm=no "CXXFLAGS=-O1 -g $san" "CFLAGS=-O1 -g $san" "LDFLAGS=$san -no-pie")
            export PATH="$llvm_bin:$PATH"
            printf '%s\n' "ac_site_file='$CONFIG_SITE'" '. "$ac_site_file"' 'CC=clang' 'CXX=clang++' \
                > "$builddir/config.site"
            export CONFIG_SITE="$builddir/config.site" ;;
        functional-tests) flags+=(--enable-low-difficulty-for-development "CXXFLAGS=-O1 -g" "CFLAGS=-O1 -g") ;;
        cov-unit) flags+=(--enable-lcov "CXXFLAGS=-O0 -g" "CFLAGS=-O0 -g") ;;
        cov-functional) flags+=(--enable-lcov --enable-low-difficulty-for-development "CXXFLAGS=-O0 -g" "CFLAGS=-O0 -g") ;;
    esac
    (cd "$builddir" && "$SRC/configure" "${flags[@]}")
    export TMPDIR="$builddir/test/tmp"; mkdir -p "$TMPDIR"
    case "$MODE" in
        unit-tests|unit-tests-asan|unit-tests-tsan)
            targets=(test/test_bitcoin)
            [[ "$MODE" != unit-tests ]] || targets+=(bench/bench_yacoin)
            make -C "$builddir/src" -j"$JOBS" "${targets[@]}"
            for target in "${targets[@]}"; do
                [[ -x "$builddir/src/$target" ]] || die "the build made no $builddir/src/$target"
            done
            runner=() suites_opts=()
            if [[ "$MODE" == unit-tests-asan ]]; then
                # Leak checks at exit, the tree's suppressions, and a stack
                # trace with every UBSan report (it stops the process, as
                # built with -fno-sanitize-recover). The listed test cases
                # are left out, as by dev.sh asan.
                export ASAN_OPTIONS=detect_leaks=1
                export LSAN_OPTIONS="suppressions=$lsan_suppressions"
                export UBSAN_OPTIONS=print_stacktrace=1
                suites_opts=(--exclude-cases "$asan_excluded_cases")
            elif [[ "$MODE" == unit-tests-tsan ]]; then
                # The tree's suppressions; every report of a run is printed
                # (the process goes on and exits with a failure status at
                # the end), and lock-order reports show both stacks.
                export TSAN_OPTIONS="suppressions=$tsan_suppressions:halt_on_error=0:second_deadlock_stack=1"
                runner=(setarch "$(uname -m)" -R)
            fi
            # ${runner[@]+...}: an empty array is "unbound" under set -u in
            # bash < 4.4.
            ${runner[@]+"${runner[@]}"} contrib/devtools/run-unit-suites.sh ${suites_opts[@]+"${suites_opts[@]}"} \
                "$builddir/src/test/test_bitcoin" "$builddir/unit-test-logs" "$JOBS"
            if [[ "$MODE" == unit-tests ]]; then
                # Keeps the benchmarks compiling and their result checks
                # passing; a failed benchmark fails the mode.
                echo "== Running the benchmarks (bench_yacoin -time=$BENCH_TIME) =="
                cpu=$(grep -m1 '^model name' /proc/cpuinfo || true)
                echo "CPU: ${cpu#*: }"
                "$builddir/src/bench/bench_yacoin" -time="$BENCH_TIME"
            fi
            ;;
        fuzz-corpus)
            make -C "$builddir/src" -j"$JOBS" test/fuzz/fuzz
            [[ -x "$builddir/src/test/fuzz/fuzz" ]] || die "the build made no $builddir/src/test/fuzz/fuzz"
            # Leak checks at exit, and a stack trace with every UBSan report
            # (it stops the process, as built with -fno-sanitize-recover).
            export ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1
            contrib/devtools/run-fuzz-corpus.py --jobs "$JOBS" "$builddir/src/test/fuzz/fuzz" "$fuzz_corpus" \
                "$builddir/fuzz-corpus-logs"
            ;;
        functional-tests|functional-tests-asan)
            # The functional tests only run yacoind and yacoin-cli.
            make -C "$builddir/src" -j"$JOBS" yacoind yacoin-cli
            # The runner reads ../config.ini relative to its own path.
            mkdir -p "$builddir/test/functional"
            ln -sf "$SRC/test/functional/test_runner.py" "$builddir/test/functional/test_runner.py"
            runner_opts=()
            if [[ "$MODE" == functional-tests-asan ]]; then
                # The runtime options of unit-tests-asan. The runner adds a
                # log_path per script, so the reports of every process go to
                # a file named after its script, also those of a process
                # whose stderr or exit status a test expects to differ from
                # a clean run's. A leak report that is suppressed in full
                # would still write the suppression counts there
                # (print_suppressions=0). A segmentation fault ends the
                # process with the signal, as in the other functional runs
                # (handle_segv=0). The listed scripts are left out; a listed
                # name that is not a script of the runner fails the run.
                export ASAN_OPTIONS=detect_leaks=1:handle_segv=0
                export LSAN_OPTIONS="suppressions=$lsan_suppressions:print_suppressions=0"
                export UBSAN_OPTIONS=print_stacktrace=1
                sanitizer_logs="$builddir/sanitizer-logs"
                runner_opts=(--sanitizer-logs="$sanitizer_logs" --exclude-file="$asan_excluded_scripts")
            fi
            [[ -z "${FTEST_SHARD:-}" ]] || runner_opts+=(--shard="$FTEST_SHARD")
            status=0
            "$builddir/test/functional/test_runner.py" -j "${FTEST_JOBS:-4}" --extended --tmpdirprefix="$TMPDIR" \
                ${runner_opts[@]+"${runner_opts[@]}"} || status=$?
            if [[ "$MODE" == functional-tests-asan ]]; then
                # Every report fails the mode, also one the runner did not
                # see (a runner that stopped early).
                mapfile -t reports < <(find "$sanitizer_logs" -type f 2>/dev/null | LC_ALL=C sort)
                if (( ${#reports[@]} )); then
                    echo "== Sanitizer reports (${#reports[@]}) in $sanitizer_logs =="
                    for report in "${reports[@]}"; do
                        echo "-- ${report##*/} --"
                        cat "$report"
                    done
                    (( status != 0 )) || status=1
                fi
            fi
            (( status == 0 )) || exit "$status"
            ;;
        cov-unit)
            make -C "$builddir" -j"$JOBS" COV_JOBS="$JOBS" cov-unit
            echo "== Coverage report: $builddir/test_bitcoin.coverage/index.html =="
            ;;
        cov-functional)
            make -C "$builddir" -j"$JOBS" COV_JOBS="$JOBS" FTEST_JOBS="${FTEST_JOBS:-4}" FTEST_SHARD="${FTEST_SHARD:-}" \
                cov-functional
            echo "== Coverage report: $builddir/functional_test.coverage/index.html =="
            ;;
    esac
fi

echo "== Done ($MODE) =="
