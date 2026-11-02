#!/usr/bin/env bash
# Runs Boost unit test suites of test_bitcoin as separate parallel processes.
# Used by dev.sh (unit, asan) and "make cov-unit".
#
# Usage: run-unit-suites.sh BIN LOGDIR JOBS [SELECTOR...]
#
# A selector passes only if BIN exits with status 0 and its log has Boost.Test's
# summary of a completed run without errors ("*** No errors detected").
# BIN is started without any BOOST_TEST_* variable from the environment, so
# Boost.Test's settings come only from the options passed below.
#
# Without selectors, all suites are listed from BIN and run. Each process gets
# its own TMPDIR below $TMPDIR (default /tmp), because the test fixtures create
# their datadirs in the temp dir. Writes LOGDIR/<n>-<name>.log per selector and
# LOGDIR/summary.txt; exits non-zero if any selector fails or none are found.
set -euo pipefail

bin="${1:?test binary required}" logdir="${2:?log dir required}" jobs="${3:?job count required}"
shift 3
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "$0: job count must be a positive integer" >&2; exit 2; }
# Boost.Test reads its settings from BOOST_TEST_* variables too, and some of
# them override the options (BOOST_TEST_OUTPUT_FORMAT overrides
# --report_format in Boost 1.64), so none of them may reach BIN.
while IFS= read -r var; do unset "$var"; done < <(compgen -e | grep '^BOOST_TEST_' || true)
if [[ $# -gt 0 ]]; then
    suites=("$@")
else
    # A failed or empty listing must never be reported as a pass, since suites
    # would be silently skipped.
    if ! content=$("$bin" --list_content 2>&1); then
        echo "'$bin --list_content' failed:" >&2
        echo "$content" >&2
        exit 1
    fi
    mapfile -t listed < <(sed -n 's/^\([A-Za-z0-9_][A-Za-z0-9_]*\)\*$/\1/p' <<< "$content")
    if [[ ${#listed[@]} -eq 0 ]]; then
        echo "No unit test suites found; '$bin --list_content' failed?" >&2
        exit 1
    fi
    # Start the slowest suites first, so they don't finish last on their own.
    slow=(transaction_tests coins_tests)
    suites=()
    for s in "${slow[@]}"; do
        for t in "${listed[@]}"; do if [[ $t == "$s" ]]; then suites+=("$t"); fi; done
    done
    for t in "${listed[@]}"; do
        if [[ " ${slow[*]} " != *" $t "* ]]; then suites+=("$t"); fi
    done
fi

tmproot="${TMPDIR:-/tmp}/unit-suites.$$"
rm -rf "$logdir"; mkdir -p "$logdir" "$tmproot"
trap 'rm -rf "$tmproot"' EXIT
export bin logdir tmproot
# Each selector is passed to bash as "$2", never pasted into the script, so
# Boost filters such as suite/case, suite/* or !suite reach --run_test as is.
# Log and temp dir names are the selector's index plus its characters that
# are safe in file names, so different selectors never share them.
for i in "${!suites[@]}"; do printf '%s\0%s\0' "$i" "${suites[$i]}"; done |
    xargs -0 -P "$jobs" -n 2 bash -c '
        name="$1-$(printf "%s" "$2" | tr -c "A-Za-z0-9_.-" "_")"
        dir="$tmproot/$name"; mkdir -p "$dir"
        log="$logdir/$name.log"
        # The report and colour options fix the form of the summary checked
        # below: one plain-text line in the log.
        if ! TMPDIR="$dir" "$bin" --run_test="$2" --log_level=test_suite \
                --report_level=confirm --report_format=HRF --report_sink=stderr \
                --color_output=no >"$log" 2>&1; then
            echo "FAIL $2"
        elif grep -qx "\*\*\* No errors detected" "$log"; then
            echo "PASS $2"
        else
            # Exit status 0 without the summary: the process ended before
            # Boost.Test finished, so not every test case ran.
            echo "FAIL $2 (no test report)"
        fi
        rm -rf "$dir"' _ | sort -k2 | tee "$logdir/summary.txt"
failed=$(grep -c '^FAIL' "$logdir/summary.txt" || true)
echo "$(grep -c '^PASS' "$logdir/summary.txt") passed, $failed failed (logs: $logdir)"
[[ "$failed" -eq 0 ]]
