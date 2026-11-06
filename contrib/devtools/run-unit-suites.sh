#!/usr/bin/env bash
# Runs Boost unit test suites of test_bitcoin as separate parallel processes.
# Used by dev.sh (unit, asan), the unit test modes of the CI images
# (ci/containers/entrypoint.sh) and "make cov-unit".
#
# Usage: run-unit-suites.sh [--exclude-cases LIST] BIN LOGDIR JOBS [SELECTOR...]
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
#
# --exclude-cases LIST leaves the test cases named in the file LIST out of
# every selector, so the other cases of their suites still run (Boost.Test's
# disabling filter --run_test=!<case path> next to each selector; it applies
# after the selector and disables nothing outside it). One test case path per
# line (suite/case, suite/inner_suite/case); "#" starts a comment, blank lines
# are ignored. Every entry must name a test case of BIN (--list_content):
# otherwise the run fails before any selector runs, so an entry cannot outlive
# its test case unnoticed.
set -euo pipefail

exclude_list=""
if [[ "${1:-}" == --exclude-cases ]]; then
    [[ $# -ge 2 ]] || { echo "$0: --exclude-cases needs a file" >&2; exit 2; }
    exclude_list="$2"
    shift 2
fi
bin="${1:?test binary required}" logdir="${2:?log dir required}" jobs="${3:?job count required}"
shift 3
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "$0: job count must be a positive integer" >&2; exit 2; }
excluded=()
if [[ -n "$exclude_list" ]]; then
    [[ -f "$exclude_list" && -r "$exclude_list" ]] ||
        { echo "$0: cannot read the list of test cases to leave out: $exclude_list" >&2; exit 2; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        # Names only: no Boost filter syntax (wildcards, lists, labels).
        if [[ ! "$line" =~ ^[A-Za-z0-9_]+(/[A-Za-z0-9_]+)+$ ]]; then
            echo "$exclude_list: '$line' is not a test case path (suite/case)" >&2
            exit 1
        fi
        excluded+=("$line")
    done < "$exclude_list"
fi
# Boost.Test reads its settings from BOOST_TEST_* variables too, and some of
# them override the options (BOOST_TEST_OUTPUT_FORMAT overrides
# --report_format in Boost 1.64), so none of them may reach BIN.
while IFS= read -r var; do unset "$var"; done < <(compgen -e | grep '^BOOST_TEST_' || true)
if [[ $# -eq 0 || ${#excluded[@]} -gt 0 ]]; then
    # A failed or empty listing must never be reported as a pass, since suites
    # would be silently skipped.
    if ! content=$("$bin" --list_content 2>&1); then
        echo "'$bin --list_content' failed:" >&2
        echo "$content" >&2
        exit 1
    fi
fi
disablers=""
if [[ ${#excluded[@]} -gt 0 ]]; then
    # The test case paths of the listing: four spaces of indentation per
    # level, then the name, "*" if enabled by default and the description,
    # if any. A unit is a test case when the next unit is not inside it.
    declare -A is_case=()
    re='^(( {4})*)([A-Za-z0-9_]+)[* ]?(: .*)?$'
    path=() prev="" prev_depth=-1
    while IFS= read -r line; do
        [[ "$line" =~ $re ]] || continue
        depth=$(( ${#BASH_REMATCH[1]} / 4 ))
        if (( depth <= prev_depth )); then is_case[$prev]=1; fi
        path[depth]="${BASH_REMATCH[3]}"
        prev="${path[0]}"
        for (( i = 1; i <= depth; i++ )); do prev+="/${path[i]}"; done
        prev_depth=$depth
    done <<< "$content"
    if (( prev_depth >= 0 )); then is_case[$prev]=1; fi
    missing=0
    for case in "${excluded[@]}"; do
        if [[ -z "${is_case[$case]:-}" ]]; then
            echo "$exclude_list: '$case' is not a test case of $bin" >&2
            missing=1
        fi
        disablers+=" --run_test=!$case"
    done
    [[ $missing -eq 0 ]] || exit 1
    echo "Left out of every selector ($exclude_list): ${excluded[*]}"
fi
if [[ $# -gt 0 ]]; then
    suites=("$@")
else
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
export bin logdir tmproot disablers
# Each selector is passed to bash as "$2", never pasted into the script, so
# Boost filters such as suite/case, suite/* or !suite reach --run_test as is.
# Log and temp dir names are the selector's index plus its characters that
# are safe in file names, so different selectors never share them. The
# disabling filters follow the selector; they are names only, so splitting
# them on spaces is safe.
for i in "${!suites[@]}"; do printf '%s\0%s\0' "$i" "${suites[$i]}"; done |
    xargs -0 -P "$jobs" -n 2 bash -c '
        name="$1-$(printf "%s" "$2" | tr -c "A-Za-z0-9_.-" "_")"
        dir="$tmproot/$name"; mkdir -p "$dir"
        log="$logdir/$name.log"
        read -ra skip <<< "$disablers"
        # The report and colour options fix the form of the summary checked
        # below: one plain-text line in the log.
        if ! TMPDIR="$dir" "$bin" --run_test="$2" "${skip[@]}" --log_level=test_suite \
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
