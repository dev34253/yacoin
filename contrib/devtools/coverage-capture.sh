#!/usr/bin/env bash
# Captures the coverage data of a build into a tracefile with geninfo (lcov
# 2.5 or newer), JOBS processes in parallel. Used by "make cov-unit" /
# "cov-functional".
#
# Usage: coverage-capture.sh --geninfo CMD --dir SRCDIR --out FILE
#                            (--initial | --test-name NAME) [--jobs N]
#
# --initial captures a baseline from the .gcno files (every instrumented line
# at 0); --test-name captures the counters in the .gcda files. CMD is split on
# spaces (the geninfo path plus options such as --gcov-tool and
# --config-file). Without .gcda files (e.g. the tests crashed) an empty output
# file is written and the exit status is 0; the Makefile then falls back to the
# baseline. Any other failure exits non-zero.
set -euo pipefail

geninfo="" dir="" out="" mode="" name="" jobs=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --geninfo) geninfo="$2"; shift 2 ;;
        --dir) dir="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --initial) mode=initial; shift ;;
        --test-name) mode="test"; name="$2"; shift 2 ;;
        --jobs) jobs="$2"; shift 2 ;;
        *) echo "$0: unknown argument $1" >&2; exit 2 ;;
    esac
done
[[ -n "$geninfo" && -n "$dir" && -n "$out" && -n "$mode" ]] ||
    { echo "$0: missing arguments" >&2; exit 2; }
[[ -n "$jobs" ]] || jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "$0: --jobs must be a positive integer" >&2; exit 2; }

read -ra geninfo_cmd <<< "$geninfo"
geninfo_cmd+=(-q --parallel "$jobs" -b "$dir")
if [[ $mode == initial ]]; then
    ext=gcno; geninfo_cmd+=(-i)
else
    ext=gcda; geninfo_cmd+=(-t "$name")
fi

if [[ -z "$(find "$dir" -name "*.$ext" -print -quit)" ]]; then
    if [[ $mode == initial ]]; then
        echo "$0: no .gcno files under $dir; is this an --enable-lcov build?" >&2
        exit 1
    fi
    : > "$out"
    exit 0
fi

# geninfo finds the data files under the directory itself. With --initial it
# copies each .gcno file to a temporary directory before running gcov on it,
# so a baseline taken while the tests write their counters stays all 0.
"${geninfo_cmd[@]}" -o "$out" "$dir"
