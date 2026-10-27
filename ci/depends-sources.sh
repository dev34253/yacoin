#!/usr/bin/env bash
# Checks that every depends source file can still be downloaded. Run locally
# and by .github/workflows/depends-sources.yml.
#
# Usage: ci/depends-sources.sh [--steps LIST]
#
# Steps (default: http,primary,mirror,download), run in this order:
#   http      every URL `make download` fetches from (as `make -n download`
#             resolves them: each recipe host and FALLBACK_DOWNLOAD_PATH) is
#             https://. A host that redirects to anything else counts as not
#             serving the file (curl's proto-redir, below). Recipes that no
#             build uses are not fetched, so no download path in a recipe may
#             start with http:// either
#   primary   `make -k download` from the recipes' own hosts only (the
#             fallback disabled). Every file that fails is reported (in GitHub
#             Actions as a warning and in the job summary) but does not fail
#             the check: the mirror step covers it
#   mirror    `make -k download` with every recipe host disabled, so each
#             file comes from FALLBACK_DOWNLOAD_PATH through depends' own
#             fallback and must match the recipe's hash. Fails at once if the
#             mirror's SHA256SUMS cannot be fetched, for each file the mirror
#             lacks or has different, and if any file was fetched from
#             somewhere else (a recipe host the step failed to disable)
#   download  `make -k download` as a build runs it (the recipe's host first,
#             then FALLBACK_DOWNLOAD_PATH), into the sources the primary step
#             left (an empty directory without it). Fails for each file that
#             can be fetched from neither, which is what breaks a build
#
# The make runs share a curl config (CURL_HOME) that refuses redirects to
# anything but https:// and gives up on a download that stalls (under 1 KiB/s
# for 60 s) instead of waiting forever. GitHub release downloads sometimes
# answer 404 once, which curl does not retry, so the primary, mirror and
# download steps run `make download` up to DOWNLOAD_ATTEMPTS times (default
# 3); files fetched once are kept, and the primary step reports only what its
# last attempt failed to fetch. A recipe with several files (qt,
# native_cctools) fetches them one after another and stops at the first that
# fails, so the files after it are neither tried nor listed until it is
# fixed. DEPENDS_SOURCES_WORKDIR keeps the work files (default: a new
# temporary directory, removed when every step passes).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DEPENDS="$ROOT/depends"
ATTEMPTS="${DOWNLOAD_ATTEMPTS:-3}"

steps=http,primary,mirror,download
while [[ $# -gt 0 ]]; do
    case "$1" in
        --steps)
            [[ $# -ge 2 ]] || { echo "--steps needs a comma-separated list of steps" >&2; exit 2; }
            steps="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument '$1'" >&2; exit 2 ;;
    esac
done
for step in ${steps//,/ }; do
    case "$step" in
        http|primary|mirror|download) ;;
        *) echo "unknown step '$step'" >&2; exit 2 ;;
    esac
done
has_step() { [[ ",$steps," == *",$1,"* ]]; }

keep_work="${DEPENDS_SOURCES_WORKDIR:-}"
work="${DEPENDS_SOURCES_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/depends-sources.XXXXXX")}"
mkdir -p "$work"; work="$(cd "$work" && pwd)"
# A directory that stays empty: a download path pointing here always fails.
none="file://$work/none"
mkdir -p "$work/none" "$work/curl"
# The quotes matter: unquoted, curl reads "= =https" as "https" (added to
# the allowed protocols) and still follows a redirect to http://.
cat > "$work/curl/.curlrc" <<'EOF'
proto-redir = "=https"
speed-limit = 1024
speed-time = 60
EOF

failures=()
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures+=("$*"); }
warn() {
    echo "WARN  $*"
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::warning title=depends source::$*"; fi
}
summary() { if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then echo "$*" >> "$GITHUB_STEP_SUMMARY"; fi; }

fallback=$(make -s -C "$DEPENDS" --no-print-directory -f Makefile -f - print-fallback <<'EOF'
print-fallback:
	@echo $(FALLBACK_DOWNLOAD_PATH)
EOF
)

# depends_download <log> <sources dir> [make arguments...]: `make download`
# into <sources dir>, output appended to <log>. Its scratch directory lives in
# the work dir, so the checkout is not touched.
depends_download() {
    local log="$1" sources="$2"; shift 2
    mkdir -p "$sources"
    CURL_HOME="$work/curl" make -C "$DEPENDS" download SOURCES_PATH="$sources" \
        base_download_dir="$work/download" "$@" >> "$log" 2>&1
}

# depends_download_retried <name> <sources dir> [make arguments...]
depends_download_retried() {
    local name="$1" sources="$2" attempt; shift 2
    : > "$work/$name.log"
    for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
        echo "== attempt $attempt" >> "$work/$name.log"
        if depends_download "$work/$name.log" "$sources" "$@"; then
            return 0
        fi
    done
    return 1
}

# The files in a sources directory, without the download stamps.
source_files() { find "$1" -maxdepth 1 -type f -printf '%f\n' | sort; }

# last_attempt <log>: the part of a depends_download_retried log after its
# last "== attempt" line.
last_attempt() { awk '/^== attempt/ { n = NR } { line[NR] = $0 } END { for (i = n + 1; i <= NR; i++) print line[i] }' "$1"; }

# fetches <log>: "<download name> <path>" of every fetch in a log, in order.
fetches() { grep -oE 'Fetching [^ ]+ from [^ )]+' "$1" | awk '{ print $2, $4 }' || true; }

# failed_fetches <log> <fallback>: "<download name> <path>" of each fetch
# from a recipe host that failed in the log's last attempt, i.e. was followed
# by a fetch from <fallback> (depends fetches one file at a time). Each once,
# although `make download` fetches the sources for all three HOSTs.
failed_fetches() {
    last_attempt "$1" | awk -v fallback="$2" '
        $1 == "Fetching" && $3 == "from" {
            if ($4 == fallback && prev_path != fallback) print prev_file, prev_path
            prev_file = $2; prev_path = $4
        }' | sort -u
}

# fallback_misses <log> <sources dir>: the files the log fetched from the
# fallback that are not in <sources dir>.
fallback_misses() {
    local name
    awk -v fallback="$fallback" '$1 == "Fetching" && $3 == "from" && $4 == fallback { print $2 }' "$1" |
        sort -u | while read -r name; do
            [[ -f "$2/$name" ]] || echo "$name"
        done
}

step_http() {
    local file path urls=0 bad=0
    # -n only prints the fetch commands, with every URL resolved.
    make -n -C "$DEPENDS" download SOURCES_PATH="$work/dry-run" base_download_dir="$work/download" \
        > "$work/http.log" 2>&1 || { fail "http: make -n download failed (log: $work/http.log)"; return; }
    while read -r file path; do
        urls=$((urls + 1))
        shopt -s nocasematch
        if [[ "$path" != https://* ]]; then
            fail "http: $file is fetched from $path, not https://"
            bad=$((bad + 1))
        fi
        shopt -u nocasematch
    done < <(fetches "$work/http.log" | sort -u)
    if [[ "$urls" -eq 0 ]]; then
        fail "http: make -n download fetches nothing (log: $work/http.log)"
    elif [[ "$bad" -eq 0 ]]; then
        pass "http: all $urls fetch URLs (recipe hosts and FALLBACK_DOWNLOAD_PATH) are https://"
    fi
    local hits hit
    hits=$(grep -inE '^[^#]*download_path[[:space:]]*[:?+]?=[[:space:]]*http://' "$DEPENDS"/packages/*.mk |
           sed "s|^$DEPENDS/||" || true)
    if [[ -z "$hits" ]]; then
        pass "http: no recipe download path starts with http://"
    else
        while read -r hit; do fail "http: $hit"; done <<< "$hits"
    fi
}

step_primary() {
    local file path status=0 dead=0
    depends_download_retried primary "$work/sources" -k FALLBACK_DOWNLOAD_PATH="$none" || status=$?
    echo "primary: $(source_files "$work/sources" | wc -l) files fetched from the recipes' hosts"
    summary "### Files the recipes' own hosts did not serve"
    summary ""
    while read -r file path; do
        [[ -n "$file" ]] || continue
        warn "$path/$file: not served, or not with the recipe's hash"
        summary "- \`$path/$file\`"
        dead=$((dead + 1))
    done < <(failed_fetches "$work/primary.log" "$none")
    if [[ "$status" -ne 0 && "$dead" -eq 0 ]]; then
        fail "primary: make download failed, but not on a fetch (log: $work/primary.log)"
        summary "make download failed, but not on a fetch."
    elif [[ "$(source_files "$work/sources" | wc -l)" -eq 0 ]]; then
        fail "primary: no file fetched at all (log: $work/primary.log)"
    elif [[ "$dead" -eq 0 ]]; then
        pass "primary: every file came from its recipe's host"
        summary "None."
    fi
    summary ""
}

# probe_mirror: whether the mirror answers at all (its SHA256SUMS), so a dead
# mirror fails in seconds instead of once per file and attempt.
probe_mirror() {
    local attempt
    for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
        curl -fsSL --proto-redir =https --connect-timeout 10 --max-time 60 -o /dev/null \
            "$fallback/SHA256SUMS" 2>> "$work/mirror-probe.log" && return 0
        sleep 5
    done
    return 1
}

step_mirror() {
    local overrides=() f package var others
    if ! probe_mirror; then
        fail "mirror: unreachable, $fallback/SHA256SUMS cannot be fetched (log: $work/mirror-probe.log)"
        summary "Mirror: unreachable, \`$fallback/SHA256SUMS\` cannot be fetched."
        return
    fi
    # Every <package>_..._download_path of every recipe, pointed at nothing.
    for f in "$DEPENDS"/packages/*.mk; do
        package=$(basename "$f" .mk)
        [[ "$package" != packages ]] || continue
        # shellcheck disable=SC2016  # $(package) is the recipe's text
        while read -r var; do
            overrides+=("${package}_$var=$none")
        done < <(sed -n 's/^\$(package)_\([A-Za-z0-9_]*download_path\)[[:space:]]*[:?+]\{0,1\}=.*/\1/p' "$f")
    done
    local status=0
    depends_download_retried mirror "$work/sources-mirror" -k "${overrides[@]}" || status=$?
    # Every fetch must have been from the disabled hosts or the mirror;
    # anything else means the overrides above missed a recipe's host.
    others=$(fetches "$work/mirror.log" | awk -v none="$none" -v fallback="$fallback" '$2 != none && $2 != fallback' |
             sort -u)
    if [[ -n "$others" ]]; then
        while read -r f; do fail "mirror: fetched from a recipe host, not disabled: $f"; done <<< "$others"
    fi
    if [[ "$status" -ne 0 ]]; then
        report_misses mirror "$work/sources-mirror" "not on the mirror, or different"
    elif [[ "$(source_files "$work/sources-mirror" | wc -l)" -eq 0 ]]; then
        fail "mirror: no file fetched at all (log: $work/mirror.log)"
    elif [[ -z "$others" ]]; then
        pass "mirror: $(source_files "$work/sources-mirror" | wc -l) files fetched from $fallback match their recipes"
        summary "Mirror: all $(source_files "$work/sources-mirror" | wc -l) files fetched from $fallback by file name."
    fi
}

step_download() {
    if depends_download_retried download "$work/sources" -k; then
        pass "download: all $(source_files "$work/sources" | wc -l) files fetched (recipe host, then the mirror)"
        summary "Download: all $(source_files "$work/sources" | wc -l) files fetched (recipe host, then the mirror)."
    else
        report_misses download "$work/sources" "fetched neither from its host nor from the mirror"
    fi
}

# report_misses <step> <sources dir> <what>: a failure for each file the
# step's last `make download` could not get from the fallback.
report_misses() {
    local step="$1" sources="$2" what="$3" name missing
    missing=$(fallback_misses "$work/$step.log" "$sources")
    if [[ -z "$missing" ]]; then
        fail "$step: make download failed (log: $work/$step.log)"
        return
    fi
    summary "Files $what:"
    summary ""
    while read -r name; do
        fail "$step: $name: $what"
        summary "- \`$name\`"
    done <<< "$missing"
    summary ""
    echo "      log: $work/$step.log"
}

summary "## depends sources"
summary ""
for step in http primary mirror download; do
    if has_step "$step"; then "step_$step"; fi
done

echo
if [[ ${#failures[@]} -eq 0 ]]; then
    echo "All checks passed."
    summary "All checks passed."
    [[ -n "$keep_work" ]] || rm -rf "$work"
else
    echo "${#failures[@]} check(s) failed (work files: $work):"
    printf '  %s\n' "${failures[@]}"
    summary "**${#failures[@]} check(s) failed.**"
    exit 1
fi
