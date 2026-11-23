#!/usr/bin/env bash
# The result of the CI job all-jobs-passed: passes only when every job it
# needs passed.
#
# Usage: NEEDS_JSON=<needs context as JSON> MASTER_PUSH=true|false \
#            ci/containers/all-jobs-passed.sh
#
#   NEEDS_JSON   the needs context, ${{ toJSON(needs) }}: one object with an
#                entry {"result": ..., "outputs": {...}} per needed job
#   MASTER_PUSH  true on a push to master, false otherwise
#
# A needed job passes when its result is success; prune-caches also passes
# when it was skipped and MASTER_PUSH is false. Prints one line per needed
# job ("ok   <job>: <result>" or "FAIL <job>: <result>") and a summary.
# Exit status 0 when every needed job passed; 1 when one did not, and when
# an input is missing, empty or not as described (needs jq).
set -euo pipefail

error() { echo "::error::$*"; exit 1; }

[[ -n "${NEEDS_JSON:-}" ]] || error "NEEDS_JSON is empty or unset"
[[ "${MASTER_PUSH:-}" == true || "${MASTER_PUSH:-}" == false ]] ||
    error "MASTER_PUSH is '${MASTER_PUSH:-}', not true or false"
command -v jq > /dev/null || error "jq is not installed"

# One line "<job><tab><result>" per needed job, in the order of the input.
# Anything but exactly one non-empty object of such entries is an error.
filter='
    if length != 1 or (.[0] | type) != "object" or (.[0] | length) == 0
    then error("not one non-empty JSON object") else .[0] end
    | to_entries[]
    | if (.key | test("^[A-Za-z0-9_-]+\\z")) and (.value | type) == "object"
         and (.value.result | type) == "string" and (.value.result | test("^[a-z_]+\\z"))
      then "\(.key)\t\(.value.result)"
      else error("no result for a needed job") end'
results=$(jq -r -s "$filter" <<< "$NEEDS_JSON" 2>&1) || error "NEEDS_JSON: ${results//$'\n'/ }"

total=0
failed=()
while IFS=$'\t' read -r job result; do
    total=$((total + 1))
    if [[ "$result" == success ]]; then
        echo "ok   $job: $result"
    elif [[ "$job" == prune-caches && "$result" == skipped && "$MASTER_PUSH" == false ]]; then
        echo "ok   $job: $result (not a push to master)"
    else
        echo "FAIL $job: $result"
        failed+=("$job")
    fi
done <<< "$results"

if (( ${#failed[@]} )); then
    joined=$(printf ', %s' "${failed[@]}")
    error "${#failed[@]} of $total needed jobs did not pass: ${joined:2}"
fi
echo "$total of $total needed jobs passed"
