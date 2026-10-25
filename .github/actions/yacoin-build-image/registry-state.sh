#!/usr/bin/env bash
# Prints whether an image tag is in its registry: "exists", "missing", or
# "error: <reason>" for anything else (denied, unauthorized, a registry or
# network failure), so that callers never mistake an error for a missing tag.
#
# Usage: registry-state.sh <registry>/<repository>:<tag>
#
# Asks the registry API directly: a bearer token from the registry's token
# endpoint (with REGISTRY_USER and REGISTRY_PASSWORD if set, anonymous
# otherwise; scope pull, plus push if REGISTRY_PUSH=1, which a repository
# that does not exist yet needs), then a HEAD request for the manifest:
# 200 is "exists", 404 is "missing". Always exits 0 if it printed a state.
set -uo pipefail

ref="${1:?usage: registry-state.sh <registry>/<repository>:<tag>}"
registry="${ref%%/*}" rest="${ref#*/}"
repo="${rest%:*}" tag="${rest##*:}"
[[ "$registry" != "$ref" && "$repo" != "$rest" && -n "$tag" ]] || { echo "error: not <registry>/<repository>:<tag>: $ref"; exit 0; }

scope="repository:$repo:pull"
[[ "${REGISTRY_PUSH:-0}" != 1 ]] || scope+=",push"
auth=()
[[ -z "${REGISTRY_USER:-}" ]] || auth=(-u "$REGISTRY_USER:${REGISTRY_PASSWORD:-}")

body=$(curl -sS --retry 3 --max-time 30 -w '\n%{http_code}' "${auth[@]}" \
    "https://$registry/token?service=$registry&scope=$scope" 2>&1)
code="${body##*$'\n'}" body="${body%$'\n'*}"
if [[ "$code" != 200 ]]; then
    echo "error: token request: HTTP $code ${body//$'\n'/ }"; exit 0
fi
token=$(jq -r '.token // .access_token // empty' <<< "$body" 2>/dev/null)
[[ -n "$token" ]] || { echo "error: token request: no token in the answer"; exit 0; }

accept="application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json"
accept+=",application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json"
code=$(curl -sS --retry 3 --max-time 30 -o /dev/null -w '%{http_code}' -I \
    -H "Authorization: Bearer $token" -H "Accept: $accept" \
    "https://$registry/v2/$repo/manifests/$tag" 2>&1)
case "$code" in
    200) echo exists ;;
    404) echo missing ;;
    *) echo "error: manifest request: HTTP $code" ;;
esac
