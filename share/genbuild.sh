#!/bin/sh

if [ $# -gt 0 ]; then
    FILE="$1"
    shift
    if [ -f "$FILE" ]; then
        INFO="$(head -n 1 "$FILE")"
    fi
else
    echo "Usage: $0 <filename>"
    exit 1
fi

GIT_TAG=""
GIT_COMMIT=""
if [ -e "$(command -v git)" ] && [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ]; then
    # clean 'dirty' status of touched files that haven't been modified
    git diff >/dev/null 2>/dev/null

    # if latest commit is tagged and not dirty, then override using the tag name
    RAWDESC=$(git describe --abbrev=0 2>/dev/null)
    if [ "$(git rev-parse HEAD)" = "$(git rev-list -1 $RAWDESC 2>/dev/null)" ]; then
        git diff-index --quiet HEAD -- && GIT_TAG=$RAWDESC
    fi

    # otherwise generate suffix from git, i.e. string like "59887e8-dirty"
    GIT_COMMIT=$(git rev-parse --short=12 HEAD)
    git diff-index --quiet HEAD -- || GIT_COMMIT="$GIT_COMMIT-dirty"

    # get a string like "2012-04-10 16:27:19 +0200"
    TIME="$(git log -n 1 --format="%ci")"
fi

if [ -n "$GIT_TAG" ]; then
    NEWINFO="#define BUILD_GIT_TAG \"$GIT_TAG\""
elif [ -n "$GIT_COMMIT" ]; then
    NEWINFO="#define BUILD_GIT_COMMIT \"$GIT_COMMIT\""
else
    NEWINFO="// No build information available"
fi

# only update build.h if necessary
if [ "$INFO" != "$NEWINFO" ]; then
    echo "$NEWINFO" >"$FILE"
    echo "#define BUILD_DATE \"$TIME\"" >>"$FILE"
fi

if [ -n "$BUILDVERSION" ]; then
    echo "#define DISPLAY_VERSION_BUILD $BUILDVERSION" >> "$FILE"
fi
