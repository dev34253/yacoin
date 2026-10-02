#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mirror a git checkout into a build copy for contrib/testing/build.sh.

Copies tracked and untracked-but-not-ignored files from REPO to DEST. Copied
files get the current time (not the checkout's), so make always treats them
as newer than objects built from an older version. A manifest
(DEST/.sync-manifest.json) records the size and mtime each file had in the
checkout when it was last copied, so that:

  * only files that changed in the checkout since the last sync are copied –
    files the build regenerates in DEST (autogen.sh rewrites some tracked
    files such as aclocal.m4 and build-aux/*) are left alone otherwise, which
    avoids spurious autotools re-runs;
  * files that were deleted or renamed in the checkout are removed from DEST,
    so a build cannot pass on stale copies;
  * tracked files that are deleted in the working tree (deletion not staged)
    are treated as deleted.

Prints a one-line summary.
"""

import json
import os
import shutil
import subprocess
import sys


def checkout_files(repo):
    out = subprocess.run(
        ["git", "-C", repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True, stdout=subprocess.PIPE).stdout
    files = set()
    for raw in out.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        full = os.path.join(repo, path)
        # Skip tracked files deleted in the working tree, and anything that is
        # not a regular file or symlink (e.g. submodule directories).
        if os.path.islink(full) or os.path.isfile(full):
            files.add(path)
    return files


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: sync_tree.py REPO DEST")
    repo, dest = (os.path.abspath(p) for p in sys.argv[1:])
    manifest_path = os.path.join(dest, ".sync-manifest.json")
    os.makedirs(dest, exist_ok=True)
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
    except (FileNotFoundError, ValueError):
        manifest = {}

    files = checkout_files(repo)
    copied = removed = 0

    # Remove what disappeared from the checkout first, so a path that changed
    # from file to directory (or back) can be recreated below.
    for path in manifest:
        if path not in files:
            dst = os.path.join(dest, path)
            if os.path.islink(dst) or os.path.isfile(dst):
                os.unlink(dst)
                removed += 1

    new_manifest = {}
    for path in sorted(files):
        src = os.path.join(repo, path)
        dst = os.path.join(dest, path)
        st = os.lstat(src)
        stamp = [st.st_size, st.st_mtime_ns]
        new_manifest[path] = stamp
        if manifest.get(path) == stamp and os.path.lexists(dst):
            continue
        parent = os.path.dirname(dst)
        if os.path.lexists(parent) and not os.path.isdir(parent):
            os.unlink(parent)  # a file where a directory is needed now
        os.makedirs(parent, exist_ok=True)
        if os.path.isdir(dst) and not os.path.islink(dst):
            shutil.rmtree(dst)  # a directory where a file is needed now
        elif os.path.lexists(dst):
            os.unlink(dst)
        if os.path.islink(src):
            os.symlink(os.readlink(src), dst)
        else:
            # Content and permissions, but the current time as mtime.
            shutil.copy(src, dst)
        copied += 1

    tmp = manifest_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(new_manifest, f)
    os.replace(tmp, manifest_path)
    print("synced {} files: {} copied, {} removed".format(len(files), copied, removed))


if __name__ == "__main__":
    main()
