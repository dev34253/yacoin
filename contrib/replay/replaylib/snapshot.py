"""Snapshots: a read-only copy of the databases of a complete full run's
data directory, at the tip of the run's block files.

A snapshot directory holds blocks/ (the blk and rev files and
blocks/index), chainstate/ and tokens/ as the run left them, the run's
report.json and failures.tsv, and snapshot.json: format, height, hash,
digest and section digests of the state, the run's node command line,
binary, source and directory, its failure counts, the time it was made,
and the manifest (size and SHA-256 of every copied file). A directory
without snapshot.json is not a snapshot.
"""

import hashlib
import json
import os
import re
import shutil
import stat

from . import blockfiles
from . import digest as digest_mod
from . import report

FORMAT = 1
META = "snapshot.json"
DATABASE_DIRS = (os.path.join("blocks", "index"), "chainstate", "tokens")
BLOCK_FILE_RE = re.compile(r"(blk|rev)\d{5}\.dat")
CHUNK = 1 << 20


class SnapshotRefused(Exception):
    """A precondition does not hold; nothing was created."""


class SnapshotFailed(Exception):
    """Making the snapshot failed after the copy began; there is no
    snapshot.json."""


class SnapshotMismatch(Exception):
    """A file of a snapshot is missing or differs from its manifest."""


def copy_file(src, dst):
    """Copies src to the new file dst; returns (size, SHA-256) of what was
    copied."""
    h = hashlib.sha256()
    size = 0
    with open(src, "rb") as fin, open(dst, "xb") as fout:
        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                return size, h.hexdigest()
            h.update(chunk)
            fout.write(chunk)
            size += len(chunk)


def database_files(datadir):
    """The paths, relative to datadir, of the files a snapshot holds."""
    blocks = os.path.join(datadir, "blocks")
    if not os.path.isdir(blocks):
        raise SnapshotRefused("no blocks directory in %s" % datadir)
    out = [os.path.join("blocks", n) for n in sorted(os.listdir(blocks))
           if BLOCK_FILE_RE.fullmatch(n) and os.path.isfile(os.path.join(blocks, n))]
    for name in DATABASE_DIRS:
        path = os.path.join(datadir, name)
        if not os.path.isdir(path):
            raise SnapshotRefused("no %s directory in %s" % (name, datadir))
        out += [os.path.join(name, n) for n in sorted(os.listdir(path)) if os.path.isfile(os.path.join(path, n))]
    return out


def _inside(path, directory):
    real = os.path.realpath(directory)
    return os.path.commonpath([os.path.realpath(path), real]) == real


def _load_run_report(run_out):
    path = os.path.join(run_out, "report.json")
    try:
        with open(path) as f:
            rep = json.load(f)
    except (OSError, ValueError) as e:
        raise SnapshotRefused("cannot read %s: %s" % (path, e))
    if not isinstance(rep, dict):
        raise SnapshotRefused("%s is not a report" % path)
    if rep.get("kind") != "run":
        raise SnapshotRefused("%s is not of a run (kind %s)" % (path, rep.get("kind")))
    if rep.get("status") != "complete":
        raise SnapshotRefused("the run of %s is not complete" % path)
    if rep.get("mode", "full") != "full" or rep.get("snapshot"):
        raise SnapshotRefused("%s is of a snapshot run; a snapshot is made from a full run" % path)
    if rep.get("stop_at_height") is not None:
        raise SnapshotRefused("the run of %s was made with --stop-at-height; a snapshot is made from a run "
                              "to the tip of its block files" % path)
    if not isinstance(rep.get("tip"), dict) or not rep.get("digest"):
        raise SnapshotRefused("%s has no digest" % path)
    return rep


def make(run_out, snap, log=print):
    """Makes the snapshot snap of the full run in run_out; returns the
    content of its snapshot.json. Raises SnapshotRefused before anything is
    created, SnapshotFailed after."""
    run_out = os.path.abspath(run_out)
    snap = os.path.abspath(snap)
    datadir = os.path.join(run_out, "datadir")
    if os.path.lexists(snap):
        raise SnapshotRefused("snapshot directory exists: %s" % snap)
    if _inside(snap, run_out):
        raise SnapshotRefused("snapshot directory %s is inside the run directory %s" % (snap, run_out))
    rep = _load_run_report(run_out)
    if not os.path.isdir(datadir):
        raise SnapshotRefused("not a directory: %s" % datadir)
    try:
        digest_mod.check_not_running(datadir)
    except (digest_mod.DigestError, OSError) as e:
        raise SnapshotRefused(str(e))
    files = database_files(datadir)
    failures_path = os.path.join(run_out, "failures.tsv")
    try:
        failures = report.read_failures(failures_path)
    except report.ReportError as e:
        raise SnapshotRefused(str(e))
    if len(failures) != rep.get("failures"):
        raise SnapshotRefused("%s has %d rows, the report %s failures" % (failures_path, len(failures),
                                                                         rep.get("failures")))

    os.makedirs(snap)
    manifest = {}
    try:
        for rel in files:
            os.makedirs(os.path.dirname(os.path.join(snap, rel)), exist_ok=True)
            size, sha256 = copy_file(os.path.join(datadir, rel), os.path.join(snap, rel))
            manifest[rel] = {"size": size, "sha256": sha256}
        log("copied %d files" % len(files))
        d = digest_mod.compute(snap)
        tip = {"height": d.tip_height, "hash": d.tip_hash}
        if tip != rep["tip"]:
            raise SnapshotFailed("tip of the copy %d %s differs from the report's %s %s" % (
                d.tip_height, d.tip_hash, rep["tip"].get("height"), rep["tip"].get("hash")))
        if d.overall != rep["digest"]:
            raise SnapshotFailed("digest of the copy %s differs from the report's %s" % (d.overall, rep["digest"]))
        result = blockfiles.check(blockfiles.block_files(os.path.join(snap, "blocks")), snap, d.tip_height)
        if result.reasons:
            raise SnapshotFailed("; ".join(result.reasons))
        meta = {
            "format": FORMAT,
            "height": d.tip_height,
            "hash": d.tip_hash,
            "digest": d.overall,
            "sections": {name: {"count": s.count, "sha256": s.sha256} for name, s in d.sections.items()},
            "command": rep.get("command"),
            "binary": rep.get("binary"),
            "source": rep.get("source"),
            "failures": rep.get("failures"),
            "failure_blocks": rep.get("failure_blocks"),
            "failures_off_main_chain": rep.get("failures_off_main_chain"),
            "up_to_height": rep.get("up_to_height"),
            "chain": rep.get("chain"),
            "run": run_out,
            "made": report.utc_now(),
            "manifest": manifest,
        }
        shutil.copyfile(os.path.join(run_out, "report.json"), os.path.join(snap, "report.json"))
        shutil.copyfile(failures_path, os.path.join(snap, "failures.tsv"))
        make_read_only(snap, top=False)
        _write_meta(snap, meta)
    except (OSError, digest_mod.DigestError) as e:
        raise SnapshotFailed(str(e))
    return meta


def _read_only(path):
    os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) & ~0o222)


def _write_meta(snap, meta):
    """Writes snap's snapshot.json and makes it and snap read-only; on a
    failure there is no snapshot.json."""
    path = os.path.join(snap, META)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(meta, f, indent=2, sort_keys=True)
            f.write("\n")
        _read_only(tmp)
        os.rename(tmp, path)
        _read_only(snap)
    except OSError:
        for name in (tmp, path):
            if os.path.lexists(name):
                os.remove(name)
        raise


def make_read_only(path, top=True):
    """Removes every write permission of everything under path, and of path
    itself unless top is False."""
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            _read_only(os.path.join(root, name))
        if top or root != path:
            _read_only(root)


def load(snap):
    """The content of snap's snapshot.json. Raises SnapshotRefused when there
    is none or it cannot be used."""
    path = os.path.join(snap, META)
    if not os.path.isfile(path):
        raise SnapshotRefused("no %s in %s" % (META, snap))
    try:
        with open(path) as f:
            meta = json.load(f)
    except (OSError, ValueError) as e:
        raise SnapshotRefused("cannot read %s: %s" % (path, e))
    if not isinstance(meta, dict):
        raise SnapshotRefused("%s is not a snapshot description" % path)
    if meta.get("format") != FORMAT:
        raise SnapshotRefused("unknown snapshot format %s in %s" % (meta.get("format"), path))
    for key in ("height", "hash", "digest", "manifest", "failures"):
        if key not in meta:
            raise SnapshotRefused("%s has no %s" % (path, key))
    for key, kind in (("height", int), ("hash", str), ("digest", str), ("manifest", dict), ("failures", int)):
        if not isinstance(meta[key], kind) or isinstance(meta[key], bool):
            raise SnapshotRefused("%s: %s is not a %s" % (path, key, {int: "number", str: "string",
                                                                       dict: "mapping"}[kind]))
    for rel in meta["manifest"]:
        parts = rel.split(os.sep)
        if os.path.isabs(rel) or ".." in parts or parts[0] not in ("blocks", "chainstate", "tokens"):
            raise SnapshotRefused("%s: file outside the databases in the manifest: %s" % (path, rel))
    return meta


def failures(snap, meta):
    """The failures of the run the snapshot snap was made from (its
    failures.tsv). Raises SnapshotRefused when they cannot be read or their
    number differs from snapshot.json's."""
    path = os.path.join(snap, "failures.tsv")
    try:
        rows = report.read_failures(path)
    except report.ReportError as e:
        raise SnapshotRefused(str(e))
    if len(rows) != meta["failures"]:
        raise SnapshotRefused("%s has %d rows, %s %d failures" % (path, len(rows), META, meta["failures"]))
    return rows


def copy_into(snap, meta, datadir):
    """Copies the files of the snapshot snap into datadir, checking each
    against the manifest; returns (number of files, bytes). Raises
    SnapshotMismatch at the first file that is missing or differs."""
    total = 0
    for rel in sorted(meta["manifest"]):
        entry = meta["manifest"][rel]
        src = os.path.join(snap, rel)
        if not os.path.isfile(src):
            raise SnapshotMismatch("snapshot file %s is missing" % rel)
        dst = os.path.join(datadir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        size, sha256 = copy_file(src, dst)
        if size != entry.get("size") or sha256 != entry.get("sha256"):
            raise SnapshotMismatch("snapshot file %s differs from the snapshot's manifest" % rel)
        total += size
    return len(meta["manifest"]), total
