"""The replay run: copies the block files of a source directory into a new
data directory, imports them with yacoind -reindex -replayvalidation=report
on a node without network connections, stops the node, computes the digest,
checks the block files against the block index and writes the report.

With --up-to-height H the data directory gets block files holding only the
main-chain blocks 0 to H of the chain (--chain). The snapshot run copies a
snapshot's databases into the new data directory instead and gives the
node block files holding the main-chain blocks above the snapshot with
-loadblock."""

import errno
import hashlib
import os
import shutil
import signal
import socket
import subprocess
import time

from . import blockfiles, logscan, mainchain, report
from . import digest as digest_mod
from . import snapshot as snapshot_mod

REPORT_FORMAT = 1
DEFAULT_PORT = 17788
DEFAULT_RPCPORT = 17789
POLL_SECONDS = 0.5

ISOLATION_ARGS = [
    "-connect=0",
    "-listen=0",
    "-dnsseed=0",
    "-discover=0",
    "-upnp=0",
    "-listenonion=0",
    "-server=0",
    "-disablewallet",
    "-printtoconsole=0",
]

# The snapshot run gives the node its block files twice: a block stored
# before its parent is imported in the second pass. Blocks still missing
# after that show in the block-file check.
IMPORT_PASSES = 2

CONF_TEXT = "# Written by contrib/replay/replay.py; the options are on the command line.\n"

# Options the script sets itself; refused in the node arguments after --.
OWN_OPTIONS = (
    "datadir", "conf", "daemon", "reindex", "replayvalidation", "connect", "listen", "dnsseed",
    "discover", "upnp", "listenonion", "server", "disablewallet", "printtoconsole", "port", "rpcport",
    "dbcache", "stopatheight", "loadblock",
)


class RunRefused(Exception):
    """A precondition of the run does not hold; nothing was started."""


class Interrupted(Exception):
    """The script got SIGINT, SIGTERM or SIGHUP while the node ran; the node
    was stopped with SIGTERM and has exited."""

    def __init__(self, signum):
        Exception.__init__(self, "interrupted by %s; the node was stopped" % signal.Signals(signum).name)
        self.signum = signum


STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


utc_now = report.utc_now
block_files = blockfiles.block_files


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)


def port_in_use(port):
    """True when a TCP socket of this host is bound to port. Raises
    RunRefused when the port cannot be checked."""
    if not 1 <= port <= 65535:
        raise RunRefused("port %d is not between 1 and 65535" % port)
    for host in ("127.0.0.1", "0.0.0.0"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                return True
            raise RunRefused("cannot check port %d on %s: %s" % (port, host, e.strerror or e))
        finally:
            s.close()
    return False


def loadblock_files(imports):
    """The -loadblock files of a snapshot run, in the order they are given:
    imports, IMPORT_PASSES times."""
    return list(imports) * IMPORT_PASSES


def node_command(binary, datadir, conf, port, rpcport, dbcache=None, stop_at_height=None, extra=(), imports=None):
    """The node's command line: with -reindex, or, when imports is a list
    of block files, with -loadblock for each of loadblock_files(imports)."""
    cmd = [binary, "-datadir=" + datadir, "-conf=" + conf, "-daemon=0"]
    if imports is None:
        cmd.append("-reindex")
    cmd.append("-replayvalidation=report")
    cmd += ISOLATION_ARGS
    cmd += ["-port=%d" % port, "-rpcport=%d" % rpcport]
    if dbcache is not None:
        cmd.append("-dbcache=%d" % dbcache)
    if stop_at_height is not None:
        cmd.append("-stopatheight=%d" % stop_at_height)
    if imports is not None:
        cmd += ["-loadblock=" + path for path in loadblock_files(imports)]
    return cmd + list(extra)


def own_option(arg):
    """The option of OWN_OPTIONS that the node argument arg sets, or None."""
    if not arg.startswith("-"):
        return None
    name = arg.lstrip("-").split("=", 1)[0]
    if name.startswith("no") and name[2:] in OWN_OPTIONS:
        name = name[2:]
    return name if name in OWN_OPTIONS else None


def check(binary, source, out, port, rpcport, extra=()):
    for arg in extra:
        if own_option(arg):
            raise RunRefused("node argument %s: -%s is set by the script" % (arg, own_option(arg)))
    if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
        raise RunRefused("not an executable file: %s" % binary)
    if not os.path.isdir(source):
        raise RunRefused("not a directory: %s" % source)
    if not block_files(source):
        raise RunRefused("no blk00000.dat in %s" % source)
    if os.path.lexists(out):
        raise RunRefused("output directory exists: %s" % out)
    real_source = os.path.realpath(source)
    real_out = os.path.realpath(out)
    if os.path.commonpath([real_source, real_out]) == real_source:
        raise RunRefused("output directory %s is inside the source directory %s" % (out, source))
    if port == rpcport:
        raise RunRefused("--port and --rpcport are the same")
    for p in (port, rpcport):
        if port_in_use(p):
            raise RunRefused("port %d is in use" % p)


def _wait(pid, follower, marks, start, stop_sent, reaped, log):
    """Waits for the node to exit; sends SIGTERM once "Done loading" is in
    its log. Returns (status, rusage); reaped gets them as soon as the
    node is reaped."""
    while True:
        # A stop signal is handled after the reap is recorded, not between.
        signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
        try:
            done, status, rusage = os.wait4(pid, os.WNOHANG)
            if done:
                reaped.append((status, rusage))
        finally:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, STOP_SIGNALS)
        follower.poll()
        now = time.monotonic() - start
        s = follower.scanner
        if s.reindex_finished and marks.get("reindex_finished_seconds") is None:
            marks["reindex_finished_seconds"] = round(now, 3)
            log("reindex finished after %.0f s" % now)
        if s.done_loading and marks.get("done_loading_seconds") is None:
            marks["done_loading_seconds"] = round(now, 3)
        if done:
            return status, rusage
        if s.done_loading and not stop_sent[0]:
            log("start-up done; stopping the node")
            os.kill(pid, signal.SIGTERM)
            stop_sent[0] = True
        time.sleep(POLL_SECONDS)


def check_modes(out, snapshot, stop_at_height, up_to_height, chain):
    """Refuses option combinations a run does not take."""
    if up_to_height is not None:
        if stop_at_height is not None:
            raise RunRefused("--up-to-height is not taken with --stop-at-height")
        if snapshot is not None:
            raise RunRefused("--up-to-height is not taken with --snapshot")
        if up_to_height < 0:
            raise RunRefused("--up-to-height %d is below 0" % up_to_height)
    if chain is None:
        if snapshot is not None or up_to_height is not None:
            raise RunRefused("--chain is needed with %s" % ("--snapshot" if snapshot is not None else "--up-to-height"))
        return
    if snapshot is None and up_to_height is None:
        raise RunRefused("--chain is only taken with --up-to-height or --snapshot")
    real_chain = os.path.realpath(chain)
    if os.path.commonpath([real_chain, os.path.realpath(out)]) == real_chain:
        raise RunRefused("output directory %s is inside the chain's data directory %s" % (out, chain))


def load_chain(chain, meta, stop_at_height, up_to_height):
    """The mainchain.Chain of the data directory chain; raises RunRefused
    when it cannot be read or does not hold the blocks the run needs."""
    try:
        c = mainchain.load(chain)
    except mainchain.ChainError as e:
        raise RunRefused("--chain %s: %s" % (chain, e))
    if up_to_height is not None and c.tip_height < up_to_height:
        raise RunRefused("the chain of %s ends at height %d, below --up-to-height %d"
                         % (chain, c.tip_height, up_to_height))
    if meta is not None:
        height = meta["height"]
        if c.tip_height < height or c.hashes[height] != meta["hash"]:
            raise RunRefused("the chain of %s does not hold the snapshot's block %s at height %d"
                             % (chain, meta["hash"], height))
        if c.tip_height == height:
            raise RunRefused("the chain of %s ends at height %d, the snapshot's height" % (chain, height))
        if stop_at_height is not None and c.tip_height < stop_at_height:
            raise RunRefused("the chain of %s ends at height %d, below --stop-at-height %d"
                             % (chain, c.tip_height, stop_at_height))
    return c


def check_snapshot(snapshot, out, stop_at_height):
    """The content of the snapshot's snapshot.json; raises RunRefused when
    the snapshot run cannot be made."""
    real_snapshot = os.path.realpath(snapshot)
    if os.path.commonpath([real_snapshot, os.path.realpath(out)]) == real_snapshot:
        raise RunRefused("output directory %s is inside the snapshot directory %s" % (out, snapshot))
    try:
        meta = snapshot_mod.load(snapshot)
        meta["failure_rows"] = snapshot_mod.failures(snapshot, meta)
    except snapshot_mod.SnapshotRefused as e:
        raise RunRefused(str(e))
    if stop_at_height is not None and stop_at_height <= meta["height"]:
        raise RunRefused("--stop-at-height %d is not above the snapshot's height %d" % (stop_at_height, meta["height"]))
    return meta


def _copy_block_files(files, directory):
    total = 0
    for path in files:
        shutil.copyfile(path, os.path.join(directory, os.path.basename(path)))
        total += os.path.getsize(path)
    return total


def run(binary, source, out, port=DEFAULT_PORT, rpcport=DEFAULT_RPCPORT, dbcache=None, stop_at_height=None,
        extra=(), log=print, snapshot=None, up_to_height=None, chain=None):
    """Runs the replay: a full one, up to height up_to_height of the main
    chain of the data directory chain if given, or from the snapshot
    directory snapshot with the main-chain blocks of chain above it.
    Returns the report dict. Raises RunRefused before anything is created
    when a precondition does not hold."""
    binary = os.path.abspath(binary)
    source = os.path.abspath(source)
    out = os.path.abspath(out)
    check(binary, source, out, port, rpcport, extra)
    if chain is not None:
        chain = os.path.abspath(chain)
    check_modes(out, snapshot, stop_at_height, up_to_height, chain)
    meta = None
    if snapshot is not None:
        snapshot = os.path.abspath(snapshot)
        meta = check_snapshot(snapshot, out, stop_at_height)
    main_chain = None
    chain_seconds = None
    if chain is not None:
        log("reading the main chain of %s" % chain)
        t_chain = time.monotonic()
        main_chain = load_chain(chain, meta, stop_at_height, up_to_height)
        chain_seconds = round(time.monotonic() - t_chain, 3)

    rep = {"format": REPORT_FORMAT, "kind": "run", "mode": "full" if meta is None else "snapshot",
           "snapshot": None, "blocks_above_snapshot": None, "start_time": utc_now(), "source": source,
           "binary": {"path": binary, "sha256": file_sha256(binary)}}
    if meta is not None:
        rep["snapshot"] = {"path": snapshot, "height": meta["height"], "hash": meta["hash"], "digest": meta["digest"],
                           "binary": meta.get("binary")}
    datadir = os.path.join(out, "datadir")
    blocks = os.path.join(datadir, "blocks")
    rep["datadir"] = datadir
    rep["stop_at_height"] = stop_at_height
    rep["up_to_height"] = up_to_height
    rep["chain"] = None
    if main_chain is not None:
        rep["chain"] = {"datadir": chain, "height": main_chain.tip_height, "hash": main_chain.tip_hash}

    t0 = time.monotonic()
    files = block_files(source)
    phases = {}
    if chain_seconds is not None:
        phases["chain_seconds"] = chain_seconds
    imports = None
    if main_chain is None:
        os.makedirs(blocks)
        rep["block_files"] = {"count": len(files), "bytes": _copy_block_files(files, blocks)}
    else:
        if meta is None:
            target, first, last = blocks, 0, up_to_height
        else:
            target, first, last = os.path.join(out, "import"), meta["height"] + 1, main_chain.tip_height
        os.makedirs(target)
        written = mainchain.write_block_files(files, main_chain, first, last, target)
        main_chain = None
        rep["block_files"] = {"count": len(written.paths), "bytes": written.bytes}
        reasons = mainchain.reasons(written)
        if reasons:
            for reason in reasons:
                log(reason)
            phases["copy_seconds"] = round(time.monotonic() - t0, 3)
            return _not_started(out, rep, phases, reasons)
        if meta is not None:
            imports = written.paths
    if meta is not None:
        os.makedirs(datadir)
        try:
            count, total = snapshot_mod.copy_into(snapshot, meta, datadir)
        except snapshot_mod.SnapshotMismatch as e:
            log(str(e))
            phases["copy_seconds"] = round(time.monotonic() - t0, 3)
            return _not_started(out, rep, phases, [str(e)])
        log("copied %d files of the snapshot (%d bytes)" % (count, total))
    phases["copy_seconds"] = round(time.monotonic() - t0, 3)
    log("block files: %d (%d bytes)" % (rep["block_files"]["count"], rep["block_files"]["bytes"]))

    conf = os.path.join(datadir, "yacoin.conf")
    with open(conf, "w") as f:
        f.write(CONF_TEXT)
    cmd = node_command(binary, datadir, conf, port, rpcport, dbcache, stop_at_height, extra, imports)
    rep["command"] = cmd

    follower = logscan.LogFollower(os.path.join(datadir, "debug.log"))
    marks = {"reindex_finished_seconds": None, "done_loading_seconds": None}
    stop_sent = [False]
    log("starting the node")
    start = time.monotonic()

    def interrupt(signum, frame):
        raise Interrupted(signum)

    # Signals the caller ignores (for example under nohup) stay ignored.
    old_handlers = {sig: signal.signal(sig, interrupt) for sig in STOP_SIGNALS
                    if signal.getsignal(sig) is not signal.SIG_IGN}
    proc = None
    start_error = None
    reaped = []
    try:
        try:
            with open(os.path.join(out, "node-stdout.log"), "wb") as stdout, \
                    open(os.path.join(out, "node-stderr.log"), "wb") as stderr:
                # Stop signals wait until proc is set; the node starts with
                # the signal mask of the script before the block.
                old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
                try:
                    proc = subprocess.Popen(
                        cmd, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, cwd=out,
                        start_new_session=True,
                        preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, old_mask))
                except OSError as e:
                    start_error = e
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            if start_error is None:
                status, rusage = _wait(proc.pid, follower, marks, start, stop_sent, reaped, log)
        except BaseException as e:
            if proc is None:
                raise
            # Stop the node with SIGTERM and wait for it to exit; stop
            # signals are ignored meanwhile.
            for sig in old_handlers:
                signal.signal(sig, signal.SIG_IGN)
            if not reaped:
                if not stop_sent[0]:
                    os.kill(proc.pid, signal.SIGTERM)
                log("stopping the node (%s)" % (e if isinstance(e, Interrupted) else type(e).__name__))
                _, status, rusage = os.wait4(proc.pid, 0)
                reaped.append((status, rusage))
            status = reaped[0][0]
            proc.returncode = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
            follower.finish()
            raise
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    if start_error is not None:
        log("cannot start the node: %s" % start_error)
        return _not_started(out, rep, phases, ["cannot start the node: %s" % start_error])
    node_seconds = time.monotonic() - start
    follower.finish()
    exit_status = os.WEXITSTATUS(status) if os.WIFEXITED(status) else None
    exit_signal = signal.Signals(os.WTERMSIG(status)).name if os.WIFSIGNALED(status) else None
    # Reaped by os.wait4 above; tell the Popen object.
    proc.returncode = exit_status if exit_signal is None else -os.WTERMSIG(status)
    rep.update({
        "end_time": utc_now(),
        "exit_status": exit_status,
        "exit_signal": exit_signal,
        "wall_seconds": round(node_seconds, 3),
        "user_seconds": round(rusage.ru_utime, 3),
        "system_seconds": round(rusage.ru_stime, 3),
        "cpu_seconds": round(rusage.ru_utime + rusage.ru_stime, 3),
        "peak_rss_kib": rusage.ru_maxrss,
        "reindex_finished": follower.scanner.reindex_finished,
        "done_loading": follower.scanner.done_loading,
    })
    phases.update(marks)
    phases["node_seconds"] = round(node_seconds, 3)
    log("node exited (%s) after %.0f s" % (
        "status %s" % exit_status if exit_signal is None else "signal %s" % exit_signal, node_seconds))

    t1 = time.monotonic()
    try:
        d = digest_mod.compute(datadir)
        rep["digest_error"] = None
    except digest_mod.DigestError as e:
        d = None
        rep["digest_error"] = str(e)
        log("digest: %s" % e)
    except Exception as e:  # the report of the run is written in any case
        d = None
        rep["digest_error"] = "%s: %s" % (type(e).__name__, e)
        log("digest: %s" % rep["digest_error"])
    phases["digest_seconds"] = round(time.monotonic() - t1, 3)
    rep["phases"] = phases

    # A snapshot run's failures include those of the run the snapshot was
    # made from.
    failures = (meta["failure_rows"] if meta is not None else []) + follower.scanner.failures
    marked = logscan.mark_main_chain(failures, d.rows if d else [])
    n_failures, n_blocks = logscan.counts(failures)
    rep["failures"] = n_failures
    rep["failure_blocks"] = n_blocks
    rep["failures_off_main_chain"] = sum(1 for _, main in marked if not main)
    fill_digest(rep, d)
    if meta is not None and d is not None:
        rep["blocks_above_snapshot"] = d.tip_height - meta["height"]

    reasons = incomplete_reasons(exit_status, exit_signal, follower.scanner, d, stop_at_height,
                                 None if meta is None else meta["height"], loadblock_files(imports or ()),
                                 up_to_height)
    rep["block_file_check"] = None
    if d is not None:
        t2 = time.monotonic()
        result = blockfiles.check(block_files(blocks) if imports is None else imports, datadir, d.tip_height,
                                  stop_at_height)
        phases["block_file_check_seconds"] = round(time.monotonic() - t2, 3)
        rep["block_file_check"] = result.fields
        reasons += result.reasons
    rep["incomplete_reasons"] = reasons
    rep["status"] = "incomplete" if reasons else "complete"
    report.write(out, rep, d.rows if d else [], marked)
    return rep


def _not_started(out, rep, phases, reasons):
    """The report of a run whose node was not started or could not be
    started, for the reasons given."""
    rep.setdefault("command", None)
    rep.update({
        "end_time": utc_now(), "exit_status": None, "exit_signal": None, "wall_seconds": None,
        "user_seconds": None, "system_seconds": None, "cpu_seconds": None, "peak_rss_kib": None,
        "reindex_finished": False, "done_loading": False, "phases": phases, "digest_error": None,
        "failures": 0, "failure_blocks": 0, "failures_off_main_chain": 0, "block_file_check": None,
        "incomplete_reasons": list(reasons), "status": "incomplete",
    })
    fill_digest(rep, None)
    report.write(out, rep, [], [])
    return rep


def incomplete_reasons(exit_status, exit_signal, scanner, d, stop_at_height, snapshot_height=None, imports=(),
                       up_to_height=None):
    """Why a run is incomplete, apart from the block-file check; empty for a
    complete run. A node stopped by -stopatheight during the import exits
    with status 1 after "Done loading"; with stop_at_height that status
    counts as a clean exit when the tip is at stop_at_height. A snapshot
    run (snapshot_height set) needs "Done loading", an "Importing blocks
    file" line for each -loadblock file (imports, in the order given), no
    "Could not open blocks file" line and a tip at or above
    snapshot_height. A run with up_to_height needs its tip at that height."""
    reasons = []
    clean = (0, 1) if stop_at_height is not None else (0,)
    if exit_signal is not None:
        reasons.append("node ended by signal %s" % exit_signal)
    elif exit_status not in clean or (exit_status == 1 and not scanner.done_loading):
        reasons.append("node exit status %d" % exit_status)
    if snapshot_height is None:
        if not scanner.reindex_finished:
            reasons.append("no \"Reindexing finished\" in debug.log")
    else:
        if not scanner.done_loading:
            reasons.append("no \"Done loading\" in debug.log")
        for path in sorted(set(imports), key=list(imports).index):
            logged, given = scanner.imported.count(path), list(imports).count(path)
            if logged != given:
                reasons.append("\"Importing blocks file\" logged %d of %d times for %s" % (logged, given, path))
        for path in sorted(set(scanner.not_opened), key=scanner.not_opened.index):
            reasons.append("\"Could not open blocks file\" for %s" % path)
    if d is None:
        reasons.append("no digest")
    elif stop_at_height is not None and d.tip_height != stop_at_height:
        reasons.append("tip height %d, not --stop-at-height %d" % (d.tip_height, stop_at_height))
    elif up_to_height is not None and d.tip_height != up_to_height:
        reasons.append("tip height %d, not --up-to-height %d" % (d.tip_height, up_to_height))
    elif snapshot_height is not None and d.tip_height < snapshot_height:
        reasons.append("tip height %d below the snapshot's height %d" % (d.tip_height, snapshot_height))
    return reasons


def fill_digest(rep, d):
    if d is None:
        rep["tip"] = None
        rep["sections"] = {}
        rep["digest"] = None
        return
    rep["tip"] = {"height": d.tip_height, "hash": d.tip_hash}
    rep["sections"] = {name: {"count": s.count, "sha256": s.sha256} for name, s in d.sections.items()}
    rep["digest"] = d.overall


def digest_only(datadir, out):
    """The digest command: the report of a stopped node's data directory."""
    datadir = os.path.abspath(datadir)
    out = os.path.abspath(out)
    if not os.path.isdir(datadir):
        raise RunRefused("not a directory: %s" % datadir)
    if os.path.lexists(out):
        raise RunRefused("output directory exists: %s" % out)
    rep = {"format": REPORT_FORMAT, "kind": "digest", "start_time": utc_now(), "datadir": datadir}
    t0 = time.monotonic()
    d = digest_mod.compute(datadir)
    rep["phases"] = {"digest_seconds": round(time.monotonic() - t0, 3)}
    rep["end_time"] = utc_now()
    rep["status"] = "complete"
    fill_digest(rep, d)
    os.makedirs(out)
    report.write(out, rep, d.rows, [])
    return rep
