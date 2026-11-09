"""The replay run: copies the block files of a source directory into a new
data directory, imports them with yacoind -reindex -replayvalidation=report
on a node without network connections, stops the node, computes the digest,
checks the block files against the block index and writes the report."""

import datetime
import errno
import hashlib
import os
import shutil
import signal
import socket
import subprocess
import time

from . import blockfiles, logscan, report
from . import digest as digest_mod

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

CONF_TEXT = "# Written by contrib/replay/replay.py; the options are on the command line.\n"

# Options the script sets itself; refused in the node arguments after --.
OWN_OPTIONS = (
    "datadir", "conf", "daemon", "reindex", "replayvalidation", "connect", "listen", "dnsseed",
    "discover", "upnp", "listenonion", "server", "disablewallet", "printtoconsole", "port", "rpcport",
    "dbcache", "stopatheight",
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


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


block_files = blockfiles.block_files


def node_command(binary, datadir, conf, port, rpcport, dbcache=None, stop_at_height=None, extra=()):
    cmd = [binary, "-datadir=" + datadir, "-conf=" + conf, "-daemon=0", "-reindex", "-replayvalidation=report"]
    cmd += ISOLATION_ARGS
    cmd += ["-port=%d" % port, "-rpcport=%d" % rpcport]
    if dbcache is not None:
        cmd.append("-dbcache=%d" % dbcache)
    if stop_at_height is not None:
        cmd.append("-stopatheight=%d" % stop_at_height)
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


def run(binary, source, out, port=DEFAULT_PORT, rpcport=DEFAULT_RPCPORT, dbcache=None, stop_at_height=None,
        extra=(), log=print):
    """Runs the replay; returns the report dict. Raises RunRefused before
    anything is created when a precondition does not hold."""
    binary = os.path.abspath(binary)
    source = os.path.abspath(source)
    out = os.path.abspath(out)
    check(binary, source, out, port, rpcport, extra)

    rep = {"format": REPORT_FORMAT, "kind": "run", "start_time": utc_now(), "source": source,
           "binary": {"path": binary, "sha256": file_sha256(binary)}}
    datadir = os.path.join(out, "datadir")
    blocks = os.path.join(datadir, "blocks")
    os.makedirs(blocks)
    rep["datadir"] = datadir

    t0 = time.monotonic()
    files = block_files(source)
    total = 0
    for path in files:
        shutil.copyfile(path, os.path.join(blocks, os.path.basename(path)))
        total += os.path.getsize(path)
    phases = {"copy_seconds": round(time.monotonic() - t0, 3)}
    rep["block_files"] = {"count": len(files), "bytes": total}
    log("copied %d block files (%d bytes)" % (len(files), total))

    conf = os.path.join(datadir, "yacoin.conf")
    with open(conf, "w") as f:
        f.write(CONF_TEXT)
    cmd = node_command(binary, datadir, conf, port, rpcport, dbcache, stop_at_height, extra)
    rep["command"] = cmd
    rep["stop_at_height"] = stop_at_height

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
        return _start_failed(out, rep, phases, start_error)
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

    marked = logscan.mark_main_chain(follower.scanner.failures, d.rows if d else [])
    n_failures, n_blocks = logscan.counts(follower.scanner.failures)
    rep["failures"] = n_failures
    rep["failure_blocks"] = n_blocks
    rep["failures_off_main_chain"] = sum(1 for _, main in marked if not main)
    fill_digest(rep, d)

    reasons = incomplete_reasons(exit_status, exit_signal, follower.scanner, d, stop_at_height)
    rep["block_file_check"] = None
    if d is not None:
        t2 = time.monotonic()
        result = blockfiles.check(block_files(blocks), datadir, d.tip_height, stop_at_height)
        phases["block_file_check_seconds"] = round(time.monotonic() - t2, 3)
        rep["block_file_check"] = result.fields
        reasons += result.reasons
    rep["incomplete_reasons"] = reasons
    rep["status"] = "incomplete" if reasons else "complete"
    report.write(out, rep, d.rows if d else [], marked)
    return rep


def _start_failed(out, rep, phases, error):
    """The report of a run whose node could not be started."""
    rep.update({
        "end_time": utc_now(), "exit_status": None, "exit_signal": None, "wall_seconds": None,
        "user_seconds": None, "system_seconds": None, "cpu_seconds": None, "peak_rss_kib": None,
        "reindex_finished": False, "done_loading": False, "phases": phases, "digest_error": None,
        "failures": 0, "failure_blocks": 0, "failures_off_main_chain": 0, "block_file_check": None,
        "incomplete_reasons": ["cannot start the node: %s" % error], "status": "incomplete",
    })
    fill_digest(rep, None)
    report.write(out, rep, [], [])
    return rep


def incomplete_reasons(exit_status, exit_signal, scanner, d, stop_at_height):
    """Why a run is incomplete, apart from the block-file check; empty for a complete run. A node stopped by
    -stopatheight during the import exits with status 1 after "Done
    loading"; with stop_at_height that status counts as a clean exit when
    the tip is at stop_at_height."""
    reasons = []
    clean = (0, 1) if stop_at_height is not None else (0,)
    if exit_signal is not None:
        reasons.append("node ended by signal %s" % exit_signal)
    elif exit_status not in clean or (exit_status == 1 and not scanner.done_loading):
        reasons.append("node exit status %d" % exit_status)
    if not scanner.reindex_finished:
        reasons.append("no \"Reindexing finished\" in debug.log")
    if d is None:
        reasons.append("no digest")
    elif stop_at_height is not None and d.tip_height != stop_at_height:
        reasons.append("tip height %d, not --stop-at-height %d" % (d.tip_height, stop_at_height))
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
