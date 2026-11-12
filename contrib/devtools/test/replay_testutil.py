"""Helpers of the contrib/replay tests: the path of its modules, and a
writer of LevelDB 1.20 files (write-ahead logs, tables, MANIFEST, CURRENT)
for small databases built by the tests."""

import os
import stat
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPLAY_DIR = os.path.join(os.path.dirname(os.path.dirname(HERE)), "replay")
REPLAY_SCRIPT = os.path.join(REPLAY_DIR, "replay.py")
if REPLAY_DIR not in sys.path:
    sys.path.insert(0, REPLAY_DIR)

from replaylib import leveldb  # noqa: E402
from replaylib.ser import encode_varint32 as varint32  # noqa: E402

TYPE_DELETION = 0
TYPE_VALUE = 1
BLOCK_SIZE = 32768


def lp(data):
    """A length-prefixed slice (varint32 length, then the bytes)."""
    return varint32(len(data)) + data


def internal_key(user_key, seq, kind=TYPE_VALUE):
    return user_key + struct.pack("<Q", (seq << 8) | kind)


def masked_crc(data):
    return leveldb.mask_crc(leveldb.crc32c(data))


def log_bytes(records):
    """The log-format bytes of a list of record payloads, fragmented over
    32 KiB blocks as LevelDB's log writer does."""
    out = bytearray()
    for payload in records:
        begin = True
        pos = 0
        while True:
            left = BLOCK_SIZE - len(out) % BLOCK_SIZE
            if left < 7:
                out += b"\0" * left
                left = BLOCK_SIZE
            avail = left - 7
            fragment = payload[pos:pos + avail]
            end = pos + len(fragment) == len(payload)
            if begin and end:
                kind = 1
            elif begin:
                kind = 2
            elif end:
                kind = 4
            else:
                kind = 3
            out += struct.pack("<IHB", masked_crc(bytes([kind]) + fragment), len(fragment), kind)
            out += fragment
            pos += len(fragment)
            begin = False
            if end:
                break
    return bytes(out)


def batch_bytes(seq, ops):
    """A WriteBatch: ops are (key, value) pairs, value None for a deletion."""
    out = bytearray(struct.pack("<QI", seq, len(ops)))
    for key, value in ops:
        if value is None:
            out += bytes([TYPE_DELETION]) + lp(key)
        else:
            out += bytes([TYPE_VALUE]) + lp(key) + lp(value)
    return bytes(out)


def block_bytes(entries, restart_interval, compression=0):
    """A table block of (key, value) entries with prefix compression and a
    restart point every restart_interval entries, plus its 5-byte trailer."""
    out = bytearray()
    restarts = []
    last = b""
    for i, (key, value) in enumerate(entries):
        if i % restart_interval == 0:
            restarts.append(len(out))
            shared = 0
        else:
            shared = 0
            while shared < min(len(last), len(key)) and last[shared] == key[shared]:
                shared += 1
        out += varint32(shared) + varint32(len(key) - shared) + varint32(len(value))
        out += key[shared:] + value
        last = key
    if not restarts:
        restarts.append(0)
    for r in restarts:
        out += struct.pack("<I", r)
    out += struct.pack("<I", len(restarts))
    data = bytes(out)
    trailer = bytes([compression]) + struct.pack("<I", masked_crc(data + bytes([compression])))
    return data, trailer


def handle(offset, size):
    return leveldb.encode_varint64(offset) + leveldb.encode_varint64(size)


def table_bytes(entries, restart_interval=16, entries_per_block=1000, compression=0):
    """A table (.ldb) of sorted (internal key, value) entries."""
    out = bytearray()
    index = []
    for start in range(0, len(entries), entries_per_block):
        chunk = entries[start:start + entries_per_block]
        data, trailer = block_bytes(chunk, restart_interval, compression)
        index.append((chunk[-1][0], handle(len(out), len(data))))
        out += data + trailer
    data, trailer = block_bytes([], 1)
    meta = handle(len(out), len(data))
    out += data + trailer
    data, trailer = block_bytes(index, 1)
    idx = handle(len(out), len(data))
    out += data + trailer
    footer = meta + idx
    footer += b"\0" * (40 - len(footer))
    footer += struct.pack("<Q", leveldb.TABLE_MAGIC)
    return bytes(out + footer)


def edit_bytes(comparator=None, log_number=None, prev_log_number=None, next_file=None,
               last_seq=None, new_files=(), deleted_files=()):
    """A VersionEdit record: new_files are (level, number, size, smallest,
    largest), deleted_files (level, number)."""
    out = bytearray()
    if comparator is not None:
        out += varint32(1) + lp(comparator)
    if log_number is not None:
        out += varint32(2) + leveldb.encode_varint64(log_number)
    if next_file is not None:
        out += varint32(3) + leveldb.encode_varint64(next_file)
    if last_seq is not None:
        out += varint32(4) + leveldb.encode_varint64(last_seq)
    for level, number in deleted_files:
        out += varint32(6) + varint32(level) + leveldb.encode_varint64(number)
    for level, number, size, smallest, largest in new_files:
        out += varint32(7) + varint32(level) + leveldb.encode_varint64(number)
        out += leveldb.encode_varint64(size) + lp(smallest) + lp(largest)
    if prev_log_number is not None:
        out += varint32(9) + leveldb.encode_varint64(prev_log_number)
    return bytes(out)


class DBWriter:
    """Builds a database directory step by step: tables (with their
    VersionEdit) and logs; finish() writes MANIFEST and CURRENT."""

    def __init__(self, path, manifest_number=1):
        self.path = path
        os.makedirs(path, exist_ok=True)
        self.manifest_number = manifest_number
        self.edits = [edit_bytes(comparator=b"leveldb.BytewiseComparator")]
        self.next_number = manifest_number + 1
        self.log_number = 0

    def number(self):
        n = self.next_number
        self.next_number += 1
        return n

    def add_table(self, entries, level=0, ext=".ldb", **kwargs):
        """entries: (user key, seq, value or None) triples; written sorted
        as LevelDB orders internal keys (user key up, sequence down)."""
        items = sorted(entries, key=lambda e: (e[0], -e[1]))
        ikeys = [(internal_key(k, s, TYPE_DELETION if v is None else TYPE_VALUE), v or b"")
                 for k, s, v in items]
        data = table_bytes(ikeys, **kwargs)
        n = self.number()
        with open(os.path.join(self.path, "%06d%s" % (n, ext)), "wb") as f:
            f.write(data)
        self.edits.append(edit_bytes(new_files=[(level, n, len(data), ikeys[0][0], ikeys[-1][0])]))
        return n

    def delete_table(self, level, number):
        self.edits.append(edit_bytes(deleted_files=[(level, number)]))

    def add_log(self, batches, number=None, set_log_number=True):
        """batches: (first sequence, ops) pairs, see batch_bytes."""
        n = self.number() if number is None else number
        with open(os.path.join(self.path, "%06d.log" % n), "wb") as f:
            f.write(log_bytes([batch_bytes(seq, ops) for seq, ops in batches]))
        if set_log_number:
            self.log_number = n
        return n

    def finish(self):
        self.edits.append(edit_bytes(log_number=self.log_number, next_file=self.next_number, last_seq=1 << 20))
        name = "MANIFEST-%06d" % self.manifest_number
        with open(os.path.join(self.path, name), "wb") as f:
            f.write(log_bytes(self.edits))
        with open(os.path.join(self.path, "CURRENT"), "w") as f:
            f.write(name + "\n")


BLOCK_HAVE_DATA = 8
BLOCK_HAVE_UNDO = 16
BLOCK_PROOF_OF_STAKE = 1


def block_index_bytes(f):
    """A blocks/index 'b' record value as CDiskBlockIndex serialises it;
    f is a dict with the field names of replaylib.chain.parse_block_index."""
    from replaylib.ser import encode_varint
    out = bytearray(encode_varint(f.get("client_version", 1110000)))
    out += struct.pack("<i", f["height"])
    status = f.get("status", BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)
    out += encode_varint(status) + encode_varint(f.get("tx", 1))
    if status & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO):
        out += encode_varint(f.get("file", 0))
    if status & BLOCK_HAVE_DATA:
        out += encode_varint(f.get("data_pos", 8))
    if status & BLOCK_HAVE_UNDO:
        out += encode_varint(f.get("undo_pos", 8))
    flags = f.get("flags", 0)
    out += struct.pack("<qqIQ", f.get("mint", 0), f.get("money_supply", 0), flags, f.get("stake_modifier", 0))
    if flags & BLOCK_PROOF_OF_STAKE:
        out += f.get("prevout_stake", b"\x11" * 32 + b"\x01\0\0\0")
        out += struct.pack("<I", f.get("stake_time", 0))
        out += f.get("hash_proof_of_stake", b"\x22" * 32)
    version = f.get("version", 7)
    out += struct.pack("<i", version) + f.get("hash_prev", b"\0" * 32) + f.get("merkle", b"\x33" * 32)
    if version >= 7:
        out += struct.pack("<q", f.get("time", 1700000000))
    else:
        out += struct.pack("<I", f.get("time", 1700000000))
    out += struct.pack("<II", f.get("bits", 0x1e0fffff), f.get("nonce", 0))
    out += f.get("block_hash", b"\0" * 32)
    return bytes(out)


OBFUSCATE_KEY_KEY = b"\x0e\x00obfuscate_key"


def xor(value, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(value))


def fake_hash(height, salt=0):
    """A made-up 32-byte block hash (internal byte order)."""
    import hashlib
    return hashlib.sha256(b"block %d %d" % (height, salt)).digest()


def sha256d(data):
    import hashlib
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# The record marker of the synthetic block files.
MARKER = b"\xa1\xb2\xc3\xd4"


def header_bytes(f):
    """The block header of the fields f (names of
    replaylib.chain.parse_block_index): 32-bit time below version 7,
    64-bit time from version 7."""
    version = f.get("version", 7)
    out = struct.pack("<i", version) + f["hash_prev"] + f["merkle"]
    out += struct.pack("<q" if version >= 7 else "<I", f["time"])
    return out + struct.pack("<II", f["bits"], f["nonce"])


def block_record(f, marker=MARKER, body=b"\x00" * 4):
    """A block file record: marker, size, the header of f and body."""
    content = header_bytes(f) + body
    return marker + struct.pack("<I", len(content)) + content


def index_records(datadir):
    """The parsed 'b' records of datadir's block index, by block hash."""
    from replaylib import chain
    records = leveldb.read_db(os.path.join(datadir, "blocks", "index"), b"b", b"c")
    return {k[1:]: chain.parse_block_index(v) for k, v in records}


def make_datadir(path, heights=3, coins=None, tokens=None, key=b"\x01\x02\x03\x04\x05\x06\x07\x08",
                 head_blocks=False, block_fields=None, undo=None, side_blocks=0, rev_padding=b"",
                 blk=False, tip=None, salt=0):
    """A data directory with blocks/index (a chain of heights + 1 'b'
    records and side_blocks records off the chain), blocks/rev00000.dat with
    one undo record per height above 0, chainstate (obfuscated with key,
    best block = the block at height tip, default the last) and tokens.
    coins: (key, plain value) pairs; tokens: (key, value) pairs;
    block_fields(height) adds fields to a record; undo(height) gives its
    undo content; rev_padding comes before the first undo record. With blk,
    blocks/blk00000.dat holds a record (marker MARKER) for every block with
    data. salt gives the blocks above genesis other hashes. Returns the
    block hashes in height order."""
    os.makedirs(os.path.join(path, "blocks"))
    hashes = [fake_hash(h, salt if h else 0) for h in range(heights + 1)]
    rev = bytearray(rev_padding)
    records = []
    blk_bytes = bytearray()
    for h, block_hash in enumerate(hashes):
        f = {"height": h, "hash_prev": hashes[h - 1] if h else b"\0" * 32, "block_hash": block_hash,
             "money_supply": 1000 * h, "mint": 1000 if h else 0, "time": 1700000000 + 60 * h,
             "data_pos": 8 + 300 * h, "merkle": fake_hash(h, salt=1000), "bits": 0x1e0fffff,
             "nonce": 0x1234 + h}
        if h == 0:
            f["status"] = BLOCK_HAVE_DATA
        else:
            content = undo(h) if undo else b"\x01\x00" + bytes([h])
            rev += b"\xd9\xe6\xe7\xe5" + struct.pack("<I", len(content))
            f["undo_pos"] = len(rev)
            rev += content + sha256d(hashes[h - 1] + content)
        if block_fields:
            f.update(block_fields(h))
        records.append((b"b" + block_hash, block_index_bytes(f)))
        if f.get("status", BLOCK_HAVE_DATA) & BLOCK_HAVE_DATA:
            blk_bytes += block_record(f)
    for s in range(side_blocks):
        side = fake_hash(1, salt=500 + s)
        f = {"height": 1, "hash_prev": hashes[0], "block_hash": side, "status": BLOCK_HAVE_DATA,
             "merkle": fake_hash(1, salt=2000 + s), "time": 1700000090, "bits": 0x1e0fffff, "nonce": 0x2345 + s}
        records.append((b"b" + side, block_index_bytes(f)))
        blk_bytes += block_record(f)
    if blk:
        with open(os.path.join(path, "blocks", "blk00000.dat"), "wb") as f:
            f.write(bytes(blk_bytes))
    with open(os.path.join(path, "blocks", "rev00000.dat"), "wb") as f:
        f.write(bytes(rev))
    index = DBWriter(os.path.join(path, "blocks", "index"))
    index.add_table([(k, i + 1, v) for i, (k, v) in enumerate(records)] + [(b"l", 900, b"\0\0\0\0")])
    index.add_log([(1000, [(b"t" + b"\x44" * 32, b"\0\x08\x01")])])
    index.finish()
    state = DBWriter(os.path.join(path, "chainstate"))
    best = hashes[heights if tip is None else tip]
    ops = [(OBFUSCATE_KEY_KEY, b"\x08" + key), (b"B", xor(best, key))]
    if head_blocks:
        ops.append((b"H", xor(b"\x02" + hashes[-1] + hashes[-2], key)))
    for k, v in (coins if coins is not None else [(b"C" + b"\x55" * 32 + b"\x00", b"\x03\x00\x05\x00")]):
        ops.append((k, xor(v, key)))
    state.add_log([(1, ops)])
    state.finish()
    tok = DBWriter(os.path.join(path, "tokens"))
    tok.add_log([(1, list(tokens) if tokens is not None else [])])
    tok.finish()
    return hashes


def make_run(out, heights=3, fields=None, failures=(), **kwargs):
    """The output directory of a complete full run: OUT/datadir (as
    make_datadir with blk, plus debug.log, yacoin.conf, .lock and
    peers.dat) and the report files of its digest, with the failures
    (logscan.Failure) given; fields replace fields of the report. Returns
    the report."""
    from replaylib import digest, logscan, report, runner
    datadir = os.path.join(out, "datadir")
    make_datadir(datadir, heights=heights, blk=True, **kwargs)
    for name, data in (("debug.log", b"2026-11-08 10:00:00 Done loading\n"), ("yacoin.conf", b"# conf\n"),
                       (".lock", b""), ("peers.dat", b"\x01\x02")):
        with open(os.path.join(datadir, name), "wb") as f:
            f.write(data)
    d = digest.compute(datadir)
    rep = {"format": runner.REPORT_FORMAT, "kind": "run", "mode": "full", "snapshot": None, "status": "complete",
           "incomplete_reasons": [], "datadir": datadir, "source": "/source/blocks",
           "command": ["/bin/yacoind", "-datadir=" + datadir, "-reindex"],
           "binary": {"path": "/bin/yacoind", "sha256": "ab" * 32}, "stop_at_height": None,
           "start_time": "2026-11-08T10:00:00Z", "end_time": "2026-11-08T10:01:00Z"}
    runner.fill_digest(rep, d)
    marked = logscan.mark_main_chain(list(failures), d.rows)
    rep["failures"], rep["failure_blocks"] = logscan.counts(list(failures))
    rep["failures_off_main_chain"] = sum(1 for _, main in marked if not main)
    rep.update(fields or {})
    report.write(out, rep, d.rows, marked)
    return rep


def tree_state(path):
    """Per path under path (directories included): type, size, mode, mtime
    and the SHA-256 of a file's content."""
    import hashlib
    out = {}
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            full = os.path.join(root, name)
            st = os.lstat(full)
            entry = (stat.S_IFMT(st.st_mode), st.st_size if name in files else 0, stat.S_IMODE(st.st_mode),
                     st.st_mtime_ns)
            if name in files:
                with open(full, "rb") as f:
                    entry += (hashlib.sha256(f.read()).hexdigest(),)
            out[os.path.relpath(full, path)] = entry
    return out


def make_writable(path):
    """Gives the owner write permission on path and everything under it."""
    for root, dirs, files in os.walk(path):
        os.chmod(root, os.stat(root).st_mode | stat.S_IWUSR)
        for name in files:
            full = os.path.join(root, name)
            os.chmod(full, os.stat(full).st_mode | stat.S_IWUSR)
