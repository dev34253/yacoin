"""A reader of LevelDB 1.20 databases: the logical key/value set of a
closed database, read from its files without changing them.

Files read: CURRENT names the MANIFEST; the MANIFEST's version edits give
the live tables (.ldb, or .sst) and the oldest live write-ahead log; the
logs (.log) hold the writes since. Across all of them the entry with the
highest sequence number of a key wins, and a deletion hides the key.
Every block and record checksum (CRC32C) is checked. Compressed table
blocks are not supported.
"""

import os
import re
import struct

from .ser import DecodeError, Reader, encode_varint32

TABLE_MAGIC = 0xdb4775248b80fb57
FOOTER_SIZE = 48
LOG_BLOCK_SIZE = 32768
LOG_HEADER_SIZE = 7
TYPE_DELETION = 0
TYPE_VALUE = 1
COMPARATOR = b"leveldb.BytewiseComparator"

encode_varint64 = encode_varint32


class LevelDBError(Exception):
    pass


def _crc_tables():
    poly = 0x82F63B78
    t0 = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        t0.append(c)
    tables = [t0]
    for _ in range(7):
        prev = tables[-1]
        tables.append([(prev[i] >> 8) ^ t0[prev[i] & 0xFF] for i in range(256)])
    return tables


_T = _crc_tables()


def crc32c(data, crc=0):
    """CRC32C (Castagnoli) of data, slicing by 8 bytes."""
    t0, t1, t2, t3, t4, t5, t6, t7 = _T
    crc ^= 0xFFFFFFFF
    n8 = len(data) & ~7
    if n8:
        for lo, hi in struct.iter_unpack("<II", memoryview(data)[:n8]):
            lo ^= crc
            crc = (t7[lo & 0xFF] ^ t6[(lo >> 8) & 0xFF] ^ t5[(lo >> 16) & 0xFF] ^ t4[lo >> 24]
                   ^ t3[hi & 0xFF] ^ t2[(hi >> 8) & 0xFF] ^ t1[(hi >> 16) & 0xFF] ^ t0[hi >> 24])
    for b in data[n8:]:
        crc = t0[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


MASK_DELTA = 0xa282ead8


def mask_crc(crc):
    return ((((crc >> 15) | (crc << 17)) & 0xFFFFFFFF) + MASK_DELTA) & 0xFFFFFFFF


def unmask_crc(masked):
    rot = (masked - MASK_DELTA) & 0xFFFFFFFF
    return ((rot >> 17) | (rot << 15)) & 0xFFFFFFFF


def read_log_records(data, name):
    """The records of a log-format file (write-ahead log or MANIFEST).
    A bad checksum, a truncated record or a broken fragment sequence is an
    error."""
    records = []
    pending = None
    pos = 0
    end = len(data)
    while pos < end:
        left = LOG_BLOCK_SIZE - pos % LOG_BLOCK_SIZE
        if left < LOG_HEADER_SIZE:
            trailer = data[pos:pos + left]
            if trailer.strip(b"\0"):
                raise LevelDBError("%s: bad block trailer at offset %d" % (name, pos))
            if pos + left > end:
                raise LevelDBError("%s: truncated record header at offset %d" % (name, pos))
            pos += left
            continue
        if pos + LOG_HEADER_SIZE > end:
            raise LevelDBError("%s: truncated record header at offset %d" % (name, pos))
        masked, length, kind = struct.unpack_from("<IHB", data, pos)
        if kind == 0 and length == 0:
            # Zero-filled rest of a block.
            pos += left
            continue
        start = pos + LOG_HEADER_SIZE
        if length > left - LOG_HEADER_SIZE or start + length > end:
            raise LevelDBError("%s: truncated record at offset %d" % (name, pos))
        payload = data[start:start + length]
        if crc32c(bytes([kind]) + payload) != unmask_crc(masked):
            raise LevelDBError("%s: record checksum mismatch at offset %d" % (name, pos))
        if kind == 1:
            if pending is not None:
                raise LevelDBError("%s: unfinished record before offset %d" % (name, pos))
            records.append(payload)
        elif kind == 2:
            if pending is not None:
                raise LevelDBError("%s: unfinished record before offset %d" % (name, pos))
            pending = bytearray(payload)
        elif kind in (3, 4):
            if pending is None:
                raise LevelDBError("%s: record fragment without start at offset %d" % (name, pos))
            pending += payload
            if kind == 4:
                records.append(bytes(pending))
                pending = None
        else:
            raise LevelDBError("%s: unknown record type %d at offset %d" % (name, kind, pos))
        pos = start + length
    if pending is not None:
        raise LevelDBError("%s: truncated record at the end of the file" % name)
    return records


def _read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise LevelDBError("cannot read %s: %s" % (path, e.strerror))


class Manifest:
    """The live tables and the log numbers of a MANIFEST."""

    def __init__(self, data, name):
        self.files = {}  # (level, number) -> (size, smallest, largest)
        self.log_number = 0
        self.prev_log_number = 0
        for rec in read_log_records(data, name):
            try:
                self._apply(Reader(rec), name)
            except DecodeError as e:
                raise LevelDBError("%s: bad version edit: %s" % (name, e))

    def _apply(self, r, name):
        while not r.at_end():
            tag = r.varint32()
            if tag == 1:
                comparator = r.length_prefixed()
                if comparator != COMPARATOR:
                    raise LevelDBError("%s: unsupported comparator %r" % (name, comparator.decode("latin-1")))
            elif tag == 2:
                self.log_number = r.varint32()
            elif tag in (3, 4):
                r.varint32()
            elif tag == 5:
                r.varint32()
                r.length_prefixed()
            elif tag == 6:
                level = r.varint32()
                self.files.pop((level, r.varint32()), None)
            elif tag == 7:
                level = r.varint32()
                number = r.varint32()
                size = r.varint32()
                smallest = r.length_prefixed()
                largest = r.length_prefixed()
                self.files[(level, number)] = (size, smallest, largest)
            elif tag == 9:
                self.prev_log_number = r.varint32()
            else:
                raise LevelDBError("%s: unknown version edit tag %d" % (name, tag))


def _in_range(key, lo, hi):
    return (lo is None or key >= lo) and (hi is None or key < hi)


class _Merge:
    """Collects (user key, sequence, type, value) and keeps the newest."""

    def __init__(self, lo, hi):
        self.lo = lo
        self.hi = hi
        self.entries = {}

    def add(self, key, seq, kind, value):
        if not _in_range(key, self.lo, self.hi):
            return
        old = self.entries.get(key)
        if old is None or seq > old[0]:
            self.entries[key] = (seq, kind, value)

    def result(self):
        return [(k, self.entries[k][2]) for k in sorted(self.entries) if self.entries[k][1] == TYPE_VALUE]

    def result_dict(self):
        """The live keys and values as a dict, converted in place."""
        entries = self.entries
        for k in list(entries):
            _, kind, value = entries[k]
            if kind == TYPE_VALUE:
                entries[k] = value
            else:
                del entries[k]
        self.entries = {}
        return entries


def _block(data, offset, size, name):
    if offset + size + 5 > len(data):
        raise LevelDBError("%s: block at offset %d past the end of the file" % (name, offset))
    contents = data[offset:offset + size]
    kind = data[offset + size]
    (masked,) = struct.unpack_from("<I", data, offset + size + 1)
    if crc32c(contents + bytes([kind])) != unmask_crc(masked):
        raise LevelDBError("%s: block checksum mismatch at offset %d" % (name, offset))
    if kind != 0:
        raise LevelDBError("%s: compressed block (type %d) at offset %d: not supported" % (name, kind, offset))
    return contents


def _block_entries(contents, name):
    """(key, value) pairs of a table block, in order."""
    if len(contents) < 4:
        raise LevelDBError("%s: block too short" % name)
    (num_restarts,) = struct.unpack_from("<I", contents, len(contents) - 4)
    limit = len(contents) - 4 - 4 * num_restarts
    if limit < 0:
        raise LevelDBError("%s: bad restart array" % name)
    r = Reader(contents)
    key = b""
    try:
        while r.pos < limit:
            shared = r.varint32()
            non_shared = r.varint32()
            value_len = r.varint32()
            if shared > len(key):
                raise LevelDBError("%s: bad block entry at offset %d" % (name, r.pos))
            key = key[:shared] + r.take(non_shared)
            yield key, r.take(value_len)
    except DecodeError as e:
        raise LevelDBError("%s: bad block entry: %s" % (name, e))
    if r.pos != limit:
        raise LevelDBError("%s: block entries overrun the restart array" % name)


def _handle(r):
    return r.varint32(), r.varint32()


def read_table(path, merge):
    """Adds the entries of a table file to merge, reading only the data
    blocks that can hold keys of merge's range."""
    name = os.path.basename(path)
    data = _read_file(path)
    if len(data) < FOOTER_SIZE:
        raise LevelDBError("%s: file too short for a table" % name)
    footer = data[-FOOTER_SIZE:]
    if struct.unpack_from("<Q", footer, 40)[0] != TABLE_MAGIC:
        raise LevelDBError("%s: bad table magic" % name)
    try:
        r = Reader(footer)
        _handle(r)  # metaindex: only the filter, not needed
        index_offset, index_size = _handle(r)
        index = list(_block_entries(_block(data, index_offset, index_size, name), name))
        prev_user = None
        for sep, value in index:
            sep_user = sep[:-8]
            if merge.hi is not None and prev_user is not None and prev_user >= merge.hi:
                break
            prev_user = sep_user
            if merge.lo is not None and sep_user < merge.lo:
                continue
            offset, size = _handle(Reader(value))
            for ikey, val in _block_entries(_block(data, offset, size, name), name):
                if len(ikey) < 8:
                    raise LevelDBError("%s: internal key too short" % name)
                (tag,) = struct.unpack_from("<Q", ikey, len(ikey) - 8)
                kind = tag & 0xFF
                if kind not in (TYPE_DELETION, TYPE_VALUE):
                    raise LevelDBError("%s: unknown entry type %d" % (name, kind))
                merge.add(ikey[:-8], tag >> 8, kind, val)
    except DecodeError as e:
        raise LevelDBError("%s: %s" % (name, e))


def read_log(path, merge):
    """Adds the writes of a write-ahead log to merge."""
    name = os.path.basename(path)
    for rec in read_log_records(_read_file(path), name):
        try:
            r = Reader(rec)
            seq = r.u64()
            count = r.u32()
            n = 0
            while not r.at_end():
                kind = r.u8()
                key = r.length_prefixed()
                if kind == TYPE_VALUE:
                    value = r.length_prefixed()
                elif kind == TYPE_DELETION:
                    value = b""
                else:
                    raise LevelDBError("%s: unknown batch entry type %d" % (name, kind))
                merge.add(key, seq + n, kind, value)
                n += 1
        except DecodeError as e:
            raise LevelDBError("%s: bad write batch: %s" % (name, e))
        if n != count:
            raise LevelDBError("%s: write batch holds %d entries, header says %d" % (name, n, count))


def read_db(path, lo=None, hi=None, as_dict=False):
    """The sorted (key, value) pairs of the database at path whose keys are
    in [lo, hi) (None: unbounded); with as_dict, a dict of them instead."""
    if not os.path.isdir(path):
        raise LevelDBError("no database at %s" % path)
    current = os.path.join(path, "CURRENT")
    manifest_name = _read_file(current).decode("latin-1").strip()
    if not re.fullmatch(r"MANIFEST-\d+", manifest_name):
        raise LevelDBError("%s: bad CURRENT file" % path)
    manifest = Manifest(_read_file(os.path.join(path, manifest_name)), manifest_name)
    merge = _Merge(lo, hi)
    for (level, number), (size, smallest, largest) in sorted(manifest.files.items()):
        if hi is not None and smallest[:-8] >= hi:
            continue
        if lo is not None and largest[:-8] < lo:
            continue
        table = os.path.join(path, "%06d.ldb" % number)
        if not os.path.exists(table):
            sst = os.path.join(path, "%06d.sst" % number)
            if os.path.exists(sst):
                table = sst
        read_table(table, merge)
    logs = []
    for entry in os.listdir(path):
        m = re.fullmatch(r"(\d+)\.log", entry)
        if m:
            number = int(m.group(1))
            if number >= manifest.log_number or (manifest.prev_log_number and number == manifest.prev_log_number):
                logs.append(number)
    for number in sorted(logs):
        read_log(os.path.join(path, "%06d.log" % number), merge)
    return merge.result_dict() if as_dict else merge.result()
