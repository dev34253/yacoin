"""The block-file check: the blocks of the block files a node was given,
compared with the block index of its data directory.

A record of a block file starts with the 4-byte marker that begins
blk00000.dat, followed by its size (4 bytes, little-endian, from 80 to
1000000) and that many bytes, the block. Anything else is skipped byte by
byte (zero padding, a truncated last record). A block of the files is
matched with the 'b' records of the block index that have block data by
its header fields: version, previous block, merkle root, time (32-bit
below version 7, 64-bit from version 7), bits and nonce.

The check finds the blocks of the files that are not in the block index
with their data, and the highest stored block above the tip; finding no
block records at all while the index holds stored blocks is a failure
too.
"""

import collections
import mmap
import os
import struct

from . import chain
from .ser import DecodeError

MIN_RECORD_SIZE = 80
MAX_RECORD_SIZE = 1000000

Result = collections.namedtuple("Result", "fields reasons")


def header_key(version, hash_prev, merkle, time, bits, nonce):
    """The header fields of a block as one bytes value."""
    return struct.pack("<i32s32sqII", version, hash_prev, merkle, time, bits, nonce)


def index_key(f):
    """header_key of a parsed 'b' record (chain.parse_block_index)."""
    return header_key(f["version"], f["hash_prev"], f["merkle"], f["time"], f["bits"], f["nonce"])


def _record_key(data, pos, size):
    """header_key of the block at data[pos:pos + size], or None when the
    record is too short for its header."""
    (version,) = struct.unpack_from("<i", data, pos)
    time_format = "<q" if version >= chain.VERSION_64_BIT_TIME else "<I"
    header_size = 4 + 32 + 32 + struct.calcsize(time_format) + 8
    if size < header_size:
        return None
    hash_prev = data[pos + 4:pos + 36]
    merkle = data[pos + 36:pos + 68]
    (time,) = struct.unpack_from(time_format, data, pos + 68)
    bits, nonce = struct.unpack_from("<II", data, pos + header_size - 8)
    return header_key(version, hash_prev, merkle, time, bits, nonce)


def _records(path, marker):
    """(offset, length, header key) of the records of one block file;
    offset and length cover the whole record (marker, size and block)."""
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            return
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            pos = 0
            while True:
                start = data.find(marker, pos)
                if start < 0 or start + 8 > size:
                    return
                (length,) = struct.unpack_from("<I", data, start + 4)
                end = start + 8 + length
                key = None
                if MIN_RECORD_SIZE <= length <= MAX_RECORD_SIZE and end <= size:
                    key = _record_key(data, start + 8, length)
                if key is None:
                    pos = start + 1
                    continue
                yield start, end - start, key
                pos = end


def block_files(directory):
    """The paths of blk00000.dat, blk00001.dat, ... in directory, up to the
    first missing number."""
    out = []
    while True:
        path = os.path.join(directory, "blk%05d.dat" % len(out))
        if not os.path.isfile(path):
            return out
        out.append(path)


def record_marker(paths):
    """The first 4 bytes of the first block file, or None when it is
    shorter."""
    if not paths:
        return None
    with open(paths[0], "rb") as f:
        marker = f.read(4)
    return marker if len(marker) == 4 else None


def records(paths):
    """(path, offset, length, header key) of the records in the block files
    paths (the first is blk00000.dat), in file order; offset and length
    cover the whole record."""
    marker = record_marker(paths)
    if marker is None:
        return
    for path in paths:
        for offset, length, key in _records(path, marker):
            yield path, offset, length, key


def scan(paths):
    """The header keys of the blocks in the block files paths (the first is
    blk00000.dat), in file order; a block stored twice is yielded twice."""
    for _path, _offset, _length, key in records(paths):
        yield key


class StoredBlocks:
    """The blocks the block index holds with their data, filled from one
    read of the index (digest.compute): heights maps the header_key of each
    such 'b' record to its height; error is why a record could not be read,
    or None (records given after it are not kept)."""

    def __init__(self):
        self.heights = {}
        self.error = None

    def add(self, f):
        """Takes a parsed 'b' record (chain.parse_block_index)."""
        if f["status"] & chain.BLOCK_HAVE_DATA:
            self.heights[index_key(f)] = f["height"]

    def add_value(self, value):
        """Takes the value of a 'b' record."""
        if self.error is not None:
            return
        try:
            f = chain.parse_block_index(value)
        except DecodeError as e:
            self.error = "block index record: %s" % e
            return
        self.add(f)


def check(paths, stored, tip_height, stop_at_height=None):
    """The block-file check of the block files paths against stored, the
    StoredBlocks of the block index whose tip is at tip_height; it takes the
    blocks it finds out of stored.heights. Result.fields: blocks (distinct blocks in the files),
    not_in_index (of these, the blocks the index does not hold with their
    data), stored_above_tip (the highest height of a block the index holds
    with data above tip_height, or None); None when the check could not be
    made. Result.reasons: why the run is incomplete, also when no block
    record was found while the index holds stored blocks. With
    stop_at_height, blocks stored above the tip are not a reason."""
    if stored.error is not None:
        return Result(None, ["block-file check: %s" % stored.error])
    remaining = stored.heights
    try:
        found = {}  # the stored blocks found in the files, moved out of remaining
        missing = set()
        for key in scan(paths):
            height = remaining.pop(key, None)
            if height is not None:
                found[key] = height
            elif key not in found:
                missing.add(key)
    except OSError as e:
        return Result(None, ["block-file check: %s" % e])
    heights = list(remaining.values()) + list(found.values())
    above = max((h for h in heights if h > tip_height), default=None)
    fields = {"blocks": len(found) + len(missing), "not_in_index": len(missing), "stored_above_tip": above}
    reasons = []
    if not found and not missing and remaining:
        reasons.append("no block records found in the block files")
    if missing:
        reasons.append("%d blocks of the block files are not in the block index" % len(missing))
    if above is not None and stop_at_height is None:
        reasons.append("stored blocks above the tip, up to height %d" % above)
    return Result(fields, reasons)
