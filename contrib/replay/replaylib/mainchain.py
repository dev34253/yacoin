"""The main chain of a stopped node's data directory (--chain), and block
files written from it.

The main chain is the block index walked from the chainstate's best block
to genesis, as the digest walks it. Each height's header fields give the
key (blockfiles.header_key) by which the records of the source block files
are matched. write_block_files writes the main-chain blocks of a range of
heights into new block files, in height order, each record (marker, size
and block) copied unchanged from the source files.
"""

import collections
import os

from . import blockfiles, chain, leveldb
from . import digest as digest_mod
from .ser import DecodeError, hash_hex

# The size a block file of the node stays below (MAX_BLOCKFILE_SIZE).
MAX_FILE_SIZE = 0x8000000

Chain = collections.namedtuple("Chain", "datadir tip_height tip_hash keys hashes")
Written = collections.namedtuple("Written", "paths bytes missing conflicts")


class ChainError(Exception):
    pass


def load(datadir):
    """The Chain of the stopped node's data directory datadir: keys and
    hashes (display form) of the main-chain blocks by height."""
    try:
        digest_mod.check_not_running(datadir)
        tip = digest_mod.best_block(datadir)
        index = leveldb.read_db(os.path.join(datadir, "blocks", "index"), b"b", b"c", as_dict=True)
    except (digest_mod.DigestError, leveldb.LevelDBError, OSError) as e:
        raise ChainError(str(e))
    keys = []
    hashes = []
    block_hash = tip
    height = None
    while True:
        value = index.pop(b"b" + block_hash, None)
        if value is None:
            raise ChainError("no block index record for block %s" % hash_hex(block_hash))
        try:
            f = chain.parse_block_index(value)
        except DecodeError as e:
            raise ChainError("block index record of %s: %s" % (hash_hex(block_hash), e))
        if f["height"] < 0 or (height is not None and f["height"] != height - 1):
            raise ChainError("block %s has height %d, expected %s" % (
                hash_hex(block_hash), f["height"], "a height of 0 or more" if height is None else height - 1))
        height = f["height"]
        keys.append(blockfiles.index_key(f))
        hashes.append(hash_hex(block_hash))
        if height == 0:
            break
        block_hash = f["hash_prev"]
    keys.reverse()
    hashes.reverse()
    return Chain(datadir, len(keys) - 1, hashes[-1], keys, hashes)


def write_block_files(source_paths, chain_, first, last, out_dir, max_size=MAX_FILE_SIZE):
    """Writes the main-chain blocks of heights first to last of chain_ from
    the block files source_paths (the first is blk00000.dat) into
    out_dir/blk00000.dat, blk00001.dat, ..., in height order; a file ends
    before a record would bring it to max_size. A block stored more than
    once is taken once. Nothing is written when a height is missing in the
    source files or its block is there more than once with different
    content (Written.missing, Written.conflicts)."""
    wanted = {chain_.keys[h]: h for h in range(first, last + 1)}
    found = {}  # height -> (path, offset, length)
    conflicts = set()
    for path, offset, length, key in blockfiles.records(source_paths):
        height = wanted.get(key)
        if height is None:
            continue
        if height not in found:
            found[height] = (path, offset, length)
        elif height not in conflicts and _read(found[height]) != _read((path, offset, length)):
            conflicts.add(height)
    missing = [h for h in range(first, last + 1) if h not in found]
    if missing or conflicts:
        return Written([], 0, missing, sorted(conflicts))
    paths = []
    total = 0
    out = None
    size = 0
    files = {}
    try:
        for height in range(first, last + 1):
            path, offset, length = found[height]
            if out is None or (size and size + length >= max_size):
                if out is not None:
                    out.close()
                paths.append(os.path.join(out_dir, "blk%05d.dat" % len(paths)))
                out = open(paths[-1], "xb")
                size = 0
            src = files.get(path)
            if src is None:
                src = files[path] = open(path, "rb")
            src.seek(offset)
            data = src.read(length)
            if len(data) != length:
                raise OSError("%s: short read at offset %d" % (path, offset))
            out.write(data)
            size += length
            total += length
    finally:
        if out is not None:
            out.close()
        for f in files.values():
            f.close()
    return Written(paths, total, [], [])


def _read(location):
    path, offset, length = location
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(length)


def reasons(written):
    """Why the blocks could not be written; empty when they were."""
    out = []
    if written.missing:
        out.append("%d heights of the chain are not in the block files, the first at height %d" % (
            len(written.missing), written.missing[0]))
    if written.conflicts:
        out.append("the block at height %d is in the block files more than once with different content"
                   % written.conflicts[0])
    return out
