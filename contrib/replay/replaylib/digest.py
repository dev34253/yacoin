"""The state digest of a stopped node's data directory.

Sections, each a record count and a SHA-256:
  chain       per height of the main chain (genesis to the tip of the
              chainstate), the block hash and the fields of its block index
              record; bookkeeping fields (file positions, status flags,
              writer version) are not part of the chain digest
  undo        per height above genesis, the SHA-256 of the block's undo
              record in the rev files (its checksum is checked)
  coins       every unspent-output record of the chainstate, key and value
              bytes as stored (the values without the chainstate's
              obfuscation), in key order
  tokens      the token records ('A') of the token database
  tokenindex  its address records ('B', 'C')
The overall digest is the SHA-256 over the sections' counts and digests.
Nothing in the data directory is changed.
"""

import collections
import errno
import fcntl
import hashlib
import os
import struct

from . import chain, leveldb
from .ser import DecodeError, Reader, hash_hex, xor

SECTION_ORDER = ("chain", "undo", "coins", "tokens", "tokenindex")
OBFUSCATE_KEY_KEY = b"\x0e\x00obfuscate_key"

Row = collections.namedtuple("Row", "height hash mint money_supply chain undo")
Section = collections.namedtuple("Section", "count sha256")
Digest = collections.namedtuple("Digest", "tip_height tip_hash rows sections overall")


class DigestError(Exception):
    pass


def check_not_running(datadir):
    """Refuses a data directory whose lock a running node holds."""
    lock = os.path.join(datadir, ".lock")
    try:
        fd = os.open(lock, os.O_RDONLY)
    except OSError:
        return
    try:
        fcntl.lockf(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.lockf(fd, fcntl.LOCK_UN)
    except OSError as e:
        if e.errno in (errno.EACCES, errno.EAGAIN):
            raise DigestError("data directory %s is in use by a running node" % datadir)
        raise
    finally:
        os.close(fd)


def _read(path, lo=None, hi=None, as_dict=False):
    try:
        return leveldb.read_db(path, lo, hi, as_dict)
    except leveldb.LevelDBError as e:
        raise DigestError(str(e))


def _chainstate(datadir):
    """The de-obfuscated coin records and the best block of the chainstate."""
    records = _read(os.path.join(datadir, "chainstate"))
    values = dict(records)
    key = b""
    if OBFUSCATE_KEY_KEY in values:
        r = Reader(values[OBFUSCATE_KEY_KEY])
        try:
            key = r.take(r.compact_size())
        except DecodeError as e:
            raise DigestError("chainstate: bad obfuscation key: %s" % e)
    if b"H" in values:
        raise DigestError("chainstate was not closed cleanly (head-blocks record present); "
                          "the digest needs a cleanly stopped node")
    best = values.get(b"B")
    if best is None:
        raise DigestError("chainstate has no best-block record")
    best = xor(best, key)
    if len(best) != 32 or best == b"\0" * 32:
        raise DigestError("chainstate: bad best-block record")
    coins = [(k, xor(v, key)) for k, v in records if k[:1] == b"C"]
    return coins, best


def read_coins(datadir):
    """The unspent-output records of the chainstate: (key, value) pairs with
    the values de-obfuscated, in key order."""
    return _chainstate(datadir)[0]


def decode_coin_key(key):
    """(txid, output index) of a coin record key."""
    r = Reader(key)
    if r.take(1) != b"C":
        raise DecodeError("not a coin key")
    txid = hash_hex(r.take(32))
    n = r.varint()
    if not r.at_end():
        raise DecodeError("bytes after the coin key")
    return txid, n


def _records_section(records):
    h = hashlib.sha256()
    for k, v in records:
        h.update(struct.pack("<I", len(k)) + k + struct.pack("<I", len(v)) + v)
    return Section(len(records), h.hexdigest())


class _UndoFiles:
    def __init__(self, blocks_dir):
        self.blocks_dir = blocks_dir
        self.files = {}

    def read(self, number, pos, prev_hash, height):
        f = self.files.get(number)
        name = "rev%05d.dat" % number
        if f is None:
            try:
                f = open(os.path.join(self.blocks_dir, name), "rb")
            except OSError as e:
                raise DigestError("cannot read %s: %s" % (name, e.strerror))
            self.files[number] = f
        if pos < 4:
            raise DigestError("bad undo position %d at height %d" % (pos, height))
        f.seek(pos - 4)
        head = f.read(4)
        if len(head) != 4:
            raise DigestError("undo record of height %d past the end of %s" % (height, name))
        (size,) = struct.unpack("<I", head)
        content = f.read(size)
        checksum = f.read(32)
        if len(content) != size or len(checksum) != 32:
            raise DigestError("undo record of height %d past the end of %s" % (height, name))
        if hashlib.sha256(hashlib.sha256(prev_hash + content).digest()).digest() != checksum:
            raise DigestError("undo record of height %d in %s: checksum mismatch" % (height, name))
        return content

    def close(self):
        for f in self.files.values():
            f.close()


# What the digest keeps of a main-chain block index record.
_Block = collections.namedtuple("_Block", "hash height row_digest hash_prev file undo_pos mint money_supply")


def _main_chain(datadir, tip):
    """The _Block entries of the main chain ending at tip, tip first. The
    records are dropped from memory as they are parsed."""
    index = _read(os.path.join(datadir, "blocks", "index"), b"b", b"c", as_dict=True)
    out = []
    block_hash = tip
    height = None
    while True:
        value = index.pop(b"b" + block_hash, None)
        if value is None:
            raise DigestError("no block index record for block %s" % hash_hex(block_hash))
        try:
            rec = chain.parse_block_index(value)
        except DecodeError as e:
            raise DigestError("block index record of %s: %s" % (hash_hex(block_hash), e))
        if rec["height"] < 0 or (height is not None and rec["height"] != height - 1):
            raise DigestError("block %s has height %d, expected %s" % (
                hash_hex(block_hash), rec["height"], "a height of 0 or more" if height is None else height - 1))
        height = rec["height"]
        out.append(_Block(block_hash, height, hashlib.sha256(block_hash + chain.chain_row(rec)).digest(),
                          rec["hash_prev"], rec["file"], rec["undo_pos"], rec["mint"], rec["money_supply"]))
        if height == 0:
            return out
        block_hash = rec["hash_prev"]


def compute(datadir):
    """The Digest of the stopped node's data directory datadir."""
    check_not_running(datadir)
    coins, tip = _chainstate(datadir)
    blocks = _main_chain(datadir, tip)
    tokens = _read(os.path.join(datadir, "tokens"))

    undo_files = _UndoFiles(os.path.join(datadir, "blocks"))
    rows = []
    chain_hash = hashlib.sha256()
    undo_hash = hashlib.sha256()
    undo_count = 0
    try:
        while blocks:
            b = blocks.pop()  # genesis first
            row_digest = b.row_digest.hex()
            chain_hash.update(b"%d %s\n" % (b.height, row_digest.encode()))
            undo = "-"
            if b.undo_pos is not None:
                content = undo_files.read(b.file, b.undo_pos, b.hash_prev, b.height)
                undo = hashlib.sha256(content).hexdigest()
                undo_hash.update(b"%d %s\n" % (b.height, undo.encode()))
                undo_count += 1
            rows.append(Row(b.height, hash_hex(b.hash), b.mint, b.money_supply, row_digest, undo))
    finally:
        undo_files.close()

    sections = collections.OrderedDict()
    sections["chain"] = Section(len(rows), chain_hash.hexdigest())
    sections["undo"] = Section(undo_count, undo_hash.hexdigest())
    sections["coins"] = _records_section(coins)
    sections["tokens"] = _records_section([kv for kv in tokens if kv[0][:1] == b"A"])
    sections["tokenindex"] = _records_section([kv for kv in tokens if kv[0][:1] in (b"B", b"C")])
    overall = hashlib.sha256()
    for name in SECTION_ORDER:
        overall.update(("%s %d %s\n" % (name, sections[name].count, sections[name].sha256)).encode())
    return Digest(rows[-1].height, rows[-1].hash, rows, sections, overall.hexdigest())
