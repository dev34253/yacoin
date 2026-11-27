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

import array
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
    key, best = _key_and_best(dict(records))
    coins = [(k, xor(v, key)) for k, v in records if k[:1] == b"C"]
    return coins, best


def best_block(datadir):
    """The best block of the chainstate, read without the coin records."""
    path = os.path.join(datadir, "chainstate")
    values = dict(_read(path, None, b"C"))
    values.update(_read(path, b"H", b"I"))
    return _key_and_best(values)[1]


def _key_and_best(values):
    """The obfuscation key and the de-obfuscated best block of the
    chainstate records values."""
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
    return key, best


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


class Rows:
    """The height rows of the main chain, genesis first, kept compactly; an
    item is a Row, a slice a list of Row. Filled tip first (add)."""

    def __init__(self):
        self._hashes = bytearray()  # block hashes, internal byte order
        self._chain = bytearray()  # chain-record digests
        self._undo = bytearray()  # undo digests, zeros where there is none
        self._has_undo = bytearray()
        self._mint = array.array("q")
        self._money_supply = array.array("q")

    def add(self, block_hash, row_digest, mint, money_supply):
        """Adds the row of the height below the lowest so far."""
        self._hashes += block_hash
        self._chain += row_digest
        self._undo += bytes(32)
        self._has_undo.append(0)
        self._mint.append(mint)
        self._money_supply.append(money_supply)

    def set_undo(self, height, undo_digest):
        i = len(self) - 1 - height
        self._undo[32 * i:32 * i + 32] = undo_digest
        self._has_undo[i] = 1

    def chain_digest(self, height):
        """The chain-record digest of the row at height."""
        i = len(self) - 1 - height
        return bytes(self._chain[32 * i:32 * i + 32])

    def block_hash(self, height):
        """The hash of the block at height, internal byte order."""
        i = len(self) - 1 - height
        return bytes(self._hashes[32 * i:32 * i + 32])

    def __len__(self):
        return len(self._mint)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[h] for h in range(*index.indices(len(self)))]
        n = len(self)
        if index < 0:
            index += n
        if not 0 <= index < n:
            raise IndexError("row index out of range")
        i = n - 1 - index
        undo = self._undo[32 * i:32 * i + 32].hex() if self._has_undo[i] else "-"
        return Row(index, hash_hex(bytes(self._hashes[32 * i:32 * i + 32])), self._mint[i], self._money_supply[i],
                   self._chain[32 * i:32 * i + 32].hex(), undo)

    def __iter__(self):
        for h in range(len(self)):
            yield self[h]

    def __eq__(self, other):
        if isinstance(other, (Rows, list)):
            return len(self) == len(other) and all(a == b for a, b in zip(self, other))
        return NotImplemented

    __hash__ = None


# Undo positions of the walk: none, or a number outside the range of
# array('q') (then kept in a dict by height).
_NO_UNDO = -1
_WIDE = -2


def _main_chain(datadir, tip, stored=None):
    """The Rows of the main chain ending at tip, and per height (as stored
    in Rows, tip first) the file number and undo position of its record and
    the previous block hash of genesis. Each record of the block index is
    parsed once; with stored (blockfiles.StoredBlocks), every record is
    given to it."""
    index = _read(os.path.join(datadir, "blocks", "index"), b"b", b"c", as_dict=True)
    rows = Rows()
    files = array.array("q")
    undo_pos = array.array("q")
    wide = {}
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
        if stored is not None:
            stored.add(rec)
        rows.add(block_hash, hashlib.sha256(block_hash + chain.chain_row(rec)).digest(), rec["mint"],
                 rec["money_supply"])
        if rec["undo_pos"] is None:
            files.append(0)
            undo_pos.append(_NO_UNDO)
        elif rec["file"] < 1 << 63 and rec["undo_pos"] < 1 << 63:
            files.append(rec["file"])
            undo_pos.append(rec["undo_pos"])
        else:
            files.append(0)
            undo_pos.append(_WIDE)
            wide[height] = (rec["file"], rec["undo_pos"])
        if height == 0:
            break
        block_hash = rec["hash_prev"]
    if stored is not None:
        for key in sorted(index):
            stored.add_value(index.pop(key))
    return rows, files, undo_pos, wide, rec["hash_prev"]


def compute(datadir, stored=None):
    """The Digest of the stopped node's data directory datadir. With stored
    (blockfiles.StoredBlocks), the same read of the block index fills it."""
    check_not_running(datadir)
    coins, tip = _chainstate(datadir)
    rows, files, undo_pos, wide, genesis_prev = _main_chain(datadir, tip, stored)
    tokens = _read(os.path.join(datadir, "tokens"))

    undo_files = _UndoFiles(os.path.join(datadir, "blocks"))
    n = len(rows)
    chain_hash = hashlib.sha256()
    undo_hash = hashlib.sha256()
    undo_count = 0
    try:
        for height in range(n):  # genesis first
            i = n - 1 - height
            chain_hash.update(b"%d %s\n" % (height, rows.chain_digest(height).hex().encode()))
            if undo_pos[i] == _NO_UNDO:
                continue
            number, pos = wide[height] if undo_pos[i] == _WIDE else (files[i], undo_pos[i])
            prev_hash = rows.block_hash(height - 1) if height else genesis_prev
            undo = hashlib.sha256(undo_files.read(number, pos, prev_hash, height)).digest()
            rows.set_undo(height, undo)
            undo_hash.update(b"%d %s\n" % (height, undo.hex().encode()))
            undo_count += 1
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
    return Digest(n - 1, hash_hex(tip), rows, sections, overall.hexdigest())
