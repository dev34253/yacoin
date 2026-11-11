"""The block index record ('b' records of blocks/index, CDiskBlockIndex in
src/chain.h) and its chain row."""

import struct

from .ser import DecodeError, Reader

BLOCK_HAVE_DATA = 8
BLOCK_HAVE_UNDO = 16
BLOCK_PROOF_OF_STAKE = 1
VERSION_64_BIT_TIME = 7


def parse_block_index(value):
    """The fields of a 'b' record value as a dict. Positions absent by
    nStatus are None; the proof-of-stake fields are empty for other
    blocks."""
    r = Reader(value)
    f = {"client_version": r.varint(), "height": r.i32(), "status": r.varint(), "tx": r.varint()}
    status = f["status"]
    f["file"] = r.varint() if status & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO) else None
    f["data_pos"] = r.varint() if status & BLOCK_HAVE_DATA else None
    f["undo_pos"] = r.varint() if status & BLOCK_HAVE_UNDO else None
    f["mint"] = r.i64()
    f["money_supply"] = r.i64()
    f["flags"] = r.u32()
    f["stake_modifier"] = r.u64()
    if f["flags"] & BLOCK_PROOF_OF_STAKE:
        f["prevout_stake"] = r.take(36)
        f["stake_time"] = r.u32()
        f["hash_proof_of_stake"] = r.take(32)
    else:
        f["prevout_stake"] = b""
        f["stake_time"] = 0
        f["hash_proof_of_stake"] = b""
    f["version"] = r.i32()
    f["hash_prev"] = r.take(32)
    f["merkle"] = r.take(32)
    f["time"] = r.i64() if f["version"] >= VERSION_64_BIT_TIME else r.u32()
    f["bits"] = r.u32()
    f["nonce"] = r.u32()
    f["block_hash"] = r.take(32)
    if not r.at_end():
        raise DecodeError("%d bytes after the block index record" % r.remaining())
    return f


def chain_row(f):
    """The bytes of a record that enter the chain digest: every field except
    the bookkeeping ones (writer's client version, nStatus and the file
    positions nFile, nDataPos, nUndoPos)."""
    return b"".join([
        struct.pack("<iQqqIQ", f["height"], f["tx"], f["mint"], f["money_supply"], f["flags"], f["stake_modifier"]),
        struct.pack("<B", len(f["prevout_stake"])), f["prevout_stake"],
        struct.pack("<I", f["stake_time"]),
        struct.pack("<B", len(f["hash_proof_of_stake"])), f["hash_proof_of_stake"],
        struct.pack("<i", f["version"]), f["hash_prev"], f["merkle"],
        struct.pack("<qII", f["time"], f["bits"], f["nonce"]), f["block_hash"],
    ])
