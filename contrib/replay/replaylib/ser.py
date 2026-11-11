"""Decoders of the node's serialisation primitives (serialize.h) and of
LevelDB's varints."""

import struct


class DecodeError(Exception):
    pass


class Reader:
    """Reads values from a bytes object, front to back."""

    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise DecodeError("read of %d bytes at offset %d past the end (%d bytes)" % (n, self.pos, len(self.data)))
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def unpack(self, fmt):
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.take(size))[0]

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return self.unpack("<I")

    def i32(self):
        return self.unpack("<i")

    def u64(self):
        return self.unpack("<Q")

    def i64(self):
        return self.unpack("<q")

    def varint(self):
        """VarInt of serialize.h (MSB base-128, one added per continuation)."""
        n = 0
        while True:
            if n > (1 << 64):
                raise DecodeError("VarInt too large at offset %d" % self.pos)
            b = self.u8()
            n = (n << 7) | (b & 0x7F)
            if b & 0x80:
                n += 1
            else:
                return n

    def compact_size(self):
        b = self.u8()
        if b < 253:
            return b
        if b == 253:
            return self.unpack("<H")
        if b == 254:
            return self.unpack("<I")
        return self.unpack("<Q")

    def varint32(self):
        """LevelDB's varint (LSB base-128)."""
        n = 0
        shift = 0
        while True:
            if shift > 63:
                raise DecodeError("varint too long at offset %d" % self.pos)
            b = self.u8()
            n |= (b & 0x7F) << shift
            if not b & 0x80:
                return n
            shift += 7

    def length_prefixed(self):
        return self.take(self.varint32())

    def at_end(self):
        return self.pos == len(self.data)

    def remaining(self):
        return len(self.data) - self.pos


def encode_varint(n):
    out = bytearray()
    while True:
        out.append((n & 0x7F) | (0x80 if out else 0))
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
    return bytes(reversed(out))


def encode_compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def encode_varint32(n):
    """LevelDB's varint; also used for its 64-bit values."""
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def xor(value, key):
    """value XORed with key repeated from its first byte (CDataStream::Xor)."""
    if not key:
        return value
    reps = len(value) // len(key) + 1
    stream = (key * reps)[:len(value)]
    return (int.from_bytes(value, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(value), "little")


def hash_hex(raw):
    """Display form of a uint256 stored in internal byte order."""
    return raw[::-1].hex()
