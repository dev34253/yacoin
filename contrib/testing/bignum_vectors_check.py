#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check the CBigNum golden vectors with an independent model (task P0-13).

Usage: bignum_vectors_check.py [FILE]
FILE is src/test/data/bignum_vectors.json.xz (default) or an uncompressed
.json. Every vector is recomputed with Python integers plus the OpenSSL
1.0.1k behaviour that CBigNum exposes (sign-and-magnitude values with a
possible negative zero, the MPI-based compact encoding with its exponent
byte wrap, division truncating toward zero). Nothing here uses CBigNum or
OpenSSL, so agreement shows that the file can be read and checked without
them (the format is described in src/test/README.md).

Exit code 0 if every vector agrees, 1 otherwise.
"""

import json
import lzma
import os
import re
import sys
from collections import Counter

FORMAT = "yacoin-bignum-vectors"
VERSION = "1"
MAX_SHIFT = 2048

HEX_RE = re.compile(r"-?(0|[1-9a-f][0-9a-f]*)")


class FormatError(Exception):
    pass


# A value is (neg, mag): the OpenSSL sign flag and the magnitude, so the
# negative zero (True, 0) is representable.

def parse_value(s, allow_neg_zero=False):
    if not isinstance(s, str) or not HEX_RE.fullmatch(s):
        raise FormatError("not a value: %r" % (s,))
    neg = s.startswith("-")
    mag = int(s.lstrip("-"), 16)
    if neg and mag == 0 and not allow_neg_zero:
        raise FormatError("negative zero not allowed here: %r" % (s,))
    return neg, mag


def parse_int(s, lo, hi):
    neg, mag = parse_value(s)
    n = -mag if neg else mag
    if not lo <= n <= hi:
        raise FormatError("out of range: %r" % (s,))
    return n


def fmt(neg, mag):
    return ("-" if neg else "") + format(mag, "x")


def from_int(n):
    return fmt(n < 0, abs(n))


def mpi_bytes(neg, mag):
    """BN_bn2mpi without the 4-byte length: big-endian magnitude, an extra
    0x00 if the top bit is set, the sign in the top bit."""
    nbits = mag.bit_length()
    b = bytearray(mag.to_bytes((nbits + 7) // 8, "big"))
    if nbits > 0 and nbits % 8 == 0:
        b.insert(0, 0)
    if neg:
        b[0] |= 0x80
    return b


def set_compact(n):
    size = n >> 24
    b = bytearray(size)
    for i, shift in enumerate((16, 8, 0)):
        if size > i:
            b[i] = (n >> shift) & 0xff
    if size == 0:
        return False, 0
    neg = bool(b[0] & 0x80)
    mag = int.from_bytes(bytes(b), "big")
    if neg:
        mag &= ~(1 << (mag.bit_length() - 1))   # BN_clear_bit(top bit)
    return neg, mag


def get_compact(neg, mag):
    b = mpi_bytes(neg, mag)
    size = len(b)
    c = (size << 24) & 0xffffffff      # uint32_t: the length byte wraps
    for i, shift in enumerate((16, 8, 0)):
        if size > i:
            c |= b[i] << shift
    return c


def cmp(a, b):
    (an, am), (bn, bm) = a, b
    if an != bn:
        return -1 if an else 1
    r = (am > bm) - (am < bm)
    return -r if an else r


def to_signed(v):
    neg, mag = v
    return -mag if neg else mag


def from_signed(n):
    return fmt(n < 0, abs(n))


def model(op, ins):
    """Expected output of one vector, as text."""
    if op == "int32":
        return from_int(parse_int(ins[0], -2**31, 2**31 - 1))
    if op == "int64":
        return from_int(parse_int(ins[0], -2**63, 2**63 - 1))
    if op == "uint256":
        n = parse_int(ins[0], 0, 2**256 - 1)
        return from_int(n)
    if op == "get_uint256":
        return format(parse_value(ins[0])[1] % 2**256, "x")
    if op == "get_uint64":
        return format(parse_value(ins[0])[1] % 2**64, "x")
    if op == "set_compact":
        return fmt(*set_compact(parse_int(ins[0], 0, 2**32 - 1)))
    if op == "get_compact":
        return format(get_compact(*parse_value(ins[0])), "x")
    if op in ("to_string", "get_hex"):
        neg, mag = parse_value(ins[0], allow_neg_zero=True)
        if mag == 0:
            return "0"
        return ("-" if neg else "") + (str(mag) if op == "to_string" else format(mag, "x"))
    if op == "shl":
        neg, mag = parse_value(ins[0])
        n = parse_int(ins[1], 0, MAX_SHIFT)
        return fmt(neg, mag << n)
    neg_zero_ok = op in ("mul", "cmp")
    a = parse_value(ins[0], neg_zero_ok)
    b = parse_value(ins[1], neg_zero_ok)
    if op == "add":
        return from_signed(to_signed(a) + to_signed(b))
    if op == "sub":
        return from_signed(to_signed(a) - to_signed(b))
    if op == "mul":
        if a[1] == 0 or b[1] == 0:
            return "0"                  # BN_mul returns an ordinary zero
        return fmt(a[0] != b[0], a[1] * b[1])
    if op == "div":
        if b[1] == 0:
            return "error"
        q = a[1] // b[1]                # truncation toward zero
        return "0" if q == 0 else fmt(a[0] != b[0], q)
    if op == "cmp":
        return str(cmp(a, b))
    raise FormatError("unknown op %r" % (op,))


ARITY = {"int32": 1, "int64": 1, "uint256": 1, "get_uint256": 1,
         "get_uint64": 1, "set_compact": 1, "get_compact": 1,
         "to_string": 1, "get_hex": 1, "add": 2, "sub": 2, "mul": 2,
         "div": 2, "shl": 2, "cmp": 2}


def load(path):
    opener = lzma.open if path.endswith(".xz") else open
    with opener(path, "rt", encoding="ascii") as f:
        return json.load(f)


def main(argv):
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "src", "test", "data",
                           "bignum_vectors.json.xz")
    path = argv[1] if len(argv) > 1 else default
    doc = load(path)
    if doc.get("format") != FORMAT or doc.get("version") != VERSION:
        print("unexpected format/version: %r %r" % (doc.get("format"), doc.get("version")))
        return 1
    vectors = doc["vectors"]
    if doc.get("count") != str(len(vectors)):
        print("count %r does not match %d vectors" % (doc.get("count"), len(vectors)))
        return 1
    counts = Counter()
    failures = 0
    for i, v in enumerate(vectors):
        try:
            if not isinstance(v, list) or len(v) < 3 or not all(isinstance(x, str) for x in v):
                raise FormatError("not a list of at least 3 strings")
            op, ins, expected = v[0], v[1:-1], v[-1]
            if ARITY.get(op) != len(ins):
                raise FormatError("unknown op or wrong arity")
            actual = model(op, ins)
        except FormatError as e:
            op = v[0] if isinstance(v, list) and v and isinstance(v[0], str) else "?"
            expected, actual = None, "format error: %s" % e
        counts[op] += 1
        if actual != expected:
            failures += 1
            if failures <= 20:
                print("vector %d: %s -> model %s" % (i, json.dumps(v), actual))
    print("%d vectors, %d disagree; %s" % (len(vectors), failures,
          " ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
