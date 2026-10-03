#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate or check the block-header hash known answers (task P0-19).

Usage:
  header_hash_vectors.py [--check] [--max-nfactor N] [--jobs J]
                         [--reference BIN] [FILE]
  header_hash_vectors.py --write [--max-nfactor N] [--jobs J]
                         [--reference BIN] [FILE]
  header_hash_vectors.py --selftest
FILE defaults to src/test/data/header_hash_vectors.json.

The block PoW hash (primitives/block.h CalculateHash -> scrypt.cpp
scrypt_hash) is scrypt-jane built with SCRYPT_KECCAK512 and SCRYPT_CHACHA
(src/Makefile.am): password = salt = the 80/84 header bytes,
N = 2^(Nfactor+1), r = 1, p = 1, 32 bytes out. This file implements that
from the published algorithms, without the node code:
- Keccak-f[1600] (FIPS 202) with the original Keccak padding 0x01 and rate
  72 (Keccak-512, not SHA3-512); the permutation is self-tested against
  hashlib.sha3_512 (same permutation, padding 0x06);
- HMAC and PBKDF2 (one iteration) over Keccak-512;
- scrypt BlockMix/ROMix (Percival) with ChaCha20/8 (Bernstein) in place of
  Salsa20/8, as scrypt-jane defines it;
self-tested against the scrypt-jane power-on-self-test vector for
Keccak-512/ChaCha and the two genesis hashes in chainparams.cpp.

Pure Python takes about 0.8 s at N-factor 12 and doubles per step (about
7 min at 21, 2 h and 8 GiB at 25). Vectors with an N-factor above
--max-nfactor (default 12 for --check, 21 for --write) are computed with
--reference BIN, a build of the upstream scrypt-jane
(contrib/testing/scrypt_jane_refhash.c), or, without it, not checked
(reported). --check exits 1 on any mismatch; unchecked vectors are not a
failure. The format is described in src/test/README.md.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
from array import array
from concurrent.futures import ProcessPoolExecutor

FORMAT = "yacoin-header-hash-vectors"
VERSION = "1"
SERIAL_NFACTOR = 22                  # hashed one at a time (memory)
DEFAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "..", "src", "test", "data",
                            "header_hash_vectors.json")

# --------------------------------------------------------------------------
# Keccak (FIPS 202, section 3)

M64 = (1 << 64) - 1


def _round_constants():
    out, r = [], 1
    for _ in range(24):
        c = 0
        for j in range(7):
            if r & 1:
                c ^= 1 << ((1 << j) - 1)
            r <<= 1
            if r & 0x100:
                r ^= 0x171
        out.append(c)
    return out


RC = _round_constants()
ROT = [[0] * 5 for _ in range(5)]
_x, _y = 1, 0
for _t in range(24):
    ROT[_x][_y] = ((_t + 1) * (_t + 2) // 2) % 64
    _x, _y = _y, (2 * _x + 3 * _y) % 5


def keccak_f(a):
    """Keccak-f[1600]; a is 25 lanes, index x + 5*y."""
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & M64)
             for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                v, r = a[x + 5 * y], ROT[x][y]
                b[y + 5 * ((2 * x + 3 * y) % 5)] = ((v << r) | (v >> (64 - r))) & M64 if r else v
        a = [b[i] ^ ((~b[(i + 1) % 5 + 5 * (i // 5)]) & b[(i + 2) % 5 + 5 * (i // 5)])
             for i in range(25)]
        a[0] ^= RC[rnd]
    return a


def keccak(data, rate, outlen, pad):
    a = [0] * 25
    buf = bytearray(data) + bytes([pad])
    while len(buf) % rate:
        buf.append(0)
    buf[-1] |= 0x80
    for off in range(0, len(buf), rate):
        for i in range(rate // 8):
            a[i] ^= int.from_bytes(buf[off + 8 * i:off + 8 * i + 8], "little")
        a = keccak_f(a)
    return b"".join(a[i].to_bytes(8, "little") for i in range(outlen // 8))


def keccak512(m):
    return keccak(m, 72, 64, 0x01)


def hmac_keccak512(key, msg):
    if len(key) > 72:
        key = keccak512(key)
    key = key.ljust(72, b"\0")
    inner = keccak512(bytes(k ^ 0x36 for k in key) + msg)
    return keccak512(bytes(k ^ 0x5c for k in key) + inner)


def pbkdf2_once(password, salt, length):
    out, i = b"", 1
    while len(out) < length:
        out += hmac_keccak512(password, salt + struct.pack(">I", i))
        i += 1
    return out[:length]


# --------------------------------------------------------------------------
# ChaCha20/8 core with feed-forward, scrypt BlockMix and ROMix

def chacha8(x):
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = x
    m = 0xffffffff
    for _ in range(4):  # 4 double rounds = 8 rounds
        # column rounds
        x0 = (x0 + x4) & m; t = x12 ^ x0; x12 = ((t << 16) | (t >> 16)) & m
        x8 = (x8 + x12) & m; t = x4 ^ x8; x4 = ((t << 12) | (t >> 20)) & m
        x0 = (x0 + x4) & m; t = x12 ^ x0; x12 = ((t << 8) | (t >> 24)) & m
        x8 = (x8 + x12) & m; t = x4 ^ x8; x4 = ((t << 7) | (t >> 25)) & m
        x1 = (x1 + x5) & m; t = x13 ^ x1; x13 = ((t << 16) | (t >> 16)) & m
        x9 = (x9 + x13) & m; t = x5 ^ x9; x5 = ((t << 12) | (t >> 20)) & m
        x1 = (x1 + x5) & m; t = x13 ^ x1; x13 = ((t << 8) | (t >> 24)) & m
        x9 = (x9 + x13) & m; t = x5 ^ x9; x5 = ((t << 7) | (t >> 25)) & m
        x2 = (x2 + x6) & m; t = x14 ^ x2; x14 = ((t << 16) | (t >> 16)) & m
        x10 = (x10 + x14) & m; t = x6 ^ x10; x6 = ((t << 12) | (t >> 20)) & m
        x2 = (x2 + x6) & m; t = x14 ^ x2; x14 = ((t << 8) | (t >> 24)) & m
        x10 = (x10 + x14) & m; t = x6 ^ x10; x6 = ((t << 7) | (t >> 25)) & m
        x3 = (x3 + x7) & m; t = x15 ^ x3; x15 = ((t << 16) | (t >> 16)) & m
        x11 = (x11 + x15) & m; t = x7 ^ x11; x7 = ((t << 12) | (t >> 20)) & m
        x3 = (x3 + x7) & m; t = x15 ^ x3; x15 = ((t << 8) | (t >> 24)) & m
        x11 = (x11 + x15) & m; t = x7 ^ x11; x7 = ((t << 7) | (t >> 25)) & m
        # diagonal rounds
        x0 = (x0 + x5) & m; t = x15 ^ x0; x15 = ((t << 16) | (t >> 16)) & m
        x10 = (x10 + x15) & m; t = x5 ^ x10; x5 = ((t << 12) | (t >> 20)) & m
        x0 = (x0 + x5) & m; t = x15 ^ x0; x15 = ((t << 8) | (t >> 24)) & m
        x10 = (x10 + x15) & m; t = x5 ^ x10; x5 = ((t << 7) | (t >> 25)) & m
        x1 = (x1 + x6) & m; t = x12 ^ x1; x12 = ((t << 16) | (t >> 16)) & m
        x11 = (x11 + x12) & m; t = x6 ^ x11; x6 = ((t << 12) | (t >> 20)) & m
        x1 = (x1 + x6) & m; t = x12 ^ x1; x12 = ((t << 8) | (t >> 24)) & m
        x11 = (x11 + x12) & m; t = x6 ^ x11; x6 = ((t << 7) | (t >> 25)) & m
        x2 = (x2 + x7) & m; t = x13 ^ x2; x13 = ((t << 16) | (t >> 16)) & m
        x8 = (x8 + x13) & m; t = x7 ^ x8; x7 = ((t << 12) | (t >> 20)) & m
        x2 = (x2 + x7) & m; t = x13 ^ x2; x13 = ((t << 8) | (t >> 24)) & m
        x8 = (x8 + x13) & m; t = x7 ^ x8; x7 = ((t << 7) | (t >> 25)) & m
        x3 = (x3 + x4) & m; t = x14 ^ x3; x14 = ((t << 16) | (t >> 16)) & m
        x9 = (x9 + x14) & m; t = x4 ^ x9; x4 = ((t << 12) | (t >> 20)) & m
        x3 = (x3 + x4) & m; t = x14 ^ x3; x14 = ((t << 8) | (t >> 24)) & m
        x9 = (x9 + x14) & m; t = x4 ^ x9; x4 = ((t << 7) | (t >> 25)) & m
    y = (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)
    return [(a + b) & m for a, b in zip(x, y)]


def block_mix(b, r):
    """scrypt BlockMix over 2r 16-word blocks: Y_i = H(X ^ B_i), output the
    even Y_i, then the odd ones."""
    nb = 2 * r
    x = b[16 * (nb - 1):16 * nb]
    out = [None] * nb
    for i in range(nb):
        x = chacha8([u ^ v for u, v in zip(x, b[16 * i:16 * i + 16])])
        out[i // 2 + (r if i & 1 else 0)] = x
    return [w for blk in out for w in blk]


def ro_mix(chunk, n, r):
    words = 32 * r
    x = list(struct.unpack("<%dI" % words, chunk))
    v = array("I")
    for _ in range(n):
        v.extend(x)
        x = block_mix(x, r)
    for _ in range(n):
        j = x[words - 16] & (n - 1)  # Integerify: first word of the last block
        x = block_mix([u ^ w for u, w in zip(x, v[words * j:words * j + words])], r)
    return struct.pack("<%dI" % words, *x)


def scrypt_jane(password, salt, nfactor, rfactor, pfactor, length):
    n, r, p = 1 << (nfactor + 1), 1 << rfactor, 1 << pfactor
    chunk = 128 * r
    b = pbkdf2_once(password, salt, chunk * p)
    b = b"".join(ro_mix(b[chunk * i:chunk * (i + 1)], n, r) for i in range(p))
    return pbkdf2_once(password, b, length)


def header_hash(header, nfactor):
    """CalculateHash() result in uint256::GetHex() order."""
    return scrypt_jane(header, header, nfactor, 0, 0, 32)[::-1].hex()


# --------------------------------------------------------------------------
# Header model (primitives/block.h)

CHAIN_START_TIME = 1367991200        # primitives/block.cpp nChainStartTime
MAXIMUM_N_FACTOR = 25                # primitives/block.h
VERSION_64BIT_TIME = 7               # VERSION_of_block_for_yac_05x_new
# First nTime of N-factor 5, 6, ..., 25 and the cap bound (block.h:149-170,
# nChainStartTime + nSpanOfK).
NFACTOR_BOUNDS = [
    1368515488, 1368777632, 1369039776, 1369826208, 1370088352, 1372185504,
    1373234080, 1376379808, 1380574112, 1384768416, 1401545632, 1409934240,
    1435100064, 1468654496, 1502208928, 1602872224, 1636426656, 1904862112,
    2173297568, 2441733024, 3247039392, 3515474848,
]


def table_nfactor(t):
    """The v<7 N-factor of CalculateHash (fTestNet false)."""
    return min(4 + sum(1 for b in NFACTOR_BOUNDS if t >= b), MAXIMUM_N_FACTOR)


def get_nfactor(t):
    """main.cpp GetNfactor(t, false), recomputed from its formula."""
    age = t - CHAIN_START_TIME
    bits = 0
    while (age >> 1) > 3:
        bits += 1
        age >>= 1
    age &= 3
    num = bits * 170 + age * 25 - 2320
    n = -((-num) // 100) if num < 0 else num // 100   # C division truncates
    n = max(n, 0) & 0xff
    return min(max(n, 4), MAXIMUM_N_FACTOR)


def serialize(version, prev_hex, merkle_hex, time, bits, nonce):
    """Header bytes as serialised and as hashed (little-endian target)."""
    out = struct.pack("<i", version) + bytes.fromhex(prev_hex)[::-1] + bytes.fromhex(merkle_hex)[::-1]
    out += struct.pack("<q" if version >= VERSION_64BIT_TIME else "<I", time)
    return out + struct.pack("<II", bits, nonce)


def label_hash(label):
    return hashlib.sha256(label.encode()).hexdigest()


PREV = label_hash("yacoin P0-19 hashPrevBlock")
MERKLE = label_hash("yacoin P0-19 hashMerkleRoot")
BITS = 0x1e0fffff
NONCE = 0x9e3779b9
GENESIS_MERKLE = "678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f"
GENESIS_TIME = CHAIN_START_TIME + 20
# chainparams.cpp (pinned by chainparams_snapshot_tests, task P0-20)
GENESIS = [
    ("genesis_mainnet", 0x1e0fffff, 127357,
     "0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5"),
    ("genesis_lowdiff", 0x201fffff, 127358,
     "1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848"),
]


def cases():
    """Every vector without its hash, in file order."""
    out = []

    def add(name, version, time, prev=PREV, merkle=MERKLE, bits=BITS, nonce=NONCE,
            hardfork=None, expect=None):
        v = {"name": name, "version": version, "prev_block": prev, "merkle_root": merkle,
             "time": time, "bits": bits, "nonce": nonce}
        if version >= VERSION_64BIT_TIME:
            v["nfactor_at_hardfork"] = hardfork
            v["nfactor"] = hardfork
            v["getnfactor"] = None
        else:
            v["nfactor_at_hardfork"] = None
            v["nfactor"] = table_nfactor(time)
            v["getnfactor"] = get_nfactor(time)
        v["header_hex"] = serialize(version, prev, merkle, time, bits, nonce).hex()
        if expect is not None:
            v["expected"] = expect
        out.append(v)

    add("v6_time_0", 6, 0)
    for b in NFACTOR_BOUNDS:
        add("v6_bound_%d_minus_1" % b, 6, b - 1)
        add("v6_bound_%d" % b, 6, b)
    t = NFACTOR_BOUNDS[0] - 1
    for ver in (1, 3, -1):
        add("v%s_time_%d" % (str(ver).replace("-", "minus"), t), ver, t)
    for name, bits, nonce, h in GENESIS:
        add(name, 1, GENESIS_TIME, prev="00" * 32, merkle=GENESIS_MERKLE, bits=bits,
            nonce=nonce, expect=h)
    for nf in (0, 4, 21):
        add("v7_nf%d_time_1700000000" % nf, 7, 1700000000, hardfork=nf)
    for nf in (0, 4):
        add("v7_nf%d_time_64bit" % nf, 7, 0x123456789, hardfork=nf)
        add("v7_nf%d_time_%d" % (nf, t), 7, t, hardfork=nf)
        add("v7fffffff_nf%d_time_1700000000" % nf, 0x7fffffff, 1700000000, hardfork=nf)
    return out


# --------------------------------------------------------------------------

def selftest():
    errors = []
    for msg in (b"", b"abc", b"a" * 71, b"a" * 72, b"a" * 200):
        if keccak(msg, 72, 64, 0x06) != hashlib.sha3_512(msg).digest():
            errors.append("Keccak-f[1600] disagrees with hashlib.sha3_512 for %r" % msg[:8])
    if not keccak512(b"").hex().startswith("0eab42de4c3ceb9235fc91acffe746b2"):
        errors.append("Keccak-512('') wrong")
    # scrypt-jane-test-vectors.h, SCRYPT_KECCAK512 + SCRYPT_CHACHA, first
    # power-on-self-test setting ("", "", Nfactor 3, rfactor 0, pfactor 0).
    post = ("77cb70bfaed44c5bbcd3ec8a82438db37f1ffb7036324da6b7133777300c3cfb"
            "2c208f2af4474d698eae2dadba35e92fe6997af8cf7078bb0c7264958b36773d")
    if scrypt_jane(b"", b"", 3, 0, 0, 64).hex() != post:
        errors.append("scrypt-jane power-on-self-test vector wrong")
    for v in cases():
        if "expected" in v and header_hash(bytes.fromhex(v["header_hex"]), v["nfactor"]) != v["expected"]:
            errors.append("%s: hash differs from chainparams.cpp" % v["name"])
    return errors


def compute(args):
    header_hex, nfactor, reference = args
    if reference:
        res = subprocess.run([reference, str(nfactor), header_hex], check=True,
                             capture_output=True, text=True)
        return bytes.fromhex(res.stdout.strip())[::-1].hex(), "reference"
    return header_hash(bytes.fromhex(header_hex), nfactor), "python"


def run(vectors, max_nf, reference, jobs):
    """Returns [(hash, source) or None] per vector."""
    work = []
    for v in vectors:
        if v["nfactor"] <= max_nf:
            work.append((v["header_hex"], v["nfactor"], None))
        elif reference:
            work.append((v["header_hex"], v["nfactor"], reference))
        else:
            work.append(None)
    results = [None] * len(work)
    # N-factor 22 and above need 1-8 GiB each: one at a time, so parallel
    # jobs cannot exhaust the memory (three N-factor-25 runs at once were
    # killed on a 15 GiB machine).
    for i, w in enumerate(work):
        if w and w[1] >= SERIAL_NFACTOR:
            results[i] = compute(w)
    order = sorted((i for i, w in enumerate(work) if w and w[1] < SERIAL_NFACTOR),
                   key=lambda i: -work[i][1])
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        for i, r in zip(order, ex.map(compute, [work[i] for i in order])):
            results[i] = r
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    ap.add_argument("--max-nfactor", type=int)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--reference", help="upstream scrypt-jane driver (scrypt_jane_refhash.c)")
    ap.add_argument("file", nargs="?", default=DEFAULT_FILE)
    a = ap.parse_args()
    reference = os.path.abspath(a.reference) if a.reference else None

    errors = selftest()
    for e in errors:
        print("selftest: " + e)
    if errors:
        return 1
    print("selftest: ok (Keccak-f[1600], scrypt-jane POST vector, genesis hashes)")
    if a.selftest:
        return 0

    if a.write:
        max_nf = 21 if a.max_nfactor is None else a.max_nfactor
        vectors = cases()
        results = run(vectors, max_nf, reference, a.jobs)
        for v, r in zip(vectors, results):
            if r is None:
                print("cannot compute %s (N-factor %d): raise --max-nfactor or pass --reference"
                      % (v["name"], v["nfactor"]))
                return 1
            v["hash"], v["source"] = r
            v.pop("expected", None)
        doc = {
            "format": FORMAT,
            "version": VERSION,
            "comment": "Block-header hash known answers (task P0-19), written by "
                       "contrib/testing/header_hash_vectors.py; do not edit by hand. "
                       "header_hex = hashed bytes, hash = uint256::GetHex() of "
                       "scrypt-jane(Keccak-512, ChaCha20/8, N = 2^(nfactor+1), r = p = 1).",
            "vectors": vectors,
        }
        with open(a.file, "w") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        print("wrote %d vectors to %s" % (len(vectors), a.file))
        return 0

    max_nf = 12 if a.max_nfactor is None else a.max_nfactor
    with open(a.file) as f:
        doc = json.load(f)
    if doc.get("format") != FORMAT or doc.get("version") != VERSION:
        print("unexpected format or version")
        return 1
    expected = cases()
    vectors = doc["vectors"]
    bad = 0
    if len(vectors) != len(expected):
        print("file has %d vectors, the case list %d" % (len(vectors), len(expected)))
        bad += 1
    for v, e in zip(vectors, expected):
        for k, val in e.items():
            if k != "expected" and v.get(k) != val:
                print("%s: field %s is %r, expected %r" % (v.get("name"), k, v.get(k), val))
                bad += 1
    results = run(vectors, max_nf, reference, a.jobs)
    checked = {"python": 0, "reference": 0}
    unchecked = []
    for v, r in zip(vectors, results):
        if r is None:
            unchecked.append(v["name"])
            continue
        checked[r[1]] += 1
        if r[0] != v["hash"]:
            print("%s: hash %s, model (%s) %s" % (v["name"], v["hash"], r[1], r[0]))
            bad += 1
    print("checked %d vectors with the Python model, %d with the reference; "
          "%d not checked (N-factor above %d): %s"
          % (checked["python"], checked["reference"], len(unchecked), max_nf,
             ", ".join(unchecked) or "-"))
    print("FAIL" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
