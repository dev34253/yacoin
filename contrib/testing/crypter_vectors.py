#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate or check the wallet crypter known answers (task P0-22).

Usage:
  crypter_vectors.py [--check] [FILE]      compare FILE with the model
  crypter_vectors.py --write [FILE]        (re)write FILE
  crypter_vectors.py --selftest            only the model self-tests
  crypter_vectors.py --cross-check [FILE]  also compare every AES vector in
                                           FILE with the OpenSSL CLI and, if
                                           installed, the "cryptography"
                                           package
FILE defaults to src/test/data/crypter_vectors.json.

The wallet encryption of src/wallet/crypter.cpp, computed here without the
node code (Python 3 standard library only):
- key derivation BytesToKeySHA512AES (method 0, OpenSSL's EVP_BytesToKey
  with SHA-512 and AES-256-CBC, which v1.0.0/v1.1.0 used): D = SHA512(
  passphrase || salt), then rounds-1 times D = SHA512(D); key = D[0:32],
  IV = D[32:48] (hashlib);
- AES-256 (FIPS-197) in CBC mode with PKCS#7 padding, and the decrypt rules
  of crypto/aes.cpp CBCDecrypt as CCrypter::Decrypt sees them: empty input,
  a length that is not a multiple of 16, a bad padding byte and an empty
  result all fail;
- secp256k1 public keys (compressed and uncompressed) and their SHA256d,
  whose first 16 bytes are the IV of a crypted private key;
- the serialisation of CMasterKey (the wallet "mkey" record value).
The model self-tests AES against FIPS-197 C.3 and SP 800-38A F.2.5/F.2.6,
and secp256k1 against the generator point and 2G, before anything else.
The format is described in src/test/README.md ("Wallet crypter").
src/wallet/test/crypto_tests.cpp replays the file through the node code.

Exit code 0 if the file agrees (or was written), 1 otherwise.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

FORMAT = "yacoin-crypter-vectors"
VERSION = "1"
DEFAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "..", "src", "test", "data",
                            "crypter_vectors.json")

# ---------------------------------------------------------------- AES-256


def _xtime(a):
    a <<= 1
    return (a ^ 0x11b) if a & 0x100 else a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _make_sbox():
    sbox = [0] * 256
    for x in range(256):
        # multiplicative inverse in GF(2^8), 0 -> 0
        inv = 0
        if x:
            for y in range(1, 256):
                if _gmul(x, y) == 1:
                    inv = y
                    break
        s = inv
        for i in range(1, 5):
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xff
        sbox[x] = s ^ 0x63
    inv_sbox = [0] * 256
    for i, s in enumerate(sbox):
        inv_sbox[s] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _make_sbox()


def _expand_key(key):
    assert len(key) == 32
    words = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(words[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - 8], t)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(15)]


def _add_round_key(s, k):
    return [a ^ b for a, b in zip(s, k)]


def _shift_rows(s, inv=False):
    # state is column-major: s[r + 4c]
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            src = (c + r) % 4 if not inv else (c - r) % 4
            out[r + 4 * c] = s[r + 4 * src]
    return out


def _mix_columns(s, inv=False):
    m = (14, 11, 13, 9) if inv else (2, 3, 1, 1)
    out = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            out[r + 4 * c] = (_gmul(col[0], m[(0 - r) % 4]) ^
                              _gmul(col[1], m[(1 - r) % 4]) ^
                              _gmul(col[2], m[(2 - r) % 4]) ^
                              _gmul(col[3], m[(3 - r) % 4]))
    return out


def aes256_encrypt_block(rk, block):
    s = _add_round_key(list(block), rk[0])
    for rnd in range(1, 14):
        s = _mix_columns(_shift_rows([SBOX[b] for b in s]))
        s = _add_round_key(s, rk[rnd])
    s = _shift_rows([SBOX[b] for b in s])
    return bytes(_add_round_key(s, rk[14]))


def aes256_decrypt_block(rk, block):
    s = _add_round_key(list(block), rk[14])
    for rnd in range(13, 0, -1):
        s = [INV_SBOX[b] for b in _shift_rows(s, inv=True)]
        s = _mix_columns(_add_round_key(s, rk[rnd]), inv=True)
    s = [INV_SBOX[b] for b in _shift_rows(s, inv=True)]
    return bytes(_add_round_key(s, rk[0]))


def cbc_encrypt(key, iv, data, pad=True):
    rk = _expand_key(key)
    if pad:
        n = 16 - len(data) % 16
        data = data + bytes([n]) * n
    assert len(data) % 16 == 0
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        prev = aes256_encrypt_block(rk, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out += prev
    return out


def cbc_decrypt_raw(key, iv, data):
    assert len(data) % 16 == 0
    rk = _expand_key(key)
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(aes256_decrypt_block(rk, blk), prev))
        prev = blk
    return out


def ccrypter_decrypt(key, iv, data):
    """CCrypter::Decrypt: (ok, plaintext) as crypto/aes.cpp CBCDecrypt with
    padding decides; plaintext is "" when not ok."""
    if len(data) == 0 or len(data) % 16 != 0:
        return False, b""
    pt = cbc_decrypt_raw(key, iv, data)
    n = pt[-1]
    if n == 0 or n > 16 or pt[-n:] != bytes([n]) * n:
        return False, b""
    if len(pt) - n == 0:        # CBCDecrypt returns 0 written bytes -> false
        return False, b""
    return True, pt[:-n]


# ------------------------------------------------------------- key derive


def bytes_to_key_sha512_aes(passphrase, salt, rounds):
    d = hashlib.sha512(passphrase + salt).digest()
    for _ in range(rounds - 1):
        d = hashlib.sha512(d).digest()
    return d[:32], d[32:48]


# --------------------------------------------------------------- secp256k1

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def point_mul(k, pt=G):
    r = None
    while k:
        if k & 1:
            r = _point_add(r, pt)
        pt = _point_add(pt, pt)
        k >>= 1
    return r


def pubkey(secret, compressed):
    k = int.from_bytes(secret, "big")
    assert 0 < k < N
    x, y = point_mul(k)
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# --------------------------------------------------------------- self-test


def selftest():
    # FIPS-197 appendix C.3 (AES-256)
    key = bytes(range(32))
    rk = _expand_key(key)
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert aes256_encrypt_block(rk, pt) == ct, "FIPS-197 C.3 encrypt"
    assert aes256_decrypt_block(rk, ct) == pt, "FIPS-197 C.3 decrypt"
    # NIST SP 800-38A F.2.5 / F.2.6 (CBC-AES256, no padding)
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                       "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    ct = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
                       "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b")
    assert cbc_encrypt(key, iv, pt, pad=False) == ct, "SP 800-38A F.2.5"
    assert cbc_decrypt_raw(key, iv, ct) == pt, "SP 800-38A F.2.6"
    # secp256k1: 1G, 2G (SEC 2 / well-known), nG = infinity
    assert pubkey((1).to_bytes(32, "big"), True).hex() == \
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert pubkey((2).to_bytes(32, "big"), True).hex() == \
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    assert point_mul(N) is None
    # the one fixed KDF answer the OpenSSL oracle test already had
    k, i = bytes_to_key_sha512_aes(b"test", bytes.fromhex("0000deadbeef0000"), 25000)
    assert k.hex() == "fc7aba077ad5f4c3a0988d8daa4810d0d4a0e3bcb53af662998898f33df0556a"
    assert i.hex() == "cf2f2691526dd1aa220896fb8bf7c369"


# ------------------------------------------------------------------ vectors


def _tag(label):
    return hashlib.sha256(b"yacoin P0-22 " + label.encode()).digest()


def compact_size(n):
    assert n < 253
    return bytes([n])


def ser_vector(b):
    return compact_size(len(b)) + b


def build():
    doc = {"format": FORMAT, "version": VERSION}

    kdf = []
    for comment, pw, salt, rounds in [
        ("1 round", b"test", "0000deadbeef0000", 1),
        ("2 rounds", b"test", "0000deadbeef0000", 2),
        ("3 rounds", b"test", "0000deadbeef0000", 3),
        ("1000 rounds", b"test", "0000deadbeef0000", 1000),
        ("25000 rounds (default nDeriveIterations), the oracle test's answer",
         b"test", "0000deadbeef0000", 25000),
        ("123457 rounds, other salt", b"passphrase", "0102030405060708", 123457),
        ("empty passphrase", b"", "0000deadbeef0000", 25000),
        ("UTF-8 passphrase", "Gr\u00fc\u00dfe \u20ac".encode(), "ffffffffffffffff", 1000),
        ("embedded NUL byte (the whole SecureString is hashed)", b"a\x00b", "0000000000000000", 7),
        ("100-byte passphrase", bytes(range(32, 132)), "8899aabbccddeeff", 500),
        ("empty salt (BytesToKeySHA512AES only; SetKeyFromPassphrase needs 8 bytes)",
         b"test", "", 25000),
    ]:
        key, iv = bytes_to_key_sha512_aes(pw, bytes.fromhex(salt), rounds)
        kdf.append({"comment": comment, "passphrase": pw.hex(), "salt": salt,
                    "rounds": rounds, "key": key.hex(), "iv": iv.hex()})
    doc["kdf"] = kdf

    key = _tag("aes key")
    iv = _tag("aes iv")[:16]
    aes = {"key": key.hex(), "iv": iv.hex(), "vectors": []}
    for n in (0, 1, 15, 16, 17, 31, 32, 33, 48):
        pt = _tag("plaintext")[:n] if n <= 32 else (_tag("plaintext") + _tag("plaintext 2"))[:n]
        ct = cbc_encrypt(key, iv, pt)
        aes["vectors"].append({"plaintext": pt.hex(), "ciphertext": ct.hex(),
                               "padding": 16 - n % 16})
    doc["aes_cbc"] = aes

    # CCrypter::Decrypt outcomes with the aes_cbc key/IV (unless given)
    base_pt = (_tag("plaintext") + _tag("plaintext 2"))[:40]
    base_ct = cbc_encrypt(key, iv, base_pt)          # 48 bytes, 3 blocks
    wrong_key = _tag("wrong key")
    dec = []

    def add(comment, ct, k=key, v=iv):
        ok, pt = ccrypter_decrypt(k, v, ct)
        e = {"comment": comment, "ciphertext": ct.hex(), "ok": ok, "plaintext": pt.hex()}
        if k != key:
            e["key"] = k.hex()
        if v != iv:
            e["iv"] = v.hex()
        dec.append(e)

    def flip(b, i, bit=1):
        return b[:i] + bytes([b[i] ^ bit]) + b[i + 1:]

    add("valid, 40 bytes plaintext", base_ct)
    add("damaged: last byte flipped (padding check fails)", flip(base_ct, 47))
    add("damaged: first byte flipped (block 1 garbled, block 2 one bit flipped, padding intact)",
        flip(base_ct, 0))
    add("wrong key", base_ct, k=wrong_key)
    add("wrong IV (only the first block changes)", base_ct, v=_tag("wrong iv")[:16])
    add("length not a multiple of 16 (47 bytes)", base_ct[:47])
    add("truncated to the first two blocks (padding check on block 2)", base_ct[:32])
    add("empty", b"")
    blk = _tag("block")[:15]
    add("padding byte 0", cbc_encrypt(key, iv, blk + b"\x00", pad=False))
    add("padding byte 17", cbc_encrypt(key, iv, blk + b"\x11", pad=False))
    add("inconsistent padding (..01 02)", cbc_encrypt(key, iv, blk[:14] + b"\x01\x02", pad=False))
    add("only a padding block (CCrypter fails, OpenSSL would return empty)",
        cbc_encrypt(key, iv, b""))
    add("data block and a full padding block", cbc_encrypt(key, iv, _tag("block")[:16]))
    doc["decrypt"] = dec

    # master key (CWallet::EncryptWallet / Unlock)
    mk = _tag("master key")
    salt = bytes.fromhex("0000deadbeef0000")
    rounds = 25000
    pw = b"correct horse battery staple"
    wrong_pw = b"correct horse battery stapler"
    k, v = bytes_to_key_sha512_aes(pw, salt, rounds)
    crypted = cbc_encrypt(k, v, mk)
    wk, wv = bytes_to_key_sha512_aes(wrong_pw, salt, rounds)
    wrong_ok, _ = ccrypter_decrypt(wk, wv, crypted)
    serialized = (ser_vector(crypted) + ser_vector(salt) + (0).to_bytes(4, "little") +
                  rounds.to_bytes(4, "little") + ser_vector(b""))
    doc["masterkey"] = {
        "passphrase": pw.hex(), "salt": salt.hex(), "rounds": rounds,
        "derivation_method": 0, "master_key": mk.hex(), "crypted_key": crypted.hex(),
        "serialized": serialized.hex(), "wrong_passphrase": wrong_pw.hex(),
        "wrong_passphrase_ok": wrong_ok,
    }

    # private keys crypted under the master key, IV = SHA256d(pubkey)[0:16]
    keys = []
    for label, compressed in (("key 1", True), ("key 2", False), ("key 3", True)):
        secret = _tag(label)
        pk = pubkey(secret, compressed)
        h = sha256d(pk)
        keys.append({"secret": secret.hex(), "compressed": compressed, "pubkey": pk.hex(),
                     "pubkey_hash": h.hex(), "crypted_secret": cbc_encrypt(mk, h[:16], secret).hex()})
    doc["keys"] = keys
    # a 31-byte secret crypted for key 1 (DecryptKey rejects the length)
    h = bytes.fromhex(keys[0]["pubkey_hash"])
    doc["short_secret"] = {"pubkey": keys[0]["pubkey"],
                           "crypted_secret": cbc_encrypt(mk, h[:16], _tag("key 1")[:31]).hex()}
    return doc


def render(doc):
    return json.dumps(doc, indent=1, ensure_ascii=True) + "\n"


# -------------------------------------------------------------- cross-check


def cross_check(doc):
    """Compare every AES vector with the OpenSSL CLI and, if available, the
    cryptography package. Returns the number of disagreements."""
    bad = 0
    openssl = shutil.which("openssl")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        Cipher = None
    if not openssl and Cipher is None:
        print("cross-check: neither openssl nor cryptography available")
        return 1

    def other(key, iv, data, encrypt, pad):
        res = {}
        if openssl:
            cmd = [openssl, "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()]
            if not encrypt:
                cmd.append("-d")
            if not pad:
                cmd.append("-nopad")
            p = subprocess.run(cmd, input=data, capture_output=True)
            res["openssl"] = p.stdout if p.returncode == 0 else None
        if Cipher is not None and not pad:     # the raw cipher has no PKCS#7
            c = Cipher(algorithms.AES(key), modes.CBC(iv))
            op = c.encryptor() if encrypt else c.decryptor()
            res["cryptography"] = op.update(data) + op.finalize()
        return res

    aes = doc["aes_cbc"]
    key, iv = bytes.fromhex(aes["key"]), bytes.fromhex(aes["iv"])
    n = 0
    for v in aes["vectors"]:
        pt, ct = bytes.fromhex(v["plaintext"]), bytes.fromhex(v["ciphertext"])
        for name, out in other(key, iv, pt, True, True).items():
            n += 1
            if out != ct:
                print("cross-check %s encrypt %s: %s" % (name, v["plaintext"], out))
                bad += 1
        padded = pt + bytes([v["padding"]]) * v["padding"]
        for name, out in other(key, iv, padded, True, False).items():
            n += 1
            if out != ct:
                print("cross-check %s raw encrypt %s: %s" % (name, v["plaintext"], out))
                bad += 1
    for v in doc["decrypt"]:
        k = bytes.fromhex(v.get("key", aes["key"]))
        i = bytes.fromhex(v.get("iv", aes["iv"]))
        ct = bytes.fromhex(v["ciphertext"])
        if not ct or len(ct) % 16:
            continue
        for name, raw in other(k, i, ct, False, False).items():
            n += 1
            if raw != cbc_decrypt_raw(k, i, ct):
                print("cross-check %s raw decrypt %s" % (name, v["comment"]))
                bad += 1
    mkd = doc["masterkey"]
    mk_key, mk_iv = bytes_to_key_sha512_aes(bytes.fromhex(mkd["passphrase"]),
                                            bytes.fromhex(mkd["salt"]), mkd["rounds"])
    checks = [(mk_key, mk_iv, bytes.fromhex(mkd["master_key"]), bytes.fromhex(mkd["crypted_key"]))]
    mk = bytes.fromhex(mkd["master_key"])
    for kv in doc["keys"]:
        checks.append((mk, bytes.fromhex(kv["pubkey_hash"])[:16], bytes.fromhex(kv["secret"]),
                       bytes.fromhex(kv["crypted_secret"])))
    for k, i, pt, ct in checks:
        if openssl:
            n += 1
            if other(k, i, pt, True, True)["openssl"] != ct:
                print("cross-check openssl key/master-key vector %s" % ct.hex())
                bad += 1
    print("cross-check: %d comparisons (%s), %d disagree" %
          (n, ", ".join(x for x, y in (("openssl", openssl), ("cryptography", Cipher)) if y), bad))
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="compare FILE with the model (default)")
    g.add_argument("--write", action="store_true", help="(re)write FILE")
    g.add_argument("--selftest", action="store_true", help="only the model self-tests")
    ap.add_argument("--cross-check", action="store_true",
                    help="also compare the AES vectors with OpenSSL CLI / cryptography")
    ap.add_argument("file", nargs="?", default=DEFAULT_FILE)
    a = ap.parse_args()

    selftest()
    if a.selftest:
        print("selftest: ok")
        return 0
    text = render(build())
    if a.write:
        with open(a.file, "w", encoding="ascii") as f:
            f.write(text)
        print("wrote %s" % a.file)
        doc = json.loads(text)
    else:
        with open(a.file, encoding="ascii") as f:
            have = f.read()
        doc = json.loads(have)
        if have != text:
            for i, (x, y) in enumerate(zip(have.splitlines(), text.splitlines())):
                if x != y:
                    print("line %d: file %s\n         model %s" % (i + 1, x, y))
                    break
            print("crypter vectors: file differs from the model")
            return 1
    if a.cross_check and cross_check(doc):
        return 1
    print("crypter vectors: %d kdf, %d aes, %d decrypt, %d keys agree" %
          (len(doc["kdf"]), len(doc["aes_cbc"]["vectors"]), len(doc["decrypt"]), len(doc["keys"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
