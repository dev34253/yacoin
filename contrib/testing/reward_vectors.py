#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate or check the reward and block-size golden table (task P0-46).

Usage:
  reward_vectors.py [--check] [FILE]          compare FILE with the model
  reward_vectors.py --write [FILE]            (re)write FILE
  reward_vectors.py --write --mainnet-nbits LIST [FILE]
                                              also add one pre-fork row per
                                              nBits in LIST (one hex value
                                              per line, '#' comments) to the
                                              mainnet rows already in FILE
FILE defaults to src/test/data/reward_vectors.json. --check is the default.

The values are computed here, without CBigNum and without the node code:
- pre-fork PoW reward: the bisection of validation.cpp (GetProofOfWorkReward,
  old branch) on Python integers, with SetCompact taken from
  bignum_vectors_check.py (P0-13's independent CBigNum model);
- post-fork PoW reward: the same IEEE-754 double operations as
  validation.cpp (nMoneySupply * 0.02 / 525960, truncated), and the
  divide-first form of LoadBlockRewardAndHighestDiff;
- GetMaxSize in its three modes, and GetProofOfStakeReward.
The format is described in src/test/README.md ("Rewards and block size").
src/test/reward_tests.cpp replays the file through the node code.

Exit code 0 if the file agrees (or was written), 1 otherwise.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bignum_vectors_check import set_compact, get_compact  # noqa: E402

FORMAT = "yacoin-reward-vectors"
VERSION = "1"

COIN = 1000000
CENT = 10000
MAX_MONEY = 2000000000 * COIN
MAX_MINT_PROOF_OF_WORK = 100 * COIN
MIN_TX_FEE = CENT
MAX_GENESIS_BLOCK_SIZE = 1000000
INFLATION = 0.02                       # validation.h nInflation
BLOCKS_PER_YEAR = 365 * 24 * 60 + 6 * 60  # validation.h nNumberOfBlocksPerYear = 525960
MAINNET_EPOCH = 21000

# Target limits after the compact round trip of validation.cpp:939-940.
LIMIT_MAINNET = get_compact(False, (1 << 256) - 1 >> 20)   # 0x1e0fffff
LIMIT_LOWDIFF = get_compact(False, (1 << 256) - 1 >> 3)    # 0x201fffff


def signed_target(nbits):
    neg, mag = set_compact(nbits)
    return -mag if neg else mag   # -0 becomes 0: a product with it is 0


def prefork_reward(nbits, limit_compact):
    """validation.cpp:935-977 with nFees = 0."""
    target = signed_target(nbits)
    neg, target_limit = set_compact(limit_compact)
    assert not neg
    limit = MAX_MINT_PROOF_OF_WORK
    lower, upper = CENT, limit
    rhs = limit ** 6 * target
    while lower + CENT <= upper:
        mid = (lower + upper) // 2           # both positive
        if mid ** 6 * target_limit > rhs:
            upper = mid
        else:
            lower = mid
    subsidy = (upper // CENT) * CENT
    return min(subsidy, MAX_MINT_PROOF_OF_WORK)


def postfork_reward(supply):
    """validation.cpp:932: int64 * double / uint32, assigned to int64."""
    return int(float(supply) * INFLATION / BLOCKS_PER_YEAR)


def load_reward(supply):
    """validation.cpp:3714-3717: (int64)(supply / blocks) * 0.02, to int64."""
    return int(float(supply // BLOCKS_PER_YEAR) * INFLATION)


def max_sizes(reward):
    """consensus.cpp:20-47 after the fork: (MAX_BLOCK_SIZE, _GEN, _SIGOPS)."""
    size = reward * 1000 // MIN_TX_FEE
    return size, size // 2, max(size, MAX_GENESIS_BLOCK_SIZE) // 50


def tdiv(a, b):
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def pos_reward(coin_age):
    """pow.cpp:237-250: nCoinAge * (5 * CENT) * 33 / (365 * 33 + 8)."""
    product = coin_age * (5 * CENT) * 33
    assert -(1 << 63) <= product < (1 << 63), "int64 overflow (UB in C++)"
    return tdiv(product, 365 * 33 + 8)


# ---------------------------------------------------------------- the rows

def prefork_nbits():
    rows = []
    boundary = [
        (0x00000000, "zero (size 0)"),
        (0x00123456, "size 0, mantissa ignored"),
        (0x01000000, "zero (size 1)"),
        (0x01010000, "target 1"),
        (0x01800000, "negative zero"),
        (0x01810000, "target -1"),
        (0x02008000, "target 0x80"),
        (0x03000001, "target 1 (size 3)"),
        (0x1d80ffff, "negative target"),
        (0x1a00ffff, "difficulty ~2^24"),
        (0x1b00ffff, "difficulty ~2^16"),
        (0x1c00ffff, "difficulty ~2^8"),
        (0x1d00ffff, "bitcoin difficulty 1"),
        (0x1e0ffffe, "mainnet limit - 1"),
        (0x1e0fffff, "mainnet limit"),
        (0x1e100000, "mainnet limit + 1"),
        (0x201ffffe, "low-difficulty limit - 1"),
        (0x201fffff, "low-difficulty limit"),
        (0x20200000, "low-difficulty limit + 1"),
        (0x207fffff, "regtest-like target"),
        (0x2100ffff, "target 2^256 - 2^240"),
        (0x21010000, "target 2^256"),
        (0x2300ffff, "products of 432 bits"),
        (0xff7fffff, "largest exponent"),
    ]
    for nbits, note in boundary:
        rows.append((nbits, "boundary", note))
    for exp in range(0x01, 0x23):
        for mant in (0x008000, 0x00ffff, 0x010000, 0x7fffff):
            rows.append(((exp << 24) | mant, "sweep", ""))
    # Denser over the pre-fork mainnet range (exponents 0x1a-0x1e).
    for exp in range(0x1a, 0x1f):
        for i in range(16):
            mant = 0x008000 + i * ((0x7fffff - 0x008000) // 15)
            rows.append(((exp << 24) | mant, "sweep", ""))
    return rows


def supplies():
    rows = [
        (0, "boundary", "zero supply"),
        (1, "boundary", ""),
        (BLOCKS_PER_YEAR - 1, "boundary", ""),
        (BLOCKS_PER_YEAR, "boundary", ""),
        (26298000 - 1, "boundary", "reward 1 step - 1"),
        (26298000, "boundary", "reward 1 step: 525960 / 0.02"),
        (26298000 * 10 - 1, "boundary", "max size 1 byte - 1"),
        (26298000 * 10, "boundary", "max size 1 byte"),
        (26298000 * 10000000 - 1, "boundary", "max size 10^6 - 1"),
        (26298000 * 10000000, "boundary", "max size 10^6 (SIGOPS switch)"),
        (26298000 * 20000000, "boundary", "MAX_BLOCK_SIZE_GEN 10^6"),
        (10 ** 14, "boundary", "low-difficulty initialMoneySupply"),
        (10 ** 14 + 1, "boundary", ""),
        (1 << 53, "boundary", "2^53 (double exact limit)"),
        ((1 << 53) + 1, "boundary", "2^53 + 1 (rounded to double)"),
        (MAX_MONEY - 1, "boundary", ""),
        (MAX_MONEY, "boundary", "MAX_MONEY"),
    ]
    for k in (2, 3, 7, 49, 50, 51, 999, 3802570, 3802571, 76051410, 76051411):
        rows.append((26298000 * k - 1, "boundary", "step %d - 1" % k))
        rows.append((26298000 * k, "boundary", "step %d" % k))
    x = 1234567
    for _ in range(40):                      # deterministic spread, 10^6..2*10^15
        x = (x * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        rows.append((x % MAX_MONEY, "sweep", ""))
    return rows


def epochs(count=60, start=10 ** 14):
    """Model chain (no PoS, no fees): every epoch of 21000 blocks adds its
    reward per block; row = (epoch index, supply before the epoch)."""
    rows = []
    supply = start
    for k in range(count):
        rows.append((k, supply))
        supply += MAINNET_EPOCH * postfork_reward(supply)
    return rows


def coin_ages():
    ages = [0, 1, 2, 12052, 12053, 12054, 30, 90, 365, 366, 1000, 10 ** 6,
            10 ** 9, 2 * 10 ** 9 * 90, 5589922446578, -1, -12053,
            -5589922446578]
    return ages


# --------------------------------------------------------------- the table

def build(mainnet_nbits):
    doc = {"format": FORMAT, "version": VERSION,
           "generator": "contrib/testing/reward_vectors.py",
           "doc": "src/test/README.md",
           "target_limits": ["%08x" % LIMIT_MAINNET, "%08x" % LIMIT_LOWDIFF]}
    pre = []
    seen = set()
    on_mainnet = set(mainnet_nbits)
    for nbits, source, note in prefork_nbits() + [(n, "mainnet", "") for n in mainnet_nbits]:
        if nbits in seen:
            continue
        seen.add(nbits)
        if nbits in on_mainnet:
            source = "mainnet"   # a boundary/sweep value seen on mainnet
        pre.append(["%08x" % nbits, str(prefork_reward(nbits, LIMIT_MAINNET)),
                    str(prefork_reward(nbits, LIMIT_LOWDIFF)), source, note])
    post = []
    for supply, source, note in supplies():
        r = postfork_reward(supply)
        post.append([str(supply), str(r), str(load_reward(supply))] +
                    [str(v) for v in max_sizes(r)] + [source, note])
    ep = []
    for k, supply in epochs():
        r = postfork_reward(supply)
        ep.append([str(k), str(supply), str(r), str(load_reward(supply))] +
                  [str(v) for v in max_sizes(r)])
    pos = [[str(a), str(pos_reward(a))] for a in coin_ages()]
    doc["prefork_pow"] = pre
    doc["postfork_pow"] = post
    doc["epochs"] = ep
    doc["pos"] = pos
    return doc


def dumps(doc):
    """One row per line, so diffs show the rows that changed."""
    head = {k: v for k, v in doc.items() if not isinstance(v, list) or k == "target_limits"}
    out = ["{" + ",\n".join(json.dumps(k) + ":" + json.dumps(v) for k, v in head.items()) + ","]
    tables = [k for k, v in doc.items() if isinstance(v, list) and k != "target_limits"]
    for i, k in enumerate(tables):
        out.append(json.dumps(k) + ":[")
        rows = doc[k]
        for j, row in enumerate(rows):
            out.append(json.dumps(row) + ("," if j + 1 < len(rows) else ""))
        out.append("]" + ("," if i + 1 < len(tables) else ""))
    out.append("}")
    return "\n".join(out) + "\n"


def read_nbits_list(path):
    values = []
    with open(path, encoding="ascii") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                value = int(line, 16)
                if not 0 <= value <= 0xffffffff:
                    raise ValueError("%s: not a 32-bit nBits: %r" % (path, line))
                values.append(value)
    return values


def main(argv):
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "src", "test", "data", "reward_vectors.json")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file", nargs="?", default=default)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--mainnet-nbits", metavar="LIST")
    args = ap.parse_args(argv[1:])
    if args.write and args.check:
        ap.error("--write and --check exclude each other")
    mainnet = read_nbits_list(args.mainnet_nbits) if args.mainnet_nbits else []
    if args.write:
        if os.path.exists(args.file):
            # Keep the mainnet rows already in the file; LIST adds to them.
            with open(args.file, encoding="ascii") as f:
                mainnet = [int(r[0], 16) for r in json.load(f)["prefork_pow"] if r[3] == "mainnet"] + mainnet
        text = dumps(build(mainnet))
        with open(args.file, "w", encoding="ascii") as f:
            f.write(text)
        print("wrote %s" % args.file)
        return 0
    if args.mainnet_nbits:
        ap.error("--mainnet-nbits needs --write")
    with open(args.file, encoding="ascii") as f:
        text = f.read()
    doc = json.loads(text)
    if doc.get("format") != FORMAT or doc.get("version") != VERSION:
        print("unexpected format/version: %r %r" % (doc.get("format"), doc.get("version")))
        return 1
    mainnet = [int(r[0], 16) for r in doc["prefork_pow"] if r[3] == "mainnet"]
    expected = dumps(build(mainnet))
    if text != expected:
        exp_lines, got_lines = expected.splitlines(), text.splitlines()
        shown = 0
        for i in range(max(len(exp_lines), len(got_lines))):
            e = exp_lines[i] if i < len(exp_lines) else "<missing>"
            g = got_lines[i] if i < len(got_lines) else "<missing>"
            if e != g:
                print("line %d: file %s\n         model %s" % (i + 1, g, e))
                shown += 1
                if shown == 20:
                    break
        print("%s does not match the model" % args.file)
        return 1
    print("%s: %d pre-fork, %d post-fork, %d epoch, %d PoS rows agree" % (
        args.file, len(doc["prefork_pow"]), len(doc["postfork_pow"]),
        len(doc["epochs"]), len(doc["pos"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
