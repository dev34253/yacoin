"""Tests of the decoders and the state digest of contrib/replay
(replaylib/ser.py, replaylib/chain.py, replaylib/digest.py).

The data directories are synthetic (replay_testutil.make_datadir): made-up
block hashes and heights, written in the node's on-disk formats.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import os
import shutil
import tempfile
import unittest

import replay_testutil as tu
from replaylib import chain, digest, ser

VARINTS = [
    (0, "00"), (1, "01"), (127, "7f"), (128, "8000"), (255, "807f"), (256, "8100"),
    (16383, "fe7f"), (16384, "ff00"), (16511, "ff7f"), (65535, "82fe7f"),
    (1 << 32, "8efefeff00"),
]

COMPACT_SIZES = [
    (0, "00"), (127, "7f"), (128, "80"), (252, "fc"), (253, "fdfd00"), (255, "fdff00"),
    (16383, "fdff3f"), (16384, "fd0040"), (65535, "fdffff"), (65536, "fe00000100"),
    (1 << 32, "ff0000000001000000"),
]


class SerTest(unittest.TestCase):
    def test_varint_vectors(self):
        for value, encoded in VARINTS:
            with self.subTest(value=value):
                self.assertEqual(ser.encode_varint(value).hex(), encoded)
                r = ser.Reader(bytes.fromhex(encoded))
                self.assertEqual(r.varint(), value)
                self.assertTrue(r.at_end())

    def test_compact_size_vectors(self):
        for value, encoded in COMPACT_SIZES:
            with self.subTest(value=value):
                self.assertEqual(ser.encode_compact_size(value).hex(), encoded)
                r = ser.Reader(bytes.fromhex(encoded))
                self.assertEqual(r.compact_size(), value)
                self.assertTrue(r.at_end())

    def test_read_past_end_is_an_error(self):
        with self.assertRaises(ser.DecodeError):
            ser.Reader(b"\x80").varint()
        with self.assertRaises(ser.DecodeError):
            ser.Reader(b"\xfd\x01").compact_size()
        with self.assertRaises(ser.DecodeError):
            ser.Reader(b"\x01\x02\x03").u32()

    def test_xor_with_8_byte_key_over_longer_value(self):
        key = bytes.fromhex("0102030405060708")
        value = bytes(range(0x10, 0x10 + 20))
        expected = bytes(v ^ key[i % 8] for i, v in enumerate(value))
        self.assertEqual(ser.xor(value, key), expected)
        self.assertEqual(expected[8], value[8] ^ 0x01)
        self.assertEqual(expected[19], value[19] ^ 0x04)
        self.assertEqual(ser.xor(expected, key), value)
        self.assertEqual(ser.xor(value, b""), value)


class BlockIndexTest(unittest.TestCase):
    def fields(self, **kw):
        f = {"height": 42, "status": tu.BLOCK_HAVE_DATA | tu.BLOCK_HAVE_UNDO, "tx": 3, "file": 2,
             "data_pos": 123456, "undo_pos": 7890, "mint": 5000000, "money_supply": 987654321,
             "flags": 0, "stake_modifier": 0x0123456789abcdef, "version": 7,
             "hash_prev": tu.fake_hash(41), "merkle": b"\x77" * 32, "time": (1 << 32) + 5,
             "bits": 0x1d00ffff, "nonce": 99, "block_hash": tu.fake_hash(42)}
        f.update(kw)
        return f

    def test_proof_of_work_record_with_64_bit_time(self):
        f = self.fields()
        rec = chain.parse_block_index(tu.block_index_bytes(f))
        for name, value in f.items():
            self.assertEqual(rec[name], value, name)
        self.assertEqual(rec["client_version"], 1110000)
        self.assertEqual(rec["prevout_stake"], b"")
        self.assertEqual(rec["stake_time"], 0)
        self.assertEqual(rec["hash_proof_of_stake"], b"")

    def test_proof_of_stake_record_with_32_bit_time(self):
        f = self.fields(flags=tu.BLOCK_PROOF_OF_STAKE | 2, version=6, time=1400000000,
                        prevout_stake=b"\x12" * 32 + b"\x03\0\0\0", stake_time=1399999999,
                        hash_proof_of_stake=b"\x34" * 32)
        raw = tu.block_index_bytes(f)
        rec = chain.parse_block_index(raw)
        for name, value in f.items():
            self.assertEqual(rec[name], value, name)
        # 64-bit time is 4 bytes longer.
        self.assertEqual(len(tu.block_index_bytes(dict(f, version=7))), len(raw) + 4)

    def test_positions_present_by_status(self):
        rec = chain.parse_block_index(tu.block_index_bytes(self.fields(status=0)))
        self.assertEqual((rec["file"], rec["data_pos"], rec["undo_pos"]), (None, None, None))
        rec = chain.parse_block_index(tu.block_index_bytes(self.fields(status=tu.BLOCK_HAVE_DATA)))
        self.assertEqual((rec["file"], rec["data_pos"], rec["undo_pos"]), (2, 123456, None))

    def test_trailing_bytes_are_an_error(self):
        with self.assertRaises(ser.DecodeError):
            chain.parse_block_index(tu.block_index_bytes(self.fields()) + b"\0")

    def test_bookkeeping_fields_do_not_change_the_row(self):
        a = chain.parse_block_index(tu.block_index_bytes(self.fields()))
        b = chain.parse_block_index(tu.block_index_bytes(self.fields(
            file=7, data_pos=1, undo_pos=2, status=tu.BLOCK_HAVE_DATA | tu.BLOCK_HAVE_UNDO | 3,
            client_version=1100000)))
        self.assertNotEqual(a, b)
        self.assertEqual(chain.chain_row(a), chain.chain_row(b))

    def test_every_other_field_changes_the_row(self):
        base = self.fields(flags=tu.BLOCK_PROOF_OF_STAKE)
        row = chain.chain_row(chain.parse_block_index(tu.block_index_bytes(base)))
        changes = {"height": 43, "tx": 4, "mint": 1, "money_supply": 1, "flags": 3,
                   "stake_modifier": 1, "prevout_stake": b"\x13" * 36, "stake_time": 1,
                   "hash_proof_of_stake": b"\x35" * 32, "version": 8, "hash_prev": b"\0" * 32,
                   "merkle": b"\0" * 32, "time": 1, "bits": 1, "nonce": 1, "block_hash": b"\1" * 32}
        for name, value in changes.items():
            with self.subTest(field=name):
                other = chain.parse_block_index(tu.block_index_bytes(dict(base, **{name: value})))
                self.assertNotEqual(chain.chain_row(other), row)


class DigestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-digest-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.n = 0

    def datadir(self, **kwargs):
        self.n += 1
        path = os.path.join(self.tmp, "d%d" % self.n)
        hashes = tu.make_datadir(path, **kwargs)
        return path, hashes

    def test_tip_rows_and_sections(self):
        coins = [(b"C" + b"\x55" * 32 + b"\x00", b"\x03\x00\x05\x00"),
                 (b"C" + b"\x66" * 32 + b"\x01", b"\x05\x01\x07\x00")]
        tokens = [(b"A\x03TOK", b"meta"), (b"B\x03TOK\x01a", b"q"), (b"C\x01a\x03TOK", b"q"),
                  (b"U" + b"\x01" * 32, b"undo"), (b"Z", b"z")]
        path, hashes = self.datadir(heights=4, coins=coins, tokens=tokens, side_blocks=2)
        d = digest.compute(path)
        self.assertEqual(d.tip_height, 4)
        self.assertEqual(d.tip_hash, hashes[4][::-1].hex())
        self.assertEqual([r.height for r in d.rows], [0, 1, 2, 3, 4])
        self.assertEqual([r.hash for r in d.rows], [h[::-1].hex() for h in hashes])
        self.assertEqual(d.rows[3].money_supply, 3000)
        self.assertEqual(d.rows[3].mint, 1000)
        self.assertEqual(d.rows[0].undo, "-")
        counts = {name: s.count for name, s in d.sections.items()}
        self.assertEqual(counts, {"chain": 5, "undo": 4, "coins": 2, "tokens": 1, "tokenindex": 2})
        self.assertEqual(len(d.overall), 64)

    def test_coins_are_deobfuscated(self):
        key = bytes.fromhex("a1b2c3d4e5f60718")
        plain = [(b"C" + b"\x55" * 32 + b"\x00", b"\x03\x00\x05\x00\x10\x20\x30\x40\x50")]
        a, _ = self.datadir(coins=plain, key=key)
        b, _ = self.datadir(coins=plain, key=b"\0" * 8)
        self.assertEqual(digest.read_coins(a), plain)
        self.assertEqual(digest.compute(a).sections["coins"], digest.compute(b).sections["coins"])

    def test_decode_coin_key(self):
        txid = bytes(range(32))
        self.assertEqual(digest.decode_coin_key(b"C" + txid + ser.encode_varint(300)),
                         (txid[::-1].hex(), 300))

    def test_same_state_gives_same_digest(self):
        a, _ = self.datadir()
        b, _ = self.datadir(rev_padding=b"\0" * 100, block_fields=lambda h: {
            "client_version": 1000000, "data_pos": 5 + h,
            "status": tu.BLOCK_HAVE_DATA | (tu.BLOCK_HAVE_UNDO | 3 if h else 0)})
        da, db = digest.compute(a), digest.compute(b)
        self.assertEqual(da.overall, db.overall)
        self.assertEqual(da.rows, db.rows)

    def test_changed_money_supply_changes_chain_section(self):
        a, _ = self.datadir()
        b, _ = self.datadir(block_fields=lambda h: {"money_supply": 7} if h == 2 else {})
        da, db = digest.compute(a), digest.compute(b)
        self.assertNotEqual(da.sections["chain"], db.sections["chain"])
        self.assertEqual(da.sections["undo"], db.sections["undo"])
        self.assertEqual([r.height for r, s in zip(da.rows, db.rows) if r != s], [2])
        self.assertNotEqual(da.overall, db.overall)

    def test_changed_undo_changes_undo_section(self):
        a, _ = self.datadir()
        b, _ = self.datadir(undo=lambda h: b"\x01\x00" + bytes([h + (h == 3)]))
        da, db = digest.compute(a), digest.compute(b)
        self.assertNotEqual(da.sections["undo"], db.sections["undo"])
        self.assertEqual(da.sections["chain"], db.sections["chain"])
        self.assertEqual([r.height for r, s in zip(da.rows, db.rows) if r != s], [3])

    def test_changed_coin_changes_only_coins_section(self):
        a, _ = self.datadir(coins=[(b"C" + b"\x55" * 32 + b"\x00", b"\x03\x00\x05\x00")])
        b, _ = self.datadir(coins=[(b"C" + b"\x55" * 32 + b"\x00", b"\x03\x00\x06\x00")])
        da, db = digest.compute(a), digest.compute(b)
        diff = [n for n in da.sections if da.sections[n] != db.sections[n]]
        self.assertEqual(diff, ["coins"])
        self.assertEqual(da.rows, db.rows)

    def test_excluded_token_records(self):
        a, _ = self.datadir(tokens=[(b"A\x01T", b"1")])
        b, _ = self.datadir(tokens=[(b"A\x01T", b"1"), (b"U" + b"\x02" * 32, b"x"), (b"M", b"y"), (b"Z", b"z")])
        self.assertEqual(digest.compute(a).overall, digest.compute(b).overall)

    def test_head_blocks_record_is_an_error(self):
        path, _ = self.datadir(head_blocks=True)
        with self.assertRaisesRegex(digest.DigestError,
                                    r"^chainstate was not closed cleanly \(head-blocks record present\); "
                                    r"the digest needs a cleanly stopped node$"):
            digest.compute(path)

    def test_bad_undo_checksum_is_an_error(self):
        path, _ = self.datadir()
        rev = os.path.join(path, "blocks", "rev00000.dat")
        with open(rev, "r+b") as f:
            f.seek(9)  # first byte of the undo content of height 1
            f.write(b"\xee")
        with self.assertRaisesRegex(digest.DigestError, "undo .*height 1"):
            digest.compute(path)

    def test_missing_rev_file_is_an_error(self):
        path, _ = self.datadir()
        os.remove(os.path.join(path, "blocks", "rev00000.dat"))
        with self.assertRaisesRegex(digest.DigestError, "rev00000.dat"):
            digest.compute(path)

    def test_missing_block_record_is_an_error(self):
        path, hashes = self.datadir(block_fields=lambda h: {"hash_prev": tu.fake_hash(99)} if h == 2 else {})
        with self.assertRaisesRegex(digest.DigestError, "no block index record"):
            digest.compute(path)

    def test_missing_database_is_an_error(self):
        path, _ = self.datadir()
        shutil.rmtree(os.path.join(path, "tokens"))
        with self.assertRaisesRegex(digest.DigestError, "tokens"):
            digest.compute(path)

    def test_running_node_is_refused(self):
        path, _ = self.datadir()
        lock = os.path.join(path, ".lock")
        open(lock, "w").close()
        import subprocess
        import sys
        holder = subprocess.Popen(
            [sys.executable, "-I", "-c",
             "import fcntl,sys,time; f=open(sys.argv[1],'r+'); fcntl.lockf(f, fcntl.LOCK_EX); "
             "print('locked', flush=True); time.sleep(60)", lock],
            stdout=subprocess.PIPE)
        try:
            self.assertEqual(holder.stdout.readline().strip(), b"locked")
            with self.assertRaisesRegex(digest.DigestError, "in use"):
                digest.compute(path)
        finally:
            holder.terminate()
            holder.wait()
            holder.stdout.close()
        digest.compute(path)


if __name__ == "__main__":
    unittest.main()
