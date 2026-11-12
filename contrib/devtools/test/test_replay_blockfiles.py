"""Tests of the block-file check of contrib/replay (replaylib/blockfiles.py):
the scan of the block files and the comparison of their blocks with the
block index.

The block files and data directories are synthetic: the record marker
a1 b2 c3 d4, made-up hashes, heights below 200.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import os
import shutil
import struct
import tempfile
import unittest

import replay_testutil as tu
from replaylib import blockfiles

# A version-6 header (32-bit time) and a version-7 header (64-bit time).
V6 = {"version": 6, "hash_prev": tu.fake_hash(40), "merkle": tu.fake_hash(41, salt=1000), "time": 1374000000,
      "bits": 0x1e0fffff, "nonce": 0x5a17}
V7 = {"version": 7, "hash_prev": tu.fake_hash(50), "merkle": tu.fake_hash(51, salt=1000), "time": 1700003000,
      "bits": 0x1e0fffff, "nonce": 0x6b28}


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-blockfiles-test.")
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def keys(self, *paths):
        return list(blockfiles.scan(list(paths)))

    def test_records_after_junk_and_before_zero_padding(self):
        data = tu.block_record(V7) + b"junk\x00\xa1\xb2" + tu.block_record(V6) + b"\0" * 5000
        path = self.write("blk00000.dat", data)
        self.assertEqual(self.keys(path), [blockfiles.header_key(**_fields(V7)), blockfiles.header_key(**_fields(V6))])

    def test_marker_comes_from_the_first_file(self):
        other = b"\xe1\xe2\xe3\xe4"
        first = self.write("blk00000.dat", tu.block_record(V7, marker=other))
        second = self.write("blk00001.dat", tu.block_record(V6, marker=other) + tu.block_record(V7))
        self.assertEqual(self.keys(first, second), [blockfiles.header_key(**_fields(V7)),
                                                    blockfiles.header_key(**_fields(V6))])
        # A record with another marker than the one blk00000.dat starts with
        # is skipped.
        first = self.write("blk00000.dat", tu.block_record(V7))
        second = self.write("blk00001.dat", tu.block_record(V6, marker=other))
        self.assertEqual(self.keys(first, second), [blockfiles.header_key(**_fields(V7))])

    def test_scan_goes_on_after_the_end_of_a_record(self):
        # The body of a record holds what looks like a complete record of
        # another block; it is part of the first block, not a block of its
        # own.
        path = self.write("blk00000.dat", tu.block_record(V7, body=tu.block_record(V6)) + tu.block_record(V6))
        key7, key6 = blockfiles.header_key(**_fields(V7)), blockfiles.header_key(**_fields(V6))
        self.assertEqual(self.keys(path), [key7, key6])
        path = self.write("blk00000.dat", tu.block_record(V7, body=tu.block_record(V6)))
        self.assertEqual(self.keys(path), [key7])

    def test_truncated_last_record_is_skipped(self):
        record = tu.block_record(V6)
        path = self.write("blk00000.dat", tu.block_record(V7) + record[:-1])
        self.assertEqual(self.keys(path), [blockfiles.header_key(**_fields(V7))])
        path = self.write("blk00000.dat", tu.block_record(V7) + record[:6])
        self.assertEqual(self.keys(path), [blockfiles.header_key(**_fields(V7))])

    def test_sizes_outside_80_to_1000000_are_skipped(self):
        small = tu.MARKER + struct.pack("<I", 79) + tu.header_bytes(V6)[:79]
        large = tu.MARKER + struct.pack("<I", 1000001) + tu.header_bytes(V7) + b"\0" * (1000001 - 84)
        exact = tu.block_record(V6, body=b"")  # 80 bytes, the smallest record
        path = self.write("blk00000.dat", tu.block_record(V7) + small + large + exact)
        self.assertEqual(len(exact), 88)
        self.assertEqual(self.keys(path), [blockfiles.header_key(**_fields(V7)), blockfiles.header_key(**_fields(V6))])
        largest = tu.block_record(V7, body=b"\0" * (1000000 - 84))
        path = self.write("blk00000.dat", largest)
        self.assertEqual(self.keys(path), [blockfiles.header_key(**_fields(V7))])

    def test_header_fields_by_version(self):
        # The time is 32-bit below version 7 and 64-bit from version 7.
        key6 = blockfiles.header_key(**_fields(V6))
        key7 = blockfiles.header_key(**_fields(V7))
        path = self.write("blk00000.dat", tu.block_record(V6) + tu.block_record(V7))
        self.assertEqual(self.keys(path), [key6, key7])
        index = {}
        for name, f in (("v6", V6), ("v7", V7)):
            rec = dict(f, height=1, block_hash=tu.fake_hash(1, salt=len(index)))
            parsed = blockfiles.index_key(_parse(tu.block_index_bytes(rec)))
            index[name] = parsed
        self.assertEqual((index["v6"], index["v7"]), (key6, key7))
        # A version-6 header read with a 64-bit time is another header.
        as_v7 = dict(V6, version=7)
        self.assertNotEqual(blockfiles.header_key(**_fields(as_v7)), key6)

    def test_empty_or_short_first_file(self):
        empty = self.write("blk00000.dat", b"")
        self.assertEqual(self.keys(empty), [])
        short = self.write("blk00000.dat", b"\xa1\xb2")
        self.assertEqual(self.keys(short), [])


def _fields(f):
    return {k: f[k] for k in ("version", "hash_prev", "merkle", "time", "bits", "nonce")}


def _parse(value):
    from replaylib import chain
    return chain.parse_block_index(value)


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-blockfiles-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.datadir = os.path.join(self.tmp, "datadir")

    def blk(self, *names):
        return [os.path.join(self.datadir, "blocks", n) for n in names]

    def append(self, data, name="blk00000.dat"):
        with open(os.path.join(self.datadir, "blocks", name), "ab") as f:
            f.write(data)

    def test_every_block_in_the_index(self):
        tu.make_datadir(self.datadir, heights=5, side_blocks=1, blk=True)
        result = blockfiles.check(self.blk("blk00000.dat"), self.datadir, tip_height=5)
        self.assertEqual(result.fields, {"blocks": 7, "not_in_index": 0, "stored_above_tip": None})
        self.assertEqual(result.reasons, [])

    def test_block_twice_in_the_files_counted_once(self):
        tu.make_datadir(self.datadir, heights=5, blk=True)
        with open(self.blk("blk00000.dat")[0], "rb") as f:
            data = f.read()
        with open(os.path.join(self.datadir, "blocks", "blk00001.dat"), "wb") as f:
            f.write(data[len(data) // 2:] + b"\0" * 64)
        result = blockfiles.check(self.blk("blk00000.dat", "blk00001.dat"), self.datadir, tip_height=5)
        self.assertEqual(result.fields["blocks"], 6)
        self.assertEqual(result.reasons, [])

    def test_block_not_in_the_index(self):
        tu.make_datadir(self.datadir, heights=5, blk=True)
        self.append(tu.block_record(V7))
        result = blockfiles.check(self.blk("blk00000.dat"), self.datadir, tip_height=5)
        self.assertEqual(result.fields, {"blocks": 7, "not_in_index": 1, "stored_above_tip": None})
        self.assertEqual(result.reasons, ["1 blocks of the block files are not in the block index"])
        self.append(tu.block_record(V7) + tu.block_record(dict(V7, nonce=0x6b29)))
        result = blockfiles.check(self.blk("blk00000.dat"), self.datadir, tip_height=5)
        self.assertEqual(result.reasons, ["2 blocks of the block files are not in the block index"])

    def test_record_without_block_data_is_not_stored(self):
        # The block at height 4 has an index record without block data; its
        # record in the block files does not count as a block of the index.
        tu.make_datadir(self.datadir, heights=5, blk=True,
                        block_fields=lambda h: {"status": tu.BLOCK_HAVE_UNDO} if h == 4 else {})
        records = tu.index_records(self.datadir)
        f4 = records[tu.fake_hash(4)]
        self.append(tu.block_record(f4))
        result = blockfiles.check(self.blk("blk00000.dat"), self.datadir, tip_height=5)
        self.assertEqual(result.fields["not_in_index"], 1)
        self.assertEqual(result.reasons, ["1 blocks of the block files are not in the block index"])

    def test_stored_block_above_the_tip(self):
        tu.make_datadir(self.datadir, heights=7, blk=True, tip=4)
        result = blockfiles.check(self.blk("blk00000.dat"), self.datadir, tip_height=4)
        self.assertEqual(result.fields, {"blocks": 8, "not_in_index": 0, "stored_above_tip": 7})
        self.assertEqual(result.reasons, ["stored blocks above the tip, up to height 7"])
        # Not with --stop-at-height, where the blocks above it are stored but
        # not connected.
        result = blockfiles.check(self.blk("blk00000.dat"), self.datadir, tip_height=4, stop_at_height=4)
        self.assertEqual(result.fields["stored_above_tip"], 7)
        self.assertEqual(result.reasons, [])

    def test_both_reasons(self):
        tu.make_datadir(self.datadir, heights=7, blk=True, tip=6)
        self.append(tu.block_record(V6))
        result = blockfiles.check(self.blk("blk00000.dat"), self.datadir, tip_height=6)
        self.assertEqual(result.reasons, ["1 blocks of the block files are not in the block index",
                                          "stored blocks above the tip, up to height 7"])

    def test_no_block_records_in_the_files(self):
        # blk00000.dat does not start with a record, so no record is found.
        tu.make_datadir(self.datadir, heights=2, blk=True)
        path = self.blk("blk00000.dat")[0]
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(b"\0" + data)
        result = blockfiles.check([path], self.datadir, tip_height=2)
        self.assertEqual(result.fields, {"blocks": 0, "not_in_index": 0, "stored_above_tip": None})
        self.assertEqual(result.reasons, ["no block records found in the block files"])
        # Without stored blocks in the index, no block records is no reason.
        empty = os.path.join(self.tmp, "empty")
        tu.make_datadir(empty, heights=0, block_fields=lambda h: {"status": 0})
        self.assertEqual(blockfiles.check([path], empty, tip_height=0).reasons, [])

    def test_unreadable_file_or_index(self):
        tu.make_datadir(self.datadir, heights=2, blk=True)
        result = blockfiles.check(self.blk("blk00000.dat", "blk00009.dat"), self.datadir, tip_height=2)
        self.assertIsNone(result.fields)
        self.assertEqual(len(result.reasons), 1)
        self.assertTrue(result.reasons[0].startswith("block-file check: "), result.reasons)
        self.assertIn("blk00009.dat", result.reasons[0])
        shutil.rmtree(os.path.join(self.datadir, "blocks", "index"))
        result = blockfiles.check(self.blk("blk00000.dat"), self.datadir, tip_height=2)
        self.assertIsNone(result.fields)
        self.assertTrue(result.reasons[0].startswith("block-file check: "), result.reasons)


if __name__ == "__main__":
    unittest.main()
