"""Tests of the LevelDB reader of contrib/replay (replaylib/leveldb.py).

The databases are written by replay_testutil.DBWriter in LevelDB 1.20's file
formats: tables, write-ahead logs, MANIFEST and CURRENT.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import os
import shutil
import struct
import tempfile
import unittest

import replay_testutil as tu
from replaylib import leveldb


class Crc32cTest(unittest.TestCase):
    def test_known_values(self):
        # Values of LevelDB's crc32c unit test.
        self.assertEqual(leveldb.crc32c(b"\0" * 32), 0x8a9136aa)
        self.assertEqual(leveldb.crc32c(b"\xff" * 32), 0x62a8ab43)
        self.assertEqual(leveldb.crc32c(bytes(range(32))), 0x46dd794e)
        self.assertEqual(leveldb.crc32c(b"123456789"), 0xe3069283)

    def test_mask_round_trip(self):
        crc = leveldb.crc32c(b"foo")
        self.assertNotEqual(leveldb.mask_crc(crc), crc)
        self.assertEqual(leveldb.unmask_crc(leveldb.mask_crc(crc)), crc)


class ReaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-leveldb-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = os.path.join(self.tmp, "db")

    def read(self, **kwargs):
        return leveldb.read_db(self.db, **kwargs)

    def test_tables_only(self):
        w = tu.DBWriter(self.db)
        w.add_table([(b"a", 1, b"1"), (b"b", 2, b"2")])
        w.add_table([(b"c", 3, b"3")], level=1)
        w.finish()
        self.assertEqual(self.read(), [(b"a", b"1"), (b"b", b"2"), (b"c", b"3")])

    def test_log_only(self):
        w = tu.DBWriter(self.db)
        w.add_log([(1, [(b"k2", b"v2"), (b"k1", b"v1")]), (3, [(b"k3", b"v3")])])
        w.finish()
        self.assertEqual(self.read(), [(b"k1", b"v1"), (b"k2", b"v2"), (b"k3", b"v3")])

    def test_empty_database(self):
        w = tu.DBWriter(self.db)
        w.add_log([])
        w.finish()
        self.assertEqual(self.read(), [])

    def test_newest_wins_and_deletion_hides_older_value(self):
        w = tu.DBWriter(self.db)
        w.add_table([(b"keep", 1, b"old"), (b"over", 2, b"old"), (b"gone", 3, b"old")], level=1)
        w.add_table([(b"over", 10, b"table-new"), (b"gone", 11, None)])
        w.add_log([(20, [(b"over", b"log-new"), (b"fresh", b"x")]), (22, [(b"fresh", None)])])
        w.finish()
        self.assertEqual(self.read(), [(b"keep", b"old"), (b"over", b"log-new")])
        self.assertEqual(self.read(as_dict=True), {b"keep": b"old", b"over": b"log-new"})

    def test_order_of_files_does_not_decide(self):
        # The newer value sits in the table with the lower file number.
        w = tu.DBWriter(self.db)
        w.add_table([(b"k", 9, b"new")])
        w.add_table([(b"k", 5, b"old")], level=1)
        w.finish()
        self.assertEqual(self.read(), [(b"k", b"new")])

    def test_same_key_twice_in_one_table(self):
        w = tu.DBWriter(self.db)
        w.add_table([(b"k", 4, b"old"), (b"k", 7, b"new"), (b"j", 8, None), (b"j", 6, b"x")])
        w.finish()
        self.assertEqual(self.read(), [(b"k", b"new")])

    def test_deleted_table_is_not_read(self):
        w = tu.DBWriter(self.db)
        old = w.add_table([(b"a", 1, b"stale")])
        w.add_table([(b"b", 2, b"2")], level=1)
        w.delete_table(0, old)
        w.finish()
        self.assertEqual(self.read(), [(b"b", b"2")])

    def test_old_log_is_not_read(self):
        w = tu.DBWriter(self.db)
        w.add_log([(1, [(b"a", b"in-old-log")])], set_log_number=False)
        w.add_table([(b"b", 2, b"2")])
        w.add_log([(3, [(b"c", b"3")])])
        w.finish()
        self.assertEqual(self.read(), [(b"b", b"2"), (b"c", b"3")])

    def test_several_restart_points_and_blocks(self):
        entries = [(b"key%05d" % i, i + 1, b"value%d" % i) for i in range(300)]
        w = tu.DBWriter(self.db)
        w.add_table(entries, restart_interval=4, entries_per_block=37)
        w.finish()
        self.assertEqual(self.read(), [(k, v) for k, _, v in entries])

    def test_sst_extension(self):
        w = tu.DBWriter(self.db)
        w.add_table([(b"a", 1, b"1")], ext=".sst")
        w.finish()
        self.assertEqual(self.read(), [(b"a", b"1")])

    def test_record_fragmented_over_log_blocks(self):
        big = bytes(range(256)) * 300  # 76800 bytes: three log blocks
        w = tu.DBWriter(self.db)
        w.add_log([(1, [(b"a", b"x" * 32740)]), (2, [(b"big", big)]), (3, [(b"z", b"1")])])
        w.finish()
        self.assertEqual(self.read(), [(b"a", b"x" * 32740), (b"big", big), (b"z", b"1")])

    def test_key_range(self):
        w = tu.DBWriter(self.db)
        w.add_table([(b"a%d" % i, i + 1, b"") for i in range(50)]
                    + [(b"b%d" % i, 100 + i, b"x") for i in range(50)]
                    + [(b"c%d" % i, 200 + i, b"") for i in range(50)], entries_per_block=7)
        w.add_log([(500, [(b"b9", b"log"), (b"c0", b"log"), (b"a0", b"log")])])
        w.finish()
        got = self.read(lo=b"b", hi=b"c")
        self.assertEqual(len(got), 50)
        self.assertTrue(all(k.startswith(b"b") for k, _ in got))
        self.assertEqual(dict(got)[b"b9"], b"log")
        self.assertEqual(self.read(lo=b"c", hi=None)[0], (b"c0", b"log"))

    def test_missing_current_is_an_error(self):
        os.makedirs(self.db)
        with self.assertRaisesRegex(leveldb.LevelDBError, "CURRENT"):
            self.read()

    def test_missing_table_is_an_error(self):
        w = tu.DBWriter(self.db)
        n = w.add_table([(b"a", 1, b"1")])
        w.finish()
        os.remove(os.path.join(self.db, "%06d.ldb" % n))
        with self.assertRaisesRegex(leveldb.LevelDBError, "%06d" % n):
            self.read()

    def corrupt(self, name, offset, value=None, truncate=None):
        path = os.path.join(self.db, name)
        with open(path, "r+b") as f:
            if truncate is not None:
                f.truncate(truncate)
            else:
                f.seek(offset)
                old = f.read(1)
                f.seek(offset)
                f.write(bytes([old[0] ^ 0xff]) if value is None else value)

    def test_bad_log_checksum_is_an_error(self):
        w = tu.DBWriter(self.db)
        n = w.add_log([(1, [(b"k", b"value")])])
        w.finish()
        self.corrupt("%06d.log" % n, 7 + 12 + 3)  # a byte of the batch payload
        with self.assertRaisesRegex(leveldb.LevelDBError, "checksum"):
            self.read()

    def test_truncated_log_record_is_an_error(self):
        w = tu.DBWriter(self.db)
        n = w.add_log([(1, [(b"k", b"value")]), (2, [(b"l", b"value")])])
        w.finish()
        size = os.path.getsize(os.path.join(self.db, "%06d.log" % n))
        self.corrupt("%06d.log" % n, None, truncate=size - 2)
        with self.assertRaisesRegex(leveldb.LevelDBError, "truncated"):
            self.read()

    def test_truncated_fragmented_record_is_an_error(self):
        w = tu.DBWriter(self.db)
        n = w.add_log([(1, [(b"big", b"y" * 40000)])])
        w.finish()
        self.corrupt("%06d.log" % n, None, truncate=tu.BLOCK_SIZE)
        with self.assertRaisesRegex(leveldb.LevelDBError, "truncated"):
            self.read()

    def test_truncated_log_header_is_an_error(self):
        w = tu.DBWriter(self.db)
        n = w.add_log([(1, [(b"k", b"value")])])
        w.finish()
        path = os.path.join(self.db, "%06d.log" % n)
        with open(path, "ab") as f:
            f.write(b"\x01\x02\x03")
        with self.assertRaisesRegex(leveldb.LevelDBError, "truncated"):
            self.read()

    def test_bad_table_block_checksum_is_an_error(self):
        w = tu.DBWriter(self.db)
        n = w.add_table([(b"key", 1, b"value")])
        w.finish()
        self.corrupt("%06d.ldb" % n, 2)
        with self.assertRaisesRegex(leveldb.LevelDBError, "checksum"):
            self.read()

    def test_bad_table_magic_is_an_error(self):
        w = tu.DBWriter(self.db)
        n = w.add_table([(b"key", 1, b"value")])
        w.finish()
        size = os.path.getsize(os.path.join(self.db, "%06d.ldb" % n))
        self.corrupt("%06d.ldb" % n, size - 1)
        with self.assertRaisesRegex(leveldb.LevelDBError, "magic"):
            self.read()

    def test_compressed_block_is_an_error_with_a_message(self):
        w = tu.DBWriter(self.db)
        w.add_table([(b"key", 1, b"value")], compression=1)
        w.finish()
        with self.assertRaisesRegex(leveldb.LevelDBError, "compressed block .*not supported"):
            self.read()

    def test_bad_manifest_checksum_is_an_error(self):
        w = tu.DBWriter(self.db)
        w.add_table([(b"key", 1, b"value")])
        w.finish()
        self.corrupt("MANIFEST-000001", 10)
        with self.assertRaisesRegex(leveldb.LevelDBError, "checksum"):
            self.read()

    def test_other_comparator_is_an_error(self):
        w = tu.DBWriter(self.db)
        w.edits[0] = tu.edit_bytes(comparator=b"other.Comparator")
        w.finish()
        with self.assertRaisesRegex(leveldb.LevelDBError, "comparator"):
            self.read()

    def test_batch_count_mismatch_is_an_error(self):
        os.makedirs(self.db)
        w = tu.DBWriter(self.db)
        payload = bytearray(tu.batch_bytes(1, [(b"k", b"v")]))
        payload[8:12] = struct.pack("<I", 2)
        with open(os.path.join(self.db, "000009.log"), "wb") as f:
            f.write(tu.log_bytes([bytes(payload)]))
        w.log_number = 9
        w.finish()
        with self.assertRaisesRegex(leveldb.LevelDBError, "batch"):
            self.read()


if __name__ == "__main__":
    unittest.main()
