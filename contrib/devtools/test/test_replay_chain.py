"""Tests of the main chain of a data directory and the block files written
from it (replaylib/mainchain.py).

The data directories and block files are synthetic: made-up hashes,
heights below 200, the record marker a1 b2 c3 d4.

Run: python3 -I -m unittest discover -s contrib/devtools/test
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import replay_testutil as tu
from replaylib import blockfiles, mainchain


def records(path):
    """The records (marker, size and block) of a block file, in file order."""
    with open(path, "rb") as f:
        data = f.read()
    out = []
    pos = 0
    while pos < len(data):
        size = int.from_bytes(data[pos + 4:pos + 8], "little")
        out.append(data[pos:pos + 8 + size])
        pos += 8 + size
    return out


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-chain-test.")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.chain_dir = os.path.join(self.tmp, "chain")
        self.hashes = tu.make_datadir(self.chain_dir, heights=7, side_blocks=2, blk=True)
        self.source = os.path.join(self.chain_dir, "blocks")
        # The record of each height, as make_datadir wrote it.
        fields = tu.index_records(self.chain_dir)
        self.record = {f["height"]: tu.block_record(f) for h, f in fields.items() if h in self.hashes}

    def test_load(self):
        chain = mainchain.load(self.chain_dir)
        self.assertEqual((chain.tip_height, chain.tip_hash), (7, self.hashes[7][::-1].hex()))
        self.assertEqual(chain.hashes, [h[::-1].hex() for h in self.hashes])
        fields = tu.index_records(self.chain_dir)
        self.assertEqual(chain.keys, [blockfiles.index_key(fields[h]) for h in self.hashes])
        # The chain ends at the chainstate's best block.
        other = os.path.join(self.tmp, "other")
        tu.make_datadir(other, heights=7, blk=True, tip=4)
        self.assertEqual(mainchain.load(other).tip_height, 4)

    def test_load_refusals(self):
        with self.assertRaisesRegex(mainchain.ChainError, "no database"):
            mainchain.load(os.path.join(self.tmp, "none"))
        unclean = os.path.join(self.tmp, "unclean")
        tu.make_datadir(unclean, head_blocks=True)
        with self.assertRaisesRegex(mainchain.ChainError, "not closed cleanly"):
            mainchain.load(unclean)
        lock = os.path.join(self.chain_dir, ".lock")
        open(lock, "w").close()
        holder = subprocess.Popen(
            [sys.executable, "-I", "-c", "import fcntl, os, sys\n"
             "fd = os.open(sys.argv[1], os.O_RDWR)\n"
             "fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
             "print('locked', flush=True)\n"
             "sys.stdin.read()\n", lock],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
        try:
            self.assertEqual(holder.stdout.readline(), "locked\n")
            with self.assertRaisesRegex(mainchain.ChainError, "in use by a running node"):
                mainchain.load(self.chain_dir)
        finally:
            holder.stdin.close()
            holder.wait(timeout=30)
            holder.stdout.close()

    def test_walk_meets_a_missing_record(self):
        broken = os.path.join(self.tmp, "broken")
        tu.make_datadir(broken, heights=4, block_fields=lambda h: {"hash_prev": tu.fake_hash(99)} if h == 2 else {})
        with self.assertRaisesRegex(mainchain.ChainError,
                                    "no block index record for block %s" % tu.fake_hash(99)[::-1].hex()):
            mainchain.load(broken)

    def test_walk_meets_a_height_gap(self):
        gap = os.path.join(self.tmp, "gap")
        tu.make_datadir(gap, heights=4, block_fields=lambda h: {"height": 7} if h == 2 else {})
        with self.assertRaisesRegex(mainchain.ChainError,
                                    "block %s has height 7, expected 2" % tu.fake_hash(2)[::-1].hex()):
            mainchain.load(gap)

    def write(self, first, last, source=None, max_size=mainchain.MAX_FILE_SIZE):
        """Writes into a new directory self.out."""
        self.out = tempfile.mkdtemp(dir=self.tmp)
        chain = mainchain.load(self.chain_dir)
        return mainchain.write_block_files(blockfiles.block_files(source or self.source), chain, first, last,
                                           self.out, max_size=max_size)

    def test_heights_in_order_without_side_blocks(self):
        written = self.write(0, 5)
        self.assertEqual(written.missing, [])
        self.assertEqual(written.conflicts, [])
        self.assertEqual(written.paths, [os.path.join(self.out, "blk00000.dat")])
        self.assertEqual(records(written.paths[0]), [self.record[h] for h in range(6)])
        self.assertEqual(written.bytes, sum(len(self.record[h]) for h in range(6)))
        written = self.write(6, 7)
        self.assertEqual(records(written.paths[0]), [self.record[6], self.record[7]])

    def test_files_split_before_the_size_limit(self):
        size = len(self.record[1])
        self.assertTrue(all(len(r) == size for h, r in self.record.items() if h))
        # Three records fit below the limit; the fourth starts a new file.
        written = self.write(1, 7, max_size=3 * size + 1)
        self.assertEqual([os.path.basename(p) for p in written.paths], ["blk00000.dat", "blk00001.dat", "blk00002.dat"])
        self.assertEqual([len(records(p)) for p in written.paths], [3, 3, 1])
        self.assertEqual([r for p in written.paths for r in records(p)], [self.record[h] for h in range(1, 8)])
        # A file reaches the limit with a record: that record starts the next file.
        written = self.write(1, 7, max_size=3 * size)
        self.assertEqual([len(records(p)) for p in written.paths[:3]], [2, 2, 2])

    def test_source_out_of_order_and_with_duplicates(self):
        source = os.path.join(self.tmp, "source")
        os.makedirs(source)
        with open(os.path.join(source, "blk00000.dat"), "wb") as f:
            f.write(self.record[0] + b"\0\0junk" + self.record[5] + self.record[3] + self.record[4])
        with open(os.path.join(source, "blk00001.dat"), "wb") as f:
            f.write(self.record[2] + self.record[1] + self.record[3] + b"\0" * 40)
        written = self.write(0, 5, source=source)
        self.assertEqual((written.missing, written.conflicts), ([], []))
        self.assertEqual(records(written.paths[0]), [self.record[h] for h in range(6)])

    def test_missing_height(self):
        source = os.path.join(self.tmp, "source")
        os.makedirs(source)
        with open(os.path.join(source, "blk00000.dat"), "wb") as f:
            f.write(b"".join(self.record[h] for h in (0, 1, 3, 5)))
        written = self.write(0, 5, source=source)
        self.assertEqual(written.missing, [2, 4])
        self.assertEqual(written.paths, [])
        self.assertEqual(os.listdir(self.out), [])
        self.assertEqual(mainchain.reasons(written), ["2 heights of the chain are not in the block files, "
                                                      "the first at height 2"])

    def test_same_header_with_another_body(self):
        source = os.path.join(self.tmp, "source")
        os.makedirs(source)
        changed = self.record[3][:-1] + bytes([self.record[3][-1] ^ 1])
        with open(os.path.join(source, "blk00000.dat"), "wb") as f:
            f.write(b"".join(self.record[h] for h in range(6)) + changed)
        written = self.write(0, 5, source=source)
        self.assertEqual(written.conflicts, [3])
        self.assertEqual(written.paths, [])
        self.assertEqual(mainchain.reasons(written), [
            "the block at height 3 is in the block files more than once with different content"])

    def test_empty_range(self):
        written = self.write(8, 7)
        self.assertEqual((written.paths, written.bytes, written.missing), ([], 0, []))


if __name__ == "__main__":
    unittest.main()
