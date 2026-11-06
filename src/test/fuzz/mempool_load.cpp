// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// mempool.dat: the input is written as the file mempool.dat of the node's
// data directory, which LoadMempool() then reads, as the node does at start.
// The node is the one of InitFuzzNode (fuzz_util.h); after each run the
// mempool, its fee deltas and token entries are cleared and the file removed.

#include "test/fuzz/fuzz.h"
#include "test/fuzz/fuzz_util.h"

#include "fs.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>

FUZZ_TARGET_INIT(mempool_load, InitFuzzNode)
{
    if (buffer.size() > MAX_FUZZ_INPUT_SIZE) return;
    SetMockTime(FUZZ_NODE_TIME);
    const fs::path path = GetDataDir() / "mempool.dat";
    FILE* file = fsbridge::fopen(path, "wb");
    bool fWritten = file != nullptr && (buffer.empty() || fwrite(buffer.data(), 1, buffer.size(), file) == buffer.size());
    if (file != nullptr && fclose(file) != 0) fWritten = false;
    if (!fWritten) {
        std::cerr << "error: cannot write " << path.string() << std::endl;
        std::abort();
    }
    (void)LoadMempool();
    ResetFuzzNodeMempool();
    fs::remove(path);
}
