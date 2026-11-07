// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_BENCH_BENCH_UTIL_H
#define YACOIN_BENCH_BENCH_UTIL_H

#include "fs.h"

#include <cstdint>

/** The fixed time of the benchmarks that run node code, as mock time:
 * 2026-01-01 00:00:00 UTC */
static const int64_t BENCH_NODE_TIME = 1767225600;

/** The money supply the genesis block index carries in the node of
 * InitBenchNode(): the main network's of a recent epoch, before block
 * 1,953,000 (the value main_tests.cpp pins), in base units */
static const int64_t BENCH_MONEY_SUPPLY = 135883984037692;

/** The data directory of this process (-datadir): a new temporary directory,
 * created at the first call and removed at exit. */
const fs::path& BenchDataDir();

/**
 * Sets up what the node has after start, for the benchmarks that run node
 * code, in this process; once, later calls do nothing. The data directory of
 * BenchDataDir(); the consensus values as a unit test has them, with the
 * node's N-factor (21) and epoch and difficulty intervals (21000); the main
 * network's genesis block as the only block, its block index carrying
 * BENCH_MONEY_SUPPLY, so the reward and the size limit of a block at height 1
 * are the main network's of that epoch; in-memory block, coins and token
 * databases, the token caches, the signature and script caches, and mock time
 * BENCH_NODE_TIME.
 */
void InitBenchNode();

#endif // YACOIN_BENCH_BENCH_UTIL_H
