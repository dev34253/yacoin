// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_FUZZ_FUZZ_UTIL_H
#define YACOIN_TEST_FUZZ_FUZZ_UTIL_H

#include "test/fuzz/fuzz.h"

#include "streams.h"

#include <cstddef>
#include <cstdint>

/** Inputs over this size are ignored */
static const size_t MAX_FUZZ_INPUT_SIZE = 1 << 20;

/** Fills ds with the input and sets its version from the first 4 bytes, as a
 * network stream; false if the input is to be ignored (over 1 MiB, or shorter
 * than the version). */
bool OpenInput(const FuzzBufferType& buffer, CDataStream& ds);

/** The fixed time of the targets that run the node: mock time */
static const int64_t FUZZ_NODE_TIME = 1700000000;

/**
 * Sets up what the node has after start, for the targets that run node code,
 * in this process; once, later calls do nothing. Data directory: a new
 * temporary directory, removed at exit. The consensus values as the node sets
 * them at start, with the test networks' N-factor; the main network's genesis
 * block as the only block, in-memory block, coins and token databases, the
 * token caches, and mock time FUZZ_NODE_TIME. No script check, scheduler or
 * network threads.
 */
void InitFuzzNode();

/** Empties the mempool of the node of InitFuzzNode: its transactions, fee
 * deltas and token entries; then runs the validation callbacks that wait. */
void ResetFuzzNodeMempool();

#endif // YACOIN_TEST_FUZZ_FUZZ_UTIL_H
