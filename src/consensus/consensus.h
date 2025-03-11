// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdlib.h>
#include <stdint.h>
#include <map>
#include "primitives/block.h"
#include "validation.h"

enum GetMaxSize_mode
{
    MAX_BLOCK_SIZE,
    MAX_BLOCK_SIZE_GEN,
    MAX_BLOCK_SIGOPS,
};

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

static const unsigned int MAX_GENESIS_BLOCK_SIZE = 1000000;
static const size_t MIN_TRANSACTION_WEIGHT = 68; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 18; // 10 is the lower bound for the size of a serialized CTransaction

/** The currently-connected chain of blocks. */
extern CChain chainActive;
extern BlockMap mapBlockIndex;

extern ::uint64_t GetMaxSize(enum GetMaxSize_mode mode, unsigned int nHeight = 0);
extern ::int64_t GetProofOfWorkReward(unsigned int nBits=0, ::int64_t nFees=0, unsigned int nHeight=0);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
