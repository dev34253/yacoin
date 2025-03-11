// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CHECKPOINT_H
#define  BITCOIN_CHECKPOINT_H

#include <map>

#ifndef BITCOIN_UTIL_H
 #include "util.h"
#endif

#ifndef BITCOIN_NET_H
 #include "net.h"
#endif
#include "validation.h"

#define CHECKPOINT_MAX_SPAN (60 * 60) // max 1 hour before latest block

#ifdef WIN32
#undef STRICT_
#undef PERMISSIVE
#undef ADVISORY
#endif

class uint256;
class CBlockIndex;

/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{
    // Returns true if block passes checkpoint checks
    bool CheckHardened(int nHeight, const uint256& hash);

    // Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate();

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const BlockMap& mapBlockIndex);

    // Returns last checkpoint timestamp
    unsigned int GetLastCheckpointTime();
}

#endif
