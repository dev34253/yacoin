// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include "msvc_warnings.push.h"
#endif

#include <boost/foreach.hpp>

#ifndef BITCOIN_CHECKPOINT_H
 #include "checkpoints.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb.h"
#endif
#include "chainparams.h"
#include "streams.h"
#include "reverse_iterator.h"

namespace Checkpoints
{
// YACOIN TODO CHANGE
    bool CheckHardened(int nHeight, const uint256& hash)
    {
        const MapCheckpoints& checkpoints = Params().Checkpoints().mapCheckpoints;
        MapCheckpoints::const_iterator 
            i = checkpoints.find(nHeight);

        if (i == checkpoints.end()) 
            return true;
        return (hash == i->second.first);
    }

    int GetTotalBlocksEstimate()
    {
        const MapCheckpoints& checkpoints = Params().Checkpoints().mapCheckpoints;
        return checkpoints.rbegin()->first;
    }

    unsigned int GetLastCheckpointTime()
    {
        const MapCheckpoints& checkpoints = Params().Checkpoints().mapCheckpoints;
        return checkpoints.rbegin()->second.second;
    }

    CBlockIndex* GetLastCheckpoint(const BlockMap& mapBlockIndex)
    {
        const MapCheckpoints& checkpoints = Params().Checkpoints().mapCheckpoints;
        for (const MapCheckpoints::value_type& i : reverse_iterate(checkpoints)) {
            const uint256& hash = i.second.first;
            BlockMap::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return nullptr;
    }
}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
