// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_BLOCKCHAIN_H
#define BITCOIN_RPC_BLOCKCHAIN_H

#include "amount.h"
#include "uint256.h"

#include <stdint.h>

class CBlock;
class CBlockIndex;
class CCoinsView;
class CTokensDB;
class UniValue;

/**
 * Get the difficulty of the net wrt to the given block index, or the chain tip if
 * not provided.
 *
 * @return A floating point number that is a multiple of the main net minimum
 * difficulty (4295032833 hashes).
 */
double GetDifficulty(const CBlockIndex* blockindex = nullptr);

/** Callback for when block tip changed. */
void RPCNotifyBlockChange(bool ibd, const CBlockIndex *);

/** Block description to JSON */
UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false);

/** Mempool information to JSON */
UniValue mempoolInfoToJSON();

/** Mempool to JSON */
UniValue mempoolToJSON(bool fVerbose = false);

/** Block header to JSON */
UniValue blockheaderToJSON(const CBlockIndex* blockindex);

/**
 * Statistics about the on-disk chainstate (task P0-48, RPC gettxoutsetinfo).
 * Ported from Bitcoin Core 0.16 and adapted to Yacoin's Coin fields and token
 * database; the hash definitions are in GetUTXOStats() and the RPC help.
 */
struct CCoinsStats
{
    int nHeight;                  //!< height of hashBlock, -1 if not in mapBlockIndex
    uint256 hashBlock;            //!< best block of the coins view
    uint64_t nTransactions;       //!< txids with at least one unspent output
    uint64_t nTransactionOutputs; //!< unspent outputs
    uint64_t nBogoSize;           //!< Bitcoin Core's size metric (comparison only)
    uint256 hashSerialized;       //!< hash of all unspent outputs
    uint64_t nDiskSize;           //!< estimated size of the coins database
    CAmount nTotalAmount;         //!< sum of the unspent output values
    uint64_t nTokens;             //!< token metadata records
    uint256 hashTokens;           //!< hash of the token metadata records

    CCoinsStats() : nHeight(0), nTransactions(0), nTransactionOutputs(0), nBogoSize(0), nDiskSize(0), nTotalAmount(0), nTokens(0) {}
};

/**
 * Calculate statistics and hashes of the UTXO set in view and of the token
 * metadata in tokensdb (may be nullptr: no tokens). Reads only what is on
 * disk; callers that want the current tip call FlushStateToDisk() first.
 * Takes cs_main only to create the cursors. Returns false if a record cannot
 * be read.
 */
bool GetUTXOStats(CCoinsView* view, CTokensDB* tokensdb, CCoinsStats& stats);

#endif

