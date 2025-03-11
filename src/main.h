// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include <algorithm>
#include <list>
#include <map>
#include <boost/filesystem.hpp>

#include "timestamps.h"
#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "script/script.h"
#include "scrypt.h"

#include "primitives/transaction.h"
#include "primitives/block.h"
#include "amount.h"
#include "policy/fees.h"

#include "consensus/consensus.h"
#include "chainparams.h"
#include "txmempool.h"
#include "arith_uint256.h"

class CWallet;
class CBlock;
class CBlockIndex;
class CKeyItem;
class CReserveKey;
class COutPoint;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;

//
// END OF FUNCTIONS USED FOR TOKEN MANAGEMENT SYSTEM
//

//
// Global state
//
extern int 
    nStatisticsNumberOfBlocks2000,
    nStatisticsNumberOfBlocks1000,
    nStatisticsNumberOfBlocks200,
    nStatisticsNumberOfBlocks100,
    nStatisticsNumberOfBlocks;

extern ::int64_t nUpTimeStart;

// PoS constants
extern const unsigned int nStakeMaxAge, nOnedayOfAverageBlocks;
extern const unsigned int nStakeMinAge, nModifierInterval;

static const unsigned int MAX_ORPHAN_TRANSACTIONS = 10000;
static const ::int64_t MAX_MINT_PROOF_OF_WORK = 100 * COIN;
static const ::int64_t MAX_MINT_PROOF_OF_STAKE = 1 * COIN;
static const ::int64_t MIN_TXOUT_AMOUNT = CENT/100;

// Maximum number of script-checking threads allowed
static const int MAX_SCRIPTCHECK_THREADS = 16;
extern int nConsecutiveStakeSwitchHeight;  // see timesamps.h = 420000;
const ::int64_t nMaxClockDrift = nTwoHoursInSeconds;

inline ::int64_t PastDrift(::int64_t nTime)   
    { return nTime - nMaxClockDrift; } // up to 2 hours from the past
inline ::int64_t FutureDrift(::int64_t nTime) 
    { return nTime + nMaxClockDrift; } // up to 2 hours from the future

extern CScript COINBASE_FLAGS;
//extern unsigned int nStakeMinAge;
extern int nCoinbaseMaturity;
extern ::uint64_t nLastBlockTx;
extern ::uint64_t nLastBlockSize;
extern ::uint32_t nLastCoinStakeSearchInterval;
extern const std::string strMessageMagic;
extern unsigned char pchMessageStart[4];

// Settings
extern ::int64_t nTransactionFee;
extern int nScriptCheckThreads;
extern const uint256 entropyStore[38];

// Minimum disk space required - used in CheckDiskSpace()
static const ::uint64_t nMinDiskSpace = 52428800;

class CReserveKey;
class CScriptCheck;
class CBlockLocator;
class CValidationState;

int GetNumBlocksOfPeers();
std::string GetWarnings(std::string strFor);

bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType);

// yacoin: calculate Nfactor using timestamp
extern unsigned char GetNfactor(::int64_t nTimestamp, bool fYac1dot0BlockOrTx = false);

/**
 * Get minimum confirmations to use coinbase
 */
int GetCoinbaseMaturity();

/**
 * Get an extra confirmations to add coinbase to balance
 */
int GetCoinbaseMaturityOffset();

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    ::int32_t nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CTransaction*)this);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    int SetMerkleBranch(const CBlock* pblock=NULL);
    int GetDepthInMainChain(CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool();
};

#endif
