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

// PoS constants
extern const unsigned int nOnedayOfAverageBlocks;

static const unsigned int MAX_ORPHAN_TRANSACTIONS = 10000;
static const ::int64_t MAX_MINT_PROOF_OF_WORK = 100 * COIN;
static const ::int64_t MAX_MINT_PROOF_OF_STAKE = 1 * COIN;

extern int nConsecutiveStakeSwitchHeight;  // see timesamps.h = 420000;
const ::int64_t nMaxClockDrift = nTwoHoursInSeconds;

inline ::int64_t PastDrift(::int64_t nTime)   
    { return nTime - nMaxClockDrift; } // up to 2 hours from the past
inline ::int64_t FutureDrift(::int64_t nTime) 
    { return nTime + nMaxClockDrift; } // up to 2 hours from the future

extern unsigned char pchMessageStart[4];

// Settings
extern const uint256 entropyStore[38];

// Minimum disk space required - used in CheckDiskSpace()
static const ::uint64_t nMinDiskSpace = 52428800;

class CReserveKey;
class CBlockLocator;
class CValidationState;

int GetNumBlocksOfPeers();

// yacoin: calculate Nfactor using timestamp
extern unsigned char GetNfactor(::int64_t nTimestamp, bool fYac1dot0BlockOrTx = false);

#endif
