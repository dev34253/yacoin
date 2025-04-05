// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "main.h"

#include "checkpoints.h"
#include "consensus/validation.h"
#include "db.h"
#include "txdb.h"
#include "init.h"
#include "checkqueue.h"
#include "kernel.h"
#ifdef QT_GUI
 #include "explorer.h"
#endif
#include "pow.h"
#include "reverse_iterator.h"
#include "random.h"
#include "streams.h"
#include "validation.h"
#include "validationinterface.h"
#include "net_processing.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/math/special_functions/round.hpp>

#include <memory>

using namespace boost;

using std::list;
using std::set;
using std::string;
using std::vector;
using std::runtime_error;
using std::map;
using std::pair;
using std::make_pair;
using std::max;
using std::min;
using std::multimap;
using std::deque;

//
// END OF FUNCTIONS USED FOR TOKEN MANAGEMENT SYSTEM
//

// PoS constants
const unsigned int nStakeMaxAge = 90 * nSecondsPerDay;  // 60 * 60 * 24 * 90; // 90 days as full weight
const unsigned int nOnedayOfAverageBlocks = (nSecondsPerDay / nStakeTargetSpacing) / 10;  // the old 144
const unsigned int nStakeMinAge = 30 * nSecondsPerDay; // 60 * 60 * 24 * 30, 30 days as zero time weight
const unsigned int nModifierInterval = 6 * nSecondsPerHour; // 6 * 60 * 60, time to elapse before new modifier is computed

int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;

const ::uint32_t 
    nTestNetGenesisNonce = 0x1F656; // = 128,598 decimal
/*
Read best chain
block.nNonce == 0001F66B
block.nNonce == 0001F66B (128619 dec) after 31 tries
block.GetHash() ==
0bd0495ffce47a76504f338692b70dfcd8fabc5176a49cc646f3f28478b132dc
block.nBits ==
0fffff0000000000000000000000000000000000000000000000000000000000
block.hashMerkleRoot ==
389003d67b17d9a38a9c83b9289225f5e5469b9f6a2d70fc7c97ee6e8f995f23
*/
//
const int
    nBigLinearTrailingAverageLength = 2100, // arbitrary but 35 hours
    nNewBigLinearTrailingAverageLength = 10 * nBigLinearTrailingAverageLength, // 21000 arbitrary but 350 hours!!
    nExponentialTrailingAverageLength = 8;  //arbitrary
int 
    nStatisticsNumberOfBlocks2000 = 2000,
    nStatisticsNumberOfBlocks1000 = 1000,
    nStatisticsNumberOfBlocks200 = 200,
    nStatisticsNumberOfBlocks100 = 100,
    nStatisticsNumberOfBlocks,  // = nBigLinearTrailingAverageLength,    
    nConsecutiveStakeSwitchHeight = 420000;  // see timesamps.h

CBigNum bnProofOfStakeLegacyLimit(~uint256(0) >> 24); 
CBigNum bnProofOfStakeLimit(~uint256(0) >> 27); 

int
    nCoinbaseMaturityInBlocks = 500;

int 
    nCoinbaseMaturity = nCoinbaseMaturityInBlocks;  //500;
                                                    // @~1 blk/minute, ~8.33 hrs        

int
    nCoinbaseMaturityAfterHardfork = 6;

// Number of nodes with fSyncStarted.
int nSyncStarted = 0;
int nScriptCheckThreads = 0;

CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Yacoin Signed Message:\n";

// Settings
::int64_t nTransactionFee = MIN_TX_FEE;

::int64_t
    nLongAverageBP2000 = 0,
    nLongAverageBP1000 = 0,
    nLongAverageBP200 = 0,
    nLongAverageBP100 = 0,
    nLongAverageBP = 0;

// Blocks that are in flight, and that are in the queue to be downloaded.
// Protected by cs_main.
struct QueuedBlock {
    uint256 hash;
    CBlockIndex *pindex; // Optional.
    int64_t nTime;  // Time of "getdata" request in microseconds.
};

int GetCoinbaseMaturity()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
    {
        return nCoinbaseMaturityAfterHardfork;
    }
    else
    {
        return nCoinbaseMaturity;
    }
}

int GetCoinbaseMaturityOffset()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
    {
        return 0;
    }
    else
    {
        return 20;
    }
}

int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    CBlock blockTmp;
    if (pblock == NULL)
    {
        // Transaction index is required to get to block
        if (!fTxIndex) {
            return 0;
        }

        // Read transaction position
        CDiskTxPos postx;
        if (!pblocktree->ReadTxIndex(GetHash(), postx)) {
            return 0;
        }

        // Read block
        const Consensus::Params& consensusParams = Params().GetConsensus();
        if (!ReadBlockFromDisk(blockTmp, postx, consensusParams)) {
            return 0;
        }
        pblock = &blockTmp;
    }

    // Update the tx's hashBlock
    hashBlock = pblock->GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
        if (pblock->vtx[nIndex] == *(CTransaction*)this)
            break;
    if (nIndex == (int)pblock->vtx.size())
    {
        vMerkleBranch.clear();
        nIndex = -1;
        LogPrintf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
        return 0;
    }

    // Fill in merkle branch
    vMerkleBranch = pblock->GetMerkleBranch(nIndex);

    // Is the tx in a block that's in the main chain
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return chainActive.Tip()->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return chainActive.Height() - pindex->nHeight + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    return max(
                0, 
                fTestNet?
                (GetCoinbaseMaturity() +  0) - GetDepthInMainChain():   //<<<<<<<<<<< test
                (GetCoinbaseMaturity() + GetCoinbaseMaturityOffset()) - GetDepthInMainChain()    // why is this 20?
              );                                                    // what is this 20 from? For?
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CValidationState state;
    CTransactionRef ptx = std::make_shared<CTransaction>(*this);
    return ::AcceptToMemoryPool(mempool, state, ptx, nullptr);
}

bool CWalletTx::AcceptWalletTransaction()
{
    {
        LOCK(mempool.cs);
        // Add previous supporting transactions first
        for(CMerkleTx& tx : vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && !pblocktree->ContainsTx(hash))
                    tx.AcceptToMemoryPool();
            }
        }
        return AcceptToMemoryPool();
    }
    return false;
}

//////////////////////////////////////////////////////////////////////////////
//
// Nfactor
//

// yacoin: increasing Nfactor gradually
const unsigned char minNfactor = 4;
const unsigned char maxNfactor = MAXIMUM_N_FACTOR; //30; since uint32_t fails on 07 Feb 2106 06:28:15 GMT when stored as an uint32_t in a block so there is no point going past Nf = 25
const unsigned char maxNfactorYc1dot0 = 21;

unsigned char GetNfactor(::int64_t nTimestamp, bool fYac1dot0BlockOrTx)
{
    if (fYac1dot0BlockOrTx)
    {
        return nFactorAtHardfork;
    }

    int nBitCount = 0;

    if (fTestNet || (nTimestamp <= (fTestNet? nChainStartTimeTestNet: nChainStartTime)))
        return minNfactor;

    ::int64_t nAgeOfBlockOrTxInSeconds = nTimestamp - (fTestNet? nChainStartTimeTestNet: nChainStartTime);

    while ((nAgeOfBlockOrTxInSeconds >> 1) > 3)     // nAgeOfBlockOrTxInSeconds / 2 is 4 or more
    {
        nBitCount += 1;
        nAgeOfBlockOrTxInSeconds >>= 1;             // /2 again
    }
    nAgeOfBlockOrTxInSeconds &= 0x03;   //3;    // really a mask on the low 2 bits.  But why?

    int n = ( (nBitCount * 170) + (nAgeOfBlockOrTxInSeconds * 25) - 2320) / 100;

    if (n < 0)
        n = 0;
    if (n > 255)
        LogPrintf("GetNfactor (%"PRId64") - something wrong(n == %d)\n", nTimestamp, n); // for g++

    // so n is between 0 and 0xff
    unsigned char N = (unsigned char)n;
    return min(max(N, minNfactor), maxNfactor);
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

string GetWarnings(string strFor)
{
    string strStatusBar;
    string strRPC;

    if (gArgs.GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        strStatusBar = strMiscWarning;
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    Yassert(!"GetWarnings() : invalid parameter");
    return "error";
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;
//_____________________________________________________________________________

void releaseModeAssertionfailure( 
                                 const char* pFileName, 
                                 const int nL, 
                                 const std::string strFunctionName,
                                 const char * booleanExpression 
                                )
{   //Assertion failed: (fAssertBoolean), file l:\backups\senadjyac045.2\yacoin\src\init.cpp, line 1368
  LogPrintf(
      "\n"
      "Release mode\n"
      "Assertion failed: (%s), file %s, line %d,\n"
      "function %s()"
      "\n"
      "\n"
      "",
      booleanExpression, pFileName  //__FILE__
      ,
      nL  //__LINE__
      ,
      strFunctionName  // __FUNCTION__
  );
  StartShutdown();  // maybe there are other ways??
}
//_____________________________________________________________________________
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
