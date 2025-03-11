// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "pow.h"

#include "arith_uint256.h"
#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "timestamps.h"
#include "uint256.h"

#include <algorithm>

// POW params
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
CBigNum bnProofOfWorkLimit(~uint256(0) >> 20);
#else
CBigNum bnProofOfWorkLimit(~uint256(0) >> 3);
#endif
const uint256 nPoWeasiestTargetLimitTestNet = ((~uint256( 0 )) >> 3 ); // this is the number used by TestNet 0.5.0.x
CBigNum bnProofOfWorkLimitTestNet( nPoWeasiestTargetLimitTestNet );

// POS params
CBigNum bnProofOfStakeHardLimit(~uint256(0) >> 30); // fix minimal proof of stake difficulty at 0.25
static CBigNum bnProofOfStakeTestnetLimit(~uint256(0) >> 20);
const unsigned int nStakeTargetSpacing = 1 * nSecondsperMinute; // 1 * 60; // 1-minute stake spacing

// Target params
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
static CBigNum bnInitialHashTarget(~uint256(0) >> 20);
#else
static CBigNum bnInitialHashTarget(~uint256(0) >> 8);
#endif
static CBigNum bnInitialHashTargetTestNet(~uint256(0) >> 8);
static const ::int64_t nTargetSpacingWorkMax = 12 * nStakeTargetSpacing; // 2-hour BS, 12 minutes!
static const ::int64_t nTargetTimespan = 7 * 24 * 60 * 60;  // one week

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

static unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, ::int64_t nFirstBlockTime)
{
    //if (params.fPowNoRetargeting)   // disguised testnet, again
    //    return pindexLast->nBits;

    const ::int64_t
        nAverageBlockperiod = nStakeTargetSpacing;  // 1 minute in seconds

    ::int64_t
        nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime,
        nNominalTimespan = nDifficultyInterval * nAverageBlockperiod;

    if (nActualTimespan < nNominalTimespan / 4)
        nActualTimespan = nNominalTimespan / 4;
    if (nActualTimespan > nNominalTimespan * 4)
        nActualTimespan = nNominalTimespan * 4;

    // Calculate to target 1 minute/block for the previous 'epoch's 21,000 blocks
    uint256
        bnPrev = CBigNum().SetCompact(pindexLast->nBits).getuint256();

    CBigNum
        bnPrevTarget;
    bnPrevTarget.setuint256( bnPrev );

    bnPrevTarget *= nActualTimespan;
    bnPrevTarget /= nNominalTimespan;

    // Calculate maximum target of all blocks, it corresponds to 1/3 highest difficulty (or 3 minimum ease)
    uint256 bnMaximum = CBigNum().SetCompact(nMinEase).getuint256();
    CBigNum bnMaximumTarget;
    bnMaximumTarget.setuint256(bnMaximum);
    bnMaximumTarget *= 3;

    // Compare 1/3 highest difficulty with 0.4.9 min difficulty (genesis block difficulty), choose the higher
    if (bnMaximumTarget > bnProofOfWorkLimit)
    {
        bnMaximumTarget = bnProofOfWorkLimit;
    }

    // Choose higher difficulty (higher difficulty have smaller target)
    CBigNum bnNewTarget = std::min(bnPrevTarget, bnMaximumTarget);
    LogPrintf(
                 "PoW new constant target %s\n"
                 ""
                 , CBigNum( bnNewTarget ).getuint256().ToString().substr(0,16)
                );

    // Update minimum ease (highest difficulty) for next target calculation
    ::uint32_t nNewEase = bnNewTarget.GetCompact();
    if (nMinEase > nNewEase)
    {
        nMinEase = nNewEase;
    }

    return nNewEase;
}

// TODO: Refactor GetNextTargetRequired044
static unsigned int GetNextTargetRequired044(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    // First three blocks will have following targets:
    // genesis (zeroth) block: bnEasiestTargetLimit
    // first block and second block: bnInitialHashTarget (~uint256(0) >> 8)
    CBigNum bnEasiestTargetLimit =
        fProofOfStake
            ? (fTestNet ? bnProofOfStakeTestnetLimit : bnProofOfStakeHardLimit)
            : (fTestNet ? bnProofOfWorkLimitTestNet : bnProofOfWorkLimit);

    if (pindexLast == NULL)
    {
        return bnEasiestTargetLimit.GetCompact(); // genesis (zeroth) block
    }

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);

    if (pindexPrev->pprev == NULL)
    {
        return bnInitialHashTarget.GetCompact(); // first block
    }

    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);

    if (pindexPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block

    // so there are more than 3 blocks
    ::int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    CBigNum bnNewTarget;
    ::uint32_t nEase = pindexLast->nBits;
    CBigNum bnNew;
    uint256 nTarget = CBigNum().SetCompact(nEase).getuint256();
    uint256 nRelativeTargetDelta = (nTarget >> 3);  // i.e. 1/8 of the current target

    // Yacoind version 1.0.0
    if ((pindexLast->nHeight + 1) >= nMainnetNewLogicBlockNumber)
    {
        // Recalculate nMinEase if reorg through two or many epochs
        if (recalculateMinEase)
        {
            recalculateMinEase = false;
            ::int32_t currentEpochNumber = chainActive.Tip()->nHeight / nEpochInterval;
            ::int32_t firstEpochNumberSinceHardfork = nMainnetNewLogicBlockNumber / nEpochInterval;
            ::uint32_t tempMinEase = bnEasiestTargetLimit.GetCompact();
            for (int i = firstEpochNumberSinceHardfork; i < currentEpochNumber; i++)
            {
                CBlockIndex* pbi = chainActive[i*nEpochInterval];
                if (tempMinEase > pbi->nBits)
                {
                    tempMinEase = pbi->nBits;
                }
            }
            nMinEase = tempMinEase;
        }

        // From block 3, the target is only recalculated every 21000 blocks
        int nBlocksToGo = (pindexLast->nHeight + 1) % nDifficultyInterval;
        // Only change once per difficulty adjustment interval, first at block 21000
        if (0 != nBlocksToGo) // the btc-ltc 2016 blocks
        {                     // don't change the target
            bnNewTarget.setuint256(nTarget);

            LogPrintf("PoW constant target %s (%d block %s to go)\n",
                      nTarget.ToString().substr(0, 16),
                      (nDifficultyInterval - nBlocksToGo),
                      (1 != nBlocksToGo) ? "s" : "");
            return bnNewTarget.GetCompact();
        }
        else // actually do a DAA
        {
            // Hardfork happens
            if ((pindexLast->nHeight + 1) == nMainnetNewLogicBlockNumber)
            {
                return bnProofOfWorkLimit.GetCompact();
            }
            // Go back by what we want to be 14 days worth of blocks
            const CBlockIndex* pindexFirst = pindexLast;

            if (pindexLast->nHeight > nDifficultyInterval + 1)
            {
                for (int i = 0; pindexFirst && i < nDifficultyInterval; ++i)
                    pindexFirst = pindexFirst->pprev;
            }
            else // get block #0
            {
                CBlockIndex* pbi = chainActive.Genesis();
                CBlock block;

                block.ReadFromDisk(pbi);
                pindexFirst = pbi;
            }
            Yassert(pindexFirst);

            return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime());
        }
    }
    else
    {
        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        bnNewTarget.SetCompact(pindexPrev->nBits);

        ::int64_t nTargetSpacing = fProofOfStake
                ? nStakeTargetSpacing
                : std::min(nTargetSpacingWorkMax, (::int64_t)nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));

        ::int64_t
            nInterval = nTargetTimespan / nTargetSpacing;   // this is the one week / nTargetSpacing

        bnNewTarget *= (((nInterval - 1) * nTargetSpacing) + nActualSpacing + nActualSpacing);
        bnNewTarget /=  ((nInterval + 1) * nTargetSpacing);
    }

    if (bnNewTarget > bnEasiestTargetLimit)
        bnNewTarget = bnEasiestTargetLimit;

    return bnNewTarget.GetCompact();
}
//_____________________________________________________________________________
// yacoin2015 upgrade: penalize ignoring ProofOfStake blocks with high difficulty.
// requires adjusted PoW-PoS ratio (GetSpacingThreshold), PoW target moving average (nBitsMA)
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    return GetNextTargetRequired044( pindexLast, fProofOfStake );
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
