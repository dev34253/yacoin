// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/pos_generator.h"

#include "amount.h"
#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "clientversion.h"
#include "kernel.h"
#include "pow.h"
#include "script/sign.h"
#include "streams.h"
#include "sync.h"
#include "tinyformat.h"
#include "txdb.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

#include <boost/test/unit_test.hpp>

// Defined in kernel.cpp with external linkage but not declared in a header
// (consensusdump.cpp declares it the same way).
uint256 GetProofOfStakeHash(uint64_t nStakeModifier, uint32_t nTimeBlockFrom, uint32_t nTxPrevOffset,
                            uint32_t nTxPrevTime, uint32_t nPrevoutn, uint32_t nTimeTx, uint64_t nCoinDayWeight);

namespace synthetic_pos {

namespace {

/** Copy of the file-static GetStakeModifierSelectionInterval (kernel.cpp). */
int64_t SelectionInterval()
{
    int64_t nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; ++nSection) {
        nSelectionInterval += Params().GetConsensus().nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1)));
    }
    return nSelectionInterval;
}

/**
 * Copy of the walk in the file-static GetKernelStakeModifier (kernel.cpp):
 * from pindexFrom forward to the first stake modifier generated at least one
 * selection interval after pindexFrom. The node follows chainActive.Next on
 * the active part and a temporary chain from pindexPrev back on a fork; here
 * the walk follows pindexPrev's ancestors and throws when it reaches
 * pindexPrev. The node does not stop there: when pindexPrev is on the active
 * chain (tip or not) it continues with chainActive.Next into blocks above
 * pindexPrev (see project/known-issues.md). With a stake older than the
 * minimum age (30 days > the 8.8-day selection interval) and sane block
 * times the modifier is found below pindexPrev, so both walks agree; the
 * final CheckStakeKernelHash call catches any difference.
 */
void KernelStakeModifier(const CBlockIndex* pindexPrev, const CBlockIndex* pindexFrom, uint64_t& nStakeModifier, int& nModifierHeight)
{
    if (pindexPrev->GetAncestor(pindexFrom->nHeight) != pindexFrom)
        throw std::runtime_error("synthetic_pos: stake block is not an ancestor of pindexPrev");
    std::vector<const CBlockIndex*> path;
    for (const CBlockIndex* p = pindexPrev; p->nHeight > pindexFrom->nHeight; p = p->pprev)
        path.push_back(p);
    std::reverse(path.begin(), path.end());

    const int64_t nSelectionInterval = SelectionInterval();
    nModifierHeight = pindexFrom->nHeight;
    int64_t nModifierTime = pindexFrom->GetBlockTime();
    const CBlockIndex* pindex = pindexFrom;
    size_t n = 0;
    while (nModifierTime < pindexFrom->GetBlockTime() + nSelectionInterval) {
        if (n >= path.size())
            throw std::runtime_error(strprintf("synthetic_pos: no stake modifier yet for the stake block at height %d "
                                               "(chain ends at height %d, time %d; needs a generated modifier at time >= %d)",
                                               pindexFrom->nHeight, pindexPrev->nHeight, pindexPrev->GetBlockTime(),
                                               pindexFrom->GetBlockTime() + nSelectionInterval));
        pindex = path[n++];
        if (pindex->GeneratedStakeModifier()) {
            nModifierHeight = pindex->nHeight;
            nModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
}

/** Coinbase spending nothing: height and salt in the scriptSig. */
CTransaction MakeCoinbase(int nHeight, int64_t nTime, unsigned char nSalt)
{
    CTransaction tx;
    tx.nVersion = CTransaction::CURRENT_VERSION;
    tx.nTime = nTime;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << nHeight << std::vector<unsigned char>{nSalt, 0x55};
    return tx;
}

} // namespace

PosChainSetup::PosChainSetup() : ConsensusTestingSetup(CBaseChainParams::REGTEST)
{
    // Pre-fork era: modifiers, kernel check in AcceptBlock, ppcoin retarget,
    // maturity 500. N-factor and the other globals stay at the unit-test
    // values (N-factor 0 keeps the version-7 header hash cheap).
    globals.SetNewLogicBlockNumber(consensus_harness::MAINNET_NEW_LOGIC_BLOCK_NUMBER);
    globals.SetMockTime(START_TIME);

    const std::vector<unsigned char> vchSecret(32, 0x55);
    key.Set(vchSecret.begin(), vchSecret.end(), true);
    BOOST_REQUIRE(key.IsValid());
    keystore.AddKey(key);

    // The genesis was loaded with fork height 0, which skips the stake
    // modifier (validation.cpp:2987); a pre-fork node gives it modifier 0,
    // generated (ComputeNextStakeModifier without pprev).
    LOCK(cs_main);
    CBlockIndex* genesis = chainActive.Genesis();
    BOOST_REQUIRE(genesis != nullptr);
    BOOST_REQUIRE(chainActive.Tip() == genesis);
    genesis->SetStakeModifier(0, true);
}

CScript PosChainSetup::Script() const
{
    return CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
}

CBlock PosChainSetup::MinePowBlock(const CBlockIndex* parent, int64_t nTime, unsigned char nSalt) const
{
    CBlock block;
    block.nVersion = VERSION_of_block_for_yac_05x_new;
    block.hashPrevBlock = parent->GetBlockHash();
    block.nTime = nTime;
    block.nBits = GetNextTargetRequired(parent, false);
    CTransaction coinbase = MakeCoinbase(parent->nHeight + 1, nTime, nSalt);
    coinbase.vout.push_back(CTxOut(GetProofOfWorkReward(block.nBits, 0, parent->nHeight + 1), Script()));
    block.vtx.push_back(coinbase);
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()))
        ++block.nNonce;
    return block;
}

CBlockIndex* PosChainSetup::Submit(const CBlock& block, bool fForceProcessing, bool* pfNewBlock, bool* pfAccepted)
{
    if (block.GetBlockTime() > GetMockTime())
        SetMockTime(block.GetBlockTime()); // the guard in `globals` restores it
    bool fNewBlock = false;
    const bool fAccepted = ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), fForceProcessing, &fNewBlock);
    if (pfNewBlock) *pfNewBlock = fNewBlock;
    if (pfAccepted) *pfAccepted = fAccepted;
    LOCK(cs_main);
    BlockMap::iterator it = mapBlockIndex.find(block.GetHash());
    return it == mapBlockIndex.end() ? nullptr : it->second;
}

CBlockIndex* PosChainSetup::MinePowChain(int n, int64_t nSpacing)
{
    CBlockIndex* tip;
    {
        LOCK(cs_main);
        tip = chainActive.Tip();
    }
    for (int i = 0; i < n; ++i) {
        const int64_t nTime = tip->pprev == nullptr ? START_TIME : tip->GetBlockTime() + nSpacing;
        bool fAccepted = false;
        CBlockIndex* pindex = Submit(MinePowBlock(tip, nTime), true, nullptr, &fAccepted);
        if (!fAccepted || pindex == nullptr || pindex->pprev != tip)
            throw std::runtime_error(strprintf("synthetic_pos: PoW block at height %d not accepted", tip->nHeight + 1));
        tip = pindex;
    }
    LOCK(cs_main);
    if (chainActive.Tip() != tip)
        throw std::runtime_error("synthetic_pos: PoW chain did not become the active chain");
    return tip;
}

void PosChainSetup::SeedProofOfStakeHistory(CBlockIndex* a, CBlockIndex* b)
{
    LOCK(cs_main);
    if (a == nullptr || b == nullptr || a->nHeight < 1 || b->nHeight <= a->nHeight || b->GetAncestor(a->nHeight) != a)
        throw std::runtime_error("synthetic_pos: SeedProofOfStakeHistory needs two entries above the genesis, a an ancestor of b");
    a->SetProofOfStake();
    b->SetProofOfStake();
    BOOST_TEST_MESSAGE(strprintf("synthetic_pos: index entries at heights %d and %d marked PoS (seed)", a->nHeight, b->nHeight));
}

Kernel PosChainSetup::FindKernel(CBlockIndex* pindexPrev, const COutPoint& prevout, unsigned int nBits,
                                 int64_t nTimeFrom, uint64_t nMaxTries) const
{
    const Consensus::Params& params = Params().GetConsensus();
    Kernel k;
    k.prevout = prevout;
    k.nBits = nBits;

    // Read txPrev and its block header like CheckProofOfStake (kernel.cpp).
    CDiskTxPos postx;
    if (!pblocktree->ReadTxIndex(prevout.hash, postx))
        throw std::runtime_error("synthetic_pos: stake transaction not in the tx index");
    {
        CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
        if (file.IsNull())
            throw std::runtime_error("synthetic_pos: cannot open the stake's block file");
        file >> k.headerFrom;
        fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
        file >> k.txPrev;
    }
    if (k.txPrev.GetHash() != prevout.hash || prevout.n >= k.txPrev.vout.size())
        throw std::runtime_error("synthetic_pos: stake transaction mismatch");
    k.nTxPrevOffset = postx.nTxOffset + ::GetSerializeSize(k.headerFrom, SER_DISK, CLIENT_VERSION);

    const CBlockIndex* pindexFrom;
    {
        LOCK(cs_main);
        BlockMap::iterator it = mapBlockIndex.find(k.headerFrom.GetHash());
        if (it == mapBlockIndex.end())
            throw std::runtime_error("synthetic_pos: stake block not indexed");
        pindexFrom = it->second;
        KernelStakeModifier(pindexPrev, pindexFrom, k.nStakeModifier, k.nStakeModifierHeight);
    }

    const int64_t nTimeBlockFrom = k.headerFrom.GetBlockTime();
    int64_t nTime = std::max({nTimeFrom, pindexPrev->GetBlockTime() + 1, k.txPrev.nTime,
                              nTimeBlockFrom + (int64_t)params.nStakeMinAge});
    if (nTime > nYac10HardforkTime)
        throw std::runtime_error(strprintf("synthetic_pos: kernel time %d after nYac10HardforkTime %d (block would not be PoS)", nTime, nYac10HardforkTime));

    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    const int64_t nValueIn = k.txPrev.vout[prevout.n].nValue;
    const CBigNum bnMaxHash(~uint256(0));

    int64_t nCachedWeight = -1;
    CBigNum bnCoinDayWeight;
    bool fAnyHash = false;
    uint256 target;
    for (k.nTries = 1; k.nTries <= nMaxTries; ++k.nTries, ++nTime) {
        const int64_t nWeight = GetWeight(k.txPrev.nTime, nTime);
        if (nWeight != nCachedWeight) {
            // As CheckStakeKernelHash (kernel.cpp:457-460).
            nCachedWeight = nWeight;
            bnCoinDayWeight = CBigNum(nValueIn) * nWeight / COIN / (24 * 60 * 60);
            const CBigNum bnFull = bnCoinDayWeight * bnTarget;
            fAnyHash = bnFull >= bnMaxHash;
            target = fAnyHash ? ~uint256(0) : bnFull.getuint256();
        }
        const uint256 hash = GetProofOfStakeHash(k.nStakeModifier, (uint32_t)nTimeBlockFrom, k.nTxPrevOffset,
                                                 (uint32_t)k.txPrev.nTime, prevout.n, (uint32_t)nTime,
                                                 bnCoinDayWeight.getuint64());
        if (fAnyHash || hash <= target) {
            k.nTime = nTime;
            k.hashProofOfStake = hash;
            break;
        }
    }
    if (k.nTime == 0)
        throw std::runtime_error(strprintf("synthetic_pos: no kernel in %u tries (stake %s, nBits %08x)",
                                           nMaxTries, prevout.ToString(), nBits));

    // Confirm with the node's own kernel check.
    uint256 hashNode, targetNode;
    if (!CheckStakeKernelHash(nBits, pindexPrev, k.headerFrom, k.nTxPrevOffset, k.txPrev, prevout,
                              (uint32_t)k.nTime, hashNode, targetNode))
        throw std::runtime_error("synthetic_pos: CheckStakeKernelHash rejects the ground kernel");
    if (hashNode != k.hashProofOfStake)
        throw std::runtime_error(strprintf("synthetic_pos: kernel hash differs from the node's (%s vs %s)",
                                           k.hashProofOfStake.ToString(), hashNode.ToString()));
    k.targetProofOfStake = targetNode;
    BOOST_TEST_MESSAGE(strprintf("synthetic_pos: kernel for %s on height %d: time %d (+%d s from the first valid second), "
                                 "%u tries, modifier 0x%016x (height %d), nBits %08x, hash %s",
                                 prevout.ToString(), pindexPrev->nHeight, k.nTime, k.nTries - 1, k.nTries,
                                 k.nStakeModifier, k.nStakeModifierHeight, nBits, k.hashProofOfStake.ToString()));
    return k;
}

CTransaction PosChainSetup::CreateCoinstake(const Kernel& kernel, int64_t nReward) const
{
    CTransaction tx;
    tx.nVersion = CTransaction::CURRENT_VERSION;
    tx.nTime = kernel.nTime;
    tx.vin.push_back(CTxIn(kernel.prevout));
    CTxOut empty;
    empty.SetEmpty();
    tx.vout.push_back(empty);
    tx.vout.push_back(CTxOut(kernel.txPrev.vout[kernel.prevout.n].nValue + nReward, Script()));
    if (!SignSignature(keystore, kernel.txPrev.vout[kernel.prevout.n].scriptPubKey, tx, 0, SIGHASH_ALL))
        throw std::runtime_error("synthetic_pos: cannot sign the coinstake");
    return tx;
}

CBlock PosChainSetup::CreatePosBlock(const CBlockIndex* pindexPrev, const Kernel& kernel, unsigned char nSalt) const
{
    CBlock block;
    block.nVersion = VERSION_of_block_for_yac_05x_new;
    block.hashPrevBlock = pindexPrev->GetBlockHash();
    block.nTime = kernel.nTime;
    block.nBits = kernel.nBits;
    block.nNonce = 0;
    CTransaction coinbase = MakeCoinbase(pindexPrev->nHeight + 1, kernel.nTime, nSalt);
    CTxOut empty;
    empty.SetEmpty();
    coinbase.vout.push_back(empty);
    block.vtx.push_back(coinbase);
    block.vtx.push_back(CreateCoinstake(kernel));
    block.hashMerkleRoot = block.BuildMerkleTree();
    if (!key.Sign(block.GetHash(), block.vchBlockSig))
        throw std::runtime_error("synthetic_pos: cannot sign the block");
    return block;
}

CBlock PosChainSetup::GeneratePosBlock(CBlockIndex* pindexPrev, const COutPoint& prevout, unsigned char nSalt, Kernel* pkernel) const
{
    const unsigned int nBits = GetNextTargetRequired(pindexPrev, true);
    if (nBits > POS_LIMIT_BITS)
        throw std::runtime_error(strprintf("synthetic_pos: required PoS nBits %08x on height %d is not PoS by the header rule "
                                           "(first two PoS blocks of a chain; call SeedProofOfStakeHistory)",
                                           nBits, pindexPrev->nHeight));
    const Kernel kernel = FindKernel(pindexPrev, prevout, nBits);
    if (pkernel) *pkernel = kernel;
    return CreatePosBlock(pindexPrev, kernel, nSalt);
}

COutPoint PosChainSetup::CoinbaseOutPoint(int nHeight) const
{
    CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = chainActive[nHeight];
    }
    CBlock block;
    if (pindex == nullptr || !ReadBlockFromDisk(block, pindex, Params().GetConsensus()))
        throw std::runtime_error(strprintf("synthetic_pos: no active block at height %d", nHeight));
    return COutPoint(block.vtx[0].GetHash(), 0);
}

} // namespace synthetic_pos
