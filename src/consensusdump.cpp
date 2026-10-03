// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Per-block consensus value dump (task P0-08); see consensusdump.h.
//
// Nothing here changes consensus state: the code reads the block index,
// the block and undo files and the transaction index and calls existing
// consensus functions (GetNextTargetRequired, GetBlockTrust,
// CheckStakeKernelHash, GetProofOfStakeHash, GetCoinAge,
// GetProofOfWorkReward, GetProofOfStakeReward, GetMaxSize,
// GetLegacySigOpCount). Two pieces of consensus code that are inline or
// file-static are copied, and checked against the node's results: the
// N-factor selection of CBlockHeader::CalculateHash and the stake-modifier
// walk of GetKernelStakeModifier.

#include "consensusdump.h"

#include "amount.h"
#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "clientversion.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "hash.h"
#include "init.h"
#include "kernel.h"
#include "policy/fees.h"
#include "pow.h"
#include "primitives/block.h"
#include "scrypt.h"
#include "streams.h"
#include "timestamps.h"
#include "tinyformat.h"
#include "txdb.h"
#include "undo.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

#include <algorithm>
#include <cassert>
#include <map>
#include <set>
#include <stdexcept>

// Defined in kernel.cpp with external linkage but not declared in a header;
// declared here (global scope) so that the dump calls the node's own code.
uint256 GetProofOfStakeHash(uint64_t nStakeModifier, uint32_t nTimeBlockFrom, uint32_t nTxPrevOffset,
                            uint32_t nTxPrevTime, uint32_t nPrevoutn, uint32_t nTimeTx, uint64_t nCoinDayWeight);

namespace {

std::string OptHash(const uint256& h)
{
    return h.IsNull() ? std::string() : h.GetHex();
}

std::string OptOutPoint(const COutPoint& o)
{
    return o.IsNull() ? std::string() : strprintf("%s:%u", o.hash.GetHex(), o.n);
}

template <typename T>
std::string OptNumber(const boost::optional<T>& v)
{
    return v ? std::to_string(*v) : std::string();
}

std::string OptBits(const boost::optional<uint32_t>& v)
{
    return v ? strprintf("0x%08x", *v) : std::string();
}

/** CBigNum (non-negative, < 2^256) to arith_uint256; throws otherwise. */
arith_uint256 BigNumToArith(const CBigNum& bn, const char* what, int nHeight)
{
    if (bn < 0 || bn > CBigNum(~uint256(0))) {
        throw std::runtime_error(strprintf("%s at height %d does not fit in 256 bits: %s", what, nHeight, bn.GetHex()));
    }
    return UintToArith256(bn.getuint256());
}

/** Read a transaction and the header of its block through the transaction
 *  index, as CheckProofOfStake (kernel.cpp) does: the header is
 *  deserialised from the file, so CBlockHeader::GetHash() can use a cached
 *  hash. Throws on any error: on a valid chain the kernel input is in the
 *  index. */
void ReadTxFromIndex(const uint256& txid, CTransaction& tx, CBlockHeader& header, CDiskTxPos& postx)
{
    if (!pblocktree->ReadTxIndex(txid, postx)) {
        throw std::runtime_error("transaction index entry missing for " + txid.GetHex());
    }
    CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        throw std::runtime_error("cannot open block file for transaction " + txid.GetHex());
    }
    try {
        file >> header;
        if (fseek(file.Get(), postx.nTxOffset, SEEK_CUR) != 0) {
            throw std::runtime_error("seek failed");
        }
        file >> tx;
    } catch (const std::exception& e) {
        throw std::runtime_error(strprintf("cannot read transaction %s: %s", txid.GetHex(), e.what()));
    }
    if (tx.GetHash() != txid) {
        throw std::runtime_error("txid mismatch reading " + txid.GetHex());
    }
}

/**
 * Coins view holding the coins a block spends, taken from the block's undo
 * data: exactly the coins ConnectBlock saw (value, height, coinbase and
 * coinstake flags, nTime). On a synced node these coins are spent, so the
 * chainstate cannot answer for them. Unknown outpoints throw instead of
 * returning false, because GetCoinAge would silently skip such an input.
 */
class CCoinsViewUndo : public CCoinsView
{
public:
    void Add(const COutPoint& outpoint, const Coin& coin) { mapCoins[outpoint] = coin; }
    bool GetCoin(const COutPoint& outpoint, Coin& coin) const override
    {
        std::map<COutPoint, Coin>::const_iterator it = mapCoins.find(outpoint);
        if (it == mapCoins.end()) {
            throw std::runtime_error(strprintf("coin %s:%u is not in the undo data", outpoint.hash.GetHex(), outpoint.n));
        }
        coin = it->second;
        return true;
    }
    bool HaveCoin(const COutPoint& outpoint) const override
    {
        Coin coin;
        return GetCoin(outpoint, coin);
    }

private:
    std::map<COutPoint, Coin> mapCoins;
};

/** Read the block of pindex without the PoW recheck of ReadBlockFromDisk
 *  (which recomputes the scrypt hash when the block-hash index misses);
 *  the header is compared with the index and the merkle root recomputed. */
void ReadBlockForDump(const CBlockIndex* pindex, CBlock& block)
{
    if (!(pindex->nStatus & BLOCK_HAVE_DATA)) {
        throw std::runtime_error(strprintf("no block data for height %d (%s)", pindex->nHeight, pindex->GetBlockHash().GetHex()));
    }
    const CDiskBlockPos pos = pindex->GetBlockPos();
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        throw std::runtime_error(strprintf("cannot open block file for height %d at %s", pindex->nHeight, pos.ToString()));
    }
    try {
        filein >> block;
    } catch (const std::exception& e) {
        throw std::runtime_error(strprintf("cannot read block at height %d (%s): %s", pindex->nHeight, pos.ToString(), e.what()));
    }
    block.blockHash = pindex->GetBlockHash();
    const uint256 hashPrev = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
    if (block.nVersion != pindex->nVersion || block.hashPrevBlock != hashPrev || block.nTime != pindex->nTime ||
        block.nBits != pindex->nBits || block.nNonce != pindex->nNonce || block.hashMerkleRoot != pindex->hashMerkleRoot) {
        throw std::runtime_error(strprintf("block on disk at height %d does not match the index", pindex->nHeight));
    }
    if (block.vtx.empty() || block.BuildMerkleTree() != pindex->hashMerkleRoot) {
        throw std::runtime_error(strprintf("merkle root of the block at height %d does not match", pindex->nHeight));
    }
}

/** Read the undo data of a block. Same steps as UndoReadFromDisk
 *  (validation.cpp), which is file-local: the record is followed by
 *  SHA256d(hash of pprev || record), which is checked. */
void ReadBlockUndo(const CBlockIndex* pindex, CBlockUndo& blockundo)
{
    const CDiskBlockPos pos = pindex->GetUndoPos();
    FILE* file = fsbridge::fopen(GetBlockPosFilename(pos, "rev"), "rb");
    if (file != nullptr && fseek(file, pos.nPos, SEEK_SET) != 0) {
        fclose(file);
        file = nullptr;
    }
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        throw std::runtime_error(strprintf("cannot open undo file for height %d at %s", pindex->nHeight, pos.ToString()));
    }
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein);
    try {
        verifier << pindex->pprev->GetBlockHash();
        verifier >> blockundo;
        filein >> hashChecksum;
    } catch (const std::exception& e) {
        throw std::runtime_error(strprintf("cannot read undo data for height %d: %s", pindex->nHeight, e.what()));
    }
    if (hashChecksum != verifier.GetHash()) {
        throw std::runtime_error(strprintf("undo data checksum mismatch at height %d", pindex->nHeight));
    }
}

/** Fill the undo-data view with every coin the block spends. */
void ReadUndoForDump(const CBlockIndex* pindex, const CBlock& block, CCoinsViewUndo& view)
{
    if (!(pindex->nStatus & BLOCK_HAVE_UNDO)) {
        throw std::runtime_error(strprintf("no undo data for height %d (%s)", pindex->nHeight, pindex->GetBlockHash().GetHex()));
    }
    CBlockUndo blockundo;
    ReadBlockUndo(pindex, blockundo);
    if (blockundo.vtxundo.size() + 1 != block.vtx.size()) {
        throw std::runtime_error(strprintf("undo data for height %d has %u entries for %u transactions", pindex->nHeight,
                                           blockundo.vtxundo.size(), block.vtx.size()));
    }
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        const CTransaction& tx = block.vtx[i];
        const CTxUndo& txundo = blockundo.vtxundo[i - 1];
        if (txundo.vprevout.size() != tx.vin.size()) {
            throw std::runtime_error(strprintf("undo data for tx %u at height %d has %u coins for %u inputs", (unsigned)i,
                                               pindex->nHeight, txundo.vprevout.size(), tx.vin.size()));
        }
        for (size_t j = 0; j < tx.vin.size(); ++j) {
            view.Add(tx.vin[j].prevout, txundo.vprevout[j]);
        }
    }
}

/** Recompute the scrypt header hash at the given N-factor (the byte layout
 *  of CBlockHeader::CalculateHash) and compare with the stored hash. */
bool CheckNFactor(const CBlockIndex* pindex, unsigned char nFactor)
{
    const uint256 hashPrev = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
    uint256 thash;
    bool fOk;
    if (pindex->nVersion >= VERSION_of_block_for_yac_05x_new) {
        struct block_header data;
        data.version = pindex->nVersion;
        data.prev_block = hashPrev;
        data.merkle_root = pindex->hashMerkleRoot;
        data.timestamp = pindex->nTime;
        data.bits = pindex->nBits;
        data.nonce = pindex->nNonce;
        fOk = scrypt_hash(CVOIDBEGIN(data), sizeof(struct block_header), UINTBEGIN(thash), nFactor);
    } else {
        old_block_header data;
        data.version = pindex->nVersion;
        data.prev_block = hashPrev;
        data.merkle_root = pindex->hashMerkleRoot;
        data.timestamp = pindex->nTime;
        data.bits = pindex->nBits;
        data.nonce = pindex->nNonce;
        fOk = scrypt_hash(CVOIDBEGIN(data), sizeof(old_block_header), UINTBEGIN(thash), nFactor);
    }
    return fOk && thash == pindex->GetBlockHash();
}

/** Copy of the file-static GetStakeModifierSelectionInterval (kernel.cpp). */
int64_t StakeModifierSelectionInterval()
{
    int64_t nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; ++nSection) {
        nSelectionInterval += (Params().GetConsensus().nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
    }
    return nSelectionInterval;
}

/**
 * Copy of the walk in the file-static GetKernelStakeModifier (kernel.cpp)
 * for a block on the active chain: from the block holding the kernel input,
 * follow chainActive.Next until a stake modifier generated at least one
 * selection interval after that block is reached. Returns false if the
 * walk reaches the tip. nLastHeight is the height where the walk stopped
 * (at validation time it could not go past the block's pprev).
 */
bool KernelStakeModifier(const CBlockIndex* pindexFrom, uint64_t& nStakeModifier, int& nModifierHeight, int& nLastHeight)
{
    const int64_t nSelectionInterval = StakeModifierSelectionInterval();
    nModifierHeight = pindexFrom->nHeight;
    int64_t nModifierTime = pindexFrom->GetBlockTime();
    const CBlockIndex* pindex = pindexFrom;
    while (nModifierTime < pindexFrom->GetBlockTime() + nSelectionInterval) {
        pindex = chainActive.Next(pindex);
        if (pindex == nullptr) return false;
        if (pindex->GeneratedStakeModifier()) {
            nModifierHeight = pindex->nHeight;
            nModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    nLastHeight = pindex->nHeight;
    return true;
}

/** Kernel and coinstake columns of a proof-of-stake block. */
void FillProofOfStake(CBlockIndex* pindex, const CBlock& block, CCoinsViewUndo& viewUndo, ConsensusDumpRow& row,
                      ConsensusDumpResult& result)
{
    const CTransaction& txCoinStake = block.vtx[1];
    const COutPoint& prevout = txCoinStake.vin[0].prevout;

    CTransaction txPrev;
    CBlockHeader header;
    CDiskTxPos postx;
    ReadTxFromIndex(prevout.hash, txPrev, header, postx);
    if (prevout.n >= txPrev.vout.size()) {
        throw std::runtime_error(strprintf("kernel prevout %s of height %d does not exist", OptOutPoint(prevout), pindex->nHeight));
    }
    // Block hash from the block-hash index, as CheckProofOfStake does, so
    // that GetHash() does not recompute the scrypt hash.
    if (fBlockHashIndex && !pblocktree->ReadBlockHash(postx.nFile, postx.nPos, header.blockHash)) {
        LogPrint(BCLog::RPC, "dumpconsensusvalues: no block-hash index entry at file %d pos %d, recomputing the hash\n", postx.nFile, postx.nPos);
    }
    const uint256 hashBlockFrom = header.GetHash();
    BlockMap::const_iterator itFrom = mapBlockIndex.find(hashBlockFrom);
    if (itFrom == mapBlockIndex.end()) {
        throw std::runtime_error(strprintf("block %s of the kernel input of height %d is not indexed", hashBlockFrom.GetHex(), pindex->nHeight));
    }
    const uint32_t nTxPrevOffset = postx.nTxOffset + ::GetSerializeSize(header, SER_DISK, CLIENT_VERSION);

    row.fHasKernel = true;
    row.kernelPrevout = prevout;
    row.kernelBlockFromHash = hashBlockFrom;
    row.nKernelBlockFromTime = header.GetBlockTime();
    row.nKernelTxPrevTime = txPrev.nTime;
    row.nKernelTxPrevOffset = nTxPrevOffset;
    row.nKernelValueIn = txPrev.vout[prevout.n].nValue;
    row.nKernelTxTime = txCoinStake.nTime;

    uint256 hashProofOfStake;
    uint256 targetProofOfStake;
    row.fKernelOk = CheckStakeKernelHash(pindex->nBits, pindex->pprev, header, nTxPrevOffset, txPrev, prevout,
                                         txCoinStake.nTime, hashProofOfStake, targetProofOfStake, false);
    if (!hashProofOfStake.IsNull()) row.kernelHash = hashProofOfStake;
    if (row.fKernelOk) {
        row.kernelTarget = UintToArith256(targetProofOfStake);
    } else {
        ++result.nKernelFailed;
        LogPrintf("dumpconsensusvalues: kernel check fails at height %d (%s)\n", pindex->nHeight, pindex->GetBlockHash().GetHex());
    }
    if (hashProofOfStake != pindex->hashProofOfStake) {
        ++result.nKernelHashMismatch;
        LogPrintf("dumpconsensusvalues: kernel hash %s != stored %s at height %d\n", hashProofOfStake.GetHex(),
                  pindex->hashProofOfStake.GetHex(), pindex->nHeight);
    }

    // The stake modifier the kernel used, through the copied walk; checked
    // by hashing again with it.
    uint64_t nStakeModifier = 0;
    int nModifierHeight = 0;
    int nLastHeight = 0;
    if (KernelStakeModifier(itFrom->second, nStakeModifier, nModifierHeight, nLastHeight)) {
        row.nKernelStakeModifier = nStakeModifier;
        row.nKernelModifierHeight = nModifierHeight;
        if (nLastHeight > pindex->pprev->nHeight) {
            ++result.nKernelModifierAfterPrev;
            LogPrintf("dumpconsensusvalues: kernel modifier walk of height %d stops at %d, after its pprev\n", pindex->nHeight, nLastHeight);
        }
        const uint256 hashCheck = GetProofOfStakeHash(nStakeModifier, (uint32_t)header.GetBlockTime(), nTxPrevOffset,
                                                      txPrev.nTime, prevout.n, txCoinStake.nTime, 0);
        if (!hashProofOfStake.IsNull() && hashCheck != hashProofOfStake) {
            ++result.nKernelRehashMismatch;
            LogPrintf("dumpconsensusvalues: kernel re-hash with modifier 0x%016x differs at height %d\n", nStakeModifier, pindex->nHeight);
        }
    } else if (!hashProofOfStake.IsNull()) {
        ++result.nKernelRehashMismatch;
        LogPrintf("dumpconsensusvalues: kernel modifier walk reaches the tip at height %d\n", pindex->nHeight);
    }

    // Coin age and reward through the real GetCoinAge, on the coins the
    // block spent (undo data); the limit as in Consensus::CheckTxInputs
    // (consensus/tx_verify.cpp:417-419).
    CCoinsViewCache view(&viewUndo);
    uint64_t nCoinAge = 0;
    if (!GetCoinAge(txCoinStake, view, nCoinAge)) {
        throw std::runtime_error(strprintf("GetCoinAge failed for the coinstake of height %d", pindex->nHeight));
    }
    row.nCoinAge = nCoinAge;
    row.nPosReward = GetProofOfStakeReward(nCoinAge, pindex->nBits, txCoinStake.nTime);
    const unsigned int nTxSize = (txCoinStake.nTime > VALIDATION_SWITCH_TIME || fTestNet) ?
        ::GetSerializeSize(txCoinStake, SER_NETWORK, PROTOCOL_VERSION) : 0;
    row.nPosRewardLimit = *row.nPosReward - GetMinFee(nTxSize) + CENT;
    row.nCoinstakeValueIn = view.GetValueIn(txCoinStake);
    row.nCoinstakeValueOut = txCoinStake.GetValueOut();
    if (*row.nCoinstakeValueOut - *row.nCoinstakeValueIn > *row.nPosRewardLimit) {
        ++result.nCoinstakeOverLimit;
        LogPrintf("dumpconsensusvalues: coinstake pays more than the limit at height %d\n", pindex->nHeight);
    }
}

void WriteLine(FILE* file, const std::string& line)
{
    if (fwrite(line.data(), 1, line.size(), file) != line.size() || fputc('\n', file) == EOF) {
        throw std::runtime_error("write error");
    }
}

} // namespace

const std::vector<std::string>& ConsensusDumpColumns()
{
    static const std::vector<std::string> columns = {
        // P0-47 index-chain CSV columns
        "height", "hash", "prev_hash", "time", "bits", "version", "nonce", "merkle_root", "flags",
        "stake_modifier", "hash_proof_of_stake", "prevout_stake", "stake_time",
        // header and difficulty
        "header_sha256", "nfactor", "is_pos", "median_time_past", "required_bits", "min_bits_since_fork",
        // trust and stake modifier
        "block_trust", "chain_trust", "stake_modifier_checksum",
        // kernel
        "kernel_prevout", "kernel_block_from_hash", "kernel_block_from_time", "kernel_tx_prev_time",
        "kernel_tx_prev_offset", "kernel_value_in", "kernel_tx_time", "kernel_stake_modifier",
        "kernel_modifier_height", "kernel_hash", "kernel_target", "kernel_ok",
        // block contents and money
        "tx_count", "block_size", "sigops", "max_sigops", "coinbase_value", "fees", "pow_reward",
        "coinstake_value_in", "coinstake_value_out", "coin_age", "pos_reward", "pos_reward_limit",
        "max_block_size", "mint", "money_supply",
    };
    return columns;
}

std::string ConsensusDumpHeaderLine()
{
    std::string line;
    for (const std::string& column : ConsensusDumpColumns()) {
        if (!line.empty()) line += ',';
        line += column;
    }
    return line;
}

std::string FormatConsensusDumpBigHex(const arith_uint256& n)
{
    const std::string hex = n.GetHex();
    const std::string::size_type first = hex.find_first_not_of('0');
    return "0x" + (first == std::string::npos ? std::string("0") : hex.substr(first));
}

std::string FormatConsensusDumpRow(const ConsensusDumpRow& r)
{
    std::vector<std::string> f;
    f.reserve(ConsensusDumpColumns().size());
    f.push_back(std::to_string(r.nHeight));
    f.push_back(r.hash.GetHex());
    f.push_back(OptHash(r.hashPrev));
    f.push_back(std::to_string(r.nTime));
    f.push_back(strprintf("0x%08x", r.nBits));
    f.push_back(std::to_string(r.nVersion));
    f.push_back(std::to_string(r.nNonce));
    f.push_back(r.hashMerkleRoot.GetHex());
    f.push_back(std::to_string(r.nFlags));
    f.push_back(strprintf("0x%016x", r.nStakeModifier));
    f.push_back(OptHash(r.hashProofOfStake));
    f.push_back(OptOutPoint(r.prevoutStake));
    f.push_back(r.nStakeTime ? std::to_string(r.nStakeTime) : std::string());

    f.push_back(r.hashHeaderSha256.GetHex());
    f.push_back(std::to_string(r.nFactor));
    f.push_back(r.fProofOfStake ? "1" : "0");
    f.push_back(std::to_string(r.nMedianTimePast));
    f.push_back(OptBits(r.nRequiredBits));
    f.push_back(OptBits(r.nMinBitsSinceFork));

    f.push_back(FormatConsensusDumpBigHex(r.blockTrust));
    f.push_back(FormatConsensusDumpBigHex(r.chainTrust));
    f.push_back(strprintf("0x%08x", r.nStakeModifierChecksum));

    if (r.fHasKernel) {
        f.push_back(strprintf("%s:%u", r.kernelPrevout.hash.GetHex(), r.kernelPrevout.n));
        f.push_back(r.kernelBlockFromHash.GetHex());
        f.push_back(std::to_string(r.nKernelBlockFromTime));
        f.push_back(std::to_string(r.nKernelTxPrevTime));
        f.push_back(std::to_string(r.nKernelTxPrevOffset));
        f.push_back(std::to_string(r.nKernelValueIn));
        f.push_back(std::to_string(r.nKernelTxTime));
        f.push_back(r.nKernelStakeModifier ? strprintf("0x%016x", *r.nKernelStakeModifier) : std::string());
        f.push_back(OptNumber(r.nKernelModifierHeight));
        f.push_back(r.kernelHash ? r.kernelHash->GetHex() : std::string());
        f.push_back(r.kernelTarget ? FormatConsensusDumpBigHex(*r.kernelTarget) : std::string());
        f.push_back(r.fKernelOk ? "1" : "0");
    } else {
        for (int i = 0; i < 12; ++i) f.push_back(std::string());
    }

    f.push_back(std::to_string(r.nTxCount));
    f.push_back(std::to_string(r.nBlockSize));
    f.push_back(std::to_string(r.nSigOps));
    f.push_back(OptNumber(r.nMaxSigOps));
    f.push_back(std::to_string(r.nCoinbaseValue));
    f.push_back(OptNumber(r.nFees));
    f.push_back(OptNumber(r.nPowReward));
    f.push_back(OptNumber(r.nCoinstakeValueIn));
    f.push_back(OptNumber(r.nCoinstakeValueOut));
    f.push_back(OptNumber(r.nCoinAge));
    f.push_back(OptNumber(r.nPosReward));
    f.push_back(OptNumber(r.nPosRewardLimit));
    f.push_back(OptNumber(r.nMaxBlockSize));
    f.push_back(std::to_string(r.nMint));
    f.push_back(std::to_string(r.nMoneySupply));

    assert(f.size() == ConsensusDumpColumns().size());
    std::string line;
    for (size_t i = 0; i < f.size(); ++i) {
        if (i) line += ',';
        line += f[i];
    }
    return line;
}

unsigned char ConsensusDumpNFactor(int32_t nVersion, int64_t nTime)
{
    if (nVersion >= VERSION_of_block_for_yac_05x_new) return nFactorAtHardfork;
    if (fTestNet) return 4;
    // First time of N-factor 5, 6, ..., 26 (block.h: nChainStartTime +
    // nSpanOf4 ... nSpanOf25); before the first step the N-factor is 4,
    // from the last step on MAXIMUM_N_FACTOR. CalculateHash compares
    // nTime with an unsigned sum; times of version < 7 headers are 32-bit
    // unsigned, so a signed comparison gives the same result.
    static const int64_t STEPS[] = {
        1368515488, 1368777632, 1369039776, 1369826208, 1370088352, 1372185504,
        1373234080, 1376379808, 1380574112, 1384768416, 1401545632, 1409934240,
        1435100064, 1468654496, 1502208928, 1602872224, 1636426656, 1904862112,
        2173297568LL, 2441733024LL, 3247039392LL, 3515474848LL,
    };
    for (size_t i = 0; i < sizeof(STEPS) / sizeof(STEPS[0]); ++i) {
        if (nTime < STEPS[i]) return (unsigned char)(4 + i);
    }
    return MAXIMUM_N_FACTOR;
}

ConsensusDumpRow ComputeConsensusDumpRow(CBlockIndex* pindex, uint32_t nMinEase, ConsensusDumpResult& result)
{
    AssertLockHeld(cs_main);
    const int nHeight = pindex->nHeight;
    ConsensusDumpRow row;

    row.nHeight = nHeight;
    row.hash = pindex->GetBlockHash();
    row.hashPrev = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
    row.nTime = pindex->GetBlockTime();
    row.nBits = pindex->nBits;
    row.nVersion = pindex->nVersion;
    row.nNonce = pindex->nNonce;
    row.hashMerkleRoot = pindex->hashMerkleRoot;
    row.nFlags = pindex->nFlags;
    row.nStakeModifier = pindex->nStakeModifier;
    row.hashProofOfStake = pindex->hashProofOfStake;
    row.prevoutStake = pindex->prevoutStake;
    row.nStakeTime = pindex->nStakeTime;

    row.hashHeaderSha256 = pindex->GetSHA256Hash();
    row.nFactor = ConsensusDumpNFactor(pindex->nVersion, pindex->GetBlockTime());
    row.fProofOfStake = pindex->IsProofOfStake();
    row.nMedianTimePast = pindex->GetMedianTimePast();
    if (pindex->pprev) {
        row.nRequiredBits = GetNextTargetRequired(pindex->pprev, pindex->IsProofOfStake());
        if (*row.nRequiredBits != pindex->nBits) {
            ++result.nRequiredBitsMismatch;
            LogPrintf("dumpconsensusvalues: required bits 0x%08x != nBits 0x%08x at height %d\n", *row.nRequiredBits, pindex->nBits, nHeight);
        }
    }
    if (nHeight >= nMainnetNewLogicBlockNumber) {
        row.nMinBitsSinceFork = nMinEase;
    }

    row.blockTrust = BigNumToArith(pindex->GetBlockTrust(), "block trust", nHeight);
    row.chainTrust = BigNumToArith(pindex->bnChainTrust, "chain trust", nHeight);
    row.nStakeModifierChecksum = pindex->nStakeModifierChecksum;

    CBlock block;
    ReadBlockForDump(pindex, block);
    row.nTxCount = block.vtx.size();
    row.nBlockSize = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
    for (const CTransaction& tx : block.vtx) row.nSigOps += GetLegacySigOpCount(tx);
    row.nCoinbaseValue = block.vtx[0].GetValueOut();
    row.nMint = pindex->nMint;
    row.nMoneySupply = pindex->nMoneySupply;

    const bool fCoinStake = block.vtx.size() > 1 && block.vtx[1].IsCoinStake();
    if (pindex->IsProofOfStake()) ++result.nPosBlocks;
    if (pindex->IsProofOfStake() && !fCoinStake) {
        ++result.nPosWithoutCoinstake;
        LogPrintf("dumpconsensusvalues: PoS block without coinstake at height %d (%s)\n", nHeight, row.hash.GetHex());
    }
    if (!pindex->IsProofOfStake() && fCoinStake) {
        ++result.nCoinstakeInPowBlock;
        LogPrintf("dumpconsensusvalues: coinstake in a PoW block at height %d (%s)\n", nHeight, row.hash.GetHex());
    }

    if (pindex->pprev == nullptr) return row; // genesis: no undo data, not connected by ConnectBlock

    CCoinsViewUndo viewUndo;
    ReadUndoForDump(pindex, block, viewUndo);
    {
        // Fees as ConnectBlock counts them: non-coinbase, non-coinstake.
        CCoinsViewCache view(&viewUndo);
        int64_t nFees = 0;
        for (size_t i = 1; i < block.vtx.size(); ++i) {
            const CTransaction& tx = block.vtx[i];
            if (!tx.IsCoinStake()) nFees += view.GetValueIn(tx) - tx.GetValueOut();
        }
        row.nFees = nFees;
        const int64_t nFeesIndex = pindex->nMint - (pindex->nMoneySupply - pindex->pprev->nMoneySupply);
        if (nFees != nFeesIndex) {
            ++result.nFeesMismatch;
            LogPrintf("dumpconsensusvalues: fees %d != mint - supply change %d at height %d\n", nFees, nFeesIndex, nHeight);
        }
    }
    row.nMaxBlockSize = GetMaxSize(MAX_BLOCK_SIZE, nHeight);
    row.nMaxSigOps = GetMaxSize(MAX_BLOCK_SIGOPS, nHeight);
    if (pindex->IsProofOfWork()) {
        row.nPowReward = GetProofOfWorkReward(pindex->nBits, *row.nFees, nHeight);
        if (row.nCoinbaseValue > *row.nPowReward) {
            ++result.nCoinbaseOverReward;
            LogPrintf("dumpconsensusvalues: coinbase %d above reward %d at height %d\n", row.nCoinbaseValue, *row.nPowReward, nHeight);
        }
    } else if (fCoinStake) {
        FillProofOfStake(pindex, block, viewUndo, row, result);
    }
    return row;
}

ConsensusDumpResult DumpConsensusValues(const fs::path& path, int nStartHeight, int nEndHeight)
{
    AssertLockHeld(cs_main);
    const int64_t nStartMillis = GetTimeMillis();
    if (chainActive.Tip() == nullptr) throw std::runtime_error("no active chain");
    if (nStartHeight < 0 || nEndHeight > chainActive.Height() || nStartHeight > nEndHeight) {
        throw std::runtime_error(strprintf("invalid height range %d..%d (tip %d)", nStartHeight, nEndHeight, chainActive.Height()));
    }
    if (!fTxIndex) throw std::runtime_error("-txindex is required (kernel and coin age read the transaction index)");
    if (fs::exists(path)) throw std::runtime_error("file already exists: " + path.string());
    const fs::path pathTmp = path.string() + ".incomplete";
    // Never overwrite (and then delete) a file this run did not create.
    if (fs::exists(pathTmp)) throw std::runtime_error("file already exists: " + pathTmp.string() + " (left by an aborted run? remove it)");
    if (!fBlockHashIndex) {
        LogPrintf("dumpconsensusvalues: warning: -blockhashindex is off, every PoS row recomputes a scrypt hash (slow)\n");
    }

    ConsensusDumpResult result;
    result.strFilename = path.string();
    result.nStartHeight = nStartHeight;
    result.nEndHeight = nEndHeight;
    result.hashEnd = chainActive[nEndHeight]->GetBlockHash();

    LogPrintf("dumpconsensusvalues: writing heights %d..%d (%s) to %s\n", nStartHeight, nEndHeight, result.hashEnd.GetHex(), path.string());

    // Running nMinEase as CalculateNextWorkRequired computes it (pow.cpp:42-50)
    // for a node validating block h with tip h-1: start at the compact
    // powLimit, minimum of the compact nBits as unsigned integers over the
    // blocks from the fork height to h-1.
    uint32_t nMinEase = Params().GetConsensus().powLimit.GetCompact();
    for (int h = std::max(nMainnetNewLogicBlockNumber, 0); h < nStartHeight; ++h) {
        nMinEase = std::min(nMinEase, chainActive[h]->nBits);
    }

    FILE* file = fsbridge::fopen(pathTmp, "wb");
    if (file == nullptr) throw std::runtime_error("cannot open " + pathTmp.string() + " for writing");
    try {
        WriteLine(file, strprintf("# format=%s version=%d doc=src/test/README.md", CONSENSUS_DUMP_FORMAT, CONSENSUS_DUMP_VERSION));
#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT
        const int nLowDiff = 1;
#else
        const int nLowDiff = 0;
#endif
        WriteLine(file, strprintf("# client=%s chain=%s lowdiff=%d fork_height=%d heliopolis_hardfork_height=%d "
                                  "nfactor_at_hardfork=%d epoch_interval=%u difficulty_interval=%u yac10_hardfork_time=%d "
                                  "start_height=%d end_height=%d",
                                  FormatFullVersion(), Params().NetworkIDString(), nLowDiff, nMainnetNewLogicBlockNumber,
                                  Params().GetConsensus().HeliopolisHardforkHeight, (int)nFactorAtHardfork, nEpochInterval,
                                  nDifficultyInterval, nYac10HardforkTime, nStartHeight, nEndHeight));
        WriteLine(file, ConsensusDumpHeaderLine());

        std::set<int> setNFactorChecked;
        for (int h = nStartHeight; h <= nEndHeight; ++h) {
            CBlockIndex* pindex = chainActive[h];
            const ConsensusDumpRow row = ComputeConsensusDumpRow(pindex, nMinEase, result);
            if (h >= nMainnetNewLogicBlockNumber) nMinEase = std::min(nMinEase, pindex->nBits);
            // Check the N-factor column once per distinct value (and header
            // layout) by recomputing the scrypt hash.
            const int nFactorKey = row.nFactor + (pindex->nVersion >= VERSION_of_block_for_yac_05x_new ? 1000 : 0);
            if (setNFactorChecked.insert(nFactorKey).second) {
                ++result.nFactorChecked;
                const bool fMatch = CheckNFactor(pindex, (unsigned char)row.nFactor);
                if (!fMatch) ++result.nFactorMismatch;
                LogPrintf("dumpconsensusvalues: N-factor %d (version %d) at height %d: %s\n", row.nFactor, pindex->nVersion, h,
                          fMatch ? "hash reproduced" : "HASH DIFFERS");
            }
            WriteLine(file, FormatConsensusDumpRow(row));
            ++result.nRows;
            if (result.nRows % 100000 == 0) {
                LogPrintf("dumpconsensusvalues: %u rows written, height %d\n", result.nRows, h);
            }
            if (result.nRows % 1000 == 0 && ShutdownRequested()) {
                throw std::runtime_error("shutdown requested");
            }
        }
        WriteLine(file, strprintf("# end rows=%u end_hash=%s", result.nRows, result.hashEnd.GetHex()));
        if (fflush(file) != 0 || ferror(file)) throw std::runtime_error("write error");
        FILE* f = file;
        file = nullptr;
        if (fclose(f) != 0) throw std::runtime_error("write error on close");
        fs::rename(pathTmp, path);
    } catch (const std::exception& e) {
        if (file != nullptr) fclose(file);
        boost::system::error_code ec;
        fs::remove(pathTmp, ec);
        LogPrintf("dumpconsensusvalues: failed: %s\n", e.what());
        throw std::runtime_error(std::string("dumpconsensusvalues: ") + e.what());
    }

    result.nSeconds = (GetTimeMillis() - nStartMillis) / 1000.0;
    LogPrintf("dumpconsensusvalues: done, %u rows in %.1f s; pos_blocks=%u kernel_failed=%u kernel_hash_mismatch=%u "
              "kernel_rehash_mismatch=%u kernel_modifier_after_prev=%u required_bits_mismatch=%u fees_mismatch=%u "
              "coinbase_over_reward=%u coinstake_over_limit=%u pos_without_coinstake=%u coinstake_in_pow_block=%u "
              "nfactor_checked=%u nfactor_mismatch=%u\n",
              result.nRows, result.nSeconds, result.nPosBlocks, result.nKernelFailed, result.nKernelHashMismatch,
              result.nKernelRehashMismatch, result.nKernelModifierAfterPrev, result.nRequiredBitsMismatch,
              result.nFeesMismatch, result.nCoinbaseOverReward, result.nCoinstakeOverLimit,
              result.nPosWithoutCoinstake, result.nCoinstakeInPowBlock, result.nFactorChecked, result.nFactorMismatch);
    return result;
}
