// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Per-block consensus value dump (task P0-08).
//
// Writes one CSV row per block of the active chain with the values that
// later phases must reproduce (difficulty, trust, stake modifier, kernel,
// rewards, block size, money supply), plus the inputs needed to recompute
// them offline. Used by the hidden RPC `dumpconsensusvalues`. Read-only:
// it only calls existing consensus functions and reads the block index,
// the block and undo files and the transaction index. The format is described in
// src/test/README.md ("Consensus value dump"); the C++ reader for tests is
// src/test/consensus_dump_reader.h.
#ifndef YACOIN_CONSENSUSDUMP_H
#define YACOIN_CONSENSUSDUMP_H

#include "arith_uint256.h"
#include "fs.h"
#include "primitives/transaction.h"
#include "uint256.h"

#include <boost/optional.hpp>

#include <cstdint>
#include <string>
#include <vector>

class CBlockIndex;

/** Format name and version written in the first comment line. */
static const char* const CONSENSUS_DUMP_FORMAT = "yacoin-consensus-dump";
static const int CONSENSUS_DUMP_VERSION = 1;

/** One row of the dump. Optional fields are written as empty fields. */
struct ConsensusDumpRow {
    // Index-chain CSV columns (P0-47, src/test/README.md), as stored in the
    // block index.
    int32_t nHeight = 0;
    uint256 hash;
    uint256 hashPrev;                   // null (empty field) for the genesis
    int64_t nTime = 0;
    uint32_t nBits = 0;
    int32_t nVersion = 0;
    uint32_t nNonce = 0;
    uint256 hashMerkleRoot;
    uint32_t nFlags = 0;
    uint64_t nStakeModifier = 0;
    uint256 hashProofOfStake;           // empty field when null
    COutPoint prevoutStake;             // empty field when null
    uint32_t nStakeTime = 0;            // empty field when 0

    // Header and difficulty
    uint256 hashHeaderSha256;
    int nFactor = 0;
    bool fProofOfStake = false;
    int64_t nMedianTimePast = 0;
    boost::optional<uint32_t> nRequiredBits;
    boost::optional<uint32_t> nMinBitsSinceFork;

    // Trust and stake modifier
    arith_uint256 blockTrust;
    arith_uint256 chainTrust;
    uint32_t nStakeModifierChecksum = 0;

    // Kernel (proof-of-stake blocks with a coinstake only)
    bool fHasKernel = false;
    COutPoint kernelPrevout;
    uint256 kernelBlockFromHash;
    int64_t nKernelBlockFromTime = 0;
    int64_t nKernelTxPrevTime = 0;
    uint32_t nKernelTxPrevOffset = 0;
    int64_t nKernelValueIn = 0;
    int64_t nKernelTxTime = 0;
    boost::optional<uint64_t> nKernelStakeModifier;  // empty if not found
    boost::optional<int32_t> nKernelModifierHeight;  // height that generated it
    boost::optional<uint256> kernelHash;             // empty if not hashed
    boost::optional<arith_uint256> kernelTarget;     // only when the kernel passes
    bool fKernelOk = false;

    // Block contents and money
    uint32_t nTxCount = 0;
    uint64_t nBlockSize = 0;
    uint32_t nSigOps = 0;
    boost::optional<uint64_t> nMaxSigOps;
    int64_t nCoinbaseValue = 0;
    boost::optional<int64_t> nFees;
    boost::optional<int64_t> nPowReward;
    boost::optional<int64_t> nCoinstakeValueIn;
    boost::optional<int64_t> nCoinstakeValueOut;
    boost::optional<uint64_t> nCoinAge;
    boost::optional<int64_t> nPosReward;
    boost::optional<int64_t> nPosRewardLimit;
    boost::optional<uint64_t> nMaxBlockSize;
    int64_t nMint = 0;
    int64_t nMoneySupply = 0;
};

/** Column names of format version 1, in output order. The first 13 are the
 *  index-chain CSV columns of P0-47. */
const std::vector<std::string>& ConsensusDumpColumns();

/** The header line (column names joined by commas, no newline). */
std::string ConsensusDumpHeaderLine();

/** One CSV line for the row (no newline). */
std::string FormatConsensusDumpRow(const ConsensusDumpRow& row);

/** Hex form used for trust and kernel target: "0x" + lowercase hex without
 *  leading zeros ("0x0" for zero). */
std::string FormatConsensusDumpBigHex(const arith_uint256& n);

/**
 * N-factor of the scrypt-jane header hash of a header with this version and
 * time. Copy of the selection in CBlockHeader::CalculateHash()
 * (primitives/block.h), which has it inline: version >= 7 uses the global
 * nFactorAtHardfork, older headers a table of nTime steps (4 on testnet).
 * DumpConsensusValues checks it against the stored block hashes.
 */
unsigned char ConsensusDumpNFactor(int32_t nVersion, int64_t nTime);

/** Summary of one dump run. */
struct ConsensusDumpResult {
    std::string strFilename;
    int nStartHeight = 0;
    int nEndHeight = 0;
    uint256 hashEnd;
    uint64_t nRows = 0;
    uint64_t nPosBlocks = 0;
    uint64_t nKernelFailed = 0;         // CheckStakeKernelHash returned false
    uint64_t nKernelHashMismatch = 0;   // kernel hash != stored hashProofOfStake
    uint64_t nKernelRehashMismatch = 0; // re-hash with the walked modifier != kernel hash
    uint64_t nKernelModifierAfterPrev = 0; // modifier walk went past pprev
    uint64_t nRequiredBitsMismatch = 0; // required_bits != bits
    uint64_t nFeesMismatch = 0;         // undo fees != mint - (supply - prev supply)
    uint64_t nCoinbaseOverReward = 0;   // PoW coinbase value > pow_reward
    uint64_t nCoinstakeOverLimit = 0;   // coinstake out - in > pos_reward_limit
    uint64_t nPosWithoutCoinstake = 0;  // PoS flag without coinstake at vtx[1]
    uint64_t nCoinstakeInPowBlock = 0;  // coinstake at vtx[1] without PoS flag
    uint64_t nFactorChecked = 0;        // scrypt hashes recomputed
    uint64_t nFactorMismatch = 0;
    double nSeconds = 0;
};

/**
 * Compute the row of one block of chainActive. nMinEase is the running
 * minimum for min_bits_since_fork (heights fork..h-1). The caller holds
 * cs_main. Throws std::runtime_error on missing or inconsistent data.
 * DumpConsensusValues calls it for every row; public so that tests can
 * call it on a prepared chain.
 */
ConsensusDumpRow ComputeConsensusDumpRow(CBlockIndex* pindex, uint32_t nMinEase, ConsensusDumpResult& result);

/**
 * Write the dump of chainActive heights nStartHeight..nEndHeight to path.
 * The caller holds cs_main. Writes "<path>.incomplete" and renames it when
 * done. Throws std::runtime_error (after removing the incomplete file) on
 * any error: invalid range, existing file or "<path>.incomplete", no
 * -txindex, missing block, undo or transaction index data, write errors,
 * shutdown requested.
 */
ConsensusDumpResult DumpConsensusValues(const fs::path& path, int nStartHeight, int nEndHeight);

#endif // YACOIN_CONSENSUSDUMP_H
