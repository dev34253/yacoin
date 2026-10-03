// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Synthetic proof-of-stake blocks for unit tests (task P0-55).
//
// Builds a pre-fork regtest chain with real PoW blocks (ProcessNewBlock,
// blocks and transaction index on disk), grinds a coinstake kernel for one
// of its coinbase outputs with mock time and assembles a signed PoS block
// that CheckProofOfStake, ProcessNewBlock and ConnectBlock accept.
//
// Era: pre-fork. The fixture sets nMainnetNewLogicBlockNumber to the
// mainnet value, so stake modifiers are computed, AcceptBlock checks the
// kernel, PoS nBits follow the per-block ppcoin retarget and coinbase
// maturity is 500. Block times lie in 2020: after
// CONSECUTIVE_STAKE_SWITCH_TIME (new trust rules) and before
// nYac10HardforkTime (blocks are PoS by their header only up to that time).
// Post-fork PoS is not supported (no kernel check, no modifiers there).
//
// The first two PoS blocks of any chain need nBits = initialHashTarget,
// which the header rule does not count as PoS; block.h IsProofOfStake
// accepts two hard-coded mainnet hashes regardless (presumably those first
// blocks). SeedProofOfStakeHistory marks two PoW index entries as PoS to
// stand in for them.
//
// Test-only code: nothing here changes consensus behaviour. See
// src/test/README.md, "Synthetic proof-of-stake blocks".

#ifndef YACOIN_TEST_POS_GENERATOR_H
#define YACOIN_TEST_POS_GENERATOR_H

#include "test/consensus_harness.h"

#include "key.h"
#include "keystore.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "uint256.h"

#include <cstdint>

class CBlockIndex;

namespace synthetic_pos {

/** First block time of the synthetic chain: 2020-01-01 00:00:00 UTC. */
static const int64_t START_TIME = 1577836800;
/** Default spacing of the PoW blocks (one stake-modifier interval). */
static const int64_t BLOCK_SPACING = 6 * 60 * 60;
/** Compact form of the PoS limit ~uint256(0) >> 30 (pow.cpp:21). */
static const unsigned int POS_LIMIT_BITS = 0x1d03ffff;
/** Compact form of the regtest initialHashTarget and powLimit. */
static const unsigned int REGTEST_INITIAL_BITS = 0x207fffff;
/** Default bound for the kernel grind (seconds tried). */
static const uint64_t DEFAULT_MAX_TRIES = uint64_t(1) << 22;

/** A coinstake kernel found by PosChainSetup::FindKernel. */
struct Kernel {
    COutPoint prevout;
    CTransaction txPrev;
    CBlockHeader headerFrom;            // header of the block holding txPrev
    uint32_t nTxPrevOffset = 0;         // as CheckProofOfStake computes it
    uint64_t nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64_t nTime = 0;                  // coinstake and block time
    unsigned int nBits = 0;
    uint256 hashProofOfStake;
    uint256 targetProofOfStake;         // target(nBits) * coin-day weight
    uint64_t nTries = 0;                // kernel hashes computed
};

/**
 * Regtest ConsensusTestingSetup with the pre-fork fork height, mock time at
 * START_TIME, a fixed key (deterministic blocks and signatures) and the
 * genesis stake modifier a pre-fork node computes (0, generated). Do not
 * use the inherited TestChain: the chain here is built with ProcessNewBlock.
 */
struct PosChainSetup : public ConsensusTestingSetup {
    PosChainSetup();

    CKey key;
    CBasicKeyStore keystore;

    /** P2PK script of key (CheckBlockSignature needs TX_PUBKEY). */
    CScript Script() const;

    /** A PoW block on parent at nTime: coinbase with the height and nSalt
     *  in its scriptSig, paying GetProofOfWorkReward to Script(); nBits =
     *  GetNextTargetRequired(parent, false); nonce ground. */
    CBlock MinePowBlock(const CBlockIndex* parent, int64_t nTime, unsigned char nSalt = 0) const;

    /** Raise mock time to the block time (never lowers it) and call
     *  ProcessNewBlock. Returns the block's index entry or nullptr if it is
     *  not in mapBlockIndex. *pfAccepted gets ProcessNewBlock's result. */
    CBlockIndex* Submit(const CBlock& block, bool fForceProcessing = true, bool* pfNewBlock = nullptr, bool* pfAccepted = nullptr);

    /** n PoW blocks on the active tip, nSpacing seconds apart (the first at
     *  START_TIME if the tip is the genesis, else tip time + nSpacing).
     *  Requires every block to be accepted; returns the new tip. */
    CBlockIndex* MinePowChain(int n, int64_t nSpacing = BLOCK_SPACING);

    /** Mark a and b (ancestor first, both above the genesis) as PoS index
     *  entries, standing in for the two hard-coded mainnet PoS blocks.
     *  Their bnChainTrust is left as computed for PoW. */
    void SeedProofOfStakeHistory(CBlockIndex* a, CBlockIndex* b);

    /** Grind the kernel time for prevout (an output of a transaction in the
     *  tx index) on top of pindexPrev, trying each second from the first
     *  valid one (> pindexPrev time, > txPrev time, blockFrom + min age <=
     *  time, >= nTimeFrom). Uses a copy of the stake-modifier walk and the
     *  node's GetProofOfStakeHash, then confirms the result with the node's
     *  CheckStakeKernelHash. Throws std::runtime_error when no kernel is
     *  found within nMaxTries or the node disagrees. */
    Kernel FindKernel(CBlockIndex* pindexPrev, const COutPoint& prevout, unsigned int nBits,
                      int64_t nTimeFrom = 0, uint64_t nMaxTries = DEFAULT_MAX_TRIES) const;

    /** Coinstake for the kernel: vin[0] = prevout signed with key,
     *  vout[0] empty, vout[1] = stake value + nReward to Script(),
     *  nTime = kernel time. */
    CTransaction CreateCoinstake(const Kernel& kernel, int64_t nReward = 0) const;

    /** PoS block on pindexPrev: coinbase (height, nSalt) with one empty
     *  output, the coinstake, nBits = kernel.nBits, nNonce 0, nTime =
     *  kernel time, signed with key. */
    CBlock CreatePosBlock(const CBlockIndex* pindexPrev, const Kernel& kernel, unsigned char nSalt = 0) const;

    /** FindKernel with nBits = GetNextTargetRequired(pindexPrev, true),
     *  then CreatePosBlock. pkernel receives the kernel if not null. */
    CBlock GeneratePosBlock(CBlockIndex* pindexPrev, const COutPoint& prevout, unsigned char nSalt = 0,
                            Kernel* pkernel = nullptr) const;

    /** Output 0 of the coinbase of the active block at nHeight. */
    COutPoint CoinbaseOutPoint(int nHeight) const;
};

} // namespace synthetic_pos

#endif // YACOIN_TEST_POS_GENERATOR_H
