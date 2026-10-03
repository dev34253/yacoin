// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Consensus test harness (task P0-47).
//
// One way for consensus unit tests to
//  - set the consensus globals explicitly and get them restored afterwards
//    (ScopedConsensusGlobals),
//  - build CBlockIndex chains in mapBlockIndex / chainActive (TestChain),
//  - put blocks on disk for ReadBlockFromDisk (WriteBlockToTestFile,
//    TestChain::StartOnExistingGenesis / AppendBlock),
//  - load index chains from the index-chain CSV format (LoadIndexChainCsv).
//
// Test-only code: nothing here changes consensus behaviour. See
// src/test/README.md for usage, the CSV format and the limitations.

#ifndef YACOIN_TEST_CONSENSUS_HARNESS_H
#define YACOIN_TEST_CONSENSUS_HARNESS_H

#include "bignum.h"
#include "chain.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "test/test_bitcoin.h"
#include "uint256.h"

#include <cstdint>
#include <deque>
#include <istream>
#include <memory>
#include <string>

namespace consensus_harness {

// Defaults that AppInit uses for a mainnet node. The originals are file-static
// in init.cpp (mainnetNewLogicBlockNumber, tokenSupportBlockNumber at
// init.cpp:72-74; -nFactorAtHardfork and -epochinterval at init.cpp:858-860).
static const int32_t MAINNET_NEW_LOGIC_BLOCK_NUMBER = 1890000;
static const int32_t MAINNET_TOKEN_SUPPORT_BLOCK_NUMBER = 1911210;
static const unsigned char MAINNET_N_FACTOR_AT_HARDFORK = 21;
static const uint32_t MAINNET_EPOCH_INTERVAL = 21000;
// Values the functional test framework writes to yacoin.conf
// (test/functional/test_framework/util.py:347-353).
static const unsigned char FUNCTIONAL_N_FACTOR_AT_HARDFORK = 4;
static const uint32_t FUNCTIONAL_EPOCH_INTERVAL = 10;
// Compiled-in value of nYac10HardforkTime (util.cpp:578).
static const int64_t DEFAULT_YAC10_HARDFORK_TIME = 1619048730;

/** Snapshot of every mutable global that consensus code reads. */
struct ConsensusGlobals {
    int32_t nMainnetNewLogicBlockNumber;
    int32_t nTokenSupportBlockNumber;
    unsigned char nFactorAtHardfork;
    uint32_t nEpochInterval;
    uint32_t nDifficultyInterval;
    bool fTestNet;
    int64_t nYac10HardforkTime;
    int64_t nMockTime;

    /** Read the current values of the globals. */
    static ConsensusGlobals Capture();
    /** Write these values to the globals. */
    void Apply() const;
    bool operator==(const ConsensusGlobals& o) const;
    bool operator!=(const ConsensusGlobals& o) const { return !(*this == o); }
    std::string ToString() const;
};

/**
 * Saves the consensus globals on construction and restores them on
 * destruction (also when the test fails or throws). The setters change the
 * real globals; every change is reported with BOOST_TEST_MESSAGE.
 */
class ScopedConsensusGlobals {
public:
    ScopedConsensusGlobals();
    ~ScopedConsensusGlobals();
    ScopedConsensusGlobals(const ScopedConsensusGlobals&) = delete;
    ScopedConsensusGlobals& operator=(const ScopedConsensusGlobals&) = delete;

    const ConsensusGlobals& Saved() const { return saved; }

    void SetNewLogicBlockNumber(int32_t nHeight);
    void SetTokenSupportBlockNumber(int32_t nHeight);
    void SetNFactorAtHardfork(unsigned char nFactor);
    /** Sets nEpochInterval and nDifficultyInterval, like AppInit does. */
    void SetEpochInterval(uint32_t nInterval);
    /** Sets nDifficultyInterval only. */
    void SetDifficultyInterval(uint32_t nInterval);
    void SetTestNet(bool fTestNetIn);
    void SetYac10HardforkTime(int64_t nTime);
    /** SetMockTime(); 0 means real time. */
    void SetMockTime(int64_t nTime);

    /** What test_bitcoin has without AppInit: fork height 0, token height 0,
     *  N-factor 0, epoch 21000, mainnet, default nYac10HardforkTime. Mock
     *  time is not changed. */
    void UseUnitTestGlobals();
    /** Mainnet node: fork 1,890,000, token 1,911,210, N-factor 21, epoch
     *  21000. Mock time is not changed. */
    void UseMainnetGlobals();
    /** Functional tests: epoch 10, N-factor 4, fork height as given (the
     *  framework passes -testnetNewLogicBlockNumber per test). Token height
     *  stays at the mainnet default, as in the framework (only the token
     *  tests pass -tokenSupportBlockNumber). */
    void UseFunctionalTestGlobals(int32_t nForkHeight);

private:
    const ConsensusGlobals saved;
};

/** Fields of one synthetic block index entry. Defaults: PoW, version 6,
 *  everything else 0/null. */
struct BlockSpec {
    int64_t nTime = 0;
    uint32_t nBits = 0;
    int32_t nVersion = 6;
    uint32_t nNonce = 0;
    uint256 hashMerkleRoot;
    bool fProofOfStake = false;
    unsigned int nEntropyBit = 0;
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    uint256 hashProofOfStake;
    COutPoint prevoutStake;
    uint32_t nStakeTime = 0;
    /** Block hash; null = a deterministic synthetic hash. */
    uint256 hash;
    /** Height; -1 = pprev height + 1 (0 without pprev). Only used for an
     *  entry without pprev (segment start). */
    int32_t nHeight = -1;

    BlockSpec() {}
    BlockSpec(int64_t nTimeIn, uint32_t nBitsIn, bool fPoS = false)
        : nTime(nTimeIn), nBits(nBitsIn), fProofOfStake(fPoS) {}
};

/**
 * Builds CBlockIndex chains for tests.
 *
 * Entries are owned by the TestChain and inserted into mapBlockIndex.
 * bnChainTrust, nTimeMax and pskip are computed like AddToBlockIndex
 * (validation.cpp:2905); flags, entropy bit and stake fields come from the
 * BlockSpec. A chain may start above height 0 (a segment, pprev == nullptr):
 * then pskip pointers that would point below the segment are null,
 * chainActive.Genesis() and chainActive[h] below the segment are null after
 * SetActiveTip() (it clears chainActive first), and node code that
 * calls GetAncestor() below the segment asserts. On destruction chainActive is set back to the tip it had before
 * the first SetActiveTip() and all own entries are removed from
 * mapBlockIndex. pindexBestHeader, setBlockIndexCandidates and the block tree
 * database are never touched, so do not mix TestChain with
 * ProcessNewBlock/ActivateBestChain in one test.
 */
class TestChain {
public:
    /** nSalt makes the synthetic hashes of two chains in one test differ. */
    explicit TestChain(uint32_t nSalt = 0);
    ~TestChain();
    TestChain(const TestChain&) = delete;
    TestChain& operator=(const TestChain&) = delete;

    /** Use the genesis entry that LoadGenesisBlock put in mapBlockIndex (the
     *  real genesis of the selected params, on disk) as the first block.
     *  The entry is not owned and not modified. Throws if it is missing or
     *  the chain is not empty. */
    CBlockIndex* StartOnExistingGenesis();

    /** Append on the current tip (or start the chain if it is empty). */
    CBlockIndex* Append(const BlockSpec& spec);
    /** Append on any entry (forks); prev == nullptr starts a segment at
     *  spec.nHeight (default 0). */
    CBlockIndex* Append(CBlockIndex* prev, const BlockSpec& spec);
    /** Append n entries on the tip, nSpacing seconds apart (the first one
     *  nSpacing after the tip; at nFirstTime if the chain is empty), all
     *  with nBits and the same PoS flag. Returns the new tip. */
    CBlockIndex* AppendMany(int n, int64_t nSpacing, uint32_t nBits, bool fProofOfStake = false, int64_t nFirstTime = 0);
    /** Append an index entry for a real block, made like AddToBlockIndex
     *  does (CBlockIndex(header), hash = block.GetHash(), entropy bit from
     *  the block). Links to block.hashPrevBlock when that is in
     *  mapBlockIndex, otherwise starts a segment at nSegmentHeight. With
     *  fWriteToDisk the block is written with WriteBlockToTestFile and the
     *  entry gets nFile/nDataPos/BLOCK_HAVE_DATA. */
    CBlockIndex* AppendBlock(const CBlock& block, bool fWriteToDisk, int32_t nSegmentHeight = 0);

    /** Point chainActive at pindex (any entry, own or not). chainActive is
     *  cleared first, so heights below a segment start are null. */
    void SetActiveTip(CBlockIndex* pindex);

    /** Last appended entry (or the genesis from StartOnExistingGenesis);
     *  nullptr when empty. */
    CBlockIndex* Tip() const { return pindexTip; }
    /** Entry at nHeight on the path from Tip() back; nullptr if none (also
     *  below the start of a segment, where CBlockIndex::GetAncestor would
     *  assert). */
    CBlockIndex* AtHeight(int nHeight) const;
    /** Number of entries created by this chain (excludes a borrowed genesis). */
    size_t size() const { return entries.size(); }

private:
    uint256 NextSyntheticHash();
    CBlockIndex* Insert(std::unique_ptr<CBlockIndex> pindex, const uint256& hash, CBlockIndex* prev, int32_t nSegmentHeight);

    const uint32_t nSalt;
    uint64_t nCounter;
    std::deque<std::unique_ptr<CBlockIndex>> entries;
    CBlockIndex* pindexTip;
    bool fChangedActiveChain;
    CBlockIndex* pindexSavedActiveTip;
};

/** File number used by WriteBlockToTestFile (blocks/blk09000.dat). */
static const int TEST_BLOCK_FILE = 9000;

/** Append block to blocks/blk09000.dat in the data directory in the node's
 *  on-disk format (message start, size, block) and return its position for
 *  ReadBlockFromDisk. Throws on I/O errors. Needs a data directory
 *  (TestingSetup). The block-hash index is not written. */
CDiskBlockPos WriteBlockToTestFile(const CBlock& block);

/**
 * Index-chain CSV loader (format in src/test/README.md). Appends one entry
 * per row to chain and returns the last one (nullptr for no rows). Throws
 * std::runtime_error("<name>:<line>: ...") on any format error. The first
 * row links to prev_hash when that hash is in mapBlockIndex, otherwise it
 * starts a segment at its height.
 */
CBlockIndex* LoadIndexChainCsv(std::istream& in, TestChain& chain, const std::string& name = "csv");
CBlockIndex* LoadIndexChainCsvFile(const std::string& path, TestChain& chain);

} // namespace consensus_harness

/**
 * Fixture for consensus unit tests: TestingSetup (temporary data directory,
 * the real genesis on disk, chainActive at genesis) plus the global-state
 * guard and one TestChain. Members are destroyed before TestingSetup, the
 * chain first: chainActive and mapBlockIndex are restored, then the globals.
 */
struct ConsensusTestingSetup : public TestingSetup {
    consensus_harness::ScopedConsensusGlobals globals;
    consensus_harness::TestChain chain;

    explicit ConsensusTestingSetup(const std::string& chainName = CBaseChainParams::MAIN);
};

#endif // YACOIN_TEST_CONSENSUS_HARNESS_H
