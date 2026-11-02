// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The legacy proof-of-stake code of kernel.cpp: coin weight, the stake modifier and its
// checksum and checkpoints, the kernel hash and the proof-of-stake check of a coinstake.
//
// The tests run on the main network with the fork height at 1890000 and an active tip far
// below it, so the stake modifier code runs as it does for the historical chain. Block index
// entries are synthetic (SyntheticChain); the kernel tests use real mainnet blocks.

#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "kernel.h"
#include "streams.h"
#include "timedata.h"
#include "timestamps.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
#include "data/stake_modifier_blocks.raw.h"
#endif

#include <algorithm>
#include <functional>
#include <map>

#include <boost/test/unit_test.hpp>

// Defined in kernel.cpp, not declared in kernel.h
uint256 GetProofOfStakeHash(::uint64_t nStakeModifier, ::uint32_t nTimeBlockFrom, ::uint32_t nTxPrevOffset,
                            ::uint32_t nTxPrevTime, ::uint32_t nPrevoutn, ::uint32_t nTimeTx, ::uint64_t nCoinDayWeight);

namespace {

const ::int64_t DAY = 24 * 60 * 60;
const ::int64_t MODIFIER_INTERVAL = 6 * 60 * 60;
// Sum of the 64 selection interval sections (7200 s for the first, 21600 s for the last)
const ::int64_t SELECTION_INTERVAL = 761920;
const unsigned int POW_BITS = 0x1e0fffff;

/** Sets the fork height above the genesis block before the chain is loaded */
struct StakeForkHeight {
    ConsensusGlobalsGuard globals;
    StakeForkHeight() { globals.Set(1890000, 21000); }
};

/** Main network, fork height 1890000: the genesis block gets its stake modifier when it is
 * loaded, as on a node */
struct KernelSetup : public StakeForkHeight, public TestingSetup {
    KernelSetup() : StakeForkHeight(), TestingSetup(CBaseChainParams::MAIN) {}
};

/** Sets a variable while it lives */
template <typename T>
struct ValueGuard {
    T& m_ref;
    T m_saved;
    ValueGuard(T& ref, T value) : m_ref(ref), m_saved(ref) { ref = value; }
    ~ValueGuard() { m_ref = m_saved; }
};

/** -debug and -printstakemodifier on while it lives */
struct StakeLogGuard {
    ValueGuard<bool> debug{fDebug, true};
    StakeLogGuard() { gArgs.ForceSetArg("-printstakemodifier", "1"); }
    ~StakeLogGuard() { gArgs.ForceSetArg("-printstakemodifier", "0"); }
};

struct MockTimeGuard {
    explicit MockTimeGuard(::int64_t nTime) { SetMockTime(nTime); }
    ~MockTimeGuard() { SetMockTime(0); }
};

struct Modifier {
    ::uint64_t nModifier;
    bool fGenerated;
};

/** ComputeNextStakeModifier for pindex, once quiet and once with its log lines; both runs
 * must agree */
Modifier Compute(const CBlockIndex* pindex)
{
    // ComputeNextStakeModifier sets both outputs, whatever they held before
    Modifier quiet{0xdeadbeef, true};
    BOOST_REQUIRE(ComputeNextStakeModifier(pindex, quiet.nModifier, quiet.fGenerated));
    Modifier logged{0xdeadbeef, true};
    {
        StakeLogGuard log;
        BOOST_REQUIRE(ComputeNextStakeModifier(pindex, logged.nModifier, logged.fGenerated));
    }
    BOOST_CHECK_EQUAL(quiet.nModifier, logged.nModifier);
    BOOST_CHECK_EQUAL(quiet.fGenerated, logged.fGenerated);
    return quiet;
}

/** A registered block index entry on top of pprev (nullptr: genesis) with the given entropy bit */
CBlockIndex* AddBlock(SyntheticChain& chain, CBlockIndex* pprev, ::int64_t nTime, unsigned int nEntropyBit = 1)
{
    CBlockIndex* pindex = chain.Add(pprev, nTime, POW_BITS);
    chain.Register(pindex);
    pindex->SetStakeEntropyBit(nEntropyBit);
    return pindex;
}

/** AddBlock with a generated stake modifier */
CBlockIndex* AddModifier(SyntheticChain& chain, CBlockIndex* pprev, ::int64_t nTime, ::uint64_t nModifier)
{
    CBlockIndex* pindex = AddBlock(chain, pprev, nTime, 0);
    pindex->SetStakeModifier(nModifier, true);
    return pindex;
}

// The parent of the block whose modifier is computed lies in the modifier interval starting at
// BUCKET; the candidates for a new modifier are the blocks from WINDOW_START on.
const ::int64_t BUCKET = 64000 * MODIFIER_INTERVAL;
const ::int64_t WINDOW_START = BUCKET - SELECTION_INTERVAL;
const ::uint64_t PREVIOUS_MODIFIER = 0x2222222222222222;

/** A generated modifier before the window, then n candidates spread evenly from WINDOW_START
 * to BUCKET + 100 (the last one is the parent), with the entropy bits and proof-of-stake flags
 * given per candidate; returns the parent */
CBlockIndex* BuildCandidates(SyntheticChain& chain, int n, std::function<unsigned int(int)> entropyBit,
                             std::function<bool(int)> proofOfStake = nullptr)
{
    CBlockIndex* pindex = AddModifier(chain, nullptr, WINDOW_START - 5000, PREVIOUS_MODIFIER);
    const ::int64_t nSpacing = (BUCKET + 100 - WINDOW_START) / (n - 1);
    for (int i = 0; i < n; i++) {
        const ::int64_t nTime = (i == n - 1) ? BUCKET + 100 : WINDOW_START + i * nSpacing;
        pindex = AddBlock(chain, pindex, nTime, entropyBit(i));
        if (proofOfStake && proofOfStake(i)) {
            pindex->SetProofOfStake();
            pindex->hashProofOfStake = uint256(0x9000 + i);
        }
    }
    return pindex;
}

// Mainnet data, read from a node over RPC (getblock <hash> false): block 644, whose coinbase
// is the coin staked in block 82204, the lowest proof-of-stake block, and block 82204. The kernel
// of 82204 uses the stake modifier of block 64327.
const char* BLOCK_644_HEX =
    "030000004c06edad08eaa0057278e7ad7131c12f7b2aa16c4de2e07866c74f8aaf0b0000f4ed0aafca5b6b9db4708956ec463f"
    "c37910538d31f673856ea2b6450188cc37b5fe895101310e1e901900000101000000b5fe89510100000000000000000000000000"
    "00000000000000000000000000000000000000ffffffff0c028402010e062f503253482fffffffff01a0aad70500000000232103"
    "54c0e1446ae9bd305ae8899a009a44775a31ce0292cad8f6bee00d7263b59685ac00000000473045022065d7bafd8338278ce26a"
    "ed9c92874f0b99a62306b723f27032cd2b90bddea8ee022100a44ac0e94ea3a6faa47c61c43c67e7d7c66689a244072521dca3e6"
    "ee7c068613";
const char* BLOCK_82204_HEX =
    "0300000091c426b67f34fc33154c1358b76773f504d0d6c9fd0b4c9b34686f1e00000000015a4f248441475b271acbec093226615e"
    "e24d731f721ae8f847841a4d1864fb5b91b151ffff0f1e0000000002010000005b91b1510100000000000000000000000000000000"
    "00000000000000000000000000000000ffffffff0d031c41010138062f503253482fffffffff01000000000000000000000000000100"
    "00005b91b15101f4ed0aafca5b6b9db4708956ec463fc37910538d31f673856ea2b6450188cc37000000004a493046022100e64452"
    "8196f915becc4d2f96e7f166b3c44ad6ce3796be9f919cf473385990b9022100e66d0a45296da31dde405372c91450ffc910a9d7c4"
    "bea4235344e14271f4c3b001ffffffff0300000000000000000090e2ee020000000023210354c0e1446ae9bd305ae8899a009a4477"
    "5a31ce0292cad8f6bee00d7263b59685ac90e2ee020000000023210354c0e1446ae9bd305ae8899a009a44775a31ce0292cad8f6be"
    "e00d7263b59685ac00000000463044022009ff758e92a00c8c9843792ff0054672ba8d3030c619731529ce8a5f86050a7a02205460"
    "2b91e6cefb63579cc455eb47bef4c3b8c510ce0a287afd98efa0a4bc2095";
const ::int64_t MODIFIER_64327_TIME = 1368770430;
const ::uint64_t MODIFIER_64327 = 0x79867109da3e3e5d;
const ::int64_t BLOCK_82203_TIME = 1370591604;
const unsigned int BITS_82204 = 0x1e0fffff;
const char* PROOF_HASH_82204 = "00000a65a901336eddd0e26e44b9fc42e498cc596563f0c4ad441c813ce2e5c2";
// The coin is the first transaction of block 644: after the 80-byte header and the
// one-byte transaction count
const unsigned int TX_PREV_OFFSET = 81;

CBlock ParseBlock(const char* hex)
{
    CDataStream ss(ParseHex(hex), SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    ss >> block;
    return block;
}

/** Blocks 644 and 82204 */
struct RealKernel {
    CBlock blockFrom = ParseBlock(BLOCK_644_HEX);
    CBlock blockStake = ParseBlock(BLOCK_82204_HEX);
    const CTransaction& txPrev() const { return blockFrom.vtx[0]; }
    const CTransaction& coinstake() const { return blockStake.vtx[1]; }
};

/** Index entries for a kernel whose coin is in blockFrom */
struct KernelChain {
    CBlockIndex* pindexFrom = nullptr;
    CBlockIndex* pindexModifier = nullptr;
    CBlockIndex* pindexPrev = nullptr;
};

/** blockFrom under its real hash, then one entry a day up to nTimeEnd (the last entry, the
 * coinstake's parent); the entry a day after blockFrom has a generated modifier too early for
 * the kernel, and an entry at block 64327's time (if before nTimeEnd) has 64327's modifier */
KernelChain BuildKernelChain(SyntheticChain& chain, const CBlockHeader& blockFrom, ::int64_t nTimeEnd)
{
    std::vector< ::int64_t> vTimes;
    for (::int64_t nTime = blockFrom.GetBlockTime() + DAY; nTime < nTimeEnd; nTime += DAY) vTimes.push_back(nTime);
    if (MODIFIER_64327_TIME < nTimeEnd) vTimes.push_back(MODIFIER_64327_TIME);
    vTimes.push_back(nTimeEnd);
    std::sort(vTimes.begin(), vTimes.end());

    KernelChain k;
    k.pindexFrom = chain.Add(nullptr, blockFrom.GetBlockTime(), blockFrom.nBits);
    chain.Register(k.pindexFrom, blockFrom.GetHash());
    CBlockIndex* pindex = k.pindexFrom;
    for (::int64_t nTime : vTimes) {
        pindex = AddBlock(chain, pindex, nTime);
        if (nTime == blockFrom.GetBlockTime() + DAY) pindex->SetStakeModifier(0x5e5e5e5e5e5e5e5e, true);
        if (nTime == MODIFIER_64327_TIME) {
            pindex->SetStakeModifier(MODIFIER_64327, true);
            k.pindexModifier = pindex;
        }
    }
    k.pindexPrev = pindex;
    return k;
}

struct KernelResult {
    bool fPass;
    uint256 hashProof;
    uint256 target;
};

KernelResult CheckKernel(const RealKernel& real, CBlockIndex* pindexPrev, unsigned int nBits, ::uint32_t nTimeTx,
                         bool fPrintProofOfStake = false)
{
    KernelResult result;
    result.fPass = CheckStakeKernelHash(nBits, pindexPrev, real.blockFrom, TX_PREV_OFFSET, real.txPrev(),
                                        real.coinstake().vin[0].prevout, nTimeTx, result.hashProof, result.target,
                                        fPrintProofOfStake);
    return result;
}

/** Writes a block to block file nFile (at its start, after the network magic and size) */
CDiskBlockPos WriteBlockFile(const CBlock& block, int nFile)
{
    CDiskBlockPos pos(nFile, 0);
    CAutoFile file(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    BOOST_REQUIRE(!file.IsNull());
    file << FLATDATA(Params().MessageStart()) << (unsigned int)GetSerializeSize(file, block);
    pos.nPos = (unsigned int)ftell(file.Get());
    file << block;
    return pos;
}

/** Points the transaction index entry of the block's first transaction at the block */
void IndexFirstTx(const CBlock& block, const CDiskBlockPos& pos)
{
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.emplace_back(block.vtx[0].GetHash(), CDiskTxPos(pos, GetSizeOfCompactSize(block.vtx.size())));
    BOOST_REQUIRE(pblocktree->WriteTxIndex(vPos));
}

// Stake modifiers of a chain given by block hashes and times, from the genesis block on.
// A row is 36 bytes: the hash in its internal byte order, then the time as 4 bytes, little-endian.
const size_t ROW_SIZE = 36;

struct HashTimeRow {
    uint256 hash;
    ::uint32_t nTime;
};

std::vector<HashTimeRow> ReadRows(const unsigned char* data, size_t nSize)
{
    BOOST_REQUIRE_EQUAL(nSize % ROW_SIZE, 0U);
    CDataStream ss(std::vector<unsigned char>(data, data + nSize), SER_DISK, CLIENT_VERSION);
    std::vector<HashTimeRow> rows;
    while (!ss.empty()) {
        HashTimeRow row;
        ss >> row.hash >> row.nTime;
        rows.push_back(row);
    }
    return rows;
}

struct StakeModifierEntry {
    ::uint64_t nModifier;
    bool fGenerated;
    ::uint32_t nChecksum;
};

/** Builds the block index of rows (rows[0] is the genesis block) and computes every block's
 * modifier and checksum as ReceivedBlockTransactions does; the entropy bit is the hash's lowest
 * bit, as AddToBlockIndex sets it. Every row is a proof-of-work block. */
std::vector<StakeModifierEntry> ComputeModifiers(SyntheticChain& chain, const std::vector<HashTimeRow>& rows)
{
    BOOST_REQUIRE(!rows.empty());
    CBlockIndex* pindex = chain.Genesis();
    BOOST_REQUIRE(rows[0].hash == pindex->GetBlockHash());
    BOOST_REQUIRE_EQUAL(rows[0].nTime, pindex->GetBlockTime());

    std::vector<StakeModifierEntry> entries;
    // The genesis entry got its modifier when it was loaded
    Modifier genesis = Compute(pindex);
    BOOST_REQUIRE_EQUAL(genesis.nModifier, pindex->nStakeModifier);
    BOOST_REQUIRE_EQUAL(genesis.fGenerated, pindex->GeneratedStakeModifier());
    BOOST_REQUIRE_EQUAL(GetStakeModifierChecksum(pindex), pindex->nStakeModifierChecksum);
    entries.push_back({pindex->nStakeModifier, pindex->GeneratedStakeModifier(), pindex->nStakeModifierChecksum});

    for (size_t i = 1; i < rows.size(); i++) {
        // nBits does not enter the modifier
        pindex = chain.Add(pindex, rows[i].nTime, POW_BITS);
        chain.Register(pindex, rows[i].hash);
        pindex->SetStakeEntropyBit(rows[i].hash.Get64() & 1);
        StakeModifierEntry entry;
        BOOST_REQUIRE(ComputeNextStakeModifier(pindex, entry.nModifier, entry.fGenerated));
        pindex->SetStakeModifier(entry.nModifier, entry.fGenerated);
        pindex->nStakeModifierChecksum = entry.nChecksum = GetStakeModifierChecksum(pindex);
        entries.push_back(entry);
    }
    return entries;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(kernel_tests, KernelSetup)

/* Coin weight: 0 at the minimum age of 30 days, one second per second after it, at most 90 days */
BOOST_AUTO_TEST_CASE(weight)
{
    const ::int64_t nStart = 1370000000;
    BOOST_CHECK_EQUAL(GetWeight(nStart, nStart + 29 * DAY), -DAY);
    BOOST_CHECK_EQUAL(GetWeight(nStart, nStart + 30 * DAY), 0);
    BOOST_CHECK_EQUAL(GetWeight(nStart, nStart + 30 * DAY + 1), 1);
    BOOST_CHECK_EQUAL(GetWeight(nStart, nStart + 45 * DAY), 15 * DAY);
    BOOST_CHECK_EQUAL(GetWeight(nStart, nStart + 120 * DAY - 1), 90 * DAY - 1);
    BOOST_CHECK_EQUAL(GetWeight(nStart, nStart + 120 * DAY), 90 * DAY);
    BOOST_CHECK_EQUAL(GetWeight(nStart, nStart + 400 * DAY), 90 * DAY);
}

/* The fixed modifier interval starts at the switch time (2055-11-12), on both networks */
BOOST_AUTO_TEST_CASE(fixed_modifier_interval)
{
    BOOST_CHECK_EQUAL(nModifierSwitchTime, 2709614280U);
    BOOST_CHECK(!IsFixedModifierInterval(1370591579));
    BOOST_CHECK(!IsFixedModifierInterval(nModifierSwitchTime - 1));
    BOOST_CHECK(IsFixedModifierInterval(nModifierSwitchTime));
    BOOST_CHECK(IsFixedModifierInterval(0xffffffff));

    ValueGuard<bool> testnet(fTestNet, true);
    BOOST_CHECK_EQUAL(nModifierTestSwitchTime, 2709614280U);
    BOOST_CHECK(!IsFixedModifierInterval(nModifierTestSwitchTime - 1));
    BOOST_CHECK(IsFixedModifierInterval(nModifierTestSwitchTime));
}

/* The genesis block's modifier is 0, generated */
BOOST_AUTO_TEST_CASE(modifier_genesis)
{
    const CBlockIndex* pindexGenesis = chainActive.Genesis();
    Modifier modifier = Compute(pindexGenesis);
    BOOST_CHECK_EQUAL(modifier.nModifier, 0U);
    BOOST_CHECK(modifier.fGenerated);
}

/* While the parent is in the modifier interval of the last generated modifier, the block keeps
 * that modifier, found by walking back over entries without one */
BOOST_AUTO_TEST_CASE(modifier_same_interval)
{
    SyntheticChain chain;
    CBlockIndex* pindexModifier = AddModifier(chain, nullptr, BUCKET + 10, PREVIOUS_MODIFIER);

    Modifier modifier = Compute(AddBlock(chain, pindexModifier, BUCKET + 20));
    BOOST_CHECK_EQUAL(modifier.nModifier, PREVIOUS_MODIFIER);
    BOOST_CHECK(!modifier.fGenerated);

    CBlockIndex* pindex = AddBlock(chain, pindexModifier, BUCKET + 30);
    pindex = AddBlock(chain, pindex, BUCKET + MODIFIER_INTERVAL - 1);
    // The block itself may be in the next interval
    modifier = Compute(AddBlock(chain, pindex, BUCKET + MODIFIER_INTERVAL + 5));
    BOOST_CHECK_EQUAL(modifier.nModifier, PREVIOUS_MODIFIER);
    BOOST_CHECK(!modifier.fGenerated);
}

/* Once the parent is in a later interval a new modifier is generated, one round per candidate:
 * the candidates are the blocks from the window start on (here 4, all with entropy bit 1) */
BOOST_AUTO_TEST_CASE(modifier_new_interval_few_candidates)
{
    SyntheticChain chain;
    CBlockIndex* pindex = AddModifier(chain, nullptr, WINDOW_START - 5000, PREVIOUS_MODIFIER);
    pindex = AddBlock(chain, pindex, WINDOW_START - 1); // outside the window
    pindex = AddBlock(chain, pindex, WINDOW_START);     // inside
    pindex = AddBlock(chain, pindex, WINDOW_START + 1000);
    pindex = AddBlock(chain, pindex, BUCKET - 1000);
    pindex = AddBlock(chain, pindex, BUCKET + 100);
    Modifier modifier = Compute(AddBlock(chain, pindex, BUCKET + 200));
    BOOST_CHECK_EQUAL(modifier.nModifier, 0xfU);
    BOOST_CHECK(modifier.fGenerated);

    // The same with the parent in the last generated modifier's interval + 1
    SyntheticChain chain2;
    pindex = AddModifier(chain2, nullptr, BUCKET - 10, PREVIOUS_MODIFIER);
    pindex = AddBlock(chain2, pindex, BUCKET + 100, 1);
    modifier = Compute(AddBlock(chain2, pindex, BUCKET + 200));
    // Candidates: the modifier's block (bit 0) and the parent (bit 1); the first round's section
    // holds only the modifier's block
    BOOST_CHECK_EQUAL(modifier.nModifier, 0x2U);
    BOOST_CHECK(modifier.fGenerated);
}

/* With 64 or more candidates there are 64 rounds; one modifier value pinned */
BOOST_AUTO_TEST_CASE(modifier_new_interval_64_rounds)
{
    SyntheticChain chain;
    CBlockIndex* pindexPrev = BuildCandidates(chain, 70, [](int) { return 1U; });
    Modifier modifier = Compute(AddBlock(chain, pindexPrev, BUCKET + 200));
    BOOST_CHECK_EQUAL(modifier.nModifier, 0xffffffffffffffffULL);
    BOOST_CHECK(modifier.fGenerated);

    // Exactly 64
    pindexPrev = BuildCandidates(chain, 64, [](int) { return 1U; });
    modifier = Compute(AddBlock(chain, pindexPrev, BUCKET + 200));
    BOOST_CHECK_EQUAL(modifier.nModifier, 0xffffffffffffffffULL);

    // Today's selection: entropy bit 1 on every third candidate
    pindexPrev = BuildCandidates(chain, 70, [](int i) { return i % 3 == 0 ? 1U : 0U; });
    modifier = Compute(AddBlock(chain, pindexPrev, BUCKET + 200));
    BOOST_CHECK_EQUAL(modifier.nModifier, 0x4049249249249249ULL);
    BOOST_CHECK(modifier.fGenerated);

    // Proof-of-stake candidates (the selection map of the log marks those not selected)
    pindexPrev = BuildCandidates(chain, 70, [](int) { return 1U; }, [](int) { return true; });
    modifier = Compute(AddBlock(chain, pindexPrev, BUCKET + 200));
    BOOST_CHECK_EQUAL(modifier.nModifier, 0xffffffffffffffffULL);
}

/* The selection favours proof-of-stake candidates: their selection hash (from hashProofOfStake)
 * is divided by 2^32, so the one proof-of-stake candidate is selected in the first round */
BOOST_AUTO_TEST_CASE(modifier_favours_proof_of_stake)
{
    SyntheticChain chain;
    // 11 candidates in the first round's section (7200 s from the window start) and the parent;
    // only candidate 6 has entropy bit 1
    auto build = [&chain](bool fProofOfStake) {
        CBlockIndex* pindex = AddModifier(chain, nullptr, WINDOW_START - 5000, PREVIOUS_MODIFIER);
        for (int i = 0; i < 11; i++) {
            pindex = AddBlock(chain, pindex, WINDOW_START + 600 * i, i == 6 ? 1 : 0);
            if (i == 6 && fProofOfStake) {
                pindex->SetProofOfStake();
                pindex->hashProofOfStake = uint256S("0x77");
            }
        }
        pindex = AddBlock(chain, pindex, BUCKET + 100, 0);
        return AddBlock(chain, pindex, BUCKET + 200);
    };
    Modifier modifier = Compute(build(true));
    BOOST_CHECK_EQUAL(modifier.nModifier, 0x1U);
    modifier = Compute(build(false));
    // As a proof-of-work candidate it is selected in the second round
    BOOST_CHECK_EQUAL(modifier.nModifier, 0x2U);
}

/* A block earlier than its parent, back in the last modifier's interval: before the fixed
 * interval's switch time a new modifier is computed, after it the old one is kept */
BOOST_AUTO_TEST_CASE(modifier_block_before_parent)
{
    SyntheticChain chain;
    CBlockIndex* pindexModifier = AddModifier(chain, nullptr, WINDOW_START - 5000, PREVIOUS_MODIFIER);
    CBlockIndex* pindexPrev = AddBlock(chain, pindexModifier, BUCKET + 100, 1);
    Modifier modifier = Compute(AddBlock(chain, pindexPrev, WINDOW_START - 4000));
    // One candidate, the parent
    BOOST_CHECK_EQUAL(modifier.nModifier, 0x1U);
    BOOST_CHECK(modifier.fGenerated);

    const ::int64_t nLateBucket = (nModifierSwitchTime / MODIFIER_INTERVAL + 2) * MODIFIER_INTERVAL;
    pindexModifier = AddModifier(chain, nullptr, nLateBucket + 10, PREVIOUS_MODIFIER);
    pindexPrev = AddBlock(chain, pindexModifier, nLateBucket + MODIFIER_INTERVAL + 10, 1);
    CBlockIndex* pindex = AddBlock(chain, pindexPrev, nLateBucket + 20);
    BOOST_CHECK(IsFixedModifierInterval(pindex->nTime));
    modifier = Compute(pindex);
    BOOST_CHECK_EQUAL(modifier.nModifier, PREVIOUS_MODIFIER);
    BOOST_CHECK(!modifier.fGenerated);
}

/* The checksum hashes the previous checksum, the flags, hashProofOfStake and the modifier
 * (known answer: the top 32 bits of the double SHA-256 of
 * struct.pack('<II', 0x12345678, 5) + hashProofOfStake + struct.pack('<Q', 0x0123456789abcdef),
 * computed with Python's hashlib) */
BOOST_AUTO_TEST_CASE(modifier_checksum)
{
    const CBlockIndex* pindexGenesis = chainActive.Genesis();
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(GetStakeModifierChecksum(pindexGenesis), 0x0e00670bU);
#else // the low-difficulty build has another genesis block
    BOOST_CHECK_EQUAL(GetStakeModifierChecksum(pindexGenesis), 0xfd11f4e7U);
#endif
    BOOST_CHECK_EQUAL(GetStakeModifierChecksum(pindexGenesis), pindexGenesis->nStakeModifierChecksum);

    SyntheticChain chain;
    CBlockIndex* pindexPrev = AddBlock(chain, nullptr, 1370000000);
    pindexPrev->nStakeModifierChecksum = 0x12345678;
    CBlockIndex* pindex = chain.Add(pindexPrev, 1370000060, POW_BITS);
    pindex->nFlags = CBlockIndex::BLOCK_PROOF_OF_STAKE | CBlockIndex::BLOCK_STAKE_MODIFIER;
    pindex->hashProofOfStake = uint256S("0x1111111111111111111111111111111111111111111111111111111111111122");
    pindex->nStakeModifier = 0x0123456789abcdef;
    const ::uint32_t nChecksum = GetStakeModifierChecksum(pindex);
    BOOST_CHECK_EQUAL(nChecksum, 0x615f1981U);

    // Every input changes it
    pindexPrev->nStakeModifierChecksum ^= 1;
    BOOST_CHECK(GetStakeModifierChecksum(pindex) != nChecksum);
    pindexPrev->nStakeModifierChecksum ^= 1;
    pindex->nFlags |= CBlockIndex::BLOCK_STAKE_ENTROPY;
    BOOST_CHECK(GetStakeModifierChecksum(pindex) != nChecksum);
    pindex->nFlags &= ~CBlockIndex::BLOCK_STAKE_ENTROPY;
    pindex->hashProofOfStake = uint256S("0x1111111111111111111111111111111111111111111111111111111111111123");
    BOOST_CHECK(GetStakeModifierChecksum(pindex) != nChecksum);
    pindex->hashProofOfStake = uint256S("0x1111111111111111111111111111111111111111111111111111111111111122");
    pindex->nStakeModifier ^= 1;
    BOOST_CHECK(GetStakeModifierChecksum(pindex) != nChecksum);
    pindex->nStakeModifier ^= 1;
    BOOST_CHECK_EQUAL(GetStakeModifierChecksum(pindex), nChecksum);
}

/* The checksum must match the checkpoint at a listed height; other heights pass */
BOOST_AUTO_TEST_CASE(modifier_checkpoints)
{
    const ::uint32_t nGenesisChecksum = chainActive.Genesis()->nStakeModifierChecksum;
    BOOST_CHECK(CheckStakeModifierCheckpoints(0, nGenesisChecksum));
    BOOST_CHECK(!CheckStakeModifierCheckpoints(0, nGenesisChecksum ^ 1));
    BOOST_CHECK(CheckStakeModifierCheckpoints(15000, 0x085e9caf));
    BOOST_CHECK(!CheckStakeModifierCheckpoints(15000, 0x085e9cae));
    BOOST_CHECK(CheckStakeModifierCheckpoints(712177, 0xad692cc0));
    BOOST_CHECK(!CheckStakeModifierCheckpoints(712177, 0));
    BOOST_CHECK(CheckStakeModifierCheckpoints(15001, 0));
    BOOST_CHECK(CheckStakeModifierCheckpoints(712178, 0x12345678));

    // Testnet's table has only height 0
    ValueGuard<bool> testnet(fTestNet, true);
    BOOST_CHECK(CheckStakeModifierCheckpoints(0, 0x0e00670b));
    BOOST_CHECK(!CheckStakeModifierCheckpoints(0, 0xfd11f4e7));
    BOOST_CHECK(CheckStakeModifierCheckpoints(15000, 0));
}

/* Modifiers and checksums block by block from (hash, time) rows; here 400 synthetic rows ten
 * minutes apart, far enough after the genesis block that it is never a candidate */
BOOST_AUTO_TEST_CASE(modifiers_from_rows)
{
    SyntheticChain chain;
    const CBlockIndex* pindexGenesis = chain.Genesis();
    std::vector<unsigned char> data;
    {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << pindexGenesis->GetBlockHash() << (::uint32_t)pindexGenesis->GetBlockTime();
        for (::uint32_t i = 1; i < 400; i++) {
            ss << Hash(BEGIN(i), END(i)) << (::uint32_t)(pindexGenesis->GetBlockTime() + 1000000 + 600 * i);
        }
        data.assign(ss.begin(), ss.end());
    }
    BOOST_REQUIRE_EQUAL(data.size(), 400 * ROW_SIZE);
    std::vector<HashTimeRow> rows = ReadRows(data.data(), data.size());
    BOOST_REQUIRE_EQUAL(rows.size(), 400U);
    std::vector<StakeModifierEntry> entries = ComputeModifiers(chain, rows);
    BOOST_REQUIRE_EQUAL(entries.size(), 400U);

    BOOST_CHECK_EQUAL(entries[0].nModifier, 0U);
    BOOST_CHECK(entries[0].fGenerated);
    BOOST_CHECK(CheckStakeModifierCheckpoints(0, entries[0].nChecksum));

    // A block generates a modifier when its parent is in a later interval than the last one;
    // the others keep the last modifier
    ::int64_t nLastModifierTime = rows[0].nTime;
    int nGenerated = 0;
    for (size_t i = 1; i < rows.size(); i++) {
        const bool fExpected = rows[i - 1].nTime / MODIFIER_INTERVAL > nLastModifierTime / MODIFIER_INTERVAL;
        BOOST_CHECK_EQUAL(entries[i].fGenerated, fExpected);
        if (entries[i].fGenerated) {
            nLastModifierTime = rows[i].nTime;
            nGenerated++;
        } else {
            BOOST_CHECK_EQUAL(entries[i].nModifier, entries[i - 1].nModifier);
        }
        BOOST_CHECK(entries[i].nChecksum != entries[i - 1].nChecksum);
    }
    BOOST_CHECK_EQUAL(nGenerated, 12);
    BOOST_CHECK_EQUAL(entries.back().nModifier, 0x99376b954611be7fULL);
}

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
/* Mainnet blocks 0-15000 (hash and time of each, read from a node over RPC, in
 * data/stake_modifier_blocks.raw): the computed checksums pass the checkpoints at heights 0 and
 * 15000, and the modifiers are the node's. All of these blocks are proof of work, and modifiers
 * are generated only at heights 0, 2 and 10089 (the blocks span 9.3 hours). */
BOOST_AUTO_TEST_CASE(mainnet_modifiers_0_15000)
{
    SyntheticChain chain;
    std::vector<HashTimeRow> rows = ReadRows(raw_tests::stake_modifier_blocks, sizeof(raw_tests::stake_modifier_blocks));
    BOOST_REQUIRE_EQUAL(rows.size(), 15001U);
    BOOST_CHECK_EQUAL(rows[15000].hash.GetHex(), "00000082cab82d04354692fac3b83d19cbe3c3ab4b73610d0e73397545eb012e");
    std::vector<StakeModifierEntry> entries = ComputeModifiers(chain, rows);
    BOOST_REQUIRE_EQUAL(entries.size(), 15001U);

    BOOST_CHECK_EQUAL(entries[0].nChecksum, 0x0e00670bU);
    BOOST_CHECK(CheckStakeModifierCheckpoints(0, entries[0].nChecksum));
    BOOST_CHECK_EQUAL(entries[15000].nChecksum, 0x085e9cafU);
    BOOST_CHECK(CheckStakeModifierCheckpoints(15000, entries[15000].nChecksum));
    BOOST_CHECK(!CheckStakeModifierCheckpoints(15000, entries[15000].nChecksum ^ 1));
    // Checksums the node reports at the heights with a new modifier
    BOOST_CHECK_EQUAL(entries[2].nChecksum, 0x919e03c5U);
    BOOST_CHECK_EQUAL(entries[10089].nChecksum, 0x9e1bda36U);

    // The node's modifiers at the heights that generate one
    const std::map<size_t, ::uint64_t> generated = {{0, 0x0}, {2, 0x1}, {10089, 0x514ac69ff6a11fd1}};
    ::uint64_t nModifier = 0;
    for (size_t i = 0; i < entries.size(); i++) {
        auto it = generated.find(i);
        if (it != generated.end()) nModifier = it->second;
        if (entries[i].fGenerated != (it != generated.end()) || entries[i].nModifier != nModifier) {
            BOOST_ERROR("height " << i << ": modifier " << std::hex << entries[i].nModifier << " generated "
                                   << entries[i].fGenerated << ", the node's " << nModifier);
        }
    }
}
#endif

/* The kernel hash: double SHA-256 of the modifier, the coin's block time, the coin's offset in
 * its block, its transaction time, its output index and the coinstake time; the coin-day weight
 * does not enter it. Known answers computed with Python's hashlib:
 * sha256(sha256(struct.pack('<QIIIII', ...))) */
BOOST_AUTO_TEST_CASE(proof_of_stake_hash)
{
    // Block 82204's kernel
    BOOST_CHECK_EQUAL(GetProofOfStakeHash(MODIFIER_64327, 1367998133, 81, 1367998133, 0, 1370591579, 1).GetHex(),
                      PROOF_HASH_82204);
    const uint256 hash = GetProofOfStakeHash(0x0123456789abcdef, 1400000000, 1234, 1399999000, 3, 1410000000, 0);
    BOOST_CHECK_EQUAL(hash.GetHex(), "096d5a56ca8a0afe957168b9f6d878fe16cd90f817f67896bb677dfb89982280");
    BOOST_CHECK(GetProofOfStakeHash(0x0123456789abcdef, 1400000000, 1234, 1399999000, 3, 1410000000, 999999) == hash);
    BOOST_CHECK(GetProofOfStakeHash(0x0123456789abcdee, 1400000000, 1234, 1399999000, 3, 1410000000, 0) != hash);
    BOOST_CHECK(GetProofOfStakeHash(0x0123456789abcdef, 1400000000, 1234, 1399999000, 2, 1410000000, 0) != hash);
}

/* The data of block 82204's kernel */
BOOST_AUTO_TEST_CASE(real_kernel_data)
{
    RealKernel real;
    BOOST_CHECK_EQUAL(real.blockFrom.GetHash().GetHex(), "00000af3c7a0d0f5e904aa96dbd39adeb74402aa2dc41e0adcd2a028c4995020");
    BOOST_CHECK_EQUAL(real.blockStake.GetHash().GetHex(), "5dc2a000963f075f3dec7fa8f220987bff3c4a978528594e5408448155cdc8e4");
    BOOST_CHECK(real.blockStake.IsProofOfStake());
    BOOST_CHECK_EQUAL(real.txPrev().GetHash().GetHex(), "37cc880145b6a26e8573f6318d531079c33f46ec568970b49d6b5bcaaf0aedf4");
    BOOST_CHECK(real.coinstake().IsCoinStake());
    BOOST_CHECK_EQUAL(real.coinstake().GetHash().GetHex(), "5b9f9ceab4c44662b182a04e06821561af138c6fb29ec2795fed05e9211855a7");
    BOOST_CHECK(real.coinstake().vin[0].prevout.hash == real.txPrev().GetHash());
    BOOST_CHECK_EQUAL(real.coinstake().vin[0].prevout.n, 0U);
    BOOST_CHECK_EQUAL(real.blockFrom.GetBlockTime(), 1367998133);
    BOOST_CHECK_EQUAL(real.txPrev().nTime, 1367998133);
    BOOST_CHECK_EQUAL(real.coinstake().nTime, 1370591579);
    BOOST_CHECK_EQUAL(real.blockStake.nBits, BITS_82204);
    BOOST_CHECK_EQUAL(::GetSerializeSize(CBlockHeader(real.blockFrom), SER_DISK, CLIENT_VERSION) +
                          GetSizeOfCompactSize(real.blockFrom.vtx.size()),
                      TX_PREV_OFFSET);
}

/* Block 82204's kernel passes with the node's proof hash; the target is the coin-day weight
 * (here 1: 98.02 coins, 1446 s past the minimum age) times the target of nBits. The modifier
 * is found walking the active chain, a chain that is not active, or both. */
BOOST_AUTO_TEST_CASE(real_kernel_passes)
{
    RealKernel real;
    SyntheticChain chain;
    KernelChain k = BuildKernelChain(chain, real.blockFrom, BLOCK_82203_TIME);
    BOOST_REQUIRE(k.pindexModifier != nullptr);
    const ::uint32_t nTimeTx = real.coinstake().nTime;

    auto check = [&](bool fPrint) {
        KernelResult result = CheckKernel(real, k.pindexPrev, BITS_82204, nTimeTx, fPrint);
        BOOST_CHECK(result.fPass);
        BOOST_CHECK_EQUAL(result.hashProof.GetHex(), PROOF_HASH_82204);
        BOOST_CHECK_EQUAL(result.target.GetHex(), "00000fffff000000000000000000000000000000000000000000000000000000");
    };
    // Not on the active chain (its tip is the genesis block)
    check(false);
    check(true);
    {
        ValueGuard<bool> debug(fDebug, true);
        check(false);
    }
    // On the active chain
    chain.SetActiveTip(k.pindexPrev);
    check(false);
    // Partly: the active chain ends below the modifier's entry
    chain.SetActiveTip(k.pindexModifier->pprev->pprev);
    check(false);
}

/* With the coin older than 120 days the weight is capped at 90 days: the target is 8821 times
 * that of nBits (98.02 coins for 90 days). The first coinstake time from 130 days on that
 * passes, found with the same Python hash as above, is 2 s later. */
BOOST_AUTO_TEST_CASE(real_kernel_weight_cap)
{
    RealKernel real;
    SyntheticChain chain;
    KernelChain k = BuildKernelChain(chain, real.blockFrom, BLOCK_82203_TIME);
    const ::uint32_t nTimeTx = real.blockFrom.GetBlockTime() + 130 * DAY + 2;
    KernelResult result = CheckKernel(real, k.pindexPrev, BITS_82204, nTimeTx);
    BOOST_CHECK(result.fPass);
    BOOST_CHECK_EQUAL(result.hashProof.GetHex(), "01179449a1fad214cf23f816d67bd9a4d93b418f7efcb01afafc1682ba98e8b1");
    BOOST_CHECK_EQUAL(result.target.GetHex(), "02274fdd8b000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK(!CheckKernel(real, k.pindexPrev, BITS_82204, nTimeTx - 1).fPass);
}

/* Kernels that fail */
BOOST_AUTO_TEST_CASE(real_kernel_fails)
{
    RealKernel real;
    SyntheticChain chain;
    KernelChain k = BuildKernelChain(chain, real.blockFrom, BLOCK_82203_TIME);
    const ::uint32_t nTimeTx = real.coinstake().nTime;
    const ::uint32_t nTimeFrom = real.blockFrom.GetBlockTime();

    // Coinstake time before the coin's transaction time
    BOOST_CHECK(!CheckKernel(real, k.pindexPrev, BITS_82204, real.txPrev().nTime - 1).fPass);
    // The coin is younger than 30 days (measured from its block's time)
    BOOST_CHECK(!CheckKernel(real, k.pindexPrev, BITS_82204, nTimeFrom + 30 * DAY - 1).fPass);
    // At exactly 30 days the weight is 0, so the target is 0
    KernelResult result = CheckKernel(real, k.pindexPrev, BITS_82204, nTimeFrom + 30 * DAY);
    BOOST_CHECK(!result.fPass);
    // A harder target: the hash is computed but above it
    result = CheckKernel(real, k.pindexPrev, 0x1d00ffff, nTimeTx);
    BOOST_CHECK(!result.fPass);
    BOOST_CHECK_EQUAL(result.hashProof.GetHex(), PROOF_HASH_82204);
}

/* The chain ends before an entry with a modifier late enough: the kernel fails, logged as an
 * error if fPrintProofOfStake is set or the chain's end is recent (less than the minimum age
 * minus the selection interval ago) */
BOOST_AUTO_TEST_CASE(real_kernel_chain_ends_before_modifier)
{
    RealKernel real;
    SyntheticChain chain;
    KernelChain k = BuildKernelChain(chain, real.blockFrom, real.blockFrom.GetBlockTime() + 5 * DAY);
    BOOST_REQUIRE(k.pindexModifier == nullptr);
    chain.SetActiveTip(k.pindexPrev);
    const ::uint32_t nTimeTx = real.coinstake().nTime;

    BOOST_CHECK(!CheckKernel(real, k.pindexPrev, BITS_82204, nTimeTx, false).fPass);
    BOOST_CHECK(!CheckKernel(real, k.pindexPrev, BITS_82204, nTimeTx, true).fPass);
    MockTimeGuard mocktime(k.pindexPrev->GetBlockTime() + 30 * DAY - SELECTION_INTERVAL - 1);
    BOOST_CHECK(!CheckKernel(real, k.pindexPrev, BITS_82204, nTimeTx, false).fPass);
}

/* CheckProofOfStake reads the coin's block from the block files through the transaction index,
 * verifies the coinstake's signature and checks the kernel */
BOOST_AUTO_TEST_CASE(real_proof_of_stake)
{
    RealKernel real;
    SyntheticChain chain;
    KernelChain k = BuildKernelChain(chain, real.blockFrom, BLOCK_82203_TIME);
    chain.SetActiveTip(k.pindexPrev);

    // Block 644 in block file 7 with its block hash index entry, and in file 8 without one
    const CDiskBlockPos pos = WriteBlockFile(real.blockFrom, 7);
    BOOST_REQUIRE(pblocktree->WriteBlockHash(pos, real.blockFrom.GetHash()));
    const CDiskBlockPos posNoHash = WriteBlockFile(real.blockFrom, 8);

    auto check = [&](const CTransaction& tx, unsigned int nBits, int nExpectedDoS) {
        CValidationState state;
        uint256 hashProof, target;
        const bool fPass = CheckProofOfStake(state, k.pindexPrev, tx, nBits, hashProof, target);
        int nDoS = 0;
        if (nExpectedDoS < 0) {
            BOOST_CHECK(fPass);
            BOOST_CHECK(state.IsValid());
            BOOST_CHECK_EQUAL(hashProof.GetHex(), PROOF_HASH_82204);
            BOOST_CHECK_EQUAL(target.GetHex(), "00000fffff000000000000000000000000000000000000000000000000000000");
        } else {
            BOOST_CHECK(!fPass);
            BOOST_CHECK_EQUAL(state.IsInvalid(nDoS), nExpectedDoS > 0);
            BOOST_CHECK_EQUAL(nDoS, nExpectedDoS);
        }
    };

    IndexFirstTx(real.blockFrom, pos);
    check(real.coinstake(), BITS_82204, -1);
    // A harder target fails the kernel (DoS 1)
    check(real.coinstake(), 0x1d00ffff, 1);
    // A changed signature (DoS 100)
    CTransaction txBadSig = real.coinstake();
    txBadSig.vin[0].scriptSig[10] ^= 1;
    check(txBadSig, BITS_82204, 100);
    // Not a coinstake: the coinbase of block 82204
    check(real.blockStake.vtx[0], BITS_82204, 0);
    {
        // Without the transaction index
        ValueGuard<bool> txindex(fTxIndex, false);
        check(real.coinstake(), BITS_82204, 0);
    }

    // Without a block hash index entry the hash of block 644 is computed (and the miss logged)
    IndexFirstTx(real.blockFrom, posNoHash);
    check(real.coinstake(), BITS_82204, -1);
    {
        ValueGuard<bool> blockhashindex(fBlockHashIndex, false);
        check(real.coinstake(), BITS_82204, -1);
    }
}

BOOST_AUTO_TEST_SUITE_END()
