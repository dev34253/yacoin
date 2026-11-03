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
#include "test/stake_test_util.h"
#include "test/test_bitcoin.h"

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
#include "data/stake_modifier_blocks.raw.h"
#endif

#include <algorithm>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

// Defined in kernel.cpp, not declared in kernel.h
uint256 GetProofOfStakeHash(::uint64_t nStakeModifier, ::uint32_t nTimeBlockFrom, ::uint32_t nTxPrevOffset,
                            ::uint32_t nTxPrevTime, ::uint32_t nPrevoutn, ::uint32_t nTimeTx, ::uint64_t nCoinDayWeight);

namespace {

const ::int64_t MODIFIER_INTERVAL = 6 * 60 * 60;
// Sum of the 64 selection interval sections (7200 s for the first, 21600 s for the last)
const ::int64_t SELECTION_INTERVAL = 761920;

struct Modifier {
    ::uint64_t nModifier;
    bool fGenerated;
};

/** ComputeNextStakeModifier for pindex, quiet, with -debug and with -debug and
 * -printstakemodifier; all runs must agree */
Modifier Compute(const CBlockIndex* pindex)
{
    // ComputeNextStakeModifier sets both outputs, whatever they held before
    Modifier quiet{0xdeadbeef, true};
    BOOST_REQUIRE(ComputeNextStakeModifier(pindex, quiet.nModifier, quiet.fGenerated));
    for (bool fPrint : {false, true}) {
        Modifier logged{0xdeadbeef, true};
        StakeLogGuard log(fPrint);
        BOOST_REQUIRE(ComputeNextStakeModifier(pindex, logged.nModifier, logged.fGenerated));
        BOOST_CHECK_EQUAL(quiet.nModifier, logged.nModifier);
        BOOST_CHECK_EQUAL(quiet.fGenerated, logged.fGenerated);
    }
    return quiet;
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
    // The log runs leave the arguments as they were
    BOOST_CHECK(!gArgs.IsArgSet("-printstakemodifier"));
    BOOST_CHECK(!fDebug);
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

/* Close to the genesis block the window reaches back past it: the genesis block is a
 * candidate too */
BOOST_AUTO_TEST_CASE(modifier_window_includes_genesis)
{
    SyntheticChain chain;
    const CBlockIndex* pindexGenesis = chain.Genesis();
    const ::int64_t nGenesisTime = pindexGenesis->GetBlockTime();
    CBlockIndex* pindex = AddBlock(chain, nullptr, nGenesisTime + 600);
    pindex = AddBlock(chain, pindex, nGenesisTime + 1200);
    pindex = AddBlock(chain, pindex, nGenesisTime + 2 * MODIFIER_INTERVAL);
    Modifier modifier = Compute(AddBlock(chain, pindex, nGenesisTime + 2 * MODIFIER_INTERVAL + 60));
    BOOST_CHECK(modifier.fGenerated);
    // Four rounds: three candidates with entropy bit 1 and the genesis block with its own
    BOOST_CHECK(modifier.nModifier < 0x10U);
    int nBits = 0;
    for (::uint64_t n = modifier.nModifier; n; n >>= 1) nBits += n & 1;
    BOOST_CHECK_EQUAL(nBits, 3 + (int)pindexGenesis->GetStakeEntropyBit());
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
/* Mainnet blocks 0-15000 (hash and time of each, in data/stake_modifier_blocks.raw, read with
 * getblockhash and getblock from a yacoind built from master commit 6d723834 of 2026-10-18 and
 * synced to height 1964924): the computed checksums pass the checkpoints at heights 0 and
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
        check(true);
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
