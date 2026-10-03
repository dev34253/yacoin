// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests of the consensus test harness itself (task P0-47).

#include "test/consensus_harness.h"

#include "chainparams.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

#include <sstream>
#include <stdexcept>
#include <string>

#include <boost/test/unit_test.hpp>

using namespace consensus_harness;

namespace {

// What test_bitcoin has without AppInit (mock time excluded: other suites
// such as DoS_tests leave it set).
void CheckUnitTestDefaults()
{
    BOOST_CHECK_EQUAL(nMainnetNewLogicBlockNumber, 0);
    BOOST_CHECK_EQUAL(nTokenSupportBlockNumber, 0);
    BOOST_CHECK_EQUAL((int)nFactorAtHardfork, 0);
    BOOST_CHECK_EQUAL(nEpochInterval, 21000U);
    BOOST_CHECK_EQUAL(nDifficultyInterval, 21000U);
    BOOST_CHECK(!fTestNet);
    BOOST_CHECK_EQUAL(nYac10HardforkTime, DEFAULT_YAC10_HARDFORK_TIME);
}

// True if what() of the exception contains the given text.
struct HasMessage {
    std::string text;
    explicit HasMessage(const std::string& t) : text(t) {}
    bool operator()(const std::runtime_error& e) const
    {
        const bool found = std::string(e.what()).find(text) != std::string::npos;
        if (!found) BOOST_TEST_MESSAGE("unexpected message: " << e.what());
        return found;
    }
};

const std::string HASH_A = "00000000000000000000000000000000000000000000000000000000000000a1";
const std::string HASH_B = "00000000000000000000000000000000000000000000000000000000000000b2";
const std::string HASH_C = "00000000000000000000000000000000000000000000000000000000000000c3";
const std::string HASH_D = "00000000000000000000000000000000000000000000000000000000000000d4";

CBlockIndex* Load(const std::string& csv, TestChain& chain)
{
    std::istringstream in(csv);
    return LoadIndexChainCsv(in, chain, "test.csv");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_harness_tests, ConsensusTestingSetup)

// The next three cases run in this order (Boost's default): the middle one
// changes every global through the fixture, the outer ones check that
// nothing leaks into the next test case.
BOOST_AUTO_TEST_CASE(globals_at_defaults_before)
{
    CheckUnitTestDefaults();
}

BOOST_AUTO_TEST_CASE(globals_changed_by_fixture)
{
    globals.UseMainnetGlobals();
    globals.SetTestNet(true);
    globals.SetYac10HardforkTime(1);
    globals.SetMockTime(1500000000);
    BOOST_CHECK_EQUAL(nMainnetNewLogicBlockNumber, 1890000);
    BOOST_CHECK_EQUAL(GetTime(), 1500000000);
    chain.AppendMany(3, 60, 0x1d00ffff, false, 1500000000);
    chain.SetActiveTip(chain.Tip());
    BOOST_CHECK_EQUAL(chainActive.Height(), 2);
}

BOOST_AUTO_TEST_CASE(globals_at_defaults_after)
{
    CheckUnitTestDefaults();
    // chainActive is back at the genesis that TestingSetup loaded.
    BOOST_CHECK_EQUAL(chainActive.Height(), 0);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == Params().GetConsensus().hashGenesisBlock);
}

BOOST_AUTO_TEST_CASE(globals_presets_and_restore)
{
    const ConsensusGlobals before = ConsensusGlobals::Capture();
    {
        ScopedConsensusGlobals g;
        BOOST_CHECK(g.Saved() == before);

        g.UseMainnetGlobals();
        BOOST_CHECK_EQUAL(nMainnetNewLogicBlockNumber, 1890000);
        BOOST_CHECK_EQUAL(nTokenSupportBlockNumber, 1911210);
        BOOST_CHECK_EQUAL((int)nFactorAtHardfork, 21);
        BOOST_CHECK_EQUAL(nEpochInterval, 21000U);
        BOOST_CHECK_EQUAL(nDifficultyInterval, 21000U);
        BOOST_CHECK(!fTestNet);

        g.UseFunctionalTestGlobals(150);
        BOOST_CHECK_EQUAL(nMainnetNewLogicBlockNumber, 150);
        BOOST_CHECK_EQUAL(nTokenSupportBlockNumber, 1911210);
        BOOST_CHECK_EQUAL((int)nFactorAtHardfork, 4);
        BOOST_CHECK_EQUAL(nEpochInterval, 10U);
        BOOST_CHECK_EQUAL(nDifficultyInterval, 10U);

        g.SetDifficultyInterval(7);
        BOOST_CHECK_EQUAL(nEpochInterval, 10U);
        BOOST_CHECK_EQUAL(nDifficultyInterval, 7U);
        g.SetTestNet(true);
        g.SetYac10HardforkTime(42);
        g.SetMockTime(1234567890);
        BOOST_CHECK(fTestNet);
        BOOST_CHECK_EQUAL(nYac10HardforkTime, 42);
        BOOST_CHECK_EQUAL(GetTime(), 1234567890);
        BOOST_CHECK_EQUAL(GetAdjustedTime(), 1234567890);

        g.UseUnitTestGlobals();
        CheckUnitTestDefaults();
        BOOST_CHECK_EQUAL(GetMockTime(), 1234567890); // presets keep mock time

        // A nested guard restores to the state at its own construction.
        {
            ScopedConsensusGlobals inner;
            inner.SetNewLogicBlockNumber(99);
            inner.SetMockTime(0);
        }
        BOOST_CHECK_EQUAL(nMainnetNewLogicBlockNumber, 0);
        BOOST_CHECK_EQUAL(GetMockTime(), 1234567890);
    }
    BOOST_CHECK(ConsensusGlobals::Capture() == before);
    BOOST_TEST_MESSAGE("restored: " << ConsensusGlobals::Capture().ToString());
}

BOOST_AUTO_TEST_CASE(globals_restored_after_exception)
{
    const ConsensusGlobals before = ConsensusGlobals::Capture();
    try {
        ScopedConsensusGlobals g;
        g.UseMainnetGlobals();
        g.SetMockTime(1);
        throw std::runtime_error("test");
    } catch (const std::runtime_error&) {
    }
    BOOST_CHECK(ConsensusGlobals::Capture() == before);
}

BOOST_AUTO_TEST_CASE(chain_builder_basic)
{
    const size_t nMapSize = mapBlockIndex.size();
    CBlockIndex* const pindexOldTip = chainActive.Tip();
    std::vector<uint256> hashes;
    {
        TestChain c;
        BOOST_CHECK(c.Tip() == nullptr);
        BOOST_CHECK(c.AtHeight(0) == nullptr);
        CBlockIndex* tip = c.AppendMany(300, 60, 0x1d00ffff, false, 1400000000);
        BOOST_CHECK_EQUAL(c.size(), 300U);
        BOOST_CHECK_EQUAL(tip->nHeight, 299);
        BOOST_CHECK_EQUAL(mapBlockIndex.size(), nMapSize + 300);

        CBigNum bnTrust(0);
        for (int h = 0; h < 300; ++h) {
            CBlockIndex* p = c.AtHeight(h);
            BOOST_REQUIRE(p != nullptr);
            BOOST_CHECK_EQUAL(p->nHeight, h);
            BOOST_CHECK(p->pprev == (h ? c.AtHeight(h - 1) : nullptr));
            BOOST_CHECK_EQUAL(p->GetBlockTime(), 1400000000 + 60 * h);
            BOOST_CHECK_EQUAL(p->nTimeMax, p->GetBlockTime());
            BOOST_CHECK_EQUAL(p->nBits, 0x1d00ffffU);
            BOOST_CHECK(p->IsProofOfWork());
            BOOST_CHECK(p->phashBlock != nullptr);
            BOOST_CHECK(p->blockHash == p->GetBlockHash());
            BOOST_CHECK(mapBlockIndex.count(p->GetBlockHash()) == 1 && mapBlockIndex[p->GetBlockHash()] == p);
            bnTrust += p->GetBlockTrust();
            BOOST_CHECK(p->bnChainTrust == bnTrust);
            // Same skip pointer as the node's BuildSkip().
            CBlockIndex copy = *p;
            copy.BuildSkip();
            BOOST_CHECK(copy.pskip == p->pskip);
            hashes.push_back(p->GetBlockHash());
        }
        // Skip pointers work (GetAncestor follows pskip).
        BOOST_CHECK(tip->pskip != nullptr);
        BOOST_CHECK(tip->GetAncestor(17) == c.AtHeight(17));

        c.SetActiveTip(tip);
        BOOST_CHECK_EQUAL(chainActive.Height(), 299);
        BOOST_CHECK(chainActive.Genesis() == c.AtHeight(0));
        BOOST_CHECK(chainActive[150] == c.AtHeight(150));
        c.SetActiveTip(c.AtHeight(10));
        BOOST_CHECK_EQUAL(chainActive.Height(), 10);
    }
    // Everything restored.
    BOOST_CHECK(chainActive.Tip() == pindexOldTip);
    BOOST_CHECK(chainActive.Genesis() == pindexOldTip); // TestingSetup: tip is the genesis
    BOOST_CHECK_EQUAL(mapBlockIndex.size(), nMapSize);
    for (const uint256& hash : hashes) {
        BOOST_CHECK(mapBlockIndex.count(hash) == 0);
    }
}

BOOST_AUTO_TEST_CASE(chain_builder_specs_forks_segments)
{
    BlockSpec spec(1400000000, 0x1d00ffff, true);
    spec.nEntropyBit = 1;
    spec.nStakeModifier = 0x0123456789abcdefULL;
    spec.fGeneratedStakeModifier = true;
    spec.hashProofOfStake = uint256S(HASH_A);
    spec.prevoutStake = COutPoint(uint256S(HASH_B), 3);
    spec.nStakeTime = 1399999999;
    spec.nVersion = 7;
    spec.nNonce = 5;
    spec.hashMerkleRoot = uint256S(HASH_C);
    spec.hash = uint256S(HASH_D);
    spec.nHeight = 1889998;
    CBlockIndex* s = chain.Append(nullptr, spec); // segment start
    BOOST_CHECK(s->pprev == nullptr);
    BOOST_CHECK_EQUAL(s->nHeight, 1889998);
    BOOST_CHECK(s->IsProofOfStake());
    BOOST_CHECK_EQUAL(s->GetStakeEntropyBit(), 1U);
    BOOST_CHECK(s->GeneratedStakeModifier());
    BOOST_CHECK_EQUAL(s->nStakeModifier, 0x0123456789abcdefULL);
    BOOST_CHECK(s->hashProofOfStake == uint256S(HASH_A));
    BOOST_CHECK(s->prevoutStake == COutPoint(uint256S(HASH_B), 3));
    BOOST_CHECK_EQUAL(s->nStakeTime, 1399999999U);
    BOOST_CHECK_EQUAL(s->nVersion, 7);
    BOOST_CHECK_EQUAL(s->nNonce, 5U);
    BOOST_CHECK(s->hashMerkleRoot == uint256S(HASH_C));
    BOOST_CHECK(s->GetBlockHash() == uint256S(HASH_D));
    BOOST_CHECK(s->nFlags == (CBlockIndex::BLOCK_PROOF_OF_STAKE | CBlockIndex::BLOCK_STAKE_ENTROPY | CBlockIndex::BLOCK_STAKE_MODIFIER));
    // Segment start: no parent, so the pprev == nullptr trust rule applies.
    BOOST_CHECK(s->bnChainTrust == s->GetBlockTrust());

    CBlockIndex* a2 = chain.AppendMany(2, 60, 0x1d00ffff);
    BOOST_CHECK_EQUAL(a2->nHeight, 1890000);
    BOOST_CHECK(chain.AtHeight(1889997) == nullptr); // below the segment
    BOOST_CHECK(chain.AtHeight(1889998) == s);
    BOOST_CHECK(a2->pskip == nullptr); // skip target lies below the segment
    BOOST_CHECK(a2->pprev->pprev == s);
    // chainActive on a segment: nothing below the segment start, in
    // particular not the genesis that TestingSetup had there.
    BOOST_REQUIRE(chainActive.Genesis() != nullptr);
    CBlockIndex* realGenesis = chainActive.Genesis();
    chain.SetActiveTip(a2);
    BOOST_CHECK_EQUAL(chainActive.Height(), 1890000);
    BOOST_CHECK(chainActive.Genesis() == nullptr);
    BOOST_CHECK(chainActive[1889997] == nullptr);
    BOOST_CHECK(chainActive[1889998] == s);
    BOOST_CHECK(!chainActive.Contains(realGenesis));

    // Fork from the segment start.
    CBlockIndex* b1 = chain.Append(s, BlockSpec(1400000100, 0x1c00ffff));
    BOOST_CHECK_EQUAL(b1->nHeight, 1889999);
    BOOST_CHECK(b1->pprev == s);
    BOOST_CHECK(chain.Tip() == b1);
    BOOST_CHECK(b1->GetBlockHash() != a2->pprev->GetBlockHash());
    BOOST_CHECK(b1->bnChainTrust == s->bnChainTrust + b1->GetBlockTrust());

    // Errors.
    BlockSpec bad(1400000200, 0x1d00ffff);
    bad.nHeight = 5;
    BOOST_CHECK_EXCEPTION(chain.Append(b1, bad), std::runtime_error, HasMessage("does not follow"));
    BlockSpec dup(1400000200, 0x1d00ffff);
    dup.hash = uint256S(HASH_D);
    BOOST_CHECK_EXCEPTION(chain.Append(dup), std::runtime_error, HasMessage("already in mapBlockIndex"));
    BlockSpec genesisDup(1400000200, 0x1d00ffff);
    genesisDup.hash = Params().GetConsensus().hashGenesisBlock;
    BOOST_CHECK_EXCEPTION(chain.Append(genesisDup), std::runtime_error, HasMessage("already in mapBlockIndex"));
    BlockSpec entropy(1400000200, 0x1d00ffff);
    entropy.nEntropyBit = 2;
    BOOST_CHECK_EXCEPTION(chain.Append(entropy), std::runtime_error, HasMessage("entropy bit"));
    BOOST_CHECK(chain.Tip() == b1);

    // Two chains in one test: different salts give different hashes.
    TestChain other(1);
    CBlockIndex* o = other.Append(BlockSpec(1400000000, 0x1d00ffff));
    TestChain same(0);
    BOOST_CHECK_EXCEPTION(same.Append(BlockSpec(1400000000, 0x1d00ffff)), std::runtime_error, HasMessage("already in mapBlockIndex"));
    BOOST_CHECK(o->GetBlockHash() != chain.AtHeight(1889999)->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(chain_builder_existing_genesis)
{
    CBlockIndex* genesis = chain.StartOnExistingGenesis();
    BOOST_REQUIRE(genesis != nullptr);
    BOOST_CHECK(genesis == mapBlockIndex[Params().GetConsensus().hashGenesisBlock]);
    BOOST_CHECK(genesis == chainActive.Genesis());
    BOOST_CHECK_EQUAL(chain.size(), 0U);
    BOOST_CHECK_EXCEPTION(chain.StartOnExistingGenesis(), std::runtime_error, HasMessage("not empty"));

    CBlockIndex* tip = chain.AppendMany(5, 60, 0x1d00ffff);
    BOOST_CHECK_EQUAL(tip->nHeight, 5);
    BOOST_CHECK(chain.AtHeight(0) == genesis);
    BOOST_CHECK_EQUAL(chain.AtHeight(1)->GetBlockTime(), genesis->GetBlockTime() + 60);
    BOOST_CHECK(chain.AtHeight(1)->bnChainTrust == genesis->bnChainTrust + chain.AtHeight(1)->GetBlockTrust());
    chain.SetActiveTip(tip);
    BOOST_CHECK(chainActive.Genesis() == genesis);
    {
        // A chain that only borrows the genesis leaves it in place.
        TestChain borrow(7);
        borrow.StartOnExistingGenesis();
        borrow.Append(BlockSpec(genesis->GetBlockTime() + 30, 0x1d00ffff));
    }
    BOOST_CHECK(mapBlockIndex.count(Params().GetConsensus().hashGenesisBlock) == 1);
}

BOOST_AUTO_TEST_CASE(block_files)
{
    const Consensus::Params& params = Params().GetConsensus();
    CBlockIndex* genesis = chain.StartOnExistingGenesis();

    // The genesis that TestingSetup wrote is readable through the index.
    CBlock block;
    BOOST_CHECK(ReadBlockFromDisk(block, genesis, params));
    BOOST_CHECK(block.GetHash() == params.hashGenesisBlock);

    // A copy of the genesis block written to the harness block file.
    const CDiskBlockPos posGenesis = WriteBlockToTestFile(Params().GenesisBlock());
    BOOST_CHECK_EQUAL(posGenesis.nFile, TEST_BLOCK_FILE);
    CBlock copy;
    BOOST_CHECK(ReadBlockFromDisk(copy, posGenesis, params));
    BOOST_CHECK(copy.GetHash() == params.hashGenesisBlock);

    // A synthetic child block. Its header counts as proof-of-stake under
    // CBlockHeader::IsProofOfStake() (nonce 0, time before
    // nYac10HardforkTime, nBits <= 0x1d00ffff), so ReadBlockFromDisk skips
    // the proof-of-work check and no grinding is needed. Version 6 and a
    // 2013 time keep the scrypt N-factor low.
    CBlock child;
    child.nVersion = 6;
    child.hashPrevBlock = params.hashGenesisBlock;
    child.nTime = genesis->GetBlockTime() + 60;
    child.nBits = 0x1c00ffff;
    child.nNonce = 0;
    BOOST_REQUIRE(child.IsProofOfStake());
    CBlockIndex* pindexChild = chain.AppendBlock(child, true);
    BOOST_CHECK(pindexChild->pprev == genesis);
    BOOST_CHECK_EQUAL(pindexChild->nHeight, 1);
    BOOST_CHECK(pindexChild->IsProofOfStake());
    BOOST_CHECK(pindexChild->GetBlockHash() == child.GetHash());
    BOOST_CHECK_EQUAL(pindexChild->GetStakeEntropyBit(), (unsigned int)(child.GetHash().Get64() & 1));
    BOOST_CHECK_EQUAL(pindexChild->nFile, (unsigned int)TEST_BLOCK_FILE);
    BOOST_CHECK(pindexChild->nDataPos > posGenesis.nPos); // appended after the copy
    BOOST_CHECK(pindexChild->nStatus & BLOCK_HAVE_DATA);
    CBlock readChild;
    BOOST_CHECK(ReadBlockFromDisk(readChild, pindexChild, params));
    BOOST_CHECK(readChild.GetHash() == child.GetHash());

    // Index-only entry for a block whose parent is unknown: segment start.
    CBlock orphan = child;
    orphan.hashPrevBlock = uint256S(HASH_A);
    CBlockIndex* pindexOrphan = chain.AppendBlock(orphan, false, 77);
    BOOST_CHECK(pindexOrphan->pprev == nullptr);
    BOOST_CHECK_EQUAL(pindexOrphan->nHeight, 77);
    BOOST_CHECK(!(pindexOrphan->nStatus & BLOCK_HAVE_DATA));
}

BOOST_AUTO_TEST_CASE(csv_loader_valid)
{
    const std::string csv =
        "# index-chain test data\r\n"
        "height,hash,prev_hash,time,bits,version,nonce,merkle_root,flags,stake_modifier,hash_proof_of_stake,prevout_stake,stake_time,extra_column\r\n"
        "\r\n"
        "1889998," + HASH_A + ",," + "1600000000,0x1c0fffff,7,12," + HASH_D + ",4,0x1122334455667788,,,,ignored\r\n"
        "# comment between rows\n"
        "1889999," + HASH_B + "," + HASH_A + ",1600000060,469827583,,,,0x7,0," + HASH_C + "," + HASH_D + ":2,1599990000,\n"
        "1890000," + HASH_C + ",,1600000120,0x1c0fffff,,,,0,,,,,\n";
    CBlockIndex* tip = Load(csv, chain);
    BOOST_REQUIRE(tip != nullptr);
    BOOST_CHECK_EQUAL(chain.size(), 3U);
    BOOST_CHECK(tip == chain.Tip());
    BOOST_CHECK_EQUAL(tip->nHeight, 1890000);
    BOOST_CHECK(tip->GetBlockHash() == uint256S(HASH_C));

    CBlockIndex* r0 = chain.AtHeight(1889998);
    BOOST_REQUIRE(r0 != nullptr);
    BOOST_CHECK(r0->pprev == nullptr); // segment start
    BOOST_CHECK(r0->GetBlockHash() == uint256S(HASH_A));
    BOOST_CHECK_EQUAL(r0->GetBlockTime(), 1600000000);
    BOOST_CHECK_EQUAL(r0->nBits, 0x1c0fffffU);
    BOOST_CHECK_EQUAL(r0->nVersion, 7);
    BOOST_CHECK_EQUAL(r0->nNonce, 12U);
    BOOST_CHECK(r0->hashMerkleRoot == uint256S(HASH_D));
    BOOST_CHECK(r0->IsProofOfWork());
    BOOST_CHECK(r0->GeneratedStakeModifier());
    BOOST_CHECK_EQUAL(r0->GetStakeEntropyBit(), 0U);
    BOOST_CHECK_EQUAL(r0->nStakeModifier, 0x1122334455667788ULL);

    CBlockIndex* r1 = chain.AtHeight(1889999);
    BOOST_CHECK(r1->pprev == r0);
    BOOST_CHECK_EQUAL(r1->nBits, 469827583U); // decimal 0x1c0fffff
    BOOST_CHECK_EQUAL(r1->nVersion, 6);       // empty field: BlockSpec default
    BOOST_CHECK(r1->IsProofOfStake());
    BOOST_CHECK_EQUAL(r1->GetStakeEntropyBit(), 1U);
    BOOST_CHECK(r1->GeneratedStakeModifier());
    BOOST_CHECK_EQUAL(r1->nStakeModifier, 0U);
    BOOST_CHECK(r1->hashProofOfStake == uint256S(HASH_C));
    BOOST_CHECK(r1->prevoutStake == COutPoint(uint256S(HASH_D), 2));
    BOOST_CHECK_EQUAL(r1->nStakeTime, 1599990000U);

    BOOST_CHECK(tip->pprev == r1);
    BOOST_CHECK_EQUAL(tip->nFlags, 0U);
    BOOST_CHECK(tip->prevoutStake.IsNull());

    // Header only: no rows.
    TestChain empty(1);
    BOOST_CHECK(Load("height,hash,time,bits\n", empty) == nullptr);
    BOOST_CHECK_EQUAL(empty.size(), 0U);
}

BOOST_AUTO_TEST_CASE(csv_loader_links_to_existing_entry)
{
    CBlockIndex* genesis = chain.StartOnExistingGenesis();
    const std::string hashGenesis = genesis->GetBlockHash().GetHex();
    TestChain loaded(1);
    CBlockIndex* tip = Load("height,hash,prev_hash,time,bits\n"
                            "1," + HASH_A + "," + hashGenesis + ",1400000000,0x1d00ffff\n"
                            "2," + HASH_B + "," + HASH_A + ",1400000060,0x1d00ffff\n",
                            loaded);
    BOOST_REQUIRE(tip != nullptr);
    BOOST_CHECK(loaded.AtHeight(0) == genesis);
    BOOST_CHECK(tip->bnChainTrust == genesis->bnChainTrust + tip->pprev->GetBlockTrust() + tip->GetBlockTrust());

    // Linking also needs the right height.
    TestChain wrong(2);
    BOOST_CHECK_EXCEPTION(Load("height,hash,prev_hash,time,bits\n"
                               "5," + HASH_C + "," + hashGenesis + ",1400000000,0x1d00ffff\n", wrong),
                          std::runtime_error, HasMessage("test.csv:2: height 5 does not follow prev_hash at height 0"));
}

BOOST_AUTO_TEST_CASE(csv_loader_errors)
{
    const std::string header = "height,hash,time,bits\n";
    struct Case {
        std::string csv;
        std::string message;
    };
    const Case cases[] = {
        {"", "test.csv:0: no header line"},
        {"# only a comment\n", "test.csv:1: no header line"},
        {"height,hash,time\n", "test.csv:1: missing required column bits"},
        {"height,hash,time,bits,height\n", "duplicate column height"},
        {"height,,time,bits\n", "empty column name"},
        {header + "0," + HASH_A + ",1400000000\n", "test.csv:2: 3 fields, header has 4"},
        {header + "0," + HASH_A + ",1400000000,0x1d00ffff,9\n", "5 fields, header has 4"},
        {header + "," + HASH_A + ",1400000000,0x1d00ffff\n", "empty height"},
        {header + "0,,1400000000,0x1d00ffff\n", "empty hash"},
        {header + "-1," + HASH_A + ",1400000000,0x1d00ffff\n", "bad number in height: '-1'"},
        {header + "0," + HASH_A + ",14000000x0,0x1d00ffff\n", "bad number in time"},
        {header + "0," + HASH_A + ",1400000000,0x\n", "bad number in bits"},
        {header + "0," + HASH_A + ",1400000000,0x100000000\n", "bad number in bits"},
        {header + "0," + HASH_A + ",1400000000, 0x1d00ffff\n", "bad number in bits"},
        {header + "2147483648," + HASH_A + ",1400000000,0x1d00ffff\n", "bad number in height"},
        {header + "0," + HASH_A.substr(1) + ",1400000000,0x1d00ffff\n", "bad hash in hash"},
        {header + "0," + HASH_A.substr(1) + "g,1400000000,0x1d00ffff\n", "bad hash in hash"},
        {"height,hash,time,bits,flags\n0," + HASH_A + ",1400000000,0x1d00ffff,8\n", "bad number in flags: '8'"},
        {"height,hash,time,bits,prevout_stake\n0," + HASH_A + ",1400000000,0x1d00ffff," + HASH_B + "\n", "bad prevout_stake"},
        {"height,hash,time,bits,prevout_stake\n0," + HASH_A + ",1400000000,0x1d00ffff," + HASH_B + ":x\n", "bad prevout_stake"},
        {header + "0," + HASH_A + ",1400000000,0x1d00ffff\n2," + HASH_B + ",1400000060,0x1d00ffff\n", "test.csv:3: height 2 does not follow 0"},
        {"height,hash,prev_hash,time,bits\n0," + HASH_A + ",,1400000000,0x1d00ffff\n1," + HASH_B + "," + HASH_C + ",1400000060,0x1d00ffff\n", "test.csv:3: prev_hash does not match the previous row"},
        {header + "0," + HASH_A + ",1400000000,0x1d00ffff\n1," + HASH_A + ",1400000060,0x1d00ffff\n", "test.csv:3: TestChain: block hash already in mapBlockIndex"},
    };
    uint32_t nSalt = 100;
    for (const Case& c : cases) {
        TestChain chainForCase(nSalt++);
        BOOST_CHECK_EXCEPTION(Load(c.csv, chainForCase), std::runtime_error, HasMessage(c.message));
    }
    BOOST_CHECK_EXCEPTION(LoadIndexChainCsvFile("/nonexistent/p0-47.csv", chain), std::runtime_error, HasMessage("cannot open"));
}

BOOST_AUTO_TEST_SUITE_END()
