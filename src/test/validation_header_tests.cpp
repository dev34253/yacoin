// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Header acceptance (ProcessNewBlockHeaders, AcceptBlockHeader, CheckBlockHeader,
// ContextualCheckBlockHeader, AddToBlockIndex), and how received blocks are linked
// (ReceivedBlockTransactions) and chosen as the new tip (FindMostWorkChain).
//
// The regtest headers here are version 7, apart from one version 6 header, and hash at
// nFactorAtHardfork, which is 0 in the unit tests. Every header here is a proof-of-work header.

#include "chainparams.h"
#include "consensus/validation.h"
#include "miner.h"
#include "pow.h"
#include "script/script.h"
#include "timedata.h"
#include "tokens/tokendb.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <functional>

#include <boost/test/unit_test.hpp>

namespace {

/** Find a nonce, starting at 1, for the header as it is */
void Mine(CBlockHeader& header)
{
    if (header.nNonce == 0) header.nNonce = 1;
    while (!CheckProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus())) ++header.nNonce;
}

/** Find a nonce whose hash misses the target */
void MineBadly(CBlockHeader& header)
{
    if (header.nNonce == 0) header.nNonce = 1;
    while (CheckProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus())) ++header.nNonce;
}

/** Outcome of ProcessNewBlockHeaders: "" if accepted, else the reject reason ("no reason"
 * if it has none), with the misbehaviour score and reject code */
struct HeaderResult {
    std::string reason;
    int nScore = 0;
    unsigned int nCode = 0;
    const CBlockIndex* pindex = nullptr;
};

HeaderResult AcceptHeaders(const std::vector<CBlockHeader>& headers, CBlockHeader* pfirstInvalid = nullptr)
{
    HeaderResult result;
    CValidationState state;
    if (ProcessNewBlockHeaders(headers, state, Params(), &result.pindex, pfirstInvalid)) {
        BOOST_CHECK(state.IsValid());
        return result;
    }
    BOOST_CHECK(state.IsInvalid(result.nScore));
    result.nCode = state.GetRejectCode();
    result.reason = state.GetRejectReason().empty() ? "no reason" : state.GetRejectReason();
    return result;
}

CBlockIndex* Index(const uint256& hash)
{
    LOCK(cs_main);
    BlockMap::iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? nullptr : it->second;
}

size_t IndexSize()
{
    LOCK(cs_main);
    return mapBlockIndex.size();
}

CBlockIndex* Tip()
{
    LOCK(cs_main);
    return chainActive.Tip();
}

CBlockIndex* BestHeader()
{
    LOCK(cs_main);
    return pindexBestHeader;
}

/** Submit a block; true if it became the tip */
bool Submit(const CBlock& block)
{
    ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, nullptr);
    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash() == block.GetHash();
}

/** A regtest chain of a few blocks, and blocks built on any of them; with the token
 * database that disconnecting blocks in a reorganisation needs */
struct HeaderSetup : public TestingSetup {
    std::vector<CBlock> blocks; // blocks[i] is at height i + 1
    CTokensDB* prevTokensDb;

    HeaderSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        prevTokensDb = ptokensdb;
        ptokensdb = new CTokensDB(1 << 20, true, true);
        for (int i = 0; i < 12; i++) {
            std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(CScript() << OP_TRUE);
            CBlock block = pblocktemplate->block;
            block.vtx.resize(1);
            unsigned int nExtraNonce = 0;
            {
                LOCK(cs_main);
                IncrementExtraNonce(&block, chainActive.Tip(), nExtraNonce);
            }
            Mine(block);
            if (!Submit(block)) throw std::runtime_error("HeaderSetup: block not connected");
            blocks.push_back(block);
        }
    }

    ~HeaderSetup()
    {
        delete ptokensdb;
        ptokensdb = prevTokensDb;
    }

    int Height() const { return (int)blocks.size(); }

    /** A block with only a coinbase on top of prev, which is at height nHeight - 1: prev's
     * coinbase with the new height (and `extra` after it, to tell siblings apart), the same
     * target (constant on regtest at these heights) and a time one second later */
    static CBlock BuildOn(const CBlock& prev, int nHeight, opcodetype extra = OP_0)
    {
        CBlock block = prev;
        block.hashPrevBlock = prev.GetHash();
        block.nTime = prev.nTime + 1;
        block.nNonce = 1;
        block.vtx.resize(1);
        block.vtx[0].vin[0].scriptSig = CScript() << nHeight << extra;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.fChecked = false;
        Mine(block);
        return block;
    }

    /** BuildOn with a coinbase that pays one satoshi too much: valid until it is connected */
    static CBlock BuildInvalidOn(const CBlock& prev, int nHeight)
    {
        CBlock block = BuildOn(prev, nHeight);
        block.vtx[0].vout[0].nValue += 1;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.fChecked = false;
        Mine(block);
        return block;
    }

    /** A header on top of the tip, mined after `modify` */
    CBlockHeader HeaderOnTip(std::function<void(CBlockHeader&)> modify = nullptr) const
    {
        CBlockHeader header = BuildOn(blocks.back(), Height() + 1).GetBlockHeader();
        if (modify) {
            modify(header);
            header.nNonce = 1;
            Mine(header);
        }
        return header;
    }
};

/** Turns off the block index consistency check (CheckBlockIndex) while it lives */
struct NoCheckBlockIndex {
    bool fWas = fCheckBlockIndex;
    NoCheckBlockIndex() { fCheckBlockIndex = false; }
    ~NoCheckBlockIndex() { fCheckBlockIndex = fWas; }
};

/** Restores fCheckpointsEnabled */
struct CheckpointsGuard {
    bool fWas = fCheckpointsEnabled;
    ~CheckpointsGuard() { fCheckpointsEnabled = fWas; }
};

struct RegtestSetup : public TestingSetup {
    RegtestSetup() : TestingSetup(CBaseChainParams::REGTEST) {}
};

/** Sets the fork height above the genesis block before the chain is loaded */
struct ForkAboveGenesis {
    ConsensusGlobalsGuard globals;
    ForkAboveGenesis() { globals.Set(1890000, 21000); }
};

/** Mainnet genesis block loaded while the fork height is still ahead */
struct PreForkGenesisSetup : public ForkAboveGenesis, public TestingSetup {
    PreForkGenesisSetup() : ForkAboveGenesis(), TestingSetup(CBaseChainParams::MAIN) {}
};

/** A version 7 header on top of pindexPrev with the target it requires, mined */
CBlockHeader HeaderOn(const CBlockIndex* pindexPrev, ::int64_t nTime, int nVersion = VERSION_of_block_for_yac_05x_new)
{
    CBlockHeader header;
    header.nVersion = nVersion;
    header.hashPrevBlock = pindexPrev->GetBlockHash();
    header.hashMerkleRoot = uint256S("0x5e5e");
    header.nTime = nTime;
    header.nBits = GetNextTargetRequired(pindexPrev, false);
    header.nNonce = 1;
    Mine(header);
    return header;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(validation_header_tests, HeaderSetup)

/* A new header gets a block index entry (tree-valid, without data) and becomes the best
 * header; the active chain stays */
BOOST_AUTO_TEST_CASE(accept_header)
{
    CBlockIndex* pindexTip = Tip();
    const size_t nIndexSize = IndexSize();
    const CBlock a = BuildOn(blocks.back(), Height() + 1);

    HeaderResult result = AcceptHeaders({a.GetBlockHeader()});
    BOOST_CHECK_EQUAL(result.reason, "");
    BOOST_REQUIRE(result.pindex != nullptr);
    CBlockIndex* pindex = Index(a.GetHash());
    BOOST_CHECK(result.pindex == pindex);
    BOOST_CHECK_EQUAL(IndexSize(), nIndexSize + 1);
    {
        LOCK(cs_main);
        BOOST_CHECK(pindex->GetBlockHash() == a.GetHash());
        BOOST_CHECK(pindex->pprev == pindexTip);
        BOOST_CHECK_EQUAL(pindex->nHeight, pindexTip->nHeight + 1);
        BOOST_CHECK(pindex->pskip != nullptr && pindex->pskip->nHeight < pindex->nHeight);
        BOOST_CHECK_EQUAL(pindex->nVersion, a.nVersion);
        BOOST_CHECK(pindex->hashMerkleRoot == a.hashMerkleRoot);
        BOOST_CHECK_EQUAL(pindex->nTime, a.nTime);
        BOOST_CHECK_EQUAL(pindex->nBits, a.nBits);
        BOOST_CHECK_EQUAL(pindex->nNonce, a.nNonce);
        BOOST_CHECK(pindex->IsProofOfWork());
        BOOST_CHECK(pindex->IsValid(BLOCK_VALID_TREE));
        BOOST_CHECK(!pindex->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_CHECK(!(pindex->nStatus & BLOCK_HAVE_DATA));
        BOOST_CHECK_EQUAL(pindex->nTx, 0U);
        BOOST_CHECK_EQUAL(pindex->nChainTx, 0U);
        BOOST_CHECK_EQUAL(pindex->nSequenceId, 0);
        BOOST_CHECK(pindex->GetBlockTrust() > 0);
        BOOST_CHECK(pindex->bnChainTrust == pindexTip->bnChainTrust + pindex->GetBlockTrust());
        BOOST_CHECK_EQUAL(pindex->nTimeMax, std::max(pindexTip->nTimeMax, a.GetBlockTime()));
    }
    BOOST_CHECK(BestHeader() == pindex);
    BOOST_CHECK(Tip() == pindexTip);

    // A known header is accepted again; nothing is added
    result = AcceptHeaders({a.GetBlockHeader()});
    BOOST_CHECK_EQUAL(result.reason, "");
    BOOST_CHECK(result.pindex == pindex);
    BOOST_CHECK_EQUAL(IndexSize(), nIndexSize + 1);

    // A sibling with the same work is added but doesn't replace the best header
    const CBlock sibling = BuildOn(blocks.back(), Height() + 1, OP_1);
    result = AcceptHeaders({sibling.GetBlockHeader()});
    BOOST_CHECK_EQUAL(result.reason, "");
    BOOST_CHECK(result.pindex != pindex);
    BOOST_CHECK(BestHeader() == pindex);

    // Several headers at once: the entry of the last one is returned
    const CBlock b = BuildOn(a, Height() + 2);
    const CBlock c = BuildOn(b, Height() + 3);
    result = AcceptHeaders({b.GetBlockHeader(), c.GetBlockHeader()});
    BOOST_CHECK_EQUAL(result.reason, "");
    BOOST_CHECK(result.pindex == Index(c.GetHash()));
    BOOST_CHECK(Index(b.GetHash()) != nullptr);
    BOOST_CHECK(BestHeader() == Index(c.GetHash()));
    BOOST_CHECK(Tip() == pindexTip);

    // The genesis header is known without any check
    result = AcceptHeaders({Params().GenesisBlock().GetBlockHeader()});
    BOOST_CHECK_EQUAL(result.reason, "");
    BOOST_CHECK(result.pindex == Index(Params().GetConsensus().hashGenesisBlock));

    // The full block after its header: same entry, now with data, linked and connected
    BOOST_CHECK(Submit(a));
    BOOST_CHECK(Tip() == pindex);
    LOCK(cs_main);
    BOOST_CHECK(pindex->nStatus & BLOCK_HAVE_DATA);
    BOOST_CHECK(pindex->IsValid(BLOCK_VALID_SCRIPTS));
    BOOST_CHECK_EQUAL(pindex->nTx, 1U);
    BOOST_CHECK_EQUAL(pindex->nChainTx, pindexTip->nChainTx + 1);
    BOOST_CHECK(pindex->nSequenceId > pindexTip->nSequenceId);
}

/* ProcessNewBlockHeaders stops at the first header that fails and hands it back; the ones
 * before it are kept */
BOOST_AUTO_TEST_CASE(first_invalid_header)
{
    const CBlock good = BuildOn(blocks.back(), Height() + 1);
    CBlockHeader orphan = BuildOn(good, Height() + 2).GetBlockHeader();
    orphan.hashPrevBlock = uint256S("0x5e5e");
    Mine(orphan);
    CBlockHeader firstInvalid;
    HeaderResult result = AcceptHeaders({good.GetBlockHeader(), orphan}, &firstInvalid);
    BOOST_CHECK_EQUAL(result.reason, "prev-blk-not-found");
    BOOST_CHECK(firstInvalid.GetHash() == orphan.GetHash());
    BOOST_CHECK(Index(good.GetHash()) != nullptr);
    BOOST_CHECK(Index(orphan.GetHash()) == nullptr);

    // On success it is null
    result = AcceptHeaders({good.GetBlockHeader()}, &firstInvalid);
    BOOST_CHECK_EQUAL(result.reason, "");
    BOOST_CHECK(firstInvalid.IsNull());
}

/* Headers that are rejected, with the reason and misbehaviour score; none of them is stored */
BOOST_AUTO_TEST_CASE(reject_header)
{
    const size_t nIndexSize = IndexSize();
    CBlockIndex* pindexBestHeader = BestHeader();
    const unsigned int nBits = blocks.back().nBits;
    BOOST_CHECK_EQUAL(GetNextTargetRequired(Tip(), false), nBits);

    struct Case {
        std::string name;
        CBlockHeader header;
        std::string reason;
        int nScore;
        unsigned int nCode;
    };
    std::vector<Case> cases;

    // Unknown previous block
    cases.push_back({"unknown prev", HeaderOnTip([](CBlockHeader& h) { h.hashPrevBlock = uint256S("0x5e5e"); }),
                     "prev-blk-not-found", 10, 0});

    // Proof of work: a hash above the target, a target above the limit
    CBlockHeader badPow = HeaderOnTip();
    MineBadly(badPow);
    cases.push_back({"hash above target", badPow, "no reason", 50, 0});
    CBlockHeader easy = HeaderOnTip();
    easy.nBits = (Params().GetConsensus().powLimit * 2).GetCompact(); // no nonce can meet it
    cases.push_back({"target above limit", easy, "no reason", 50, 0});

    // Target other than the required one (a slightly lower target, still easy enough to mine here)
    cases.push_back({"wrong target", HeaderOnTip([&](CBlockHeader& h) { h.nBits = nBits - 1; }),
                     "bad-diffbits", 10, REJECT_INVALID});

    // Time: not after the median time past of the previous block, or too far ahead
    const ::int64_t nMedianTimePast = Tip()->GetMedianTimePast();
    cases.push_back({"time at median time past", HeaderOnTip([&](CBlockHeader& h) { h.nTime = nMedianTimePast; }),
                     "time-too-old", 0, REJECT_INVALID});
    const ::int64_t nFuture = GetAdjustedTime() + MAX_FUTURE_BLOCK_TIME + 60;
    cases.push_back({"time too far ahead", HeaderOnTip([&](CBlockHeader& h) { h.nTime = nFuture; }),
                     "time-too-new", 0, REJECT_INVALID});

    for (const Case& c : cases) {
        BOOST_TEST_MESSAGE(c.name);
        HeaderResult result = AcceptHeaders({c.header});
        BOOST_CHECK_EQUAL(result.reason, c.reason);
        BOOST_CHECK_EQUAL(result.nScore, c.nScore);
        BOOST_CHECK_EQUAL(result.nCode, c.nCode);
        BOOST_CHECK(Index(c.header.GetHash()) == nullptr);
    }
    BOOST_CHECK_EQUAL(IndexSize(), nIndexSize);
    BOOST_CHECK(BestHeader() == pindexBestHeader);

    // Times just inside the window are accepted
    HeaderResult result = AcceptHeaders({HeaderOnTip([&](CBlockHeader& h) { h.nTime = nMedianTimePast + 1; })});
    BOOST_CHECK_EQUAL(result.reason, "");
    result = AcceptHeaders({HeaderOnTip([&](CBlockHeader& h) { h.nTime = GetAdjustedTime() + MAX_FUTURE_BLOCK_TIME - 60; })});
    BOOST_CHECK_EQUAL(result.reason, "");
}

/* Blocks that arrive before their parent wait (no chain transaction count, no sequence id)
 * and are linked when the parent arrives */
BOOST_AUTO_TEST_CASE(blocks_out_of_order)
{
    CBlockIndex* pindexTip = Tip();
    const CBlock a = BuildOn(blocks.back(), Height() + 1);
    const CBlock b = BuildOn(a, Height() + 2);
    BOOST_CHECK_EQUAL(AcceptHeaders({a.GetBlockHeader(), b.GetBlockHeader()}).reason, "");
    CBlockIndex* pindexA = Index(a.GetHash());
    CBlockIndex* pindexB = Index(b.GetHash());

    BOOST_CHECK(!Submit(b));
    BOOST_CHECK(Tip() == pindexTip);
    {
        LOCK(cs_main);
        BOOST_CHECK(pindexB->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(pindexB->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_CHECK_EQUAL(pindexB->nTx, 1U);
        BOOST_CHECK_EQUAL(pindexB->nChainTx, 0U);
        BOOST_CHECK_EQUAL(pindexB->nSequenceId, 0);
    }

    BOOST_CHECK(!Submit(a)); // b, not a, becomes the tip
    BOOST_CHECK(Tip() == pindexB);
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(pindexA->nChainTx, pindexTip->nChainTx + 1);
    BOOST_CHECK_EQUAL(pindexB->nChainTx, pindexTip->nChainTx + 2);
    BOOST_CHECK(pindexA->nSequenceId > pindexTip->nSequenceId);
    BOOST_CHECK(pindexB->nSequenceId > pindexA->nSequenceId);
    BOOST_CHECK(pindexA->IsValid(BLOCK_VALID_SCRIPTS));
    BOOST_CHECK(pindexB->IsValid(BLOCK_VALID_SCRIPTS));
}

/* A block that fails when connected marks its descendants invalid: blocks through the
 * search for the best chain, headers when a header builds on them */
BOOST_AUTO_TEST_CASE(invalid_ancestor)
{
    CBlockIndex* pindexTip = Tip();
    const CBlock x1 = BuildInvalidOn(blocks.back(), Height() + 1);
    const CBlock x2 = BuildOn(x1, Height() + 2);
    const CBlock y2 = BuildOn(x1, Height() + 2, OP_1); // stays a header
    BOOST_CHECK_EQUAL(AcceptHeaders({x1.GetBlockHeader(), x2.GetBlockHeader(), y2.GetBlockHeader()}).reason, "");
    CBlockIndex* pindexX1 = Index(x1.GetHash());
    CBlockIndex* pindexX2 = Index(x2.GetHash());
    CBlockIndex* pindexY2 = Index(y2.GetHash());

    // A header on another branch that is only a header too
    const CBlock e1 = BuildOn(blocks.back(), Height() + 1, OP_1);
    BOOST_CHECK_EQUAL(AcceptHeaders({e1.GetBlockHeader()}).reason, "");

    // x2 waits for x1; with x1 both are candidates for the tip, x1 fails to connect
    BOOST_CHECK(!Submit(x2));
    BOOST_CHECK(!Submit(x1));
    BOOST_CHECK(Tip() == pindexTip);
    {
        LOCK(cs_main);
        BOOST_CHECK(pindexX1->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(pindexX2->nStatus & BLOCK_FAILED_CHILD);
        BOOST_CHECK(pindexX2->nChainTx > 0);
        BOOST_CHECK_EQUAL(pindexY2->nStatus & BLOCK_FAILED_MASK, 0U);
    }

    // The failed block's header again, and a header on it
    HeaderResult result = AcceptHeaders({x1.GetBlockHeader()});
    BOOST_CHECK_EQUAL(result.reason, "duplicate");
    BOOST_CHECK_EQUAL(result.nScore, 0);
    const CBlock x3 = BuildOn(x2, Height() + 3);
    result = AcceptHeaders({x3.GetBlockHeader()});
    BOOST_CHECK_EQUAL(result.reason, "bad-prevblk");
    BOOST_CHECK_EQUAL(result.nScore, 100);
    BOOST_CHECK(Index(x3.GetHash()) == nullptr);

    // A header on y2: its parent isn't marked yet, but descends from a failed block, so
    // the parent is marked and the header rejected
    const CBlock y3 = BuildOn(y2, Height() + 3);
    result = AcceptHeaders({y3.GetBlockHeader()});
    BOOST_CHECK_EQUAL(result.reason, "bad-prevblk");
    BOOST_CHECK_EQUAL(result.nScore, 100);
    BOOST_CHECK(Index(y3.GetHash()) == nullptr);
    {
        LOCK(cs_main);
        BOOST_CHECK(pindexY2->nStatus & BLOCK_FAILED_CHILD);
    }

    // A header on the other branch, whose parent has no data either, is accepted
    const CBlock e2 = BuildOn(e1, Height() + 2);
    BOOST_CHECK_EQUAL(AcceptHeaders({e2.GetBlockHeader()}).reason, "");

    // The chain goes on from the old tip
    BOOST_CHECK(Submit(BuildOn(blocks.back(), Height() + 1, OP_2)));
}

/* A candidate for the tip whose ancestor has no data (as when the data was pruned) is set
 * aside until that block arrives again; then the chain moves to it */
BOOST_AUTO_TEST_CASE(candidate_missing_data)
{
    CBlockIndex* pindexTip = Tip();
    // f1 is a sibling of the tip: the same work, so it stays aside
    const CBlock f1 = BuildOn(blocks[Height() - 2], Height(), OP_1);
    BOOST_CHECK(!Submit(f1));
    CBlockIndex* pindexF1 = Index(f1.GetHash());
    BOOST_REQUIRE(pindexF1 != nullptr);
    BOOST_CHECK(pindexF1->nChainTx > 0);
    const CBlock f2 = BuildOn(f1, Height() + 1);
    {
        // f1's data flag removed: the index is not consistent until f1 arrives again
        NoCheckBlockIndex noCheck;
        {
            LOCK(cs_main);
            pindexF1->nStatus &= ~BLOCK_HAVE_DATA;
        }
        BOOST_CHECK(!Submit(f2));
        BOOST_CHECK(Tip() == pindexTip);
        CBlockIndex* pindexF2 = Index(f2.GetHash());
        {
            LOCK(cs_main);
            BOOST_CHECK(pindexF2->nStatus & BLOCK_HAVE_DATA);
            BOOST_CHECK_EQUAL(pindexF2->nStatus & BLOCK_FAILED_MASK, 0U);
        }

        // f1 again: f2 is linked to it and becomes the tip
        BOOST_CHECK(!Submit(f1));
        BOOST_CHECK(Tip() == pindexF2);
    }
    // The index is consistent again (checked when the next block is processed)
    BOOST_CHECK(Submit(BuildOn(f2, Height() + 2)));
}

/* Rules that need a parent at a given height or time; the parents are synthetic block index
 * entries, so only rejected headers are submitted */
BOOST_FIXTURE_TEST_CASE(header_context_on_synthetic_parents, RegtestSetup)
{
    SyntheticChain chain;
    const unsigned int nBitsLimit = Params().GetConsensus().powLimit.GetCompact();
    const ::int64_t nNow = GetAdjustedTime();

    // Height 15000 has a checkpoint (the checkpoints are mainnet's on every network)
    CBlockIndex* pindexCheckpointPrev = chain.Add(nullptr, nNow - 600, nBitsLimit);
    pindexCheckpointPrev->nHeight = 14999;
    chain.Register(pindexCheckpointPrev);
    CBlockHeader header = HeaderOn(pindexCheckpointPrev, nNow - 300);
    HeaderResult result = AcceptHeaders({header});
    BOOST_CHECK_EQUAL(result.reason, "bad-fork-prior-to-checkpoint");
    BOOST_CHECK_EQUAL(result.nScore, 100);
    BOOST_CHECK_EQUAL(result.nCode, REJECT_CHECKPOINT);
    {
        // Without checkpoints the header gets to the next check (here: its time)
        CheckpointsGuard guard;
        fCheckpointsEnabled = false;
        header = HeaderOn(pindexCheckpointPrev, nNow - 600);
        BOOST_CHECK_EQUAL(AcceptHeaders({header}).reason, "time-too-old");
    }

    // A parent far ahead of its median time past: a header after the median time past but
    // more than MAX_FUTURE_BLOCK_TIME before its parent is too old
    CBlockIndex* pindexEarly = chain.Add(nullptr, nNow - 2 * 24 * 60 * 60, nBitsLimit);
    CBlockIndex* pindexLate = chain.Add(pindexEarly, nNow - 24 * 60 * 60, nBitsLimit);
    chain.Register(pindexLate);
    BOOST_CHECK_EQUAL(pindexLate->GetMedianTimePast(), pindexEarly->GetBlockTime());
    header = HeaderOn(pindexLate, pindexEarly->GetBlockTime() + 1);
    result = AcceptHeaders({header});
    BOOST_CHECK_EQUAL(result.reason, "time-too-old");
    BOOST_CHECK_EQUAL(result.nScore, 0);

    // A version 6 header after the fork height, which is 0 on regtest
    CBlockIndex* pindexOld = chain.Add(nullptr, 1368000000, nBitsLimit);
    pindexOld = chain.Add(pindexOld, 1368000100, nBitsLimit);
    chain.Register(pindexOld);
    header = HeaderOn(pindexOld, 1368000200, VERSION_of_block_for_yac_049);
    result = AcceptHeaders({header});
    BOOST_CHECK_EQUAL(result.reason, "bad-version(0x00000006)");
    BOOST_CHECK_EQUAL(result.nCode, REJECT_OBSOLETE);
}

/* Below the fork height, a block that is received also gets its stake modifier: for the
 * mainnet genesis block, modifier 0 and the checksum of the modifier checkpoint at height 0 */
BOOST_FIXTURE_TEST_CASE(genesis_stake_modifier_before_fork, PreForkGenesisSetup)
{
    LOCK(cs_main);
    CBlockIndex* pindexGenesis = chainActive.Genesis();
    BOOST_REQUIRE(pindexGenesis != nullptr);
    BOOST_CHECK(pindexGenesis->GetBlockHash() == Params().GetConsensus().hashGenesisBlock);
    BOOST_CHECK(pindexGenesis->IsProofOfWork());
    BOOST_CHECK(pindexGenesis->GeneratedStakeModifier());
    BOOST_CHECK_EQUAL(pindexGenesis->nStakeModifier, 0U);
    BOOST_CHECK_EQUAL(pindexGenesis->nStakeModifierChecksum, 0x0e00670bU);
}

BOOST_AUTO_TEST_SUITE_END()
