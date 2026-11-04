// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block validation paths: the rules TestBlockValidity applies (relative time
// locks included), connecting and invalidating blocks (DisconnectBlock), blocks
// that fail while being connected (InvalidBlockFound), VerifyDB, ReplayBlocks
// after an interrupted flush (RollforwardBlock) and without usable undo data, and
// moving the tip (ActivateBestChain, ConnectTip, DisconnectTip, InvalidateBlock)
// when a block or its undo data can't be read, a shutdown is requested, or the
// block is on a side branch.
//
// Note: script checks only run above the last checkpoint (fScriptChecks), and
// the checkpoint map is mainnet's, so signatures aren't verified here.

#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "init.h"
#include "miner.h"
#include "pow.h"
#include "random.h"
#include "script/sign.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "txdb.h"
#include "txmempool.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "warnings.h"

#include "test/test_bitcoin.h"

#include <functional>
#include <map>
#include <string>

#include <boost/test/unit_test.hpp>

namespace {

/** Regtest chain with mature coinbases, and the token database DisconnectBlock needs */
struct ValidationSetup : public TestChain100Setup {
    CScript scriptPubKey;
    std::vector<CTransaction> matureCoinbases; // spendable
    std::vector<CTransaction> recentCoinbases; // the newest ones aren't mature yet
    CTokensDB* prevTokensDb;

    ValidationSetup()
    {
        prevTokensDb = ptokensdb;
        ptokensdb = new CTokensDB(1 << 20, true, true);
        scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        matureCoinbases = coinbaseTxns;
        for (int i = 0; i < COINBASE_MATURITY_AFTER_HARDFORK; i++)
            recentCoinbases.push_back(CreateAndProcessBlock({}, scriptPubKey).vtx[0]);
    }

    ~ValidationSetup()
    {
        delete ptokensdb;
        ptokensdb = prevTokensDb;
    }

    /** Signed spend of output n of prev; `modify` changes the tx before signing */
    CTransaction Spend(const CTransaction& prev, unsigned int n = 0, CAmount nFee = CENT,
                       std::function<void(CMutableTransaction&)> modify = nullptr)
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(prev.GetHash(), n);
        tx.vout.resize(1);
        tx.vout[0].nValue = prev.vout[n].nValue - nFee;
        tx.vout[0].scriptPubKey = scriptPubKey;
        if (modify) modify(tx);
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(prev.vout[n].scriptPubKey, tx, 0, SIGHASH_ALL);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[0].scriptSig = CScript() << vchSig;
        return CTransaction(tx);
    }

    /** Find a nonce for the block as it is (merkle root not recomputed) */
    static void Mine(CBlock& block)
    {
        block.fChecked = false;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
    }

    /** Recompute the merkle root, then mine */
    static void Solve(CBlock& block)
    {
        block.hashMerkleRoot = block.BuildMerkleTree();
        Mine(block);
    }

    /** A valid next block with the given transactions, paying the coinbase to coinbaseScript */
    CBlock BuildBlock(const std::vector<CTransaction>& txs, const CScript& coinbaseScript)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(coinbaseScript);
        CBlock block = pblocktemplate->block;
        block.vtx.resize(1);
        for (const CTransaction& tx : txs) block.vtx.push_back(tx);
        block.nTime = std::max(block.GetBlockTime(), block.GetMaxTransactionTime());
        unsigned int nExtraNonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, chainActive.Tip(), nExtraNonce);
        }
        Mine(block);
        return block;
    }

    CBlock BuildBlock(const std::vector<CTransaction>& txs) { return BuildBlock(txs, scriptPubKey); }

    /** A valid block on pprev, which need not be the tip */
    CBlock BuildOn(CBlockIndex* pprev, const std::vector<CTransaction>& txs, const CScript& coinbaseScript)
    {
        CBlock block = BuildBlock(txs, coinbaseScript);
        block.hashPrevBlock = pprev->GetBlockHash();
        block.nBits = GetNextTargetRequired(pprev, false);
        block.nTime = std::max(block.GetBlockTime(), pprev->GetMedianTimePast() + 1);
        unsigned int nExtraNonce = 0;
        IncrementExtraNonce(&block, pprev, nExtraNonce); // coinbase height and merkle root
        Mine(block);
        return block;
    }

    static CBlockIndex* Index(const CBlock& block)
    {
        LOCK(cs_main);
        BlockMap::iterator it = mapBlockIndex.find(block.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        return it->second;
    }

    static void AddToMempool(const CTransaction& tx)
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), nullptr));
    }

    static bool Failed(const CBlockIndex* pindex)
    {
        LOCK(cs_main);
        return pindex->nStatus & BLOCK_FAILED_MASK;
    }

    /** TestBlockValidity on top of the tip: "" if valid, else the reject reason (the debug message if it has none) */
    static std::string Validity(const CBlock& block, bool fCheckPOW = true)
    {
        LOCK(cs_main);
        CValidationState state;
        if (TestBlockValidity(state, Params(), block, chainActive.Tip(), fCheckPOW)) return "";
        if (!state.GetRejectReason().empty()) return state.GetRejectReason();
        return state.GetDebugMessage().empty() ? "no reason" : state.GetDebugMessage();
    }

    /** Submit a block; true if it became the tip */
    static bool Submit(const CBlock& block)
    {
        ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, nullptr);
        LOCK(cs_main);
        return chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    static CBlockIndex* Tip()
    {
        LOCK(cs_main);
        return chainActive.Tip();
    }

    static bool HaveCoin(const CCoinsView& view, const COutPoint& out)
    {
        LOCK(cs_main);
        return view.HaveCoin(out);
    }
};

/** Coins view that reports an interrupted flush (GetHeadBlocks), over a copy of a UTXO set */
class HeadsView : public CCoinsViewBacked
{
public:
    std::vector<uint256> heads;
    explicit HeadsView(CCoinsView* base) : CCoinsViewBacked(base) {}
    std::vector<uint256> GetHeadBlocks() const override { return heads; }
};

/** Copy of the current UTXO set (flushed to the coins database first). TestingSetup
 * keeps its coins database in a member that hides the global pcoinsdbview. */
struct UtxoSnapshot {
    CCoinsView empty;
    CCoinsViewCache coins;
    explicit UtxoSnapshot(CCoinsViewDB* pcoinsdbview) : coins(&empty)
    {
        FlushStateToDisk();
        LOCK(cs_main);
        std::unique_ptr<CCoinsViewCursor> cursor(pcoinsdbview->Cursor());
        for (; cursor->Valid(); cursor->Next()) {
            COutPoint key;
            Coin coin;
            BOOST_REQUIRE(cursor->GetKey(key) && cursor->GetValue(coin));
            coins.AddCoin(key, std::move(coin), false);
        }
        coins.SetBestBlock(pcoinsdbview->GetBestBlock());
    }
};

/** Records shutdown requests while it lives, and clears the misc warning that
 *  AbortNode sets, both now with Reset() and again when it goes out of scope */
struct AbortGuard {
    ShutdownRequestRecorder recorder;
    static void Reset()
    {
        ShutdownRequestRecorder::Reset();
        SetMiscWarning("");
    }
    ~AbortGuard() { SetMiscWarning(""); }
};

/** Points a block's data or undo position past the end of its file while it lives,
 *  so reading it fails; Restore() puts it back earlier */
class BrokenPos
{
    unsigned int& m_pos;
    const unsigned int m_saved;

public:
    explicit BrokenPos(unsigned int& pos) : m_pos(pos), m_saved(pos)
    {
        LOCK(cs_main);
        m_pos = 0x7fffffff;
    }
    void Restore()
    {
        LOCK(cs_main);
        m_pos = m_saved;
    }
    ~BrokenPos() { Restore(); }
    BrokenPos(const BrokenPos&) = delete;
    BrokenPos& operator=(const BrokenPos&) = delete;
};

/** Restores the reissue maps of the token layer when it goes out of scope */
struct ReissueMapsGuard {
    const std::map<uint256, std::string> savedTx = mapReissuedTx;
    const std::map<std::string, uint256> savedTokens = mapReissuedTokens;
    ~ReissueMapsGuard()
    {
        mapReissuedTx = savedTx;
        mapReissuedTokens = savedTokens;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, ValidationSetup)

BOOST_AUTO_TEST_CASE(test_block_validity)
{
    CTransaction spend = Spend(matureCoinbases[0]);
    const int nHeight = Tip()->nHeight + 1;
    BOOST_CHECK_EQUAL(Validity(BuildBlock({spend})), "");

    // Header in context
    CBlock block = BuildBlock({spend});
    block.nBits -= 1; // still an easy regtest target, but not the required one
    Mine(block);
    BOOST_CHECK_EQUAL(Validity(block), "bad-diffbits");

    block = BuildBlock({spend});
    block.nTime = Tip()->GetMedianTimePast();
    Mine(block);
    BOOST_CHECK_EQUAL(Validity(block), "time-too-old");

    block = BuildBlock({spend});
    block.nTime = GetAdjustedTime() + MAX_FUTURE_BLOCK_TIME + 60;
    Mine(block);
    BOOST_CHECK_EQUAL(Validity(block), "time-too-new");

    // Pre-1.0 header version (not mined: the header check fails before proof of work is checked)
    block = BuildBlock({spend});
    block.nVersion = VERSION_of_block_for_yac_05x_new - 1;
    BOOST_CHECK_EQUAL(Validity(block).substr(0, 11), "bad-version");

    // Proof of work: a nonce whose hash misses the target. The failure has no reject
    // reason, so also check that the block is valid when proof of work isn't checked.
    block = BuildBlock({spend});
    for (int i = 0; i < 1000 && CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()); i++)
        ++block.nNonce;
    block.fChecked = false;
    BOOST_REQUIRE(!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()));
    BOOST_CHECK_EQUAL(Validity(block), "no reason");
    BOOST_CHECK_EQUAL(Validity(block, false), "");

    // Block structure
    block = BuildBlock({spend});
    block.hashMerkleRoot = InsecureRand256();
    Mine(block);
    BOOST_CHECK_EQUAL(Validity(block), "bad-txnmrklroot");

    block = BuildBlock({spend});
    block.vtx.erase(block.vtx.begin());
    Solve(block);
    BOOST_CHECK_EQUAL(Validity(block), "bad-cb-missing");

    block = BuildBlock({spend});
    CTransaction coinbase2 = block.vtx[0];
    coinbase2.vin[0].scriptSig = CScript() << nHeight << OP_2;
    block.vtx.push_back(coinbase2);
    Solve(block);
    BOOST_CHECK_EQUAL(Validity(block), "bad-cb-multiple");

    BOOST_CHECK_EQUAL(Validity(BuildBlock({spend, spend})), "bad-txns-duplicate");

    block = BuildBlock({spend});
    block.vtx[0].vin[0].scriptSig = CScript() << (nHeight + 5) << OP_0;
    Solve(block);
    BOOST_CHECK_EQUAL(Validity(block), "bad-cb-height");

    // A block can't be older than its transactions
    block = BuildBlock({spend});
    block.vtx[1] = Spend(matureCoinbases[0], 0, CENT, [&](CMutableTransaction& tx) { tx.nTime = block.nTime + 1; });
    Solve(block);
    BOOST_CHECK_EQUAL(Validity(block), "bad-tx-time");

    // Transactions in context
    CTransaction locked = Spend(matureCoinbases[1], 0, CENT, [&](CMutableTransaction& tx) {
        tx.nLockTime = nHeight + 10;
        tx.vin[0].nSequence = 0;
    });
    BOOST_CHECK_EQUAL(Validity(BuildBlock({locked})), "bad-txns-nonfinal");

    CTransaction v1 = Spend(matureCoinbases[1], 0, CENT, [](CMutableTransaction& tx) {
        tx.nVersion = CTransaction::CURRENT_VERSION_of_Tx_for_yac_old;
    });
    BOOST_CHECK_EQUAL(Validity(BuildBlock({v1})), "bad-txns-version");

    // Connecting: reward, inputs, maturity, timestamps
    block = BuildBlock({spend});
    block.vtx[0].vout[0].nValue += 1;
    Solve(block);
    BOOST_CHECK_EQUAL(Validity(block), "bad-cb-amount");

    CTransaction missing = Spend(matureCoinbases[1], 0, CENT, [](CMutableTransaction& tx) { tx.vin[0].prevout.n = 5; });
    // Missing or already spent inputs are rejected without a reject reason (only a debug message)
    BOOST_CHECK_EQUAL(Validity(BuildBlock({missing})), "Inputs unavailable");
    CTransaction doubleSpend = Spend(matureCoinbases[0], 0, 2 * CENT);
    BOOST_CHECK_EQUAL(Validity(BuildBlock({spend, doubleSpend})), "Inputs unavailable");

    CTransaction premature = Spend(recentCoinbases.back());
    BOOST_CHECK_EQUAL(Validity(BuildBlock({premature})), "bad-txns-premature-spend-of-coinbase/coinstake");

    CTransaction tooEarly = Spend(matureCoinbases[1], 0, CENT, [&](CMutableTransaction& tx) {
        tx.nTime = matureCoinbases[1].nTime - 1;
    });
    BOOST_CHECK_EQUAL(Validity(BuildBlock({tooEarly})), "bad-txns-spent-too-early");

    // A confirmed transaction with unspent outputs can't be included again
    BOOST_CHECK(Submit(BuildBlock({spend})));
    BOOST_CHECK_EQUAL(Validity(BuildBlock({spend})), "bad-txns-BIP30");
    BOOST_CHECK_EQUAL(Validity(BuildBlock({Spend(spend)})), "");
}

BOOST_AUTO_TEST_CASE(connect_and_invalidate)
{
    CBlockIndex* pindexStart = Tip();
    CTransaction spend = Spend(matureCoinbases[0]);
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_CHECK(AcceptToMemoryPool(mempool, state, MakeTransactionRef(spend), nullptr));
    }
    const COutPoint spent(matureCoinbases[0].GetHash(), 0), created(spend.GetHash(), 0);

    CBlock blockA = BuildBlock({spend});
    BOOST_REQUIRE(Submit(blockA));
    BOOST_CHECK(!mempool.exists(spend.GetHash()));
    BOOST_CHECK(!HaveCoin(*pcoinsTip, spent));
    BOOST_CHECK(HaveCoin(*pcoinsTip, created));
    CBlockIndex* pindexA = Tip();
    BOOST_REQUIRE(Submit(BuildBlock({})));
    CBlockIndex* pindexB = Tip();

    // Disconnects B and A: the UTXO set is as before A, its tx back in the mempool
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_CHECK(InvalidateBlock(state, Params(), pindexA));
    }
    BOOST_CHECK(Tip() == pindexStart);
    BOOST_CHECK(HaveCoin(*pcoinsTip, spent));
    BOOST_CHECK(!HaveCoin(*pcoinsTip, created));
    BOOST_CHECK(!HaveCoin(*pcoinsTip, COutPoint(blockA.vtx[0].GetHash(), 0)));
    BOOST_CHECK(pindexA->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(pindexB->nStatus & BLOCK_FAILED_CHILD);
    BOOST_CHECK(mempool.exists(spend.GetHash()));

    // The invalidated branch isn't reconnected, and A can't be submitted again
    {
        CValidationState state;
        BOOST_CHECK(ActivateBestChain(state, Params()));
    }
    BOOST_CHECK(Tip() == pindexStart);
    {
        CValidationState state;
        BOOST_CHECK(!ProcessNewBlockHeaders({blockA.GetBlockHeader()}, state, Params()));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "duplicate");
    }

    // The chain continues on the old tip (with a different coinbase than A)
    CBlock other = BuildBlock({spend}, CScript() << OP_TRUE);
    BOOST_CHECK(Submit(other));
    BOOST_CHECK(!HaveCoin(*pcoinsTip, spent));
    BOOST_CHECK(HaveCoin(*pcoinsTip, created));
}

/* A block that only fails while being connected is marked invalid (InvalidBlockFound) */
BOOST_AUTO_TEST_CASE(invalid_block_found)
{
    CBlockIndex* pindexStart = Tip();
    CBlock block = BuildBlock({});
    block.vtx[0].vout[0].nValue += 1; // the reward doesn't include fees after the fork
    Solve(block);
    BOOST_CHECK(!Submit(block));
    BOOST_CHECK(Tip() == pindexStart);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(block.GetHash()));
        BOOST_CHECK(mapBlockIndex[block.GetHash()]->nStatus & BLOCK_FAILED_VALID);
    }

    // A header building on it is rejected and not stored
    CBlockHeader child = block.GetBlockHeader();
    child.hashPrevBlock = block.GetHash();
    while (!CheckProofOfWork(child.GetHash(), child.nBits, Params().GetConsensus())) ++child.nNonce;
    CValidationState state;
    BOOST_CHECK(!ProcessNewBlockHeaders({child}, state, Params()));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-prevblk");
    LOCK(cs_main);
    BOOST_CHECK(!mapBlockIndex.count(child.GetHash()));
}

/* VerifyDB level 4 disconnects the recent blocks in memory and connects them again */
BOOST_AUTO_TEST_CASE(verify_db)
{
    CTransaction spend1 = Spend(matureCoinbases[0]);
    BOOST_REQUIRE(Submit(BuildBlock({spend1})));
    BOOST_REQUIRE(Submit(BuildBlock({Spend(spend1), Spend(matureCoinbases[1])})));
    CBlockIndex* pindexTip = Tip();
    const COutPoint spent(spend1.GetHash(), 0);

    // Level 4 includes level 3's memory-only disconnect, which runs while the coin caches
    // fit in nCoinCacheUsage (always, for a chain this small), so every block is
    // disconnected and then reconnected. VerifyDB works on its own cache.
    BOOST_CHECK(CVerifyDB().VerifyDB(Params(), pcoinsTip, 4, 0));
    // Nothing leaks into the real chain state
    BOOST_CHECK(Tip() == pindexTip);
    BOOST_CHECK(!HaveCoin(*pcoinsTip, spent));
    LOCK(cs_main);
    BOOST_CHECK(pcoinsTip->GetBestBlock() == pindexTip->GetBlockHash());
}

/** Compare a replayed UTXO set with pcoinsTip for the outputs of every block since height 1 */
static void CheckSameCoins(const CCoinsView& replayed)
{
    LOCK(cs_main);
    BOOST_CHECK(replayed.GetBestBlock() == chainActive.Tip()->GetBlockHash());
    for (CBlockIndex* pindex = chainActive[1]; pindex; pindex = chainActive.Next(pindex)) {
        CBlock block;
        BOOST_REQUIRE(ReadBlockFromDisk(block, pindex, Params().GetConsensus()));
        for (const CTransaction& tx : block.vtx) {
            for (unsigned int n = 0; n < tx.vout.size(); n++) {
                COutPoint out(tx.GetHash(), n);
                Coin a, b;
                bool fA = replayed.GetCoin(out, a), fB = pcoinsTip->GetCoin(out, b);
                BOOST_CHECK_EQUAL(fA, fB);
                if (fA && fB)
                    BOOST_CHECK(a.out == b.out && a.nHeight == b.nHeight && a.fCoinBase == b.fCoinBase && a.nTime == b.nTime);
            }
        }
    }
}

/** None of the block's outputs are in the view */
static void CheckNoOutputs(const CCoinsView& view, const CBlock& block)
{
    LOCK(cs_main);
    for (const CTransaction& tx : block.vtx)
        for (unsigned int n = 0; n < tx.vout.size(); n++)
            BOOST_CHECK(!view.HaveCoin(COutPoint(tx.GetHash(), n)));
}

/* Roll forward after an interrupted flush from tip A to a later tip */
BOOST_AUTO_TEST_CASE(replay_forward)
{
    UtxoSnapshot snapshot(pcoinsdbview);
    uint256 hashA = Tip()->GetBlockHash();
    CTransaction spend1 = Spend(matureCoinbases[0]);
    BOOST_REQUIRE(Submit(BuildBlock({spend1})));
    BOOST_REQUIRE(Submit(BuildBlock({Spend(spend1), Spend(matureCoinbases[1])})));

    HeadsView view(&snapshot.coins);
    view.heads = {Tip()->GetBlockHash(), hashA};
    BOOST_CHECK(ReplayBlocks(Params(), &view));
    CheckSameCoins(snapshot.coins);
}

/* Roll back a block that was replaced in a reorg, then forward along the new branch */
BOOST_AUTO_TEST_CASE(replay_reorg)
{
    CBlockIndex* pindexFork = Tip();
    UtxoSnapshot beforeX(pcoinsdbview);
    CBlock blockX = BuildBlock({Spend(matureCoinbases[0])});
    BOOST_REQUIRE(Submit(blockX));
    CBlockIndex* pindexX = Tip();
    UtxoSnapshot atX(pcoinsdbview);

    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_CHECK(InvalidateBlock(state, Params(), pindexX));
    }
    BOOST_REQUIRE(Tip() == pindexFork);
    // A different coinbase script than X: otherwise both coinbases (same height, extra nonce
    // and possibly second) would be the same transaction, and X's coinbase output would stay
    BOOST_REQUIRE(Submit(BuildBlock({Spend(matureCoinbases[1])}, CScript() << OP_TRUE)));
    BOOST_REQUIRE(Submit(BuildBlock({})));
    BOOST_CHECK(HaveCoin(*pcoinsTip, COutPoint(matureCoinbases[0].GetHash(), 0)));

    // Flush interrupted while moving from X to the new tip: X's spend is undone, its outputs removed
    HeadsView view(&atX.coins);
    view.heads = {Tip()->GetBlockHash(), pindexX->GetBlockHash()};
    BOOST_CHECK(ReplayBlocks(Params(), &view));
    CheckSameCoins(atX.coins);
    CheckNoOutputs(atX.coins, blockX);

    // X was never applied to this copy: its rollback is unclean but harmless
    HeadsView unclean(&beforeX.coins);
    unclean.heads = {Tip()->GetBlockHash(), pindexX->GetBlockHash()};
    BOOST_CHECK(ReplayBlocks(Params(), &unclean));
    CheckSameCoins(beforeX.coins);
    CheckNoOutputs(beforeX.coins, blockX);
}

BOOST_AUTO_TEST_CASE(replay_heads)
{
    BOOST_REQUIRE(Submit(BuildBlock({Spend(matureCoinbases[0])})));

    // A null old head means a first flush: everything from block 1 is rolled forward
    CCoinsView empty;
    CCoinsViewCache fresh(&empty);
    HeadsView first(&fresh);
    first.heads = {Tip()->GetBlockHash(), uint256()};
    BOOST_CHECK(ReplayBlocks(Params(), &first));
    CheckSameCoins(fresh);

    // No heads: nothing to do. Unknown heads or a wrong count: error, before the view is touched
    HeadsView view(&fresh);
    BOOST_CHECK(ReplayBlocks(Params(), &view));
    view.heads = {InsecureRand256(), Tip()->GetBlockHash()};
    BOOST_CHECK(!ReplayBlocks(Params(), &view));
    view.heads = {Tip()->GetBlockHash(), InsecureRand256()};
    BOOST_CHECK(!ReplayBlocks(Params(), &view));
    view.heads = {Tip()->GetBlockHash()};
    BOOST_CHECK(!ReplayBlocks(Params(), &view));
}

/* A relative lock in seconds (YaCoin counts them one by one) is checked in ConnectBlock,
 * where the heights of the spent coins are known. The spend of a coin of height h in the
 * next block is valid while the time of block h - 1 plus the lock, minus 1, is before the
 * tip's time: a lock of the difference d is met, d + 1 is not. */
BOOST_AUTO_TEST_CASE(relative_time_lock)
{
    // The newest mature coinbase whose block's predecessor is at least a second older than the tip
    const CTransaction* prev = nullptr;
    int64_t d = 0;
    {
        LOCK(cs_main);
        for (auto it = matureCoinbases.rbegin(); it != matureCoinbases.rend() && !prev; ++it) {
            const int h = pcoinsTip->AccessCoin(COutPoint(it->GetHash(), 0)).nHeight;
            BOOST_REQUIRE(h > 0);
            d = chainActive.Tip()->GetBlockTime() - chainActive[h - 1]->GetBlockTime();
            if (d >= 1) prev = &*it;
        }
    }
    BOOST_REQUIRE(prev);
    BOOST_REQUIRE(d <= (int64_t)CTxIn::SEQUENCE_LOCKTIME_MASK);

    auto spendLocked = [&](int64_t nLock) {
        return Spend(*prev, 0, CENT, [&](CMutableTransaction& tx) {
            tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (uint32_t)nLock;
        });
    };
    BOOST_REQUIRE_EQUAL(spendLocked(d).nLockTime, 0U);
    BOOST_CHECK_EQUAL(Validity(BuildBlock({spendLocked(d)})), "");
    BOOST_CHECK_EQUAL(Validity(BuildBlock({spendLocked(d + 1)})), "bad-txns-nonfinal");
}

/** Append an undo record for pindex to its undo file, as ConnectBlock writes it (with a
 *  wrong checksum if fCorrupt), and point pindex at it */
static void WriteUndo(CBlockIndex* pindex, const CBlockUndo& blockundo, bool fCorrupt = false)
{
    CDiskBlockPos pos(pindex->nFile, 0);
    CAutoFile file(fsbridge::fopen(GetBlockPosFilename(pos, "rev"), "ab"), SER_DISK, CLIENT_VERSION);
    BOOST_REQUIRE(!file.IsNull());
    BOOST_REQUIRE(fseek(file.Get(), 0, SEEK_END) == 0);
    unsigned int nSize = GetSerializeSize(file, blockundo);
    file << FLATDATA(Params().MessageStart()) << nSize;
    long nPos = ftell(file.Get());
    BOOST_REQUIRE(nPos > 0);
    file << blockundo;
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << pindex->pprev->GetBlockHash() << blockundo;
    uint256 hash = hasher.GetHash();
    if (fCorrupt) *hash.begin() ^= 1;
    file << hash;
    pindex->nUndoPos = nPos;
}

/* Rolling back a block without usable undo data fails, and the view is left as it was */
BOOST_AUTO_TEST_CASE(replay_without_undo_data)
{
    const CTransaction& cb = matureCoinbases[0];
    const COutPoint spent(cb.GetHash(), 0);
    Coin tipCoin;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(pcoinsTip->GetCoin(spent, tipCoin));
    }
    BOOST_REQUIRE(Submit(BuildBlock({Spend(cb)})));
    CBlockIndex* pindexX = Tip();
    UtxoSnapshot atX(pcoinsdbview);
    LOCK(cs_main);
    const unsigned int nUndoPos = pindexX->nUndoPos;
    BOOST_REQUIRE(pindexX->nStatus & BLOCK_HAVE_UNDO);

    auto rollback = [&]() {
        HeadsView view(&atX.coins);
        view.heads = {pindexX->pprev->GetBlockHash(), pindexX->GetBlockHash()};
        return ReplayBlocks(Params(), &view);
    };
    auto unchanged = [&]() {
        BOOST_CHECK(!atX.coins.HaveCoin(spent));
        BOOST_CHECK(atX.coins.GetBestBlock() == pindexX->GetBlockHash());
    };

    // No undo data
    pindexX->nStatus &= ~BLOCK_HAVE_UNDO;
    BOOST_CHECK(!rollback());
    unchanged();
    pindexX->nStatus |= BLOCK_HAVE_UNDO;

    // The undo record of the block's one spend
    CBlockUndo good;
    good.vtxundo.resize(1);
    good.vtxundo[0].vprevout.push_back(tipCoin);

    // Wrong checksum
    WriteUndo(pindexX, good, true);
    BOOST_CHECK(!rollback());
    unchanged();

    // Undo data for a different number of transactions
    WriteUndo(pindexX, CBlockUndo());
    BOOST_CHECK(!rollback());
    unchanged();

    // Undo data for a different number of inputs
    CBlockUndo twoInputs = good;
    twoInputs.vtxundo[0].vprevout.push_back(tipCoin);
    WriteUndo(pindexX, twoInputs);
    BOOST_CHECK(!rollback());
    unchanged();

    // The same record with the right checksum rolls the block back
    WriteUndo(pindexX, good);
    BOOST_CHECK(rollback());
    const Coin& restored = atX.coins.AccessCoin(spent);
    BOOST_CHECK(restored.out == tipCoin.out);
    BOOST_CHECK_EQUAL(restored.nHeight, tipCoin.nHeight);
    BOOST_CHECK_EQUAL(restored.fCoinBase, tipCoin.fCoinBase);
    BOOST_CHECK_EQUAL(restored.fCoinStake, tipCoin.fCoinStake);
    BOOST_CHECK_EQUAL(restored.nTime, tipCoin.nTime);
    BOOST_CHECK(atX.coins.GetBestBlock() == pindexX->pprev->GetBlockHash());
    pindexX->nUndoPos = nUndoPos;
}


/* The tip's block can't be read: InvalidateBlock fails with an error state (not an
 * invalid one), aborts (shutdown requested, warning set) and changes nothing; once the
 * block can be read again, the same call succeeds */
BOOST_AUTO_TEST_CASE(disconnect_tip_read_failure)
{
    AbortGuard abort;
    BOOST_REQUIRE(Submit(BuildBlock({})));
    CBlockIndex* pindexTip = Tip();
    CTransaction spend = Spend(matureCoinbases[0]);
    AddToMempool(spend);
    {
        BrokenPos broken(pindexTip->nDataPos);
        LOCK(cs_main);
        CValidationState state;
        BOOST_CHECK(!InvalidateBlock(state, Params(), pindexTip));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(!state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "DisconnectTip(): Failed to read block");
        BOOST_CHECK(ShutdownRequested());
        BOOST_CHECK_EQUAL(GetWarnings("statusbar"), "DisconnectTip(): Failed to read block");
        BOOST_CHECK(chainActive.Tip() == pindexTip);
        BOOST_CHECK(pcoinsTip->GetBestBlock() == pindexTip->GetBlockHash());
        BOOST_CHECK(!(pindexTip->nStatus & BLOCK_FAILED_MASK));
        BOOST_CHECK(mempool.exists(spend.GetHash()));
    }
    AbortGuard::Reset();

    LOCK(cs_main);
    CValidationState state;
    BOOST_CHECK(InvalidateBlock(state, Params(), pindexTip));
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(!ShutdownRequested());
    BOOST_CHECK(chainActive.Tip() == pindexTip->pprev);
    BOOST_CHECK(pindexTip->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(mempool.exists(spend.GetHash()));
}

/* A block that is stored but not connected yet, and can't be read when its turn comes:
 * ActivateBestChain fails with an error and aborts; the block isn't marked invalid and
 * stays a candidate, so the next call connects it once it can be read */
BOOST_AUTO_TEST_CASE(connect_tip_read_failure)
{
    AbortGuard abort;
    CBlockIndex* pindexStart = Tip();
    CBlock block = BuildBlock({});
    // Stored without being connected: ActivateBestChain stops at once on a shutdown request
    StartShutdown();
    BOOST_REQUIRE(!Submit(block));
    AbortGuard::Reset();
    CBlockIndex* pindex = Index(block);
    BOOST_REQUIRE(pindex->nStatus & BLOCK_HAVE_DATA);
    BOOST_REQUIRE(Tip() == pindexStart);
    {
        BrokenPos broken(pindex->nDataPos);
        CValidationState state;
        BOOST_CHECK(!ActivateBestChain(state, Params()));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(!state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "Failed to read block");
        BOOST_CHECK(ShutdownRequested());
        BOOST_CHECK_EQUAL(GetWarnings("statusbar"), "Failed to read block");
        BOOST_CHECK(Tip() == pindexStart);
        BOOST_CHECK(!Failed(pindex));
        BOOST_CHECK(pindex->nStatus & BLOCK_HAVE_DATA);
    }
    AbortGuard::Reset();

    CValidationState state;
    BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(Tip() == pindex);
    BOOST_CHECK(!ShutdownRequested());
}

/* With a shutdown requested ActivateBestChain returns success without moving the tip,
 * and the next call after the request is gone connects the waiting block; -stopatheight
 * requests the shutdown once a block at that height is connected */
BOOST_AUTO_TEST_CASE(activate_best_chain_shutdown_requested)
{
    AbortGuard abort;
    CBlockIndex* pindexStart = Tip();
    CBlock block = BuildBlock({});
    StartShutdown();
    BOOST_CHECK(!Submit(block));
    BOOST_CHECK(Tip() == pindexStart);
    {
        CValidationState state;
        BOOST_CHECK(ActivateBestChain(state, Params()));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(Tip() == pindexStart);
    }
    AbortGuard::Reset();
    {
        CValidationState state;
        BOOST_CHECK(ActivateBestChain(state, Params()));
        BOOST_CHECK(Tip()->GetBlockHash() == block.GetHash());
    }

    ArgGuard stop("-stopatheight", itostr(Tip()->nHeight + 2));
    BOOST_CHECK(Submit(BuildBlock({})));
    BOOST_CHECK(!ShutdownRequested());
    BOOST_CHECK(Submit(BuildBlock({})));
    BOOST_CHECK(ShutdownRequested());
    BOOST_CHECK_EQUAL(Tip()->nHeight, pindexStart->nHeight + 3);
}

/* The tip's undo data can't be read: InvalidateBlock fails in DisconnectBlock with the
 * state still valid and changes nothing; with the undo data back, the same call succeeds */
BOOST_AUTO_TEST_CASE(disconnect_tip_undo_failure)
{
    BOOST_REQUIRE(Submit(BuildBlock({})));
    CBlockIndex* pindexTip = Tip();
    CTransaction spend = Spend(matureCoinbases[0]);
    AddToMempool(spend);
    {
        BrokenPos broken(pindexTip->nUndoPos);
        LOCK(cs_main);
        CValidationState state;
        BOOST_CHECK(!InvalidateBlock(state, Params(), pindexTip));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(chainActive.Tip() == pindexTip);
        BOOST_CHECK(pcoinsTip->GetBestBlock() == pindexTip->GetBlockHash());
        BOOST_CHECK(!(pindexTip->nStatus & BLOCK_FAILED_MASK));
        BOOST_CHECK(mempool.exists(spend.GetHash()));
    }

    LOCK(cs_main);
    CValidationState state;
    BOOST_CHECK(InvalidateBlock(state, Params(), pindexTip));
    BOOST_CHECK(chainActive.Tip() == pindexTip->pprev);
    BOOST_CHECK(pcoinsTip->GetBestBlock() == pindexTip->pprev->GetBlockHash());
    BOOST_CHECK(pindexTip->nStatus & BLOCK_FAILED_VALID);
}

/* A fork with more work arrives while the active tip's undo data can't be read: the
 * reorg fails before anything is disconnected, with the state still valid; with the
 * undo data back, ActivateBestChain moves to the fork */
BOOST_AUTO_TEST_CASE(reorg_disconnect_failure)
{
    CBlockIndex* pindexFork = Tip();
    BOOST_REQUIRE(Submit(BuildBlock({})));
    CBlockIndex* pindexA = Tip();
    // Same work as A, received later: stays on the side
    CBlock blockB1 = BuildOn(pindexFork, {}, CScript() << OP_TRUE);
    BOOST_REQUIRE(!Submit(blockB1));
    CBlockIndex* pindexB1 = Index(blockB1);
    CBlock blockB2 = BuildOn(pindexB1, {}, CScript() << OP_TRUE);
    CTransaction spend = Spend(matureCoinbases[0]);
    AddToMempool(spend);
    {
        BrokenPos broken(pindexA->nUndoPos);
        BOOST_CHECK(!Submit(blockB2));
        CBlockIndex* pindexB2 = Index(blockB2);
        BOOST_CHECK(pindexB2->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(!Failed(pindexB2));

        // The same again, called directly
        CValidationState state;
        BOOST_CHECK(!ActivateBestChain(state, Params()));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(Tip() == pindexA);
        BOOST_CHECK(!Failed(pindexA));
        BOOST_CHECK(!Failed(pindexB2));
        BOOST_CHECK(mempool.exists(spend.GetHash()));
        LOCK(cs_main);
        BOOST_CHECK(pcoinsTip->GetBestBlock() == pindexA->GetBlockHash());
    }

    CValidationState state;
    BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(Tip()->GetBlockHash() == blockB2.GetHash());
    BOOST_CHECK(Tip()->pprev == pindexB1);
    BOOST_CHECK(!Failed(pindexA));
    BOOST_CHECK(mempool.exists(spend.GetHash()));
    LOCK(cs_main);
    BOOST_CHECK(pcoinsTip->GetBestBlock() == blockB2.GetHash());
}

/* Connecting a block removes the reissue entries of the transactions it includes, both
 * by transaction and by token name; other entries stay */
BOOST_AUTO_TEST_CASE(connect_tip_clears_reissue_entries)
{
    ReissueMapsGuard maps;
    CTransaction spend = Spend(matureCoinbases[0]);
    const uint256 other = InsecureRand256();
    mapReissuedTx[spend.GetHash()] = "REISSUED";
    mapReissuedTokens["REISSUED"] = spend.GetHash();
    mapReissuedTx[other] = "OTHER";
    mapReissuedTokens["OTHER"] = other;

    BOOST_REQUIRE(Submit(BuildBlock({spend})));
    BOOST_CHECK(!mapReissuedTx.count(spend.GetHash()));
    BOOST_CHECK(!mapReissuedTokens.count("REISSUED"));
    BOOST_CHECK(mapReissuedTx.count(other) && mapReissuedTx[other] == "OTHER");
    BOOST_CHECK(mapReissuedTokens.count("OTHER") && mapReissuedTokens["OTHER"] == other);
}

/* Invalidating a block on a side branch leaves the active chain alone; when the tip is
 * invalidated later, the chain falls back to the fork point, not to the side branch */
BOOST_AUTO_TEST_CASE(invalidate_side_branch)
{
    CBlockIndex* pindexFork = Tip();
    BOOST_REQUIRE(Submit(BuildBlock({})));
    CBlockIndex* pindexA = Tip();
    CBlock blockB = BuildOn(pindexFork, {}, CScript() << OP_TRUE);
    BOOST_REQUIRE(!Submit(blockB));
    CBlockIndex* pindexB = Index(blockB);

    LOCK(cs_main);
    {
        CValidationState state;
        BOOST_CHECK(InvalidateBlock(state, Params(), pindexB));
        BOOST_CHECK(state.IsValid());
    }
    BOOST_CHECK(chainActive.Tip() == pindexA);
    BOOST_CHECK(pindexB->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(!(pindexA->nStatus & BLOCK_FAILED_MASK));

    // A has the same work as B, which is already recorded as invalid
    BOOST_REQUIRE(pindexA->bnChainTrust == pindexB->bnChainTrust);
    {
        CValidationState state;
        BOOST_CHECK(InvalidateBlock(state, Params(), pindexA));
        BOOST_CHECK(ActivateBestChain(state, Params()));
    }
    BOOST_CHECK(chainActive.Tip() == pindexFork);
    BOOST_CHECK(pindexA->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(pindexB->nStatus & BLOCK_FAILED_VALID);
}

BOOST_AUTO_TEST_SUITE_END()
