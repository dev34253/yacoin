// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Writing the chain state to disk (FlushStateToDisk: when the coin cache is
// flushed, the best-chain notification, write failures), the initial block
// download state, FindForkInGlobalIndex and GuessVerificationProgress.
//
// IsInitialBlockDownload stays false for the rest of the process once it has
// returned false, so on the mainnet build no case here calls it with a tip at
// or above Checkpoints::GetTotalBlocksEstimate() that is recent.

#include "chainparams.h"
#include "checkpoints.h"
#include "coins.h"
#include "consensus/validation.h"
#include "init.h"
#include "tokens/tokens.h"
#include "txmempool.h"
#include "utiltime.h"
#include "validation.h"
#include "validationinterface.h"
#include "warnings.h"

#include "test/test_bitcoin.h"

#include <ctime>
#include <stdexcept>
#include <string>

#include <boost/test/unit_test.hpp>

namespace {

/** Sets a global under cs_main while it lives and puts the old value back after */
template <typename T>
class GlobalGuard
{
    T& m_ref;
    const T m_saved;

public:
    GlobalGuard(T& ref, T value) : m_ref(ref), m_saved(ref)
    {
        LOCK(cs_main);
        m_ref = value;
    }
    ~GlobalGuard()
    {
        LOCK(cs_main);
        m_ref = m_saved;
    }
    GlobalGuard(const GlobalGuard&) = delete;
    GlobalGuard& operator=(const GlobalGuard&) = delete;
};

/** Records the coin cache when a block is connected, and the best-chain notifications */
class FlushListener : public CValidationInterface
{
public:
    int nSetBestChain = 0;
    CBlockLocator lastLocator;
    size_t nCacheAtConnect = 0;
    uint256 dbBestAtConnect;
    CCoinsView* pdb;

    explicit FlushListener(CCoinsView* pdbIn) : pdb(pdbIn) { RegisterValidationInterface(this); }
    ~FlushListener() { UnregisterValidationInterface(this); }

protected:
    void SetBestChain(const CBlockLocator& locator) override
    {
        ++nSetBestChain;
        lastLocator = locator;
    }
    void BlockConnected(const std::shared_ptr<const CBlock>&, const CBlockIndex*, const std::vector<CTransactionRef>&) override
    {
        nCacheAtConnect = pcoinsTip->GetCacheSize();
        dbBestAtConnect = pdb->GetBestBlock();
    }
};

/** A coins view whose writes throw */
class ThrowingView : public CCoinsView
{
public:
    bool BatchWrite(CCoinsMap&, const uint256&) override { throw std::runtime_error("injected write error"); }
};

struct FlushSetup : public TestChain100Setup {
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    uint256 Mine() { return CreateAndProcessBlock({}, scriptPubKey).GetHash(); }

    static uint256 TipHash()
    {
        LOCK(cs_main);
        return chainActive.Tip()->GetBlockHash();
    }

    static size_t CacheEntries()
    {
        LOCK(cs_main);
        return pcoinsTip->GetCacheSize();
    }

    static size_t CacheUsage()
    {
        LOCK(cs_main);
        return pcoinsTip->DynamicMemoryUsage();
    }

    /** Submits a transaction the mempool refuses before it reads any coin, so the
     *  coin cache is unchanged; every submission ends with a periodic flush check */
    static void SubmitRefused()
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_CHECK(!AcceptToMemoryPool(mempool, state, MakeTransactionRef(CMutableTransaction()), nullptr));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-empty");
    }

    /** FlushStateToDisk() with pcoinsTip replaced by a cache over base; returns the misc warning */
    static std::string FlushOver(CCoinsView& base)
    {
        CCoinsViewCache cache(&base);
        ShutdownRequestRecorder recorder;
        {
            GlobalGuard<CCoinsViewCache*> swap(pcoinsTip, &cache);
            FlushStateToDisk();
        }
        BOOST_CHECK(ShutdownRequested());
        std::string warning = GetWarnings("statusbar");
        SetMiscWarning("");
        return warning;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(validation_flush_tests, FlushSetup)

BOOST_AUTO_TEST_CASE(find_fork_in_global_index)
{
    LOCK(cs_main);
    CBlockIndex* genesis = chainActive.Genesis();
    CBlockIndex* tip = chainActive.Tip();
    BOOST_CHECK_EQUAL(FindForkInGlobalIndex(chainActive, CBlockLocator()), genesis);
    BOOST_CHECK_EQUAL(FindForkInGlobalIndex(chainActive, CBlockLocator({uint256S("0x1234"), uint256S("0x5678")})), genesis);
    BOOST_CHECK_EQUAL(FindForkInGlobalIndex(chainActive, chainActive.GetLocator()), tip);

    // A known block on a side branch (not in the chain, not above its tip) is skipped
    CBlockIndex side;
    side.pprev = genesis;
    side.nHeight = 1;
    const uint256 sideHash = uint256S("0x5151");
    BOOST_REQUIRE(mapBlockIndex.count(sideHash) == 0);
    side.phashBlock = &mapBlockIndex.emplace(sideHash, &side).first->first;
    BOOST_CHECK_EQUAL(FindForkInGlobalIndex(chainActive, CBlockLocator({sideHash, chainActive[3]->GetBlockHash()})), chainActive[3]);
    mapBlockIndex.erase(sideHash);

    // A block above the tip of the given chain that descends from it gives that tip
    CChain shorter;
    shorter.SetTip(chainActive[3]);
    BOOST_CHECK_EQUAL(FindForkInGlobalIndex(shorter, chainActive.GetLocator()), chainActive[3]);
}

BOOST_AUTO_TEST_CASE(guess_verification_progress)
{
    BOOST_CHECK_EQUAL(GuessVerificationProgress(ChainTxData{0, 100, 1.0}, nullptr), 0.0);

    CBlockIndex index;
    index.nChainTx = 50;
    BOOST_CHECK_EQUAL(GuessVerificationProgress(ChainTxData{0, 200, 0.0}, &index), 0.25);

    // More transactions than the chain data: the block's own count and time are the base
    index.nChainTx = 300;
    BOOST_CHECK_EQUAL(GuessVerificationProgress(ChainTxData{0, 200, 0.0}, &index), 1.0);

    index.nTime = time(nullptr) - 1000;
    const int64_t nBefore = time(nullptr);
    const double progress = GuessVerificationProgress(ChainTxData{0, 200, 0.5}, &index);
    const int64_t nAfter = time(nullptr);
    BOOST_CHECK_LE(progress, 300.0 / (300 + (nBefore - index.GetBlockTime()) * 0.5));
    BOOST_CHECK_GE(progress, 300.0 / (300 + (nAfter - index.GetBlockTime()) * 0.5));
}

BOOST_AUTO_TEST_CASE(initial_block_download_state)
{
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    {
        LOCK(cs_main);
        CBlockIndex* realTip = chainActive.Tip();
        BOOST_REQUIRE_LT(realTip->nHeight, Checkpoints::GetTotalBlocksEstimate());

        chainActive.SetTip(nullptr);
        BOOST_CHECK(IsInitialBlockDownload()); // no tip
        chainActive.SetTip(realTip);
        BOOST_CHECK(IsInitialBlockDownload()); // below the estimate

        // At the estimate, but older than nMaxTipAge
        CBlockIndex old;
        old.nHeight = Checkpoints::GetTotalBlocksEstimate();
        old.nTime = GetTime() - nMaxTipAge - 60 * 60;
        chainActive.SetTip(&old);
        BOOST_CHECK(IsInitialBlockDownload());
        chainActive.SetTip(realTip);
        BOOST_CHECK(chainActive.Tip() == realTip);
    }
    BOOST_CHECK(IsInitialBlockDownload()); // still in initial download
#else
    // The build's only checkpoint is genesis and the tip's age is not checked
    BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(), 0);
    BOOST_CHECK(!IsInitialBlockDownload());
#endif
}

BOOST_AUTO_TEST_CASE(flush_if_needed_cache_critical)
{
    FlushListener listener(pcoinsdbview);
    {
        // A cache over its limit is written when the block is connected
        GlobalGuard<size_t> limit(nCoinCacheUsage, 0);
        const uint256 hash = Mine();
        BOOST_CHECK(TipHash() == hash);
        BOOST_CHECK_EQUAL(listener.nCacheAtConnect, 0U);
        BOOST_CHECK(listener.dbBestAtConnect == hash);
    }
    // Within the default limit it stays in memory
    const uint256 hash = Mine();
    BOOST_CHECK(TipHash() == hash);
    BOOST_CHECK_GT(listener.nCacheAtConnect, 0U);
    BOOST_CHECK(listener.dbBestAtConnect != hash);
    BOOST_CHECK_GT(CacheEntries(), 0U);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK(IsInitialBlockDownload()); // still in initial download
#endif
}

BOOST_AUTO_TEST_CASE(flush_periodic_cache_large)
{
    // Without tokens the cache size is the coin cache's alone
    GlobalGuard<int32_t> tokens(nTokenSupportBlockNumber, 1000000);
    FlushStateToDisk(); // a recent full flush, so no time-based one follows
    const uint256 flushed = pcoinsdbview->GetBestBlock();
    const uint256 tip = Mine(); // within the default limit: stays in memory
    BOOST_REQUIRE(pcoinsdbview->GetBestBlock() == flushed);
    const size_t nUsage = CacheUsage();
    BOOST_REQUIRE_GT(nUsage, 20U);
    {
        // Below 90 % of the limit: nothing is written
        GlobalGuard<size_t> limit(nCoinCacheUsage, 2 * nUsage);
        SubmitRefused();
        BOOST_CHECK_GT(CacheEntries(), 0U);
        BOOST_CHECK(pcoinsdbview->GetBestBlock() == flushed);
    }
    // Within 10 % of the limit, not over it: written by the periodic check
    GlobalGuard<size_t> limit(nCoinCacheUsage, nUsage + nUsage / 20);
    SubmitRefused();
    BOOST_CHECK_EQUAL(CacheEntries(), 0U);
    BOOST_CHECK(pcoinsdbview->GetBestBlock() == tip);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK(IsInitialBlockDownload()); // still in initial download
#endif
}

BOOST_AUTO_TEST_CASE(flush_signals_best_chain)
{
    FlushListener listener(pcoinsdbview);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(listener.nSetBestChain, 1);
    LOCK(cs_main);
    BOOST_CHECK(listener.lastLocator.vHave == chainActive.GetLocator().vHave);
    BOOST_CHECK(pcoinsdbview->GetBestBlock() == chainActive.Tip()->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(flush_coin_write_failure)
{
    CCoinsView refusing; // BatchWrite returns false
    BOOST_CHECK_EQUAL(FlushOver(refusing), "Failed to write to coin database");
}

BOOST_AUTO_TEST_CASE(flush_exception)
{
    ThrowingView throwing;
    BOOST_CHECK_EQUAL(FlushOver(throwing), "System error while flushing: injected write error");
}

BOOST_AUTO_TEST_CASE(flush_without_token_cache)
{
    // Tokens deployed, but no current token cache: the coins are still written
    Mine();
    {
        GlobalGuard<CTokensCache*> noTokens(ptokens, nullptr);
        FlushStateToDisk();
    }
    BOOST_CHECK_EQUAL(CacheEntries(), 0U);
    BOOST_CHECK(pcoinsdbview->GetBestBlock() == TipHash());
    BOOST_CHECK_EQUAL(GetWarnings("statusbar"), "");
}

BOOST_AUTO_TEST_SUITE_END()
