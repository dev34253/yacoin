// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for GetUTXOStats / RPC gettxoutsetinfo (task P0-48): the UTXO set
// hash (hash_serialized) and the token metadata hash (hash_tokens) must be
// equal for identical chainstates and change when any stored field changes.

#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "rpc/blockchain.h"
#include "script/script.h"
#include "script/sign.h"
#include "test/test_bitcoin.h"
#include "tokens/tokendb.h"
#include "tokens/tokentypes.h"
#include "txdb.h"
#include "uint256.h"
#include "validation.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <set>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

struct TestCoin {
    COutPoint outpoint;
    Coin coin;
};

const uint256 BEST_BLOCK = uint256S("0x00000000000000000000000000000000000000000000000000000000000000b1");

Coin MakeCoin(CAmount nValue, const CScript& script, int nHeight, bool fCoinBase, bool fCoinStake, int64_t nTime)
{
    return Coin(CTxOut(nValue, script), nHeight, fCoinBase, fCoinStake, nTime);
}

// A small fixed UTXO set: two txids, one with two outputs, plus a coinstake.
// Heights are below the main-net Heliopolis height, so fCoinStake is stored.
std::vector<TestCoin> BaseCoins()
{
    const CScript script1 = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG;
    const CScript script2 = CScript() << OP_HASH160 << std::vector<unsigned char>(20, 0x22) << OP_EQUAL;
    const uint256 txid1 = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    const uint256 txid2 = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    const uint256 txid3 = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");
    return {
        {COutPoint(txid1, 0), MakeCoin(50 * COIN, script1, 10, true, false, 1367991200)},
        {COutPoint(txid2, 0), MakeCoin(3 * COIN, script1, 12, false, false, 1367991300)},
        {COutPoint(txid2, 2), MakeCoin(7 * CENT, script2, 12, false, false, 1367991300)},
        {COutPoint(txid3, 1), MakeCoin(120 * COIN, script2, 15, false, true, 1367991500)},
    };
}

// Write coins (in the given order, flushing after each batch of batchSize)
// into a fresh in-memory coins database and return its statistics.
CCoinsStats StatsOf(const std::vector<TestCoin>& coins, const uint256& best = BEST_BLOCK, size_t batchSize = 1000, CTokensDB* tokensdb = nullptr)
{
    CCoinsViewDB db(1 << 20, true /* fMemory */);
    size_t n = 0;
    {
        CCoinsViewCache cache(&db);
        for (const TestCoin& tc : coins) {
            cache.AddCoin(tc.outpoint, Coin(tc.coin), false);
            if (++n % batchSize == 0) {
                cache.SetBestBlock(best);
                BOOST_REQUIRE(cache.Flush());
            }
        }
        cache.SetBestBlock(best);
        BOOST_REQUIRE(cache.Flush());
    }
    CCoinsStats stats;
    BOOST_REQUIRE(GetUTXOStats(&db, tokensdb, stats));
    return stats;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(utxostats_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(counts_and_totals)
{
    // Empty set: no outputs, deterministic hash over the best block only.
    const CCoinsStats empty = StatsOf({});
    BOOST_CHECK_EQUAL(empty.nTransactions, 0U);
    BOOST_CHECK_EQUAL(empty.nTransactionOutputs, 0U);
    BOOST_CHECK_EQUAL(empty.nTotalAmount, 0);
    BOOST_CHECK_EQUAL(empty.nBogoSize, 0U);
    BOOST_CHECK(empty.hashBlock == BEST_BLOCK);
    BOOST_CHECK_EQUAL(empty.nHeight, -1); // not in mapBlockIndex
    BOOST_CHECK_EQUAL(empty.nTokens, 0U);
    BOOST_CHECK(StatsOf({}).hashSerialized == empty.hashSerialized);
    BOOST_CHECK(StatsOf({}, uint256S("0xb2")).hashSerialized != empty.hashSerialized);

    const std::vector<TestCoin> coins = BaseCoins();
    const CCoinsStats stats = StatsOf(coins);
    BOOST_CHECK_EQUAL(stats.nTransactions, 3U);
    BOOST_CHECK_EQUAL(stats.nTransactionOutputs, 4U);
    BOOST_CHECK_EQUAL(stats.nTotalAmount, 50 * COIN + 3 * COIN + 7 * CENT + 120 * COIN);
    uint64_t nBogo = 0;
    for (const TestCoin& tc : coins)
        nBogo += 32 + 4 + 4 + 8 + 2 + tc.coin.out.scriptPubKey.size();
    BOOST_CHECK_EQUAL(stats.nBogoSize, nBogo);
    BOOST_CHECK(stats.hashSerialized != empty.hashSerialized);
}

BOOST_AUTO_TEST_CASE(identical_sets_same_hash)
{
    std::vector<TestCoin> coins = BaseCoins();
    const CCoinsStats a = StatsOf(coins);
    std::reverse(coins.begin(), coins.end());
    const CCoinsStats b = StatsOf(coins, BEST_BLOCK, 1); // other order, one flush per coin
    BOOST_CHECK(a.hashSerialized == b.hashSerialized);
    BOOST_CHECK_EQUAL(a.nTransactions, b.nTransactions);
    BOOST_CHECK_EQUAL(a.nTransactionOutputs, b.nTransactionOutputs);
    BOOST_CHECK_EQUAL(a.nTotalAmount, b.nTotalAmount);
    BOOST_CHECK_EQUAL(a.nBogoSize, b.nBogoSize);

    // A coin added and spent again before the scan leaves no trace.
    CCoinsViewDB db(1 << 20, true);
    {
        CCoinsViewCache cache(&db);
        for (const TestCoin& tc : BaseCoins())
            cache.AddCoin(tc.outpoint, Coin(tc.coin), false);
        const COutPoint extra(uint256S("0x44"), 0);
        cache.AddCoin(extra, MakeCoin(COIN, CScript() << OP_TRUE, 20, false, false, 1367992000), false);
        cache.SetBestBlock(BEST_BLOCK);
        BOOST_REQUIRE(cache.Flush());
        BOOST_REQUIRE(cache.SpendCoin(extra));
        BOOST_REQUIRE(cache.Flush());
    }
    CCoinsStats c;
    BOOST_REQUIRE(GetUTXOStats(&db, nullptr, c));
    BOOST_CHECK(c.hashSerialized == a.hashSerialized);
    BOOST_CHECK_EQUAL(c.nTransactionOutputs, 4U);
}

BOOST_AUTO_TEST_CASE(each_field_changes_hash)
{
    std::set<uint256> hashes;
    const std::vector<TestCoin> base = BaseCoins();
    hashes.insert(StatsOf(base).hashSerialized);

    // Every variant changes exactly one stored field of the coin at index 1
    // (txid2:0), or the best block; each must give a new hash.
    std::vector<std::vector<TestCoin> > variants;
    auto variant = [&](std::function<void(TestCoin&)> change) {
        std::vector<TestCoin> v = base;
        change(v[1]);
        variants.push_back(v);
    };
    variant([](TestCoin& t) { t.coin.out.nValue += 1; });
    variant([](TestCoin& t) { t.coin.out.scriptPubKey << OP_DROP; });
    variant([](TestCoin& t) { t.coin.nHeight = t.coin.nHeight + 1; });
    variant([](TestCoin& t) { t.coin.fCoinBase = 1; });
    variant([](TestCoin& t) { t.coin.fCoinStake = true; });
    variant([](TestCoin& t) { t.coin.nTime += 1; });
    variant([](TestCoin& t) { t.outpoint.n = 1; });
    variant([](TestCoin& t) { t.outpoint.hash = uint256S("0x2222222222222222222222222222222222222222222222222222222222222223"); });
    for (const auto& v : variants)
        BOOST_CHECK(hashes.insert(StatsOf(v).hashSerialized).second);
    BOOST_CHECK(hashes.insert(StatsOf(base, uint256S("0xb2")).hashSerialized).second);
    BOOST_CHECK_EQUAL(hashes.size(), variants.size() + 2);
}

BOOST_AUTO_TEST_CASE(known_answer)
{
    // Pins the hash format: P0-06/P0-24/P0-35 compare against stored
    // baseline values, so a change here must be deliberate (and documented
    // in the gettxoutsetinfo help and doc/functional-specification.md).
    // The hash_serialized value and the empty-token-DB hash_tokens value
    // (SHA-256d of the best block alone) were also computed independently
    // from the documented format with a short Python script (task P0-48 log).
    const CCoinsStats stats = StatsOf(BaseCoins(), BEST_BLOCK, 1000, ptokensdb);
    BOOST_CHECK_EQUAL(stats.hashSerialized.GetHex(), "6e65f68009243be36c133e5412a69cba595757026bb37ef898f07a9430ff07d4");
    BOOST_CHECK_EQUAL(stats.nTokens, 0U);
    BOOST_CHECK_EQUAL(stats.hashTokens.GetHex(), "35374abb9c13ae4c451a1765966e25c1a2edb9985997cb0095f5ce6697f0d384");

    BOOST_REQUIRE(ptokensdb->WriteTokenData(CNewToken("KAT_TOKEN", 1000 * COIN, 4, 1, 0, ""), 42, BEST_BLOCK));
    const CCoinsStats withToken = StatsOf(BaseCoins(), BEST_BLOCK, 1000, ptokensdb);
    BOOST_CHECK(withToken.hashSerialized == stats.hashSerialized);
    BOOST_CHECK_EQUAL(withToken.nTokens, 1U);
    BOOST_CHECK_EQUAL(withToken.hashTokens.GetHex(), "a393ebd651f097f1f831725825835491fa1fd57293647ddb92b34b4167c50008");
}

BOOST_AUTO_TEST_CASE(token_data_hash)
{
    BOOST_REQUIRE(ptokensdb);
    const std::vector<TestCoin> coins = BaseCoins();
    const CCoinsStats none = StatsOf(coins, BEST_BLOCK, 1000, ptokensdb);
    BOOST_CHECK_EQUAL(none.nTokens, 0U);

    const CNewToken tokenA("ALPHA", 1000 * COIN, 4, 1, 0, "");
    const CNewToken tokenB("BETA", 5 * COIN, 0, 0, 0, "");
    BOOST_REQUIRE(ptokensdb->WriteTokenData(tokenA, 30, BEST_BLOCK));
    const CCoinsStats one = StatsOf(coins, BEST_BLOCK, 1000, ptokensdb);
    BOOST_CHECK_EQUAL(one.nTokens, 1U);
    BOOST_CHECK(one.hashTokens != none.hashTokens);
    BOOST_CHECK(one.hashSerialized == none.hashSerialized); // coins hash unaffected

    BOOST_REQUIRE(ptokensdb->WriteTokenData(tokenB, 31, BEST_BLOCK));
    const CCoinsStats two = StatsOf(coins, BEST_BLOCK, 1000, ptokensdb);
    BOOST_CHECK_EQUAL(two.nTokens, 2U);
    BOOST_CHECK(two.hashTokens != one.hashTokens);

    // Records that are not token metadata are not hashed: per-address
    // balances (-tokenindex only), block undo data, mempool reissue state.
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("ALPHA", "addr", 7 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteAddressTokenQuantity("addr", "ALPHA", 7 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteBlockUndoTokenData(BEST_BLOCK, {}));
    BOOST_REQUIRE(ptokensdb->WriteReissuedMempoolState());
    const CCoinsStats twoIndexed = StatsOf(coins, BEST_BLOCK, 1000, ptokensdb);
    BOOST_CHECK_EQUAL(twoIndexed.nTokens, 2U);
    BOOST_CHECK(twoIndexed.hashTokens == two.hashTokens);

    // Reissue-style change of the metadata (units) changes the hash.
    const CNewToken tokenA2("ALPHA", 1000 * COIN, 5, 1, 0, "");
    BOOST_REQUIRE(ptokensdb->WriteTokenData(tokenA2, 30, BEST_BLOCK));
    BOOST_CHECK(StatsOf(coins, BEST_BLOCK, 1000, ptokensdb).hashTokens != two.hashTokens);

    // Back to the earlier state: same hash again.
    BOOST_REQUIRE(ptokensdb->WriteTokenData(tokenA, 30, BEST_BLOCK));
    BOOST_REQUIRE(ptokensdb->EraseTokenData("BETA"));
    const CCoinsStats back = StatsOf(coins, BEST_BLOCK, 1000, ptokensdb);
    BOOST_CHECK_EQUAL(back.nTokens, 1U);
    BOOST_CHECK(back.hashTokens == one.hashTokens);
}

BOOST_FIXTURE_TEST_CASE(small_chain_hash, TestChain100Setup)
{
    FlushStateToDisk();
    CCoinsStats before;
    BOOST_REQUIRE(GetUTXOStats(pcoinsdbview, ptokensdb, before));
    BOOST_CHECK(before.hashBlock == chainActive.Tip()->GetBlockHash());
    BOOST_CHECK_EQUAL(before.nHeight, chainActive.Height());
    BOOST_CHECK(before.nTransactionOutputs > 0);
    BOOST_CHECK(before.nTotalAmount > 0);

    // Same chainstate read twice: same result.
    CCoinsStats again;
    BOOST_REQUIRE(GetUTXOStats(pcoinsdbview, ptokensdb, again));
    BOOST_CHECK(again.hashSerialized == before.hashSerialized);
    BOOST_CHECK(again.hashTokens == before.hashTokens);

    // A block that spends a mature coinbase changes the hash.
    const CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CTransaction spend;
    spend.nVersion = 2;
    spend.vin.resize(1);
    spend.vin[0].prevout.hash = coinbaseTxns[0].GetHash();
    spend.vin[0].prevout.n = 0;
    spend.vout.resize(1);
    spend.vout[0].nValue = 11 * CENT;
    spend.vout[0].scriptPubKey = scriptPubKey;
    std::vector<unsigned char> vchSig;
    const uint256 sighash = SignatureHash(scriptPubKey, spend, 0, SIGHASH_ALL);
    BOOST_REQUIRE(coinbaseKey.Sign(sighash, vchSig));
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    spend.vin[0].scriptSig << vchSig;

    const CBlock block = CreateAndProcessBlock({spend}, scriptPubKey);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
    FlushStateToDisk();
    CCoinsStats after;
    BOOST_REQUIRE(GetUTXOStats(pcoinsdbview, ptokensdb, after));
    BOOST_CHECK(after.hashBlock == block.GetHash());
    BOOST_CHECK_EQUAL(after.nHeight, before.nHeight + 1);
    BOOST_CHECK(after.hashSerialized != before.hashSerialized);
    BOOST_CHECK(after.hashTokens != before.hashTokens); // best block is part of it
    // One coinbase output spent, the spend output and the new coinbase added.
    BOOST_CHECK(after.nTransactionOutputs > before.nTransactionOutputs);

    // Disconnecting the block restores the earlier chainstate and hash.
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(InvalidateBlock(state, Params(), chainActive.Tip()));
    }
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == before.hashBlock);
    FlushStateToDisk();
    CCoinsStats restored;
    BOOST_REQUIRE(GetUTXOStats(pcoinsdbview, ptokensdb, restored));
    BOOST_CHECK(restored.hashBlock == before.hashBlock);
    BOOST_CHECK(restored.hashSerialized == before.hashSerialized);
    BOOST_CHECK(restored.hashTokens == before.hashTokens);
    BOOST_CHECK_EQUAL(restored.nTransactionOutputs, before.nTransactionOutputs);
    BOOST_CHECK_EQUAL(restored.nTotalAmount, before.nTotalAmount);
}

BOOST_AUTO_TEST_SUITE_END()
