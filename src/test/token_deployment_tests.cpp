// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// AreTokensDeployed(): true when the active chain has a genesis entry and its
// height is at or past the token support height nTokenSupportBlockNumber,
// false otherwise, whatever the token support height (negative ones included).

#include "chain.h"
#include "sync.h"
#include "util.h"
#include "validation.h"
#include "test/consensus_test_util.h"
#include "test/stake_test_util.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

const unsigned int TEST_BITS = 0x1e0fffff;
const ::int64_t TEST_SPACING = 60;

/** Entries at heights 1 to nTop on top of genesis; element h is at height h, element 0 is genesis. */
std::vector<CBlockIndex*> BuildChain(SyntheticChain& chain, int nTop)
{
    std::vector<CBlockIndex*> v{chain.Genesis()};
    for (int h = 1; h <= nTop; h++) {
        v.push_back(chain.Add(v.back(), v.back()->GetBlockTime() + TEST_SPACING, TEST_BITS));
    }
    return v;
}

void RequireActiveAtGenesis()
{
    LOCK(cs_main);
    BOOST_REQUIRE(chainActive.Genesis() != nullptr);
    BOOST_REQUIRE_EQUAL(chainActive.Height(), 0);
}

void CheckDeployed(bool fExpected, const std::string& strWhat)
{
    const bool fGot = AreTokensDeployed();
    BOOST_CHECK_MESSAGE(fGot == fExpected,
        strWhat << ": AreTokensDeployed() is " << fGot << ", expected " << fExpected);
}

std::string TokenHeight(int nHeight)
{
    return "token height " + std::to_string(nHeight);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(token_deployment_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(no_chain_gives_false)
{
    RequireActiveAtGenesis();
    ValueGuard<::int32_t> tokens(nTokenSupportBlockNumber, 0);
    SyntheticChain chain;
    chain.SetActiveTip(nullptr);
    for (int nToken : {0, 1, 1000, -1, -5}) {
        nTokenSupportBlockNumber = nToken;
        CheckDeployed(false, "no chain, " + TokenHeight(nToken));
    }
}

BOOST_AUTO_TEST_CASE(genesis_only)
{
    RequireActiveAtGenesis();
    ValueGuard<::int32_t> tokens(nTokenSupportBlockNumber, 0);
    SyntheticChain chain;
    chain.SetActiveTip(chain.Genesis());
    nTokenSupportBlockNumber = 0;
    CheckDeployed(true, "genesis, " + TokenHeight(0));
    nTokenSupportBlockNumber = 1;
    CheckDeployed(false, "genesis, " + TokenHeight(1));
    nTokenSupportBlockNumber = -1;
    CheckDeployed(true, "genesis, " + TokenHeight(-1));
}

BOOST_AUTO_TEST_CASE(around_the_token_height)
{
    RequireActiveAtGenesis();
    const int nToken = 10;
    ValueGuard<::int32_t> tokens(nTokenSupportBlockNumber, nToken);
    SyntheticChain chain;
    const std::vector<CBlockIndex*> v = BuildChain(chain, nToken + 1);

    chain.SetActiveTip(v[nToken - 1]);
    CheckDeployed(false, "tip one before the token height");
    chain.SetActiveTip(v[nToken]);
    CheckDeployed(true, "tip at the token height");
    chain.SetActiveTip(v[nToken + 1]);
    CheckDeployed(true, "tip one past the token height");
}

BOOST_AUTO_TEST_CASE(follows_a_lower_tip)
{
    RequireActiveAtGenesis();
    const int nToken = 10;
    ValueGuard<::int32_t> tokens(nTokenSupportBlockNumber, nToken);
    SyntheticChain chain;
    const std::vector<CBlockIndex*> v = BuildChain(chain, nToken);

    chain.SetActiveTip(v[nToken]);
    CheckDeployed(true, "tip at the token height");
    chain.SetActiveTip(v[nToken - 1]);
    CheckDeployed(false, "tip lowered to one before the token height");
    chain.SetActiveTip(chain.Genesis());
    CheckDeployed(false, "tip lowered to genesis");
    chain.SetActiveTip(v[nToken]);
    CheckDeployed(true, "tip back at the token height");
}

BOOST_AUTO_TEST_CASE(tip_not_reaching_genesis)
{
    RequireActiveAtGenesis();
    ValueGuard<::int32_t> tokens(nTokenSupportBlockNumber, 0);
    // An entry at height 20 without a pprev.
    CBlockIndex standalone;
    standalone.nHeight = 20;
    standalone.nTime = chainActive.Genesis()->nTime + 20 * TEST_SPACING;
    standalone.nBits = TEST_BITS;
    SyntheticChain chain;

    // From an empty active chain: element 0 stays empty.
    chain.SetActiveTip(nullptr);
    chain.SetActiveTip(&standalone);
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(chainActive.Height(), 20);
        BOOST_REQUIRE(chainActive.Genesis() == nullptr);
    }
    for (int nToken : {0, -1}) {
        nTokenSupportBlockNumber = nToken;
        CheckDeployed(false, "tip at height 20 without a genesis entry, " + TokenHeight(nToken));
    }

    // From an active chain at genesis: element 0 keeps genesis.
    chain.SetActiveTip(chain.Genesis());
    chain.SetActiveTip(&standalone);
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(chainActive.Height(), 20);
        BOOST_REQUIRE(chainActive.Genesis() == chain.Genesis());
    }
    for (int nToken : {0, -1}) {
        nTokenSupportBlockNumber = nToken;
        CheckDeployed(true, "tip at height 20 with the earlier genesis entry kept, " + TokenHeight(nToken));
    }
}

BOOST_AUTO_TEST_CASE(other_chain_has_no_effect)
{
    RequireActiveAtGenesis();
    ValueGuard<::int32_t> tokens(nTokenSupportBlockNumber, 0);
    SyntheticChain chain;
    const std::vector<CBlockIndex*> v = BuildChain(chain, 10);

    {
        nTokenSupportBlockNumber = 0;
        chain.SetActiveTip(nullptr);
        CChain local;
        local.SetTip(v[10]);
        BOOST_REQUIRE_EQUAL(local.Height(), 10);
        CheckDeployed(false, "empty active chain, other chain at height 10, " + TokenHeight(0));
    }
    {
        nTokenSupportBlockNumber = 5;
        chain.SetActiveTip(chain.Genesis());
        CChain local;
        local.SetTip(v[10]);
        BOOST_REQUIRE_EQUAL(local.Height(), 10);
        CheckDeployed(false, "active chain at genesis, other chain at height 10, " + TokenHeight(5));
        local.SetTip(nullptr);
        CheckDeployed(false, "active chain at genesis, other chain emptied, " + TokenHeight(5));
    }
}

BOOST_AUTO_TEST_CASE(follows_the_token_height)
{
    RequireActiveAtGenesis();
    ValueGuard<::int32_t> tokens(nTokenSupportBlockNumber, 0);
    SyntheticChain chain;
    const std::vector<CBlockIndex*> v = BuildChain(chain, 10);

    chain.SetActiveTip(v[10]);
    nTokenSupportBlockNumber = 9;
    CheckDeployed(true, "tip at height 10, " + TokenHeight(9));
    nTokenSupportBlockNumber = 10;
    CheckDeployed(true, "tip at height 10, " + TokenHeight(10));
    nTokenSupportBlockNumber = 11;
    CheckDeployed(false, "tip at height 10, " + TokenHeight(11));
}

BOOST_AUTO_TEST_SUITE_END()
