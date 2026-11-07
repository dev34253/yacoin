// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The default nVersion of a block header, a block and a transaction, chosen by
// CBlockHeader::SetNull and CTransaction::SetNull from the height of the active
// chain and the fork height nMainnetNewLogicBlockNumber: the new versions once
// the next block (tip height + 1) is at or past the fork height, the old ones
// before that and when the active chain has no genesis entry.

#include "chain.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "timedata.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"
#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

const unsigned int TEST_BITS = 0x1e0fffff;
const ::int64_t TEST_SPACING = 60;

// Local copies: the class constants are declared without a definition, and
// BOOST_CHECK_EQUAL takes its arguments by reference.
const int TX_VERSION_OLD = CTransaction::CURRENT_VERSION_of_Tx_for_yac_old;
const int TX_VERSION_NEW = CTransaction::CURRENT_VERSION;
const int BLOCK_VERSION_OLD = CURRENT_VERSION_of_block;
const int BLOCK_VERSION_NEW = VERSION_of_block_for_yac_05x_new;

/** Checks the defaults of a newly constructed header, block and transaction. */
void CheckDefaults(bool fNew, const std::string& strWhat)
{
    const int nBlockVersion = fNew ? BLOCK_VERSION_NEW : BLOCK_VERSION_OLD;
    const int nTxVersion = fNew ? TX_VERSION_NEW : TX_VERSION_OLD;
    const int nHeaderGot = CBlockHeader().nVersion;
    const int nBlockGot = CBlock().nVersion;
    const int nTxGot = CTransaction().nVersion;
    BOOST_CHECK_MESSAGE(nHeaderGot == nBlockVersion,
        strWhat << ": CBlockHeader().nVersion is " << nHeaderGot << ", expected " << nBlockVersion);
    BOOST_CHECK_MESSAGE(nBlockGot == nBlockVersion,
        strWhat << ": CBlock().nVersion is " << nBlockGot << ", expected " << nBlockVersion);
    BOOST_CHECK_MESSAGE(nTxGot == nTxVersion,
        strWhat << ": CTransaction().nVersion is " << nTxGot << ", expected " << nTxVersion);
}

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

/** Restores the mock time when the test ends. */
struct MockTimeGuard
{
    ::int64_t nSaved = GetMockTime();
    ~MockTimeGuard() { SetMockTime(nSaved); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(default_version_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(no_chain_gives_old_defaults)
{
    RequireActiveAtGenesis();
    ConsensusGlobalsGuard globals;
    SyntheticChain chain;
    chain.SetActiveTip(nullptr);
    for (int nFork : {0, 1, 1000}) {
        nMainnetNewLogicBlockNumber = nFork;
        CheckDefaults(false, "no chain, fork height " + std::to_string(nFork));
    }
}

BOOST_AUTO_TEST_CASE(genesis_only)
{
    RequireActiveAtGenesis();
    ConsensusGlobalsGuard globals;
    SyntheticChain chain;
    chain.SetActiveTip(chain.Genesis());
    nMainnetNewLogicBlockNumber = 0;
    CheckDefaults(true, "genesis, fork height 0");
    nMainnetNewLogicBlockNumber = 1;
    CheckDefaults(true, "genesis, fork height 1");
    nMainnetNewLogicBlockNumber = 2;
    CheckDefaults(false, "genesis, fork height 2");
}

BOOST_AUTO_TEST_CASE(around_the_fork_height)
{
    RequireActiveAtGenesis();
    ConsensusGlobalsGuard globals;
    SyntheticChain chain;
    const int nFork = 10;
    nMainnetNewLogicBlockNumber = nFork;
    const std::vector<CBlockIndex*> v = BuildChain(chain, nFork);

    // Next block at nFork - 1, nFork and nFork + 1.
    chain.SetActiveTip(v[nFork - 2]);
    CheckDefaults(false, "next block one before the fork height");
    chain.SetActiveTip(v[nFork - 1]);
    CheckDefaults(true, "next block at the fork height");
    chain.SetActiveTip(v[nFork]);
    CheckDefaults(true, "next block one past the fork height");
}

BOOST_AUTO_TEST_CASE(follows_a_lower_tip)
{
    RequireActiveAtGenesis();
    ConsensusGlobalsGuard globals;
    SyntheticChain chain;
    const int nFork = 10;
    nMainnetNewLogicBlockNumber = nFork;
    const std::vector<CBlockIndex*> v = BuildChain(chain, nFork);

    chain.SetActiveTip(v[nFork - 1]);
    CheckDefaults(true, "tip at fork height - 1");
    chain.SetActiveTip(v[nFork - 2]);
    CheckDefaults(false, "tip lowered to fork height - 2");
    chain.SetActiveTip(chain.Genesis());
    CheckDefaults(false, "tip lowered to genesis");
}

BOOST_AUTO_TEST_CASE(tip_not_reaching_genesis)
{
    RequireActiveAtGenesis();
    ConsensusGlobalsGuard globals;
    // An entry at height 20 whose pprev chain ends at once.
    CBlockIndex standalone;
    standalone.nHeight = 20;
    standalone.nTime = chainActive.Genesis()->nTime + 20 * TEST_SPACING;
    standalone.nBits = TEST_BITS;
    SyntheticChain chain;
    nMainnetNewLogicBlockNumber = 0;

    // From an empty active chain: element 0 stays empty.
    chain.SetActiveTip(nullptr);
    chain.SetActiveTip(&standalone);
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(chainActive.Height(), 20);
        BOOST_REQUIRE(chainActive.Genesis() == nullptr);
    }
    CheckDefaults(false, "tip at height 20 without a genesis entry");

    // From an active chain at genesis: element 0 keeps genesis.
    chain.SetActiveTip(chain.Genesis());
    chain.SetActiveTip(&standalone);
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(chainActive.Height(), 20);
        BOOST_REQUIRE(chainActive.Genesis() == chain.Genesis());
    }
    CheckDefaults(true, "tip at height 20 with the earlier genesis entry kept");
}

BOOST_AUTO_TEST_CASE(other_chain_has_no_effect)
{
    RequireActiveAtGenesis();
    ConsensusGlobalsGuard globals;
    SyntheticChain chain;
    const std::vector<CBlockIndex*> v = BuildChain(chain, 10);

    {
        nMainnetNewLogicBlockNumber = 0;
        chain.SetActiveTip(nullptr);
        CChain local;
        local.SetTip(v[10]);
        BOOST_REQUIRE_EQUAL(local.Height(), 10);
        CheckDefaults(false, "empty active chain, other chain at height 10, fork height 0");
    }
    {
        nMainnetNewLogicBlockNumber = 5;
        chain.SetActiveTip(chain.Genesis());
        CChain local;
        local.SetTip(v[10]);
        BOOST_REQUIRE_EQUAL(local.Height(), 10);
        CheckDefaults(false, "active chain at genesis, other chain at height 10, fork height 5");
        local.SetTip(nullptr);
        CheckDefaults(false, "active chain at genesis, other chain emptied, fork height 5");
    }
}

BOOST_AUTO_TEST_CASE(explicit_setnull_follows_the_tip)
{
    RequireActiveAtGenesis();
    ConsensusGlobalsGuard globals;
    SyntheticChain chain;
    const int nFork = 10;
    nMainnetNewLogicBlockNumber = nFork;
    const std::vector<CBlockIndex*> v = BuildChain(chain, nFork);

    chain.SetActiveTip(chain.Genesis());
    CBlockHeader header;
    CBlock block;
    CTransaction tx;
    BOOST_CHECK_EQUAL(header.nVersion, BLOCK_VERSION_OLD);
    BOOST_CHECK_EQUAL(block.nVersion, BLOCK_VERSION_OLD);
    BOOST_CHECK_EQUAL(tx.nVersion, TX_VERSION_OLD);

    chain.SetActiveTip(v[nFork]);
    header.SetNull();
    block.SetNull();
    tx.SetNull();
    BOOST_CHECK_EQUAL(header.nVersion, BLOCK_VERSION_NEW);
    BOOST_CHECK_EQUAL(block.nVersion, BLOCK_VERSION_NEW);
    BOOST_CHECK_EQUAL(tx.nVersion, TX_VERSION_NEW);

    chain.SetActiveTip(chain.Genesis());
    header.SetNull();
    block.SetNull();
    tx.SetNull();
    BOOST_CHECK_EQUAL(header.nVersion, BLOCK_VERSION_OLD);
    BOOST_CHECK_EQUAL(block.nVersion, BLOCK_VERSION_OLD);
    BOOST_CHECK_EQUAL(tx.nVersion, TX_VERSION_OLD);
}

BOOST_AUTO_TEST_CASE(transaction_default_time_is_adjusted_time)
{
    RequireActiveAtGenesis();
    MockTimeGuard mocktime;
    const ::int64_t nMock = 1700000000;
    SetMockTime(nMock);
    CTransaction tx;
    BOOST_CHECK_EQUAL(tx.nTime, nMock + GetTimeOffset());

    SetMockTime(nMock + 100);
    tx.SetNull();
    BOOST_CHECK_EQUAL(tx.nTime, nMock + 100 + GetTimeOffset());
}

BOOST_AUTO_TEST_SUITE_END()
