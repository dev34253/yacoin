// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Activation heights of the consensus rules: the table, its regtest override, and each rule
// one block below and at its height.

#include "chain.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "script/interpreter.h"
#include "sync.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace {

/** The script flags of a block at nHeight, with the selected chain's parameters */
unsigned int FlagsAt(int nHeight)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.nTime = Params().GenesisBlock().nTime + 60;
    LOCK(cs_main);
    return GetBlockScriptFlags(&index, Params().GetConsensus());
}

bool HasCLTV(int nHeight) { return (FlagsAt(nHeight) & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) != 0; }
bool HasCSV(int nHeight) { return (FlagsAt(nHeight) & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) != 0; }

} // namespace

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cltv_boundary)
{
    SelectedParamsGuard restore(CBaseChainParams::REGTEST);
    UpdateActivationHeight(Consensus::ACTIVATION_CLTV, 10);
    BOOST_CHECK(!HasCLTV(9));
    BOOST_CHECK(HasCLTV(10));
    BOOST_CHECK(HasCLTV(11));
    // The CSV entry stays at 0.
    BOOST_CHECK(HasCSV(9));
    BOOST_CHECK(HasCSV(10));
}

BOOST_AUTO_TEST_CASE(csv_boundary)
{
    SelectedParamsGuard restore(CBaseChainParams::REGTEST);
    UpdateActivationHeight(Consensus::ACTIVATION_CSV, 10);
    BOOST_CHECK(!HasCSV(9));
    BOOST_CHECK(HasCSV(10));
    BOOST_CHECK(HasCSV(11));
    // The CLTV entry stays at 0.
    BOOST_CHECK(HasCLTV(9));
    BOOST_CHECK(HasCLTV(10));
}

BOOST_AUTO_TEST_CASE(main_cltv_and_csv_at_their_height)
{
    SelectedParamsGuard restore(CBaseChainParams::MAIN);
    BOOST_CHECK(!HasCLTV(1889999));
    BOOST_CHECK(HasCLTV(1890000));
    BOOST_CHECK(!HasCSV(1889999));
    BOOST_CHECK(HasCSV(1890000));
}

BOOST_AUTO_TEST_SUITE_END()
