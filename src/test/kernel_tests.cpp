// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Proof-of-stake kernel and stake modifier (kernel.cpp). First tests use the
// consensus harness (P0-47); the full coverage is tasks P0-17 and P0-18.
// They pin current behaviour, including the early returns that make the
// stake-modifier code unreachable with the unit-test globals (review A4).

#include "test/consensus_harness.h"

#include "chain.h"
#include "chainparams.h"
#include "kernel.h"

#include <boost/test/unit_test.hpp>

using namespace consensus_harness;

BOOST_FIXTURE_TEST_SUITE(kernel_tests, ConsensusTestingSetup)

/* CheckStakeModifierCheckpoints (kernel.cpp:649) returns true early when
 * chainActive.Tip()->nHeight + 1 >= nMainnetNewLogicBlockNumber, i.e. always
 * with the unit-test globals; with the mainnet fork height it checks the
 * hard checkpoints, and fTestNet selects the testnet table. */
BOOST_AUTO_TEST_CASE(harness_stake_modifier_checkpoints)
{
    chain.StartOnExistingGenesis();
    chain.SetActiveTip(chain.Tip());

    globals.UseUnitTestGlobals();
    BOOST_CHECK(CheckStakeModifierCheckpoints(15000, 0));

    globals.UseMainnetGlobals();
    BOOST_CHECK(!CheckStakeModifierCheckpoints(15000, 0));
    BOOST_CHECK(CheckStakeModifierCheckpoints(15000, 0x085e9caf));
    BOOST_CHECK(CheckStakeModifierCheckpoints(15001, 0)); // no checkpoint there

    globals.SetTestNet(true);
    BOOST_CHECK(CheckStakeModifierCheckpoints(15000, 0)); // testnet table has only height 0
}

/* The real genesis with the stake modifier that ReceivedBlockTransactions
 * gives it on a mainnet node (generated, 0) matches the height-0 checkpoint
 * of the build's parameters. */
BOOST_AUTO_TEST_CASE(harness_genesis_stake_modifier_checksum)
{
    globals.UseMainnetGlobals();
    CBlockIndex* genesis = chain.StartOnExistingGenesis();
    chain.SetActiveTip(genesis);

    uint64_t nStakeModifier = 0xdeadbeef;
    bool fGenerated = false;
    BOOST_CHECK(ComputeNextStakeModifier(genesis, nStakeModifier, fGenerated));
    BOOST_CHECK_EQUAL(nStakeModifier, 0U);
    BOOST_CHECK(fGenerated);

    // Work on a copy: the genesis entry belongs to TestingSetup. In
    // test_bitcoin it has no modifier, because the unit-test fork height 0
    // skips the stake-modifier code in ReceivedBlockTransactions.
    CBlockIndex copy = *genesis;
    copy.SetStakeModifier(nStakeModifier, fGenerated);
    const uint32_t nChecksum = GetStakeModifierChecksum(&copy);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(nChecksum, 0x0e00670bU);
#else
    BOOST_CHECK_EQUAL(nChecksum, 0xfd11f4e7U);
#endif
    BOOST_CHECK(CheckStakeModifierCheckpoints(0, nChecksum));
    BOOST_CHECK(!CheckStakeModifierCheckpoints(0, nChecksum ^ 1));
}

/* ComputeNextStakeModifier (kernel.cpp:187): early return with the unit-test
 * globals (outputs untouched); with mainnet globals the genesis generates
 * modifier 0, a block in the same 6-hour modifier interval keeps it, and the
 * first block whose parent is in a new interval selects min(64, candidates)
 * blocks and takes their entropy bits. All entropy bits are 1 here, so the
 * result does not depend on which blocks are selected: 4 candidates give 0xf. */
BOOST_AUTO_TEST_CASE(harness_compute_next_stake_modifier)
{
    const int64_t nInterval = Params().GetConsensus().nModifierInterval;
    BOOST_REQUIRE_EQUAL(nInterval, 6 * 60 * 60);
    const int64_t nT0 = 63334 * nInterval; // 1368014400, start of an interval
    const unsigned int nBits = 0x1d00ffff;

    BlockSpec spec(nT0, nBits);
    spec.nEntropyBit = 1;
    spec.fGeneratedStakeModifier = true; // genesis modifier 0, generated
    CBlockIndex* g = chain.Append(spec);
    spec.fGeneratedStakeModifier = false;
    spec.nTime = nT0 + 60;
    CBlockIndex* b1 = chain.Append(spec);
    spec.nTime = nT0 + 120;
    CBlockIndex* b2 = chain.Append(spec);
    spec.nTime = nT0 + nInterval + 60; // next interval
    CBlockIndex* b3 = chain.Append(spec);
    spec.nTime = nT0 + nInterval + 120;
    CBlockIndex* b4 = chain.Append(spec);

    uint64_t nModifier;
    bool fGenerated;

    // Unit-test globals: returns true at once, outputs untouched.
    globals.UseUnitTestGlobals();
    chain.SetActiveTip(b3);
    nModifier = 0xdeadbeef;
    fGenerated = true;
    BOOST_CHECK(ComputeNextStakeModifier(b4, nModifier, fGenerated));
    BOOST_CHECK_EQUAL(nModifier, 0xdeadbeefU);
    BOOST_CHECK(fGenerated);

    globals.UseMainnetGlobals();

    chain.SetActiveTip(g);
    nModifier = 0xdeadbeef;
    fGenerated = false;
    BOOST_CHECK(ComputeNextStakeModifier(g, nModifier, fGenerated));
    BOOST_CHECK_EQUAL(nModifier, 0U);
    BOOST_CHECK(fGenerated);

    chain.SetActiveTip(b1);
    nModifier = 0xdeadbeef;
    fGenerated = true;
    BOOST_CHECK(ComputeNextStakeModifier(b2, nModifier, fGenerated));
    BOOST_CHECK_EQUAL(nModifier, 0U); // modifier of g, kept
    BOOST_CHECK(!fGenerated);

    chain.SetActiveTip(b3);
    nModifier = 0xdeadbeef;
    fGenerated = false;
    BOOST_CHECK(ComputeNextStakeModifier(b4, nModifier, fGenerated));
    BOOST_CHECK_EQUAL(nModifier, 0xfU);
    BOOST_CHECK(fGenerated);
}

BOOST_AUTO_TEST_SUITE_END()
