// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block trust and chain trust (chain.cpp:75-115). First tests use the
// consensus harness (P0-47); the full coverage is task P0-16. These tests pin
// current behaviour, see review A7 in project/plans/phase0-review.md.

#include "test/consensus_harness.h"

#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "timestamps.h"

#include <boost/test/unit_test.hpp>

using namespace consensus_harness;

BOOST_FIXTURE_TEST_SUITE(chain_trust_tests, ConsensusTestingSetup)

/* Rules since CONSECUTIVE_STAKE_SWITCH_TIME: first block 1, PoW
 * powLimit / target (doubled after PoS), PoS after PoW previous trust + 1,
 * PoS after PoS 0; bnChainTrust is the running sum. */
BOOST_AUTO_TEST_CASE(harness_trust_after_switch_time)
{
    const CBigNum bnPowLimit = Params().GetConsensus().powLimit;
    const unsigned int nBits = 0x1d00ffff;
    const CBigNum bnPowTrust = bnPowLimit / CBigNum().SetCompact(nBits);
    const int64_t nTime = CONSECUTIVE_STAKE_SWITCH_TIME + 1000;

    CBlockIndex* first = chain.Append(BlockSpec(nTime, nBits));
    CBlockIndex* pow1 = chain.Append(BlockSpec(nTime + 60, nBits));
    CBlockIndex* pos1 = chain.Append(BlockSpec(nTime + 120, nBits, true));
    CBlockIndex* pos2 = chain.Append(BlockSpec(nTime + 180, nBits, true));
    CBlockIndex* pow2 = chain.Append(BlockSpec(nTime + 240, nBits));

    BOOST_CHECK(first->GetBlockTrust() == CBigNum(1));
    BOOST_CHECK(pow1->GetBlockTrust() == bnPowTrust);
    BOOST_CHECK(pos1->GetBlockTrust() == bnPowTrust + 1);
    BOOST_CHECK(pos2->GetBlockTrust() == CBigNum(0));
    BOOST_CHECK(pow2->GetBlockTrust() == bnPowTrust * 2);
    BOOST_CHECK(pow2->bnChainTrust == CBigNum(1) + bnPowTrust + (bnPowTrust + 1) + CBigNum(0) + bnPowTrust * 2);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    // Mainnet powLimit = 2^236 - 1, target = 0xffff * 2^208.
    BOOST_CHECK(bnPowTrust == CBigNum(4096));
#endif

    // Target <= 0 gives no trust.
    CBlockIndex* zero = chain.Append(BlockSpec(nTime + 300, 0));
    BOOST_CHECK(zero->GetBlockTrust() == CBigNum(0));
}

/* Before CONSECUTIVE_STAKE_SWITCH_TIME: PoW 1, PoS (1 << 256) / (target + 1).
 * fTestNet switches to the new rules regardless of the time (chain.cpp:83). */
BOOST_AUTO_TEST_CASE(harness_trust_legacy_rules_and_testnet_switch)
{
    const CBigNum bnPowLimit = Params().GetConsensus().powLimit;
    const unsigned int nBits = 0x1d00ffff;
    const CBigNum bnTarget = CBigNum().SetCompact(nBits);
    const int64_t nTime = CONSECUTIVE_STAKE_SWITCH_TIME - 1000;

    chain.Append(BlockSpec(nTime, nBits));
    CBlockIndex* pow = chain.Append(BlockSpec(nTime + 60, nBits));
    CBlockIndex* pos = chain.Append(BlockSpec(nTime + 120, nBits, true));

    BOOST_CHECK(pow->GetBlockTrust() == CBigNum(1));
    BOOST_CHECK(pos->GetBlockTrust() == (CBigNum(1) << 256) / (bnTarget + 1));
    BOOST_CHECK(pos->bnChainTrust == CBigNum(1) + CBigNum(1) + (CBigNum(1) << 256) / (bnTarget + 1));

    globals.SetTestNet(true);
    BOOST_CHECK(pow->GetBlockTrust() == bnPowLimit / bnTarget);
    BOOST_CHECK(pos->GetBlockTrust() == bnPowLimit / bnTarget + 1);
    // bnChainTrust was computed when the entries were added and is not
    // recomputed.
    BOOST_CHECK(pos->bnChainTrust == CBigNum(1) + CBigNum(1) + (CBigNum(1) << 256) / (bnTarget + 1));
}

BOOST_AUTO_TEST_SUITE_END()
