// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block trust, chain trust and fork choice (tasks P0-47, P0-16).
//
// Pins current behaviour, bugs included (CLAUDE.md rule 1; review A5, A7, C8
// in project/plans/phase0-review.md):
//  - every reachable branch of CBlockIndex::GetBlockTrust (chain.cpp:75-115),
//  - the accumulated bnChainTrust and fork choice by trust
//    (CBlockIndexWorkComparator, validation.cpp:112; AcceptBlock,
//    validation.cpp:3457) with real regtest blocks,
//  - GetBlockProofEquivalentTime (chain.cpp:188-205), which mixes Yacoin
//    trust with Bitcoin's GetBlockProof,
//  - the RPC output of the trust values,
//  - the trust comparisons in net_processing.cpp (438-456, 536, 3113-3119)
//    through P2P messages on test peers.
// The header-sync comparisons (net_processing.cpp 1481, 1507, 1583) are left
// to the functional test of P0-32. Mainnet trust values are checked by P0-23.

#include "test/consensus_harness.h"
#include "test/pos_generator.h"

#include "arith_uint256.h"
#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "hash.h"
#include "miner.h"
#include "net.h"
#include "net_processing.h"
#include "netmessagemaker.h"
#include "pow.h"
#include "protocol.h"
#include "rpc/blockchain.h"
#include "rpc/server.h"
#include "streams.h"
#include "timedata.h"
#include "tokens/tokendb.h"
#include "timestamps.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

using namespace consensus_harness;

UniValue CallRPC(std::string args); // defined in rpc_tests.cpp

namespace {

const unsigned int NBITS_1D00FFFF = 0x1d00ffff;
const int64_t NEW_RULES_TIME = CONSECUTIVE_STAKE_SWITCH_TIME + 1000;
const int64_t LEGACY_TIME = CONSECUTIVE_STAKE_SWITCH_TIME - 1000;

CBigNum Target(unsigned int nBits)
{
    CBigNum bn;
    bn.SetCompact(nBits);
    return bn;
}

CBigNum PowLimit()
{
    return Params().GetConsensus().powLimit;
}

/** 2^n */
CBigNum Pow2(unsigned int n)
{
    return CBigNum(1) << n;
}

} // namespace

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

/* chain.cpp:77-80: a target <= 0 gives 0 before any other rule – nBits 0, a
 * zero mantissa and a negative compact (sign bit 0x00800000) – for PoW and
 * PoS, with and without pprev, under the new and the legacy rules. */
BOOST_AUTO_TEST_CASE(trust_target_not_positive)
{
    BOOST_CHECK(Target(0x04923456) < 0);
    BOOST_CHECK(Target(0x01fedcba) < 0);
    BOOST_CHECK(Target(0x05000000) == 0);

    uint32_t nSalt = 1;
    for (int64_t nTime : {NEW_RULES_TIME, LEGACY_TIME}) {
        for (unsigned int nBits : {0x00000000U, 0x05000000U, 0x04923456U, 0x01fedcbaU}) {
            TestChain c(nSalt++);
            CBlockIndex* first = c.Append(BlockSpec(nTime, nBits));           // no pprev
            CBlockIndex* pow = c.Append(BlockSpec(nTime + 60, nBits));        // PoW after PoW
            CBlockIndex* pos = c.Append(BlockSpec(nTime + 120, nBits, true)); // PoS after PoW
            CBlockIndex* pow2 = c.Append(BlockSpec(nTime + 180, nBits));      // PoW after PoS
            CBlockIndex* posFirst = c.Append(nullptr, BlockSpec(nTime, nBits, true));
            for (CBlockIndex* p : {first, pow, pos, pow2, posFirst}) {
                BOOST_CHECK_MESSAGE(p->GetBlockTrust() == 0,
                    strprintf("nBits %08x time %d height %d", nBits, nTime, p->nHeight));
            }
            BOOST_CHECK(pow2->bnChainTrust == 0);
        }
    }
}

/* chain.cpp:86-87: under the new rules an entry without pprev gets 1, PoW or
 * PoS, whatever its positive target (also above powLimit). The real genesis
 * is older than the switch time and gets 1 from the legacy PoW rule instead
 * (trust_genesis). */
BOOST_AUTO_TEST_CASE(trust_first_block_new_rules)
{
    for (unsigned int nBits : {NBITS_1D00FFFF, 0x1e0fffffU, 0x2100ffffU, 0x03000001U}) {
        CBlockIndex* pow = chain.Append(nullptr, BlockSpec(NEW_RULES_TIME, nBits));
        CBlockIndex* pos = chain.Append(nullptr, BlockSpec(NEW_RULES_TIME, nBits, true));
        BOOST_CHECK(pow->GetBlockTrust() == 1);
        BOOST_CHECK(pos->GetBlockTrust() == 1);
        BOOST_CHECK(pos->bnChainTrust == 1);
    }
}

/* The real genesis of the build's main params (2013, before the switch time)
 * gets 1 from the legacy PoW rule. */
BOOST_AUTO_TEST_CASE(trust_genesis)
{
    LOCK(cs_main);
    CBlockIndex* genesis = chainActive.Genesis();
    BOOST_REQUIRE(genesis != nullptr);
    BOOST_CHECK(genesis->GetBlockTime() < CONSECUTIVE_STAKE_SWITCH_TIME);
    BOOST_CHECK(genesis->pprev == nullptr);
    BOOST_CHECK(genesis->IsProofOfWork());
    BOOST_CHECK(genesis->GetBlockTrust() == 1);
    BOOST_CHECK(genesis->bnChainTrust == 1);
}

/* chain.cpp:99-111: PoW under the new rules = powLimit / target (integer
 * division, so a target above powLimit gives 0), doubled when pprev is PoS –
 * also when that PoS block has trust 0 itself – and not doubled after PoW. */
BOOST_AUTO_TEST_CASE(trust_pow_new_rules)
{
    struct Case {
        unsigned int nBits;
        int64_t nMainnet; // expected powLimit / target, mainnet build
        int64_t nLowDiff; // low-difficulty build
    };
    // powLimit: mainnet 2^236 - 1 (compact 0x1e0fffff), low difficulty
    // 2^253 - 1 (chainparams.cpp:78/82).
    const Case cases[] = {
        {NBITS_1D00FFFF, 4096, 536879104}, // target 0xffff * 2^208
        {0x1e0fffff, 1, 131072},           // mainnet compact powLimit, 2^236 - 2^216
        {0x1f00ffff, 0, 8192},             // 0xffff * 2^224 > mainnet powLimit
        {0x2100ffff, 0, 0},                // 0xffff * 2^240 > both
        {0x03000001, -1, -1},              // target 1: powLimit itself
    };
    uint32_t nSalt = 1;
    for (const Case& tc : cases) {
        TestChain c(nSalt++);
        c.Append(BlockSpec(NEW_RULES_TIME, NBITS_1D00FFFF));
        CBlockIndex* powAfterPow = c.Append(BlockSpec(NEW_RULES_TIME + 60, tc.nBits));
        c.Append(BlockSpec(NEW_RULES_TIME + 120, NBITS_1D00FFFF, true));                // PoS after PoW
        CBlockIndex* powAfterPos = c.Append(BlockSpec(NEW_RULES_TIME + 180, tc.nBits));
        c.Append(BlockSpec(NEW_RULES_TIME + 240, NBITS_1D00FFFF, true));                // PoS after PoW
        CBlockIndex* pos3 = c.Append(BlockSpec(NEW_RULES_TIME + 300, NBITS_1D00FFFF, true)); // PoS after PoS
        CBlockIndex* powAfterZeroPos = c.Append(BlockSpec(NEW_RULES_TIME + 360, tc.nBits));

        const CBigNum bnExpected = PowLimit() / Target(tc.nBits);
        if (tc.nMainnet >= 0) {
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
            BOOST_CHECK_MESSAGE(bnExpected == CBigNum(tc.nMainnet), strprintf("nBits %08x", tc.nBits));
#else
            BOOST_CHECK_MESSAGE(bnExpected == CBigNum(tc.nLowDiff), strprintf("nBits %08x", tc.nBits));
#endif
        } else {
            BOOST_CHECK(bnExpected == PowLimit());
        }
        BOOST_CHECK(powAfterPow->GetBlockTrust() == bnExpected);
        BOOST_CHECK(powAfterPos->GetBlockTrust() == bnExpected * 2);
        BOOST_CHECK(pos3->GetBlockTrust() == 0);
        BOOST_CHECK(powAfterZeroPos->GetBlockTrust() == bnExpected * 2);
    }
}

/* chain.cpp:92-97: PoS after PoS = 0 whatever the targets; PoS after PoW =
 * pprev->GetBlockTrust() + 1, evaluated with pprev's own rules, so the PoS
 * block's own (positive) target does not matter. */
BOOST_AUTO_TEST_CASE(trust_pos_new_rules)
{
    const CBigNum T = PowLimit() / Target(NBITS_1D00FFFF);

    CBlockIndex* first = chain.Append(BlockSpec(NEW_RULES_TIME, NBITS_1D00FFFF));
    CBlockIndex* posAfterFirst = chain.Append(BlockSpec(NEW_RULES_TIME + 60, NBITS_1D00FFFF, true));
    CBlockIndex* posAfterPos = chain.Append(BlockSpec(NEW_RULES_TIME + 120, 0x03000001, true));
    CBlockIndex* powAfterPos = chain.Append(BlockSpec(NEW_RULES_TIME + 180, NBITS_1D00FFFF));
    CBlockIndex* posAfterDoubled = chain.Append(BlockSpec(NEW_RULES_TIME + 240, 0x2100ffff, true));
    CBlockIndex* pow = chain.Append(BlockSpec(NEW_RULES_TIME + 300, NBITS_1D00FFFF));
    CBlockIndex* posTinyTarget = chain.Append(BlockSpec(NEW_RULES_TIME + 360, 0x03000001, true));

    BOOST_CHECK(first->GetBlockTrust() == 1);
    BOOST_CHECK(posAfterFirst->GetBlockTrust() == 2); // 1 + 1
    BOOST_CHECK(posAfterPos->GetBlockTrust() == 0);
    BOOST_CHECK(powAfterPos->GetBlockTrust() == T * 2);
    BOOST_CHECK(posAfterDoubled->GetBlockTrust() == T * 2 + 1); // pprev doubled
    BOOST_CHECK(pow->GetBlockTrust() == T * 2);                 // pprev is PoS
    BOOST_CHECK(posTinyTarget->GetBlockTrust() == T * 2 + 1);   // own target irrelevant
    BOOST_CHECK(posTinyTarget->bnChainTrust == CBigNum(1) + 2 + 0 + T * 2 + (T * 2 + 1) + T * 2 + (T * 2 + 1));

    // PoS on a PoW block with target 0 (trust 0): 0 + 1.
    TestChain c(1);
    c.Append(BlockSpec(NEW_RULES_TIME, NBITS_1D00FFFF));
    c.Append(BlockSpec(NEW_RULES_TIME + 60, 0));
    CBlockIndex* posAfterZero = c.Append(BlockSpec(NEW_RULES_TIME + 120, NBITS_1D00FFFF, true));
    BOOST_CHECK(posAfterZero->GetBlockTrust() == 1);
}

/* chain.cpp:83: the switch is "nTime >= CONSECUTIVE_STAKE_SWITCH_TIME" on the
 * block's own time. pprev's trust (PoS after PoW) is evaluated with pprev's
 * own time, and the PoW doubling only looks at pprev's PoS flag. */
BOOST_AUTO_TEST_CASE(trust_switch_time_boundary)
{
    const int64_t nSwitch = CONSECUTIVE_STAKE_SWITCH_TIME;
    const CBigNum T = PowLimit() / Target(NBITS_1D00FFFF);
    const CBigNum bnLegacyPos = Pow2(256) / (Target(NBITS_1D00FFFF) + 1);

    chain.Append(BlockSpec(nSwitch - 120, NBITS_1D00FFFF));
    CBlockIndex* powBefore = chain.Append(BlockSpec(nSwitch - 1, NBITS_1D00FFFF));
    CBlockIndex* powAt = chain.Append(BlockSpec(nSwitch, NBITS_1D00FFFF));
    BOOST_CHECK(powBefore->GetBlockTrust() == 1); // legacy
    BOOST_CHECK(powAt->GetBlockTrust() == T);     // new rules

    // PoS after the switch on a legacy PoW: legacy 1, + 1.
    TestChain c1(1);
    c1.Append(BlockSpec(nSwitch - 120, NBITS_1D00FFFF));
    c1.Append(BlockSpec(nSwitch - 60, NBITS_1D00FFFF));
    CBlockIndex* posOnLegacyPow = c1.Append(BlockSpec(nSwitch, NBITS_1D00FFFF, true));
    BOOST_CHECK(posOnLegacyPow->GetBlockTrust() == 2);

    // Before the switch PoS after PoS keeps the legacy value (no "0" rule).
    TestChain c2(2);
    c2.Append(BlockSpec(nSwitch - 180, NBITS_1D00FFFF));
    CBlockIndex* legacyPos1 = c2.Append(BlockSpec(nSwitch - 120, NBITS_1D00FFFF, true));
    CBlockIndex* legacyPos2 = c2.Append(BlockSpec(nSwitch - 60, NBITS_1D00FFFF, true));
    BOOST_CHECK(legacyPos1->GetBlockTrust() == bnLegacyPos);
    BOOST_CHECK(legacyPos2->GetBlockTrust() == bnLegacyPos);
    // PoW after the switch on a legacy PoS: doubled.
    CBlockIndex* powOnLegacyPos = c2.Append(BlockSpec(nSwitch, NBITS_1D00FFFF));
    BOOST_CHECK(powOnLegacyPos->GetBlockTrust() == T * 2);

    // PoS after the switch on a legacy PoS: 0.
    TestChain c3(3);
    c3.Append(BlockSpec(nSwitch - 120, NBITS_1D00FFFF));
    c3.Append(BlockSpec(nSwitch - 60, NBITS_1D00FFFF, true));
    CBlockIndex* posOnLegacyPos = c3.Append(BlockSpec(nSwitch, NBITS_1D00FFFF, true));
    BOOST_CHECK(posOnLegacyPos->GetBlockTrust() == 0);
}

/* chain.cpp:114, legacy rules (before the switch time, not testnet): PoW 1
 * for any positive target, PoS (1 << 256) / (target + 1) – also without
 * pprev and after PoS. For targets < 2^256 this equals Bitcoin's
 * GetBlockProof (chain.cpp:173, review A7); for target 2^256 (representable
 * in CBigNum) it is 0, and GetBlockProof gives 0 too (compact overflow). */
BOOST_AUTO_TEST_CASE(trust_legacy_rules)
{
    uint32_t nSalt = 1;
    for (unsigned int nBits : {NBITS_1D00FFFF, 0x1e0fffffU, 0x2100ffffU, 0x21008000U, 0x03000001U, 0x01010000U, 0x14010000U}) {
        TestChain c(nSalt++);
        CBlockIndex* posFirst = c.Append(BlockSpec(LEGACY_TIME, nBits, true));
        CBlockIndex* pos = c.Append(BlockSpec(LEGACY_TIME + 60, nBits, true));
        CBlockIndex* pow = c.Append(BlockSpec(LEGACY_TIME + 120, nBits));
        const CBigNum bnExpected = Pow2(256) / (Target(nBits) + 1);
        BOOST_CHECK(posFirst->GetBlockTrust() == bnExpected);
        BOOST_CHECK(pos->GetBlockTrust() == bnExpected);
        BOOST_CHECK(pow->GetBlockTrust() == 1);
        BOOST_CHECK_EQUAL(CBigNum(ArithToUint256(GetBlockProof(*pos))).GetHex(), bnExpected.GetHex());
    }

    // Literal values.
    BOOST_CHECK(Pow2(256) / (Target(NBITS_1D00FFFF) + 1) == CBigNum((int64_t)4295032833));
    BOOST_CHECK(Target(0x01010000) == 1);
    BOOST_CHECK_EQUAL((Pow2(256) / (Target(0x01010000) + 1)).GetHex(), "8" + std::string(63, '0')); // 2^255
    BOOST_CHECK(Target(0x14010000) == Pow2(152));
    BOOST_CHECK_EQUAL((Pow2(256) / (Target(0x14010000) + 1)).GetHex(), std::string(26, 'f')); // 2^104 - 1

    // Target 2^256: 0 for PoS (and for GetBlockProof); PoW still 1.
    TestChain c(nSalt++);
    CBlockIndex* posHuge = c.Append(BlockSpec(LEGACY_TIME, 0x21010000, true));
    CBlockIndex* powHuge = c.Append(BlockSpec(LEGACY_TIME + 60, 0x21010000));
    BOOST_CHECK(Target(0x21010000) == Pow2(256));
    BOOST_CHECK(posHuge->GetBlockTrust() == 0);
    BOOST_CHECK(GetBlockProof(*posHuge) == 0);
    BOOST_CHECK(powHuge->GetBlockTrust() == 1);
}

/* fTestNet selects the new rules for pre-switch times (chain.cpp:83), also
 * the first-block and the PoS-after-PoS rule; switching it back restores the
 * legacy values (trust is computed on demand). */
BOOST_AUTO_TEST_CASE(trust_testnet_switch)
{
    CBlockIndex* first = chain.Append(BlockSpec(LEGACY_TIME, NBITS_1D00FFFF, true));
    CBlockIndex* pos = chain.Append(BlockSpec(LEGACY_TIME + 60, NBITS_1D00FFFF, true));
    const CBigNum bnLegacyPos = Pow2(256) / (Target(NBITS_1D00FFFF) + 1);
    BOOST_CHECK(first->GetBlockTrust() == bnLegacyPos);
    BOOST_CHECK(pos->GetBlockTrust() == bnLegacyPos);

    globals.SetTestNet(true);
    BOOST_CHECK(first->GetBlockTrust() == 1);
    BOOST_CHECK(pos->GetBlockTrust() == 0);
    globals.SetTestNet(false);
    BOOST_CHECK(pos->GetBlockTrust() == bnLegacyPos);
}

/* What the fork choice compares (bnChainTrust, review C8), with T = PoW
 * trust: PoW→PoS beats PoW→PoW by exactly 1, PoW→PoS→PoW beats PoW→PoW→PoW
 * by T + 1, and a second consecutive PoS block adds nothing, so PoS→PoS loses
 * against an equally long PoW→PoW fork by T - 1. */
BOOST_AUTO_TEST_CASE(fork_trust_with_pos)
{
    const CBigNum T = PowLimit() / Target(NBITS_1D00FFFF);
    chain.Append(BlockSpec(NEW_RULES_TIME, NBITS_1D00FFFF));
    CBlockIndex* base = chain.Append(BlockSpec(NEW_RULES_TIME + 60, NBITS_1D00FFFF));

    CBlockIndex* powA = chain.Append(base, BlockSpec(NEW_RULES_TIME + 120, NBITS_1D00FFFF));
    CBlockIndex* posB = chain.Append(base, BlockSpec(NEW_RULES_TIME + 121, NBITS_1D00FFFF, true));
    BOOST_CHECK(posB->bnChainTrust - powA->bnChainTrust == 1);

    CBlockIndex* powA2 = chain.Append(powA, BlockSpec(NEW_RULES_TIME + 180, NBITS_1D00FFFF));
    CBlockIndex* powB2 = chain.Append(posB, BlockSpec(NEW_RULES_TIME + 181, NBITS_1D00FFFF));
    BOOST_CHECK(powB2->bnChainTrust - powA2->bnChainTrust == T + 1);

    CBlockIndex* posC = chain.Append(base, BlockSpec(NEW_RULES_TIME + 122, NBITS_1D00FFFF, true));
    CBlockIndex* posC2 = chain.Append(posC, BlockSpec(NEW_RULES_TIME + 182, NBITS_1D00FFFF, true));
    BOOST_CHECK(posC2->bnChainTrust == posC->bnChainTrust);
    BOOST_CHECK(posC2->bnChainTrust < powA2->bnChainTrust);
    BOOST_CHECK(powA2->bnChainTrust - posC2->bnChainTrust == T - 1);
}

/* GetBlockProofEquivalentTime (chain.cpp:188-205), pinned, not fixed:
 *   sign(to - from) * (((|to.bnChainTrust - from.bnChainTrust| mod 2^256)
 *                       * nPowTargetSpacing) mod 2^256) / GetBlockProof(tip)
 * saturated to +-INT64_MAX when the quotient has more than 63 bits. The
 * difference is Yacoin trust, the divisor Bitcoin's work of the tip, so the
 * "a month of work" check in net_processing.cpp:1119 compares unrelated
 * units (review A7). */
BOOST_AUTO_TEST_CASE(proof_equivalent_time)
{
    const Consensus::Params& params = Params().GetConsensus();
    BOOST_REQUIRE_EQUAL(params.nPowTargetSpacing, 60);
    const int64_t nMax = std::numeric_limits<int64_t>::max();

    // A month of 1-minute PoW blocks at 0x1d00ffff (43200 blocks).
    CBlockIndex* from = chain.Append(BlockSpec(NEW_RULES_TIME, NBITS_1D00FFFF));
    CBlockIndex* to = chain.AppendMany(43200, 60, NBITS_1D00FFFF);
    BOOST_CHECK(GetBlockProof(*to) == arith_uint256(4295032833ULL));
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    // 43200 * 4096 * 60 / 4295032833 = 2.47
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*to, *from, *to, params), 2);
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*from, *to, *to, params), -2);
#else
    // 43200 * 536879104 * 60 / 4295032833 = 323999.9
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*to, *from, *to, params), 323999);
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*from, *to, *to, params), -323999);
#endif
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*to, *to, *to, params), 0);
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*from, *from, *to, params), 0);

    // Divisor 1: a tip with target 2^255 (compact 0x21008000).
    TestChain c(1);
    c.Append(BlockSpec(LEGACY_TIME, NBITS_1D00FFFF));
    CBlockIndex* tip1 = c.Append(BlockSpec(LEGACY_TIME + 60, 0x21008000));
    BOOST_CHECK(GetBlockProof(*tip1) == 1);
    // 10 PoW blocks: 10 * T * 60.
    const CBigNum T = PowLimit() / Target(NBITS_1D00FFFF);
    CBlockIndex* to10 = chain.AtHeight(10);
    BOOST_REQUIRE(to10 != nullptr);
    CBigNum bn10 = T * 600;
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*to10, *from, *tip1, params), (int64_t)bn10.getuint64());
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*to10, *from, *tip1, params), 2457600);
#else
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*to10, *from, *tip1, params), 322127462400LL);
#endif

    // Saturation: a legacy PoS block with target 2^152 adds 2^104 - 1.
    TestChain s(2);
    CBlockIndex* sFrom = s.Append(BlockSpec(LEGACY_TIME, NBITS_1D00FFFF));
    CBlockIndex* sTo = s.Append(BlockSpec(LEGACY_TIME + 60, 0x14010000, true));
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*sTo, *sFrom, *tip1, params), nMax);
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*sFrom, *sTo, *tip1, params), -nMax); // not INT64_MIN
    // Also with the 0x1d00ffff tip: 2^104 * 60 / 4295032833 > 2^63.
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*sTo, *sFrom, *to, params), nMax);

    // Wrap-around: a difference of 2^255 times 60 is 0 mod 2^256, and a
    // difference of 2^256 is 0 after getuint256 (mod 2^256).
    TestChain w(3);
    CBlockIndex* wFrom = w.Append(BlockSpec(LEGACY_TIME, NBITS_1D00FFFF));
    CBlockIndex* w1 = w.Append(BlockSpec(LEGACY_TIME + 60, 0x01010000, true));
    CBlockIndex* w2 = w.Append(BlockSpec(LEGACY_TIME + 120, 0x01010000, true));
    BOOST_CHECK(w1->bnChainTrust - wFrom->bnChainTrust == Pow2(255));
    BOOST_CHECK(w2->bnChainTrust - wFrom->bnChainTrust == Pow2(256));
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*w1, *wFrom, *tip1, params), 0);
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*w2, *wFrom, *tip1, params), 0);
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(*wFrom, *w2, *tip1, params), 0);

    // A tip whose GetBlockProof is 0 (nBits 0, negative, compact overflow):
    // division by zero throws uint_error, also for equal trust.
    uint32_t nSalt = 10;
    for (unsigned int nBits : {0x00000000U, 0x04923456U, 0x23000001U}) {
        TestChain z(nSalt++);
        CBlockIndex* tip0 = z.Append(BlockSpec(NEW_RULES_TIME, nBits));
        BOOST_CHECK(GetBlockProof(*tip0) == 0);
        BOOST_CHECK_THROW(GetBlockProofEquivalentTime(*to, *from, *tip0, params), uint_error);
        BOOST_CHECK_THROW(GetBlockProofEquivalentTime(*to, *to, *tip0, params), uint_error);
    }
}

/* RPC output (rpc/blockchain.cpp:96, 126-127, 945): "chaintrust" and
 * "blocktrust" are lower-case hex without leading zeros, so 0 becomes "";
 * gettimechaininfo's "bnChainTrust" is a JSON number with the low 64 bits
 * (getuint64), although its help text says "string ... hexadecimal". */
BOOST_AUTO_TEST_CASE(rpc_chaintrust)
{
    const CBigNum T = PowLimit() / Target(NBITS_1D00FFFF);
    CBlockIndex* genesis = chain.StartOnExistingGenesis();
    CBlockIndex* pow = chain.Append(BlockSpec(NEW_RULES_TIME, NBITS_1D00FFFF));
    CBlockIndex* pos = chain.Append(BlockSpec(NEW_RULES_TIME + 60, NBITS_1D00FFFF, true));
    CBlockIndex* pos2 = chain.Append(BlockSpec(NEW_RULES_TIME + 120, NBITS_1D00FFFF, true));
    chain.SetActiveTip(pos2);

    UniValue header = CallRPC("getblockheader " + pos2->GetBlockHash().GetHex());
    BOOST_CHECK_EQUAL(find_value(header.get_obj(), "chaintrust").get_str(), (CBigNum(1) + T + T + 1).GetHex());
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(find_value(header.get_obj(), "chaintrust").get_str(), "2002"); // 1 + 4096 + 4097
#else
    BOOST_CHECK_EQUAL(find_value(header.get_obj(), "chaintrust").get_str(), "40004002"); // 1 + 2 * 536879104 + 1
#endif
    UniValue genesisHeader = CallRPC("getblockheader " + genesis->GetBlockHash().GetHex());
    BOOST_CHECK_EQUAL(find_value(genesisHeader.get_obj(), "chaintrust").get_str(), "1");

    {
        LOCK(cs_main);
        UniValue blockPos2 = blockToJSON(CBlock(), pos2);
        BOOST_CHECK_EQUAL(find_value(blockPos2.get_obj(), "blocktrust").get_str(), ""); // 0
        BOOST_CHECK_EQUAL(find_value(blockPos2.get_obj(), "chaintrust").get_str(), pos2->bnChainTrust.GetHex());
        UniValue blockPos = blockToJSON(CBlock(), pos);
        BOOST_CHECK_EQUAL(find_value(blockPos.get_obj(), "blocktrust").get_str(), (T + 1).GetHex());
        UniValue blockPow = blockToJSON(CBlock(), pow);
        BOOST_CHECK_EQUAL(find_value(blockPow.get_obj(), "blocktrust").get_str(), T.GetHex());
    }

    // gettimechaininfo: a number, the low 64 bits.
    UniValue info = CallRPC("gettimechaininfo");
    BOOST_CHECK(find_value(info.get_obj(), "bnChainTrust").isNum());
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "bnChainTrust").get_int64(), (int64_t)pos2->bnChainTrust.getuint64());

    // Test-owned entries with chosen bnChainTrust (the RPCs only read it):
    // 2^64 + 5 -> 5, 2^64 -> 0 in gettimechaininfo; the full hex in
    // getblockheader; a chain trust of 0 is "".
    CBlockIndex* big = chain.Append(pos2, BlockSpec(NEW_RULES_TIME + 180, NBITS_1D00FFFF));
    big->bnChainTrust = Pow2(64) + 5;
    chain.SetActiveTip(big);
    info = CallRPC("gettimechaininfo");
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "bnChainTrust").get_int64(), 5);
    big->bnChainTrust = Pow2(64);
    info = CallRPC("gettimechaininfo");
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "bnChainTrust").get_int64(), 0);
    header = CallRPC("getblockheader " + big->GetBlockHash().GetHex());
    BOOST_CHECK_EQUAL(find_value(header.get_obj(), "chaintrust").get_str(), "1" + std::string(16, '0'));
    big->bnChainTrust = 0;
    header = CallRPC("getblockheader " + big->GetBlockHash().GetHex());
    BOOST_CHECK_EQUAL(find_value(header.get_obj(), "chaintrust").get_str(), "");
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Real blocks on regtest: AddToBlockIndex trust and fork choice.
// ---------------------------------------------------------------------------

namespace {

/** Regtest (powLimit 2^255 - 1) makes mining in a unit test cheap. No
 *  TestChain entries here: CheckBlockIndex walks mapBlockIndex.
 *  DisconnectBlock reads token undo data from ptokensdb
 *  (validation.cpp:1322); TestingSetup provides an in-memory one (P0-62). */
struct RegtestConsensusSetup : public ConsensusTestingSetup {
    RegtestConsensusSetup() : ConsensusTestingSetup(CBaseChainParams::REGTEST)
    {
        BOOST_REQUIRE(ptokensdb != nullptr);
    }

    /** A valid PoW block on parent (any entry, not only the tip): the
     *  miner's template with hashPrevBlock, time, nBits, coinbase height,
     *  value and merkle root redone for parent, paying to script. */
    CBlock MineBlock(CBlockIndex* parent, const CScript& script)
    {
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler().CreateNewBlock(script);
        BOOST_REQUIRE(tmpl);
        CBlock block = tmpl->block;
        block.vtx.resize(1);
        block.hashPrevBlock = parent->GetBlockHash();
        block.nTime = std::max<int64_t>(parent->GetMedianTimePast() + 1, GetAdjustedTime());
        block.nBits = GetNextTargetRequired(parent, false);
        // The template's value is for the active height (miner.cpp:525).
        block.vtx[0].vout[0].nValue = GetProofOfWorkReward(block.nBits, 0, parent->nHeight + 1);
        unsigned int nExtraNonce = 0;
        IncrementExtraNonce(&block, parent, nExtraNonce);
        block.nNonce = 0;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()))
            ++block.nNonce;
        return block;
    }

    /** ProcessNewBlock; returns the block's index entry. */
    CBlockIndex* Submit(const CBlock& block, bool fForceProcessing = true, bool* pfNewBlock = nullptr)
    {
        bool fNewBlock = false;
        BOOST_CHECK(ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), fForceProcessing, &fNewBlock));
        if (pfNewBlock) *pfNewBlock = fNewBlock;
        LOCK(cs_main);
        BlockMap::iterator it = mapBlockIndex.find(block.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        return it->second;
    }

    static CScript Script(unsigned char n)
    {
        return CScript() << std::vector<unsigned char>(33, n) << OP_CHECKSIG;
    }

    static CBlockIndex* Tip()
    {
        LOCK(cs_main);
        return chainActive.Tip();
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(chain_trust_fork_choice_tests)

/* AddToBlockIndex (validation.cpp:2934): bnChainTrust = pprev's +
 * GetBlockTrust() for real blocks accepted by ProcessNewBlock. */
BOOST_FIXTURE_TEST_CASE(chain_trust_real_blocks, RegtestConsensusSetup)
{
    CBlockIndex* genesis = Tip();
    BOOST_CHECK_EQUAL(genesis->nHeight, 0);
    BOOST_CHECK(genesis->bnChainTrust == genesis->GetBlockTrust());
    BOOST_CHECK(genesis->bnChainTrust == 1);

    for (int i = 0; i < 4; ++i) {
        CBlockIndex* prev = Tip();
        CBlockIndex* pindex = Submit(MineBlock(prev, Script(1)));
        BOOST_CHECK(Tip() == pindex);
        BOOST_CHECK(pindex->pprev == prev);
        BOOST_CHECK(pindex->GetBlockTime() >= CONSECUTIVE_STAKE_SWITCH_TIME);
        BOOST_CHECK(pindex->GetBlockTrust() == PowLimit() / Target(pindex->nBits));
        BOOST_CHECK(pindex->GetBlockTrust() > 0);
        BOOST_CHECK(pindex->bnChainTrust == prev->bnChainTrust + pindex->GetBlockTrust());
        BOOST_TEST_MESSAGE("regtest block " << pindex->nHeight << " nBits " << strprintf("%08x", pindex->nBits)
                           << " trust " << pindex->GetBlockTrust().ToString() << " chain trust " << pindex->bnChainTrust.ToString());
    }
}

/* Fork choice (CBlockIndexWorkComparator, validation.cpp:112-131): more chain
 * trust wins; with equal trust the block received first (lower nSequenceId)
 * stays the tip. AcceptBlock (validation.cpp:3457) stores an unrequested
 * block only if its chain trust is >= the tip's. */
BOOST_FIXTURE_TEST_CASE(fork_choice_by_trust, RegtestConsensusSetup)
{
    for (int i = 0; i < 2; ++i)
        Submit(MineBlock(Tip(), Script(1)));
    CBlockIndex* parent = Tip();

    const CBlock blockA3 = MineBlock(parent, Script(0xa));
    const CBlock blockB3 = MineBlock(parent, Script(0xb));
    BOOST_REQUIRE(blockA3.GetHash() != blockB3.GetHash());

    CBlockIndex* a3 = Submit(blockA3);
    BOOST_CHECK(Tip() == a3);
    CBlockIndex* b3 = Submit(blockB3);
    BOOST_REQUIRE(a3->bnChainTrust == b3->bnChainTrust);
    BOOST_CHECK(b3->nStatus & BLOCK_HAVE_DATA);
    BOOST_CHECK(a3->nSequenceId < b3->nSequenceId);
    BOOST_CHECK(Tip() == a3); // equal trust: the first received stays

    // One more block on B: more trust, reorg to B.
    CBlockIndex* b4 = Submit(MineBlock(b3, Script(0xb)));
    BOOST_CHECK(b4->bnChainTrust > a3->bnChainTrust);
    BOOST_CHECK(Tip() == b4);

    // A catches up to equal trust: B stays.
    CBlockIndex* a4 = Submit(MineBlock(a3, Script(0xa)));
    BOOST_REQUIRE(a4->bnChainTrust == b4->bnChainTrust);
    BOOST_CHECK(Tip() == b4);

    // A overtakes: reorg back to A.
    CBlockIndex* a5 = Submit(MineBlock(a4, Script(0xa)));
    BOOST_CHECK(Tip() == a5);

    // Unrequested blocks (fForceProcessing = false): less trust than the
    // tip is not stored, equal trust is stored (and does not reorg).
    bool fNewBlock = true;
    CBlockIndex* c3 = Submit(MineBlock(parent, Script(0xc)), false, &fNewBlock);
    BOOST_CHECK(c3->bnChainTrust < a5->bnChainTrust);
    BOOST_CHECK(!fNewBlock);
    BOOST_CHECK(!(c3->nStatus & BLOCK_HAVE_DATA));
    BOOST_CHECK(Tip() == a5);

    CBlockIndex* b5 = Submit(MineBlock(b4, Script(0xb)), false, &fNewBlock);
    BOOST_REQUIRE(b5->bnChainTrust == a5->bnChainTrust);
    BOOST_CHECK(fNewBlock);
    BOOST_CHECK(b5->nStatus & BLOCK_HAVE_DATA);
    BOOST_CHECK(Tip() == a5);
}

/* Fork choice with real PoS blocks (review C8), made by the synthetic PoS
 * generator (P0-55) on a pre-fork regtest chain (PoW trust T = 1 there:
 * powLimit 2^255 - 1 over target 0x207fffff). A PoS block on the fork point
 * has the PoW sibling's trust + 1 (chain.cpp:96-97), so it wins although
 * it arrived later; PoW on top of it is doubled, giving T + 1 more than the
 * PoW-only fork. The PoW fork needs three more blocks to take over: at
 * equal trust the current tip stays, one more reorganises back and
 * disconnects the PoS block (its stake is unspent again). */
BOOST_FIXTURE_TEST_CASE(fork_choice_with_pos_blocks, synthetic_pos::PosChainSetup)
{
    CBlockIndex* base = MinePowChain(505);
    {
        LOCK(cs_main);
        SeedProofOfStakeHistory(chainActive[2], chainActive[3]);
    }
    const CBigNum T = PowLimit() / Target(base->nBits);
    BOOST_CHECK(T == 1);
    BOOST_CHECK(base->GetBlockTrust() == T);
    auto Tip = []() { LOCK(cs_main); return chainActive.Tip(); };

    CBlockIndex* a1 = Submit(MinePowBlock(base, base->GetBlockTime() + 60, 0xa));
    BOOST_REQUIRE(a1 != nullptr);
    BOOST_CHECK(Tip() == a1);

    const COutPoint stake = CoinbaseOutPoint(1);
    const CBlock blockB1 = GeneratePosBlock(base, stake, 0xb);
    CBlockIndex* b1 = Submit(blockB1);
    BOOST_REQUIRE(b1 != nullptr);
    BOOST_CHECK(b1->IsProofOfStake());
    BOOST_CHECK(b1->bnChainTrust - a1->bnChainTrust == 1);
    BOOST_CHECK(a1->nSequenceId < b1->nSequenceId);
    BOOST_CHECK(Tip() == b1); // reorg to the PoS fork
    {
        LOCK(cs_main);
        BOOST_CHECK(!pcoinsTip->HaveCoin(stake));
    }

    CBlockIndex* a2 = Submit(MinePowBlock(a1, a1->GetBlockTime() + 60, 0xa));
    CBlockIndex* b2 = Submit(MinePowBlock(b1, b1->GetBlockTime() + 60, 0xb));
    BOOST_REQUIRE(a2 != nullptr && b2 != nullptr);
    BOOST_CHECK(b2->GetBlockTrust() == T * 2);
    BOOST_CHECK(b2->bnChainTrust - a2->bnChainTrust == T + 1);
    BOOST_CHECK(Tip() == b2);

    CBlockIndex* a3 = Submit(MinePowBlock(a2, a2->GetBlockTime() + 60, 0xa));
    CBlockIndex* a4 = Submit(MinePowBlock(a3, a3->GetBlockTime() + 60, 0xa));
    BOOST_REQUIRE(a4 != nullptr);
    BOOST_CHECK(a4->bnChainTrust == b2->bnChainTrust);
    BOOST_CHECK(Tip() == b2); // equal trust: the earlier block stays

    CBlockIndex* a5 = Submit(MinePowBlock(a4, a4->GetBlockTime() + 60, 0xa));
    BOOST_REQUIRE(a5 != nullptr);
    BOOST_CHECK(Tip() == a5);
    LOCK(cs_main);
    BOOST_CHECK(!chainActive.Contains(b1));
    BOOST_CHECK(pcoinsTip->HaveCoin(stake));
    BOOST_CHECK(!pcoinsTip->HaveCoin(COutPoint(blockB1.vtx[1].GetHash(), 1)));
}

/* What the regtest cases above and the P2P cases below rely on from
 * TestingSetup (P0-62): an in-memory token database, fresh for every fixture
 * and reset to null when the fixture ends, and a test CConnman whose send
 * buffer limit is the node's default (1000 * DEFAULT_MAXSENDBUFFER bytes),
 * so queuing a message does not pause the peer. No fixture: the case builds
 * its own. */
BOOST_AUTO_TEST_CASE(testingsetup_token_db_and_buffers)
{
    const std::pair<char, std::string> key('Z', "P0-62 test key");
    BOOST_REQUIRE(ptokensdb == nullptr);
    {
        TestingSetup setup(CBaseChainParams::REGTEST);
        BOOST_REQUIRE(ptokensdb != nullptr);
        BOOST_REQUIRE(g_connman);
        BOOST_CHECK(!ptokensdb->Exists(key));
        BOOST_CHECK(ptokensdb->Write(key, 42));
        int nValue = 0;
        BOOST_CHECK(ptokensdb->Read(key, nValue));
        BOOST_CHECK_EQUAL(nValue, 42);

        CNode node(1, ServiceFlags(NODE_NETWORK), 0, INVALID_SOCKET, CAddress(CService(CNetAddr(), Params().GetDefaultPort()), NODE_NONE), 0, 0, CAddress(), "", /*fInboundIn=*/false);
        node.SetSendVersion(PROTOCOL_VERSION);
        const CNetMsgMaker msgMaker(PROTOCOL_VERSION);
        g_connman->PushMessage(&node, msgMaker.Make(NetMsgType::PING, uint64_t(1)));
        BOOST_CHECK(!node.fPauseSend);
        // Exactly at the limit the peer is not paused; any further message
        // pauses it (net.cpp PushMessage: nSendSize > nSendBufferMaxSize).
        const size_t nLimit = 1000 * DEFAULT_MAXSENDBUFFER;
        size_t nFill;
        {
            LOCK(node.cs_vSend);
            BOOST_REQUIRE(node.nSendSize + CMessageHeader::HEADER_SIZE < nLimit);
            nFill = nLimit - node.nSendSize - CMessageHeader::HEADER_SIZE;
        }
        CSerializedNetMsg fill;
        fill.command = NetMsgType::PING;
        fill.data.assign(nFill, 0);
        g_connman->PushMessage(&node, std::move(fill));
        {
            LOCK(node.cs_vSend);
            BOOST_CHECK_EQUAL(node.nSendSize, nLimit);
        }
        BOOST_CHECK(!node.fPauseSend);
        CSerializedNetMsg empty;
        empty.command = NetMsgType::PING;
        g_connman->PushMessage(&node, std::move(empty));
        BOOST_CHECK(node.fPauseSend);
    }
    BOOST_CHECK(ptokensdb == nullptr);
    BOOST_CHECK(!g_connman);
    {
        TestingSetup setup(CBaseChainParams::REGTEST);
        BOOST_REQUIRE(ptokensdb != nullptr);
        BOOST_CHECK(!ptokensdb->Exists(key)); // the previous fixture's data is gone
    }
    BOOST_CHECK(ptokensdb == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// net_processing.cpp trust comparisons, driven through a test peer.
// ---------------------------------------------------------------------------

namespace {

/** An outbound test peer registered with peerLogic and g_connman. The
 *  destructor finalises it (node state, blocks in flight), so it must be
 *  destroyed before the TestChain whose entries it references. Only one
 *  TestPeer may exist at a time: the destructor empties g_connman's node
 *  list (CConnmanTest::ClearNodes). */
class TestPeer {
public:
    TestPeer(PeerLogicValidation& logicIn, NodeId id)
        : logic(logicIn),
          node(id, ServiceFlags(NODE_NETWORK), 0, INVALID_SOCKET, CAddress(CService(CNetAddr(), Params().GetDefaultPort()), NODE_NONE), 0, 0, CAddress(), "", /*fInboundIn=*/false)
    {
        node.SetSendVersion(PROTOCOL_VERSION);
        logic.InitializeNode(&node);
        node.nVersion = PROTOCOL_VERSION;
        node.nStartingHeight = 1;
        node.fSuccessfullyConnected = true;
        CConnmanTest::AddNode(node);
        ClearSent(); // the "version" message InitializeNode queued
    }
    ~TestPeer()
    {
        CConnmanTest::ClearNodes();
        bool fUpdateConnectionTime = false;
        logic.FinalizeNode(node.GetId(), fUpdateConnectionTime);
    }
    TestPeer(const TestPeer&) = delete;
    TestPeer& operator=(const TestPeer&) = delete;

    /** Deliver one message as if received from the peer and process it. */
    void Receive(const CSerializedNetMsg& msg)
    {
        CMessageHeader hdr(msg.command.c_str(), msg.data.size());
        const uint256 hash = Hash(msg.data.begin(), msg.data.end());
        memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);
        std::vector<unsigned char> vHeader;
        CVectorWriter{SER_NETWORK, INIT_PROTO_VERSION, vHeader, 0, hdr};

        CNetMessage netmsg(Params().MessageStart(), SER_NETWORK, INIT_PROTO_VERSION);
        BOOST_REQUIRE_EQUAL(netmsg.readHeader((const char*)vHeader.data(), vHeader.size()), (int)vHeader.size());
        if (!msg.data.empty()) {
            BOOST_REQUIRE_EQUAL(netmsg.readData((const char*)msg.data.data(), msg.data.size()), (int)msg.data.size());
        }
        BOOST_REQUIRE(netmsg.complete());
        {
            LOCK(node.cs_vProcessMsg);
            node.nProcessQueueSize += netmsg.vRecv.size() + CMessageHeader::HEADER_SIZE;
            node.vProcessMsg.push_back(std::move(netmsg));
        }
        // ProcessMessages skips the queue while fPauseSend is set. TestingSetup
        // gives the test CConnman the node's send buffer limit (P0-62), so
        // the few messages a test peer queues never set it.
        BOOST_REQUIRE(!node.fPauseSend);
        std::atomic<bool> interrupt(false);
        logic.ProcessMessages(&node, interrupt);
        BOOST_CHECK(node.vProcessMsg.empty());
    }

    /** The peer announces a block with an "inv". */
    void AnnounceInv(const uint256& hash)
    {
        Receive(CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::INV, std::vector<CInv>{CInv(MSG_BLOCK, hash)}));
    }

    void Send()
    {
        std::atomic<bool> interrupt(false);
        logic.SendMessages(&node, interrupt);
    }

    /** Number of queued outgoing messages with this command. vSendMsg holds
     *  each header, followed by its payload when that is not empty. */
    int CountSent(const std::string& command)
    {
        LOCK(node.cs_vSend);
        int n = 0;
        bool fPayloadNext = false;
        for (const std::vector<unsigned char>& v : node.vSendMsg) {
            if (fPayloadNext) {
                fPayloadNext = false;
                continue;
            }
            BOOST_REQUIRE_EQUAL(v.size(), (size_t)CMessageHeader::HEADER_SIZE);
            CMessageHeader hdr;
            CDataStream(v, SER_NETWORK, INIT_PROTO_VERSION) >> hdr;
            if (hdr.GetCommand() == command) ++n;
            fPayloadNext = hdr.nMessageSize > 0;
        }
        return n;
    }

    /** Forget the queued outgoing messages, as if the socket had sent them
     *  (net.cpp SocketSendData/ThreadSocketHandler also recompute
     *  fPauseSend then). */
    void ClearSent()
    {
        LOCK(node.cs_vSend);
        node.vSendMsg.clear();
        node.nSendSize = 0;
        node.fPauseSend = false;
    }

    CNodeStateStats Stats() const
    {
        CNodeStateStats stats;
        BOOST_REQUIRE(GetNodeStateStats(node.GetId(), stats));
        return stats;
    }

    /** Height of the peer's best known block (pindexBestKnownBlock), -1 if
     *  there is none. */
    int SyncHeight() const { return Stats().nSyncHeight; }

    PeerLogicValidation& logic;
    CNode node;
};

NodeId g_nNextPeerId = 1000;

/** P2P cases on main params: synthetic entries on the real genesis. The P2P
 *  code only reads bnChainTrust (and the tree), so the cases set it directly
 *  on their own entries to get the ordering they need. */
struct TrustP2PSetup : public ConsensusTestingSetup {
    CBlockIndex* genesis;
    TrustP2PSetup()
    {
        genesis = chain.StartOnExistingGenesis();
        globals.SetMockTime(GetTime());
    }
    /** Entry on prev with the given chain trust; hash null = synthetic. */
    CBlockIndex* Add(CBlockIndex* prev, int64_t nTrust, const uint256& hash = uint256())
    {
        BlockSpec spec(NEW_RULES_TIME + 60 * (prev->nHeight + 1), NBITS_1D00FFFF);
        spec.hash = hash;
        CBlockIndex* p = chain.Append(prev, spec);
        p->bnChainTrust = CBigNum(nTrust);
        return p;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(chain_trust_p2p_tests, TrustP2PSetup)

/* UpdateBlockAvailability / ProcessBlockAvailability
 * (net_processing.cpp:432-461) on "inv": a known block with chain trust > 0
 * becomes the peer's best known block if its trust is >= the current one; a
 * block with trust 0 or an unknown hash is remembered as "last unknown" and
 * adopted with the next announcement once it is known with trust > 0 and >=
 * the best one; if its trust is lower then, it is dropped for good. */
BOOST_AUTO_TEST_CASE(p2p_block_availability_by_trust)
{
    CBlockIndex* a1 = Add(genesis, 100);
    CBlockIndex* a2 = Add(a1, 200);
    CBlockIndex* a3 = Add(a2, 300);
    CBlockIndex* b1 = Add(genesis, 50);
    CBlockIndex* b2 = Add(b1, 300); // same trust as a3, height 2
    CBlockIndex* zero = Add(genesis, 0);

    TestPeer peer(*peerLogic, g_nNextPeerId++);
    BOOST_CHECK_EQUAL(peer.SyncHeight(), -1);

    peer.AnnounceInv(a2->GetBlockHash());
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 2);
    peer.AnnounceInv(a1->GetBlockHash()); // less trust: ignored
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 2);
    peer.AnnounceInv(a3->GetBlockHash()); // more
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 3);
    peer.AnnounceInv(b2->GetBlockHash()); // equal trust (>=): replaces
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 2);
    peer.AnnounceInv(a3->GetBlockHash()); // equal again: back
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 3);

    // Chain trust 0 counts as unknown.
    peer.AnnounceInv(zero->GetBlockHash());
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 3);
    zero->bnChainTrust = CBigNum(400);
    peer.AnnounceInv(b1->GetBlockHash()); // ProcessBlockAvailability adopts zero; b1 is lower
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 1);

    // Unknown hash, later known with more trust: adopted with the next inv.
    const uint256 hashLater = uint256S("c0ffee01");
    peer.AnnounceInv(hashLater);
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 1);
    Add(a3, 500, hashLater); // height 4
    peer.AnnounceInv(a1->GetBlockHash());
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 4);

    // Unknown hash, later known with less trust: dropped, also when its
    // trust rises afterwards.
    const uint256 hashLow = uint256S("c0ffee02");
    peer.AnnounceInv(hashLow);
    CBlockIndex* low = Add(a2, 450, hashLow); // height 3
    peer.AnnounceInv(a1->GetBlockHash());
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 4);
    low->bnChainTrust = CBigNum(600);
    peer.AnnounceInv(a1->GetBlockHash());
    BOOST_CHECK_EQUAL(peer.SyncHeight(), 4);
}

/* FindNextBlocksToDownload (net_processing.cpp:536): blocks are requested
 * from a peer only if its best known block has chain trust >= our tip's;
 * equal is enough. */
BOOST_AUTO_TEST_CASE(p2p_download_by_trust)
{
    CBlockIndex* a1 = Add(genesis, 100);
    CBlockIndex* a2 = Add(a1, 200);
    CBlockIndex* b1 = Add(genesis, 150);
    CBlockIndex* b2 = Add(b1, 199);
    CBlockIndex* b3 = Add(b2, 200);
    chain.SetActiveTip(a2);

    TestPeer peer(*peerLogic, g_nNextPeerId++);
    peer.AnnounceInv(b2->GetBlockHash()); // 199 < 200
    peer.Send();
    BOOST_CHECK(peer.Stats().vHeightInFlight.empty());
    BOOST_CHECK_EQUAL(peer.CountSent(NetMsgType::GETDATA), 0);

    peer.AnnounceInv(b3->GetBlockHash()); // 200 == 200
    peer.ClearSent();
    peer.Send();
    std::vector<int> vHeights = peer.Stats().vHeightInFlight;
    std::sort(vHeights.begin(), vHeights.end());
    BOOST_CHECK(vHeights == std::vector<int>({1, 2, 3}));
    BOOST_CHECK_EQUAL(peer.CountSent(NetMsgType::GETDATA), 1);
}

/* ConsiderEviction (net_processing.cpp:3099-3149) for an outbound peer: best
 * known chain trust >= our tip's → no timeout; lower → one getheaders after
 * CHAIN_SYNC_TIMEOUT and a disconnect 120 s later; a peer that reaches the
 * trust of the tip it was compared with (m_work_header) gets a new timeout
 * against the current tip. */
BOOST_AUTO_TEST_CASE(p2p_eviction_by_trust)
{
    CBlockIndex* a1 = Add(genesis, 100);
    CBlockIndex* a2 = Add(a1, 200);
    CBlockIndex* a3 = Add(a2, 300);
    CBlockIndex* b1 = Add(genesis, 150);
    CBlockIndex* b2 = Add(b1, 200);
    chain.SetActiveTip(a2);
    const int64_t t0 = GetTime(); // mock time

    auto consider = [this](TestPeer& peer, int64_t t) {
        LOCK(cs_main);
        peerLogic->ConsiderEviction(&peer.node, t);
    };

    {
        // Equal trust: no timeout.
        TestPeer peer(*peerLogic, g_nNextPeerId++);
        peer.AnnounceInv(b2->GetBlockHash()); // 200 == tip
        peer.Send();                          // starts the sync, ConsiderEviction(t0)
        peer.ClearSent();
        consider(peer, t0 + CHAIN_SYNC_TIMEOUT + 1);
        consider(peer, t0 + 24 * 60 * 60);
        BOOST_CHECK_EQUAL(peer.CountSent(NetMsgType::GETHEADERS), 0);
        BOOST_CHECK(!peer.node.fDisconnect);
    }
    {
        // Lower trust: getheaders after the timeout, then disconnect.
        TestPeer peer(*peerLogic, g_nNextPeerId++);
        peer.AnnounceInv(b1->GetBlockHash()); // 150 < 200
        peer.Send();                          // timeout t0 + CHAIN_SYNC_TIMEOUT
        peer.ClearSent();
        consider(peer, t0 + CHAIN_SYNC_TIMEOUT);
        BOOST_CHECK_EQUAL(peer.CountSent(NetMsgType::GETHEADERS), 0);
        consider(peer, t0 + CHAIN_SYNC_TIMEOUT + 1);
        BOOST_CHECK_EQUAL(peer.CountSent(NetMsgType::GETHEADERS), 1);
        BOOST_CHECK(!peer.node.fDisconnect);
        consider(peer, t0 + CHAIN_SYNC_TIMEOUT + 1 + 121);
        BOOST_CHECK(peer.node.fDisconnect);
    }
    {
        // Behind, then reaches the work header's trust (a2, 200) while our
        // tip has moved on to a3: a new timeout from that moment.
        TestPeer peer(*peerLogic, g_nNextPeerId++);
        peer.AnnounceInv(b1->GetBlockHash()); // 150 < 200
        peer.Send();                          // timeout t0 + CHAIN_SYNC_TIMEOUT, work header a2
        chain.SetActiveTip(a3);
        peer.AnnounceInv(b2->GetBlockHash()); // 200 == work header, < tip 300
        consider(peer, t0 + 10);              // timeout t0 + 10 + CHAIN_SYNC_TIMEOUT
        peer.ClearSent();
        consider(peer, t0 + CHAIN_SYNC_TIMEOUT + 1);
        BOOST_CHECK_EQUAL(peer.CountSent(NetMsgType::GETHEADERS), 0);
        consider(peer, t0 + 10 + CHAIN_SYNC_TIMEOUT + 1);
        BOOST_CHECK_EQUAL(peer.CountSent(NetMsgType::GETHEADERS), 1);
        BOOST_CHECK(!peer.node.fDisconnect);
    }
}

BOOST_AUTO_TEST_SUITE_END()
