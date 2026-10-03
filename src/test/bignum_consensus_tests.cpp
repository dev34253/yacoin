// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// CBigNum values above 256 bits and negative intermediates in the consensus
// expressions, task P0-12 (plan 0.2a, review B1/B10).
//
// arith_uint256 cannot hold these values, so whatever replaces CBigNum in
// Phase 4 needs more than 256 bits (or signed values) exactly here:
// - stake kernel  kernel.cpp:457-461,526,568: coin-day weight (negative when
//   txPrev.nTime > nTimeTx - nStakeMinAge) and weight * target (~2^264);
// - legacy PoS block trust  chain.cpp:114: (1 << 256) / (target + 1);
// - pre-fork PoW reward  validation.cpp:935-977: bisection products
//   mid^6 * targetLimit and limit^6 * target (~400 bits).
//
// Each helper below is a verbatim copy of the production expression (same
// operand order, same implicit conversions), so the tests pin CBigNum on
// exactly the values these expressions reach. The functions themselves are
// pinned by P0-18 (CheckStakeKernelHash), P0-16 (GetBlockTrust) and P0-46
// (GetProofOfWorkReward golden table); the reward helper is cross-checked
// against GetProofOfWorkReward here because unit tests can call it without
// chain state.
//
// Expected values are literals computed independently with Python integers
// (truncating division), never with CBigNum; the script is in the P0-12 task
// file. Like bignum_tests.cpp these tests call the CBigNum API directly and
// are retired in Phase 4; the durable artefacts are P0-13's golden vectors.

#include "amount.h"
#include "bignum.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "main.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <algorithm>
#include <stdint.h>
#include <string>

#include <boost/test/unit_test.hpp>

/** validation.cpp:942-977 without fees, logging and the post-fork branch;
 *  bnTargetLimit is the already round-tripped compact powLimit. Not in the
 *  anonymous namespace: reward_tests.cpp (P0-46) uses it for the target
 *  limit of the other build configuration. */
int64_t RewardBisection(uint32_t nBits, uint32_t nTargetLimitCompact)
{
    CBigNum bnSubsidyLimit = MAX_MINT_PROOF_OF_WORK;
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    CBigNum bnTargetLimit;
    bnTargetLimit.SetCompact(nTargetLimitCompact);

    CBigNum bnLowerBound = CENT;
    CBigNum bnUpperBound = bnSubsidyLimit;
    while (bnLowerBound + CENT <= bnUpperBound)
    {
        CBigNum bnMidValue = (bnLowerBound + bnUpperBound) / 2;
        if (bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue *
                bnMidValue * bnTargetLimit >
            bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit *
                bnSubsidyLimit * bnSubsidyLimit * bnTarget)
            bnUpperBound = bnMidValue;
        else
            bnLowerBound = bnMidValue;
    }
    int64_t nSubsidy = bnUpperBound.getuint64();
    nSubsidy = (nSubsidy / CENT) * CENT;
    return std::min(nSubsidy, MAX_MINT_PROOF_OF_WORK);
}

BOOST_FIXTURE_TEST_SUITE(bignum_consensus_tests, BasicTestingSetup)

namespace {

const int64_t DAY = 24 * 60 * 60;
const int64_t STAKE_MIN_AGE = 30 * DAY; // chainparams.cpp nStakeMinAge
const int64_t STAKE_MAX_AGE = 90 * DAY; // chainparams.cpp nStakeMaxAge

CBigNum Target(uint32_t nBits)
{
    CBigNum bn;
    bn.SetCompact(nBits);
    return bn;
}

/** kernel.cpp:457-461; nTimeWeight is the int64_t result of GetWeight(). */
CBigNum CoinDayWeight(int64_t nValueIn, int64_t nTimeWeight)
{
    return CBigNum(nValueIn) * nTimeWeight / COIN / (24 * 60 * 60);
}

/** chain.cpp:114 (PoS block before CONSECUTIVE_STAKE_SWITCH_TIME). */
CBigNum TrustShift(const CBigNum& bnTarget)
{
    return (CBigNum(1) << 256) / (bnTarget + 1);
}


/** x^6, written out like the production code. */
CBigNum Pow6(const CBigNum& x)
{
    return x * x * x * x * x * x;
}

const uint256 HASH_ZERO;
const uint256 HASH_ONE = uint256S("01");
const uint256 HASH_MAX = ~uint256();

} // namespace

/* The constants the helpers rely on. */
BOOST_AUTO_TEST_CASE(consensus_constants)
{
    BOOST_CHECK_EQUAL(COIN, 1000000);
    BOOST_CHECK_EQUAL(CENT, 10000);
    BOOST_CHECK_EQUAL(MAX_MONEY, 2000000000LL * COIN);
    BOOST_CHECK_EQUAL(MAX_MINT_PROOF_OF_WORK, 100 * COIN);
    BOOST_CHECK_EQUAL(Params().GetConsensus().nStakeMinAge, STAKE_MIN_AGE);
    BOOST_CHECK_EQUAL(Params().GetConsensus().nStakeMaxAge, STAKE_MAX_AGE);
}

/* kernel.cpp:458-461: CBigNum(nValueIn) * weight / COIN / 86400, two
 * truncating divisions. getuint64() of the weight is a hash input
 * (kernel.cpp:482). */
BOOST_AUTO_TEST_CASE(kernel_coin_day_weight)
{
    // Maximum: MAX_MONEY for 90 days. The intermediate MAX_MONEY * 7776000
    // has 74 bits, more than int64_t holds.
    CBigNum bnMax = CoinDayWeight(MAX_MONEY, STAKE_MAX_AGE);
    BOOST_CHECK_EQUAL(bnMax.ToString(), "180000000000");
    BOOST_CHECK_EQUAL(bnMax.GetHex(), "29e8d60800");
    BOOST_CHECK_EQUAL(bnMax.getuint64(), 180000000000ULL);
    BOOST_CHECK_EQUAL((CBigNum(MAX_MONEY) * STAKE_MAX_AGE).GetHex(), "34b135b21f8fb000000");

    // Truncation: one unit for 90 days is 7.776 / 86400 coin-days -> 0.
    BOOST_CHECK_EQUAL(CoinDayWeight(1, STAKE_MAX_AGE).ToString(), "0");
    BOOST_CHECK_EQUAL(CoinDayWeight(COIN, DAY).ToString(), "1");

    // Negative weight (txPrev.nTime > nTimeTx - nStakeMinAge; range
    // [-nStakeMinAge, 0)). pinned: division truncates toward zero, and
    // getuint64() returns the magnitude.
    CBigNum bnNeg = CoinDayWeight(5 * COIN, -3 * DAY);
    BOOST_CHECK_EQUAL(bnNeg.ToString(), "-15");
    BOOST_CHECK_EQUAL(bnNeg.getuint64(), 15U);
    BOOST_CHECK_EQUAL(CoinDayWeight(COIN, -1).ToString(), "0"); // truncates toward zero (floor would give -1)
    BOOST_CHECK(CoinDayWeight(COIN, -1) == CBigNum(0));
    BOOST_CHECK_EQUAL(CoinDayWeight(COIN, -DAY).ToString(), "-1");
    CBigNum bnMin = CoinDayWeight(MAX_MONEY, -STAKE_MIN_AGE);
    BOOST_CHECK_EQUAL(bnMin.ToString(), "-60000000000");
    BOOST_CHECK_EQUAL(bnMin.getuint64(), 60000000000ULL);
    // 1 COIN for one second less than a day: -86399000000 / 1000000 = -86399,
    // / 86400 = 0
    BOOST_CHECK_EQUAL(CoinDayWeight(COIN, -DAY + 1).ToString(), "0");
}

/* kernel.cpp:526 compares the hash with the full product; kernel.cpp:568
 * returns targetProofOfStake = product.getuint256(), i.e. mod 2^256. */
BOOST_AUTO_TEST_CASE(kernel_target_product_over_256_bits)
{
    const CBigNum bnWeight = CoinDayWeight(MAX_MONEY, STAKE_MAX_AGE);

    // PoS hard limit (pow.cpp:21, ~uint256(0) >> 30), compact 0x1d03ffff.
    BOOST_CHECK_EQUAL(CBigNum(~uint256() >> 30).GetCompact(), 0x1d03ffffU);
    const CBigNum bnHard = Target(0x1d03ffff);
    BOOST_CHECK_EQUAL(bnHard.GetHex(), "3ffff" + std::string(52, '0'));
    const CBigNum bnProdHard = bnWeight * bnHard; // 264 bits
    BOOST_CHECK_EQUAL(bnProdHard.GetHex(), "a7a32e3729f8" + std::string(54, '0'));
    // pinned: getuint256() keeps the low 256 bits (drops the leading "a7").
    BOOST_CHECK_EQUAL(bnProdHard.getuint256().GetHex(), "a32e3729f8" + std::string(54, '0'));

    // Mainnet powLimit compact 0x1e0fffff: 274 bits.
    const CBigNum bnProdPow = bnWeight * Target(0x1e0fffff);
    BOOST_CHECK_EQUAL(bnProdPow.GetHex(), "29e8d369729f8" + std::string(56, '0'));
    BOOST_CHECK_EQUAL(bnProdPow.getuint256().GetHex(), "369729f8" + std::string(56, '0'));

    // Full precision (kernel.cpp:526): even the largest hash meets the target.
    BOOST_CHECK(!(CBigNum(HASH_MAX) > bnProdHard));
    BOOST_CHECK(!(CBigNum(HASH_MAX) > bnProdPow));
    // pinned: the truncated targetProofOfStake (kernel.cpp:568) is smaller
    // than that hash, so a caller comparing with it would disagree.
    BOOST_CHECK(CBigNum(HASH_MAX) > CBigNum(bnProdHard.getuint256()));
    BOOST_CHECK(CBigNum(HASH_MAX) > CBigNum(bnProdPow.getuint256()));
}

/* A negative or zero weight makes the product <= 0 (kernel.cpp:526). */
BOOST_AUTO_TEST_CASE(kernel_negative_weight_product)
{
    const CBigNum bnTarget = Target(0x1d03ffff);
    const CBigNum bnNegProd = CoinDayWeight(5 * COIN, -3 * DAY) * bnTarget;
    BOOST_CHECK_EQUAL(bnNegProd.GetHex(), "-3bfff1" + std::string(52, '0'));
    BOOST_CHECK(bnNegProd < 0);
    // Every hash, including 0, is greater: the kernel is rejected.
    BOOST_CHECK(CBigNum(HASH_ZERO) > bnNegProd);
    BOOST_CHECK(CBigNum(HASH_MAX) > bnNegProd);
    // pinned: getuint256() of the negative product is its magnitude.
    BOOST_CHECK_EQUAL(bnNegProd.getuint256().GetHex(), "0000003bfff1" + std::string(52, '0'));

    // Weight truncated to 0: product 0; only a hash of exactly 0 passes.
    const CBigNum bnZeroProd = CoinDayWeight(COIN, -1) * bnTarget;
    BOOST_CHECK(bnZeroProd == CBigNum(0));
    BOOST_CHECK(!(CBigNum(HASH_ZERO) > bnZeroProd));
    BOOST_CHECK(CBigNum(HASH_ONE) > bnZeroProd);
}

/* chain.cpp:114: (1 << 256) / (target + 1). Targets <= 0 never get here
 * (chain.cpp:79-80), so the result is at most 2^255. */
BOOST_AUTO_TEST_CASE(trust_shift_over_256_bits)
{
    const CBigNum bnTwo256 = CBigNum(1) << 256; // 257 bits
    BOOST_CHECK_EQUAL(bnTwo256.GetHex(), "1" + std::string(64, '0'));
    BOOST_CHECK(bnTwo256.getuint256() == uint256()); // pinned: mod 2^256

    BOOST_CHECK_EQUAL(TrustShift(Target(0x01010000)).GetHex(), "8" + std::string(63, '0')); // target 1
    BOOST_CHECK_EQUAL(TrustShift(Target(0x1d03ffff)).GetHex(), "40001000");
    BOOST_CHECK_EQUAL(TrustShift(Target(0x1e0fffff)).GetHex(), "100001");
    BOOST_CHECK_EQUAL(TrustShift(Target(0x201fffff)).GetHex(), "8");
    BOOST_CHECK_EQUAL(TrustShift(Target(0x207fffff)).GetHex(), "2");
    BOOST_CHECK_EQUAL(TrustShift(Target(0x2100ffff)).GetHex(), "1");
    // Compact targets of 2^256 and more give no trust.
    BOOST_CHECK_EQUAL(Target(0x21010000).GetHex(), "1" + std::string(64, '0'));
    BOOST_CHECK_EQUAL(TrustShift(Target(0x21010000)).GetHex(), "0");

    // Accumulated trust (bnChainTrust) can pass 2^256: GetHex() prints it
    // in full (RPC chaintrust), getuint256() (GetBlockProofEquivalentTime)
    // and getuint64() (gettimechaininfo) truncate.
    CBigNum bnChain = TrustShift(Target(0x01010000)) + TrustShift(Target(0x01010000)) + 5;
    BOOST_CHECK_EQUAL(bnChain.GetHex(), "1" + std::string(63, '0') + "5");
    BOOST_CHECK_EQUAL(bnChain.getuint256().GetHex(), std::string(63, '0') + "5");
    BOOST_CHECK_EQUAL(bnChain.getuint64(), 5U);
}

/* validation.cpp:958-961: mid^6 * targetLimit > limit^6 * target. */
BOOST_AUTO_TEST_CASE(reward_bisection_products)
{
    const CBigNum bnLimit = MAX_MINT_PROOF_OF_WORK;
    BOOST_CHECK_EQUAL(Pow6(bnLimit).GetHex(), "af298d050e4395d69670b12b7f41" + std::string(12, '0')); // 160 bits

    // limit^6 * target: 396 bits at the mainnet powLimit, 432 at 0x2300ffff.
    BOOST_CHECK_EQUAL((Pow6(bnLimit) * Target(0x1e0fffff)).GetHex(),
                      "af298212757344f25d1347c4742e480bf" + std::string(66, '0'));
    BOOST_CHECK_EQUAL((Pow6(bnLimit) * Target(0x2300ffff)).GetHex(),
                      "af28dddb813e8793009a1abace1580bf" + std::string(76, '0'));

    // mid^6 * targetLimit for both target limits (390 to 413 bits).
    const CBigNum bnMid50 = 50 * COIN;
    const CBigNum bnMid99 = 99 * COIN;
    BOOST_CHECK_EQUAL((Pow6(bnMid50) * Target(0x1e0fffff)).GetHex(),
                      "2bca60849d5cd13c9744d1f11d0b9202fc" + std::string(64, '0'));
    BOOST_CHECK_EQUAL((Pow6(bnMid99) * Target(0x1e0fffff)).GetHex(),
                      "a4e963c5fdba282e04fe06842e1cc82bedf7" + std::string(63, '0'));
    BOOST_CHECK_EQUAL((Pow6(bnMid50) * Target(0x201fffff)).GetHex(),
                      "5794c3c5e0edb6b23ce0fe3bfcdbd202fc" + std::string(68, '0'));
    BOOST_CHECK_EQUAL((Pow6(bnMid99) * Target(0x201fffff)).GetHex(),
                      "149d2d1da925599a5c11388c9b45de8bbedf7" + std::string(67, '0'));

    // Comparison results (true: the upper bound moves down).
    BOOST_CHECK(!(Pow6(bnMid50) * Target(0x1e0fffff) > Pow6(bnLimit) * Target(0x1e0fffff)));
    BOOST_CHECK(Pow6(bnMid50) * Target(0x1e0fffff) > Pow6(bnLimit) * Target(0x1d00ffff));
    BOOST_CHECK(!(Pow6(bnMid99) * Target(0x1e0fffff) > Pow6(bnLimit) * Target(0x1e0fffff)));
    BOOST_CHECK(Pow6(bnMid99) * Target(0x1e0fffff) > Pow6(bnLimit) * Target(0x1d00ffff));
    BOOST_CHECK(Pow6(bnMid50) * Target(0x201fffff) > Pow6(bnLimit) * Target(0x1e0fffff));
    // Equal products are not "greater" (target == targetLimit, mid == limit).
    BOOST_CHECK(!(Pow6(bnLimit) * Target(0x1e0fffff) > Pow6(bnLimit) * Target(0x1e0fffff)));

    // validation.cpp:940 round-trips powLimit through the compact form.
    CBigNum bnTargetLimit = Params().GetConsensus().powLimit;
    bnTargetLimit.SetCompact(bnTargetLimit.GetCompact());
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK(bnTargetLimit == Target(0x1e0fffff)); // powLimit ~uint256(0) >> 20
#else
    BOOST_CHECK(bnTargetLimit == Target(0x201fffff)); // powLimit ~uint256(0) >> 3
#endif
    BOOST_CHECK(bnTargetLimit < Params().GetConsensus().powLimit);
}

/* Result of the bisection for a table of nBits, with both target limits,
 * and GetProofOfWorkReward (pre-fork branch: height 0, unit-test globals
 * at 0) for the target limit of this build. */
BOOST_AUTO_TEST_CASE(reward_bisection_results)
{
    struct Row {
        uint32_t nBits;
        int64_t nMainnet; // target limit 0x1e0fffff
        int64_t nLowDiff; // target limit 0x201fffff
    };
    const Row rows[] = {
        {0x1e0fffff, 100000000, 14030000},
        {0x1d00ffff, 25000000, 3510000},
        {0x1c00ffff, 9920000, 1390000},
        {0x1b00ffff, 3940000, 550000},
        {0x1a00ffff, 1560000, 220000},
        {0x201fffff, 100000000, 100000000},
        {0x21010000, 100000000, 100000000}, // target 2^256
        {0x2300ffff, 100000000, 100000000}, // products of 432 bits
        {0x01010000, 10000, 10000},         // target 1: CENT
    };
    for (const Row& row : rows) {
        BOOST_CHECK_EQUAL(RewardBisection(row.nBits, 0x1e0fffff), row.nMainnet);
        BOOST_CHECK_EQUAL(RewardBisection(row.nBits, 0x201fffff), row.nLowDiff);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
        const int64_t nExpected = row.nMainnet;
#else
        const int64_t nExpected = row.nLowDiff;
#endif
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(row.nBits, 0, 0), nExpected);
    }
    // Fees are added after the min() with the limit.
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x201fffff, 7, 0), 100000007);
}

BOOST_AUTO_TEST_SUITE_END()
