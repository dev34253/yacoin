// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "pow.h"
#include "random.h"
#include "util.h"
#include "validation.h"
#include "test/consensus_harness.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, TestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    // Yacoin expected spacing: 1260000
    // Actual spacing: 1022578
    // => higher difficulty, lower target
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1e0fffff;

    // Retarget
    CBigNum bnNewTarget = CBigNum().SetCompact(pindexLast.nBits);
    ::int64_t nActualTimespan = pindexLast.nTime - nLastRetargetTime;
    ::int64_t nExpectedTimespan = nDifficultyInterval * chainParams->GetConsensus().nPowTargetSpacing;
    bnNewTarget *= nActualTimespan;
    bnNewTarget /= nExpectedTimespan;
    unsigned int retargetWork = bnNewTarget.GetCompact();

    unsigned int nextWork = CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus());
    BOOST_CHECK_EQUAL(nextWork, 0x1E0CFC2F);
    BOOST_CHECK(nextWork == retargetWork);
}

/* Test the constraint on the upper bound for next work (powLimit)
 *
 * The expected values depend on the build configuration because powLimit
 * does (chainparams.cpp):
 * - mainnet:        powLimit = ~uint256(0) >> 20, compact 0x1e0fffff
 * - low difficulty: powLimit = ~uint256(0) >> 3,  compact 0x201fffff
 *   (--enable-low-difficulty-for-development, LOW_DIFFICULTY_FOR_DEVELOPMENT)
 * Unit tests do not run AppInit, so nDifficultyInterval is 21000 (expected
 * timespan 21000 * 60 = 1260000 s), and the only block in chainActive is the
 * genesis block (nBits = powLimit), so the cap is powLimit in both builds.
 * Both builds pin their exact result; nothing is skipped (task P0-02).
 */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    const unsigned int nPowLimitCompact = chainParams->GetConsensus().powLimit.GetCompact();
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(nPowLimitCompact, 0x1e0fffffU);
#else
    BOOST_CHECK_EQUAL(nPowLimitCompact, 0x201fffffU);
#endif

    // Yacoin expected spacing: 1260000
    // Actual spacing: 2055491
    // => lower difficulty, higher target (retarget 0x1e0fffff * 2055491 / 1260000 = 0x1e1a19f8)
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1e0fffff;

    // Retarget
    CBigNum bnNewTarget = CBigNum().SetCompact(pindexLast.nBits);
    ::int64_t nActualTimespan = pindexLast.nTime - nLastRetargetTime;
    ::int64_t nExpectedTimespan = nDifficultyInterval * chainParams->GetConsensus().nPowTargetSpacing;
    bnNewTarget *= nActualTimespan;
    bnNewTarget /= nExpectedTimespan;
    unsigned int retargetWork = bnNewTarget.GetCompact();
    BOOST_CHECK_EQUAL(retargetWork, 0x1e1a19f8U);

    unsigned int nextWork = CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus());
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    // Mainnet: the retarget exceeds powLimit (0x1e0fffff)
    // => clamped, keep target
    BOOST_CHECK_EQUAL(nextWork, 0x1e0fffffU);
    BOOST_CHECK(nextWork < retargetWork);
#else
    // Low difficulty: powLimit (0x201fffff) is far above the retarget
    // => not clamped, the retarget is used as is
    BOOST_CHECK_EQUAL(nextWork, 0x1e1a19f8U);
    BOOST_CHECK(nextWork == retargetWork);

    // Exercise the powLimit clamp with the low-difficulty limit: start from
    // nBits = powLimit, so the same retarget exceeds powLimit
    // => clamped, keep target
    pindexLast.nBits = nPowLimitCompact;
    CBigNum bnLimitRetarget = CBigNum().SetCompact(pindexLast.nBits);
    bnLimitRetarget *= nActualTimespan;
    bnLimitRetarget /= nExpectedTimespan;
    unsigned int limitRetargetWork = bnLimitRetarget.GetCompact();

    unsigned int limitNextWork = CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus());
    BOOST_CHECK_EQUAL(limitNextWork, 0x201fffffU);
    BOOST_CHECK(limitNextWork < limitRetargetWork);
#endif
}

/* Test the constraint on the 1/3 highest difficulty */
BOOST_AUTO_TEST_CASE(get_next_work_one_third_highest_difficulty)
{
    // Create the chain with target 0000000000000000000000000000000000000fffff0000000000000000000000
    unsigned int highestDiff = 0xe0fffff;
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 9; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = highestDiff;
        blocks[i].bnChainTrust = i ? blocks[i - 1].bnChainTrust + blocks[i].GetBlockTrust() : 0;
    }
    chainActive.SetTip(&blocks[8]);

    // Yacoin expected spacing: 1260000
    // Actual spacing: 5040000
    // => lower difficulty, higher target, but the upper bound limit is 1/3 highest difficulty (0xe2ffffd)
    // => keep target
    int64_t nLastRetargetTime = 1269211443; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1274251443;  // Block #2015
    pindexLast.nBits = highestDiff;

    // Retarget
    CBigNum bnNewTarget = CBigNum().SetCompact(pindexLast.nBits);
    ::int64_t nActualTimespan = pindexLast.nTime - nLastRetargetTime;
    ::int64_t nExpectedTimespan = nDifficultyInterval * chainParams->GetConsensus().nPowTargetSpacing;
    bnNewTarget *= nActualTimespan;
    bnNewTarget /= nExpectedTimespan;
    unsigned int retargetWork = bnNewTarget.GetCompact();

    // Maximum target corresponding to 1/3 highest difficulty
    CBigNum bnMaximumTarget = CBigNum().SetCompact(highestDiff);
    bnMaximumTarget *= 3;
    unsigned int maximumWork = bnMaximumTarget.GetCompact();

    unsigned int nextWork = CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus());
    BOOST_CHECK_EQUAL(nextWork, 0xe2ffffd);
    BOOST_CHECK_EQUAL(nextWork, maximumWork);
    BOOST_CHECK(nextWork < retargetWork);
}

// ---------------------------------------------------------------------------
// Tests using the consensus harness (P0-47). They pin current behaviour; the
// full difficulty coverage is task P0-14.
// ---------------------------------------------------------------------------

/* Post-fork retarget at an epoch boundary: GetNextTargetRequired reads the
 * genesis block from disk (pow.cpp:174-176), and CalculateNextWorkRequired
 * scans chainActive and mapBlockIndex for nMinEase (pow.cpp:40-68). */
BOOST_FIXTURE_TEST_CASE(harness_post_fork_epoch_retarget, ConsensusTestingSetup)
{
    globals.UseUnitTestGlobals();   // fork at height 0: post-fork logic everywhere
    globals.SetEpochInterval(10);   // as in the functional tests
    const unsigned int nBits = 0x1d00ffff;
    CBlockIndex* genesis = chain.StartOnExistingGenesis();
    // Heights 1..9, 60 s apart: 540 s for a nominal 10 * 60 = 600 s.
    CBlockIndex* tip = chain.AppendMany(9, 60, nBits);
    chain.SetActiveTip(tip);
    BOOST_REQUIRE_EQUAL(tip->nHeight, 9);

    // Expected: target * 540 / 600; the 1/3-highest-difficulty cap
    // (3 * target of nMinEase = nBits) and powLimit do not apply.
    CBigNum bnExpected = CBigNum().SetCompact(nBits);
    bnExpected *= tip->GetBlockTime() - genesis->GetBlockTime();
    bnExpected /= 10 * Params().GetConsensus().nPowTargetSpacing;
    const unsigned int nNext = GetNextTargetRequired(tip, false);
    BOOST_CHECK_EQUAL(nNext, bnExpected.GetCompact());
    BOOST_CHECK_EQUAL(nNext, 0x1d00e665U);

    // Within an epoch the target stays (height 6 is not a boundary).
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(5), false), nBits);
}

/* Pre-fork: with the mainnet fork height the old per-block ppcoin retarget
 * (pow.cpp:184-203) is used, which unit tests never reach with the default
 * globals (review A4). */
BOOST_FIXTURE_TEST_CASE(harness_pre_fork_per_block_retarget, ConsensusTestingSetup)
{
    const Consensus::Params& params = Params().GetConsensus();
    const unsigned int nBits = 0x1d00ffff;
    globals.UseMainnetGlobals();
    CBlockIndex* genesis = chain.StartOnExistingGenesis();
    chain.AppendMany(3, 120, nBits);
    chain.SetActiveTip(chain.Tip());

    // First and second block after genesis: initialHashTarget.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(genesis, false), params.initialHashTarget.GetCompact());
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(1), false), params.initialHashTarget.GetCompact());

    // Then: target * ((nInterval - 1) * spacing + 2 * actual) / ((nInterval + 1) * spacing)
    // with spacing 60 s, nInterval = one week / 60 s = 10080 and actual 120 s.
    CBigNum bnExpected = CBigNum().SetCompact(nBits);
    bnExpected *= 10079 * 60 + 2 * 120;
    bnExpected /= 10081 * 60;
    const unsigned int nNext = GetNextTargetRequired(chain.Tip(), false);
    BOOST_CHECK_EQUAL(nNext, bnExpected.GetCompact());
    BOOST_CHECK_EQUAL(nNext, 0x1d01000cU);

    // With the unit-test globals the same chain takes the post-fork branch
    // and keeps the target (height 4 is not an epoch boundary).
    globals.UseUnitTestGlobals();
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.Tip(), false), nBits);
}

BOOST_AUTO_TEST_SUITE_END()
