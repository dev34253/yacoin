// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Difficulty (pow.cpp) on synthetic chains, pre- and post-fork (task P0-14).
//
// Every function in pow.cpp, built on the consensus harness (P0-47). The
// tests pin current behaviour, quirks included (CLAUDE.md rule 1); the
// quirks are listed in project/known-issues.md. Expected values come from a
// model with arith_uint256 (independent of CBigNum/OpenSSL) where it cannot
// overflow, and are pinned as compact hex as well. Values that depend on
// powLimit / initialHashTarget are pinned per build
// (LOW_DIFFICULTY_FOR_DEVELOPMENT), nothing is skipped.
//
// Not tested because the code has undefined behaviour or dereferences null
// there (documented in project/done/P0-14-pow-synthetic-chain-tests.md):
// a pindexLast whose phashBlock is not in mapBlockIndex (pow.cpp:57-58), the
// first post-fork retarget without a genesis in chainActive (pow.cpp:174-176)
// and a retarget window longer than the chain (pow.cpp:169-181, Yassert only
// logs in a release build).

#include "arith_uint256.h"
#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "pow.h"
#include "uint256.h"
#include "util.h"
#include "validation.h"
#include "test/consensus_harness.h"
#include "test/test_bitcoin.h"

#include <algorithm>

#include <boost/test/unit_test.hpp>

// Not declared in a header (pow.cpp:21, pow.cpp:255).
extern CBigNum bnProofOfStakeHardLimit;
unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime);

using namespace consensus_harness;

namespace {

// chainparams.cpp:78-83
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
const uint32_t POW_LIMIT = 0x1e0fffff;           // ~uint256(0) >> 20
const uint32_t INITIAL_HASH_TARGET = 0x1e0fffff; // ~uint256(0) >> 20
const uint32_t HALF_POW_LIMIT = 0x1e07ffff;      // powLimit / 2
#else
const uint32_t POW_LIMIT = 0x201fffff;           // ~uint256(0) >> 3
const uint32_t INITIAL_HASH_TARGET = 0x2000ffff; // ~uint256(0) >> 8
const uint32_t HALF_POW_LIMIT = 0x200fffff;      // powLimit / 2
#endif
const uint32_t POS_LIMIT = 0x1d03ffff; // bnProofOfStakeHardLimit, ~uint256(0) >> 30
const uint32_t BITS = 0x1d00ffff;      // a target well inside both limits
const int64_t ONE_WEEK = 7 * 24 * 60 * 60;
const int64_t NOMINAL_21000 = 21000 * 60; // nDifficultyInterval * nPowTargetSpacing
const int64_t NOMINAL_10 = 10 * 60;

arith_uint256 Target(uint32_t nBits)
{
    arith_uint256 t;
    bool fNegative = false, fOverflow = false;
    t.SetCompact(nBits, &fNegative, &fOverflow);
    BOOST_REQUIRE(!fNegative && !fOverflow);
    return t;
}

/** Model of CalculateNextWorkRequired (pow.cpp:70-103) without the scans:
 *  clamp the timespan to [nominal/4, 4 * nominal], retarget, cap at
 *  min(3 * target(nMinEase), powLimit). Only for targets where
 *  target * 4 * nominal fits into 256 bits. */
uint32_t ModelCalc(uint32_t nBitsLast, int64_t nActual, int64_t nNominal, uint32_t nMinEase)
{
    nActual = std::max(nActual, nNominal / 4);
    nActual = std::min(nActual, nNominal * 4);
    const arith_uint256 retarget = Target(nBitsLast) * arith_uint256((uint64_t)nActual) / arith_uint256((uint64_t)nNominal);
    arith_uint256 cap = Target(nMinEase) * 3;
    if (cap > Target(POW_LIMIT)) cap = Target(POW_LIMIT);
    return std::min(retarget, cap).GetCompact();
}

/** Model of the pre-fork ppcoin retarget (pow.cpp:189-202) for a
 *  non-negative multiplier and targets where the product fits. */
uint32_t ModelPreFork(uint32_t nBitsPrev, int64_t nActualSpacing, int64_t nSpacing, uint32_t nLimit)
{
    const int64_t nInterval = ONE_WEEK / nSpacing;
    const int64_t nMul = (nInterval - 1) * nSpacing + 2 * nActualSpacing;
    BOOST_REQUIRE(nMul >= 0);
    arith_uint256 r = Target(nBitsPrev) * arith_uint256((uint64_t)nMul) / arith_uint256((uint64_t)((nInterval + 1) * nSpacing));
    if (r > Target(nLimit)) r = Target(nLimit);
    return r.GetCompact();
}

/** base_uint arithmetic returns base_uint<256>, which has no GetCompact. */
uint32_t Compact(const arith_uint256& a) { return a.GetCompact(); }

uint256 AsHash(const arith_uint256& a) { return ArithToUint256(a); }

const Consensus::Params& ConsensusParams() { return Params().GetConsensus(); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(pow_chain_tests, ConsensusTestingSetup)

/* The per-build constants above match the parameters. */
BOOST_AUTO_TEST_CASE(build_constants)
{
    BOOST_CHECK_EQUAL(ConsensusParams().powLimit.GetCompact(), POW_LIMIT);
    BOOST_CHECK_EQUAL(ConsensusParams().initialHashTarget.GetCompact(), INITIAL_HASH_TARGET);
    BOOST_CHECK_EQUAL(bnProofOfStakeHardLimit.GetCompact(), POS_LIMIT);
    BOOST_CHECK_EQUAL(Compact(Target(POW_LIMIT) / 2), HALF_POW_LIMIT);
    BOOST_CHECK_EQUAL(ConsensusParams().nPowTargetSpacing, 60);
}

/* GetLastBlockIndex (pow.cpp:30-35): walks back to the nearest block of the
 * wanted type, but stops at the first block of the chain (pprev == nullptr)
 * whatever its type. */
BOOST_AUTO_TEST_CASE(last_block_index)
{
    BOOST_CHECK(GetLastBlockIndex(nullptr, false) == nullptr);
    BOOST_CHECK(GetLastBlockIndex(nullptr, true) == nullptr);

    CBlockIndex* g = chain.StartOnExistingGenesis();
    BOOST_REQUIRE(g->IsProofOfWork());
    BOOST_CHECK(GetLastBlockIndex(g, false) == g);
    BOOST_CHECK(GetLastBlockIndex(g, true) == g); // no PoS block: the genesis

    const int64_t t = g->GetBlockTime();
    CBlockIndex* b1 = chain.Append(BlockSpec(t + 60, BITS, false));
    CBlockIndex* p2 = chain.Append(BlockSpec(t + 120, POS_LIMIT, true));
    CBlockIndex* p3 = chain.Append(BlockSpec(t + 180, POS_LIMIT, true));
    CBlockIndex* b4 = chain.Append(BlockSpec(t + 240, BITS, false));
    BOOST_CHECK(GetLastBlockIndex(b1, false) == b1);
    BOOST_CHECK(GetLastBlockIndex(b1, true) == g);
    BOOST_CHECK(GetLastBlockIndex(p3, true) == p3);
    BOOST_CHECK(GetLastBlockIndex(p3, false) == b1);
    BOOST_CHECK(GetLastBlockIndex(p2, false) == b1);
    BOOST_CHECK(GetLastBlockIndex(b4, true) == p3);
    BOOST_CHECK(GetLastBlockIndex(b4, false) == b4);

    // A segment that starts with a PoS block: a PoW request ends there.
    TestChain seg(1);
    BlockSpec start(t, POS_LIMIT, true);
    start.nHeight = 100;
    CBlockIndex* s0 = seg.Append(nullptr, start);
    CBlockIndex* s1 = seg.Append(BlockSpec(t + 60, POS_LIMIT, true));
    BOOST_CHECK(GetLastBlockIndex(s1, false) == s0);
    BOOST_CHECK(s0->IsProofOfStake());
}

/* CheckProofOfWork (pow.cpp:213-226): range check of nBits, then hash <=
 * target. */
BOOST_AUTO_TEST_CASE(check_proof_of_work)
{
    // Params with the mainnet powLimit in both builds.
    Consensus::Params params = ConsensusParams();
    params.powLimit = CBigNum(~uint256(0) >> 20);
    BOOST_REQUIRE_EQUAL(params.powLimit.GetCompact(), 0x1e0fffffU);

    const arith_uint256 target = Target(BITS);
    BOOST_CHECK(CheckProofOfWork(AsHash(target), BITS, params));      // hash == target
    BOOST_CHECK(!CheckProofOfWork(AsHash(target + 1), BITS, params)); // target + 1
    BOOST_CHECK(CheckProofOfWork(AsHash(target - 1), BITS, params));  // target - 1
    BOOST_CHECK(CheckProofOfWork(uint256(), BITS, params));         // hash 0
    BOOST_CHECK(!CheckProofOfWork(~uint256(), BITS, params));

    // nBits == powLimit, and one step above it.
    // The compact 0x1e0fffff is powLimit truncated to 3 mantissa bytes: a
    // hash between that target and the full powLimit is rejected.
    BOOST_CHECK(CheckProofOfWork(AsHash(Target(0x1e0fffff)), 0x1e0fffff, params));
    BOOST_CHECK(!CheckProofOfWork(~uint256(0) >> 20, 0x1e0fffff, params));
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x1e100000, params));

    // Zero, negative, overflowing nBits: rejected even for hash 0.
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0, params));
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x00123456, params)); // size 0 => 0
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x01003456, params)); // size 1 => 0
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x04923456, params)); // sign bit
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x01fedcba, params)); // sign bit, size 1
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0xff123456, params)); // far above any limit
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x2000ffff, params)); // lowdiff initialHashTarget

    // A non-normalised encoding of the same target behaves the same.
    BOOST_REQUIRE(Target(0x1e000fff) == Target(0x1d0fff00));
    for (uint32_t nBits : {0x1e000fffU, 0x1d0fff00U}) {
        BOOST_CHECK(CheckProofOfWork(AsHash(Target(0x1d0fff00)), nBits, params));
        BOOST_CHECK(!CheckProofOfWork(AsHash(Target(0x1d0fff00) + 1), nBits, params));
    }

    // With the build's own parameters.
    BOOST_CHECK(CheckProofOfWork(AsHash(Target(POW_LIMIT)), POW_LIMIT, ConsensusParams()));
    BOOST_CHECK(!CheckProofOfWork(AsHash(Target(POW_LIMIT) + 1), POW_LIMIT, ConsensusParams()));
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x1e100000, ConsensusParams()));
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x2000ffff, ConsensusParams()));
#else
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x20200000, ConsensusParams()));
    BOOST_CHECK(CheckProofOfWork(uint256(), 0x2000ffff, ConsensusParams()));
#endif
}

/* CalculateNextWorkRequired (pow.cpp:70-75): the timespan is clamped to
 * [nominal / 4, 4 * nominal], nominal = nDifficultyInterval * 60. pindexLast
 * has no phashBlock and chainActive holds only the genesis (nBits =
 * powLimit), so the cap is powLimit and the clamps are visible. */
BOOST_AUTO_TEST_CASE(calc_timespan_clamps)
{
    globals.UseUnitTestGlobals();
    BOOST_REQUIRE_EQUAL(nDifficultyInterval, 21000U);
    const int64_t nLast = 1500000000;
    CBlockIndex last;
    last.nHeight = 50000;
    last.nTime = nLast;
    last.nBits = BITS;
    BOOST_REQUIRE(last.phashBlock == nullptr);

    struct Case { int64_t nActual; uint32_t nExpected; };
    const Case cases[] = {
        {-1000, 0x1c3fffc0},        // negative => nominal / 4
        {0, 0x1c3fffc0},            // zero => nominal / 4
        {314999, 0x1c3fffc0},       // just below nominal / 4
        {315000, 0x1c3fffc0},       // exactly nominal / 4
        {1260000, BITS},            // on target
        {5040000, 0x1d03fffc},      // exactly 4 * nominal
        {5040001, 0x1d03fffc},      // just above
        {1000000000, 0x1d03fffc},   // extremely slow
    };
    for (const Case& c : cases) {
        const uint32_t nNext = CalculateNextWorkRequired(&last, nLast - c.nActual, ConsensusParams());
        BOOST_CHECK_MESSAGE(nNext == c.nExpected, "actual " << c.nActual << ": " << std::hex << nNext);
        BOOST_CHECK_EQUAL(nNext, ModelCalc(BITS, c.nActual, NOMINAL_21000, POW_LIMIT));
    }

    // The nominal timespan follows nDifficultyInterval.
    globals.SetEpochInterval(10);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, nLast - 100, ConsensusParams()), 0x1c3fffc0U);  // 100 < 150
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, nLast - 600, ConsensusParams()), BITS);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, nLast - 3000, ConsensusParams()), 0x1d03fffcU); // 3000 > 2400
    BOOST_CHECK_EQUAL(ModelCalc(BITS, 3000, NOMINAL_10, POW_LIMIT), 0x1d03fffcU);
}

/* CalculateNextWorkRequired (pow.cpp:39-68): nMinEase is the lowest nBits of
 * the blocks at heights >= nMainnetNewLogicBlockNumber, first on chainActive
 * (loop 1), then on pindexLast's own chain via mapBlockIndex (loop 2). */
BOOST_AUTO_TEST_CASE(calc_min_ease_scans)
{
    globals.UseUnitTestGlobals();
    globals.SetNewLogicBlockNumber(3);
    CBlockIndex* g = chain.StartOnExistingGenesis();
    const int64_t t = g->GetBlockTime();
    chain.Append(BlockSpec(t + 60, 0x1b00ffff));            // h1, below the fork height
    CBlockIndex* h2 = chain.Append(BlockSpec(t + 120, BITS)); // h2, below the fork height
    chain.Append(BlockSpec(t + 180, 0x1c400000));           // h3: lowest nBits >= fork
    chain.Append(BlockSpec(t + 240, BITS));
    CBlockIndex* h5 = chain.Append(BlockSpec(t + 300, BITS));
    chain.SetActiveTip(h5);
    const int64_t nOnTarget = h5->GetBlockTime() - NOMINAL_21000;

    // Main chain: cap = 3 * target(0x1c400000) = 0x1d00c000 < target(BITS).
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(h5, nOnTarget, ConsensusParams()), 0x1d00c000U);
    BOOST_CHECK_EQUAL(ModelCalc(BITS, NOMINAL_21000, NOMINAL_21000, 0x1c400000), 0x1d00c000U);
    // With the fork at height 1, h1 counts too.
    globals.SetNewLogicBlockNumber(1);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(h5, nOnTarget, ConsensusParams()), 0x1b02fffdU);
    globals.SetNewLogicBlockNumber(3);

    // (a) Side chain from h2, harder than chainActive: found by loop 2.
    CBlockIndex* s3 = chain.Append(h2, BlockSpec(t + 180, 0x1c100000));
    CBlockIndex* s4 = chain.Append(s3, BlockSpec(t + 300, BITS));
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(s4, nOnTarget, ConsensusParams()), 0x1c300000U);
    // (b) Side chain without hard blocks: chainActive (loop 1) still counts.
    CBlockIndex* r3 = chain.Append(h2, BlockSpec(t + 180, BITS));
    CBlockIndex* r4 = chain.Append(r3, BlockSpec(t + 300, BITS));
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(r4, nOnTarget, ConsensusParams()), 0x1d00c000U);
    // (c) pindexLast without phashBlock on top of s4: loop 2 does not run,
    // s3 is not seen, only chainActive counts.
    CBlockIndex copy;
    copy.pprev = s4;
    copy.nHeight = 5;
    copy.nTime = s4->nTime;
    copy.nBits = BITS;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&copy, nOnTarget, ConsensusParams()), 0x1d00c000U);
    // (d) Empty chainActive: only loop 2.
    chain.SetActiveTip(nullptr);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(s4, nOnTarget, ConsensusParams()), 0x1c300000U);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(r4, nOnTarget, ConsensusParams()), BITS);
}

/* nMinEase quirks, pinned as is (project/known-issues.md): PoS blocks count,
 * and the comparison is on the compact value, not on the target. */
BOOST_AUTO_TEST_CASE(calc_min_ease_quirks)
{
    globals.UseUnitTestGlobals();
    CBlockIndex* g = chain.StartOnExistingGenesis();
    const int64_t t = g->GetBlockTime();
    chain.Append(BlockSpec(t + 60, BITS));
    CBlockIndex* p2 = chain.Append(BlockSpec(t + 120, 0x1c100000, true)); // PoS
    CBlockIndex* b3 = chain.Append(BlockSpec(t + 180, BITS));
    chain.SetActiveTip(b3);
    const int64_t nOnTarget = b3->GetBlockTime() - NOMINAL_21000;
    // The PoS block's nBits lower the cap: 3 * target(0x1c100000).
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(b3, nOnTarget, ConsensusParams()), 0x1c300000U);

    // A non-normalised nBits 0x1e000001 has target 2^216, far below
    // target(BITS) ~ 2^224, but as a number 0x1e000001 > 0x1d00ffff, so it
    // does not become nMinEase.
    TestChain other(1);
    BlockSpec start(t, POW_LIMIT);
    start.nHeight = 0;
    other.Append(nullptr, start);
    other.Append(BlockSpec(t + 60, BITS));
    other.Append(BlockSpec(t + 120, 0x1e000001));
    CBlockIndex* o3 = other.Append(BlockSpec(t + 180, BITS));
    other.SetActiveTip(o3);
    BOOST_REQUIRE(Target(0x1e000001) == arith_uint256(1) << 216);
    const uint32_t nNext = CalculateNextWorkRequired(o3, nOnTarget, ConsensusParams());
    BOOST_CHECK_EQUAL(nNext, BITS);
    BOOST_CHECK(nNext != Compact(Target(0x1e000001) * 3)); // 0x1c030000 by target
    (void)p2;
}

/* The cap (pow.cpp:84-96): result = min(retarget, 3 * target(nMinEase)),
 * the cap itself at most powLimit. */
BOOST_AUTO_TEST_CASE(calc_cap)
{
    globals.UseUnitTestGlobals();
    CBlockIndex* g = chain.StartOnExistingGenesis();
    CBlockIndex* b1 = chain.Append(BlockSpec(g->GetBlockTime() + 60, BITS));
    chain.SetActiveTip(b1);
    const int64_t nLast = b1->GetBlockTime();
    // nMinEase = BITS (b1 itself): below 3x the retarget wins, above the cap.
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(b1, nLast - 2 * NOMINAL_21000, ConsensusParams()), 0x1d01fffeU);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(b1, nLast - 3 * NOMINAL_21000, ConsensusParams()), 0x1d02fffdU);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(b1, nLast - 7 * NOMINAL_21000 / 2, ConsensusParams()), 0x1d02fffdU);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(b1, nLast - 4 * NOMINAL_21000, ConsensusParams()), 0x1d02fffdU);
    BOOST_CHECK_EQUAL(ModelCalc(BITS, 4 * NOMINAL_21000, NOMINAL_21000, BITS), 0x1d02fffdU);

    // nMinEase = powLimit / 2: 3 * nMinEase is above powLimit, so the cap is
    // powLimit (uncapped it would be 1.5 * powLimit).
    TestChain fresh(1);
    BlockSpec start(g->GetBlockTime(), HALF_POW_LIMIT);
    start.nHeight = 0;
    CBlockIndex* f0 = fresh.Append(nullptr, start);
    CBlockIndex* f1 = fresh.Append(BlockSpec(g->GetBlockTime() + 60, HALF_POW_LIMIT));
    fresh.SetActiveTip(f1);
    const uint32_t nCapped = CalculateNextWorkRequired(f1, f1->GetBlockTime() - 4 * NOMINAL_21000, ConsensusParams());
    BOOST_CHECK_EQUAL(nCapped, POW_LIMIT);
    // 3 * nMinEase: mainnet 0x1e17fffd, lowdiff 0x202ffffd.
    BOOST_CHECK(Target(nCapped) < Target(HALF_POW_LIMIT) * 3);
    // pindexLast at powLimit (no phashBlock), 4x retarget: powLimit.
    CBlockIndex last;
    last.nHeight = 1;
    last.nTime = nLast;
    last.nBits = POW_LIMIT;
    fresh.SetActiveTip(f0);
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, nLast - 4 * NOMINAL_21000, ConsensusParams()), POW_LIMIT);
}

/* GetNextTargetRequired (pow.cpp:107-129, 208-211): genesis, first and second
 * block, for PoW and PoS requests. */
BOOST_AUTO_TEST_CASE(next_target_first_blocks)
{
    BOOST_CHECK_EQUAL(GetNextTargetRequired(nullptr, false), POW_LIMIT);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(nullptr, true), POS_LIMIT);

    for (int nGlobals = 0; nGlobals < 2; ++nGlobals) {
        TestChain c(10 + nGlobals);
        if (nGlobals == 0) globals.UseUnitTestGlobals(); else globals.UseMainnetGlobals();
        CBlockIndex* g = c.StartOnExistingGenesis();
        const int64_t t = g->GetBlockTime();
        CBlockIndex* b1 = c.Append(BlockSpec(t + 60, BITS));
        CBlockIndex* b2 = c.Append(BlockSpec(t + 120, BITS));
        c.SetActiveTip(b2);
        BOOST_CHECK_EQUAL(GetNextTargetRequired(g, false), INITIAL_HASH_TARGET);  // first block
        BOOST_CHECK_EQUAL(GetNextTargetRequired(g, true), INITIAL_HASH_TARGET);
        BOOST_CHECK_EQUAL(GetNextTargetRequired(b1, false), INITIAL_HASH_TARGET); // second block
        BOOST_CHECK_EQUAL(GetNextTargetRequired(b1, true), INITIAL_HASH_TARGET);
        // A PoS request on a PoW-only chain finds the genesis: still initial.
        BOOST_CHECK_EQUAL(GetNextTargetRequired(b2, true), INITIAL_HASH_TARGET);

        // PoS chain: the first two PoS blocks count like genesis + first.
        CBlockIndex* p3 = c.Append(BlockSpec(t + 180, POS_LIMIT, true));
        BOOST_CHECK_EQUAL(GetNextTargetRequired(p3, true), INITIAL_HASH_TARGET);
        CBlockIndex* p4 = c.Append(BlockSpec(t + 300, 0x1c00ffff, true)); // 120 s after p3
        c.SetActiveTip(p4);
        if (nGlobals == 0) {
            // Post-fork: keep pindexLast's nBits.
            BOOST_CHECK_EQUAL(GetNextTargetRequired(p4, true), 0x1c00ffffU);
        } else {
            // Pre-fork: retarget from p4's nBits with 120 s actual spacing.
            BOOST_CHECK_EQUAL(GetNextTargetRequired(p4, true), ModelPreFork(0x1c00ffff, 120, 60, POS_LIMIT));
            BOOST_CHECK(GetNextTargetRequired(p4, true) != 0x1c00ffffU);
        }
    }
}

/* Pre-fork PoW retarget (pow.cpp:184-203), mainnet globals:
 * target(prev) * ((nInterval - 1) * spacing + 2 * actual) / ((nInterval + 1) * spacing),
 * spacing = min(720, 60 * (1 + hLast - hPrev)), nInterval = one week / spacing,
 * capped at powLimit. */
BOOST_AUTO_TEST_CASE(pre_fork_pow)
{
    globals.UseMainnetGlobals();
    CBlockIndex* g = chain.StartOnExistingGenesis();
    const int64_t t = g->GetBlockTime();
    CBlockIndex* b1 = chain.Append(BlockSpec(t + 60, BITS));
    CBlockIndex* b2 = chain.Append(BlockSpec(t + 120, BITS));

    // Actual spacing (b3 - b2) from extremely fast to extremely slow.
    struct Case { int64_t nActual; uint32_t nExpected; };
    const Case cases[] = {
        {-120, 0x1d00ffd7}, {0, 0x1d00fff1}, {1, 0x1d00fff2}, {60, BITS},
        {3600, 0x1d0102fe}, {1000000, 0x1d044e68},
    };
    for (const Case& c : cases) {
        CBlockIndex* b3 = chain.Append(b2, BlockSpec(b2->GetBlockTime() + c.nActual, BITS));
        const uint32_t nNext = GetNextTargetRequired(b3, false);
        BOOST_CHECK_MESSAGE(nNext == c.nExpected, "actual " << c.nActual << ": " << std::hex << nNext);
        BOOST_CHECK_EQUAL(nNext, ModelPreFork(BITS, c.nActual, 60, POW_LIMIT));
    }

    // The base is pindexPrev's nBits (the last PoW block), not pindexLast's.
    CBlockIndex* b3 = chain.Append(b2, BlockSpec(b2->GetBlockTime() + 120, BITS));
    // spacing 60 * (1 + number of PoS blocks on top), at most 720 s.
    struct Spacing { int nPoS; int64_t nSpacing; uint32_t nExpected; };
    const Spacing spacings[] = {
        {0, 60, 0x1d01000c}, {1, 120, BITS}, {11, 720, 0x1d00ff7d}, {20, 720, 0x1d00ff7d},
    };
    for (const Spacing& s : spacings) {
        CBlockIndex* tip = b3;
        for (int i = 0; i < s.nPoS; ++i) {
            tip = chain.Append(tip, BlockSpec(tip->GetBlockTime() + 60, 0x1c00ffff, true));
        }
        const uint32_t nNext = GetNextTargetRequired(tip, false);
        BOOST_CHECK_MESSAGE(nNext == s.nExpected, "PoS on top " << s.nPoS << ": " << std::hex << nNext);
        BOOST_CHECK_EQUAL(nNext, ModelPreFork(BITS, 120, s.nSpacing, POW_LIMIT));
    }

    // Clamp at powLimit: prev at powLimit and slow.
    CBlockIndex* l1 = chain.Append(b1, BlockSpec(b1->GetBlockTime() + 60, POW_LIMIT));
    CBlockIndex* l2 = chain.Append(l1, BlockSpec(l1->GetBlockTime() + 600, POW_LIMIT));
    BOOST_CHECK_EQUAL(GetNextTargetRequired(l2, false), POW_LIMIT);
    // Fast (30 s): just below powLimit.
    CBlockIndex* l3 = chain.Append(l1, BlockSpec(l1->GetBlockTime() + 30, POW_LIMIT));
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(GetNextTargetRequired(l3, false), 0x1e0fff96U);
#else
    BOOST_CHECK_EQUAL(GetNextTargetRequired(l3, false), 0x201fff2eU);
#endif
}

/* Pre-fork, a very negative actual spacing makes the multiplier negative:
 * the target becomes negative, is not clamped, and the compact result has
 * the sign bit set (pinned as is, project/known-issues.md). */
BOOST_AUTO_TEST_CASE(pre_fork_negative_spacing)
{
    globals.UseMainnetGlobals();
    CBlockIndex* g = chain.StartOnExistingGenesis();
    const int64_t t = g->GetBlockTime() + 1000000;
    chain.Append(BlockSpec(t, BITS));
    CBlockIndex* b2 = chain.Append(BlockSpec(t + 60, BITS));
    // (10079 * 60 + 2 * actual) < 0 for actual < -302370.
    CBlockIndex* b3 = chain.Append(BlockSpec(b2->GetBlockTime() - 400000, BITS));
    const uint32_t nNext = GetNextTargetRequired(b3, false);
    BOOST_CHECK_EQUAL(nNext, 0x1cd2a3e9U);
    BOOST_CHECK(nNext & 0x00800000); // negative compact
    // Magnitude: target * 195260 / 604860.
    const arith_uint256 magnitude = Target(BITS) * 195260 / 604860;
    BOOST_CHECK_EQUAL(nNext & ~0x00800000U, magnitude.GetCompact());
    // CheckProofOfWork would reject that target.
    BOOST_CHECK(!CheckProofOfWork(uint256(), nNext, ConsensusParams()));
    // Exactly at the edge (-302370): multiplier 0, target 0.
    CBlockIndex* b4 = chain.Append(b2, BlockSpec(b2->GetBlockTime() - 302370, BITS));
    BOOST_CHECK_EQUAL(GetNextTargetRequired(b4, false), 0U);
}

/* Pre-fork PoS retarget: spacing always 60 s, capped at the PoS hard limit
 * (bnProofOfStakeHardLimit). */
BOOST_AUTO_TEST_CASE(pre_fork_pos)
{
    globals.UseMainnetGlobals();
    CBlockIndex* g = chain.StartOnExistingGenesis();
    const int64_t t = g->GetBlockTime();
    CBlockIndex* b1 = chain.Append(BlockSpec(t + 60, BITS));
    CBlockIndex* p2 = chain.Append(BlockSpec(t + 120, 0x1c00ffff, true));
    // Only one PoS block: the PoS request walks to the genesis => initial.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(p2, true), INITIAL_HASH_TARGET);
    CBlockIndex* b3 = chain.Append(BlockSpec(t + 180, BITS));
    CBlockIndex* p4 = chain.Append(BlockSpec(t + 300, 0x1c00ffff, true)); // 180 s after p2
    BOOST_CHECK_EQUAL(GetNextTargetRequired(p4, true), 0x1c010019U);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(p4, true), ModelPreFork(0x1c00ffff, 180, 60, POS_LIMIT));
    // PoW blocks on top do not change the PoS spacing (always 60 s).
    CBlockIndex* b5 = chain.Append(BlockSpec(t + 360, BITS));
    CBlockIndex* b6 = chain.Append(BlockSpec(t + 420, BITS));
    BOOST_CHECK_EQUAL(GetNextTargetRequired(b6, true), 0x1c010019U);
    // Clamp at the PoS limit, and below it when fast.
    CBlockIndex* q1 = chain.Append(b1, BlockSpec(t + 120, POS_LIMIT, true));
    CBlockIndex* q2 = chain.Append(q1, BlockSpec(t + 720, POS_LIMIT, true));
    BOOST_CHECK_EQUAL(GetNextTargetRequired(q2, true), POS_LIMIT);
    CBlockIndex* q3 = chain.Append(q1, BlockSpec(t + 150, POS_LIMIT, true));
    BOOST_CHECK_EQUAL(GetNextTargetRequired(q3, true), 0x1d03ffe4U);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(q3, true), ModelPreFork(POS_LIMIT, 30, 60, POS_LIMIT));
    (void)b3; (void)b5;
}

/* The fork boundary with the mainnet numbers (segment around 1,890,000):
 * the block before uses the pre-fork rule, the fork block gets powLimit
 * (1,890,000 is a multiple of 21000), later blocks keep the target. */
BOOST_AUTO_TEST_CASE(fork_boundary_mainnet)
{
    globals.UseMainnetGlobals();
    const int64_t t = 1600000000;
    BlockSpec start(t, BITS);
    start.nHeight = 1889990;
    chain.Append(nullptr, start);
    chain.AppendMany(8, 60, BITS);                            // .. 1889998
    CBlockIndex* last = chain.Append(BlockSpec(chain.Tip()->GetBlockTime() + 120, BITS)); // 1889999
    BOOST_REQUIRE_EQUAL(last->nHeight, 1889999);
    CBlockIndex* fork = chain.Append(BlockSpec(last->GetBlockTime() + 60, POW_LIMIT)); // 1890000
    CBlockIndex* after = chain.Append(BlockSpec(fork->GetBlockTime() + 60, POW_LIMIT));
    chain.SetActiveTip(after);

    // Next height 1,889,999: pre-fork rule.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(1889998), false), BITS);
    // Next height 1,890,000 = fork, 1890000 % 21000 == 0: powLimit.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(last, false), POW_LIMIT);
    // Next heights 1,890,001 and 1,890,002: keep pindexLast's nBits.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(fork, false), POW_LIMIT);
    CBlockIndex* other = chain.Append(fork, BlockSpec(fork->GetBlockTime() + 60, BITS));
    BOOST_CHECK_EQUAL(GetNextTargetRequired(other, false), BITS);
    (void)after;
}

/* A fork height that is not a multiple of the interval: the first post-fork
 * block keeps the target (no powLimit reset); a fork height that is a
 * multiple resets to powLimit. Unit-test globals with interval 10. */
BOOST_AUTO_TEST_CASE(fork_boundary_not_multiple)
{
    globals.UseUnitTestGlobals();
    globals.SetEpochInterval(10);
    CBlockIndex* g = chain.StartOnExistingGenesis();
    CBlockIndex* tip = chain.AppendMany(12, 60, BITS);
    chain.SetActiveTip(tip);

    globals.SetNewLogicBlockNumber(5);
    // Next height 4: pre-fork rule (spacing 60 => unchanged).
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(3), false), BITS);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(3), false), ModelPreFork(BITS, 60, 60, POW_LIMIT));
    // Next height 5 = fork, 5 % 10 != 0: keep.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(4), false), BITS);
    // Next height 10: retarget from the genesis (height 9 is not > 11).
    // nMinEase over heights >= 5 = BITS; actual 540 s.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(9), false), 0x1d00e665U);
    BOOST_CHECK_EQUAL(ModelCalc(BITS, 9 * 60, NOMINAL_10, BITS), 0x1d00e665U);

    globals.SetNewLogicBlockNumber(10);
    // Next height 10 = fork, a multiple of 10: powLimit.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(9), false), POW_LIMIT);
    // Next height 9: still pre-fork.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(8), false), BITS);
    (void)g;
}

/* Post-fork epochs (unit-test globals, interval 10): constant target within
 * an epoch, retarget at each boundary; the first boundary measures from the
 * genesis, later ones go back nDifficultyInterval blocks. Fast and slow
 * epochs hit the /4 clamp and the 1/3-highest-difficulty cap. */
BOOST_AUTO_TEST_CASE(post_fork_epochs)
{
    globals.UseUnitTestGlobals();
    globals.SetEpochInterval(10);
    CBlockIndex* g = chain.StartOnExistingGenesis();
    // Epoch 1: heights 1..9, 60 s => 540 s from the genesis.
    chain.AppendMany(9, 60, BITS);
    chain.SetActiveTip(chain.Tip());
    const uint32_t nEpoch2 = GetNextTargetRequired(chain.Tip(), false);
    BOOST_CHECK_EQUAL(nEpoch2, 0x1d00e665U);
    BOOST_CHECK_EQUAL(nEpoch2, ModelCalc(BITS, 540, NOMINAL_10, BITS));
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(5), false), BITS); // within the epoch

    // Epoch 2: heights 10..19 at nEpoch2, 10 s apart: 100 s since height 9
    // (< 150) => clamped to nominal / 4.
    chain.AppendMany(10, 10, nEpoch2);
    chain.SetActiveTip(chain.Tip());
    BOOST_REQUIRE_EQUAL(chain.Tip()->nHeight, 19);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(15), false), nEpoch2);
    const uint32_t nEpoch3 = GetNextTargetRequired(chain.Tip(), false);
    BOOST_CHECK_EQUAL(nEpoch3, 0x1c399940U);
    BOOST_CHECK_EQUAL(nEpoch3, ModelCalc(nEpoch2, 100, NOMINAL_10, nEpoch2));

    // Epoch 3: heights 20..29, 1000 s apart: 10000 s (> 2400) => 4x, but
    // the cap 3 * target(nMinEase = nEpoch3) wins.
    chain.AppendMany(10, 1000, nEpoch3);
    chain.SetActiveTip(chain.Tip());
    const uint32_t nEpoch4 = GetNextTargetRequired(chain.Tip(), false);
    BOOST_CHECK_EQUAL(nEpoch4, 0x1d00accbU);
    BOOST_CHECK_EQUAL(nEpoch4, Compact(Target(nEpoch3) * 3));
    BOOST_CHECK_EQUAL(nEpoch4, ModelCalc(nEpoch3, 10000, NOMINAL_10, nEpoch3));

    // Within an epoch: keep. (Height 20 is the case nBlocksToGo == 1 of the
    // log line's plural, pow.cpp:153.)
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(28), false), nEpoch3);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(20), false), nEpoch3);
    (void)g;
}

/* The window rule pindexLast->nHeight > nDifficultyInterval + 1
 * (pow.cpp:167): with interval 2, the boundary at height 3 takes the
 * genesis (a 3-block window), the one at height 5 goes back 2 blocks. */
BOOST_AUTO_TEST_CASE(post_fork_window_off_by_one)
{
    globals.UseUnitTestGlobals();
    globals.SetEpochInterval(2);
    chain.StartOnExistingGenesis();
    CBlockIndex* tip = chain.AppendMany(5, 60, BITS);
    chain.SetActiveTip(tip);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(1), false), INITIAL_HASH_TARGET);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(2), false), BITS); // 3 % 2 != 0
    // Height 3: 180 s since the genesis for a nominal 120 s => 1.5x.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(3), false), 0x1d017ffeU);
    BOOST_CHECK_EQUAL(ModelCalc(BITS, 180, 120, BITS), 0x1d017ffeU);
    // Height 5: back to height 3, 120 s => unchanged.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.AtHeight(5), false), BITS);
}

/* The first post-fork retarget reads the genesis from disk, but ignores the
 * result: only the index entry's time counts (pow.cpp:172-181). Here the
 * genesis in chainActive is a synthetic entry whose block file does not
 * exist, so the read fails. */
BOOST_AUTO_TEST_CASE(post_fork_genesis_read_ignored)
{
    globals.UseUnitTestGlobals();
    globals.SetEpochInterval(10);
    BlockSpec start(1000000, POW_LIMIT);
    start.nHeight = 0;
    CBlockIndex* g = chain.Append(nullptr, start);
    g->nFile = 99999; // no such block file
    g->nDataPos = 0;
    chain.Append(BlockSpec(1001000, BITS));
    CBlockIndex* tip = chain.AppendMany(8, 60, BITS); // height 9 at 1001480
    chain.SetActiveTip(tip);
    BOOST_REQUIRE(chainActive.Genesis() == g);
    CBlock block;
    BOOST_REQUIRE(!ReadBlockFromDisk(block, g, ConsensusParams()));
    // 1480 s since the genesis (< 2400).
    BOOST_CHECK_EQUAL(GetNextTargetRequired(tip, false), ModelCalc(BITS, 1480, NOMINAL_10, BITS));
    BOOST_CHECK_EQUAL(GetNextTargetRequired(tip, false), 0x1d027775U);
}

/* The first real mainnet retarget at height 1,911,000 (mainnet globals):
 * the window goes back 21000 blocks to the pre-fork block 1,889,999, and
 * the harder pre-fork nBits are ignored for nMinEase. */
BOOST_AUTO_TEST_CASE(post_fork_mainnet_first_retarget)
{
    globals.UseMainnetGlobals();
    BlockSpec start(1600000000, 0x1c00ffff);
    start.nHeight = 1889990;
    chain.Append(nullptr, start);
    chain.AppendMany(9, 60, 0x1c00ffff);                  // .. 1889999
    BOOST_REQUIRE_EQUAL(chain.Tip()->nHeight, 1889999);
    const int64_t nFirst = chain.Tip()->GetBlockTime();
    chain.AppendMany(21000, 30, POW_LIMIT);               // 1890000 .. 1910999, fast
    CBlockIndex* tip = chain.Tip();
    chain.SetActiveTip(tip);
    BOOST_REQUIRE_EQUAL(tip->nHeight, 1910999);
    BOOST_REQUIRE_EQUAL(tip->GetBlockTime() - nFirst, 630000);
    // Half the nominal 1,260,000 s => half the target; cap = powLimit.
    BOOST_CHECK_EQUAL(GetNextTargetRequired(tip, false), HALF_POW_LIMIT);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(tip->pprev, false), POW_LIMIT); // 1 block to go
}

/* PoS requests after the fork use the PoW epoch rule: pindexLast's nBits
 * are kept within an epoch (even when pindexLast is a PoW block), and at a
 * boundary the result is the same as for a PoW request. */
BOOST_AUTO_TEST_CASE(post_fork_pos_requests)
{
    globals.UseUnitTestGlobals();
    globals.SetEpochInterval(10);
    CBlockIndex* g = chain.StartOnExistingGenesis();
    const int64_t t = g->GetBlockTime();
    chain.Append(BlockSpec(t + 60, BITS));                        // 1
    CBlockIndex* p2 = chain.Append(BlockSpec(t + 120, 0x1c7fffff, true)); // 2
    CBlockIndex* p3 = chain.Append(BlockSpec(t + 180, 0x1c7fffff, true)); // 3
    CBlockIndex* b4 = chain.Append(BlockSpec(t + 240, BITS));     // 4
    chain.SetActiveTip(b4);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(b4, true), BITS);        // PoW nBits for a PoS request
    BOOST_CHECK_EQUAL(GetNextTargetRequired(p3, true), 0x1c7fffffU);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(p3, false), INITIAL_HASH_TARGET); // only 1 PoW block
    BOOST_CHECK_EQUAL(GetNextTargetRequired(b4, false), BITS);
    // Up to height 9, a PoS block at the boundary.
    chain.AppendMany(4, 60, BITS);                                 // 5..8
    CBlockIndex* p9 = chain.Append(BlockSpec(t + 540, 0x1c7fffff, true));
    chain.SetActiveTip(p9);
    const uint32_t nPoW = GetNextTargetRequired(p9, false);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(p9, true), nPoW);
    // Base = pindexLast's (PoS) nBits, nMinEase = 0x1c7fffff: 540 / 600.
    BOOST_CHECK_EQUAL(nPoW, ModelCalc(0x1c7fffff, 540, NOMINAL_10, 0x1c7fffff));
    BOOST_CHECK_EQUAL(nPoW, 0x1c733332U);
    (void)p2;
}

/* Dead code (project/plans/dead-code.md, removed in P0-59), pinned until
 * then: ComputeMaxBits doubles once more per started day after the first
 * doubling, capped at the limit; ComputeMinWork uses powLimit,
 * ComputeMinStake the PoS hard limit (via GetProofOfStakeLimit). */
BOOST_AUTO_TEST_CASE(dead_compute_max_bits)
{
    const CBigNum limit(~uint256(0) >> 20); // 0x1e0fffff
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, BITS, 0), 0x1d01fffeU);       // 2x
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, BITS, -5), 0x1d01fffeU);      // 2x
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, BITS, 1), 0x1d03fffcU);       // 4x
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, BITS, 86400), 0x1d03fffcU);   // 4x
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, BITS, 86401), 0x1d07fff8U);   // 8x
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, BITS, 100 * 86400), 0x1e0fffffU); // capped
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, 0x1e1fffff, 0), 0x1e0fffffU); // base above the limit
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, 0x1e07ffff, 0), 0x1e0ffffeU); // 2x, just below the limit
    BOOST_CHECK_EQUAL(ComputeMaxBits(limit, 0x1e07ffff, 1), 0x1e0fffffU); // 4x, capped

    BOOST_CHECK_EQUAL(ComputeMinWork(BITS, 86401), 0x1d07fff8U);
    BOOST_CHECK_EQUAL(ComputeMinWork(BITS, 100000000), POW_LIMIT);
    BOOST_CHECK_EQUAL(ComputeMinStake(0x1c00ffff, 0, 0), 0x1c01fffeU);
    BOOST_CHECK_EQUAL(ComputeMinStake(BITS, 30 * 86400, 1400000000), POS_LIMIT);
}

BOOST_AUTO_TEST_SUITE_END()
