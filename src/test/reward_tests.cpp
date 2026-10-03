// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Rewards and the reward-derived block size limit, task P0-46 (plan 0.2f,
// review B1, B2). Phase 0 pins what the code does today, quirks included:
//
// - GetProofOfWorkReward (validation.cpp:918-980): pre-fork CBigNum
//   bisection on nBits, post-fork double nMoneySupply * 0.02 / 525960 of
//   the block before the epoch start; fees are added only pre-fork;
// - GetMaxSize (consensus/consensus.cpp:20-47) in its three modes;
// - GetProofOfStakeReward (pow.cpp:237-250), GetCoinAge
//   (validation.cpp:4809-4866) and the coinstake limit that uses them in
//   Consensus::CheckTxInputs (consensus/tx_verify.cpp:410-423);
// - LoadBlockRewardAndHighestDiff (validation.cpp:3677-3729, log output
//   only, divides before multiplying) and the getsubsidy RPC.
//
// The golden table test/data/reward_vectors.json is computed without
// CBigNum or node code by contrib/testing/reward_vectors.py; the golden_*
// cases replay it through the real functions. Format: src/test/README.md.

#include "test/consensus_harness.h"

#include <boost/version.hpp>

// BOOST_TEST_CONTEXT exists from Boost 1.59. The release workflow's
// build-ubuntu-1604-functional-test job builds with Ubuntu 16.04's system
// Boost 1.58, so fall back to logging the context as a test message and
// running the block once.
#if BOOST_VERSION < 105900
#define BOOST_TEST_CONTEXT(msg) if (([&] { BOOST_TEST_MESSAGE(msg); }(), true))
#endif

#include "amount.h"
#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "fs.h"
#include "main.h"
#include "policy/fees.h"
#include "pow.h"
#include "rpc/server.h"
#include "utilmoneystr.h"
#include "script/script.h"
#include "txdb.h"
#include "util.h"
#include "validation.h"

#include "data/reward_vectors.json.h"

#include <univalue.h>

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace consensus_harness;

UniValue CallRPC(std::string args); // defined in rpc_tests.cpp
// Copy of the pre-fork bisection, defined in bignum_consensus_tests.cpp.
int64_t RewardBisection(uint32_t nBits, uint32_t nTargetLimitCompact);

extern bool fPrintToConsole;

BOOST_FIXTURE_TEST_SUITE(reward_tests, ConsensusTestingSetup)

namespace {

const int64_t DAY = 24 * 60 * 60;

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
const size_t PREFORK_COLUMN = 1; // target limit 0x1e0fffff
#else
const size_t PREFORK_COLUMN = 2; // target limit 0x201fffff
#endif

/** Golden table, parsed once. */
const UniValue& Vectors()
{
    static UniValue doc;
    if (doc.isNull()) {
        const std::string text(json_tests::reward_vectors, json_tests::reward_vectors + sizeof(json_tests::reward_vectors));
        if (!doc.read(text) || !doc.isObject()) {
            throw std::runtime_error("reward_vectors.json: parse error");
        }
        if (find_value(doc, "format").get_str() != "yacoin-reward-vectors" || find_value(doc, "version").get_str() != "1") {
            throw std::runtime_error("reward_vectors.json: unexpected format or version");
        }
    }
    return doc;
}

const UniValue& Table(const std::string& name)
{
    const UniValue& t = find_value(Vectors(), name);
    if (!t.isArray() || t.size() == 0) {
        throw std::runtime_error("reward_vectors.json: missing table " + name);
    }
    return t;
}

int64_t Dec(const UniValue& row, size_t i)
{
    return std::stoll(row[i].get_str());
}

uint32_t Hex32(const UniValue& row, size_t i)
{
    return (uint32_t)std::stoul(row[i].get_str(), nullptr, 16);
}

/**
 * Captures what LogPrintf writes while it is alive: sets fPrintToConsole
 * and points the stdout file descriptor at a file in the data directory.
 * Restores both in Stop() or the destructor. Do not use BOOST_CHECK while
 * capturing (its output would land in the file).
 */
class LogCapture {
public:
    LogCapture() : path(GetDataDir() / "reward_tests_log.txt")
    {
        std::cout.flush();
        fflush(stdout);
        FILE* f = fsbridge::fopen(path, "w");
        if (!f) throw std::runtime_error("LogCapture: cannot open " + path.string());
        nSavedFd = dup(fileno(stdout));
        if (nSavedFd < 0 || dup2(fileno(f), fileno(stdout)) < 0) {
            fclose(f);
            throw std::runtime_error("LogCapture: dup/dup2 failed");
        }
        fclose(f);
        fSavedPrintToConsole = fPrintToConsole;
        fPrintToConsole = true;
        fActive = true;
    }
    ~LogCapture() { Stop(); }
    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    /** Stops capturing and returns everything logged. */
    std::string Stop()
    {
        if (fActive) {
            fflush(stdout);
            fPrintToConsole = fSavedPrintToConsole;
            dup2(nSavedFd, fileno(stdout));
            close(nSavedFd);
            fActive = false;
            std::ifstream in(path.string());
            std::stringstream ss;
            ss << in.rdbuf();
            text = ss.str();
        }
        return text;
    }

private:
    fs::path path;
    int nSavedFd = -1;
    bool fSavedPrintToConsole = false;
    bool fActive = false;
    std::string text;
};

/** Sets a -switch for the scope; afterwards it is "0" (ArgsManager has no
 *  way to remove an argument) or its previous value. */
class ScopedArg {
public:
    ScopedArg(const std::string& strArgIn, const std::string& strValue)
        : strArg(strArgIn), fWasSet(gArgs.IsArgSet(strArgIn)), strOld(gArgs.GetArg(strArgIn, "0"))
    {
        gArgs.ForceSetArg(strArg, strValue);
    }
    ~ScopedArg() { gArgs.ForceSetArg(strArg, fWasSet ? strOld : "0"); }

private:
    const std::string strArg;
    const bool fWasSet;
    const std::string strOld;
};

/** Sets a global for the scope. */
template <typename T>
class ScopedValue {
public:
    ScopedValue(T& refIn, T value) : ref(refIn), old(refIn) { ref = value; }
    ~ScopedValue() { ref = old; }

private:
    T& ref;
    const T old;
};

bool Contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

/** The "Current block reward = " value LoadBlockRewardAndHighestDiff logs. */
std::string LoggedLoadReward()
{
    LogCapture capture;
    LoadBlockRewardAndHighestDiff();
    return capture.Stop();
}

/** Own chain segment from height 0 (pprev == nullptr) up to nTipHeight;
 *  every entry gets nMoneySupply 0. Returns the tip, made active. */
CBlockIndex* BuildChain(TestChain& chain, int nTipHeight, uint32_t nBits = 0x1d00ffff)
{
    BlockSpec first(1400000000, nBits);
    first.nHeight = 0;
    chain.Append(nullptr, first);
    if (nTipHeight > 0) chain.AppendMany(nTipHeight, 60, nBits);
    for (int h = 0; h <= nTipHeight; ++h) chain.AtHeight(h)->nMoneySupply = 0;
    chain.SetActiveTip(chain.Tip());
    return chain.Tip();
}

/** validation.cpp:932 and 3714-3717, written the same way. */
int64_t PostForkRewardExpr(int64_t nMoneySupply)
{
    int64_t blockReward = (nMoneySupply * nInflation / nNumberOfBlocksPerYear);
    return blockReward;
}
int64_t LoadRewardExpr(int64_t nMoneySupply)
{
    int64_t nBlockReward = (::int64_t)(nMoneySupply / nNumberOfBlocksPerYear) * nInflation;
    return nBlockReward;
}

} // namespace

/* Constants the table and the expected values rely on. */
BOOST_AUTO_TEST_CASE(reward_constants)
{
    BOOST_CHECK_EQUAL(COIN, 1000000);
    BOOST_CHECK_EQUAL(CENT, 10000);
    BOOST_CHECK_EQUAL(MAX_MINT_PROOF_OF_WORK, 100 * COIN);
    BOOST_CHECK_EQUAL(MIN_TX_FEE, CENT);
    BOOST_CHECK_EQUAL(MAX_GENESIS_BLOCK_SIZE, 1000000U);
    BOOST_CHECK_EQUAL(nNumberOfBlocksPerYear, 525960U);
    BOOST_CHECK(nInflation == 0.02);
    BOOST_CHECK_EQUAL(GetMinFee(0), 0);
    BOOST_CHECK_EQUAL(Params().GetConsensus().nStakeMinAge, 30 * DAY);
    BOOST_CHECK_EQUAL(find_value(Vectors(), "target_limits")[0].get_str(), "1e0fffff");
    BOOST_CHECK_EQUAL(find_value(Vectors(), "target_limits")[1].get_str(), "201fffff");
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(Params().GetConsensus().powLimit.GetCompact(), 0x1e0fffffU);
    BOOST_CHECK_EQUAL(Params().GetConsensus().initialMoneySupply, 0);
#else
    BOOST_CHECK_EQUAL(Params().GetConsensus().powLimit.GetCompact(), 0x201fffffU);
    BOOST_CHECK_EQUAL(Params().GetConsensus().initialMoneySupply, 100000000000000LL);
#endif
}

/* Every pre-fork row: GetProofOfWorkReward (height 0, and height 1 below the
 * mainnet fork) gives the column of this build; the copied bisection gives
 * both columns. */
BOOST_AUTO_TEST_CASE(golden_prefork_pow)
{
    globals.UseMainnetGlobals();
    const UniValue& rows = Table("prefork_pow");
    BOOST_TEST_MESSAGE("reward_tests: " << rows.size() << " pre-fork rows");
    for (size_t i = 0; i < rows.size(); ++i) {
        const UniValue& row = rows[i];
        const uint32_t nBits = Hex32(row, 0);
        BOOST_TEST_CONTEXT("nBits " << row[0].get_str())
        {
            BOOST_CHECK_EQUAL(GetProofOfWorkReward(nBits, 0, 0), Dec(row, PREFORK_COLUMN));
            BOOST_CHECK_EQUAL(GetProofOfWorkReward(nBits, 0, 1), Dec(row, PREFORK_COLUMN));
            BOOST_CHECK_EQUAL(RewardBisection(nBits, 0x1e0fffff), Dec(row, 1));
            BOOST_CHECK_EQUAL(RewardBisection(nBits, 0x201fffff), Dec(row, 2));
        }
    }
}

/* Every post-fork row (functional-test globals: epoch 10, fork 10; chain
 * 0..10, so height 11 reads the supply of height 9): reward, the three
 * max sizes and the reward LoadBlockRewardAndHighestDiff logs. */
BOOST_AUTO_TEST_CASE(golden_postfork_pow_and_max_size)
{
    globals.UseFunctionalTestGlobals(10);
    BuildChain(chain, 10);
    CBlockIndex* pindexSupply = chain.AtHeight(9);
    const UniValue& rows = Table("postfork_pow");
    for (size_t i = 0; i < rows.size(); ++i) {
        const UniValue& row = rows[i];
        pindexSupply->nMoneySupply = Dec(row, 0);
        BOOST_TEST_CONTEXT("supply " << row[0].get_str())
        {
            BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 11), Dec(row, 1));
            BOOST_CHECK_EQUAL(PostForkRewardExpr(Dec(row, 0)), Dec(row, 1));
            BOOST_CHECK_EQUAL(LoadRewardExpr(Dec(row, 0)), Dec(row, 2));
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 11), (uint64_t)Dec(row, 3));
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, 11), (uint64_t)Dec(row, 4));
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, 11), (uint64_t)Dec(row, 5));
            const std::string log = LoggedLoadReward();
            BOOST_CHECK_MESSAGE(Contains(log, "Current block reward = " + row[2].get_str() + "\n"), log);
        }
    }
}

/* The per-epoch model table: chain of 62 epochs of 10 blocks (functional
 * globals); epoch k+1 starts at 10(k+1) and reads the supply of the block
 * before it. Every height of the epoch gets row k's reward and sizes. */
BOOST_AUTO_TEST_CASE(golden_per_epoch)
{
    globals.UseFunctionalTestGlobals(10);
    const UniValue& rows = Table("epochs");
    BuildChain(chain, 10 * ((int)rows.size() + 2));
    for (size_t i = 0; i < rows.size(); ++i) {
        const UniValue& row = rows[i];
        const int nStart = 10 * ((int)Dec(row, 0) + 1);
        chain.AtHeight(nStart - 1)->nMoneySupply = Dec(row, 1);
    }
    for (size_t i = 0; i < rows.size(); ++i) {
        const UniValue& row = rows[i];
        const int nStart = 10 * ((int)Dec(row, 0) + 1);
        for (int h = nStart; h < nStart + 10; ++h) {
            BOOST_TEST_CONTEXT("epoch " << row[0].get_str() << " height " << h)
            {
                BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, h), Dec(row, 2));
                BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, h), (uint64_t)Dec(row, 4));
                BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, h), (uint64_t)Dec(row, 5));
                BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, h), (uint64_t)Dec(row, 6));
            }
        }
    }
    // LoadBlockRewardAndHighestDiff with the tip inside the last model
    // epoch logs that epoch's reward (divide-first form).
    const UniValue& last = rows[rows.size() - 1];
    chain.SetActiveTip(chain.AtHeight(10 * ((int)Dec(last, 0) + 1) + 3));
    const std::string log = LoggedLoadReward();
    BOOST_CHECK_MESSAGE(Contains(log, "Current block reward = " + last[3].get_str() + "\n"), log);
}

/* Every PoS row; nBits and nTime do not change the result. */
BOOST_AUTO_TEST_CASE(golden_pos)
{
    const UniValue& rows = Table("pos");
    for (size_t i = 0; i < rows.size(); ++i) {
        const UniValue& row = rows[i];
        BOOST_TEST_CONTEXT("coin age " << row[0].get_str())
        {
            BOOST_CHECK_EQUAL(GetProofOfStakeReward(Dec(row, 0), 0x1d00ffff, 1400000000), Dec(row, 1));
            BOOST_CHECK_EQUAL(GetProofOfStakeReward(Dec(row, 0), 0, 0), Dec(row, 1));
            BOOST_CHECK_EQUAL(GetProofOfStakeReward(Dec(row, 0), 0x1e0fffff, 4000000000LL), Dec(row, 1));
        }
    }
}

/* The -printcreation logging of GetProofOfStakeReward (needs fDebug too). */
BOOST_AUTO_TEST_CASE(pos_reward_logging)
{
    std::string log;
    int64_t nReward = 0;
    {
        ScopedArg printcreation("-printcreation", "1");
        LogCapture capture;
        nReward = GetProofOfStakeReward(365, 0x1d00ffff, 0);
        log = capture.Stop();
    }
    BOOST_CHECK_EQUAL(nReward, 49966);
    BOOST_CHECK(!Contains(log, "GetProofOfStakeReward()"));
    {
        ScopedValue<bool> debug(fDebug, true);
        LogCapture capture;
        nReward = GetProofOfStakeReward(365, 0x1d00ffff, 0);
        log = capture.Stop();
    }
    BOOST_CHECK_EQUAL(nReward, 49966);
    BOOST_CHECK(!Contains(log, "GetProofOfStakeReward()"));
    {
        ScopedValue<bool> debug(fDebug, true);
        ScopedArg printcreation("-printcreation", "1");
        LogCapture capture;
        nReward = GetProofOfStakeReward(365, 0x1d00ffff, 0);
        log = capture.Stop();
    }
    BOOST_CHECK_EQUAL(nReward, 49966);
    // nBits is printed with %d (decimal).
    BOOST_CHECK_MESSAGE(Contains(log, strprintf("GetProofOfStakeReward(): create=%s nCoinAge=365 nBits=486604799\n", FormatMoney(49966))), log);
}

/* B2: on this target both double forms equal the exact integer
 * floor(nMoneySupply / 26,298,000) for every supply 0 .. MAX_MONEY. Both
 * are monotone in the supply (each double operation rounds monotonically),
 * so checking every step point k * 26,298,000 and the value just below it
 * suffices. P0-53 runs this on the other targets (x87, ...). */
BOOST_AUTO_TEST_CASE(postfork_double_equals_integer)
{
    const int64_t STEP = 26298000; // 525960 / 0.02
    BOOST_CHECK_EQUAL(STEP, (int64_t)nNumberOfBlocksPerYear * 50);
    const int64_t kMax = MAX_MONEY / STEP + 1; // 76,051,411
    int64_t nFailures = 0;
    for (int64_t k = 1; k <= kMax; ++k) {
        const int64_t s = k * STEP;
        if (PostForkRewardExpr(s) != k || PostForkRewardExpr(s - 1) != k - 1 ||
            LoadRewardExpr(s) != k || LoadRewardExpr(s - 1) != k - 1) {
            if (++nFailures <= 10) {
                BOOST_ERROR("step " << k << ": " << PostForkRewardExpr(s) << " " << PostForkRewardExpr(s - 1)
                                    << " " << LoadRewardExpr(s) << " " << LoadRewardExpr(s - 1));
            }
        }
    }
    BOOST_CHECK_EQUAL(nFailures, 0);
    BOOST_CHECK_EQUAL(PostForkRewardExpr(0), 0);
    BOOST_CHECK_EQUAL(PostForkRewardExpr(MAX_MONEY), MAX_MONEY / STEP);
}

/* Fees, the nHeight == 0 rule and the -printcreation logging. */
BOOST_AUTO_TEST_CASE(pow_reward_fees_height_zero_and_logging)
{
    globals.UseFunctionalTestGlobals(10);
    BuildChain(chain, 10);
    chain.AtHeight(9)->nMoneySupply = 100000000000000LL;
    // Pre-fork: fees after the cap. Post-fork: fees ignored.
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1e0fffff, 7, 0), 100000007);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1d00ffff, 5 * COIN, 9), 30000000);
#else
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1e0fffff, 7, 0), 14030007);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1d00ffff, 5 * COIN, 9), 8510000);
#endif
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1d00ffff, 0, 11), 3802570);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1d00ffff, 5 * COIN, 11), 3802570);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1e0fffff, -1, 11), 3802570);
    // GetMaxSize without a height: tip (10) + 1 = 11.
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE), 380257U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, 0), 190128U);

    // nHeight 0 is pre-fork even with fork height 0 (unit-test globals).
    globals.UseUnitTestGlobals();
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1d00ffff, 0, 0), RewardBisection(0x1d00ffff, Params().GetConsensus().powLimit.GetCompact()));
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 0), CENT);
    // Height 1 with fork 0: first epoch, supply of FindBlockByHeight(-1) =
    // chainActive.Genesis() (here the own height-0 entry).
    chain.AtHeight(0)->nMoneySupply = 26298000LL * 42;
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1d00ffff, 0, 1), 42);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1d00ffff, 0, 20999), 42);
    // Height 21000: epoch start 21000, FindBlockByHeight(20999) clamps to
    // the tip (height 10).
    chain.AtHeight(10)->nMoneySupply = 26298000LL * 7;
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1d00ffff, 0, 21000), 7);

    // Logging: fDebug alone does not log; fDebug and -printcreation do.
    const int64_t nExpected = RewardBisection(0x1d00ffff, Params().GetConsensus().powLimit.GetCompact());
    std::string log;
    int64_t nReward = 0;
    {
        LogCapture capture;
        GetProofOfWorkReward(0x1d00ffff, 0, 0);
        log = capture.Stop();
    }
    BOOST_CHECK(!Contains(log, "GetProofOfWorkReward()"));
    {
        ScopedValue<bool> debug(fDebug, true);
        LogCapture capture;
        GetProofOfWorkReward(0x1d00ffff, 0, 0);
        log = capture.Stop();
    }
    BOOST_CHECK(!Contains(log, "GetProofOfWorkReward()"));
    {
        ScopedValue<bool> debug(fDebug, true);
        ScopedArg printcreation("-printcreation", "1");
        LogCapture capture;
        nReward = GetProofOfWorkReward(0x1d00ffff, 0, 0);
        log = capture.Stop();
    }
    BOOST_CHECK_EQUAL(nReward, nExpected);
    BOOST_CHECK_MESSAGE(Contains(log, "GetProofOfWorkReward() : lower=10000 upper=100000000 mid=50005000\n"), log);
    BOOST_CHECK_MESSAGE(Contains(log, strprintf("nBits=0x1d00ffff nSubsidy=%d\n", nExpected)), log);
    BOOST_CHECK(!fDebug);
    BOOST_CHECK(!gArgs.GetBoolArg("-printcreation", false));
}

/* Which block's supply each height reads, at the real mainnet heights
 * (segment 1,889,990 .. 1,932,001; supply of height h = h * 26,298,000, so
 * the reward is the height the supply came from). */
BOOST_AUTO_TEST_CASE(epoch_selection_mainnet)
{
    globals.UseMainnetGlobals();
    BlockSpec first(1600000000, 0x1c00ffff);
    first.nHeight = 1889990;
    chain.Append(nullptr, first);
    chain.AppendMany(1932001 - 1889990, 60, 0x1c00ffff);
    for (int h = 1889990; h <= 1932001; ++h) chain.AtHeight(h)->nMoneySupply = 26298000LL * h;
    chain.SetActiveTip(chain.Tip());

    const int64_t nPreFork = GetProofOfWorkReward(0x1c00ffff, 0, 0);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1c00ffff, 0, 1889999), nPreFork);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 1889999), 1000000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, 1889999), 500000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, 1889999), 20000U);
    const int heights[][2] = {
        {1890000, 1889999}, {1890001, 1889999}, {1910999, 1889999},
        {1911000, 1910999}, {1931999, 1910999}, {1932000, 1931999},
        {1932001, 1931999}, {1932002, 1931999},
        {1953000, 1932001}, // epoch beyond the tip: FindBlockByHeight clamps to the tip
        {4000000, 1932001},
    };
    for (const auto& hs : heights) {
        BOOST_TEST_CONTEXT("height " << hs[0])
        {
            BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1c00ffff, 0, hs[0]), hs[1]);
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, hs[0]), (uint64_t)hs[1] / 10);
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, hs[0]), (uint64_t)hs[1] / 20);
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, hs[0]), 20000U);
        }
    }
    // nHeight 0 means "tip + 1" only when chainActive has a genesis; on
    // this segment chainActive.Genesis() is null, so the height is 0 and
    // the pre-fork size is returned (consensus.cpp:23).
    BOOST_CHECK(chainActive.Genesis() == nullptr);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE), 1000000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 0), 1000000U);

    // LoadBlockRewardAndHighestDiff: the highest epoch block is 1,932,000;
    // reward from the supply of 1,931,999; minimum difficulty = 3 * target.
    const std::string log = LoggedLoadReward();
    BOOST_CHECK_MESSAGE(Contains(log, strprintf("last epoch change at block 1932000 (%s)\n", chain.AtHeight(1932000)->GetBlockHash().GetHex())), log);
    BOOST_CHECK_MESSAGE(Contains(log, "Minimum difficulty target = 0000000002fffd00\n"), log);
    BOOST_CHECK_MESSAGE(Contains(log, "Current block reward = 1931999\n"), log);
}

/* GetMaxSize before the fork and on an empty chainActive. */
BOOST_AUTO_TEST_CASE(max_size_prefork_and_empty_chain)
{
    globals.UseMainnetGlobals();
    // chainActive is the real genesis (height 0): nHeight 0 -> height 1.
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE), 1000000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN), 500000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS), 20000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 1), 1000000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 1889999), 1000000U);

    // Fork 0 and no chainActive: height 0, GetProofOfWorkReward(0, 0, 0) is
    // the pre-fork reward of target 0 (CENT), so the sizes are 1000 / 500
    // and the sigops limit 10^6 / 50.
    globals.UseUnitTestGlobals();
    chain.SetActiveTip(nullptr);
    BOOST_CHECK(chainActive.Genesis() == nullptr);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE), 1000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN), 500U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS), 20000U);
}

namespace {

/** Writes a block with time nBlockTime containing txs to the test block
 *  file and indexes every tx in pblocktree (like ConnectBlock). */
void WriteAndIndex(const std::vector<CTransaction>& txs, int64_t nBlockTime, std::vector<CDiskTxPos>* pPos = nullptr)
{
    CBlock block;
    block.nVersion = 6;
    block.nTime = nBlockTime;
    block.nBits = 0x1c00ffff;
    block.vtx = txs;
    const CDiskBlockPos blockPos = WriteBlockToTestFile(block);
    CDiskTxPos pos(blockPos, GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos>> vPos;
    for (const CTransaction& tx : block.vtx) {
        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        if (pPos) pPos->push_back(pos);
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }
    BOOST_REQUIRE(pblocktree->WriteTxIndex(vPos));
}

CTransaction PrevTx(int64_t nTime, const std::vector<CAmount>& values, uint32_t nSalt)
{
    CMutableTransaction mtx;
    mtx.nTime = nTime;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(ArithToUint256(arith_uint256(nSalt + 1)), 0);
    for (CAmount v : values) mtx.vout.push_back(CTxOut(v, CScript() << OP_TRUE));
    return CTransaction(mtx);
}

} // namespace

/* Every GetCoinAge path; inputs from a block written to disk. */
BOOST_AUTO_TEST_CASE(coin_age_paths)
{
    ScopedValue<bool> txindex(fTxIndex, true);
    const int64_t T0 = 1400000000;
    const CTransaction prev = PrevTx(T0, {1000 * COIN, COIN / 2, 1}, 1);
    const CTransaction young = PrevTx(T0 + 20 * DAY, {1000 * COIN}, 2);
    WriteAndIndex({prev}, T0);
    WriteAndIndex({young}, T0 + 20 * DAY);

    CCoinsView dummy;
    CCoinsViewCache view(&dummy);
    for (uint32_t n = 0; n < prev.vout.size(); ++n)
        view.AddCoin(COutPoint(prev.GetHash(), n), Coin(prev.vout[n], 1, false, false, prev.nTime), false);
    view.AddCoin(COutPoint(young.GetHash(), 0), Coin(young.vout[0], 2, false, false, young.nTime), false);

    CMutableTransaction spend;
    spend.nTime = T0 + 40 * DAY;
    spend.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
    auto age = [&](const CMutableTransaction& mtx, uint64_t& nCoinAge) {
        return GetCoinAge(CTransaction(mtx), view, nCoinAge);
    };
    uint64_t nCoinAge = 99;

    // One input of 1000 COIN for 40 days: 3.456e11 cent-seconds = 40000 coin-days.
    spend.vin = {CTxIn(COutPoint(prev.GetHash(), 0))};
    BOOST_CHECK(age(spend, nCoinAge));
    BOOST_CHECK_EQUAL(nCoinAge, 40000U);
    // A unit amount truncates per input (345.6 cent-seconds -> 345), and
    // the total to whole coin-days.
    spend.vin = {CTxIn(COutPoint(prev.GetHash(), 2))};
    BOOST_CHECK(age(spend, nCoinAge));
    BOOST_CHECK_EQUAL(nCoinAge, 0U);
    // Three inputs, spent 40 days + 1 s later: 345600100000 + 172800050 +
    // 345 cent-seconds = 345772900395 -> 40020 coin-days.
    spend.nTime = T0 + 40 * DAY + 1;
    spend.vin = {CTxIn(COutPoint(prev.GetHash(), 0)), CTxIn(COutPoint(prev.GetHash(), 1)), CTxIn(COutPoint(prev.GetHash(), 2))};
    BOOST_CHECK(age(spend, nCoinAge));
    BOOST_CHECK_EQUAL(nCoinAge, 40020U); // 345772900395 * 10^4 / 10^6 / 86400
    spend.nTime = T0 + 40 * DAY;
    // Younger than nStakeMinAge (block time + 30 days > tx time): skipped.
    spend.vin = {CTxIn(COutPoint(young.GetHash(), 0)), CTxIn(COutPoint(prev.GetHash(), 0))};
    BOOST_CHECK(age(spend, nCoinAge));
    BOOST_CHECK_EQUAL(nCoinAge, 40000U);
    // A coin missing from the view is skipped.
    spend.vin = {CTxIn(COutPoint(uint256S("ab"), 0)), CTxIn(COutPoint(prev.GetHash(), 0))};
    BOOST_CHECK(age(spend, nCoinAge));
    BOOST_CHECK_EQUAL(nCoinAge, 40000U);
    // Coinbase: true, age 0.
    {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vout.push_back(CTxOut(1, CScript()));
        nCoinAge = 99;
        BOOST_CHECK(age(coinbase, nCoinAge));
        BOOST_CHECK_EQUAL(nCoinAge, 0U);
    }
    // Spending before the coin's time: false.
    spend.vin = {CTxIn(COutPoint(prev.GetHash(), 0))};
    spend.nTime = T0 - 1;
    BOOST_CHECK(!age(spend, nCoinAge));
    spend.nTime = T0 + 40 * DAY;
    // -printcoinage logs per input and the total.
    {
        ScopedArg printcoinage("-printcoinage", "1");
        LogCapture capture;
        const bool fOk = age(spend, nCoinAge);
        const std::string log = capture.Stop();
        BOOST_CHECK(fOk);
        // arith_uint256::ToString() is hex: 345600000000 = 0x50775d8000,
        // 40000 = 0x9c40.
        BOOST_CHECK_MESSAGE(Contains(log, "coin age nValueIn=1000000000   nTimeDiff=3456000 bnCentSecond=" + std::string(54, '0') + "50775d8000\n"), log);
        BOOST_CHECK_MESSAGE(Contains(log, "coin age bnCoinDay=" + std::string(60, '0') + "9c40\n"), log);
    }
    // No transaction index: false.
    {
        ScopedValue<bool> noindex(fTxIndex, false);
        BOOST_CHECK(!age(spend, nCoinAge));
    }
    // In the view but not in the tx index: false.
    const CTransaction unindexed = PrevTx(T0, {COIN}, 3);
    view.AddCoin(COutPoint(unindexed.GetHash(), 0), Coin(unindexed.vout[0], 3, false, false, T0), false);
    spend.vin = {CTxIn(COutPoint(unindexed.GetHash(), 0))};
    BOOST_CHECK(!age(spend, nCoinAge));
    // Index entry pointing at the wrong transaction: txid mismatch, false.
    const CTransaction other = PrevTx(T0, {COIN}, 4);
    std::vector<CDiskTxPos> vPos;
    WriteAndIndex({other}, T0, &vPos);
    BOOST_REQUIRE(pblocktree->WriteTxIndex({std::make_pair(unindexed.GetHash(), vPos[0])}));
    BOOST_CHECK(!age(spend, nCoinAge));
    // Index entry with an offset beyond the end of the file: read error, false.
    CDiskTxPos bad = vPos[0];
    bad.nTxOffset = 10000000;
    BOOST_REQUIRE(pblocktree->WriteTxIndex({std::make_pair(unindexed.GetHash(), bad)}));
    BOOST_CHECK(!age(spend, nCoinAge));
}

/* The coinstake limit in Consensus::CheckTxInputs: reward <=
 * GetProofOfStakeReward(coin age) - GetMinFee(0) + CENT. */
BOOST_AUTO_TEST_CASE(coinstake_reward_limit)
{
    ScopedValue<bool> txindex(fTxIndex, true);
    const int64_t T0 = 1400000000;
    const CTransaction prev = PrevTx(T0, {1000 * COIN}, 5);
    WriteAndIndex({prev}, T0);
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);
    view.AddCoin(COutPoint(prev.GetHash(), 0), Coin(prev.vout[0], 1, false, false, prev.nTime), false);

    CBlockIndex index;
    index.nBits = 0x1c00ffff;
    const CAmount nLimit = 5475815 + CENT; // 40000 coin-days: 40000 * 1650000 / 12053
    BOOST_CHECK_EQUAL(GetProofOfStakeReward(40000, index.nBits, T0), 5475815);

    auto check = [&](CAmount nReward, int64_t nTime, CValidationState& state) {
        CMutableTransaction stake;
        stake.nTime = nTime;
        stake.vin = {CTxIn(COutPoint(prev.GetHash(), 0))};
        stake.vout.resize(2);
        stake.vout[0].SetEmpty();
        stake.vout[1] = CTxOut(1000 * COIN + nReward, CScript() << OP_TRUE);
        const CTransaction tx(stake);
        BOOST_REQUIRE(tx.IsCoinStake());
        return Consensus::CheckTxInputs(tx, state, view, 100, &index);
    };
    {
        CValidationState state;
        BOOST_CHECK(check(nLimit, T0 + 40 * DAY, state));
    }
    {
        CValidationState state;
        BOOST_CHECK(!check(nLimit + 1, T0 + 40 * DAY, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-coinstake-too-large");
    }
    {
        // GetCoinAge fails without the tx index.
        ScopedValue<bool> noindex(fTxIndex, false);
        CValidationState state;
        BOOST_CHECK(!check(0, T0 + 40 * DAY, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "unable to get coin age for coinstake");
    }
}

/* LoadBlockRewardAndHighestDiff: the branches not reached by the cases
 * above (functional globals, epoch 10). */
BOOST_AUTO_TEST_CASE(load_block_reward_log)
{
    // Tip below the fork: loop not entered, reward 0, minimum difficulty
    // from powLimit.
    globals.UseFunctionalTestGlobals(100);
    BuildChain(chain, 12);
    std::string log = LoggedLoadReward();
    BOOST_CHECK_MESSAGE(Contains(log, "last epoch change at block 0 (" + uint256().GetHex() + ")\n"), log);
    BOOST_CHECK_MESSAGE(Contains(log, "Current block reward = 0\n"), log);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_MESSAGE(Contains(log, "Minimum difficulty target = 00002ffffd000000\n"), log);
#else
    BOOST_CHECK_MESSAGE(Contains(log, "Minimum difficulty target = 5ffffd0000000000\n"), log);
#endif
    BOOST_CHECK(!Contains(log, "something wrong"));

    // Fork 5 (not an epoch multiple), tip 7: no epoch block above the fork.
    // GetProofOfWorkReward still uses the supply of height 4.
    globals.UseFunctionalTestGlobals(5);
    chain.AtHeight(4)->nMoneySupply = 26298000LL * 11;
    chain.SetActiveTip(chain.AtHeight(7));
    log = LoggedLoadReward();
    BOOST_CHECK_MESSAGE(Contains(log, "There is something wrong, can't find last epoch change block\n"), log);
    BOOST_CHECK_MESSAGE(Contains(log, "Current block reward = 0\n"), log);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 8), 11);

    // Fork 0, tip 5: the epoch block is the height-0 entry (pprev ==
    // nullptr), whose own supply is used. A lower nBits on one block sets
    // the minimum ease.
    globals.UseFunctionalTestGlobals(0);
    chain.AtHeight(0)->nMoneySupply = 26298000LL * 13;
    chain.AtHeight(3)->nBits = 0x1b7fffff;
    chain.SetActiveTip(chain.AtHeight(5));
    log = LoggedLoadReward();
    BOOST_CHECK_MESSAGE(Contains(log, strprintf("last epoch change at block 0 (%s)\n", chain.AtHeight(0)->GetBlockHash().GetHex())), log);
    BOOST_CHECK_MESSAGE(Contains(log, "Current block reward = 13\n"), log);
    BOOST_CHECK_MESSAGE(Contains(log, "Minimum difficulty target = 00000000017ffffd\n"), log);
    chain.AtHeight(3)->nBits = 0x1d00ffff;

    // Tip 12 with fork 0: the highest epoch block (10) wins over 0.
    chain.AtHeight(9)->nMoneySupply = 26298000LL * 17;
    chain.SetActiveTip(chain.AtHeight(12));
    log = LoggedLoadReward();
    BOOST_CHECK_MESSAGE(Contains(log, strprintf("last epoch change at block 10 (%s)\n", chain.AtHeight(10)->GetBlockHash().GetHex())), log);
    BOOST_CHECK_MESSAGE(Contains(log, "Current block reward = 17\n"), log);
}

/* getsubsidy: the target is used before the fork and ignored after it. */
BOOST_AUTO_TEST_CASE(getsubsidy_rpc)
{
    const std::string target1d00ffff = "\"00000000ffff0000000000000000000000000000000000000000000000000000\"";
    globals.UseMainnetGlobals();
    chain.StartOnExistingGenesis();
    chain.SetActiveTip(chain.Tip());
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(CallRPC("getsubsidy " + target1d00ffff).get_int64(), 25000000);
#else
    BOOST_CHECK_EQUAL(CallRPC("getsubsidy " + target1d00ffff).get_int64(), 3510000);
#endif
    BOOST_CHECK_EQUAL(CallRPC("getsubsidy").get_int64(), GetProofOfWorkReward(GetNextTargetRequired(chain.Tip(), false), 0, 1));
    // The client parses ntarget as JSON: unquoted hex is not valid JSON.
    BOOST_CHECK_THROW(CallRPC("getsubsidy 00000000ffff0000000000000000000000000000000000000000000000000000"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getsubsidy " + target1d00ffff + " 1"), std::runtime_error);
    // fHelp gives the help text as an exception.
    {
        JSONRPCRequest request;
        request.strMethod = "getsubsidy";
        request.params = UniValue(UniValue::VARR);
        request.fHelp = true;
        BOOST_CHECK_THROW(tableRPC["getsubsidy"]->actor(request), std::runtime_error);
    }

    // Post-fork (fork 0, height 1): target ignored, genesis supply.
    globals.UseUnitTestGlobals();
    const int64_t nPostFork = GetProofOfWorkReward(0, 0, 1);
    BOOST_CHECK_EQUAL(nPostFork, PostForkRewardExpr(chainActive.Genesis()->nMoneySupply));
    BOOST_CHECK_EQUAL(CallRPC("getsubsidy " + target1d00ffff).get_int64(), nPostFork);
    BOOST_CHECK_EQUAL(CallRPC("getsubsidy").get_int64(), nPostFork);
}

BOOST_AUTO_TEST_SUITE_END()
