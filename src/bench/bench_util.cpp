// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench/bench_util.h"

#include "bench/bench.h"

#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "random.h"
#include "scheduler.h"
#include "script/sigcache.h"
#include "sync.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "txdb.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"
#include "validationinterface.h"

#include <cstdlib>

namespace {
fs::path g_datadir;

void RemoveDataDir()
{
    boost::system::error_code ec;
    fs::remove_all(g_datadir, ec);
}
} // namespace

const fs::path& BenchDataDir()
{
    if (g_datadir.empty()) {
        g_datadir = fs::temp_directory_path() / strprintf("yacoin_bench_%s", GetRandHash().ToString().substr(0, 16));
        fs::create_directories(g_datadir);
        std::atexit(RemoveDataDir);
        gArgs.ForceSetArg("-datadir", g_datadir.string());
        ClearDatadirCache();
    }
    return g_datadir;
}

namespace {
void SetUpNode()
{
    // The fork and token heights stay as a unit test has them; the N-factor
    // and the intervals as the node sets them at start (init.cpp)
    nEpochInterval = 21000;
    nDifficultyInterval = nEpochInterval;
    nFactorAtHardfork = 21;
    SetMockTime(BENCH_NODE_TIME);

    InitSignatureCache();
    InitScriptExecutionCache();
    BenchDataDir();

    static CScheduler scheduler;
    GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);

    pblocktree = new CBlockTreeDB(1 << 20, true);
    pcoinsdbview = new CCoinsViewDB(1 << 23, true);
    pcoinsTip = new CCoinsViewCache(pcoinsdbview);
    ptokensdb = new CTokensDB(1 << 20, true);
    ptokensCache = new CLRUCache<std::string, CDatabasedTokenData>(MAX_CACHE_TOKENS_SIZE);
    ptokens = new CTokensCache();

    const CChainParams& chainparams = Params();
    benchmark::Require(LoadBlockIndex(chainparams), "node set-up: LoadBlockIndex failed");
    benchmark::Require(LoadGenesisBlock(chainparams), "node set-up: LoadGenesisBlock failed");
    CValidationState state;
    benchmark::Require(ActivateBestChain(state, chainparams), "node set-up: ActivateBestChain failed");
    benchmark::Require(chainActive.Height() == 0, "node set-up: the genesis block is not the tip");
    GetMainSignals().FlushBackgroundCallbacks();
    {
        LOCK(cs_main);
        chainActive.Genesis()->nMoneySupply = BENCH_MONEY_SUPPLY;
    }
}
} // namespace

void InitBenchNode()
{
    // 0: not yet, 1: done, 2: failed (a half set-up node is not used again)
    static int nState = 0;
    if (nState == 1) return;
    benchmark::Require(nState == 0, "node set-up failed before");
    nState = 2;
    SetUpNode();
    nState = 1;
}
