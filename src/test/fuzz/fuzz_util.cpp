// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/fuzz/fuzz_util.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "fs.h"
#include "random.h"
#include "scheduler.h"
#include "script/sigcache.h"
#include "sync.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "txdb.h"
#include "txmempool.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"
#include "validationinterface.h"
#include "version.h"

#include <cstdlib>
#include <ios>
#include <iostream>

bool OpenInput(const FuzzBufferType& buffer, CDataStream& ds)
{
    if (buffer.size() > MAX_FUZZ_INPUT_SIZE) return false;
    ds = CDataStream(buffer, SER_NETWORK, INIT_PROTO_VERSION);
    try {
        int nVersion;
        ds >> nVersion;
        ds.SetVersion(nVersion);
    } catch (const std::ios_base::failure&) {
        return false;
    }
    return true;
}

namespace {
fs::path g_datadir;

void RemoveDataDir()
{
    boost::system::error_code ec;
    fs::remove_all(g_datadir, ec);
}

[[noreturn]] void SetUpFailed(const char* what)
{
    std::cerr << "error: fuzz node set-up: " << what << std::endl;
    std::abort();
}
} // namespace

void InitFuzzNode()
{
    static bool fDone = false;
    if (fDone) return;
    fDone = true;

    // The consensus values as the node sets them at start (init.cpp), with
    // the test networks' N-factor
    nEpochInterval = 21000;
    nDifficultyInterval = nEpochInterval;
    nFactorAtHardfork = 4;
    nMainnetNewLogicBlockNumber = 1890000;
    nTokenSupportBlockNumber = 1911210;
    SetMockTime(FUZZ_NODE_TIME);

    InitSignatureCache();
    InitScriptExecutionCache();

    g_datadir = fs::temp_directory_path() / strprintf("yacoin_fuzz_%s", GetRandHash().ToString().substr(0, 16));
    fs::create_directories(g_datadir);
    std::atexit(RemoveDataDir);
    gArgs.ForceSetArg("-datadir", g_datadir.string());
    ClearDatadirCache();

    // No thread services the scheduler: the validation callbacks wait in its
    // queue until a target runs them (FlushBackgroundCallbacks)
    static CScheduler scheduler;
    GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);

    pblocktree = new CBlockTreeDB(1 << 20, true);
    pcoinsdbview = new CCoinsViewDB(1 << 23, true);
    pcoinsTip = new CCoinsViewCache(pcoinsdbview);
    ptokensdb = new CTokensDB(1 << 20, true);
    ptokensCache = new CLRUCache<std::string, CDatabasedTokenData>(MAX_CACHE_TOKENS_SIZE);
    ptokens = new CTokensCache();

    const CChainParams& chainparams = Params();
    if (!LoadBlockIndex(chainparams)) SetUpFailed("LoadBlockIndex failed");
    if (!LoadGenesisBlock(chainparams)) SetUpFailed("LoadGenesisBlock failed");
    CValidationState state;
    if (!ActivateBestChain(state, chainparams)) SetUpFailed("ActivateBestChain failed");
    if (chainActive.Height() != 0) SetUpFailed("the genesis block is not the tip");
    GetMainSignals().FlushBackgroundCallbacks();
}

void ResetFuzzNodeMempool()
{
    mempool.clear();
    {
        LOCK(mempool.cs);
        mempool.mapDeltas.clear();
        mempool.mapTokenToHash.clear();
        mempool.mapHashToToken.clear();
    }
    mapReissuedTokens.clear();
    mapReissuedTx.clear();
    GetMainSignals().FlushBackgroundCallbacks();
}
