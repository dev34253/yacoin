// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_bitcoin.h"

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "fs.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "net_processing.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "script/sigcache.h"
#include "sync.h"
#include "util.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/signals2/connection.hpp>

void CConnmanTest::AddNode(CNode& node)
{
    LOCK(g_connman->cs_vNodes);
    g_connman->vNodes.push_back(&node);
}

void CConnmanTest::RemoveNode(CNode& node)
{
    LOCK(g_connman->cs_vNodes);
    g_connman->vNodes.erase(std::remove(g_connman->vNodes.begin(), g_connman->vNodes.end(), &node), g_connman->vNodes.end());
}

void CConnmanTest::ClearNodes()
{
    LOCK(g_connman->cs_vNodes);
    g_connman->vNodes.clear();
}

void CConnmanTest::AddNode(CConnman& connman, CNode& node)
{
    LOCK(connman.cs_vNodes);
    connman.vNodes.push_back(&node);
}

void CConnmanTest::ClearNodes(CConnman& connman)
{
    LOCK(connman.cs_vNodes);
    connman.vNodes.clear();
}

bool CConnmanTest::RunSocketHandlerUntilNotified(CConnman& connman, CClientUIInterface& ui, int& nConnections)
{
    std::mutex mutex;
    std::condition_variable cond;
    bool fNotified = false;
    int nNotified = 0;
    boost::signals2::scoped_connection connection = ui.NotifyNumConnectionsChanged.connect([&](int n) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!fNotified) {
                fNotified = true;
                nNotified = n;
            }
        }
        cond.notify_all();
    });

    connman.interruptNet.reset();
    std::thread thread(&CConnman::ThreadSocketHandler, &connman);
    bool fResult;
    {
        // A system_clock deadline, as in WaitForHTTPTest (http_test_util.h)
        std::unique_lock<std::mutex> lock(mutex);
        fResult = cond.wait_until(lock, std::chrono::system_clock::now() + std::chrono::seconds(SOCKET_HANDLER_TEST_TIMEOUT_S),
                                  [&fNotified] { return fNotified; });
    }
    connman.interruptNet();
    thread.join();
    connection.disconnect();

    std::lock_guard<std::mutex> lock(mutex);
    nConnections = nNotified;
    return fResult;
}

namespace {
/** ArgsManager offers no way to unset an argument, and its lock and maps are protected. The
 * product code stays as it is, so pointers to members formed in this derived class reach them
 * in gArgs. Only ArgGuard and ArgsSnapshot use it. */
class ArgsAccess : public ArgsManager
{
public:
    static CCriticalSection& Lock() { return gArgs.*(&ArgsAccess::cs_args); }
    static std::map<std::string, std::string>& MapArgs() { return gArgs.*(&ArgsAccess::mapArgs); }
    static std::map<std::string, std::vector<std::string> >& MapMultiArgs() { return gArgs.*(&ArgsAccess::mapMultiArgs); }
};
} // namespace

ArgGuard::ArgGuard(const std::string& arg, const std::string& value) : m_arg(arg), m_fHadArg(false), m_fHadMultiArg(false)
{
    LOCK(ArgsAccess::Lock());
    const auto it = ArgsAccess::MapArgs().find(m_arg);
    if (it != ArgsAccess::MapArgs().end()) {
        m_fHadArg = true;
        m_value = it->second;
    }
    const auto itMulti = ArgsAccess::MapMultiArgs().find(m_arg);
    if (itMulti != ArgsAccess::MapMultiArgs().end()) {
        m_fHadMultiArg = true;
        m_values = itMulti->second;
    }
    gArgs.ForceSetArg(m_arg, value);
}

ArgGuard::~ArgGuard()
{
    LOCK(ArgsAccess::Lock());
    if (m_fHadArg) {
        ArgsAccess::MapArgs()[m_arg] = m_value;
    } else {
        ArgsAccess::MapArgs().erase(m_arg);
    }
    if (m_fHadMultiArg) {
        ArgsAccess::MapMultiArgs()[m_arg] = m_values;
    } else {
        ArgsAccess::MapMultiArgs().erase(m_arg);
    }
}

ArgsSnapshot::ArgsSnapshot()
{
    LOCK(ArgsAccess::Lock());
    m_args = ArgsAccess::MapArgs();
    m_multiArgs = ArgsAccess::MapMultiArgs();
}

ArgsSnapshot::~ArgsSnapshot()
{
    LOCK(ArgsAccess::Lock());
    ArgsAccess::MapArgs() = m_args;
    ArgsAccess::MapMultiArgs() = m_multiArgs;
}

uint256 insecure_rand_seed = GetRandHash();
FastRandomContext insecure_rand_ctx(insecure_rand_seed);

extern bool fPrintToConsole;
extern void noui_connect();

BasicTestingSetup::BasicTestingSetup(const std::string& chainName)
{
        SHA256AutoDetect();
        RandomInit();
        ECC_Start();
        SetupEnvironment();
        SetupNetworking();
        InitSignatureCache();
        InitScriptExecutionCache();
        fPrintToDebugLog = false; // don't want to write to debug.log file
        fCheckBlockIndex = true;
        SelectParams(chainName);
        noui_connect();
}

BasicTestingSetup::~BasicTestingSetup()
{
        ECC_Stop();
}

TestingSetup::TestingSetup(const std::string& chainName) : BasicTestingSetup(chainName)
{
    const CChainParams& chainparams = Params();
        // Ideally we'd move all the RPC tests to the functional testing framework
        // instead of unit tests, but for now we need these here.

        RegisterAllCoreRPCCommands(tableRPC);
        ClearDatadirCache();
        pathTemp = fs::temp_directory_path() / strprintf("test_bitcoin_%lu_%i", (unsigned long)GetTime(), (int)(InsecureRandRange(100000)));
        fs::create_directories(pathTemp);
        gArgs.ForceSetArg("-datadir", pathTemp.string());

        // Note that because we don't bother running a scheduler thread here,
        // callbacks via CValidationInterface are unreliable, but that's OK,
        // our unit tests aren't testing multiple parts of the code at once.
        GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);

        mempool.setSanityCheck(1.0);
        pblocktree = new CBlockTreeDB(1 << 20, true);
        pcoinsdbview = new CCoinsViewDB(1 << 23, true);
        pcoinsTip = new CCoinsViewCache(pcoinsdbview);
        if (!LoadGenesisBlock(chainparams)) {
            throw std::runtime_error("LoadGenesisBlock failed.");
        }

        ptokens = new CTokensCache();
        {
            CValidationState state;
            if (!ActivateBestChain(state, chainparams)) {
                throw std::runtime_error("ActivateBestChain failed.");
            }
        }
        nScriptCheckThreads = 3;
        for (int i=0; i < nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
        g_connman = std::unique_ptr<CConnman>(new CConnman(0x1337, 0x1337)); // Deterministic randomness for tests.
        connman = g_connman.get();
        peerLogic.reset(new PeerLogicValidation(connman, scheduler));
}

TestingSetup::~TestingSetup()
{
        threadGroup.interrupt_all();
        threadGroup.join_all();
        GetMainSignals().FlushBackgroundCallbacks();
        GetMainSignals().UnregisterBackgroundSignalScheduler();
        g_connman.reset();
        peerLogic.reset();
        UnloadBlockIndex();
        delete pcoinsTip;
        delete pcoinsdbview;
        delete pblocktree;
        delete ptokens;
        ptokens = nullptr;
        fs::remove_all(pathTemp);
}

TestChain100Setup::TestChain100Setup() : TestingSetup(CBaseChainParams::REGTEST)
{
    // Generate a 100-block chain:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < COINBASE_MATURITY_AFTER_HARDFORK; i++)
    {
        std::vector<CTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        coinbaseTxns.push_back(b.vtx[0]);
    }
}

//
// Create a new block with just given transactions, coinbase paying to
// scriptPubKey, and try to add it to the current chain.
//
CBlock
TestChain100Setup::CreateAndProcessBlock(const std::vector<CTransaction>& txns, const CScript& scriptPubKey)
{
    const CChainParams& chainparams = Params();
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    CBlock& block = pblocktemplate->block;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    block.vtx.resize(1);
    for (const CTransaction& tx : txns)
        block.vtx.push_back(tx);
    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())) ++block.nNonce;

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    ProcessNewBlock(chainparams, shared_pblock, true, nullptr);

    CBlock result = block;
    return result;
}

TestChain100Setup::~TestChain100Setup()
{
}


CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CTransaction &txn) {
    return CTxMemPoolEntry(MakeTransactionRef(txn), nFee, nTime, nHeight,
                           spendsCoinbase, sigOpCost, lp);
}
