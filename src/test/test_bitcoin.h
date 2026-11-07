// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_TEST_BITCOIN_H
#define BITCOIN_TEST_TEST_BITCOIN_H

#include "chainparamsbase.h"
#include "fs.h"
#include "key.h"
#include "pubkey.h"
#include "random.h"
#include "scheduler.h"
#include "txdb.h"
#include "txmempool.h"

#include <map>
#include <string>
#include <vector>

#include <boost/thread.hpp>

extern uint256 insecure_rand_seed;
extern FastRandomContext insecure_rand_ctx;

static inline void SeedInsecureRand(bool fDeterministic = false)
{
    if (fDeterministic) {
        insecure_rand_seed = uint256();
    } else {
        insecure_rand_seed = GetRandHash();
    }
    insecure_rand_ctx = FastRandomContext(insecure_rand_seed);
}

static inline uint32_t InsecureRand32() { return insecure_rand_ctx.rand32(); }
static inline uint256 InsecureRand256() { return insecure_rand_ctx.rand256(); }
static inline uint64_t InsecureRandBits(int bits) { return insecure_rand_ctx.randbits(bits); }
static inline uint64_t InsecureRandRange(uint64_t range) { return insecure_rand_ctx.randrange(range); }
static inline bool InsecureRandBool() { return insecure_rand_ctx.randbool(); }

/** Sets an argument of gArgs while it lives. On destruction each of gArgs's two maps gets its
 * entry for the argument back as it was before, or loses it if there was none, so an argument
 * that was unset is unset again. Both steps hold gArgs's lock. */
class ArgGuard
{
public:
    ArgGuard(const std::string& arg, const std::string& value);
    ~ArgGuard();
    ArgGuard(const ArgGuard&) = delete;
    ArgGuard& operator=(const ArgGuard&) = delete;

private:
    const std::string m_arg;
    bool m_fHadArg;
    std::string m_value;
    bool m_fHadMultiArg;
    std::vector<std::string> m_values;
};

/** Saves both maps of gArgs and puts them back on destruction, so every argument set, changed
 * or removed while it lives (for example by ParseParameters or a soft set) is as before. */
class ArgsSnapshot
{
public:
    ArgsSnapshot();
    ~ArgsSnapshot();
    ArgsSnapshot(const ArgsSnapshot&) = delete;
    ArgsSnapshot& operator=(const ArgsSnapshot&) = delete;

private:
    std::map<std::string, std::string> m_args;
    std::map<std::string, std::vector<std::string> > m_multiArgs;
};

/** While it lives, a shutdown request in the unit tests is recorded instead of ending the
 * process: StartShutdown() records it and ShutdownRequested() returns it. Reset() clears a
 * recorded request. Without one, StartShutdown() ends the process with a failure status and
 * ShutdownRequested() is false (test_bitcoin_main.cpp). One may live at a time. */
class ShutdownRequestRecorder
{
public:
    ShutdownRequestRecorder();
    ~ShutdownRequestRecorder();
    static void Reset();
    ShutdownRequestRecorder(const ShutdownRequestRecorder&) = delete;
    ShutdownRequestRecorder& operator=(const ShutdownRequestRecorder&) = delete;
};

/** Basic testing setup.
 * This just configures logging and chain parameters.
 */
struct BasicTestingSetup {
    ECCVerifyHandle globalVerifyHandle;

    BasicTestingSetup(const std::string& chainName = CBaseChainParams::MAIN);
    ~BasicTestingSetup();
};

/** Testing setup that configures a complete environment.
 * Included are data directory, coins database, script check threads setup.
 */
class CClientUIInterface;
class CConnman;
class CNode;
struct CConnmanTest {
    static void AddNode(CNode& node);
    static void RemoveNode(CNode& node);
    static void ClearNodes();

    /** The same on the given connection manager instead of g_connman. Its threads must not run. */
    static void AddNode(CConnman& connman, CNode& node);
    static void ClearNodes(CConnman& connman);

    /** Runs connman's socket handler loop on a new thread until ui, which connman was
     * initialised with (Options::uiInterface), reports the number of connections for the first
     * time; then interrupts the loop and joins the thread. nConnections gets the reported number.
     * Returns false if no report came within SOCKET_HANDLER_TEST_TIMEOUT_S; the thread is
     * interrupted and joined in that case too. */
    static bool RunSocketHandlerUntilNotified(CConnman& connman, CClientUIInterface& ui, int& nConnections);
};

/** Upper bound for the wait of CConnmanTest::RunSocketHandlerUntilNotified */
static const int SOCKET_HANDLER_TEST_TIMEOUT_S = 120;

class PeerLogicValidation;
struct TestingSetup: public BasicTestingSetup {
    CCoinsViewDB *pcoinsdbview;
    fs::path pathTemp;
    boost::thread_group threadGroup;
    CConnman* connman;
    CScheduler scheduler;
    std::unique_ptr<PeerLogicValidation> peerLogic;

    TestingSetup(const std::string& chainName = CBaseChainParams::MAIN);
    ~TestingSetup();
};

class CBlock;
class CScript;

//
// Testing fixture that pre-creates a
// 100-block REGTEST-mode block chain
//
struct TestChain100Setup : public TestingSetup {
    TestChain100Setup();

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CTransaction>& txns,
                                 const CScript& scriptPubKey);

    ~TestChain100Setup();

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

class CTxMemPoolEntry;

struct TestMemPoolEntryHelper
{
    // Default values
    CAmount nFee;
    int64_t nTime;
    unsigned int nHeight;
    bool spendsCoinbase;
    unsigned int sigOpCost;
    LockPoints lp;

    TestMemPoolEntryHelper() :
        nFee(0), nTime(0), nHeight(1),
        spendsCoinbase(false), sigOpCost(4) { }
    
    CTxMemPoolEntry FromTx(const CTransaction &tx);

    // Change the default value
    TestMemPoolEntryHelper &Fee(CAmount _fee) { nFee = _fee; return *this; }
    TestMemPoolEntryHelper &Time(int64_t _time) { nTime = _time; return *this; }
    TestMemPoolEntryHelper &Height(unsigned int _height) { nHeight = _height; return *this; }
    TestMemPoolEntryHelper &SpendsCoinbase(bool _flag) { spendsCoinbase = _flag; return *this; }
    TestMemPoolEntryHelper &SigOpsCost(unsigned int _sigopsCost) { sigOpCost = _sigopsCost; return *this; }
};

/** The fee delta stored for hash in pool, as AcceptToMemoryPool would apply it */
inline CAmount StoredDelta(const CTxMemPool& pool, const uint256& hash)
{
    CAmount nDelta = 0;
    pool.ApplyDelta(hash, nDelta);
    return nDelta;
}
#endif
