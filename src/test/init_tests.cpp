// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The start-up option handling of init.cpp: the help text (HelpMessage), the
// network options derived from others (InitParameterInteraction) and the
// options read into globals (AppInitParameterInteraction).

// The test binary defines StartShutdown(), ShutdownRequested() and g_connman
// itself (test_bitcoin_main.cpp), so in the copy of init.cpp compiled here
// these three get other names.
#define StartShutdown InitTestsStartShutdown
#define ShutdownRequested InitTestsShutdownRequested
#define g_connman init_tests_g_connman
#include "init.cpp"
#undef g_connman
#undef ShutdownRequested
#undef StartShutdown

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <algorithm>
#include <initializer_list>
#include <string>
#include <vector>

#include <boost/signals2/connection.hpp>
#include <boost/test/unit_test.hpp>

namespace {

/** Saves a global and puts its value back at the end of the case */
template <typename T>
class SavedGlobal
{
public:
    explicit SavedGlobal(T& ref) : m_ref(ref), m_saved(ref) {}
    ~SavedGlobal() { m_ref = m_saved; }
    SavedGlobal(const SavedGlobal&) = delete;
    SavedGlobal& operator=(const SavedGlobal&) = delete;

private:
    T& m_ref;
    const T m_saved;
};

/** Saves everything the three functions change and restores it after each
 * case, and records the errors and warnings they report (InitError,
 * InitWarning). */
struct InitTestingSetup : public BasicTestingSetup {
    ArgsSnapshot args;
    const std::string chain{Params().NetworkIDString()};
    ConsensusGlobalsGuard consensusGlobals;
    const uint32_t savedLogCategories{logCategories};
    const int64_t savedMockTime{GetMockTime()};
    const CScript savedCoinbaseFlags{COINBASE_FLAGS};
    SavedGlobal<bool> debug{fDebug};
    SavedGlobal<bool> checkBlockIndex{fCheckBlockIndex};
    SavedGlobal<bool> checkpointsEnabled{fCheckpointsEnabled};
    SavedGlobal<int> scriptCheckThreads{nScriptCheckThreads};
    SavedGlobal<int> hashCalcThreads{nHashCalcThreads};
    SavedGlobal<int> connectTimeout{nConnectTimeout};
    SavedGlobal<bool> requireStandard{fRequireStandard};
    SavedGlobal<int64_t> maxTipAge{nMaxTipAge};
    SavedGlobal<bool> blockHashIndex{fBlockHashIndex};
    SavedGlobal<bool> useMemoryLog{fUseMemoryLog};
    SavedGlobal<int64_t> headersDownloadTimeoutBase{HEADERS_DOWNLOAD_TIMEOUT_BASE};
    SavedGlobal<int64_t> blockDownloadTimeoutBase{BLOCK_DOWNLOAD_TIMEOUT_BASE};
    SavedGlobal<int> maxBlocksInTransitPerPeer{MAX_BLOCKS_IN_TRANSIT_PER_PEER};
    SavedGlobal<unsigned int> blockDownloadWindow{BLOCK_DOWNLOAD_WINDOW};
    SavedGlobal<unsigned int> headerBlockDifferencesTriggerGetBlocks{HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS};
    SavedGlobal<bool> testNet{fTestNet};
    SavedGlobal<bool> daemon{fDaemon};
    SavedGlobal<bool> server{fServer};
    SavedGlobal<bool> confChange{fConfChange};
    SavedGlobal<int64_t> transactionFee{nTransactionFee};
    SavedGlobal<unsigned int> txConfirmTarget{nTxConfirmTarget};
    SavedGlobal<bool> spendZeroConfChange{bSpendZeroConfChange};

    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    boost::signals2::scoped_connection messageBox;

    InitTestingSetup()
        : messageBox(uiInterface.ThreadSafeMessageBox.connect(
              [this](const std::string& message, const std::string&, unsigned int style) {
                  if ((style & CClientUIInterface::ICON_MASK) == CClientUIInterface::ICON_ERROR) {
                      errors.push_back(message);
                  } else {
                      warnings.push_back(message);
                  }
                  return false;
              }))
    {
    }

    ~InitTestingSetup()
    {
        logCategories = savedLogCategories;
        SetMockTime(savedMockTime);
        COINBASE_FLAGS = savedCoinbaseFlags;
        SelectParams(chain);
    }
};

/** Replaces all arguments of gArgs by these, as if they were the command line */
void SetArgs(std::initializer_list<std::string> args)
{
    std::vector<const char*> argv{"yacoind"};
    for (const std::string& arg : args) {
        argv.push_back(arg.c_str());
    }
    gArgs.ParseParameters(argv.size(), argv.data());
}

/** The messages, one per line, for a single comparison */
std::string Lines(const std::vector<std::string>& messages)
{
    std::string result;
    for (const std::string& message : messages) {
        result += message + "\n";
    }
    return result;
}

/** -par=0 and the default: one script-check thread per core, none on a
 * single core, at most MAX_SCRIPTCHECK_THREADS */
int ScriptCheckThreadsForCores(int nCores)
{
    if (nCores <= 1) return 0;
    return std::min(nCores, MAX_SCRIPTCHECK_THREADS);
}

// The help text. The parts that depend on the machine (the core count) or on
// the build configuration (UPnP) are made in ExpectedHelp().
const std::string HELP_OPTIONS = R"HELP(Options:

  -?
       Print this help message and exit

  -version
       Print version and exit

  -conf=<file>
       Specify configuration file (default: yacoin.conf)

  -pid=<file>
       Specify pid file (default: yacoind.pid)

)HELP";

const std::string HELP_DAEMON = R"HELP(  -daemon
       Run in the background as a daemon and accept commands

)HELP";

const std::string HELP_BEFORE_PAR = R"HELP(  -datadir=<dir>
       Specify data directory

  -blocknotify=<cmd>
       Execute command when the best block changes (%s in cmd is replaced by
       block hash)

  -blocksonly
       Whether to operate in a blocks only mode (default: 0)

  -dbcache=<n>
       Set database cache size in megabytes (default: 25)

  -loadblock=<file>
       Imports blocks from external blk000??.dat file on startup

  -maxorphantx=<n>
       Keep at most <n> unconnectable transactions in memory (default: 100)

)HELP";

const std::string HELP_BEFORE_UPNP = R"HELP(  -reindex-fast
       Rebuild chain state and block index from the blk*.dat files on disk
       without recalculating block hash

  -reindex
       Rebuild chain state and block index from the blk*.dat files on disk

  -txindex
       Maintain a full transaction index, used by the getrawtransaction rpc
       call (default: 1)

  -blockhashindex
       Maintain a block hash index, used to avoid recalculating block hash when
       reading block data from disk (default: 1)

Connection options:

  -addnode=<ip>
       Add a node to connect to and attempt to keep the connection open

  -banscore=<n>
       Threshold for disconnecting misbehaving peers (default: 100)

  -bantime=<n>
       Number of seconds to keep misbehaving peers from reconnecting (default:
       86400)

  -bind=<addr>
       Bind to given address and always listen on it. Use [host]:port notation
       for IPv6

  -connect=<ip>
       Connect only to the specified node(s); -connect=0 disables automatic
       connections

  -discover
       Discover own IP addresses (default: 1 when listening and no -externalip
       or -proxy)

  -dns
       Allow DNS lookups for -addnode, -seednode and -connect (default: 1)

  -dnsseed
       Query for peer addresses via DNS lookup, if low on addresses (default: 1
       unless -connect used)

  -externalip=<ip>
       Specify your own public address

  -forcednsseed
       Always query for peer addresses via DNS lookup (default: 0)

  -listen
       Accept connections from outside (default: 1 if no -proxy or -connect)

  -listenonion
       Automatically create Tor hidden service (default: 1)

  -maxconnections=<n>
       Maintain at most <n> connections to peers (default: 125)

  -maxreceivebuffer=<n>
       Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)

  -maxsendbuffer=<n>
       Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)

  -maxtimeadjustment
       Maximum allowed median peer time offset adjustment. Local perspective of
       time may be influenced by peers forward or backward by this
       amount. (default: 4200 seconds)

  -onion=<ip:port>
       Use separate SOCKS5 proxy to reach peers via Tor hidden services
       (default: -proxy)

  -onlynet=<net>
       Only connect to nodes in network <net> (ipv4, ipv6 or onion)

  -port=<port>
       Listen for connections on <port> (default: 7688 or testnet: 17688)

  -proxy=<ip:port>
       Connect through SOCKS5 proxy

  -proxyrandomize
       Randomize credentials for every proxy connection. This enables Tor
       stream isolation (default: 1)

  -seednode=<ip>
       Connect to a node to retrieve peer addresses, and disconnect

  -timeout=<n>
       Specify connection timeout in milliseconds (minimum: 1, default: 5000)

  -torcontrol=<ip>:<port>
       Tor control port to use if onion listening enabled (default:
       127.0.0.1:9051)

  -torpassword=<pass>
       Tor control port password (default: empty)

)HELP";

const std::string HELP_BEFORE_HASHCALCTHREADS = R"HELP(  -whitebind=<addr>
       Bind to given address and whitelist peers connecting to it. Use
       [host]:port notation for IPv6

  -whitelist=<IP address or network>
       Whitelist peers connecting from the given IP address (e.g. 1.2.3.4) or
       CIDR notated network (e.g. 1.2.3.0/24). Can be specified multiple
       times. Whitelisted peers cannot be DoS banned and their
       transactions are always relayed, even if they are already in the
       mempool, useful e.g. for a gateway

  -maxuploadtarget=<n>
       Tries to keep outbound traffic under the given target (in MiB per 24h),
       0 = no limit (default: 0)

Wallet options:

  -disablewallet
       Do not load the wallet and disable wallet RPC calls

  -keypool=<n>
       Set key pool size to <n> (default: 100)

  -paytxfee=<amt>
       Fee per KB to add to transactions you send

  -rescan
       Rescan the block chain for missing wallet transactions on startup

  -salvagewallet
       Attempt to recover private keys from a corrupt wallet on startup

  -spendzeroconfchange
       Allow to spend unconfirmed change when sending transactions (default: 1)

  -usehd
       Use hierarchical deterministic key generation (HD) after BIP32. Only has
       effect during wallet creation/first start (default: 1)

  -upgradewallet
       Upgrade wallet to latest format on startup

  -wallet=<file>
       Specify wallet file (within data directory) (default: wallet.dat)

  -walletbroadcast
       Make the wallet broadcast transactions (default: 1)

  -walletnotify=<cmd>
       Execute command when a wallet transaction changes (%s in cmd is replaced
       by TxID)

  -zapwallettxes=<mode>
       Delete all wallet transactions and only recover those parts of the
       blockchain through -rescan on startup (1 = keep tx meta data e.g.
       account owner and payment request information, 2 = drop tx meta
       data)

Wallet debugging/testing options:

  -dblogsize=<n>
       Flush wallet database activity from memory to disk log every <n>
       megabytes (default: 100)

  -flushwallet
       Run a thread to flush wallet periodically (default: 1)

  -privdb
       Sets the DB_PRIVATE flag in the wallet db environment (default: 1)

  -walletrejectlongchains
       Wallet will not create transactions that violate mempool chain limits
       (default: 0)

Debugging/Testing options:

  -uacomment=<cmt>
       Append comment to the user agent string

  -checkblocks=<n>
       How many blocks to check at startup (default: 750)

  -checklevel=<n>
       How thorough the block verification of -checkblocks is (0-6, default: 1)

  -debug=<category>
       Output debugging information (default: 0, supplying <category> is
       optional). If <category> is not supplied or if <category> = 1,
       output all debugging information. <category> can be: net, tor,
       mempool, http, bench, zmq, db, rpc, estimatefee, addrman,
       selectcoins, reindex, cmpctblock, rand, prune, proxy, mempoolrej,
       libevent, coindb, qt, leveldb.

  -logips
       Include IP addresses in debug output (default: 1)

  -logtimestamps
       Prepend debug output with timestamp (default: 1)

  -logtimemicros
       Add microsecond precision to debug timestamps (default: 0)

  -maxsigcachesize=<n>
       Limit sum of signature cache and script execution cache sizes to <n> MiB
       (default: 32)

  -maxtipage=<n>
       Maximum tip age in seconds to consider node in initial block download
       (default: 86400)

  -printtoconsole
       Send trace/debug info to console instead of debug.log file

  -printtodebugger
       Send trace/debug info to debug.log file

  -printpriority
       Log transaction fee per kB when mining blocks (default: false)

  -shrinkdebugfile
       Shrink debug.log file on client startup (default: 1 when no -debug)

RPC server options:

  -server
       Accept command line and JSON-RPC commands

  -rpcuser=<user>
       Username for JSON-RPC connections

  -rpcpassword=<pw>
       Password for JSON-RPC connections

  -rpcport=<port>
       Listen for JSON-RPC connections on <port> (default: 7687 or testnet:
       17687)

  -rpcallowip=<ip>
       Allow JSON-RPC connections from specified source. Valid for <ip> are a
       single IP (e.g. 1.2.3.4), a network/netmask (e.g.
       1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This
       option can be specified multiple times

  -rpcconnect=<ip>
       Send commands to node running on <ip> (default: 127.0.0.1)

  -rpcssl
       Use OpenSSL (https) for JSON-RPC connections

  -rpcsslcertificatechainfile=<file.cert>
       Server certificate file (default: server.cert)

  -rpcsslprivatekeyfile=<file.pem>
       Server private key (default: server.pem)

  -rpcsslciphers=<ciphers>
       Acceptable ciphers (default:
       TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)

Other options:

  -tokenindex
       Keep an index of tokens. Requires a -reindex-fast or -reindex.

  -addressindex
       Maintain a full address index, used to query for the balance, txids and
       unspent outputs for addresses. Require a -reindex-fast or
       -reindex

  -initSyncDownloadTimeout=<n>
       Headers/block download timeout in seconds (default: 600)

  -initSyncMaximumBlocksInDownloadPerPeer=<n>
       Maximum number of blocks being downloaded at a time from one peer
       (default: 500)

  -initSyncBlockDownloadWindow=<n>
       Block download windows (default: initSyncMaximumBlocksInDownloadPerPeer
       * 64)

  -initSyncTriggerGetBlocks=<n>
       When number of synced headers - number of synced blocks, send getblocks
       message to all peers to download block (default: 10000)

  -detachdb
       Detach block and address databases. Increases shutdown time (default: 0)

  -memorylog
       Use in-memory logging for block index database (default: 1)

  -testnet
       Use the test network

  -testnetnewlogicblocknumber=<number>
       New Logic starting at block = <number>

  -btcyacprovider
       Add a BTC to YAC price provider, entered as
       domain,key,argument,offset,port. For example: where the url is
       http://pubapi2.cryptsy.com/api.php?method=singlemarketdata&marketid=11
       one would enter
       pubapi2.cryptsy.com,lasttradeprice,/api.php?method=singlemarketdata&marketid=11,3,80
       . See https://www.cryptsy.com/pages/publicapi

  -usdbtcprovider
       Add a USD to BTC price provider, entered as domain,key,argument,offset.
       For example: where the url is
       http://pubapi2.cryptsy.com/api.php?method=singlemarketdata&marketid=2
       one would enter
       pubapi2.cryptsy.com,lastdata,/api.php?method=singlemarketdata&marketid=2,3,80
       . See https://www.cryptsy.com/pages/publicapi

  -confchange
       Require a confirmations for change (default: 0)

)HELP";

std::string ExpectedHelp(HelpMessageMode mode)
{
    std::string upnp;
#ifdef USE_UPNP
#if USE_UPNP
    upnp = HelpMessageOpt("-upnp", "Use UPnP to map the listening port (default: 1 when listening and no -proxy)");
#else
    upnp = HelpMessageOpt("-upnp", "Use UPnP to map the listening port (default: 0)");
#endif
#endif
    return HELP_OPTIONS + (mode == HMM_BITCOIND ? HELP_DAEMON : "") + HELP_BEFORE_PAR +
           HelpMessageOpt("-par=<n>", strprintf("Set the number of script verification threads (%d to 16, 0 = auto, "
                                                "<0 = leave that many cores free, default: 0)", -GetNumCores())) +
           HELP_BEFORE_UPNP + upnp + HELP_BEFORE_HASHCALCTHREADS +
           HelpMessageOpt("-hashcalcthreads=N", strprintf("Set the number of threads which calculate hash (maximum "
                                                          "threads = number of cpu cores, default: %d)",
                                                          (int)boost::thread::hardware_concurrency() - 1));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(init_tests, InitTestingSetup)

BOOST_AUTO_TEST_CASE(help_message_bitcoind)
{
    BOOST_CHECK_EQUAL(HelpMessage(HMM_BITCOIND), ExpectedHelp(HMM_BITCOIND));
}

BOOST_AUTO_TEST_CASE(help_message_qt)
{
    const std::string strQt = HelpMessage(HMM_BITCOIN_QT);
    BOOST_CHECK_EQUAL(strQt, ExpectedHelp(HMM_BITCOIN_QT));

    // The daemon's text is the same with -daemon added.
    std::string strDaemon = HelpMessage(HMM_BITCOIND);
    BOOST_CHECK(strQt.find("-daemon") == std::string::npos);
    const size_t nPos = strDaemon.find(HELP_DAEMON);
    BOOST_REQUIRE(nPos != std::string::npos);
    BOOST_CHECK_EQUAL(strDaemon.erase(nPos, HELP_DAEMON.size()), strQt);
}

// InitParameterInteraction sets options that are not set yet from others.

BOOST_AUTO_TEST_CASE(init_parameter_interaction_nothing_set)
{
    SetArgs({});
    InitParameterInteraction();
    for (const char* arg : {"-listen", "-dnsseed", "-upnp", "-discover", "-listenonion"}) {
        BOOST_CHECK_MESSAGE(!gArgs.IsArgSet(arg), arg);
    }
}

BOOST_AUTO_TEST_CASE(init_parameter_interaction_bind)
{
    SetArgs({"-bind=127.0.0.1"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listen", ""), "1");
    BOOST_CHECK(!gArgs.IsArgSet("-discover"));

    SetArgs({"-bind=127.0.0.1", "-listen=0"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listen", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-discover", ""), "0");
}

BOOST_AUTO_TEST_CASE(init_parameter_interaction_whitebind)
{
    SetArgs({"-whitebind=127.0.0.1"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listen", ""), "1");
}

BOOST_AUTO_TEST_CASE(init_parameter_interaction_connect)
{
    SetArgs({"-connect=127.0.0.1"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-dnsseed", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listen", ""), "0");
    // Not listening then sets the options of the next case.
    BOOST_CHECK_EQUAL(gArgs.GetArg("-upnp", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-discover", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listenonion", ""), "0");

    // Options set explicitly are kept.
    SetArgs({"-connect=127.0.0.1", "-dnsseed=1", "-listen=1"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-dnsseed", ""), "1");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listen", ""), "1");
    BOOST_CHECK(!gArgs.IsArgSet("-discover"));

    // -connect=0 counts as set.
    SetArgs({"-connect=0"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-dnsseed", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listen", ""), "0");
}

BOOST_AUTO_TEST_CASE(init_parameter_interaction_proxy)
{
    SetArgs({"-proxy=127.0.0.1:9050"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listen", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-upnp", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-discover", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listenonion", ""), "0");
    BOOST_CHECK(!gArgs.IsArgSet("-dnsseed"));
}

BOOST_AUTO_TEST_CASE(init_parameter_interaction_listen_off)
{
    SetArgs({"-listen=0"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-upnp", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-discover", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listenonion", ""), "0");
    BOOST_CHECK(!gArgs.IsArgSet("-dnsseed"));
}

BOOST_AUTO_TEST_CASE(init_parameter_interaction_externalip)
{
    SetArgs({"-externalip=1.2.3.4"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-discover", ""), "0");
    BOOST_CHECK(!gArgs.IsArgSet("-listen"));
    BOOST_CHECK(!gArgs.IsArgSet("-upnp"));
}

BOOST_AUTO_TEST_CASE(init_parameter_interaction_bind_before_connect)
{
    // -bind is handled first, so its -listen=1 stays and -connect's -listen=0
    // is not set.
    SetArgs({"-bind=127.0.0.1", "-connect=127.0.0.1"});
    InitParameterInteraction();
    BOOST_CHECK_EQUAL(gArgs.GetArg("-listen", ""), "1");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-dnsseed", ""), "0");
    BOOST_CHECK(!gArgs.IsArgSet("-discover"));
}

// AppInitParameterInteraction checks the options and reads them into globals.

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_defaults)
{
    SetMockTime(1388534400);
    SetArgs({});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(Lines(errors), "");
    BOOST_CHECK_EQUAL(Lines(warnings), "");

    BOOST_CHECK(!fDebug);
    BOOST_CHECK_EQUAL(logCategories, savedLogCategories);
    BOOST_CHECK(!fCheckBlockIndex);
    BOOST_CHECK(fCheckpointsEnabled);
    BOOST_CHECK_EQUAL(nScriptCheckThreads, ScriptCheckThreadsForCores(GetNumCores()));
    BOOST_CHECK_EQUAL(nHashCalcThreads, std::max(GetNumCores() - 1, 1));
    BOOST_CHECK_EQUAL(nConnectTimeout, DEFAULT_CONNECT_TIMEOUT);
    BOOST_CHECK(fRequireStandard);
    // Without -mocktime the mock time is set to 0, so a mock time set before is gone.
    BOOST_CHECK_EQUAL(GetMockTime(), 0);
    BOOST_CHECK_EQUAL(nMaxTipAge, DEFAULT_MAX_TIP_AGE);
    BOOST_CHECK(fBlockHashIndex);
    BOOST_CHECK(fUseMemoryLog);
    // Without -initSyncDownloadTimeout the download timeout is 900 s.
    BOOST_CHECK_EQUAL(HEADERS_DOWNLOAD_TIMEOUT_BASE, 900 * 1000000);
    BOOST_CHECK_EQUAL(BLOCK_DOWNLOAD_TIMEOUT_BASE, 900 * 1000000);
    BOOST_CHECK_EQUAL(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 500);
    BOOST_CHECK_EQUAL(BLOCK_DOWNLOAD_WINDOW, 500U * 64);
    BOOST_CHECK_EQUAL(HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS, 10000U);
    BOOST_CHECK(!fTestNet);
    BOOST_CHECK(!fDaemon);
    BOOST_CHECK(!fServer);
    BOOST_CHECK_EQUAL(nEpochInterval, 21000U);
    BOOST_CHECK_EQUAL(nDifficultyInterval, 21000U);
    BOOST_CHECK_EQUAL((int)nFactorAtHardfork, 21);
    BOOST_CHECK(!fConfChange);

    // The RPC commands are registered.
    BOOST_CHECK(tableRPC["getblockcount"] != nullptr);
#ifdef ENABLE_WALLET
    BOOST_CHECK(tableRPC["getbalance"] != nullptr);
#endif

    // Each call appends /P2SH/ to the coinbase flags.
    const std::string strP2SH = "/P2SH/";
    CScript expectedFlags = savedCoinbaseFlags;
    expectedFlags << std::vector<unsigned char>(strP2SH.begin(), strP2SH.end());
    BOOST_CHECK(COINBASE_FLAGS == expectedFlags);

    // The wallet's options.
    BOOST_CHECK_EQUAL(gArgs.GetArg("-wallet", ""), DEFAULT_WALLET_DAT);
    BOOST_CHECK_EQUAL(nTxConfirmTarget, DEFAULT_TX_CONFIRM_TARGET);
    BOOST_CHECK_EQUAL(bSpendZeroConfChange, DEFAULT_SPEND_ZEROCONF_CHANGE);

    // A second call registers no RPC command again and appends /P2SH/ once more.
    const size_t nCommands = tableRPC.listCommands().size();
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(tableRPC.listCommands().size(), nCommands);
    expectedFlags << std::vector<unsigned char>(strP2SH.begin(), strP2SH.end());
    BOOST_CHECK(COINBASE_FLAGS == expectedFlags);
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_bind_without_listen)
{
    for (const char* bind : {"-bind=127.0.0.1", "-whitebind=127.0.0.1"}) {
        errors.clear();
        SetArgs({bind, "-listen=0"});
        BOOST_CHECK(!AppInitParameterInteraction());
        BOOST_CHECK_EQUAL(Lines(errors), "Cannot set -bind or -whitebind together with -listen=0\n");
    }
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_maxconnections)
{
    // More than the system allows: reduced, with a warning.
    SetArgs({"-maxconnections=100000"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_LT(nMaxConnections, 100000);
    BOOST_CHECK_LE(nMaxConnections, (int)FD_SETSIZE - 1 - MIN_CORE_FILEDESCRIPTORS - MAX_ADDNODE_CONNECTIONS);
    BOOST_CHECK_EQUAL(Lines(warnings),
                      strprintf("Reducing -maxconnections from 100000 to %d, because of system limitations.\n", nMaxConnections));

    // A small and a negative value: no warning; a negative one gives none.
    warnings.clear();
    SetArgs({"-maxconnections=8"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(nMaxConnections, 8);
    SetArgs({"-maxconnections=-1"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(nMaxConnections, 0);
    BOOST_CHECK_EQUAL(Lines(warnings), "");
    BOOST_CHECK_EQUAL(Lines(errors), "");
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_debug)
{
    SetArgs({"-debug=net"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(logCategories, savedLogCategories | BCLog::NET);

    // -debug=0 next to categories adds none of them.
    logCategories = savedLogCategories;
    SetArgs({"-debug=0", "-debug=net"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(logCategories, savedLogCategories);
    BOOST_CHECK_EQUAL(Lines(warnings), "");

    // An unknown category is reported, the others are still added.
    SetArgs({"-debug=nosuchcategory", "-debug=net"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(logCategories, savedLogCategories | BCLog::NET);
    BOOST_CHECK_EQUAL(Lines(warnings), "Unsupported logging category -debug=nosuchcategory.\n");

    // -debug=1 turns all categories on and sets fDebug; -debugexclude removes one.
    warnings.clear();
    fDebug = false;
    SetArgs({"-debug=1", "-debugexclude=net"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK(fDebug);
    BOOST_CHECK_EQUAL(logCategories, (uint32_t)BCLog::ALL & ~(uint32_t)BCLog::NET);
    BOOST_CHECK_EQUAL(Lines(warnings), "");

    SetArgs({"-debugexclude=nosuchcategory"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK(!fDebug);
    BOOST_CHECK_EQUAL(Lines(warnings), "Unsupported logging category -debugexclude=nosuchcategory.\n");
    BOOST_CHECK_EQUAL(Lines(errors), "");
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_unsupported_options)
{
    SetArgs({"-debugnet=1"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(Lines(warnings), "Unsupported argument -debugnet ignored, use -debug=net.\n");

    warnings.clear();
    SetArgs({"-benchmark=1"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(Lines(warnings), "Unsupported argument -benchmark ignored, use -debug=bench.\n");
    BOOST_CHECK_EQUAL(Lines(errors), "");

    SetArgs({"-socks=5"});
    BOOST_CHECK(!AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(Lines(errors), "Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported.\n");

    errors.clear();
    SetArgs({"-tor=1"});
    BOOST_CHECK(!AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(Lines(errors), "Unsupported argument -tor found, use -onion.\n");
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_checkblockindex)
{
    fCheckBlockIndex = false;
    SetArgs({"-checkblockindex=1"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK(fCheckBlockIndex);
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_par)
{
    const std::vector<std::pair<std::string, int>> cases{
        {"-par=1", 0},
        {"-par=2", 2},
        {"-par=0", ScriptCheckThreadsForCores(GetNumCores())},
        {"-par=17", MAX_SCRIPTCHECK_THREADS},
        // A negative value gives no script-check threads.
        {"-par=-1", 0},
    };
    for (const auto& c : cases) {
        SetArgs({c.first});
        BOOST_CHECK(AppInitParameterInteraction());
        BOOST_CHECK_MESSAGE(nScriptCheckThreads == c.second, c.first << ": " << nScriptCheckThreads);
    }
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_hashcalcthreads)
{
    // At least one thread, at most one per core.
    const int nCores = GetNumCores();
    const std::vector<std::pair<std::string, int>> cases{
        {"-hashcalcthreads=1", 1},
        {"-hashcalcthreads=0", 1},
        {strprintf("-hashcalcthreads=%d", nCores + 1), nCores},
    };
    for (const auto& c : cases) {
        SetArgs({c.first});
        BOOST_CHECK(AppInitParameterInteraction());
        BOOST_CHECK_MESSAGE(nHashCalcThreads == c.second, c.first << ": " << nHashCalcThreads);
    }
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_timeout)
{
    const std::vector<std::pair<std::string, int>> cases{
        {"-timeout=0", DEFAULT_CONNECT_TIMEOUT},
        {"-timeout=-1", DEFAULT_CONNECT_TIMEOUT},
        {"-timeout=1", 1},
        {"-timeout=5000", 5000},
        {"-timeout=7000", 7000},
    };
    for (const auto& c : cases) {
        SetArgs({c.first});
        BOOST_CHECK(AppInitParameterInteraction());
        BOOST_CHECK_MESSAGE(nConnectTimeout == c.second, c.first << ": " << nConnectTimeout);
    }
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_acceptnonstdtxn)
{
    SetArgs({"-acceptnonstdtxn=1"});
    BOOST_CHECK(!AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(Lines(errors), "acceptnonstdtxn is not currently supported for main chain\n");

    errors.clear();
    fRequireStandard = false;
    SetArgs({"-acceptnonstdtxn=0"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK(fRequireStandard);
    BOOST_CHECK_EQUAL(Lines(errors), "");
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_other_globals)
{
    SetArgs({"-mocktime=1388534400", "-maxtipage=3600", "-memorylog=0", "-confchange=1"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(GetMockTime(), 1388534400);
    BOOST_CHECK_EQUAL(nMaxTipAge, 3600);
    BOOST_CHECK(!fUseMemoryLog);
    BOOST_CHECK(fConfChange);
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_initsync)
{
    SetArgs({"-initSyncDownloadTimeout=2"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(HEADERS_DOWNLOAD_TIMEOUT_BASE, 2 * 1000000);
    BOOST_CHECK_EQUAL(BLOCK_DOWNLOAD_TIMEOUT_BASE, 2 * 1000000);

    // The window follows the blocks per peer unless it is set.
    SetArgs({"-initSyncMaximumBlocksInDownloadPerPeer=2"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 2);
    BOOST_CHECK_EQUAL(BLOCK_DOWNLOAD_WINDOW, 128U);

    SetArgs({"-initSyncMaximumBlocksInDownloadPerPeer=2", "-initSyncBlockDownloadWindow=4"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 2);
    BOOST_CHECK_EQUAL(BLOCK_DOWNLOAD_WINDOW, 4U);
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_daemon_server)
{
    // -daemon turns the server on.
    SetArgs({"-daemon=1"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK(fDaemon);
    BOOST_CHECK(fServer);

    SetArgs({"-daemon=1", "-server=0"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK(fDaemon);
    BOOST_CHECK(fServer);

    SetArgs({"-server=1"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK(!fDaemon);
    BOOST_CHECK(fServer);
}

BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_regtest_intervals)
{
    // The values the functional tests start their nodes with.
    SelectParams(CBaseChainParams::REGTEST);
    SetArgs({"-epochinterval=10", "-nFactorAtHardfork=4"});
    BOOST_CHECK(AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(nEpochInterval, 10U);
    BOOST_CHECK_EQUAL(nDifficultyInterval, 10U);
    BOOST_CHECK_EQUAL((int)nFactorAtHardfork, 4);
    BOOST_CHECK_EQUAL(Lines(errors), "");
}

#ifdef ENABLE_WALLET
BOOST_AUTO_TEST_CASE(app_init_parameter_interaction_wallet_rejects)
{
    // The wallet's own checks run last; -confchange is not read after a failure.
    SetArgs({"-sysperms=1", "-confchange=1"});
    BOOST_CHECK(!AppInitParameterInteraction());
    BOOST_CHECK_EQUAL(Lines(errors), "-sysperms is not allowed in combination with enabled wallet functionality\n");
    BOOST_CHECK(!fConfChange);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
