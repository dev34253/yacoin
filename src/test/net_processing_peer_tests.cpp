// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Peer handling of the peer-to-peer code (net_processing.cpp): the version handshake, ping and
// pong, addr and getaddr, transactions (inv, getdata, tx, orphans, mempool, feefilter), reject,
// the messages of features the node does not offer, misbehaviour scores and bans, the end of a
// peer's state (FinalizeNode), outbound peer eviction, the stale tip check, and how
// ProcessMessages treats a peer whose processing has to wait.
//
// Transactions spend coins added to the coins cache under random outpoints, so they are unique in
// the whole test binary.
//
// Initial download: the mainnet build never leaves it in the unit tests (its checkpoint estimate
// is above any test chain), the low-difficulty build leaves it with the first tip. Behaviour that
// depends on it is checked per build.

#include "amount.h"
#include "bloom.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "net.h"
#include "net_processing.h"
#include "netaddress.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "random.h"
#include "script/script.h"
#include "script/standard.h"
#include "txmempool.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"
#include "version.h"

#include "test/p2p_test_util.h"
#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <algorithm>
#include <atomic>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <string.h>

#include <boost/test/unit_test.hpp>

// Defined in net_processing.cpp without a declaration in its header
bool AddOrphanTx(const CTransactionRef& tx, NodeId peer);
void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds);

namespace {

/** TestChain100Setup's regtest chain, the token globals transaction checks read, and the
 * CConnman's buffer limits as the node sets them. Coins pay to a P2SH script whose redeem script
 * is OP_TRUE, so spending one needs no signature. */
struct PeerSetup : public TestChain100Setup, public TokenGlobalsGuard {
    CScript trueScript;
    CScript p2shTrue;

    PeerSetup()
    {
        InitP2PTestConnman(*connman);
        trueScript = CScript() << OP_TRUE;
        p2shTrue = GetScriptForDestination(CScriptID(trueScript));
    }

    ~PeerSetup()
    {
        connman->ClearBanned();
        LOCK(cs_main);
        mempool.clear();
    }

    const CBlockIndex* Tip() const
    {
        LOCK(cs_main);
        return chainActive.Tip();
    }

    int Height() const
    {
        LOCK(cs_main);
        return chainActive.Height();
    }

    /** A coin of nValue in the coins cache under a random outpoint */
    COutPoint AddCoin(CAmount nValue)
    {
        LOCK(cs_main);
        const COutPoint outpoint(GetRandHash(), 0);
        pcoinsTip->AddCoin(outpoint, Coin(CTxOut(nValue, p2shTrue), 1, false, false, (int)(GetAdjustedTime() - 600)), false);
        return outpoint;
    }

    /** Spends prevout (a P2SH-OP_TRUE output) to nOutputs outputs of nValue each */
    CTransaction Spend(const COutPoint& prevout, CAmount nValue, int nOutputs = 1) const
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = prevout;
        tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(trueScript.begin(), trueScript.end());
        for (int i = 0; i < nOutputs; i++)
            tx.vout.emplace_back(nValue, p2shTrue);
        return CTransaction(tx);
    }

    /** A valid transaction of a new coin, paying a fee of CENT */
    CTransaction NewTransaction() { return Spend(AddCoin(COIN), COIN - CENT); }

    /** Accepted to the mempool here, as if a local wallet had sent it */
    static void AcceptHere(const CTransaction& tx)
    {
        LOCK(cs_main);
        CValidationState state;
        bool fMissingInputs = false;
        BOOST_REQUIRE_MESSAGE(AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), &fMissingInputs),
                              FormatStateMessage(state));
    }

    static bool InMempool(const CTransaction& tx) { return mempool.exists(tx.GetHash()); }
};

P2PTestPeerOptions Inbound()
{
    P2PTestPeerOptions options;
    options.fInbound = true;
    return options;
}

P2PTestPeerOptions NoHandshake(bool fInbound = false)
{
    P2PTestPeerOptions options;
    options.fInbound = fInbound;
    options.fHandshake = false;
    return options;
}

P2PTestPeerOptions WithVersion(int nVersion)
{
    P2PTestPeerOptions options;
    options.nVersion = nVersion;
    return options;
}

std::string Joined(const std::vector<std::string>& words)
{
    std::string result;
    for (const std::string& word : words)
        result += (result.empty() ? "" : " ") + word;
    return result;
}

std::string ReceivedCommands(P2PTestPeer& peer) { return Joined(Commands(peer.TakeReceived())); }

/** The inventory of every message with the given command (inv, getdata or notfound), in order */
std::vector<CInv> Inventory(const std::vector<P2PTestMessage>& messages, const std::string& command)
{
    std::vector<CInv> result;
    for (const P2PTestMessage& message : WithCommand(messages, command)) {
        const std::vector<CInv> invs = message.Read<std::vector<CInv> >();
        result.insert(result.end(), invs.begin(), invs.end());
    }
    return result;
}

/** The transaction hashes of an inventory, as a set; every entry must be a transaction */
std::set<uint256> TxHashes(const std::vector<CInv>& invs)
{
    std::set<uint256> hashes;
    for (const CInv& inv : invs) {
        BOOST_CHECK_EQUAL(inv.type, (int)MSG_TX);
        hashes.insert(inv.hash);
    }
    return hashes;
}

/** The transaction hashes of an inventory, in order; every entry must be a transaction */
std::vector<uint256> TxHashList(const std::vector<CInv>& invs)
{
    std::vector<uint256> hashes;
    for (const CInv& inv : invs) {
        BOOST_CHECK_EQUAL(inv.type, (int)MSG_TX);
        hashes.push_back(inv.hash);
    }
    return hashes;
}

std::vector<CInv> TxInv(const uint256& hash) { return std::vector<CInv>{CInv(MSG_TX, hash)}; }

/** The fields of a reject message */
struct Reject {
    std::string strCommand;
    unsigned char nCode = 0;
    std::string strReason;
    uint256 hash;
};

Reject ReadReject(const P2PTestMessage& message)
{
    BOOST_CHECK_EQUAL(message.command, NetMsgType::REJECT);
    Reject reject;
    CDataStream stream = message.Stream();
    stream >> reject.strCommand >> reject.nCode >> reject.strReason;
    if (!stream.empty())
        stream >> reject.hash;
    return reject;
}

/** The single message the node sent, which must be a reject */
Reject OnlyReject(P2PTestPeer& peer)
{
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "reject");
    return ReadReject(received[0]);
}

/** The fields of a version message the node sent */
struct Version {
    int nVersion = 0;
    uint64_t nServices = 0;
    int64_t nTime = 0;
    CAddress addrYou;
    CAddress addrMe;
    uint64_t nNonce = 0;
    std::string strSubVer;
    int nStartingHeight = 0;
    bool fRelay = false;
};

Version ReadVersion(const P2PTestMessage& message)
{
    BOOST_CHECK_EQUAL(message.command, NetMsgType::VERSION);
    // A version message is written with the version of the handshake's framing
    CDataStream stream(message.payload, SER_NETWORK, INIT_PROTO_VERSION);
    Version version;
    stream >> version.nVersion >> version.nServices >> version.nTime >> version.addrYou >> version.addrMe >>
        version.nNonce >> version.strSubVer >> version.nStartingHeight >> version.fRelay;
    BOOST_CHECK(stream.empty());
    return version;
}

/** The nonce of the single ping among the messages */
uint64_t PingNonce(const std::vector<P2PTestMessage>& messages)
{
    const std::vector<P2PTestMessage> pings = WithCommand(messages, NetMsgType::PING);
    BOOST_REQUIRE_EQUAL(pings.size(), 1U);
    return pings[0].Read<uint64_t>();
}

/** A public IPv4 address (5.x.y.z) with the services and the time of the last sighting */
CAddress PublicAddress(unsigned int n, ServiceFlags services, int64_t nTime)
{
    struct in_addr s;
    const unsigned char bytes[4] = {5, (unsigned char)(n >> 16), (unsigned char)(n >> 8), (unsigned char)n};
    memcpy(&s.s_addr, bytes, 4);
    CAddress addr(CService(CNetAddr(s), Params().GetDefaultPort()), services);
    addr.nTime = nTime;
    return addr;
}

CService IPv4(unsigned char a, unsigned char b, unsigned char c, unsigned char d)
{
    struct in_addr s;
    const unsigned char bytes[4] = {a, b, c, d};
    memcpy(&s.s_addr, bytes, 4);
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

/** The addresses of every addr message, in order */
std::vector<CAddress> Addresses(const std::vector<P2PTestMessage>& messages)
{
    std::vector<CAddress> result;
    for (const P2PTestMessage& message : WithCommand(messages, NetMsgType::ADDR)) {
        const std::vector<CAddress> addrs = message.Read<std::vector<CAddress> >();
        result.insert(result.end(), addrs.begin(), addrs.end());
    }
    return result;
}

bool Contains(const std::vector<CAddress>& addrs, const CService& addr)
{
    for (const CAddress& a : addrs) {
        if ((const CService&)a == addr)
            return true;
    }
    return false;
}

bool IsBanned(PeerSetup& setup, P2PTestPeer& peer) { return setup.connman->IsBanned(peer.Node().addr); }

/** Turns the logging of a category on while it lives */
class LogCategoryOn
{
public:
    explicit LogCategoryOn(BCLog::LogFlags category) : m_saved(logCategories.load()) { logCategories |= category; }
    ~LogCategoryOn() { logCategories = m_saved; }
    LogCategoryOn(const LogCategoryOn&) = delete;
    LogCategoryOn& operator=(const LogCategoryOn&) = delete;

private:
    const uint32_t m_saved;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(net_processing_peer_tests, PeerSetup)

//
// The version handshake
//

/** An inbound peer's version is answered with the node's version and verack, and the peer's
 * version, services, starting height, relay flag and user agent are recorded; its verack completes
 * the handshake and is answered with sendheaders. The answer is the same with IP logging off. */
BOOST_AUTO_TEST_CASE(inbound_version_answered_with_version_and_verack)
{
    P2PTestValue<bool> logIPs(fLogIPs, false);
    P2PTestPeerOptions options = NoHandshake(true);
    options.nStartingHeight = 7;
    options.fRelay = false;
    P2PTestPeer peer(*peerLogic, options);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");

    peer.SendVersion();
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "version verack");
    const Version version = ReadVersion(received[0]);
    BOOST_CHECK_EQUAL(version.nVersion, PROTOCOL_VERSION);
    BOOST_CHECK_EQUAL(version.nServices, (uint64_t)peer.Node().GetLocalServices());
    BOOST_CHECK_EQUAL(version.nNonce, peer.Node().GetLocalNonce());
    BOOST_CHECK_EQUAL(version.nStartingHeight, peer.Node().GetMyStartingHeight());
    BOOST_CHECK_EQUAL(version.fRelay, ::fRelayTxes);

    CNode& node = peer.Node();
    BOOST_CHECK_EQUAL(node.nVersion, PROTOCOL_VERSION);
    BOOST_CHECK_EQUAL((uint64_t)node.nServices, (uint64_t)NODE_NETWORK);
    BOOST_CHECK_EQUAL(node.nStartingHeight, 7);
    BOOST_CHECK(!node.fRelayTxes);
    BOOST_CHECK(!node.fClient);
    BOOST_CHECK_EQUAL(node.cleanSubVer, "/p2p_test:1.0/");
    BOOST_CHECK(!node.fSuccessfullyConnected);
    BOOST_CHECK(!node.fGetAddr);

    // Nothing is sent before the handshake is complete
    peer.RunSendMessages();
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");

    peer.Send(NetMsgType::VERACK);
    BOOST_CHECK(node.fSuccessfullyConnected);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "sendheaders");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** The node sends its version to an outbound peer as soon as the connection starts; the peer's
 * version is answered with verack and getaddr; a peer without NODE_NETWORK is a client */
BOOST_AUTO_TEST_CASE(outbound_handshake)
{
    P2PTestPeerOptions options = NoHandshake();
    options.services = NODE_NONE;
    P2PTestPeer peer(*peerLogic, options);
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "version");
    BOOST_CHECK_EQUAL(ReadVersion(received[0]).nNonce, peer.Node().GetLocalNonce());

    peer.SendVersion();
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "verack getaddr");
    BOOST_CHECK(peer.Node().fGetAddr);
    BOOST_CHECK(peer.Node().fClient);

    peer.Send(NetMsgType::VERACK);
    BOOST_CHECK(peer.Node().fSuccessfullyConnected);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "sendheaders");
}

/** An outbound peer that does not offer the services the node expects from it gets a reject and
 * is disconnected; one that offers them is not */
BOOST_AUTO_TEST_CASE(outbound_peer_without_expected_services_is_disconnected)
{
    P2PTestPeerOptions options = NoHandshake();
    options.services = NODE_NONE;
    P2PTestPeer peer(*peerLogic, options);
    peer.Node().nServicesExpected = NODE_NETWORK;
    peer.TakeReceived();

    peer.SendVersion();
    const Reject reject = OnlyReject(peer);
    BOOST_CHECK_EQUAL(reject.strCommand, NetMsgType::VERSION);
    BOOST_CHECK_EQUAL(reject.nCode, REJECT_NONSTANDARD);
    BOOST_CHECK_EQUAL(reject.strReason, "Expected to offer services 00000001");
    BOOST_CHECK(peer.Node().fDisconnect);
    BOOST_CHECK_EQUAL(peer.Node().nVersion, 0);
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);

    P2PTestPeer offering(*peerLogic, NoHandshake());
    offering.Node().nServicesExpected = NODE_NETWORK;
    offering.Handshake();
    BOOST_CHECK(offering.Node().fSuccessfullyConnected);
    BOOST_CHECK(!offering.Node().fDisconnect);
}

/** A peer below the minimum protocol version gets a reject and is disconnected; a peer at it
 * completes the handshake */
BOOST_AUTO_TEST_CASE(obsolete_version_is_rejected)
{
    P2PTestPeerOptions options = NoHandshake(true);
    options.nVersion = MIN_PEER_PROTO_VERSION - 1;
    P2PTestPeer peer(*peerLogic, options);

    peer.SendVersion();
    const Reject reject = OnlyReject(peer);
    BOOST_CHECK_EQUAL(reject.strCommand, NetMsgType::VERSION);
    BOOST_CHECK_EQUAL(reject.nCode, REJECT_OBSOLETE);
    BOOST_CHECK_EQUAL(reject.strReason, strprintf("Version must be %d or greater", MIN_PEER_PROTO_VERSION));
    BOOST_CHECK(peer.Node().fDisconnect);
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);

    P2PTestPeer oldest(*peerLogic, WithVersion(MIN_PEER_PROTO_VERSION));
    BOOST_CHECK(oldest.Node().fSuccessfullyConnected);
    BOOST_CHECK(!oldest.Node().fDisconnect);
}

/** Service bits 5 and 7 marked incompatible peers until August 2018; a peer offering them today
 * completes the handshake */
BOOST_AUTO_TEST_CASE(service_bits_5_and_7_accepted)
{
    P2PTestPeerOptions options = Inbound();
    options.services = ServiceFlags(NODE_NETWORK | (1 << 5) | (1 << 7));
    P2PTestPeer peer(*peerLogic, options);
    BOOST_CHECK(peer.Node().fSuccessfullyConnected);
    BOOST_CHECK(!peer.Node().fDisconnect);
    BOOST_CHECK_EQUAL((uint64_t)peer.Node().nServices, (uint64_t)options.services);
}

/** A second version message gets a reject and scores 1, each time; the scores add up, and the
 * message that reaches -banscore disconnects and bans the peer */
BOOST_AUTO_TEST_CASE(second_version_scores_one_up_to_banscore)
{
    ArgGuard banscore("-banscore", "3");
    P2PTestPeer peer(*peerLogic);
    for (int nScore = 1; nScore <= 3; nScore++) {
        BOOST_CHECK(!peer.Node().fDisconnect);
        BOOST_CHECK(!IsBanned(*this, peer));
        peer.SendVersion();
        const Reject reject = OnlyReject(peer);
        BOOST_CHECK_EQUAL(reject.strCommand, NetMsgType::VERSION);
        BOOST_CHECK_EQUAL(reject.nCode, REJECT_DUPLICATE);
        BOOST_CHECK_EQUAL(reject.strReason, "Duplicate version message");
        BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, nScore);
    }
    BOOST_CHECK(peer.Node().fDisconnect);
    BOOST_CHECK(IsBanned(*this, peer));
    connman->ClearBanned();
    BOOST_CHECK(!IsBanned(*this, peer));
}

/** A message before the peer's version, and one after its version but before its verack, each
 * score 1 and are not processed; after the verack the same message is */
BOOST_AUTO_TEST_CASE(messages_before_handshake_score_one)
{
    P2PTestPeer peer(*peerLogic, NoHandshake(true));
    peer.Send(NetMsgType::PING, (uint64_t)1);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 1);

    peer.SendVersion();
    peer.TakeReceived();
    peer.Send(NetMsgType::PING, (uint64_t)2);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 2);

    peer.Send(NetMsgType::VERACK);
    peer.TakeReceived();
    peer.Send(NetMsgType::PING, (uint64_t)3);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "pong");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 2);
    BOOST_CHECK(!peer.Node().fDisconnect);
}

/** A feeler connection only checks that the address answers: it is disconnected after the peer's
 * version, and nothing the peer sends after it is processed */
BOOST_AUTO_TEST_CASE(feeler_disconnected_after_version)
{
    P2PTestPeer peer(*peerLogic, NoHandshake());
    peer.Node().fFeeler = true;
    peer.TakeReceived();

    peer.SendVersion();
    BOOST_CHECK(peer.Node().fDisconnect);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "verack getaddr");

    peer.Send(NetMsgType::VERACK);
    BOOST_CHECK(!peer.Node().fSuccessfullyConnected);
    LOCK(peer.Node().cs_vProcessMsg);
    BOOST_CHECK_EQUAL(peer.Node().vProcessMsg.size(), 1U);
}

/** With -dropmessagestest=1 every message is dropped unread */
BOOST_AUTO_TEST_CASE(dropmessagestest_drops_messages)
{
    P2PTestPeer peer(*peerLogic);
    {
        ArgGuard drop("-dropmessagestest", "1");
        peer.Send(NetMsgType::PING, (uint64_t)1);
        BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");
    }
    peer.Send(NetMsgType::PING, (uint64_t)2);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "pong");
}

//
// ping and pong
//

/** A ping is answered with a pong carrying its nonce; a peer at the version before nonces
 * (BIP0031_VERSION) gets no pong */
BOOST_AUTO_TEST_CASE(ping_answered_with_pong)
{
    P2PTestPeer peer(*peerLogic);
    const uint64_t nonce = GetRand(std::numeric_limits<uint64_t>::max());
    peer.Send(NetMsgType::PING, nonce);
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "pong");
    BOOST_CHECK_EQUAL(received[0].Read<uint64_t>(), nonce);

    P2PTestPeer old(*peerLogic, WithVersion(BIP0031_VERSION));
    old.Send(NetMsgType::PING);
    BOOST_CHECK_EQUAL(ReceivedCommands(old), "");
    BOOST_CHECK(!old.Node().fDisconnect);
}

/** SendMessages pings a new peer; the matching pong finishes the ping and records its round trip
 * as the ping time and the best ping time. No new ping goes out before the ping interval, unless
 * one is requested. */
BOOST_AUTO_TEST_CASE(matching_pong_records_ping_time)
{
    P2PTestPeer peer(*peerLogic);
    CNode& node = peer.Node();
    peer.RunSendMessages();
    const uint64_t nonce = PingNonce(peer.TakeReceived());
    BOOST_CHECK(nonce != 0);
    BOOST_CHECK_EQUAL(node.nPingNonceSent, nonce);

    // The round trip is measured with the system clock (GetTimeMicros), which mock time does not
    // change; a short wait makes it positive
    MilliSleep(2);
    peer.Send(NetMsgType::PONG, nonce);
    BOOST_CHECK_EQUAL(node.nPingNonceSent, 0U);
    BOOST_CHECK(node.nPingUsecTime >= 2000);
    BOOST_CHECK_EQUAL(node.nMinPingUsecTime, node.nPingUsecTime);

    peer.RunSendMessages();
    BOOST_CHECK(WithCommand(peer.TakeReceived(), NetMsgType::PING).empty());

    node.fPingQueued = true;
    peer.RunSendMessages();
    const uint64_t requested = PingNonce(peer.TakeReceived());
    BOOST_CHECK(requested != 0);
    BOOST_CHECK_EQUAL(node.nPingNonceSent, requested);
    BOOST_CHECK(!node.fPingQueued);
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** A pong without a ping changes nothing; one with another nonce leaves the ping outstanding; a
 * nonce of 0, a payload too short for a nonce, or a pong that arrives before the ping went out by
 * the node's clock finish the ping without a ping time. None of them scores. */
BOOST_AUTO_TEST_CASE(pongs_that_do_not_match)
{
    P2PTestPeer peer(*peerLogic);
    CNode& node = peer.Node();

    peer.Send(NetMsgType::PONG, (uint64_t)5);
    BOOST_CHECK_EQUAL(node.nPingNonceSent, 0U);

    peer.RunSendMessages();
    const uint64_t nonce = PingNonce(peer.TakeReceived());
    peer.Send(NetMsgType::PONG, nonce + 1);
    BOOST_CHECK_EQUAL(node.nPingNonceSent, nonce);
    peer.Send(NetMsgType::PONG, (uint64_t)0);
    BOOST_CHECK_EQUAL(node.nPingNonceSent, 0U);

    node.fPingQueued = true;
    peer.RunSendMessages();
    const uint64_t nonce2 = PingNonce(peer.TakeReceived());
    peer.Send(NetMsgType::PONG, (uint32_t)nonce2);
    BOOST_CHECK_EQUAL(node.nPingNonceSent, 0U);

    node.fPingQueued = true;
    peer.RunSendMessages();
    const uint64_t nonce3 = PingNonce(peer.TakeReceived());
    node.nPingUsecStart = GetTimeMicros() + 60 * 1000000;
    peer.Send(NetMsgType::PONG, nonce3);
    BOOST_CHECK_EQUAL(node.nPingNonceSent, 0U);

    BOOST_CHECK_EQUAL(node.nPingUsecTime, 0);
    BOOST_CHECK_EQUAL(node.nMinPingUsecTime, std::numeric_limits<int64_t>::max());
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
    BOOST_CHECK(!node.fDisconnect);
}

//
// addr and getaddr
//

/** Of the addresses in an addr message, only routable ones with NODE_NETWORK enter the address
 * manager */
BOOST_AUTO_TEST_CASE(addr_stores_routable_addresses_with_services)
{
    P2PTestPeer peer(*peerLogic, Inbound());
    const int64_t nNow = GetAdjustedTime();
    const CAddress good = PublicAddress(1, NODE_NETWORK, nNow);
    BOOST_REQUIRE(good.IsRoutable());
    CAddress unroutable(IPv4(10, 1, 2, 3), NODE_NETWORK);
    unroutable.nTime = nNow;
    BOOST_REQUIRE(!unroutable.IsRoutable());
    const CAddress noServices = PublicAddress(2, NODE_NONE, nNow);
    BOOST_REQUIRE_EQUAL(connman->GetAddressCount(), 0U);

    peer.Send(NetMsgType::ADDR, std::vector<CAddress>{good, unroutable, noServices});
    BOOST_CHECK_EQUAL(connman->GetAddressCount(), 1U);
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
    BOOST_CHECK(!peer.Node().fDisconnect);
}

/** A recent routable address from an addr message of at most 10 entries is relayed to another
 * peer; not when the message has more entries, not an old address, and not from the answer to the
 * node's getaddr */
BOOST_AUTO_TEST_CASE(addr_relayed_to_another_peer)
{
    const int64_t nNow = GetAdjustedTime();
    P2PTestPeer other(*peerLogic, Inbound());
    {
        // An outbound peer's first addr message answers the node's getaddr
        P2PTestPeer outbound(*peerLogic);
        BOOST_REQUIRE(outbound.Node().fGetAddr);
        outbound.Send(NetMsgType::ADDR, std::vector<CAddress>{PublicAddress(10, NODE_NETWORK, nNow)});
        BOOST_CHECK(!outbound.Node().fGetAddr);
        BOOST_CHECK(other.Node().vAddrToSend.empty());
    }

    // Two peers: the address goes to both, and the sender knows it already
    P2PTestPeer sender(*peerLogic, Inbound());
    std::vector<CAddress> eleven;
    for (unsigned int i = 0; i < 11; i++)
        eleven.push_back(PublicAddress(20 + i, NODE_NETWORK, nNow));
    sender.Send(NetMsgType::ADDR, eleven);
    BOOST_CHECK(other.Node().vAddrToSend.empty());

    sender.Send(NetMsgType::ADDR, std::vector<CAddress>{PublicAddress(40, NODE_NETWORK, nNow - 60 * 60)});
    BOOST_CHECK(other.Node().vAddrToSend.empty());

    const CAddress recent = PublicAddress(50, NODE_NETWORK, nNow);
    BOOST_REQUIRE(IsReachable(recent));
    sender.Send(NetMsgType::ADDR, std::vector<CAddress>{recent});
    BOOST_REQUIRE_EQUAL(other.Node().vAddrToSend.size(), 1U);
    other.RunSendMessages();
    const std::vector<CAddress> relayed = Addresses(other.TakeReceived());
    BOOST_REQUIRE_EQUAL(relayed.size(), 1U);
    BOOST_CHECK((const CService&)relayed[0] == (const CService&)recent);
    BOOST_CHECK_EQUAL(relayed[0].nTime, recent.nTime);
    BOOST_CHECK(sender.Node().vAddrToSend.empty());
    BOOST_CHECK_EQUAL(sender.Stats().nMisbehavior, 0);
}

/** getaddr from an inbound peer is answered once, with 23 % of the known addresses; getaddr from
 * an outbound peer is not answered */
BOOST_AUTO_TEST_CASE(getaddr_answered_once_to_inbound_peer)
{
    const int64_t nNow = GetAdjustedTime();
    // Enough addresses that a second answer would almost surely hold some not sent before
    std::vector<CAddress> known;
    for (unsigned int i = 0; i < 200; i++)
        known.push_back(PublicAddress((i << 16) + 100, NODE_NETWORK, nNow));
    connman->AddNewAddresses(known, CAddress(IPv4(5, 0, 0, 1), NODE_NETWORK), 0);
    // An address whose place in the address manager's table is taken is not added
    const size_t nKnown = connman->GetAddressCount();
    BOOST_REQUIRE(nKnown >= 100);

    P2PTestPeer outbound(*peerLogic);
    outbound.Send(NetMsgType::GETADDR);
    BOOST_CHECK(outbound.Node().vAddrToSend.empty());

    P2PTestPeer peer(*peerLogic, Inbound());
    peer.Send(NetMsgType::GETADDR);
    peer.RunSendMessages();
    const std::vector<CAddress> answer = Addresses(peer.TakeReceived());
    BOOST_CHECK_EQUAL(answer.size(), 23 * nKnown / 100);
    for (const CAddress& addr : answer)
        BOOST_CHECK(Contains(known, addr));

    peer.Send(NetMsgType::GETADDR);
    BOOST_CHECK(peer.Node().vAddrToSend.empty());
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** A one-shot connection, which only asks for addresses, is disconnected after the addr answer */
BOOST_AUTO_TEST_CASE(one_shot_peer_disconnected_after_addr)
{
    P2PTestPeer peer(*peerLogic, NoHandshake());
    peer.Node().fOneShot = true;
    peer.TakeReceived();
    peer.SendVersion();
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "verack getaddr");
    peer.Send(NetMsgType::VERACK);
    BOOST_CHECK(!peer.Node().fDisconnect);

    peer.Send(NetMsgType::ADDR, std::vector<CAddress>{PublicAddress(1, NODE_NETWORK, GetAdjustedTime())});
    BOOST_CHECK(peer.Node().fDisconnect);
}

/** At most 1000 addresses wait to be sent to a peer (a further one takes the place of a random
 * one), and SendMessages sends them in addr messages of at most 1000 */
BOOST_AUTO_TEST_CASE(queued_addresses_sent_in_messages_of_at_most_1000)
{
    P2PTestPeer peer(*peerLogic, Inbound());
    const int64_t nNow = GetAdjustedTime();
    FastRandomContext insecure_rand;
    for (unsigned int i = 0; i <= MAX_ADDR_TO_SEND; i++)
        peer.Node().PushAddress(PublicAddress(i, NODE_NETWORK, nNow), insecure_rand);
    BOOST_CHECK_EQUAL(peer.Node().vAddrToSend.size(), MAX_ADDR_TO_SEND);

    peer.RunSendMessages();
    const std::vector<P2PTestMessage> addrs = WithCommand(peer.TakeReceived(), NetMsgType::ADDR);
    BOOST_REQUIRE_EQUAL(addrs.size(), 1U);
    BOOST_CHECK_EQUAL(addrs[0].Read<std::vector<CAddress> >().size(), MAX_ADDR_TO_SEND);
    BOOST_CHECK(peer.Node().vAddrToSend.empty());
}

//
// Transactions
//

/** An inv of an unknown transaction is requested only after initial download; an inv of a
 * transaction in the mempool, or of an inventory type the node does not know, is not requested */
BOOST_AUTO_TEST_CASE(inv_of_transactions)
{
    const CTransaction inPool = NewTransaction();
    AcceptHere(inPool);
    const uint256 unknown = GetRandHash();

    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::INV, std::vector<CInv>{CInv(MSG_TX, unknown), CInv(MSG_TX, inPool.GetHash()),
                                                 CInv(MSG_FILTERED_BLOCK, GetRandHash())});
    peer.RunSendMessages();
    const std::vector<CInv> requested = Inventory(peer.TakeReceived(), NetMsgType::GETDATA);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    // In initial download (always on this build in the unit tests)
    BOOST_CHECK(requested.empty());
#else
    BOOST_CHECK(TxHashes(requested) == std::set<uint256>{unknown});
#endif
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** A valid transaction from a peer enters the mempool and is announced with an inv to the other
 * peers, not to its sender and not to a peer that asked for no transaction announcements; the
 * announced transaction is served on getdata, an unknown one answered with notfound */
BOOST_AUTO_TEST_CASE(transaction_accepted_and_announced)
{
    P2PTestPeer sender(*peerLogic);
    P2PTestPeer other(*peerLogic, Inbound());
    P2PTestPeerOptions noRelay;
    noRelay.fRelay = false;
    P2PTestPeer quiet(*peerLogic, noRelay);
    const CTransaction tx = NewTransaction();

    sender.Send(NetMsgType::TX, tx);
    BOOST_CHECK(InMempool(tx));
    BOOST_CHECK(sender.Node().nLastTXTime > 0);
    BOOST_CHECK_EQUAL(sender.Stats().nMisbehavior, 0);

    other.RunSendMessages();
    BOOST_CHECK(TxHashes(Inventory(other.TakeReceived(), NetMsgType::INV)) == std::set<uint256>{tx.GetHash()});
    quiet.RunSendMessages();
    BOOST_CHECK(Inventory(quiet.TakeReceived(), NetMsgType::INV).empty());
    sender.RunSendMessages();
    BOOST_CHECK(Inventory(sender.TakeReceived(), NetMsgType::INV).empty());

    other.Send(NetMsgType::GETDATA, TxInv(tx.GetHash()));
    std::vector<P2PTestMessage> received = other.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "tx");
    BOOST_CHECK(received[0].Read<CTransaction>().GetHash() == tx.GetHash());

    const uint256 unknown = GetRandHash();
    other.Send(NetMsgType::GETDATA, TxInv(unknown));
    received = other.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "notfound");
    BOOST_CHECK(TxHashList(Inventory(received, NetMsgType::NOTFOUND)) == std::vector<uint256>{unknown});
}

/** A transaction whose input is unknown is kept as an orphan and its parent is requested from the
 * sender; when the parent arrives from another peer, both enter the mempool and are announced. A
 * parent that arrives before the request goes out is not requested. */
BOOST_AUTO_TEST_CASE(orphan_accepted_when_parent_arrives)
{
    P2PTestPeer sender(*peerLogic);
    P2PTestPeer parentSender(*peerLogic);
    P2PTestPeer other(*peerLogic, Inbound());

    const CTransaction parent = NewTransaction();
    const CTransaction child = Spend(COutPoint(parent.GetHash(), 0), COIN - 2 * CENT);
    sender.Send(NetMsgType::TX, child);
    BOOST_CHECK(!InMempool(child));
    BOOST_CHECK_EQUAL(ReceivedCommands(sender), "");
    sender.RunSendMessages();
    BOOST_CHECK(TxHashList(Inventory(sender.TakeReceived(), NetMsgType::GETDATA)) == std::vector<uint256>{parent.GetHash()});

    parentSender.Send(NetMsgType::TX, parent);
    BOOST_CHECK(InMempool(parent));
    BOOST_CHECK(InMempool(child));
    other.RunSendMessages();
    BOOST_CHECK(TxHashes(Inventory(other.TakeReceived(), NetMsgType::INV)) ==
                (std::set<uint256>{parent.GetHash(), child.GetHash()}));

    const CTransaction parent2 = NewTransaction();
    const CTransaction child2 = Spend(COutPoint(parent2.GetHash(), 0), COIN - 2 * CENT);
    sender.Send(NetMsgType::TX, child2);
    parentSender.Send(NetMsgType::TX, parent2);
    BOOST_CHECK(InMempool(child2));
    sender.RunSendMessages();
    BOOST_CHECK(Inventory(sender.TakeReceived(), NetMsgType::GETDATA).empty());
    BOOST_CHECK_EQUAL(sender.Stats().nMisbehavior, 0);
}

/** The orphans a peer sent are dropped when its connection ends: their parent arriving later does
 * not bring them into the mempool */
BOOST_AUTO_TEST_CASE(orphans_dropped_when_sender_disconnects)
{
    P2PTestPeer parentSender(*peerLogic);
    const CTransaction parent = NewTransaction();
    const CTransaction child = Spend(COutPoint(parent.GetHash(), 0), COIN - 2 * CENT);
    {
        P2PTestPeer sender(*peerLogic);
        sender.Send(NetMsgType::TX, child);
        BOOST_CHECK(!InMempool(child));
    }
    parentSender.Send(NetMsgType::TX, parent);
    BOOST_CHECK(InMempool(parent));
    BOOST_CHECK(!InMempool(child));
}

/** A transaction the mempool refuses gets a reject with the code and reason, and the score that
 * validation sets; it is remembered, so the same transaction again gets neither */
BOOST_AUTO_TEST_CASE(refused_transactions_rejected_and_scored)
{
    ArgGuard banscore("-banscore", "1000");
    P2PTestPeer peer(*peerLogic);

    CMutableTransaction version3 = Spend(AddCoin(COIN), COIN - CENT);
    version3.nVersion = 3;
    const CTransaction nonstandard(version3);
    peer.Send(NetMsgType::TX, nonstandard);
    Reject reject = OnlyReject(peer);
    BOOST_CHECK_EQUAL(reject.strCommand, NetMsgType::TX);
    BOOST_CHECK_EQUAL(reject.nCode, REJECT_NONSTANDARD);
    BOOST_CHECK_EQUAL(reject.strReason, "version");
    BOOST_CHECK(reject.hash == nonstandard.GetHash());
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);

    peer.Send(NetMsgType::TX, nonstandard);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");

    const CTransaction invalid = Spend(AddCoin(COIN), COIN + 1);
    peer.Send(NetMsgType::TX, invalid);
    reject = OnlyReject(peer);
    BOOST_CHECK_EQUAL(reject.nCode, REJECT_INVALID);
    BOOST_CHECK_EQUAL(reject.strReason, "bad-txns-in-belowout");
    BOOST_CHECK(reject.hash == invalid.GetHash());
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 100);
    BOOST_CHECK(!peer.Node().fDisconnect);
    BOOST_CHECK(!InMempool(nonstandard));
    BOOST_CHECK(!InMempool(invalid));
}

/** Orphans that turn out invalid when their parent arrives score their sender, once for all of
 * them; the parent's sender is not scored */
BOOST_AUTO_TEST_CASE(invalid_orphans_score_their_sender_once)
{
    ArgGuard banscore("-banscore", "1000");
    P2PTestPeer sender(*peerLogic);
    P2PTestPeer parentSender(*peerLogic);
    const CTransaction parent = Spend(AddCoin(COIN), (COIN - CENT) / 2, 2);
    const CTransaction invalid1 = Spend(COutPoint(parent.GetHash(), 0), COIN);
    const CTransaction invalid2 = Spend(COutPoint(parent.GetHash(), 1), COIN);
    sender.Send(NetMsgType::TX, invalid1);
    sender.Send(NetMsgType::TX, invalid2);
    BOOST_CHECK_EQUAL(sender.Stats().nMisbehavior, 0);

    parentSender.Send(NetMsgType::TX, parent);
    BOOST_CHECK(InMempool(parent));
    BOOST_CHECK(!InMempool(invalid1));
    BOOST_CHECK(!InMempool(invalid2));
    BOOST_CHECK_EQUAL(sender.Stats().nMisbehavior, 100);
    BOOST_CHECK_EQUAL(parentSender.Stats().nMisbehavior, 0);
}

/** mempool from a whitelisted peer is answered with an inv of the mempool; the peer may then get
 * those transactions, but not one that entered the mempool after its request. A peer that is not
 * whitelisted is disconnected, without a score. */
BOOST_AUTO_TEST_CASE(mempool_request)
{
    P2PTestMockTime now(GetTime());
    const CTransaction tx = NewTransaction();
    AcceptHere(tx);

    P2PTestPeerOptions whitelisted;
    whitelisted.fWhitelisted = true;
    P2PTestPeer peer(*peerLogic, whitelisted);
    peer.Send(NetMsgType::MEMPOOL);
    peer.RunSendMessages();
    BOOST_CHECK(TxHashes(Inventory(peer.TakeReceived(), NetMsgType::INV)) == std::set<uint256>{tx.GetHash()});

    now.Set(GetTime() + 1);
    const CTransaction later = NewTransaction();
    AcceptHere(later);
    peer.Send(NetMsgType::GETDATA, std::vector<CInv>{CInv(MSG_TX, tx.GetHash()), CInv(MSG_TX, later.GetHash())});
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "tx notfound");
    BOOST_CHECK(received[0].Read<CTransaction>().GetHash() == tx.GetHash());
    BOOST_CHECK(TxHashList(Inventory(received, NetMsgType::NOTFOUND)) == std::vector<uint256>{later.GetHash()});

    P2PTestPeer notWhitelisted(*peerLogic);
    notWhitelisted.Send(NetMsgType::MEMPOOL);
    BOOST_CHECK(notWhitelisted.Node().fDisconnect);
    BOOST_CHECK_EQUAL(notWhitelisted.Stats().nMisbehavior, 0);
    BOOST_CHECK(!IsBanned(*this, notWhitelisted));
}

/** A feefilter within the money range is stored and keeps transactions below it out of the peer's
 * announcements and mempool answers; a value outside the range is ignored. The node sends no
 * feefilter of its own. */
BOOST_AUTO_TEST_CASE(feefilter_filters_announcements)
{
    P2PTestPeer sender(*peerLogic);
    P2PTestPeerOptions whitelisted;
    whitelisted.fWhitelisted = true;
    P2PTestPeer above(*peerLogic, whitelisted);
    P2PTestPeer at(*peerLogic);
    P2PTestPeer negative(*peerLogic);
    P2PTestPeer tooLarge(*peerLogic);

    const CTransaction tx = NewTransaction();
    sender.Send(NetMsgType::TX, tx);
    BOOST_REQUIRE(InMempool(tx));
    const CAmount nFeeRate = mempool.info(tx.GetHash()).feeRate.GetFeePerK();
    BOOST_REQUIRE(nFeeRate > 0);

    above.Send(NetMsgType::FEEFILTER, nFeeRate + 1);
    at.Send(NetMsgType::FEEFILTER, nFeeRate);
    negative.Send(NetMsgType::FEEFILTER, (CAmount)-1);
    tooLarge.Send(NetMsgType::FEEFILTER, MAX_MONEY + 1);
    BOOST_CHECK_EQUAL(above.Node().minFeeFilter, nFeeRate + 1);
    BOOST_CHECK_EQUAL(at.Node().minFeeFilter, nFeeRate);
    BOOST_CHECK_EQUAL(negative.Node().minFeeFilter, 0);
    BOOST_CHECK_EQUAL(tooLarge.Node().minFeeFilter, 0);

    std::vector<std::string> sent;
    auto announced = [&sent](P2PTestPeer& peer) {
        peer.RunSendMessages();
        const std::vector<P2PTestMessage> received = peer.TakeReceived();
        for (const std::string& command : Commands(received))
            sent.push_back(command);
        return TxHashes(Inventory(received, NetMsgType::INV));
    };
    const std::set<uint256> announcedTx{tx.GetHash()};
    BOOST_CHECK(announced(above).empty());
    BOOST_CHECK(announced(at) == announcedTx);
    BOOST_CHECK(announced(negative) == announcedTx);
    BOOST_CHECK(announced(tooLarge) == announcedTx);

    above.Send(NetMsgType::MEMPOOL);
    BOOST_CHECK(announced(above).empty());
    BOOST_CHECK(std::find(sent.begin(), sent.end(), std::string(NetMsgType::FEEFILTER)) == sent.end());
}

//
// reject and the messages of features the node does not offer
//

/** A reject message is not answered and not scored, whether the node logs it or not, and also
 * when it is too short to read */
BOOST_AUTO_TEST_CASE(reject_accepted_without_score)
{
    P2PTestPeer peer(*peerLogic);
    for (int nLogged = 0; nLogged < 2; nLogged++) {
        std::unique_ptr<LogCategoryOn> logging(nLogged ? new LogCategoryOn(BCLog::NET) : nullptr);
        peer.Send(NetMsgType::REJECT, std::string(NetMsgType::TX), REJECT_INVALID, std::string("bad-txns-in-belowout"),
                  GetRandHash());
        peer.Send(NetMsgType::REJECT, std::string(NetMsgType::VERSION), REJECT_DUPLICATE,
                  std::string("Duplicate version message"));
        peer.Send(NetMsgType::REJECT, std::string(NetMsgType::TX));
    }
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
    BOOST_CHECK(!peer.Node().fDisconnect);
}

/** The node does not offer bloom filters: filterload or filteradd from a peer at NO_BLOOM_VERSION
 * or later scores 100, so the peer is disconnected and banned; from an older peer it disconnects
 * without a score or ban */
BOOST_AUTO_TEST_CASE(bloom_filter_messages_from_peers)
{
    {
        P2PTestPeer peer(*peerLogic);
        BOOST_REQUIRE(!(peer.Node().GetLocalServices() & NODE_BLOOM));
        peer.Send(NetMsgType::FILTERLOAD, CBloomFilter());
        BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 100);
        BOOST_CHECK(peer.Node().fDisconnect);
        BOOST_CHECK(IsBanned(*this, peer));
    }
    {
        P2PTestPeer peer(*peerLogic);
        peer.Send(NetMsgType::FILTERADD, std::vector<unsigned char>{1, 2, 3});
        BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 100);
        BOOST_CHECK(peer.Node().fDisconnect);
        BOOST_CHECK(IsBanned(*this, peer));
    }
    connman->ClearBanned();
    for (int nFilterAdd = 0; nFilterAdd < 2; nFilterAdd++) {
        P2PTestPeer old(*peerLogic, WithVersion(NO_BLOOM_VERSION - 1));
        if (nFilterAdd)
            old.Send(NetMsgType::FILTERADD, std::vector<unsigned char>{1, 2, 3});
        else
            old.Send(NetMsgType::FILTERLOAD, CBloomFilter());
        BOOST_CHECK(old.Node().fDisconnect);
        BOOST_CHECK_EQUAL(old.Stats().nMisbehavior, 0);
        BOOST_CHECK(!IsBanned(*this, old));
        BOOST_CHECK_EQUAL(ReceivedCommands(old), "");
    }
}

/** filterclear from a peer is accepted without a score; the compact block messages are ignored,
 * and getdata for a filtered or compact block is not answered */
BOOST_AUTO_TEST_CASE(messages_of_features_not_offered_are_ignored)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::FILTERCLEAR);
    peer.Send(NetMsgType::SENDCMPCT, true, (uint64_t)2);
    peer.Send(NetMsgType::CMPCTBLOCK, std::vector<unsigned char>(100, 0));
    peer.Send(NetMsgType::GETBLOCKTXN, Tip()->GetBlockHash(), std::vector<unsigned char>{1, 0});
    peer.Send(NetMsgType::BLOCKTXN, Tip()->GetBlockHash(), std::vector<unsigned char>{0});
    peer.Send(NetMsgType::GETDATA, std::vector<CInv>{CInv(MSG_FILTERED_BLOCK, Tip()->GetBlockHash()),
                                                     CInv(MSG_CMPCT_BLOCK, Tip()->GetBlockHash())});
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
    BOOST_CHECK(!peer.Node().fDisconnect);
}

//
// Misbehaviour and bans
//

/** A whitelisted peer and a manual (-addnode) peer that reach -banscore stay connected and are not
 * banned; a peer at a local address is disconnected but not banned */
BOOST_AUTO_TEST_CASE(peers_not_banned)
{
    P2PTestPeerOptions whitelistedOptions;
    whitelistedOptions.fWhitelisted = true;
    P2PTestPeer whitelisted(*peerLogic, whitelistedOptions);
    P2PTestPeer manual(*peerLogic, NoHandshake());
    manual.Node().m_manual_connection = true;
    manual.Handshake();
    P2PTestPeerOptions localOptions;
    localOptions.address = IPv4(127, 0, 0, 1);
    P2PTestPeer local(*peerLogic, localOptions);
    BOOST_REQUIRE(local.Node().addr.IsLocal());

    for (P2PTestPeer* peer : {&whitelisted, &manual, &local}) {
        peer->Send(NetMsgType::FILTERLOAD, CBloomFilter());
        BOOST_CHECK_EQUAL(peer->Stats().nMisbehavior, 100);
        BOOST_CHECK(!IsBanned(*this, *peer));
    }
    BOOST_CHECK(!whitelisted.Node().fDisconnect);
    BOOST_CHECK(!manual.Node().fDisconnect);
    BOOST_CHECK(local.Node().fDisconnect);
}

//
// Peer management
//

/** FinalizeNode ends the node's state for a peer: no statistics afterwards, a score for it changes
 * nothing, its blocks in flight can be requested from another peer, and the connection time of
 * an outbound peer that completed the handshake without a score is to be updated in the address
 * manager. A score of 0 changes nothing either. */
BOOST_AUTO_TEST_CASE(finalize_node)
{
    P2PTestMockTime now(Tip()->GetBlockTime() + 60);
    const std::vector<CBlock> blocks = BuildP2PTestChain(ReadP2PTestBlock(Tip()), Height(), 2);
    std::vector<uint256> hashes;
    for (const CBlock& block : blocks)
        hashes.push_back(block.GetHash());
    auto requested = [](P2PTestPeer& peer) {
        std::vector<uint256> result;
        for (const CInv& inv : Inventory(peer.TakeReceived(), NetMsgType::GETDATA))
            result.push_back(inv.hash);
        return result;
    };

    P2PTestPeer first(*peerLogic);
    first.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    BOOST_CHECK(requested(first) == hashes);
    const NodeId id = first.Id();
    BOOST_CHECK(first.Finalize());
    CNodeStateStats stats;
    BOOST_CHECK(!GetNodeStateStats(id, stats));

    P2PTestPeer second(*peerLogic);
    {
        LOCK(cs_main);
        Misbehaving(id, 10);
        Misbehaving(second.Id(), 0);
    }
    BOOST_CHECK(!GetNodeStateStats(id, stats));
    BOOST_CHECK_EQUAL(second.Stats().nMisbehavior, 0);
    second.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    BOOST_CHECK(requested(second) == hashes);

    P2PTestPeer inbound(*peerLogic, Inbound());
    BOOST_CHECK(!inbound.Finalize());
    P2PTestPeer scored(*peerLogic);
    scored.SendVersion();
    BOOST_CHECK(!scored.Finalize());
    P2PTestPeer unfinished(*peerLogic, NoHandshake());
    BOOST_CHECK(!unfinished.Finalize());
}

/** With one outbound peer more than the target, the one whose last block announcement is the
 * oldest is disconnected, the most recent connection among equals, once it has been connected for
 * longer than MINIMUM_CONNECT_TIME; the node then stops trying an extra outbound peer. Before
 * that, the peer is kept. A protected peer is not chosen, and the chosen peer is kept while a
 * block is requested from it. */
BOOST_AUTO_TEST_CASE(extra_outbound_peer_evicted)
{
    CConnman::Options options;
    options.nMaxConnections = DEFAULT_MAX_PEER_CONNECTIONS;
    options.nMaxOutbound = MAX_OUTBOUND_CONNECTIONS;
    options.nMaxFeeler = 1;
    InitP2PTestConnman(*connman, options);
    std::vector<std::unique_ptr<P2PTestPeer> > peers;
    for (int i = 0; i < MAX_OUTBOUND_CONNECTIONS; i++)
        peers.emplace_back(new P2PTestPeer(*peerLogic));
    // Peers that are not counted
    P2PTestPeer inbound(*peerLogic, Inbound());
    P2PTestPeer manual(*peerLogic, NoHandshake());
    manual.Node().m_manual_connection = true;
    manual.Handshake();
    BOOST_CHECK_EQUAL(connman->GetExtraOutboundCount(), 0);

    peers.emplace_back(new P2PTestPeer(*peerLogic));
    BOOST_CHECK_EQUAL(connman->GetExtraOutboundCount(), 1);
    const int64_t nConnected = peers.back()->Node().nTimeConnected;
    auto disconnected = [&peers]() {
        std::vector<size_t> result;
        for (size_t i = 0; i < peers.size(); i++) {
            if (peers[i]->Node().fDisconnect)
                result.push_back(i);
        }
        return result;
    };

    connman->SetTryNewOutboundPeer(true);
    peerLogic->EvictExtraOutboundPeers(nConnected + MINIMUM_CONNECT_TIME);
    BOOST_CHECK(disconnected().empty());
    BOOST_CHECK(connman->GetTryNewOutboundPeer());

    peerLogic->EvictExtraOutboundPeers(nConnected + MINIMUM_CONNECT_TIME + 1);
    BOOST_CHECK(disconnected() == std::vector<size_t>{peers.size() - 1});
    BOOST_CHECK(!connman->GetTryNewOutboundPeer());
    BOOST_CHECK(!inbound.Node().fDisconnect);
    BOOST_CHECK(!manual.Node().fDisconnect);

    // The newest announced a block: the next newest goes
    peers.back()->Node().fDisconnect = false;
    UpdateLastBlockAnnounceTime(peers.back()->Id(), nConnected);
    peerLogic->EvictExtraOutboundPeers(nConnected + MINIMUM_CONNECT_TIME + 1);
    BOOST_CHECK(disconnected() == std::vector<size_t>{peers.size() - 2});
    peers[peers.size() - 2]->Node().fDisconnect = false;

    // The first four peers announce the tip by headers: an outbound peer whose headers reach the
    // tip's chain trust is protected, up to MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT. Their
    // announcements stay the oldest (the tip is not new), the others announced later in order of
    // connection, so the first peer that is not protected goes.
    const std::vector<CBlock> tipHeader = P2PTestHeaders({ReadP2PTestBlock(Tip())});
    for (int i = 0; i < MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT; i++)
        peers[i]->Send(NetMsgType::HEADERS, tipHeader);
    const size_t nFirstUnprotected = MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT;
    for (size_t i = nFirstUnprotected; i < peers.size(); i++)
        UpdateLastBlockAnnounceTime(peers[i]->Id(), nConnected + i);
    peerLogic->EvictExtraOutboundPeers(nConnected + MINIMUM_CONNECT_TIME + 1);
    BOOST_CHECK(disconnected() == std::vector<size_t>{nFirstUnprotected});
    peers[nFirstUnprotected]->Node().fDisconnect = false;

    // That peer announces a new block by headers and is asked for it; the others announce later
    // still. It is the oldest again, and kept while the block is requested from it.
    {
        P2PTestMockTime now(Tip()->GetBlockTime() + 60);
        P2PTestPeer& requested = *peers[nFirstUnprotected];
        requested.Send(NetMsgType::HEADERS, P2PTestHeaders(BuildP2PTestChain(ReadP2PTestBlock(Tip()), Height(), 1)));
        BOOST_REQUIRE_EQUAL(requested.Stats().vHeightInFlight.size(), 1U);
        for (size_t i = nFirstUnprotected + 1; i < peers.size(); i++)
            UpdateLastBlockAnnounceTime(peers[i]->Id(), GetTime() + 1000);
    }
    connman->SetTryNewOutboundPeer(true);
    peerLogic->EvictExtraOutboundPeers(nConnected + MINIMUM_CONNECT_TIME + 1);
    BOOST_CHECK(disconnected().empty());
    BOOST_CHECK(connman->GetTryNewOutboundPeer());
}

/** The stale tip check runs at most every STALE_CHECK_INTERVAL: a tip not updated for three block
 * intervals lets the node try an extra outbound peer, a recent one withdraws it */
BOOST_AUTO_TEST_CASE(stale_tip_check)
{
    const int64_t nSpacing3 = Params().GetConsensus().nPowTargetSpacing * 3;
    // A start in the past, so that the last tip update this case leaves is old for later cases
    const int64_t nStart = GetTime() - 100000;
    P2PTestMockTime now(nStart);
    const std::shared_ptr<const CBlock> tipBlock = std::make_shared<const CBlock>(ReadP2PTestBlock(Tip()));
    peerLogic->BlockConnected(tipBlock, Tip(), {});
    connman->SetTryNewOutboundPeer(false);

    now.Set(nStart + nSpacing3);
    peerLogic->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK(!connman->GetTryNewOutboundPeer());

    // Not before the next check time
    now.Set(nStart + nSpacing3 + STALE_CHECK_INTERVAL);
    peerLogic->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK(!connman->GetTryNewOutboundPeer());

    now.Set(nStart + nSpacing3 + STALE_CHECK_INTERVAL + 1);
    peerLogic->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK(connman->GetTryNewOutboundPeer());

    const int64_t nNextCheck = nStart + nSpacing3 + 2 * STALE_CHECK_INTERVAL + 1;
    now.Set(nNextCheck - 1);
    peerLogic->BlockConnected(tipBlock, Tip(), {});
    now.Set(nNextCheck);
    peerLogic->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK(connman->GetTryNewOutboundPeer());

    now.Set(nNextCheck + 1);
    peerLogic->CheckForStaleTipAndEvictPeers();
    BOOST_CHECK(!connman->GetTryNewOutboundPeer());
}

/** A connected block drops the orphans that spend an outpoint one of its transactions spends, also
 * an orphan of which it spends two */
BOOST_AUTO_TEST_CASE(connected_block_drops_conflicting_orphans)
{
    P2PTestPeer peer(*peerLogic);
    CMutableTransaction orphan;
    orphan.vin.resize(2);
    orphan.vin[0].prevout = COutPoint(GetRandHash(), 0);
    orphan.vin[1].prevout = COutPoint(GetRandHash(), 1);
    orphan.vout.emplace_back(COIN, p2shTrue);
    const CTransactionRef orphanRef = MakeTransactionRef(orphan);
    {
        LOCK(cs_main);
        BOOST_CHECK(AddOrphanTx(orphanRef, peer.Id()));
        BOOST_CHECK(!AddOrphanTx(orphanRef, peer.Id()));
    }

    CMutableTransaction spend;
    spend.vin.resize(2);
    spend.vin[0].prevout = orphan.vin[0].prevout;
    spend.vin[1].prevout = orphan.vin[1].prevout;
    spend.vout.emplace_back(COIN, p2shTrue);
    CBlock block = ReadP2PTestBlock(Tip());
    block.vtx.push_back(CTransaction(spend));
    peerLogic->BlockConnected(std::make_shared<const CBlock>(block), Tip(), {});

    LOCK(cs_main);
    // Stored again, as it was dropped; the peer's end drops it again
    BOOST_CHECK(AddOrphanTx(orphanRef, peer.Id()));
}

/** With no best header known, SendMessages takes the tip as the best header */
BOOST_AUTO_TEST_CASE(send_messages_starts_best_header_at_tip)
{
    P2PTestPeer peer(*peerLogic);
    P2PTestValue<CBlockIndex*> bestHeader(pindexBestHeader, nullptr);
    peer.RunSendMessages();
    LOCK(cs_main);
    BOOST_CHECK(pindexBestHeader == chainActive.Tip());
}

//
// ProcessMessages
//

/** While the peer's send buffer is full, its messages wait, also the rest of a getdata request */
BOOST_AUTO_TEST_CASE(processing_waits_while_send_buffer_is_full)
{
    P2PTestPeer peer(*peerLogic);
    std::atomic<bool> interrupt(false);
    CNode& node = peer.Node();

    node.fPauseSend = true;
    peer.Queue(CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::PING, (uint64_t)1));
    BOOST_CHECK(!peerLogic->ProcessMessages(&node, interrupt));
    {
        LOCK(node.cs_vProcessMsg);
        BOOST_CHECK_EQUAL(node.vProcessMsg.size(), 1U);
    }
    node.fPauseSend = false;
    peer.ProcessAll();
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "pong");

    const std::vector<CInv> request{CInv(MSG_BLOCK, Tip()->GetBlockHash()), CInv(MSG_BLOCK, Tip()->pprev->GetBlockHash())};
    peer.Queue(CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETDATA, request));
    peerLogic->ProcessMessages(&node, interrupt);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "block");
    node.fPauseSend = true;
    BOOST_CHECK(peerLogic->ProcessMessages(&node, interrupt));
    BOOST_CHECK_EQUAL(node.vRecvGetData.size(), 1U);
    node.fPauseSend = false;
    peer.ProcessAll();
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "block");
    BOOST_CHECK(received[0].Read<CBlock>().GetHash() == Tip()->pprev->GetBlockHash());
}

/** When the node is shutting down (the interrupt is set), ProcessMessages stops: a message is
 * processed but reported as the last work, and the entries of inv and addr messages and the rest
 * of a getdata request are left */
BOOST_AUTO_TEST_CASE(processing_stops_when_interrupted)
{
    P2PTestPeer peer(*peerLogic);
    std::atomic<bool> stop(true);
    std::atomic<bool> go(false);
    CNode& node = peer.Node();

    peer.Queue(CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::PING, (uint64_t)1));
    peer.Queue(CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::PING, (uint64_t)2));
    BOOST_CHECK(!peerLogic->ProcessMessages(&node, stop));
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "pong");
    peer.ProcessAll();
    peer.TakeReceived();

    peer.Queue(CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::INV, std::vector<CInv>{CInv(MSG_BLOCK, Tip()->GetBlockHash())}));
    peerLogic->ProcessMessages(&node, stop);
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, -1);

    peer.Queue(CNetMsgMaker(PROTOCOL_VERSION)
                   .Make(NetMsgType::ADDR, std::vector<CAddress>{PublicAddress(1, NODE_NETWORK, GetAdjustedTime())}));
    peerLogic->ProcessMessages(&node, stop);
    BOOST_CHECK_EQUAL(connman->GetAddressCount(), 0U);

    const std::vector<CInv> request{CInv(MSG_BLOCK, Tip()->GetBlockHash()), CInv(MSG_BLOCK, Tip()->pprev->GetBlockHash())};
    peer.Queue(CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETDATA, request));
    peerLogic->ProcessMessages(&node, go);
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "block");
    BOOST_CHECK(peerLogic->ProcessMessages(&node, stop));
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "");
    BOOST_CHECK_EQUAL(node.vRecvGetData.size(), 1U);
    peer.ProcessAll();
    BOOST_CHECK_EQUAL(ReceivedCommands(peer), "block");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** A message shorter than its content gets a reject as malformed, without a score */
BOOST_AUTO_TEST_CASE(truncated_message_rejected_as_malformed)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::PING, (uint32_t)1);
    const Reject reject = OnlyReject(peer);
    BOOST_CHECK_EQUAL(reject.strCommand, NetMsgType::PING);
    BOOST_CHECK_EQUAL(reject.nCode, REJECT_MALFORMED);
    BOOST_CHECK_EQUAL(reject.strReason, "error parsing message");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
    BOOST_CHECK(!peer.Node().fDisconnect);
}

BOOST_AUTO_TEST_SUITE_END()
