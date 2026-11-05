// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_P2P_TEST_UTIL_H
#define YACOIN_TEST_P2P_TEST_UTIL_H

#include "net.h"
#include "net_processing.h"
#include "netmessagemaker.h"
#include "primitives/block.h"
#include "protocol.h"
#include "streams.h"
#include "version.h"

#include <memory>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/thread.hpp>

class CBlockIndex;

/**
 * Helpers for unit tests of the peer-to-peer message handling (net_processing.cpp): a test peer
 * whose messages go through the real PeerLogicValidation::ProcessMessages, the messages the node
 * sent to it, real blocks built on a given parent without processing them, and guards for the
 * globals such tests change.
 *
 * Nothing here opens a socket: a test peer's CNode has no socket, so what the node sends to it
 * stays in its send queue, where TakeReceived() reads it.
 */

/** Sets the send and receive buffer limits of a test's CConnman as the node's defaults do
 * (-maxsendbuffer, -maxreceivebuffer). Without them the first message the node sends to a peer
 * pauses the peer, and the node then processes nothing more from it. */
void InitP2PTestConnman(CConnman& connman);

/** One message the node sent to a test peer */
struct P2PTestMessage {
    std::string command;
    std::vector<unsigned char> payload;

    /** The payload as the peer reads it */
    CDataStream Stream() const;

    /** The payload read as one value */
    template <typename T>
    T Read() const
    {
        T value;
        CDataStream stream = Stream();
        stream >> value;
        return value;
    }
};

/** The messages with the given command, in the order they were sent */
std::vector<P2PTestMessage> WithCommand(const std::vector<P2PTestMessage>& messages, const std::string& command);

/** Their commands, in order */
std::vector<std::string> Commands(const std::vector<P2PTestMessage>& messages);

/** How a test peer connects */
struct P2PTestPeerOptions {
    bool fInbound = false;
    bool fWhitelisted = false;
    //! The services the peer offers in its version message; without NODE_NETWORK it is a client
    ServiceFlags services = NODE_NETWORK;
    int nVersion = PROTOCOL_VERSION;
    //! The starting height the peer reports in its version message
    int nStartingHeight = 0;
    //! Exchange version and verack on creation
    bool fHandshake = true;
    //! Listed in the CConnman's nodes, so the node's per-peer loops (ForEachNode) reach it
    bool fInConnman = true;
};

/**
 * A peer of the node under test. Creating it starts the node's state for it (InitializeNode),
 * adds it to the CConnman and, unless the options say otherwise, exchanges version and verack
 * as a peer does; the node's answers to the handshake are discarded. Destroying it removes it
 * from the CConnman, ends the node's state for it (FinalizeNode) and frees the CNode.
 *
 * Needs the CConnman of g_connman (TestingSetup's) and its PeerLogicValidation.
 */
class P2PTestPeer
{
public:
    explicit P2PTestPeer(PeerLogicValidation& peerLogic, const P2PTestPeerOptions& options = P2PTestPeerOptions());
    ~P2PTestPeer();
    P2PTestPeer(const P2PTestPeer&) = delete;
    P2PTestPeer& operator=(const P2PTestPeer&) = delete;

    CNode& Node() { return *m_node; }
    NodeId Id() const { return m_node->GetId(); }

    /** The peer's version message, then its verack; the node's answers are discarded */
    void Handshake();

    /** The peer sends a message with this command and payload; the node processes it and
     * everything queued before it */
    template <typename... Args>
    void Send(const std::string& command, Args&&... args)
    {
        SendMessage(CNetMsgMaker(m_nVersion).Make(command, std::forward<Args>(args)...));
    }

    /** The peer sends this message (framed as on the wire); the node processes it */
    void SendMessage(CSerializedNetMsg&& msg);

    /** Queues the message as the socket thread does, without processing it */
    void Queue(CSerializedNetMsg&& msg);

    /** Lets the node process the peer's messages (ProcessMessages) until none are left, which
     * includes serving the rest of a getdata request */
    void ProcessAll();

    /** Lets the node send what it has for the peer (SendMessages), once */
    void RunSendMessages();

    /** The messages the node sent to the peer since the last call, in order */
    std::vector<P2PTestMessage> TakeReceived();

    /** The node's statistics for the peer (GetNodeStateStats) */
    CNodeStateStats Stats() const;

private:
    PeerLogicValidation& m_peerLogic;
    std::unique_ptr<CNode> m_node;
    const P2PTestPeerOptions m_options;
    const int m_nVersion;
    bool m_fInConnman;
};

/** Sets a global while it lives and puts the previous value back */
template <typename T>
class P2PTestValue
{
public:
    P2PTestValue(T& ref, T value) : m_ref(ref), m_saved(ref) { m_ref = value; }
    ~P2PTestValue() { m_ref = m_saved; }
    P2PTestValue(const P2PTestValue&) = delete;
    P2PTestValue& operator=(const P2PTestValue&) = delete;

private:
    T& m_ref;
    const T m_saved;
};

/** Sets the mock time while it lives and puts the previous mock time (or none) back */
class P2PTestMockTime
{
public:
    explicit P2PTestMockTime(int64_t nTime);
    ~P2PTestMockTime();
    void Set(int64_t nTime);
    P2PTestMockTime(const P2PTestMockTime&) = delete;
    P2PTestMockTime& operator=(const P2PTestMockTime&) = delete;

private:
    const int64_t m_saved;
};

/** Sets nHashCalcThreads while it lives and runs nThreads - 1 header hash workers
 * (ThreadHashCalculation), as the node's start does; stops and joins them and puts the previous
 * value back. With nThreads above 1 the headers handler hashes the headers on the queue. */
class P2PTestHashWorkers
{
public:
    explicit P2PTestHashWorkers(int nThreads);
    ~P2PTestHashWorkers();
    P2PTestHashWorkers(const P2PTestHashWorkers&) = delete;
    P2PTestHashWorkers& operator=(const P2PTestHashWorkers&) = delete;

private:
    const int m_saved;
    boost::thread_group m_threads;
};

/** Registers a validation interface (for example the PeerLogicValidation) while it lives */
class P2PTestRegistration
{
public:
    explicit P2PTestRegistration(CValidationInterface* pinterface);
    ~P2PTestRegistration();
    P2PTestRegistration(const P2PTestRegistration&) = delete;
    P2PTestRegistration& operator=(const P2PTestRegistration&) = delete;

private:
    CValidationInterface* const m_pinterface;
};

/** The stored block of an index entry */
CBlock ReadP2PTestBlock(const CBlockIndex* pindex);

/**
 * A real proof-of-work block on prev at height nHeight (prev's height + 1), mined but not
 * processed: prev's coinbase with the new height and `extra` in its script (so that blocks on the
 * same parent differ), prev's version and target, and a time one second after prev's. Valid on
 * the regtest chain of TestChain100Setup, whose target and block reward stay the same at these
 * heights.
 */
CBlock BuildP2PTestBlock(const CBlock& prev, int nHeight, int extra = 0);

/** n such blocks, each on the one before, the first on prev at nPrevHeight + 1 */
std::vector<CBlock> BuildP2PTestChain(const CBlock& prev, int nPrevHeight, int n, int extra = 0);

/** The headers of the blocks as a headers message carries them: each header followed by an
 * empty transaction list and an empty block signature */
std::vector<CBlock> P2PTestHeaders(const std::vector<CBlock>& blocks);

#endif // YACOIN_TEST_P2P_TEST_UTIL_H
