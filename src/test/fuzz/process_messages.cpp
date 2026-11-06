// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The messages of one inbound peer, processed by the node's message handling
// (PeerLogicValidation::ProcessMessages) on the node of InitFuzzNode
// (fuzz_util.h).
//
// The input's first byte chooses whether the peer first completes the
// handshake (bit 0 set: a version message and a verack, as a peer of this
// version sends them). The rest is a sequence of messages, each a command
// byte (an index into the node's message types, and one command the node does
// not know), a 2-byte little-endian payload size and the payload; a size past
// the end of the input takes the rest. It sends every message type except
// headers, block, cmpctblock and blocktxn. Each message is framed with the
// main network's magic and its checksum, queued as the node queues a
// received message, and processed until the peer has nothing left to
// process or is disconnected; what the node sends to the peer is dropped.
// Each run has a new peer and a new PeerLogicValidation; after the run the
// node's address and ban lists, its list of requested transactions and its
// mempool are emptied.

#include "test/fuzz/fuzz.h"
#include "test/fuzz/fuzz_util.h"

#include "chainparams.h"
#include "clientversion.h"
#include "hash.h"
#include "net.h"
#include "net_processing.h"
#include "netaddress.h"
#include "netmessagemaker.h"
#include "protocol.h"
#include "scheduler.h"
#include "serialize.h"
#include "streams.h"
#include "sync.h"
#include "ui_interface.h"
#include "uint256.h"
#include "utiltime.h"
#include "validation.h"
#include "version.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

/** Reaches the CConnman state a run changes (a friend of CConnman) */
struct CConnmanTest {
    static void AddNode(CConnman& connman, CNode& node)
    {
        LOCK(connman.cs_vNodes);
        connman.vNodes.push_back(&node);
    }

    static void RemoveNode(CConnman& connman, CNode& node)
    {
        LOCK(connman.cs_vNodes);
        connman.vNodes.erase(std::remove(connman.vNodes.begin(), connman.vNodes.end(), &node), connman.vNodes.end());
    }

    /** Empties the address manager and the ban list */
    static void Reset(CConnman& connman)
    {
        {
            LOCK(connman.cs_setBanned);
            connman.setBanned.clear();
            connman.setBannedIsDirty = false;
        }
        connman.addrman.Clear();
    }
};

namespace {
const NodeId PEER_ID = 0;
const uint64_t PEER_NONCE = 0x5ca1ab1e5eed0001;
/** A command the node does not know */
const char* const UNKNOWN_COMMAND = "nosuchcmd";

/** The commands the target sends */
std::vector<std::string> g_commands;

bool CarriesBlocksOrHeaders(const std::string& command)
{
    return command == NetMsgType::HEADERS || command == NetMsgType::BLOCK || command == NetMsgType::CMPCTBLOCK ||
           command == NetMsgType::BLOCKTXN;
}

void InitProcessMessages()
{
    InitFuzzNode();
    // As the node sets up its connection manager at start (init.cpp)
    g_connman.reset(new CConnman(0x1337, 0x1337));
    CConnman::Options options;
    options.nLocalServices = NODE_NETWORK;
    options.uiInterface = &uiInterface;
    options.nSendBufferMaxSize = 1000 * DEFAULT_MAXSENDBUFFER;
    options.nReceiveFloodSize = 1000 * DEFAULT_MAXRECEIVEBUFFER;
    g_connman->Init(options);

    for (const std::string& command : getAllNetMessageTypes()) {
        if (!CarriesBlocksOrHeaders(command)) g_commands.push_back(command);
    }
    g_commands.push_back(UNKNOWN_COMMAND);
}

/** The peer's address: a fixed private IPv4 address */
CAddress PeerAddress()
{
    struct in_addr s;
    const unsigned char bytes[4] = {10, 0, 0, 1};
    memcpy(&s.s_addr, bytes, 4);
    return CAddress(CService(CNetAddr(s), Params().GetDefaultPort()), NODE_NONE);
}

/** Drops what the node sent to the peer, as if the socket had sent it */
void DropSent(CNode& node)
{
    LOCK(node.cs_vSend);
    node.vSendMsg.clear();
    node.nSendSize = 0;
    node.nSendOffset = 0;
    node.fPauseSend = false;
}

/** Lets the node process the peer's messages until none is left (which
 * includes serving the rest of a getdata request) or the peer is
 * disconnected */
void ProcessAll(PeerLogicValidation& peerLogic, CNode& node)
{
    std::atomic<bool> interrupt(false);
    // Each pass takes one message or serves one requested block; the bound
    // only stops a loop that would never end.
    for (int nPass = 0; nPass < 100000; ++nPass) {
        const bool fMoreWork = peerLogic.ProcessMessages(&node, interrupt);
        DropSent(node);
        if (node.fDisconnect) return;
        bool fQueued;
        {
            LOCK(node.cs_vProcessMsg);
            fQueued = !node.vProcessMsg.empty();
        }
        if (!fMoreWork && !fQueued && node.vRecvGetData.empty()) return;
    }
    std::cerr << "error: the node did not finish processing the peer's messages" << std::endl;
    std::abort();
}

/** The peer sends this message; the node receives and processes it */
void Send(PeerLogicValidation& peerLogic, CNode& node, const std::string& command, const std::vector<unsigned char>& payload)
{
    if (CarriesBlocksOrHeaders(command)) return;

    // Framed as CConnman::PushMessage frames a message
    std::vector<unsigned char> wire;
    CMessageHeader hdr(command.c_str(), payload.size());
    const uint256 hash = Hash(payload.begin(), payload.end());
    memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);
    CVectorWriter{SER_NETWORK, INIT_PROTO_VERSION, wire, 0, hdr};
    wire.insert(wire.end(), payload.begin(), payload.end());

    // Read and queued as the node reads and queues a received message
    // (CNode::ReceiveMsgBytes, CConnman::ThreadSocketHandler)
    CNetMessage message(Params().MessageStart(), SER_NETWORK, INIT_PROTO_VERSION);
    const char* pch = reinterpret_cast<const char*>(wire.data());
    const int nHeader = message.readHeader(pch, wire.size());
    if (nHeader != CMessageHeader::HEADER_SIZE ||
        (payload.size() > 0 && message.readData(pch + nHeader, payload.size()) != (int)payload.size()) ||
        !message.complete()) {
        std::cerr << "error: the node does not read the framed message" << std::endl;
        std::abort();
    }
    message.nTime = GetTimeMicros();
    {
        LOCK(node.cs_vProcessMsg);
        node.nProcessQueueSize += message.vRecv.size() + CMessageHeader::HEADER_SIZE;
        node.vProcessMsg.push_back(std::move(message));
    }
    ProcessAll(peerLogic, node);
}

void Send(PeerLogicValidation& peerLogic, CNode& node, const CSerializedNetMsg& msg)
{
    Send(peerLogic, node, msg.command, msg.data);
}

/** The peer's version message and verack */
void Handshake(PeerLogicValidation& peerLogic, CNode& node)
{
    const std::string strSubVer = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, std::vector<std::string>());
    Send(peerLogic, node, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)NODE_NETWORK,
                                                               GetTime(), CAddress(CService(), NODE_NONE),
                                                               CAddress(CService(), NODE_NETWORK), PEER_NONCE, strSubVer,
                                                               0, true));
    if (node.fDisconnect) return;
    Send(peerLogic, node, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));
}
} // namespace

FUZZ_TARGET_INIT(p2p_process_messages, InitProcessMessages)
{
    if (buffer.empty() || buffer.size() > MAX_FUZZ_INPUT_SIZE) return;
    SetMockTime(FUZZ_NODE_TIME);
    CConnman& connman = *g_connman;

    // A PeerLogicValidation of its own: its constructor starts the node's
    // filter of rejected transactions afresh; its periodic task goes with the
    // scheduler, which no thread services.
    CScheduler scheduler;
    PeerLogicValidation peerLogic(&connman, scheduler);
    CNode node(PEER_ID, NODE_NETWORK, 0, INVALID_SOCKET, PeerAddress(), 0, PEER_NONCE, CAddress(), "", true);
    peerLogic.InitializeNode(&node);
    CConnmanTest::AddNode(connman, node);

    if (buffer[0] & 1) Handshake(peerLogic, node);
    size_t nPos = 1;
    while (nPos < buffer.size() && !node.fDisconnect) {
        const std::string& command = g_commands[buffer[nPos++] % g_commands.size()];
        size_t nSize = buffer.size() - nPos;
        if (nSize >= 2) {
            nSize = std::min<size_t>(buffer[nPos] | (buffer[nPos + 1] << 8), nSize - 2);
            nPos += 2;
        }
        const std::vector<unsigned char> payload(buffer.begin() + nPos, buffer.begin() + nPos + nSize);
        nPos += nSize;
        Send(peerLogic, node, command, payload);
    }

    CConnmanTest::RemoveNode(connman, node);
    bool fUpdateConnectionTime = false;
    peerLogic.FinalizeNode(node.GetId(), fUpdateConnectionTime);
    CConnmanTest::Reset(connman);
    {
        LOCK(cs_main);
        while (mapAlreadyAskedFor.begin() != mapAlreadyAskedFor.end()) {
            mapAlreadyAskedFor.erase(mapAlreadyAskedFor.begin()->first);
        }
    }
    ResetFuzzNodeMempool();
}
