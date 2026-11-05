// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/p2p_test_util.h"

#include "chain.h"
#include "chainparams.h"
#include "hash.h"
#include "pow.h"
#include "random.h"
#include "script/script.h"
#include "sync.h"
#include "test/test_bitcoin.h"
#include "utiltime.h"
#include "validation.h"
#include "validationinterface.h"

#include <algorithm>
#include <atomic>
#include <limits>
#include <string.h>

#include <boost/test/unit_test.hpp>

namespace {

/** Node ids of test peers, above those other suites give their CNodes */
std::atomic<NodeId> nextTestPeerId{1000000};

/** A distinct private IPv4 address per test peer */
CAddress TestPeerAddress(NodeId id)
{
    struct in_addr s;
    const uint32_t n = (uint32_t)id;
    const unsigned char bytes[4] = {10, (unsigned char)(n >> 16), (unsigned char)(n >> 8), (unsigned char)n};
    memcpy(&s.s_addr, bytes, 4);
    return CAddress(CService(CNetAddr(s), Params().GetDefaultPort()), NODE_NONE);
}

/** A random nonce that is never 0 */
uint64_t TestNonce()
{
    uint64_t nonce = 0;
    while (nonce == 0)
        nonce = GetRand(std::numeric_limits<uint64_t>::max());
    return nonce;
}

} // namespace

void InitP2PTestConnman(CConnman& connman, CConnman::Options options)
{
    options.nSendBufferMaxSize = 1000 * DEFAULT_MAXSENDBUFFER;
    options.nReceiveFloodSize = 1000 * DEFAULT_MAXRECEIVEBUFFER;
    connman.Init(options);
}

CDataStream P2PTestMessage::Stream() const
{
    return CDataStream(payload, SER_NETWORK, PROTOCOL_VERSION);
}

std::vector<P2PTestMessage> WithCommand(const std::vector<P2PTestMessage>& messages, const std::string& command)
{
    std::vector<P2PTestMessage> result;
    for (const P2PTestMessage& message : messages) {
        if (message.command == command)
            result.push_back(message);
    }
    return result;
}

std::vector<std::string> Commands(const std::vector<P2PTestMessage>& messages)
{
    std::vector<std::string> result;
    for (const P2PTestMessage& message : messages)
        result.push_back(message.command);
    return result;
}

P2PTestPeer::P2PTestPeer(PeerLogicValidation& peerLogic, const P2PTestPeerOptions& options)
    : m_peerLogic(peerLogic), m_options(options), m_nVersion(std::min(options.nVersion, PROTOCOL_VERSION)), m_fInConnman(false),
      m_fFinalized(false)
{
    const NodeId id = nextTestPeerId++;
    const CAddress address = options.address.IsValid() ? CAddress(options.address, NODE_NONE) : TestPeerAddress(id);
    m_node.reset(new CNode(id, NODE_NETWORK, 0, INVALID_SOCKET, address, 0, TestNonce(), CAddress(), "", options.fInbound));
    m_node->fWhitelisted = options.fWhitelisted;
    m_peerLogic.InitializeNode(m_node.get());
    if (options.fInConnman) {
        CConnmanTest::AddNode(*m_node);
        m_fInConnman = true;
    }
    if (options.fHandshake) {
        try {
            Handshake();
        } catch (...) {
            // The destructor does not run for a constructor that throws
            if (m_fInConnman)
                CConnmanTest::RemoveNode(*m_node);
            bool fUpdateConnectionTime = false;
            m_peerLogic.FinalizeNode(m_node->GetId(), fUpdateConnectionTime);
            throw;
        }
    }
}

P2PTestPeer::~P2PTestPeer()
{
    if (!m_fFinalized)
        Finalize();
}

bool P2PTestPeer::Finalize()
{
    BOOST_REQUIRE(!m_fFinalized);
    m_fFinalized = true;
    if (m_fInConnman)
        CConnmanTest::RemoveNode(*m_node);
    m_fInConnman = false;
    bool fUpdateConnectionTime = false;
    m_peerLogic.FinalizeNode(m_node->GetId(), fUpdateConnectionTime);
    return fUpdateConnectionTime;
}

void P2PTestPeer::Handshake()
{
    SendVersion();
    SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));
    TakeReceived();
}

void P2PTestPeer::SendVersion()
{
    // The time in the version message is the node's own, so the time offset sample it adds
    // (AddTimeData) is 0.
    const int64_t nTime = GetTime();
    P2PTestMockTime now(nTime);
    SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, m_options.nVersion, (uint64_t)m_options.services, nTime,
                                                       CAddress(CService(), NODE_NONE), CAddress(CService(), m_options.services),
                                                       TestNonce(), std::string("/p2p_test:1.0/"), m_options.nStartingHeight,
                                                       m_options.fRelay));
}

void P2PTestPeer::SendMessage(CSerializedNetMsg&& msg)
{
    Queue(std::move(msg));
    ProcessAll();
}

void P2PTestPeer::Queue(CSerializedNetMsg&& msg)
{
    // Framed as CConnman::PushMessage frames it, read as the socket thread reads it
    std::vector<unsigned char> wire;
    CMessageHeader hdr(msg.command.c_str(), msg.data.size());
    const uint256 hash = Hash(msg.data.begin(), msg.data.end());
    memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);
    CVectorWriter{SER_NETWORK, INIT_PROTO_VERSION, wire, 0, hdr};
    wire.insert(wire.end(), msg.data.begin(), msg.data.end());

    CNetMessage message(::pchMessageStart, SER_NETWORK, INIT_PROTO_VERSION);
    const char* pch = reinterpret_cast<const char*>(wire.data());
    unsigned int nBytes = wire.size();
    const int nHeader = message.readHeader(pch, nBytes);
    BOOST_REQUIRE(nHeader == CMessageHeader::HEADER_SIZE);
    if (nBytes > (unsigned int)nHeader)
        BOOST_REQUIRE_EQUAL(message.readData(pch + nHeader, nBytes - nHeader), (int)(nBytes - nHeader));
    BOOST_REQUIRE(message.complete());
    message.nTime = GetTimeMicros();

    LOCK(m_node->cs_vProcessMsg);
    m_node->nProcessQueueSize += message.vRecv.size() + CMessageHeader::HEADER_SIZE;
    m_node->vProcessMsg.push_back(std::move(message));
}

void P2PTestPeer::ProcessAll()
{
    std::atomic<bool> interrupt(false);
    // Each pass takes one message or serves one requested block; the bound only stops a loop
    // that would never end.
    for (int nPass = 0; nPass < 100000; ++nPass) {
        const bool fMoreWork = m_peerLogic.ProcessMessages(m_node.get(), interrupt);
        if (m_node->fDisconnect)
            return;
        bool fQueued;
        {
            LOCK(m_node->cs_vProcessMsg);
            fQueued = !m_node->vProcessMsg.empty();
        }
        if (!fMoreWork && !fQueued && m_node->vRecvGetData.empty())
            return;
    }
    BOOST_ERROR("P2PTestPeer::ProcessAll: the node did not finish processing the peer's messages");
}

void P2PTestPeer::RunSendMessages()
{
    std::atomic<bool> interrupt(false);
    m_peerLogic.SendMessages(m_node.get(), interrupt);
}

std::vector<P2PTestMessage> P2PTestPeer::TakeReceived()
{
    std::vector<P2PTestMessage> messages;
    LOCK(m_node->cs_vSend);
    auto it = m_node->vSendMsg.begin();
    while (it != m_node->vSendMsg.end()) {
        CDataStream headerStream(*it, SER_NETWORK, INIT_PROTO_VERSION);
        CMessageHeader hdr;
        headerStream >> hdr;
        ++it;
        P2PTestMessage message;
        message.command = hdr.GetCommand();
        // A message without payload is queued as its header alone
        if (hdr.nMessageSize > 0) {
            BOOST_REQUIRE(it != m_node->vSendMsg.end());
            BOOST_REQUIRE_EQUAL(it->size(), hdr.nMessageSize);
            message.payload = *it;
            ++it;
        }
        messages.push_back(std::move(message));
    }
    m_node->vSendMsg.clear();
    m_node->nSendSize = 0;
    m_node->nSendOffset = 0;
    m_node->fPauseSend = false;
    return messages;
}

CNodeStateStats P2PTestPeer::Stats() const
{
    CNodeStateStats stats;
    BOOST_REQUIRE(GetNodeStateStats(m_node->GetId(), stats));
    return stats;
}

P2PTestMockTime::P2PTestMockTime(int64_t nTime) : m_saved(GetMockTime())
{
    SetMockTime(nTime);
}

P2PTestMockTime::~P2PTestMockTime()
{
    SetMockTime(m_saved);
}

void P2PTestMockTime::Set(int64_t nTime)
{
    SetMockTime(nTime);
}

P2PTestHashWorkers::P2PTestHashWorkers(int nThreads) : m_saved(nHashCalcThreads)
{
    nHashCalcThreads = nThreads;
    for (int i = 0; i < nThreads - 1; i++)
        m_threads.create_thread(&ThreadHashCalculation);
}

P2PTestHashWorkers::~P2PTestHashWorkers()
{
    m_threads.interrupt_all();
    m_threads.join_all();
    nHashCalcThreads = m_saved;
}

P2PTestRegistration::P2PTestRegistration(CValidationInterface* pinterface) : m_pinterface(pinterface)
{
    RegisterValidationInterface(m_pinterface);
}

P2PTestRegistration::~P2PTestRegistration()
{
    UnregisterValidationInterface(m_pinterface);
}

CBlock ReadP2PTestBlock(const CBlockIndex* pindex)
{
    CBlock block;
    BOOST_REQUIRE(ReadBlockFromDisk(block, pindex, Params().GetConsensus()));
    return block;
}

CBlock BuildP2PTestBlock(const CBlock& prev, int nHeight, int extra)
{
    CBlock block = prev;
    block.hashPrevBlock = prev.GetHash();
    block.nTime = prev.nTime + 1;
    block.nNonce = 1;
    block.vtx.resize(1);
    block.vtx[0].vin[0].scriptSig = CScript() << nHeight << extra;
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.fChecked = false;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()))
        ++block.nNonce;
    return block;
}

std::vector<CBlock> BuildP2PTestChain(const CBlock& prev, int nPrevHeight, int n, int extra)
{
    std::vector<CBlock> blocks;
    const CBlock* pprev = &prev;
    blocks.reserve(n);
    for (int i = 0; i < n; i++) {
        blocks.push_back(BuildP2PTestBlock(*pprev, nPrevHeight + 1 + i, extra));
        pprev = &blocks.back();
    }
    return blocks;
}

std::vector<CBlock> P2PTestHeaders(const std::vector<CBlock>& blocks)
{
    std::vector<CBlock> headers;
    for (const CBlock& block : blocks)
        headers.push_back(CBlock(block.GetBlockHeader()));
    return headers;
}
