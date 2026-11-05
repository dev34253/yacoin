// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block and header handling of the peer-to-peer code (net_processing.cpp): the headers,
// getheaders, sendheaders, inv, getdata, getblocks and block messages as test peers send them,
// direct fetch, block announcements, the block download and the getblocks fallback in
// SendMessages, and NewPoWValidBlock.
//
// Every block and header here is a real proof-of-work block of the regtest chain, built on the
// node's chain and mined; the peers send them as a peer does.
//
// Initial download: the mainnet build never leaves it in the unit tests (its checkpoint estimate
// is above any test chain), the low-difficulty build leaves it with the first tip. Behaviour that
// depends on it is checked per build.

#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "net.h"
#include "net_processing.h"
#include "primitives/block.h"
#include "protocol.h"
#include "random.h"
#include "script/script.h"
#include "tokens/tokendb.h"
#include "utiltime.h"
#include "validation.h"

#include "test/known_failure.h"
#include "test/p2p_test_util.h"
#include "test/test_bitcoin.h"

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

/** TestChain100Setup's regtest chain (a few blocks on genesis), the CConnman's buffer limits as
 * the node sets them, and the token database that a reorganisation needs */
struct BlockSyncSetup : public TestChain100Setup {
    CTokensDB* prevTokensDb;

    BlockSyncSetup()
    {
        InitP2PTestConnman(*connman);
        prevTokensDb = ptokensdb;
        ptokensdb = new CTokensDB(1 << 20, true, true);
    }

    ~BlockSyncSetup()
    {
        delete ptokensdb;
        ptokensdb = prevTokensDb;
    }

    const CBlockIndex* Tip() const
    {
        LOCK(cs_main);
        return chainActive.Tip();
    }

    const CBlockIndex* Active(int nHeight) const
    {
        LOCK(cs_main);
        return chainActive[nHeight];
    }

    int Height() const
    {
        LOCK(cs_main);
        return chainActive.Height();
    }

    const CBlockIndex* BestHeader() const
    {
        LOCK(cs_main);
        return pindexBestHeader;
    }

    const CBlockIndex* Index(const uint256& hash) const
    {
        LOCK(cs_main);
        BlockMap::iterator it = mapBlockIndex.find(hash);
        return it == mapBlockIndex.end() ? nullptr : it->second;
    }

    size_t IndexSize() const
    {
        LOCK(cs_main);
        return mapBlockIndex.size();
    }

    CBlockLocator Locator(const CBlockIndex* pindex) const
    {
        LOCK(cs_main);
        return chainActive.GetLocator(pindex);
    }

    /** n blocks on the tip, built and mined but not processed */
    std::vector<CBlock> BuildOnTip(int n, int extra = 0) const
    {
        const CBlockIndex* pindexTip = Tip();
        return BuildP2PTestChain(ReadP2PTestBlock(pindexTip), pindexTip->nHeight, n, extra);
    }

    /** The headers are accepted here, as if another peer had sent them */
    void AcceptHeaders(const std::vector<CBlock>& blocks) const
    {
        std::vector<CBlockHeader> headers;
        for (const CBlock& block : blocks)
            headers.push_back(block.GetBlockHeader());
        CValidationState state;
        BOOST_REQUIRE(ProcessNewBlockHeaders(headers, state, Params()));
    }

    /** The block is processed here, as if another peer had sent it */
    void ProcessHere(const CBlock& block) const
    {
        BOOST_REQUIRE(ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, nullptr));
    }

    /** The active chain grows by n blocks mined here */
    void Extend(int n)
    {
        const CScript script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        for (int i = 0; i < n; i++)
            CreateAndProcessBlock({}, script);
    }
};

std::vector<uint256> Hashes(const std::vector<CBlock>& blocks)
{
    std::vector<uint256> hashes;
    for (const CBlock& block : blocks)
        hashes.push_back(block.GetHash());
    return hashes;
}

/** The hashes of the active chain's blocks from nFirst to nLast */
std::vector<uint256> ActiveHashes(const BlockSyncSetup& setup, int nFirst, int nLast)
{
    std::vector<uint256> hashes;
    for (int nHeight = nFirst; nHeight <= nLast; nHeight++)
        hashes.push_back(setup.Active(nHeight)->GetBlockHash());
    return hashes;
}

std::string Joined(const std::vector<std::string>& words)
{
    std::string result;
    for (const std::string& word : words)
        result += (result.empty() ? "" : " ") + word;
    return result;
}

/** The inventory of every message with the given command (inv or getdata), in order */
std::vector<CInv> Inventory(const std::vector<P2PTestMessage>& messages, const std::string& command)
{
    std::vector<CInv> result;
    for (const P2PTestMessage& message : WithCommand(messages, command)) {
        const std::vector<CInv> invs = message.Read<std::vector<CInv> >();
        result.insert(result.end(), invs.begin(), invs.end());
    }
    return result;
}

/** The block hashes of an inventory; every entry must be a block */
std::vector<uint256> BlockHashes(const std::vector<CInv>& invs)
{
    std::vector<uint256> hashes;
    for (const CInv& inv : invs) {
        BOOST_CHECK_EQUAL(inv.type, (int)MSG_BLOCK);
        hashes.push_back(inv.hash);
    }
    return hashes;
}

/** The hashes of the headers in a headers message */
std::vector<uint256> HeaderHashes(const P2PTestMessage& message)
{
    BOOST_CHECK_EQUAL(message.command, NetMsgType::HEADERS);
    return Hashes(message.Read<std::vector<CBlock> >());
}

/** The locator and stop hash of a getheaders or getblocks message */
std::pair<CBlockLocator, uint256> LocatorAndStop(const P2PTestMessage& message)
{
    CDataStream stream = message.Stream();
    CBlockLocator locator;
    uint256 hashStop;
    stream >> locator >> hashStop;
    return std::make_pair(locator, hashStop);
}

std::vector<CInv> BlockInv(const uint256& hash)
{
    return std::vector<CInv>{CInv(MSG_BLOCK, hash)};
}

P2PTestPeerOptions Client()
{
    P2PTestPeerOptions options;
    options.services = NODE_NONE;
    return options;
}

#define CHECK_HASHES(actual, expected) BOOST_CHECK((actual) == (expected))

/** Headers that connect to the tip are added to the block index, become the best header and the
 * peer's best known block; the tip stays and the peer is not scored. The same headers again
 * change nothing. The tip is not recent here, so no block is requested directly. */
void CheckHeadersOnTip(BlockSyncSetup& setup)
{
    P2PTestMockTime later(setup.Tip()->GetBlockTime() + 30 * 60);
    P2PTestPeer peer(*setup.peerLogic);
    const CBlockIndex* pindexTip = setup.Tip();
    const std::vector<CBlock> blocks = setup.BuildOnTip(3);
    const size_t nIndexSize = setup.IndexSize();

    for (int nRound = 0; nRound < 2; nRound++) {
        peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
        BOOST_CHECK_EQUAL(setup.IndexSize(), nIndexSize + blocks.size());
        for (size_t i = 0; i < blocks.size(); i++) {
            const CBlockIndex* pindex = setup.Index(blocks[i].GetHash());
            BOOST_REQUIRE(pindex != nullptr);
            BOOST_CHECK_EQUAL(pindex->nHeight, pindexTip->nHeight + 1 + (int)i);
            BOOST_CHECK(pindex->IsValid(BLOCK_VALID_TREE));
            BOOST_CHECK(!(pindex->nStatus & BLOCK_HAVE_DATA));
        }
        BOOST_CHECK(setup.BestHeader() == setup.Index(blocks.back().GetHash()));
        BOOST_CHECK(setup.Tip() == pindexTip);
        const CNodeStateStats stats = peer.Stats();
        BOOST_CHECK_EQUAL(stats.nSyncHeight, pindexTip->nHeight + 3);
        BOOST_CHECK_EQUAL(stats.nMisbehavior, 0);
        BOOST_CHECK(stats.vHeightInFlight.empty());
        BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(net_processing_block_tests, BlockSyncSetup)

BOOST_AUTO_TEST_CASE(headers_on_tip_without_hash_workers)
{
    P2PTestHashWorkers single(1);
    CheckHeadersOnTip(*this);
}

BOOST_AUTO_TEST_CASE(headers_on_tip_with_hash_workers)
{
    P2PTestHashWorkers workers(2);
    CheckHeadersOnTip(*this);
}

/** An empty headers message changes nothing and is not answered */
BOOST_AUTO_TEST_CASE(empty_headers_message)
{
    P2PTestPeer peer(*peerLogic);
    const CBlockIndex* pindexBestHeader = BestHeader();
    const size_t nIndexSize = IndexSize();

    peer.Send(NetMsgType::HEADERS, std::vector<CBlock>());
    BOOST_CHECK_EQUAL(IndexSize(), nIndexSize);
    BOOST_CHECK(BestHeader() == pindexBestHeader);
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, -1);
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
}

/** A headers message with the maximum of 2000 headers makes the node ask the peer for the headers
 * after the last one */
BOOST_AUTO_TEST_CASE(full_headers_message_asks_for_more)
{
    P2PTestMockTime later(Tip()->GetBlockTime() + 30 * 60);
    P2PTestPeer peer(*peerLogic);
    const std::vector<CBlock> blocks = BuildOnTip(2000);

    peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    BOOST_CHECK(BestHeader() == Index(blocks.back().GetHash()));
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, Height() + 2000);
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);

    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "getheaders");
    const std::pair<CBlockLocator, uint256> request = LocatorAndStop(received[0]);
    BOOST_REQUIRE(!request.first.vHave.empty());
    BOOST_CHECK(request.first.vHave.front() == blocks.back().GetHash());
    BOOST_CHECK(request.first.vHave == Locator(Index(blocks.back().GetHash())).vHave);
    BOOST_CHECK(request.second.IsNull());
}

/** With a recent tip, headers that end above it make the node request the missing blocks from
 * the peer, earliest first, and mark them in flight; the same headers again request nothing */
BOOST_AUTO_TEST_CASE(direct_fetch_requests_missing_blocks)
{
    P2PTestMockTime now(Tip()->GetBlockTime() + 60);
    P2PTestPeer peer(*peerLogic);
    const int nHeight = Height();
    const std::vector<CBlock> blocks = BuildOnTip(3);

    peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_CHECK_EQUAL(Joined(Commands(received)), "getdata");
    CHECK_HASHES(BlockHashes(Inventory(received, NetMsgType::GETDATA)), Hashes(blocks));
    BOOST_CHECK(peer.Stats().vHeightInFlight == std::vector<int>({nHeight + 1, nHeight + 2, nHeight + 3}));

    peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
    BOOST_CHECK_EQUAL(peer.Stats().vHeightInFlight.size(), 3U);
}

/** Direct fetch requests at most the per-peer limit of blocks in flight */
BOOST_AUTO_TEST_CASE(direct_fetch_stops_at_per_peer_limit)
{
    P2PTestValue<int> limit(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 2);
    P2PTestMockTime now(Tip()->GetBlockTime() + 60);
    P2PTestPeer peer(*peerLogic);
    const int nHeight = Height();
    const std::vector<CBlock> blocks = BuildOnTip(3);

    peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_CHECK_EQUAL(Joined(Commands(received)), "getdata");
    CHECK_HASHES(BlockHashes(Inventory(received, NetMsgType::GETDATA)), Hashes({blocks[0], blocks[1]}));
    BOOST_CHECK(peer.Stats().vHeightInFlight == std::vector<int>({nHeight + 1, nHeight + 2}));
}

/** When the path from the tip to the last header is longer than the per-peer limit plus one,
 * direct fetch requests nothing and leaves the blocks to the block download in SendMessages */
BOOST_AUTO_TEST_CASE(direct_fetch_leaves_longer_paths_to_block_download)
{
    P2PTestValue<int> limit(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 2);
    P2PTestMockTime now(Tip()->GetBlockTime() + 60);
    P2PTestPeer peer(*peerLogic);
    const std::vector<CBlock> blocks = BuildOnTip(4);

    peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    BOOST_CHECK(BestHeader() == Index(blocks.back().GetHash()));
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
    BOOST_CHECK(peer.Stats().vHeightInFlight.empty());
}

/** After the peer sent sendcmpct version 1, direct fetch of a single block asks for it as a
 * compact block, which the node cannot process; it should ask for the block itself */
BOOST_AUTO_TEST_CASE(direct_fetch_of_one_block_after_sendcmpct)
{
    P2PTestMockTime now(Tip()->GetBlockTime() + 60);
    P2PTestPeer peer(*peerLogic);
    const std::vector<CBlock> blocks = BuildOnTip(1);

    peer.Send(NetMsgType::SENDCMPCT, false, (uint64_t)1);
    peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    const std::vector<CInv> invs = Inventory(peer.TakeReceived(), NetMsgType::GETDATA);
    BOOST_REQUIRE_EQUAL(invs.size(), 1U);
    BOOST_CHECK(invs[0].hash == blocks[0].GetHash());
    KNOWN_FAILURE_EQUAL("MG-011", invs[0].type, (int)MSG_BLOCK, (int)MSG_CMPCT_BLOCK);
}

/** getheaders from a whitelisted peer: the active chain after the fork point of the locator, up
 * to and including hashStop; with a null locator only the hashStop header, or no answer if it is
 * unknown; a locator at the tip gets an empty headers message */
BOOST_AUTO_TEST_CASE(getheaders_served_to_whitelisted_peer)
{
    P2PTestPeerOptions options;
    options.fWhitelisted = true;
    P2PTestPeer peer(*peerLogic, options);
    const int nHeight = Height();
    BOOST_REQUIRE(nHeight >= 4);
    const CBlockLocator genesis = Locator(Active(0));

    peer.Send(NetMsgType::GETHEADERS, genesis, uint256());
    std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "headers");
    CHECK_HASHES(HeaderHashes(received[0]), ActiveHashes(*this, 1, nHeight));

    peer.Send(NetMsgType::GETHEADERS, genesis, Active(3)->GetBlockHash());
    received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "headers");
    CHECK_HASHES(HeaderHashes(received[0]), ActiveHashes(*this, 1, 3));

    peer.Send(NetMsgType::GETHEADERS, CBlockLocator(), Active(4)->GetBlockHash());
    received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "headers");
    CHECK_HASHES(HeaderHashes(received[0]), ActiveHashes(*this, 4, 4));

    peer.Send(NetMsgType::GETHEADERS, CBlockLocator(), InsecureRand256());
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");

    peer.Send(NetMsgType::GETHEADERS, Locator(Tip()), uint256());
    received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "headers");
    BOOST_CHECK(HeaderHashes(received[0]).empty());
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** getheaders from a peer that is not whitelisted is answered only after initial download */
BOOST_AUTO_TEST_CASE(getheaders_from_peer_not_whitelisted)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::GETHEADERS, Locator(Active(0)), uint256());
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    // In initial download (always on this build in the unit tests)
    BOOST_CHECK_EQUAL(Joined(Commands(received)), "");
#else
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "headers");
    CHECK_HASHES(HeaderHashes(received[0]), ActiveHashes(*this, 1, Height()));
#endif
}

/** A new tip is announced with headers to a peer that sent sendheaders and has the parent */
BOOST_AUTO_TEST_CASE(new_tip_announced_by_headers)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::SENDHEADERS);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    peer.RunSendMessages();
    peer.TakeReceived();

    const CBlockIndex* pindexFork = Tip();
    Extend(1);
    peerLogic->UpdatedBlockTip(Tip(), pindexFork, false);
    peer.RunSendMessages();
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    const std::vector<P2PTestMessage> headers = WithCommand(received, NetMsgType::HEADERS);
    BOOST_REQUIRE_EQUAL(headers.size(), 1U);
    CHECK_HASHES(HeaderHashes(headers[0]), std::vector<uint256>{Tip()->GetBlockHash()});
    BOOST_CHECK(WithCommand(received, NetMsgType::INV).empty());

    // Announced once
    peer.RunSendMessages();
    BOOST_CHECK(WithCommand(peer.TakeReceived(), NetMsgType::HEADERS).empty());
}

/** Several new blocks are announced with headers from the first one the peer does not have */
BOOST_AUTO_TEST_CASE(new_blocks_announced_by_headers_from_first_unknown)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::SENDHEADERS);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    peer.RunSendMessages();
    peer.TakeReceived();

    // Two new blocks, the peer has neither
    const CBlockIndex* pindexFork = Tip();
    Extend(2);
    peerLogic->UpdatedBlockTip(Tip(), pindexFork, false);
    peer.RunSendMessages();
    std::vector<P2PTestMessage> headers = WithCommand(peer.TakeReceived(), NetMsgType::HEADERS);
    BOOST_REQUIRE_EQUAL(headers.size(), 1U);
    CHECK_HASHES(HeaderHashes(headers[0]), ActiveHashes(*this, Height() - 1, Height()));

    // Two more, the peer has announced the first of them
    pindexFork = Tip();
    Extend(2);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->pprev->GetBlockHash()));
    peerLogic->UpdatedBlockTip(Tip(), pindexFork, false);
    peer.RunSendMessages();
    headers = WithCommand(peer.TakeReceived(), NetMsgType::HEADERS);
    BOOST_REQUIRE_EQUAL(headers.size(), 1U);
    CHECK_HASHES(HeaderHashes(headers[0]), std::vector<uint256>{Tip()->GetBlockHash()});
}

/** A queued announcement of a block that a reorganisation took off the active chain falls back
 * to an inv of that block */
BOOST_AUTO_TEST_CASE(announcement_after_reorganisation_falls_back_to_inv)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::SENDHEADERS);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    peer.RunSendMessages();
    peer.TakeReceived();

    const CBlockIndex* pindexFork = Tip();
    const CBlock forkBlock = ReadP2PTestBlock(pindexFork);
    Extend(1);
    const uint256 hashAnnounced = Tip()->GetBlockHash();
    peerLogic->UpdatedBlockTip(Tip(), pindexFork, false);

    // A longer branch from the fork point is connected before the announcement goes out
    const std::vector<CBlock> branch = BuildP2PTestChain(forkBlock, pindexFork->nHeight, 2, 1);
    for (const CBlock& block : branch)
        ProcessHere(block);
    BOOST_REQUIRE(Tip()->GetBlockHash() == branch.back().GetHash());

    peer.RunSendMessages();
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_CHECK(WithCommand(received, NetMsgType::HEADERS).empty());
    CHECK_HASHES(BlockHashes(Inventory(received, NetMsgType::INV)), std::vector<uint256>{hashAnnounced});
}

/** Without sendheaders the new tip is announced with an inv */
BOOST_AUTO_TEST_CASE(new_tip_announced_by_inv)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    peer.RunSendMessages();
    peer.TakeReceived();

    const CBlockIndex* pindexFork = Tip();
    Extend(1);
    peerLogic->UpdatedBlockTip(Tip(), pindexFork, false);
    peer.RunSendMessages();
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_CHECK(WithCommand(received, NetMsgType::HEADERS).empty());
    CHECK_HASHES(BlockHashes(Inventory(received, NetMsgType::INV)), std::vector<uint256>{Tip()->GetBlockHash()});
}

/** More new blocks than one headers announcement carries (8) are announced with an inv of the
 * last one: after one update of nine blocks (only the last eight are queued, and the peer lacks
 * the parent of the first of them), and after two updates that queue nine together */
BOOST_AUTO_TEST_CASE(many_new_blocks_announced_by_inv)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::SENDHEADERS);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    peer.RunSendMessages();
    peer.TakeReceived();

    const CBlockIndex* pindexFork = Tip();
    Extend(9);
    peerLogic->UpdatedBlockTip(Tip(), pindexFork, false);
    peer.RunSendMessages();
    std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_CHECK(WithCommand(received, NetMsgType::HEADERS).empty());
    CHECK_HASHES(BlockHashes(Inventory(received, NetMsgType::INV)), std::vector<uint256>{Tip()->GetBlockHash()});

    // The peer has the tip now; nine more blocks in two updates
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    for (int n : {5, 4}) {
        pindexFork = Tip();
        Extend(n);
        peerLogic->UpdatedBlockTip(Tip(), pindexFork, false);
    }
    peer.RunSendMessages();
    received = peer.TakeReceived();
    BOOST_CHECK(WithCommand(received, NetMsgType::HEADERS).empty());
    CHECK_HASHES(BlockHashes(Inventory(received, NetMsgType::INV)), std::vector<uint256>{Tip()->GetBlockHash()});
}

/** A tip reached in initial download is not announced */
BOOST_AUTO_TEST_CASE(no_announcement_in_initial_download)
{
    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::SENDHEADERS);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    peer.RunSendMessages();
    peer.TakeReceived();

    const CBlockIndex* pindexFork = Tip();
    Extend(1);
    peerLogic->UpdatedBlockTip(Tip(), pindexFork, true);
    peer.RunSendMessages();
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_CHECK(WithCommand(received, NetMsgType::HEADERS).empty());
    BOOST_CHECK(WithCommand(received, NetMsgType::INV).empty());
}

/** A new tip is not announced to a peer whose reported starting height is 2000 or more above it */
BOOST_AUTO_TEST_CASE(no_announcement_below_peer_starting_height)
{
    P2PTestPeerOptions options;
    options.nStartingHeight = Height() + 1 + 2000;
    P2PTestPeer peer(*peerLogic, options);
    peer.Send(NetMsgType::SENDHEADERS);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    peer.RunSendMessages();
    peer.TakeReceived();

    const CBlockIndex* pindexFork = Tip();
    Extend(1);
    peerLogic->UpdatedBlockTip(Tip(), pindexFork, false);
    peer.RunSendMessages();
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_CHECK(WithCommand(received, NetMsgType::HEADERS).empty());
    BOOST_CHECK(WithCommand(received, NetMsgType::INV).empty());
}

/** An inv of known blocks moves the peer's best known block up, never down, and is not answered */
BOOST_AUTO_TEST_CASE(inv_of_known_blocks)
{
    P2PTestPeer peer(*peerLogic);
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, -1);

    peer.Send(NetMsgType::INV, BlockInv(Active(3)->GetBlockHash()));
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, 3);
    peer.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, Height());
    peer.Send(NetMsgType::INV, BlockInv(Active(2)->GetBlockHash()));
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, Height());
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** An inv of an unknown block is remembered: once the header is known, the block is the peer's
 * best known block and the node asks the peer for it. Whether the inv itself is answered with
 * getheaders depends on initial download. */
BOOST_AUTO_TEST_CASE(inv_of_unknown_block)
{
    P2PTestPeer peer(*peerLogic);
    const std::vector<CBlock> blocks = BuildOnTip(1);

    peer.Send(NetMsgType::INV, BlockInv(blocks[0].GetHash()));
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, -1);
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    // In initial download (always on this build in the unit tests)
    BOOST_CHECK_EQUAL(Joined(Commands(received)), "");
#else
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "getheaders");
    const std::pair<CBlockLocator, uint256> request = LocatorAndStop(received[0]);
    BOOST_CHECK(request.first.vHave == Locator(BestHeader()).vHave);
    BOOST_CHECK(request.second == blocks[0].GetHash());
#endif

    AcceptHeaders(blocks);
    peer.RunSendMessages();
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, Height() + 1);
    CHECK_HASHES(BlockHashes(Inventory(peer.TakeReceived(), NetMsgType::GETDATA)), Hashes(blocks));
}

/** getdata for blocks of the active chain: each is sent as a block message, one per processing
 * pass, in the order requested; an unknown block is not answered */
BOOST_AUTO_TEST_CASE(getdata_serves_active_chain_blocks)
{
    P2PTestPeer peer(*peerLogic);

    peer.Send(NetMsgType::GETDATA, BlockInv(Active(3)->GetBlockHash()));
    std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "block");
    const CBlock block = received[0].Read<CBlock>();
    BOOST_CHECK(block.GetHash() == Active(3)->GetBlockHash());
    BOOST_CHECK(block.hashMerkleRoot == ReadP2PTestBlock(Active(3)).hashMerkleRoot);
    BOOST_CHECK_EQUAL(block.vtx.size(), 1U);

    const std::vector<CInv> request{CInv(MSG_BLOCK, Active(2)->GetBlockHash()), CInv(MSG_BLOCK, Active(4)->GetBlockHash()),
                                    CInv(MSG_BLOCK, Active(1)->GetBlockHash())};
    peer.Queue(CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETDATA, request));
    std::atomic<bool> interrupt(false);
    // The first pass reads the request and serves one block; the rest wait for later passes
    peerLogic->ProcessMessages(&peer.Node(), interrupt);
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "block");
    BOOST_CHECK_EQUAL(peer.Node().vRecvGetData.size(), 2U);
    peer.ProcessAll();
    received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "block block");
    BOOST_CHECK(received[0].Read<CBlock>().GetHash() == Active(4)->GetBlockHash());
    BOOST_CHECK(received[1].Read<CBlock>().GetHash() == Active(1)->GetBlockHash());
    BOOST_CHECK(peer.Node().vRecvGetData.empty());

    peer.Send(NetMsgType::GETDATA, BlockInv(InsecureRand256()));
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** getdata for blocks off the active chain: a stored block that was never connected is not sent;
 * one that was connected and is now off the chain after a reorganisation is */
BOOST_AUTO_TEST_CASE(getdata_blocks_off_active_chain)
{
    P2PTestPeer peer(*peerLogic);
    const int nHeight = Height();
    const CBlockIndex* pindexOldTip = Tip();
    // A competing block at the tip's height, stored but not connected
    const CBlock side = BuildP2PTestBlock(ReadP2PTestBlock(Active(nHeight - 1)), nHeight, 1);
    ProcessHere(side);
    BOOST_REQUIRE(Tip() == pindexOldTip);

    peer.Send(NetMsgType::GETDATA, BlockInv(side.GetHash()));
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");

    // Its branch grows longer, the old tip is disconnected
    ProcessHere(BuildP2PTestBlock(side, nHeight + 1, 1));
    BOOST_REQUIRE(Tip()->pprev == Index(side.GetHash()));

    peer.Send(NetMsgType::GETDATA, BlockInv(pindexOldTip->GetBlockHash()));
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "block");
    BOOST_CHECK(received[0].Read<CBlock>().GetHash() == pindexOldTip->GetBlockHash());
}

/** getblocks: an inv of the active chain after the fork point of the locator, stopping before
 * hashStop; nothing for a locator at the tip */
BOOST_AUTO_TEST_CASE(getblocks_answered_with_inv)
{
    P2PTestPeer peer(*peerLogic);
    const int nHeight = Height();
    BOOST_REQUIRE(nHeight >= 4);

    peer.Send(NetMsgType::GETBLOCKS, Locator(Active(0)), Active(4)->GetBlockHash());
    peer.RunSendMessages();
    CHECK_HASHES(BlockHashes(Inventory(peer.TakeReceived(), NetMsgType::INV)), ActiveHashes(*this, 1, 3));

    peer.Send(NetMsgType::GETBLOCKS, Locator(Active(2)), uint256());
    peer.RunSendMessages();
    CHECK_HASHES(BlockHashes(Inventory(peer.TakeReceived(), NetMsgType::INV)), ActiveHashes(*this, 3, nHeight));

    peer.Send(NetMsgType::GETBLOCKS, Locator(Tip()), uint256());
    peer.RunSendMessages();
    BOOST_CHECK(Inventory(peer.TakeReceived(), NetMsgType::INV).empty());
}

/** getblocks answers with at most 500 blocks; when the peer later asks for the last of them, the
 * node sends it and then an inv of its tip, so that the peer asks for the next ones */
BOOST_AUTO_TEST_CASE(getblocks_limit_and_continuation)
{
    Extend(500 - Height() + 2);
    const int nHeight = Height();
    P2PTestPeer peer(*peerLogic);

    peer.Send(NetMsgType::GETBLOCKS, Locator(Active(0)), uint256());
    peer.RunSendMessages();
    CHECK_HASHES(BlockHashes(Inventory(peer.TakeReceived(), NetMsgType::INV)), ActiveHashes(*this, 1, 500));

    peer.Send(NetMsgType::GETDATA, BlockInv(Active(499)->GetBlockHash()));
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "block");

    peer.Send(NetMsgType::GETDATA, BlockInv(Active(500)->GetBlockHash()));
    const std::vector<P2PTestMessage> received = peer.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "block inv");
    BOOST_CHECK(received[0].Read<CBlock>().GetHash() == Active(500)->GetBlockHash());
    CHECK_HASHES(BlockHashes(received[1].Read<std::vector<CInv> >()), ActiveHashes(*this, nHeight, nHeight));

    // Only once
    peer.Send(NetMsgType::GETDATA, BlockInv(Active(500)->GetBlockHash()));
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "block");
}

/** Requested blocks are connected as they arrive and leave flight; the peer is not scored */
BOOST_AUTO_TEST_CASE(requested_blocks_are_connected)
{
    P2PTestMockTime now(Tip()->GetBlockTime() + 60);
    P2PTestPeer peer(*peerLogic);
    const int nHeight = Height();
    const std::vector<CBlock> blocks = BuildOnTip(2);
    peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    BOOST_REQUIRE_EQUAL(peer.Stats().vHeightInFlight.size(), 2U);
    peer.TakeReceived();

    peer.Send(NetMsgType::BLOCK, blocks[0]);
    BOOST_CHECK(Tip()->GetBlockHash() == blocks[0].GetHash());
    BOOST_CHECK(peer.Stats().vHeightInFlight == std::vector<int>({nHeight + 2}));
    peer.Send(NetMsgType::BLOCK, blocks[1]);
    BOOST_CHECK(Tip()->GetBlockHash() == blocks[1].GetHash());
    BOOST_CHECK(peer.Stats().vHeightInFlight.empty());
    BOOST_CHECK(peer.Node().nLastBlockTime > 0);
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
}

/** A block that was not requested and extends the tip by one is connected; the same block again
 * changes nothing and is not scored */
BOOST_AUTO_TEST_CASE(unrequested_block_on_tip_is_connected)
{
    P2PTestPeer peer(*peerLogic);
    const CBlock block = BuildOnTip(1)[0];

    peer.Send(NetMsgType::BLOCK, block);
    const CBlockIndex* pindex = Tip();
    BOOST_CHECK(pindex->GetBlockHash() == block.GetHash());
    BOOST_CHECK(peer.Node().nLastBlockTime > 0);

    peer.Node().nLastBlockTime = 0;
    peer.Send(NetMsgType::BLOCK, block);
    BOOST_CHECK(Tip() == pindex);
    BOOST_CHECK_EQUAL(peer.Node().nLastBlockTime, 0);
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
}

/** With the peer logic notified of validation, a valid block from a peer gets no reject */
BOOST_AUTO_TEST_CASE(valid_block_gets_no_reject)
{
    P2PTestPeer peer(*peerLogic);
    const CBlock block = BuildOnTip(1)[0];
    {
        P2PTestRegistration registration(peerLogic.get());
        peer.Send(NetMsgType::BLOCK, block);
    }
    BOOST_CHECK(Tip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK_EQUAL(Joined(Commands(peer.TakeReceived())), "");
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** SendMessages asks the first suitable peer for headers, from the parent of the best header;
 * a client is not asked */
BOOST_AUTO_TEST_CASE(headers_requested_from_first_suitable_peer)
{
    P2PTestPeer client(*peerLogic, Client());
    client.RunSendMessages();
    BOOST_CHECK(WithCommand(client.TakeReceived(), NetMsgType::GETHEADERS).empty());

    P2PTestPeer peer(*peerLogic);
    peer.RunSendMessages();
    const std::vector<P2PTestMessage> requests = WithCommand(peer.TakeReceived(), NetMsgType::GETHEADERS);
    BOOST_REQUIRE_EQUAL(requests.size(), 1U);
    const std::pair<CBlockLocator, uint256> request = LocatorAndStop(requests[0]);
    BOOST_CHECK(request.first.vHave == Locator(BestHeader()->pprev).vHave);
    BOOST_CHECK(request.second.IsNull());

    // Asked once
    peer.RunSendMessages();
    BOOST_CHECK(WithCommand(peer.TakeReceived(), NetMsgType::GETHEADERS).empty());
}

/** SendMessages requests the blocks up to the peer's best known block in order, at most the
 * per-peer limit at a time, and not the blocks the node has; the tip then reaches the peer's
 * best block */
BOOST_AUTO_TEST_CASE(block_download_in_order)
{
    P2PTestValue<int> limit(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 2);
    // The tip is not recent, so the headers do not make the node request blocks directly
    P2PTestMockTime later(Tip()->GetBlockTime() + 30 * 60);
    P2PTestPeer peer(*peerLogic);
    const std::vector<CBlock> blocks = BuildOnTip(4);
    peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    BOOST_CHECK(Inventory(peer.TakeReceived(), NetMsgType::GETDATA).empty());

    peer.RunSendMessages();
    CHECK_HASHES(BlockHashes(Inventory(peer.TakeReceived(), NetMsgType::GETDATA)), Hashes({blocks[0], blocks[1]}));
    peer.RunSendMessages();
    BOOST_CHECK(Inventory(peer.TakeReceived(), NetMsgType::GETDATA).empty());

    peer.Send(NetMsgType::BLOCK, blocks[0]);
    peer.Send(NetMsgType::BLOCK, blocks[1]);
    BOOST_CHECK(Tip()->GetBlockHash() == blocks[1].GetHash());
    peer.RunSendMessages();
    CHECK_HASHES(BlockHashes(Inventory(peer.TakeReceived(), NetMsgType::GETDATA)), Hashes({blocks[2], blocks[3]}));

    peer.Send(NetMsgType::BLOCK, blocks[2]);
    peer.Send(NetMsgType::BLOCK, blocks[3]);
    BOOST_CHECK(Tip()->GetBlockHash() == blocks[3].GetHash());
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, Height());
    BOOST_CHECK(peer.Stats().vHeightInFlight.empty());
    peer.RunSendMessages();
    BOOST_CHECK(Inventory(peer.TakeReceived(), NetMsgType::GETDATA).empty());
    BOOST_CHECK_EQUAL(peer.Stats().nMisbehavior, 0);
}

/** A peer whose best known block has less chain trust than the tip is asked for no blocks, even
 * when the node does not have that block */
BOOST_AUTO_TEST_CASE(no_block_download_from_peer_behind)
{
    // A block on a shorter branch: its header is known, its data is not
    const int nHeight = Height();
    const CBlock side = BuildP2PTestBlock(ReadP2PTestBlock(Active(nHeight - 2)), nHeight - 1, 1);
    AcceptHeaders({side});
    const CBlockIndex* pindexSide = Index(side.GetHash());
    BOOST_REQUIRE(pindexSide != nullptr);
    BOOST_REQUIRE(!(pindexSide->nStatus & BLOCK_HAVE_DATA));
    BOOST_REQUIRE(pindexSide->bnChainTrust < Tip()->bnChainTrust);

    P2PTestPeer peer(*peerLogic);
    peer.Send(NetMsgType::INV, BlockInv(side.GetHash()));
    BOOST_CHECK_EQUAL(peer.Stats().nSyncHeight, nHeight - 1);
    peer.RunSendMessages();
    BOOST_CHECK(Inventory(peer.TakeReceived(), NetMsgType::GETDATA).empty());
    BOOST_CHECK(peer.Stats().vHeightInFlight.empty());
}

/** Two peers are asked for different blocks: the second is not asked for those in flight from
 * the first */
BOOST_AUTO_TEST_CASE(block_download_from_two_peers_is_disjoint)
{
    P2PTestValue<int> limit(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 2);
    P2PTestMockTime now(Tip()->GetBlockTime() + 60);
    const std::vector<CBlock> blocks = BuildOnTip(3);

    // The first peer announces the blocks by headers and is asked for the first two directly
    P2PTestPeer first(*peerLogic);
    first.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    CHECK_HASHES(BlockHashes(Inventory(first.TakeReceived(), NetMsgType::GETDATA)), Hashes({blocks[0], blocks[1]}));

    // The second announces the last by inv and is asked for it in SendMessages
    P2PTestPeer second(*peerLogic);
    second.Send(NetMsgType::INV, BlockInv(blocks[2].GetHash()));
    second.RunSendMessages();
    CHECK_HASHES(BlockHashes(Inventory(second.TakeReceived(), NetMsgType::GETDATA)), Hashes({blocks[2]}));

    first.Send(NetMsgType::BLOCK, blocks[0]);
    first.Send(NetMsgType::BLOCK, blocks[1]);
    second.Send(NetMsgType::BLOCK, blocks[2]);
    BOOST_CHECK(Tip()->GetBlockHash() == blocks[2].GetHash());
    BOOST_CHECK(first.Stats().vHeightInFlight.empty());
    BOOST_CHECK(second.Stats().vHeightInFlight.empty());
}

/** While the best header is older than a day, the peer the node asked for headers is asked for
 * blocks only when it is the only connection */
BOOST_AUTO_TEST_CASE(headers_peer_asked_for_blocks_when_only_connection)
{
    const std::vector<CBlock> blocks = BuildOnTip(2);
    P2PTestMockTime later(blocks.back().GetBlockTime() + 25 * 60 * 60);
    P2PTestPeer peer(*peerLogic);
    {
        P2PTestPeer client(*peerLogic, Client());
        peer.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
        peer.RunSendMessages();
        const std::vector<P2PTestMessage> received = peer.TakeReceived();
        BOOST_CHECK_EQUAL(WithCommand(received, NetMsgType::GETHEADERS).size(), 1U);
        BOOST_CHECK(Inventory(received, NetMsgType::GETDATA).empty());
    }
    peer.RunSendMessages();
    CHECK_HASHES(BlockHashes(Inventory(peer.TakeReceived(), NetMsgType::GETDATA)), Hashes(blocks));
}

/** In initial download, a peer with nothing to download while the best header is more than the
 * trigger above the tip is sent getblocks, from the best header's grandparent up to the best
 * header, and not again at once; after initial download it is not */
BOOST_AUTO_TEST_CASE(getblocks_sent_when_headers_lead_the_tip)
{
    P2PTestValue<unsigned int> trigger(HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS, 2);
    const std::vector<CBlock> blocks = BuildOnTip(4);
    AcceptHeaders(blocks);
    const CBlockIndex* pindexBestHeader = BestHeader();
    BOOST_REQUIRE(pindexBestHeader->GetBlockHash() == blocks.back().GetHash());

    P2PTestPeer peer(*peerLogic);
    peer.RunSendMessages();
    const std::vector<P2PTestMessage> requests = WithCommand(peer.TakeReceived(), NetMsgType::GETBLOCKS);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    // In initial download (always on this build in the unit tests)
    BOOST_REQUIRE_EQUAL(requests.size(), 1U);
    const std::pair<CBlockLocator, uint256> request = LocatorAndStop(requests[0]);
    BOOST_CHECK(request.first.vHave == Locator(pindexBestHeader->pprev->pprev).vHave);
    BOOST_CHECK(request.second == pindexBestHeader->GetBlockHash());

    peer.RunSendMessages();
    BOOST_CHECK(WithCommand(peer.TakeReceived(), NetMsgType::GETBLOCKS).empty());
#else
    BOOST_CHECK(requests.empty());
#endif
}

/** When the download window cannot move because a peer holds the block it starts with, that peer
 * is disconnected once it has held it for longer than BLOCK_STALLING_TIMEOUT. Here the peer that
 * holds the blocks has no NODE_NETWORK; it announced them by headers and was asked for them
 * directly. */
BOOST_AUTO_TEST_CASE(peer_holding_window_start_is_disconnected)
{
    P2PTestValue<int> limit(MAX_BLOCKS_IN_TRANSIT_PER_PEER, 2);
    P2PTestValue<unsigned int> window(BLOCK_DOWNLOAD_WINDOW, 2);
    P2PTestMockTime now(Tip()->GetBlockTime() + 60);
    const std::vector<CBlock> blocks = BuildOnTip(3);

    P2PTestPeer holder(*peerLogic, Client());
    holder.Send(NetMsgType::HEADERS, P2PTestHeaders(blocks));
    CHECK_HASHES(BlockHashes(Inventory(holder.TakeReceived(), NetMsgType::GETDATA)), Hashes({blocks[0], blocks[1]}));

    // The next block is beyond the window, so the other peer is asked for nothing
    P2PTestPeer other(*peerLogic);
    other.Send(NetMsgType::INV, BlockInv(blocks[2].GetHash()));
    other.RunSendMessages();
    BOOST_CHECK(Inventory(other.TakeReceived(), NetMsgType::GETDATA).empty());

    holder.RunSendMessages();
    BOOST_CHECK(!holder.Node().fDisconnect);
    // The time is the system clock's (GetTimeMicros), which mock time does not change
    MilliSleep(BLOCK_STALLING_TIMEOUT * 1000 + 200);
    holder.RunSendMessages();
    BOOST_CHECK(holder.Node().fDisconnect);
    // The other peer holds nothing and stays
    other.RunSendMessages();
    BOOST_CHECK(!other.Node().fDisconnect);
}

/** NewPoWValidBlock sends the block to each connected peer that has its parent but not the block,
 * once per height */
BOOST_AUTO_TEST_CASE(new_pow_valid_block_sent_to_peers_with_parent)
{
    // Each height is sent once per process. The only other case here in which validation calls
    // the peer logic connects a block just above the fixture's chain, so this case first extends
    // the chain: its heights are above that one in any order.
    Extend(30);
    const CBlock tipBlock = ReadP2PTestBlock(Tip());
    const CBlock block = BuildP2PTestBlock(tipBlock, Height() + 1, 0);
    const CBlock sibling = BuildP2PTestBlock(tipBlock, Height() + 1, 1);
    AcceptHeaders({block});
    AcceptHeaders({sibling});

    P2PTestPeer withParent(*peerLogic);
    withParent.Send(NetMsgType::INV, BlockInv(Tip()->GetBlockHash()));
    P2PTestPeer withoutParent(*peerLogic);
    withParent.TakeReceived();
    withoutParent.TakeReceived();

    peerLogic->NewPoWValidBlock(Index(block.GetHash()), std::make_shared<const CBlock>(block));
    const std::vector<P2PTestMessage> received = withParent.TakeReceived();
    BOOST_REQUIRE_EQUAL(Joined(Commands(received)), "block");
    BOOST_CHECK(received[0].Read<CBlock>().GetHash() == block.GetHash());
    BOOST_CHECK_EQUAL(Joined(Commands(withoutParent.TakeReceived())), "");

    // A block at the same height is not sent
    peerLogic->NewPoWValidBlock(Index(sibling.GetHash()), std::make_shared<const CBlock>(sibling));
    BOOST_CHECK_EQUAL(Joined(Commands(withParent.TakeReceived())), "");
    BOOST_CHECK_EQUAL(Joined(Commands(withoutParent.TakeReceived())), "");
}

BOOST_AUTO_TEST_SUITE_END()
