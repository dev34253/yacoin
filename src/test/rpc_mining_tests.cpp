// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The mining RPCs that need no wallet (rpc/mining.cpp): help texts, getgenerate and
// setgenerate (without starting a miner thread), gethashespersec, getmininginfo, getsubsidy,
// generatetoaddress and generateBlocks, submitblock, and getblocktemplate's proposal mode and
// the checks of its template mode.
//
// On the mainnet build the unit tests stay in initial block download (the checkpoint estimate
// is above the regtest chain), so the template mode is reached up to its initial-download
// check; on the low-difficulty build that check passes, and the cases that would go further
// are left out there.

#include "base58.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpc/blockchain.h"
#include "rpc/mining.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "warnings.h"

#include "test/known_failure.h"
#include "test/rpc_test_util.h"
#include "test/test_bitcoin.h"

#include <memory>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

// Defined in rpc/mining.cpp, which declares them in no header
double GetPoWMHashPS();
extern uint64_t nHashesPerSec;

namespace {

/** Sets a variable while it lives */
template <typename T>
struct ValueGuard {
    T& m_ref;
    const T m_saved;
    ValueGuard(T& ref, T value) : m_ref(ref), m_saved(ref) { m_ref = value; }
    ~ValueGuard() { m_ref = m_saved; }
    ValueGuard(const ValueGuard&) = delete;
    ValueGuard& operator=(const ValueGuard&) = delete;
};

/** A coinbase script of a fresh key, so that no two blocks built here are the same */
CScript FreshScript()
{
    CKey key;
    key.MakeNewKey(true);
    return CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
}

std::string BlockHex(const CBlock& block)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << block;
    return HexStr(ss.begin(), ss.end());
}

uint256 TipHash()
{
    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash();
}

int TipHeight()
{
    LOCK(cs_main);
    return chainActive.Height();
}

/** Raises the nonce until the block meets its target */
void Solve(CBlock& block)
{
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()))
        ++block.nNonce;
}

/** Raises the nonce until the block misses its target */
void Unsolve(CBlock& block)
{
    while (CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()))
        ++block.nNonce;
}

/** A block on the current tip with a valid coinbase and merkle root, not solved */
CBlock NewBlock()
{
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(FreshScript());
    BOOST_REQUIRE(pblocktemplate);
    CBlock block = pblocktemplate->block;
    unsigned int nExtraNonce = 0;
    LOCK(cs_main);
    IncrementExtraNonce(&block, chainActive.Tip(), nExtraNonce);
    return block;
}

CBlock NewSolvedBlock()
{
    CBlock block = NewBlock();
    Solve(block);
    return block;
}

/** A solved block whose coinbase gives the wrong height */
CBlock NewBadHeightBlock()
{
    CBlock block = NewBlock();
    block.vtx[0].vin[0].scriptSig = CScript() << (TipHeight() + 5) << OP_0;
    block.hashMerkleRoot = block.BuildMerkleTree();
    Solve(block);
    return block;
}

void AcceptHeader(const CBlock& block)
{
    CValidationState state;
    BOOST_REQUIRE(ProcessNewBlockHeaders({block.GetBlockHeader()}, state, Params()));
}

UniValue Proposal(const CBlock& block)
{
    UniValue request(UniValue::VOBJ);
    request.pushKV("mode", "proposal");
    request.pushKV("data", BlockHex(block));
    return CallRPCHandler("getblocktemplate", RPCParams(request));
}

/** A coinbase script that counts KeepScript calls */
struct CountingReserveScript : public CReserveScript {
    int nKept = 0;
    void KeepScript() override { ++nKept; }
};

/** Takes g_connman away while it lives */
struct NoConnman {
    std::unique_ptr<CConnman> saved;
    NoConnman() { saved.swap(g_connman); }
    ~NoConnman() { saved.swap(g_connman); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(rpc_mining_tests, TestChain100Setup)

/* Every mining RPC that needs no wallet throws its help text when asked for help or given
 * the wrong number of arguments */
BOOST_AUTO_TEST_CASE(help_and_argument_count)
{
    const UniValue none(UniValue::VARR);
    for (const std::string& method : {"gethashespersec", "getgenerate", "setgenerate", "getsubsidy",
                                      "generatetoaddress", "getmininginfo", "getblocktemplate", "submitblock"}) {
        BOOST_TEST_MESSAGE(method);
        CheckRPCHelp(method, none, true);
    }
    CheckRPCHelp("gethashespersec", RPCParams(1), false);
    CheckRPCHelp("getgenerate", RPCParams(1), false);
    CheckRPCHelp("setgenerate", none, false);
    CheckRPCHelp("setgenerate", RPCParams(false, 1, 2), false);
    CheckRPCHelp("getsubsidy", RPCParams("00", "00"), false);
    CheckRPCHelp("generatetoaddress", RPCParams(1), false);
    CheckRPCHelp("generatetoaddress", RPCParams(1, "a", 1, 2), false);
    CheckRPCHelp("getmininginfo", RPCParams(1), false);
    CheckRPCHelp("getblocktemplate", RPCParams(UniValue(UniValue::VOBJ), 1), false);
    CheckRPCHelp("submitblock", none, false);
    CheckRPCHelp("submitblock", RPCParams("00", "00", "00"), false);
}

/* getgenerate reports the -gen argument, not whether a miner runs */
BOOST_AUTO_TEST_CASE(getgenerate_reflects_gen)
{
    ArgsSnapshot args;
    BOOST_REQUIRE(!gArgs.IsArgSet("-gen"));
    BOOST_CHECK(!CallRPCHandler("getgenerate").get_bool());
    gArgs.ForceSetArg("-gen", "1");
    BOOST_CHECK(CallRPCHandler("getgenerate").get_bool());
    gArgs.ForceSetArg("-gen", "0");
    BOOST_CHECK(!CallRPCHandler("getgenerate").get_bool());
}

/* setgenerate without a miner thread: off, or a processor limit of 0. It writes -gen and
 * -genproclimit and reports "<limit> of <cores>", where a negative limit shows the core count */
BOOST_AUTO_TEST_CASE(setgenerate_without_threads)
{
    ArgsSnapshot args;
    BOOST_REQUIRE(!gArgs.IsArgSet("-genproclimit"));
    BOOST_REQUIRE(!fGenerateYacoins);
    const std::string cores = std::to_string(GetNumCores());

    BOOST_CHECK_EQUAL(CallRPCHandler("setgenerate", RPCParams(false)).get_str(), cores + " of " + cores);
    BOOST_CHECK_EQUAL(gArgs.GetArg("-gen", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-genproclimit", ""), "-1");
    BOOST_CHECK(!CallRPCHandler("getgenerate").get_bool());

    BOOST_CHECK_EQUAL(CallRPCHandler("setgenerate", RPCParams(false, 2)).get_str(), "2 of " + cores);
    BOOST_CHECK_EQUAL(gArgs.GetArg("-gen", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-genproclimit", ""), "2");

    // A stored limit is used when none is given
    BOOST_CHECK_EQUAL(CallRPCHandler("setgenerate", RPCParams(false)).get_str(), "2 of " + cores);

    // A limit of 0 turns generation off even when asked to turn it on
    BOOST_CHECK_EQUAL(CallRPCHandler("setgenerate", RPCParams(true, 0)).get_str(), "0 of " + cores);
    BOOST_CHECK_EQUAL(gArgs.GetArg("-gen", ""), "0");
    BOOST_CHECK_EQUAL(gArgs.GetArg("-genproclimit", ""), "0");
    BOOST_CHECK(!CallRPCHandler("getgenerate").get_bool());
    BOOST_CHECK(!fGenerateYacoins);

    // Parameters of the wrong type
    RPCFailure failure = CallRPCFailure("setgenerate", RPCParams(1));
    BOOST_CHECK(failure.fThrown && !failure.fRPCError);
    BOOST_CHECK_EQUAL(failure.message, "JSON value is not a boolean as expected");
    failure = CallRPCFailure("setgenerate", RPCParams(false, "2"));
    BOOST_CHECK(failure.fThrown && !failure.fRPCError);
    BOOST_CHECK_EQUAL(failure.message, "JSON value is not an integer as expected");
    BOOST_CHECK(!fGenerateYacoins);
}

BOOST_AUTO_TEST_CASE(gethashespersec_reports_the_meter)
{
    ValueGuard<uint64_t> hashes(nHashesPerSec, 123456);
    BOOST_CHECK_EQUAL(CallRPCHandler("gethashespersec").get_int64(), 123456);
    nHashesPerSec = 0;
    BOOST_CHECK_EQUAL(CallRPCHandler("gethashespersec").get_int64(), 0);
}

/* Every field getmininginfo builds, from the chain, the last template and the arguments */
BOOST_AUTO_TEST_CASE(getmininginfo_fields)
{
    ArgsSnapshot args;
    ValueGuard<uint64_t> hashes(nHashesPerSec, 4321);
    gArgs.ForceSetArg("-gen", "1");
    gArgs.ForceSetArg("-genproclimit", "3");
    // An empty template: no transaction, the coinbase's reserved size
    BOOST_REQUIRE(BlockAssembler().CreateNewBlock(FreshScript()));

    const UniValue info = CallRPCHandler("getmininginfo");
    LOCK(cs_main);
    const CBlockIndex* tip = chainActive.Tip();
    BOOST_CHECK_EQUAL(find_value(info, "blocks").get_int(), chainActive.Height());
    BOOST_CHECK_EQUAL(find_value(info, "currentblocksize").get_int64(), 1000);
    BOOST_CHECK_EQUAL(find_value(info, "currentblocktx").get_int64(), 0);
    BOOST_CHECK_CLOSE(find_value(info, "difficulty").get_real(), GetDifficulty(), 1e-9);
    const int64_t nValue = GetProofOfWorkReward(GetLastBlockIndex(tip, false)->nBits, 0, chainActive.Height());
    BOOST_CHECK(nValue > 0);
    BOOST_CHECK_EQUAL(find_value(info, "blockvalue").get_int64(), nValue);
    BOOST_CHECK_CLOSE(find_value(info, "powreward").get_real(), nValue / 1000000.0, 1e-9);
    BOOST_CHECK_CLOSE(find_value(info, "netmhashps").get_real(), GetPoWMHashPS(), 1e-9);
    BOOST_CHECK_EQUAL(find_value(info, "errors").get_str(), GetWarnings("statusbar"));
    BOOST_CHECK(find_value(info, "generate").get_bool());
    BOOST_CHECK_EQUAL(find_value(info, "genproclimit").get_int(), 3);
    BOOST_CHECK_EQUAL(find_value(info, "hashespersec").get_int64(), 4321);
    BOOST_CHECK_EQUAL(find_value(info, "pooledtx").get_int64(), (int64_t)mempool.size());
    BOOST_CHECK_EQUAL(find_value(info, "chain").get_str(), Params().NetworkIDString());
    const unsigned char nFactor = GetNfactor(tip->GetBlockTime(), chainActive.Height() >= nMainnetNewLogicBlockNumber);
    BOOST_CHECK_EQUAL(find_value(info, "Nfactor").get_int(), nFactor);
    BOOST_CHECK_EQUAL(find_value(info, "N").get_int64(), int64_t(1) << (nFactor + 1));
    BOOST_CHECK_EQUAL(find_value(info, "Epoch Interval").get_int64(), (int64_t)nEpochInterval);
    BOOST_CHECK_EQUAL(find_value(info, "Difficulty Interval").get_int64(), (int64_t)nDifficultyInterval);
    BOOST_CHECK_EQUAL(info.size(), 17U);
}

/* Without -genproclimit, getmininginfo shows -1 */
BOOST_AUTO_TEST_CASE(getmininginfo_defaults)
{
    ArgsSnapshot args;
    BOOST_REQUIRE(!gArgs.IsArgSet("-genproclimit"));
    const UniValue info = CallRPCHandler("getmininginfo");
    BOOST_CHECK(!find_value(info, "generate").get_bool());
    BOOST_CHECK_EQUAL(find_value(info, "genproclimit").get_int(), -1);
}

/* The network hash rate from the spacing of the proof-of-work blocks: the first block after
 * genesis brings a long spacing, which the following quick blocks smooth down */
BOOST_AUTO_TEST_CASE(pow_mhash_per_second)
{
    LOCK(cs_main);
    const double fRate = GetPoWMHashPS();
    BOOST_CHECK(fRate > 0);
    // The spacing is at least 30 s, so the rate is at most difficulty * 2^32 / 30 / 10^6
    BOOST_CHECK(fRate <= GetDifficulty() * 4294.967296 / 30);
    // Longer than 30 s here: genesis is far older than the blocks after it
    BOOST_CHECK(fRate < GetDifficulty() * 4294.967296 / 30);
}

/* getsubsidy: the next block's reward for the next target, or for the target given */
BOOST_AUTO_TEST_CASE(getsubsidy_values)
{
    unsigned int nBits;
    int nHeight;
    {
        LOCK(cs_main);
        nBits = GetNextTargetRequired(chainActive.Tip(), false);
        nHeight = chainActive.Height() + 1;
    }
    const int64_t nReward = GetProofOfWorkReward(nBits, 0, nHeight);
    BOOST_CHECK_EQUAL(CallRPCHandler("getsubsidy").get_int64(), nReward);

    for (const std::string& target : {std::string(64, '0'), std::string(64, 'f'), "00000fff" + std::string(56, '0')}) {
        const unsigned int nTargetBits = CBigNum(uint256(target)).GetCompact();
        BOOST_CHECK_EQUAL(CallRPCHandler("getsubsidy", RPCParams(target)).get_int64(),
                          GetProofOfWorkReward(nTargetBits, 0, nHeight));
    }

    // A target that is not hex is not refused
    const RPCFailure failure = CallRPCFailure("getsubsidy", RPCParams("zz"));
    KNOWN_FAILURE("MG-008", failure.message, failure.fRPCError && failure.code == RPC_INVALID_PARAMETER,
                  !failure.fThrown);
    if (!failure.fThrown)
        BOOST_CHECK_EQUAL(CallRPCHandler("getsubsidy", RPCParams("zz")).get_int64(), GetProofOfWorkReward(0, 0, nHeight));

    const RPCFailure notString = CallRPCFailure("getsubsidy", RPCParams(1));
    BOOST_CHECK_EQUAL(notString.message, "JSON value is not a string as expected");
}

/* generatetoaddress mines blocks paying the address and returns their hashes */
BOOST_AUTO_TEST_CASE(generatetoaddress_mines)
{
    CKey key;
    key.MakeNewKey(true);
    const CBitcoinAddress address(key.GetPubKey().GetID());
    const int nHeight = TipHeight();

    const UniValue hashes = CallRPCHandler("generatetoaddress", RPCParams(3, address.ToString()));
    BOOST_REQUIRE_EQUAL(hashes.size(), 3U);
    BOOST_CHECK_EQUAL(TipHeight(), nHeight + 3);
    LOCK(cs_main);
    for (size_t i = 0; i < 3; i++) {
        const CBlockIndex* pindex = chainActive[nHeight + 1 + i];
        BOOST_CHECK_EQUAL(hashes[i].get_str(), pindex->GetBlockHash().GetHex());
        CBlock block;
        BOOST_REQUIRE(ReadBlockFromDisk(block, pindex, Params().GetConsensus()));
        BOOST_CHECK(block.vtx[0].vout[0].scriptPubKey == GetScriptForDestination(address.Get()));
        // generatetoaddress does not sign its blocks
        BOOST_CHECK(block.vchBlockSig.empty());
    }
}

BOOST_AUTO_TEST_CASE(generatetoaddress_limits)
{
    CKey key;
    key.MakeNewKey(true);
    const std::string address = CBitcoinAddress(key.GetPubKey().GetID()).ToString();
    const int nHeight = TipHeight();

    CheckRPCError("generatetoaddress", RPCParams(1, "notanaddress"), RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    // No tries left: nothing is mined
    BOOST_CHECK_EQUAL(CallRPCHandler("generatetoaddress", RPCParams(2, address, 0)).size(), 0U);
    // No blocks asked for
    BOOST_CHECK_EQUAL(CallRPCHandler("generatetoaddress", RPCParams(0, address)).size(), 0U);
    BOOST_CHECK_EQUAL(TipHeight(), nHeight);
    // Enough tries for one block
    BOOST_CHECK_EQUAL(CallRPCHandler("generatetoaddress", RPCParams(1, address, 1000)).size(), 1U);
    BOOST_CHECK_EQUAL(TipHeight(), nHeight + 1);
}

/* With keepScript, generateBlocks keeps the coinbase script once per block */
BOOST_AUTO_TEST_CASE(generate_blocks_keeps_script)
{
    auto script = std::make_shared<CountingReserveScript>();
    script->reserveScript = FreshScript();
    const int nHeight = TipHeight();
    BOOST_CHECK_EQUAL(generateBlocks(script, 2, 1000000, true).size(), 2U);
    BOOST_CHECK_EQUAL(script->nKept, 2);
    BOOST_CHECK_EQUAL(generateBlocks(script, 1, 1000000, false).size(), 1U);
    BOOST_CHECK_EQUAL(script->nKept, 2);
    BOOST_CHECK_EQUAL(TipHeight(), nHeight + 3);
}

BOOST_AUTO_TEST_CASE(submitblock_decoding)
{
    CheckRPCError("submitblock", RPCParams("zz"), RPC_DESERIALIZATION_ERROR, "Block decode failed");

    CBlock block = NewSolvedBlock();
    CBlock noTransactions = block;
    noTransactions.vtx.clear();
    CheckRPCError("submitblock", RPCParams(BlockHex(noTransactions)), RPC_DESERIALIZATION_ERROR,
                  "Block does not start with a coinbase");
    CBlock noCoinbase = block;
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(InsecureRand256(), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    noCoinbase.vtx[0] = CTransaction(tx);
    CheckRPCError("submitblock", RPCParams(BlockHex(noCoinbase)), RPC_DESERIALIZATION_ERROR,
                  "Block does not start with a coinbase");
}

/* BIP22 results: accepted, duplicate, invalid with its reason, duplicate-invalid */
BOOST_AUTO_TEST_CASE(submitblock_results)
{
    const CBlock block = NewSolvedBlock();
    BOOST_CHECK(CallRPCHandler("submitblock", RPCParams(BlockHex(block))).isNull());
    BOOST_CHECK(TipHash() == block.GetHash());
    BOOST_CHECK_EQUAL(CallRPCHandler("submitblock", RPCParams(BlockHex(block))).get_str(), "duplicate");

    // The second argument is ignored
    const CBlock next = NewSolvedBlock();
    BOOST_CHECK(CallRPCHandler("submitblock", RPCParams(BlockHex(next), "ignored")).isNull());
    BOOST_CHECK(TipHash() == next.GetHash());

    const CBlock badHeight = NewBadHeightBlock();
    BOOST_CHECK_EQUAL(CallRPCHandler("submitblock", RPCParams(BlockHex(badHeight))).get_str(), "bad-cb-height");
    BOOST_CHECK(TipHash() == next.GetHash());
    BOOST_CHECK_EQUAL(CallRPCHandler("submitblock", RPCParams(BlockHex(badHeight))).get_str(), "duplicate-invalid");

    // A block that misses its target is refused (the result string is not asserted here)
    CBlock unsolved = NewBlock();
    Unsolve(unsolved);
    const UniValue result = CallRPCHandler("submitblock", RPCParams(BlockHex(unsolved)));
    BOOST_CHECK(result.isStr());
    BOOST_CHECK(TipHash() == next.GetHash());
}

/* Blocks not on the best chain, and blocks whose header was known first */
BOOST_AUTO_TEST_CASE(submitblock_side_branch_and_known_header)
{
    // Three blocks on the same parent: the first becomes the tip
    const CBlock tip = NewSolvedBlock();
    const CBlock side = NewSolvedBlock();
    const CBlock sideWithHeader = NewSolvedBlock();
    BOOST_REQUIRE(tip.GetHash() != side.GetHash() && side.GetHash() != sideWithHeader.GetHash());
    BOOST_CHECK(CallRPCHandler("submitblock", RPCParams(BlockHex(tip))).isNull());

    // Stored without being connected, so no verdict
    BOOST_CHECK_EQUAL(CallRPCHandler("submitblock", RPCParams(BlockHex(side))).get_str(), "inconclusive");
    BOOST_CHECK(TipHash() == tip.GetHash());

    // Header known, block stored but not connected
    AcceptHeader(sideWithHeader);
    BOOST_CHECK_EQUAL(CallRPCHandler("submitblock", RPCParams(BlockHex(sideWithHeader))).get_str(), "duplicate-inconclusive");
    BOOST_CHECK(TipHash() == tip.GetHash());

    // Header known, block connected as the new tip
    const CBlock next = NewSolvedBlock();
    AcceptHeader(next);
    BOOST_CHECK_EQUAL(CallRPCHandler("submitblock", RPCParams(BlockHex(next))).get_str(), "duplicate");
    BOOST_CHECK(TipHash() == next.GetHash());
}

BOOST_AUTO_TEST_CASE(getblocktemplate_request_errors)
{
    UniValue request(UniValue::VOBJ);
    request.pushKV("mode", 5);
    CheckRPCError("getblocktemplate", RPCParams(request), RPC_INVALID_PARAMETER, "Invalid mode");

    request.setObject();
    request.pushKV("mode", "other");
    CheckRPCError("getblocktemplate", RPCParams(request), RPC_INVALID_PARAMETER, "Invalid mode");

    request.setObject();
    request.pushKV("mode", "proposal");
    CheckRPCError("getblocktemplate", RPCParams(request), RPC_TYPE_ERROR, "Missing data String key for proposal");
    request.pushKV("data", 1);
    CheckRPCError("getblocktemplate", RPCParams(request), RPC_TYPE_ERROR, "Missing data String key for proposal");

    request.setObject();
    request.pushKV("mode", "proposal");
    request.pushKV("data", "zz");
    CheckRPCError("getblocktemplate", RPCParams(request), RPC_DESERIALIZATION_ERROR, "Block decode failed");

    const RPCFailure failure = CallRPCFailure("getblocktemplate", RPCParams(1));
    BOOST_CHECK(failure.fThrown && !failure.fRPCError);
    BOOST_CHECK_EQUAL(failure.message, "JSON value is not an object as expected");
}

/* Proposals: known blocks, a block not on the tip, a valid and an invalid block */
BOOST_AUTO_TEST_CASE(getblocktemplate_proposals)
{
    // A valid block on the tip; proof of work is not checked
    CBlock proposal = NewBlock();
    Unsolve(proposal);
    BOOST_CHECK(Proposal(proposal).isNull());
    BOOST_CHECK_EQUAL(Proposal(NewBadHeightBlock()).get_str(), "bad-cb-height");
    CBlock badRoot = NewBlock();
    badRoot.hashMerkleRoot = InsecureRand256();
    BOOST_CHECK_EQUAL(Proposal(badRoot).get_str(), "bad-txnmrklroot");

    const CBlock headerOnly = NewSolvedBlock();
    const CBlock oldTip = NewSolvedBlock();
    const CBlock invalid = NewBadHeightBlock();
    BOOST_CHECK(CallRPCHandler("submitblock", RPCParams(BlockHex(oldTip))).isNull());
    BOOST_CHECK_EQUAL(CallRPCHandler("submitblock", RPCParams(BlockHex(invalid))).get_str(), "bad-cb-height");
    AcceptHeader(headerOnly);

    BOOST_CHECK_EQUAL(Proposal(oldTip).get_str(), "duplicate");
    BOOST_CHECK_EQUAL(Proposal(invalid).get_str(), "duplicate-invalid");
    BOOST_CHECK_EQUAL(Proposal(headerOnly).get_str(), "duplicate-inconclusive");
    // Built on the block before the tip
    BOOST_CHECK_EQUAL(Proposal(proposal).get_str(), "inconclusive-not-best-prevblk");
    BOOST_CHECK(TipHash() == oldTip.GetHash());
}

/* The template mode needs the connection manager, a peer and the end of initial download */
BOOST_AUTO_TEST_CASE(getblocktemplate_template_checks)
{
    {
        NoConnman noConnman;
        CheckRPCError("getblocktemplate", UniValue(UniValue::VARR), RPC_CLIENT_P2P_DISABLED,
                      "Error: Peer-to-peer functionality missing or disabled");
    }
    BOOST_REQUIRE(g_connman);
    BOOST_REQUIRE_EQUAL(g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL), 0U);
    CheckRPCError("getblocktemplate", UniValue(UniValue::VARR), RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");
    CheckRPCError("getblocktemplate", RPCParams(UniValue()), RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

    // A template request with rules and a longpoll id is checked the same way
    UniValue request(UniValue::VOBJ);
    request.pushKV("mode", "template");
    UniValue rules(UniValue::VARR);
    rules.push_back("csv");
    rules.push_back("segwit");
    request.pushKV("rules", rules);
    request.pushKV("longpollid", TipHash().GetHex() + "0");
    CheckRPCError("getblocktemplate", RPCParams(request), RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");
    UniValue noMode(UniValue::VOBJ);
    noMode.pushKV("capabilities", UniValue(UniValue::VARR));
    CheckRPCError("getblocktemplate", RPCParams(noMode), RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    ScopedPeer peer;
    BOOST_REQUIRE_EQUAL(g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL), 1U);
    CheckRPCError("getblocktemplate", UniValue(UniValue::VARR), RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                  "Yacoin is downloading blocks...");
    CheckRPCError("getblocktemplate", RPCParams(request), RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                  "Yacoin is downloading blocks...");
#endif
}

BOOST_AUTO_TEST_SUITE_END()
