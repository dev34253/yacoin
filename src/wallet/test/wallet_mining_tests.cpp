// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The mining code that needs a wallet: getwork up to and including its connection and
// initial-download checks, and CheckWork, which takes a solved block to the chain.
//
// On the mainnet build the unit tests stay in initial block download, so getwork answers
// with that error once a peer is present; on the low-difficulty build that check passes and
// the case is left out there.

#include "chainparams.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpc/protocol.h"
#include "validation.h"
#include "wallet/wallet.h"

#include "test/rpc_test_util.h"
#include "wallet/test/wallet_chain_setup.h"

#include <memory>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

namespace {

/** Sets vpwallets while it lives */
struct VpWalletsGuard {
    std::vector<CWallet*> saved;
    explicit VpWalletsGuard(const std::vector<CWallet*>& wallets) : saved(vpwallets) { vpwallets = wallets; }
    ~VpWalletsGuard() { vpwallets = saved; }
    VpWalletsGuard(const VpWalletsGuard&) = delete;
    VpWalletsGuard& operator=(const VpWalletsGuard&) = delete;
};

uint256 TipHash()
{
    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash();
}

uint256 Target(const CBlock& block)
{
    return CBigNum().SetCompact(block.nBits).getuint256();
}

/** A block on the current tip paying script, with its coinbase and merkle root, not solved */
CBlock NewBlock(const CScript& script)
{
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(script);
    BOOST_REQUIRE(pblocktemplate);
    CBlock block = pblocktemplate->block;
    unsigned int nExtraNonce = 0;
    LOCK(cs_main);
    IncrementExtraNonce(&block, chainActive.Tip(), nExtraNonce);
    return block;
}

/** Raises the nonce until the hash is at or below the target */
void Solve(CBlock& block)
{
    while (block.GetHash() > Target(block))
        ++block.nNonce;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_mining_tests, WalletChainSetup)

/* Without a wallet getwork is not available; its help is then empty */
BOOST_AUTO_TEST_CASE(getwork_without_wallet)
{
    VpWalletsGuard noWallets({});
    CheckRPCError("getwork", UniValue(UniValue::VARR), RPC_METHOD_NOT_FOUND,
                  "Method not found (wallet method is disabled because no wallet is loaded)");
    BOOST_CHECK(CallRPCHandler("getwork", UniValue(UniValue::VARR), true).isNull());
}

/* With a wallet: help, the connection check, and the initial-download check */
BOOST_AUTO_TEST_CASE(getwork_checks)
{
    VpWalletsGuard oneWallet({wallet.get()});
    CheckRPCHelp("getwork", UniValue(UniValue::VARR), true);
    CheckRPCHelp("getwork", RPCParams("00", "00"), false);

    BOOST_REQUIRE_EQUAL(g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL), 0U);
    CheckRPCError("getwork", UniValue(UniValue::VARR), RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");
    // Submitted data is not looked at before the checks
    CheckRPCError("getwork", RPCParams("00"), RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    ScopedPeer peer;
    CheckRPCError("getwork", UniValue(UniValue::VARR), RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Yacoin is downloading blocks...");
    CheckRPCError("getwork", RPCParams("00"), RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Yacoin is downloading blocks...");
#endif
}

/* A solved block on the tip is processed and becomes the new tip */
BOOST_AUTO_TEST_CASE(checkwork_accepts_solved_block)
{
    CBlock block = NewBlock(GetScriptForRawPubKey(key.GetPubKey()));
    Solve(block);
    CReserveKey reservekey(wallet.get());
    BOOST_CHECK(CheckWork(&block, *wallet, reservekey));
    BOOST_CHECK(TipHash() == block.GetHash());
}

/* CheckWork refuses blocks before processing them, and reports a block that processing
 * refuses; the tip stays */
BOOST_AUTO_TEST_CASE(checkwork_refuses)
{
    const CScript script = GetScriptForRawPubKey(key.GetPubKey());
    CReserveKey reservekey(wallet.get());
    const uint256 tip = TipHash();

    // Hash above the target
    CBlock unsolved = NewBlock(script);
    while (unsolved.GetHash() <= Target(unsolved))
        ++unsolved.nNonce;
    BOOST_CHECK(!CheckWork(&unsolved, *wallet, reservekey));
    BOOST_CHECK(TipHash() == tip);

    // Solved, but the merkle root does not match the transactions
    CBlock badRoot = NewBlock(script);
    badRoot.hashMerkleRoot = InsecureRand256();
    Solve(badRoot);
    BOOST_CHECK(!CheckWork(&badRoot, *wallet, reservekey));
    BOOST_CHECK(TipHash() == tip);

    // Solved, but the tip moved on since the block was built
    CBlock stale = NewBlock(script);
    Solve(stale);
    const CBlock newTip = Mine({}, false);
    BOOST_REQUIRE(TipHash() == newTip.GetHash());
    BOOST_CHECK(!CheckWork(&stale, *wallet, reservekey));
    BOOST_CHECK(TipHash() == newTip.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()
