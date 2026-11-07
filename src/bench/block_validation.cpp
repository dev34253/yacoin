// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block validation of a block at height 1, on the node of InitBenchNode():
// a coinbase and 1000 transactions, each spending one P2PKH coin of the node's
// coins view to two P2PKH outputs, signed. The block is built once per process,
// not by the miner; its header is a version 7 proof-of-work header with the
// difficulty of GetNextTargetRequired() and the mock time as its time, and its
// coinbase pays the block reward. The genesis block index carries the main
// network's money supply of a recent epoch (BENCH_MONEY_SUPPLY), so the
// block's reward and size limit are the main network's of that epoch. The
// set-up checks that the block passes TestBlockValidity().
//
// - CheckBlock1000Tx: CheckBlock() without the proof-of-work check, with the
//   merkle root check, and the block's checked flag cleared before each call.
// - ConnectBlock1000Tx: TestBlockValidity() with the genesis block as the
//   previous block, without the proof-of-work check, for the block in the
//   state it is in when it is connected (checked by CheckBlock() once): the
//   contextual checks of the header and the block, then ConnectBlock() on a
//   new coins view over the node's.
//
// Both calls must return true every time.

#include "bench/bench.h"
#include "bench/bench_util.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "hash.h"
#include "key.h"
#include "keystore.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "validation.h"

#include <memory>
#include <string>

namespace {
/** The number of transactions after the coinbase */
const int BLOCK_TX_COUNT = 1000;

/** The value of each coin the block's transactions spend */
const CAmount COIN_VALUE = 10 * COIN;

/** The fee each transaction pays */
const CAmount TX_FEE = CENT;

std::string StateText(const CValidationState& state)
{
    return state.GetRejectReason().empty() ? state.GetDebugMessage() : state.GetRejectReason();
}

CBlock BuildBlock()
{
    InitBenchNode();
    LOCK(cs_main);
    CBlockIndex* pindexPrev = chainActive.Tip();
    const int nHeight = pindexPrev->nHeight + 1;

    CKey key;
    key.MakeNewKey(true);
    CBasicKeyStore keystore;
    benchmark::Require(keystore.AddKey(key), "cannot add the key to the key store");
    const CScript scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

    CBlock block;
    block.nVersion = VERSION_of_block_for_yac_05x_new;
    block.hashPrevBlock = pindexPrev->GetBlockHash();
    block.nTime = BENCH_NODE_TIME;
    block.nBits = GetNextTargetRequired(pindexPrev, false);
    block.nNonce = 1;

    CMutableTransaction coinbase;
    coinbase.nVersion = CTransaction::CURRENT_VERSION;
    coinbase.nTime = BENCH_NODE_TIME;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << nHeight << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].scriptPubKey = scriptPubKey;
    coinbase.vout[0].nValue = GetProofOfWorkReward(block.nBits, 0, nHeight);
    block.vtx.push_back(CTransaction(coinbase));

    for (int i = 0; i < BLOCK_TX_COUNT; ++i) {
        // A coin of an earlier transaction, which is not a coinbase
        const COutPoint prevout(Hash(BEGIN(i), END(i)), 0);
        pcoinsTip->AddCoin(prevout, Coin(CTxOut(COIN_VALUE, scriptPubKey), 0, false, false, BENCH_NODE_TIME - 3600), false);

        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::CURRENT_VERSION;
        mtx.nTime = BENCH_NODE_TIME;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = prevout;
        mtx.vout.resize(2);
        mtx.vout[0].scriptPubKey = scriptPubKey;
        mtx.vout[0].nValue = COIN_VALUE / 2;
        mtx.vout[1].scriptPubKey = scriptPubKey;
        mtx.vout[1].nValue = COIN_VALUE - COIN_VALUE / 2 - TX_FEE;
        CTransaction tx(mtx);
        benchmark::Require(SignSignature(keystore, scriptPubKey, tx, 0, SIGHASH_ALL), "cannot sign a transaction");
        block.vtx.push_back(tx);
    }
    block.hashMerkleRoot = block.BuildMerkleTree();

    CValidationState state;
    const bool fValid = TestBlockValidity(state, Params(), block, pindexPrev, false, true);
    benchmark::Require(fValid, "the block does not pass TestBlockValidity: " + StateText(state));
    return block;
}

/** The block, built at the first call */
CBlock& Block()
{
    static std::unique_ptr<CBlock> pblock;
    if (!pblock) pblock.reset(new CBlock(BuildBlock()));
    return *pblock;
}
} // namespace

static void CheckBlock1000Tx(benchmark::State& state)
{
    const CBlock& block = Block();
    const Consensus::Params& consensusParams = Params().GetConsensus();
    while (state.KeepRunning()) {
        block.fChecked = false;
        CValidationState validationState;
        if (!CheckBlock(block, validationState, consensusParams, false, true)) {
            throw benchmark::Failure("CheckBlock failed: " + StateText(validationState));
        }
    }
}

static void ConnectBlock1000Tx(benchmark::State& state)
{
    const CBlock& block = Block();
    const CChainParams& chainparams = Params();
    {
        // The state the block is in when it is connected: checked once by
        // CheckBlock() (which sets the flag only with the proof-of-work check)
        block.fChecked = false;
        CValidationState validationState;
        const bool fValid = CheckBlock(block, validationState, chainparams.GetConsensus(), false, true);
        benchmark::Require(fValid, "CheckBlock failed: " + StateText(validationState));
        block.fChecked = true;
    }
    LOCK(cs_main);
    CBlockIndex* pindexPrev = chainActive.Tip();
    while (state.KeepRunning()) {
        CValidationState validationState;
        if (!TestBlockValidity(validationState, chainparams, block, pindexPrev, false, true)) {
            throw benchmark::Failure("TestBlockValidity failed: " + StateText(validationState));
        }
    }
}

BENCHMARK(CheckBlock1000Tx);
BENCHMARK(ConnectBlock1000Tx);
