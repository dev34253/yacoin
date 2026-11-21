// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// New blocks on a regtest chain with every activation height of the table passed, the
// consensus globals set from the table and an epoch interval of 10 (the chain crosses two
// epoch boundaries). Every block goes through ProcessNewBlock; an accepted block becomes
// the tip, a rejected one leaves the tip as it was and BlockChecked reports its reject
// reason.

#include "chainparams.h"
#include "checkpoints.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "miner.h"
#include "pow.h"
#include "script/interpreter.h"
#include "script/standard.h"
#include "tokens/tokens.h"
#include "validation.h"
#include "validationinterface.h"

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

/** The state BlockChecked reported last for each block, by hash */
struct CheckedBlocks : public CValidationInterface {
    std::map<uint256, CValidationState> states;
    CheckedBlocks() { RegisterValidationInterface(this); }
    ~CheckedBlocks() { UnregisterValidationInterface(this); }
    void BlockChecked(const CBlock& block, const CValidationState& state) override
    {
        states[block.GetHash()] = state;
    }
};

/** An output of a transaction, with what spending it needs */
struct Output {
    COutPoint prevout;
    CTxOut txout;
};

Output Out(const CTransaction& tx, unsigned int n = 0)
{
    return Output{COutPoint(tx.GetHash(), n), tx.vout[n]};
}

const int TIP_EPOCH_INTERVAL = 10;
const int TIP_HEIGHT = 3 * TIP_EPOCH_INTERVAL - 1;
const std::string TOKEN_NAME = "TESTTOKEN";

/** Regtest chain of TIP_HEIGHT blocks mined with the globals of the activation table and
 *  an epoch interval of TIP_EPOCH_INTERVAL; coinbases pay to key */
struct TipChainSetup : public TestingSetup, public TokenGlobalsGuard {
    ConsensusGlobalsGuard globals;
    CKey key;
    CScript script; // P2PKH of key
    std::vector<CTransaction> coinbases; // coinbases[h - 1] is the coinbase of height h
    CheckedBlocks checked;

    TipChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        globals.SetFromActivationTable();
        globals.Set(nMainnetNewLogicBlockNumber, TIP_EPOCH_INTERVAL);
        key.MakeNewKey(true);
        script = GetScriptForDestination(key.GetPubKey().GetID());
        while (Tip()->nHeight < TIP_HEIGHT) {
            CBlock block = BuildBlock({});
            BOOST_REQUIRE(Accept(block));
            coinbases.push_back(block.vtx[0]);
        }
    }

    static CBlockIndex* Tip()
    {
        LOCK(cs_main);
        return chainActive.Tip();
    }

    static int NextHeight() { return Tip()->nHeight + 1; }

    /** Find a nonce, starting at 1, for the block as it is */
    static void Mine(CBlock& block)
    {
        block.fChecked = false;
        if (block.nNonce == 0) block.nNonce = 1;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
    }

    /** Recompute the merkle root, then mine */
    static void Solve(CBlock& block)
    {
        block.hashMerkleRoot = block.BuildMerkleTree();
        Mine(block);
    }

    /** A valid next block from BlockAssembler with the given transactions after its coinbase */
    CBlock BuildBlock(const std::vector<CTransaction>& txs)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(script);
        CBlock block = pblocktemplate->block;
        block.vtx.resize(1);
        for (const CTransaction& tx : txs) block.vtx.push_back(tx);
        block.nTime = std::max(block.GetBlockTime(), block.GetMaxTransactionTime());
        unsigned int nExtraNonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, chainActive.Tip(), nExtraNonce);
        }
        Mine(block);
        return block;
    }

    /** Submits the block; the state BlockChecked reported for it (valid if it reported none) */
    CValidationState Submit(const CBlock& block)
    {
        checked.states.erase(block.GetHash());
        ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, nullptr);
        auto it = checked.states.find(block.GetHash());
        return it == checked.states.end() ? CValidationState() : it->second;
    }

    /** Submits the block; true if it is valid and became the tip */
    bool Accept(const CBlock& block)
    {
        CValidationState state = Submit(block);
        BOOST_CHECK_MESSAGE(state.IsValid(), "rejected: " + state.GetRejectReason() + " " + state.GetDebugMessage());
        return Tip()->GetBlockHash() == block.GetHash();
    }

    /** Submits the block, checks that it is invalid and the tip did not move; its reject reason */
    std::string Reject(const CBlock& block)
    {
        CBlockIndex* pindexBefore = Tip();
        CValidationState state = Submit(block);
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK(Tip() == pindexBefore);
        return state.GetRejectReason();
    }

    /** Signs input n, spending prevScript (P2PKH of key, with or without a time lock), with signer */
    void SignInput(CMutableTransaction& tx, unsigned int n, const CScript& prevScript, const CKey& signer) const
    {
        const uint256 hash = SignatureHash(prevScript, tx, n, SIGHASH_ALL);
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(signer.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[n].scriptSig = CScript() << vchSig << ToByteVector(key.GetPubKey());
    }

    /** A transaction spending prevs and paying their value minus nFee to script; `modify`
     *  changes it before every input is signed with key */
    CTransaction Spend(const std::vector<Output>& prevs, CAmount nFee = CENT,
                       std::function<void(CMutableTransaction&)> modify = nullptr) const
    {
        CMutableTransaction tx;
        CAmount nValue = 0;
        for (const Output& prev : prevs) {
            tx.vin.push_back(CTxIn(prev.prevout));
            nValue += prev.txout.nValue;
        }
        tx.vout.push_back(CTxOut(nValue - nFee, script));
        if (modify) modify(tx);
        for (unsigned int n = 0; n < prevs.size(); n++) SignInput(tx, n, prevs[n].txout.scriptPubKey, key);
        return CTransaction(tx);
    }

    /** The coinbase of height h */
    Output Coinbase(int h) const { return Out(coinbases.at(h - 1)); }

    static ::int64_t Reward(unsigned int nBits, int nHeight)
    {
        LOCK(cs_main);
        return GetProofOfWorkReward(nBits, 0, nHeight);
    }

    static ::uint64_t MaxSize(GetMaxSize_mode mode)
    {
        LOCK(cs_main);
        return GetMaxSize(mode, NextHeight());
    }

    /** Issues TOKEN_NAME (amount nAmount, token and owner outputs to key) in an accepted block */
    CTransaction IssueToken(CAmount nAmount)
    {
        CNewToken token(TOKEN_NAME, nAmount);
        ETokenType type;
        BOOST_REQUIRE(IsTokenNameValid(token.strName, type));
        CScript ownerScript = script;
        token.ConstructOwnerTransaction(ownerScript);
        CScript tokenScript = script;
        token.ConstructTransaction(tokenScript);
        const CTxOut lock = TokenLockOutput(type);
        CTransaction issue = Spend({Coinbase(1), Coinbase(2), Coinbase(3)}, CENT, [&](CMutableTransaction& tx) {
            tx.vout[0].nValue -= lock.nValue;
            tx.vout.insert(tx.vout.begin(), lock);
            tx.vout.push_back(CTxOut(0, ownerScript));
            tx.vout.push_back(CTxOut(0, tokenScript));
        });
        BOOST_REQUIRE(Accept(BuildBlock({issue})));
        return issue;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(tip_block_tests, TipChainSetup)

BOOST_AUTO_TEST_CASE(tip_state)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    CBlockIndex* pindexTip = Tip();
    BOOST_CHECK_EQUAL(pindexTip->nHeight, TIP_HEIGHT);
    for (int rule = 0; rule < Consensus::MAX_ACTIVATION_RULES; rule++)
        BOOST_CHECK_LE(consensus.ActivationHeight(Consensus::ActivationRule(rule)), pindexTip->nHeight);
    BOOST_CHECK_EQUAL(nMainnetNewLogicBlockNumber, consensus.ActivationHeight(Consensus::ACTIVATION_NEW_LOGIC));
    BOOST_CHECK_EQUAL(nTokenSupportBlockNumber, consensus.ActivationHeight(Consensus::ACTIVATION_TOKENS));
    BOOST_CHECK(AreTokensDeployed());
    {
        LOCK(cs_main);
        BOOST_CHECK_GT(pindexTip->nHeight, Checkpoints::GetTotalBlocksEstimate());
        CBlockIndex* pindexCheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
        BOOST_REQUIRE(pindexCheckpoint);
        BOOST_CHECK_GT(pindexTip->nHeight, pindexCheckpoint->nHeight);
    }
    BOOST_CHECK(!IsInitialBlockDownload());
    BOOST_CHECK_EQUAL(nEpochInterval, (::uint32_t)TIP_EPOCH_INTERVAL);
    BOOST_CHECK_EQUAL(nDifficultyInterval, (::uint32_t)TIP_EPOCH_INTERVAL);
    BOOST_CHECK_GE(pindexTip->nHeight, 2 * TIP_EPOCH_INTERVAL);
    // The target changed at the second boundary
    BOOST_CHECK(pindexTip->GetAncestor(2 * TIP_EPOCH_INTERVAL)->nBits != pindexTip->GetAncestor(2 * TIP_EPOCH_INTERVAL - 1)->nBits);
    BOOST_CHECK_EQUAL(pindexTip->nVersion, VERSION_of_block_for_yac_05x_new);
    BOOST_CHECK_EQUAL(BuildBlock({}).nVersion, VERSION_of_block_for_yac_05x_new);
}

BOOST_AUTO_TEST_CASE(accept_p2pkh_spend)
{
    CBlock block = BuildBlock({Spend({Coinbase(1)})});
    BOOST_CHECK_EQUAL(block.vtx[0].GetValueOut(), Reward(block.nBits, NextHeight()));
    BOOST_CHECK(Accept(block));
    LOCK(cs_main);
    BOOST_CHECK(!pcoinsTip->HaveCoin(Coinbase(1).prevout));
    BOOST_CHECK(pcoinsTip->HaveCoin(COutPoint(block.vtx[1].GetHash(), 0)));
}

BOOST_AUTO_TEST_CASE(accept_cltv_and_csv_spends)
{
    const CKeyID keyID = key.GetPubKey().GetID();
    const int nFundHeight = NextHeight();
    const uint32_t nLockHeight = nFundHeight + 1;
    const uint32_t nRelativeLock = 2;
    CTransaction fund = Spend({Coinbase(1)}, CENT, [&](CMutableTransaction& tx) {
        tx.vout[0].nValue /= 2;
        tx.vout.push_back(CTxOut(tx.vout[0].nValue, GetScriptForCltvP2PKH(nLockHeight, keyID)));
        tx.vout[0].scriptPubKey = GetScriptForCsvP2PKH(nRelativeLock, keyID);
    });
    BOOST_REQUIRE(Accept(BuildBlock({fund})));
    BOOST_REQUIRE(Accept(BuildBlock({})));

    CTransaction spendCltv = Spend({Out(fund, 1)}, CENT, [&](CMutableTransaction& tx) {
        tx.nLockTime = nLockHeight;
        tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    });
    CTransaction spendCsv = Spend({Out(fund, 0)}, CENT, [&](CMutableTransaction& tx) {
        tx.vin[0].nSequence = nRelativeLock;
    });
    BOOST_CHECK_EQUAL(NextHeight(), nFundHeight + (int)nRelativeLock);
    BOOST_CHECK(Accept(BuildBlock({spendCltv, spendCsv})));
}

BOOST_AUTO_TEST_CASE(accept_token_issue_and_transfer)
{
    const CAmount nAmount = 1000 * COIN;
    CTransaction issue = IssueToken(nAmount);
    BOOST_CHECK(GetCurrentTokenCache()->CheckIfTokenExists(TOKEN_NAME));

    CTransaction transfer = Spend({Out(issue, issue.vout.size() - 1), Coinbase(4)}, CENT, [&](CMutableTransaction& tx) {
        tx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer(TOKEN_NAME, nAmount), 2)));
    });
    BOOST_CHECK(Accept(BuildBlock({transfer})));
}

BOOST_AUTO_TEST_CASE(accept_first_block_of_epoch)
{
    const int nHeight = NextHeight();
    BOOST_REQUIRE_EQUAL(nHeight % TIP_EPOCH_INTERVAL, 0);
    CBlock block = BuildBlock({Spend({Coinbase(1)})});
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(block.nBits, GetNextTargetRequired(chainActive.Tip(), false));
    }
    BOOST_CHECK(block.nBits != Tip()->nBits);
    BOOST_CHECK_EQUAL(block.vtx[0].GetValueOut(), Reward(block.nBits, nHeight));
    BOOST_CHECK(Reward(block.nBits, nHeight) != Reward(Tip()->nBits, nHeight - 1));
    BOOST_CHECK(Accept(block));
}

BOOST_AUTO_TEST_CASE(reject_proof_of_work)
{
    CBlock block = BuildBlock({});
    while (CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
    block.fChecked = false;
    // The failure has no reject reason
    BOOST_CHECK_EQUAL(Reject(block), "");
}

BOOST_AUTO_TEST_CASE(reject_bits_of_previous_epoch)
{
    BOOST_REQUIRE_EQUAL(NextHeight() % TIP_EPOCH_INTERVAL, 0);
    CBlock block = BuildBlock({});
    BOOST_REQUIRE(block.nBits != Tip()->nBits);
    block.nBits = Tip()->nBits;
    Mine(block);
    BOOST_CHECK_EQUAL(Reject(block), "bad-diffbits");
}

BOOST_AUTO_TEST_CASE(reject_reward_in_first_block_of_epoch)
{
    BOOST_REQUIRE_EQUAL(NextHeight() % TIP_EPOCH_INTERVAL, 0);
    CBlock block = BuildBlock({});
    block.vtx[0].vout[0].nValue = Reward(block.nBits, NextHeight()) + 1;
    Solve(block);
    BOOST_CHECK_EQUAL(Reject(block), "bad-cb-amount");
}

BOOST_AUTO_TEST_CASE(reject_empty_block)
{
    CBlock block = BuildBlock({});
    block.vtx.clear();
    Solve(block);
    BOOST_CHECK_EQUAL(Reject(block), "bad-blk-length");
}

BOOST_AUTO_TEST_CASE(reject_coinbase_time)
{
    CBlock block = BuildBlock({});
    block.vtx[0].nTime = block.nTime + MAX_FUTURE_BLOCK_TIME + 1;
    Solve(block);
    BOOST_CHECK_EQUAL(Reject(block), "bad-cb-time");
}

BOOST_AUTO_TEST_CASE(reject_output_value)
{
    CTransaction tx = Spend({Coinbase(1)}, CENT, [](CMutableTransaction& tx) { tx.vout[0].nValue = MAX_MONEY + 1; });
    BOOST_CHECK_EQUAL(Reject(BuildBlock({tx})), "bad-txns-vout-toolarge");
}

BOOST_AUTO_TEST_CASE(reject_duplicate_inputs)
{
    CTransaction tx = Spend({Coinbase(1), Coinbase(1)});
    BOOST_CHECK_EQUAL(Reject(BuildBlock({tx})), "bad-txns-inputs-duplicate");
}

BOOST_AUTO_TEST_CASE(reject_coinbase_script_size)
{
    CBlock block = BuildBlock({});
    block.vtx[0].vin[0].scriptSig = CScript() << NextHeight() << std::vector<unsigned char>(100, 0x01);
    BOOST_REQUIRE_GT(block.vtx[0].vin[0].scriptSig.size(), 100U);
    Solve(block);
    BOOST_CHECK_EQUAL(Reject(block), "bad-cb-length");
}

BOOST_AUTO_TEST_CASE(reject_transfer_token_name)
{
    CTransaction tx = Spend({Coinbase(1)}, CENT, [](CMutableTransaction& tx) {
        tx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("invalid", COIN))));
    });
    BOOST_CHECK_EQUAL(Reject(BuildBlock({tx})), "bad-txns-transfer-token-name-invalid");
}

BOOST_AUTO_TEST_CASE(reject_block_size)
{
    const ::uint64_t nMaxSize = MaxSize(MAX_BLOCK_SIZE);
    CBlock block = BuildBlock({});
    unsigned int nSizeBefore = 0;
    for (int h = 1; ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) <= nMaxSize; h++) {
        nSizeBefore = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
        block.vtx.push_back(Spend({Coinbase(h)}, CENT, [&](CMutableTransaction& tx) {
            tx.vout.push_back(CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>(nMaxSize / 4, 0x01)));
        }));
    }
    BOOST_CHECK_LE(nSizeBefore, nMaxSize);
    BOOST_CHECK_GT(block.vtx.size(), 2U);
    for (const CTransaction& tx : block.vtx)
        BOOST_CHECK_LE(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION), nMaxSize);
    block.nTime = std::max(block.GetBlockTime(), block.GetMaxTransactionTime());
    Solve(block);
    BOOST_CHECK_EQUAL(Reject(block), "bad-blk-length");
}

BOOST_AUTO_TEST_CASE(reject_legacy_sigops)
{
    const ::uint64_t nMaxSigOps = MaxSize(MAX_BLOCK_SIGOPS);
    CScript multisigs;
    for (::uint64_t n = 0; n <= nMaxSigOps / MAX_PUBKEYS_PER_MULTISIG; n++) multisigs << OP_CHECKMULTISIG;
    CTransaction tx = Spend({Coinbase(1)}, CENT, [&](CMutableTransaction& tx) { tx.vout.push_back(CTxOut(0, multisigs)); });
    BOOST_REQUIRE_GT(GetLegacySigOpCount(tx), nMaxSigOps);
    BOOST_CHECK_EQUAL(Reject(BuildBlock({tx})), "bad-blk-sigops");
}

BOOST_AUTO_TEST_CASE(reject_p2sh_sigops)
{
    CScript redeemScript;
    while (redeemScript.size() < MAX_SCRIPT_ELEMENT_SIZE) redeemScript << OP_CHECKMULTISIG;
    const CScript p2sh = GetScriptForDestination(CScriptID(redeemScript));
    const ::uint64_t nMaxSigOps = MaxSize(MAX_BLOCK_SIGOPS);
    const unsigned int nOutputs = nMaxSigOps / redeemScript.GetSigOpCount(true) + 1;
    CTransaction fund = Spend({Coinbase(1)}, CENT, [&](CMutableTransaction& tx) {
        const CAmount nValue = tx.vout[0].nValue / nOutputs;
        tx.vout.clear();
        for (unsigned int n = 0; n < nOutputs; n++) tx.vout.push_back(CTxOut(nValue, p2sh));
    });
    BOOST_REQUIRE(Accept(BuildBlock({fund})));

    CMutableTransaction spend;
    CAmount nValue = 0;
    for (unsigned int n = 0; n < nOutputs; n++) {
        spend.vin.push_back(CTxIn(COutPoint(fund.GetHash(), n), CScript() << ToByteVector(redeemScript)));
        nValue += fund.vout[n].nValue;
    }
    spend.vout.push_back(CTxOut(nValue - CENT, script));
    CBlock block = BuildBlock({CTransaction(spend)});
    unsigned int nLegacy = 0;
    for (const CTransaction& tx : block.vtx) nLegacy += GetLegacySigOpCount(tx);
    BOOST_REQUIRE_LE(nLegacy, nMaxSigOps);
    BOOST_REQUIRE_GT(nLegacy + nOutputs * redeemScript.GetSigOpCount(true), nMaxSigOps);
    BOOST_CHECK_EQUAL(Reject(block), "bad-blk-sigops");
}

BOOST_AUTO_TEST_CASE(reject_value_in_below_out)
{
    CTransaction tx = Spend({Coinbase(1)}, -1);
    BOOST_CHECK_EQUAL(Reject(BuildBlock({tx})), "bad-txns-in-belowout");
}

BOOST_AUTO_TEST_CASE(reject_token_transfer_above_inputs)
{
    const CAmount nAmount = 1000 * COIN;
    CTransaction issue = IssueToken(nAmount);
    CTransaction transfer = Spend({Out(issue, issue.vout.size() - 1), Coinbase(4)}, CENT, [&](CMutableTransaction& tx) {
        tx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer(TOKEN_NAME, nAmount + COIN), 2)));
    });
    BOOST_CHECK_EQUAL(Reject(BuildBlock({transfer})),
                      "bad-tx-inputs-outputs-mismatch Bad Transaction - Tokens would be burnt " + TOKEN_NAME);
}

BOOST_AUTO_TEST_CASE(reject_transfer_of_unknown_token)
{
    CTransaction tx = Spend({Coinbase(1)}, CENT, [](CMutableTransaction& tx) {
        tx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer(TOKEN_NAME, COIN))));
    });
    BOOST_CHECK_EQUAL(Reject(BuildBlock({tx})), "bad-txns-transfer-token-not-exist");
}

BOOST_AUTO_TEST_CASE(reject_signature)
{
    CKey otherKey;
    otherKey.MakeNewKey(true);
    CMutableTransaction tx(Spend({Coinbase(1)}));
    SignInput(tx, 0, Coinbase(1).txout.scriptPubKey, otherKey);
    const std::string reason = Reject(BuildBlock({CTransaction(tx)}));
    const std::string prefix = "mandatory-script-verify-flag-failed";
    BOOST_CHECK_EQUAL(reason.substr(0, prefix.size()), prefix);
}

BOOST_AUTO_TEST_CASE(reject_cltv_spend)
{
    const int nFundHeight = NextHeight();
    const uint32_t nLockHeight = nFundHeight + 5;
    CTransaction fund = Spend({Coinbase(1)}, CENT, [&](CMutableTransaction& tx) {
        tx.vout[0].scriptPubKey = GetScriptForCltvP2PKH(nLockHeight, key.GetPubKey().GetID());
    });
    BOOST_REQUIRE(Accept(BuildBlock({fund})));
    CTransaction spend = Spend({Out(fund)}, CENT, [&](CMutableTransaction& tx) {
        tx.nLockTime = nFundHeight;
        tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    });
    BOOST_CHECK_EQUAL(Reject(BuildBlock({spend})), "non-mandatory-script-verify-flag (Locktime requirement not satisfied)");
}

BOOST_AUTO_TEST_CASE(reject_csv_spend)
{
    const uint32_t nRelativeLock = 5;
    CTransaction fund = Spend({Coinbase(1)}, CENT, [&](CMutableTransaction& tx) {
        tx.vout[0].scriptPubKey = GetScriptForCsvP2PKH(nRelativeLock, key.GetPubKey().GetID());
    });
    BOOST_REQUIRE(Accept(BuildBlock({fund})));
    CTransaction spend = Spend({Out(fund)}, CENT, [&](CMutableTransaction& tx) { tx.vin[0].nSequence = 1; });
    BOOST_CHECK_EQUAL(Reject(BuildBlock({spend})), "non-mandatory-script-verify-flag (Locktime requirement not satisfied)");
}

BOOST_AUTO_TEST_SUITE_END()
