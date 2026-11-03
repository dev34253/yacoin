// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// AcceptToMemoryPool: the order of its checks, the reject code, reason and
// misbehaviour score of each, the entry an accepted transaction gets, version 1
// transactions around the fork height, and the token steps.
//
// Coins are added to the coins cache directly, each under a random outpoint, so
// the transactions are unique in the whole test binary (the signature and script
// caches are shared by all suites). Most spend a pay-to-script-hash output whose
// redeem script is OP_TRUE: no signature, so the size of a transaction is known.

#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "random.h"
#include "script/standard.h"
#include "tokens/tokens.h"
#include "txmempool.h"
#include "utiltime.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/known_failure.h"
#include "test/stake_test_util.h"
#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <boost/test/unit_test.hpp>

namespace {

/** Regtest chain of TestChain100Setup, the token globals, and helpers to fund and submit transactions */
struct MempoolAcceptSetup : public TestChain100Setup, public TokenGlobalsGuard {
    ConsensusGlobalsGuard consensusGuard; // a case may move the fork height
    CScript p2pk;                         // the coinbases' script
    CScript trueScript;
    CScript p2shTrue;

    MempoolAcceptSetup()
    {
        p2pk = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        trueScript = CScript() << OP_TRUE;
        p2shTrue = GetScriptForDestination(CScriptID(trueScript));
    }

    ~MempoolAcceptSetup()
    {
        LOCK(cs_main);
        mempool.clear();
    }

    /** A coin in the coins cache under a random outpoint */
    COutPoint AddCoin(const CScript& script, CAmount nValue, int nHeight = 1, bool fCoinBase = false, bool fCoinStake = false)
    {
        LOCK(cs_main);
        const COutPoint outpoint(GetRandHash(), 0);
        pcoinsTip->AddCoin(outpoint, Coin(CTxOut(nValue, script), nHeight, fCoinBase, fCoinStake, (int)(GetAdjustedTime() - 600)), false);
        return outpoint;
    }

    /** The scriptSig that spends a P2SH output of redeem */
    static CScript RedeemSig(const CScript& redeem)
    {
        return CScript() << std::vector<unsigned char>(redeem.begin(), redeem.end());
    }

    /** One input spending prevout (a P2SH-OP_TRUE output), one output of nValue to out */
    CMutableTransaction SpendTrue(const COutPoint& prevout, CAmount nValue, const CScript& out)
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = prevout;
        tx.vin[0].scriptSig = RedeemSig(trueScript);
        tx.vout.resize(1);
        tx.vout[0].nValue = nValue;
        tx.vout[0].scriptPubKey = out;
        return tx;
    }
    CMutableTransaction SpendTrue(const COutPoint& prevout, CAmount nValue) { return SpendTrue(prevout, nValue, p2shTrue); }

    /** Sign input n of tx, which spends an output of coinbaseKey's P2PK or P2PKH script prevScript */
    void Sign(CMutableTransaction& tx, unsigned int n, const CScript& prevScript)
    {
        std::vector<unsigned char> vchSig;
        const uint256 hash = SignatureHash(prevScript, tx, n, SIGHASH_ALL);
        BOOST_REQUIRE(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        if (prevScript == p2pk) {
            tx.vin[n].scriptSig = CScript() << vchSig;
        } else {
            tx.vin[n].scriptSig = CScript() << vchSig << ToByteVector(coinbaseKey.GetPubKey());
        }
    }

    static unsigned int Size(const CTransaction& tx) { return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION); }

    static bool Submit(const CTransaction& tx, CValidationState& state, bool* pfMissingInputs = nullptr)
    {
        LOCK(cs_main);
        return AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), pfMissingInputs);
    }

    /** Rejected with an invalid state carrying the given score, code and reason; the pool is unchanged */
    static void CheckRejected(const CTransaction& tx, int nDoSExpected, unsigned int nCode, const std::string& strReason)
    {
        const size_t nPoolSize = mempool.size();
        CValidationState state;
        bool fMissingInputs = true;
        BOOST_CHECK(!Submit(tx, state, &fMissingInputs));
        BOOST_CHECK(!fMissingInputs);
        int nDoS = -1;
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, nDoSExpected);
        BOOST_CHECK_EQUAL(state.GetRejectCode(), nCode);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), strReason);
        BOOST_CHECK_EQUAL(mempool.size(), nPoolSize);
    }

    /** Accepted, with an entry holding the fee, the tip's height and whether it spends a coinbase or coinstake */
    static void CheckAccepted(const CTransaction& tx, CAmount nFee, bool fSpendsCoinbase = false)
    {
        CValidationState state;
        bool fMissingInputs = true;
        BOOST_CHECK_MESSAGE(Submit(tx, state, &fMissingInputs), "rejected: " + FormatStateMessage(state));
        BOOST_CHECK(!fMissingInputs);
        BOOST_CHECK(state.IsValid());
        LOCK(mempool.cs);
        auto it = mempool.mapTx.find(tx.GetHash());
        BOOST_REQUIRE(it != mempool.mapTx.end());
        BOOST_CHECK_EQUAL(it->GetFee(), nFee);
        BOOST_CHECK_EQUAL(it->GetHeight(), (unsigned int)chainActive.Height());
        BOOST_CHECK_EQUAL(it->GetSpendsCoinbase(), fSpendsCoinbase);
    }
};

/** Takes the active chain away (Height() == -1) and gives it back */
struct NoActiveChain {
    CBlockIndex* const pTip;
    NoActiveChain() : pTip(chainActive.Tip()) { chainActive.SetTip(nullptr); }
    ~NoActiveChain() { chainActive.SetTip(pTip); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mempool_accept_tests, MempoolAcceptSetup)

/* The checks that need no inputs, in their order */
BOOST_AUTO_TEST_CASE(reject_before_inputs)
{
    // CheckTransaction
    CMutableTransaction empty = SpendTrue(AddCoin(p2shTrue, COIN), COIN - CENT);
    empty.vin.clear();
    CheckRejected(empty, 10, REJECT_INVALID, "bad-txns-vin-empty");

    // CheckTransactionSize: one byte over the block size limit of the next block, and exactly at it
    {
        const unsigned int nLimit = GetMaxSize(MAX_BLOCK_SIZE);
        CMutableTransaction big = SpendTrue(COutPoint(GetRandHash(), 0), COIN);
        size_t nScript = nLimit - Size(big) - 4;
        auto resize = [&](size_t n) { big.vout[0].scriptPubKey = CScript(std::vector<unsigned char>(n, OP_TRUE)); };
        resize(nScript);
        while (Size(big) < nLimit + 1) resize(++nScript);
        while (Size(big) > nLimit + 1) resize(--nScript);
        BOOST_REQUIRE_EQUAL(Size(big), nLimit + 1);
        CheckRejected(big, 100, REJECT_INVALID, "bad-txns-oversize");
        resize(nScript - 1);
        BOOST_REQUIRE_EQUAL(Size(big), nLimit);
        // past the size step, the output script is the next thing that fails
        CheckRejected(big, 0, REJECT_NONSTANDARD, "scriptpubkey");
    }

    // A coinbase and a coinstake are only valid in a block
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << OP_1 << OP_1;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = COIN;
    coinbase.vout[0].scriptPubKey = p2shTrue;
    BOOST_REQUIRE(CTransaction(coinbase).IsCoinBase());
    CheckRejected(coinbase, 100, REJECT_INVALID, "coinbase");

    CMutableTransaction coinstake = SpendTrue(AddCoin(p2shTrue, COIN), 0, CScript());
    coinstake.vout.emplace_back(COIN, p2shTrue);
    BOOST_REQUIRE(CTransaction(coinstake).IsCoinStake());
    CheckRejected(coinstake, 100, REJECT_INVALID, "coinstake");

    // Standardness, checked while fRequireStandard is set (always, outside the tests)
    const COutPoint nonstdCoin = AddCoin(p2shTrue, COIN);
    const CTransaction nonstd = SpendTrue(nonstdCoin, COIN - CENT, trueScript);
    CheckRejected(nonstd, 0, REJECT_NONSTANDARD, "scriptpubkey");
    CMutableTransaction v3 = SpendTrue(AddCoin(p2shTrue, COIN), COIN - CENT);
    v3.nVersion = 3;
    CheckRejected(v3, 0, REJECT_NONSTANDARD, "version");
    {
        // Without it the same transaction gets past both standardness steps
        ValueGuard<bool> standard(fRequireStandard, false);
        CheckAccepted(nonstd, CENT);
    }

    // nLockTime must be final in the next block
    const int nNext = chainActive.Height() + 1;
    CMutableTransaction locked = SpendTrue(AddCoin(p2shTrue, COIN), COIN - CENT);
    locked.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    locked.nLockTime = nNext;
    CheckRejected(locked, 0, REJECT_NONSTANDARD, "non-final");
    locked.nLockTime = nNext - 1;
    CheckAccepted(locked, CENT);
}

/* Duplicates, conflicts and missing inputs */
BOOST_AUTO_TEST_CASE(reject_duplicates_and_missing_inputs)
{
    const COutPoint coin = AddCoin(p2shTrue, COIN);
    const CTransaction tx = SpendTrue(coin, COIN - CENT);
    CheckAccepted(tx, CENT);
    CheckRejected(tx, 0, REJECT_DUPLICATE, "txn-already-in-mempool");
    // Another spend of the same input: no replacement
    CheckRejected(SpendTrue(coin, COIN - 2 * CENT), 0, REJECT_DUPLICATE, "txn-mempool-conflict");

    // An unknown input: false with a valid state, reported through pfMissingInputs if given
    const CTransaction orphan = SpendTrue(COutPoint(GetRandHash(), 0), COIN);
    CValidationState state;
    bool fMissingInputs = false;
    BOOST_CHECK(!Submit(orphan, state, &fMissingInputs));
    BOOST_CHECK(fMissingInputs);
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(state.GetRejectReason().empty());
    CValidationState stateNoFlag;
    BOOST_CHECK(!Submit(orphan, stateNoFlag));
    BOOST_CHECK(stateNoFlag.IsValid());
    BOOST_CHECK(stateNoFlag.GetRejectReason().empty());
    BOOST_CHECK(!mempool.exists(orphan.GetHash()));

    // A mined transaction sent again: its input is spent, its output is in the coins cache
    CMutableTransaction spend;
    spend.vin.emplace_back(COutPoint(coinbaseTxns[0].GetHash(), 0));
    spend.vout.emplace_back(coinbaseTxns[0].vout[0].nValue - CENT, p2shTrue);
    Sign(spend, 0, p2pk);
    const CTransaction mined(spend);
    CreateAndProcessBlock({mined}, p2pk);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(pcoinsTip->HaveCoin(COutPoint(mined.GetHash(), 0)));
        BOOST_REQUIRE(pcoinsTip->HaveCoinInCache(COutPoint(mined.GetHash(), 0)));
    }
    CheckRejected(mined, 0, REJECT_DUPLICATE, "txn-already-known");
}

/* Relative lock times and the input checks of Consensus::CheckTxInputs */
BOOST_AUTO_TEST_CASE(reject_on_inputs)
{
    const int nNext = chainActive.Height() + 1;

    // BIP68: a lock of n blocks on a coin at height 1 is met from height 1 + n on
    const COutPoint lockedCoin = AddCoin(p2shTrue, COIN, 1);
    CMutableTransaction seq = SpendTrue(lockedCoin, COIN - CENT);
    seq.vin[0].nSequence = nNext;
    CheckRejected(seq, 0, REJECT_NONSTANDARD, "non-BIP68-final");
    seq.vin[0].nSequence = nNext - 1;
    CheckAccepted(seq, CENT);
    {
        LOCK(mempool.cs);
        const LockPoints& lp = mempool.mapTx.find(CTransaction(seq).GetHash())->GetLockPoints();
        BOOST_CHECK_EQUAL(lp.height, nNext - 1);
        BOOST_CHECK(lp.maxInputBlock == chainActive[1]);
    }

    // More out than in
    CheckRejected(SpendTrue(AddCoin(p2shTrue, COIN), COIN + 1), 100, REJECT_INVALID, "bad-txns-in-belowout");

    // A transaction older than its input
    CMutableTransaction early = SpendTrue(AddCoin(p2shTrue, COIN), COIN - CENT);
    early.nTime = GetAdjustedTime() - 601;
    CheckRejected(early, 100, REJECT_INVALID, "bad-txns-spent-too-early");

    // Coinbase and coinstake outputs mature at depth GetCoinbaseMaturity() of the next block
    const int nMaturity = GetCoinbaseMaturity();
    BOOST_CHECK_EQUAL(nMaturity, COINBASE_MATURITY_AFTER_HARDFORK);
    CheckRejected(SpendTrue(AddCoin(p2shTrue, COIN, nNext - nMaturity + 1, true), COIN - CENT),
                  0, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase/coinstake");
    CheckRejected(SpendTrue(AddCoin(p2shTrue, COIN, nNext - nMaturity + 1, false, true), COIN - CENT),
                  0, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase/coinstake");
    CheckAccepted(SpendTrue(AddCoin(p2shTrue, COIN, nNext - nMaturity, true), COIN - CENT), CENT, true);
    CheckAccepted(SpendTrue(AddCoin(p2shTrue, COIN, nNext - nMaturity, false, true), COIN - CENT), CENT, true);

    // A real coinbase of the chain, signed
    CMutableTransaction spend;
    spend.vin.emplace_back(COutPoint(coinbaseTxns[0].GetHash(), 0));
    spend.vout.emplace_back(coinbaseTxns[0].vout[0].nValue - CENT, p2shTrue);
    Sign(spend, 0, p2pk);
    CheckAccepted(spend, CENT, true);
}

/* Non-standard P2SH inputs, the minimum fee and the sigop limit */
BOOST_AUTO_TEST_CASE(reject_on_policy)
{
    // A redeem script with more than MAX_P2SH_SIGOPS sigops
    CScript heavy;
    for (unsigned int i = 0; i <= MAX_P2SH_SIGOPS; i++) heavy << OP_CHECKSIG;
    CMutableTransaction nonstdInput = SpendTrue(AddCoin(GetScriptForDestination(CScriptID(heavy)), COIN), COIN - CENT);
    nonstdInput.vin[0].scriptSig = RedeemSig(heavy);
    CheckRejected(nonstdInput, 0, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

    // The fee must reach GetMinFee of the size; the size doesn't depend on the output value
    const COutPoint feeCoin = AddCoin(p2shTrue, COIN);
    const unsigned int nSize = Size(SpendTrue(feeCoin, COIN));
    const CAmount nMinFee = GetMinFee(nSize);
    BOOST_REQUIRE_GT(nMinFee, 0);
    CheckRejected(SpendTrue(feeCoin, COIN - nMinFee + 1), 0, REJECT_INSUFFICIENTFEE, "mempool min fee not met");
    CheckAccepted(SpendTrue(feeCoin, COIN - nMinFee), nMinFee);

    // Sigops: 1-of-3 bare multisig outputs count 20 each, P2PKH outputs 1
    const unsigned int nLimit = GetMaxSize(MAX_BLOCK_SIGOPS) / 5;
    CPubKey pubkey = coinbaseKey.GetPubKey();
    const CScript multisig = GetScriptForMultisig(1, {pubkey, pubkey, pubkey});
    const CScript p2pkh = GetScriptForDestination(pubkey.GetID());
    auto sigops = [&](unsigned int nSigOps) {
        CMutableTransaction tx = SpendTrue(AddCoin(p2shTrue, 10 * COIN), 0);
        tx.vout.clear();
        for (unsigned int i = 0; i < nSigOps / 20; i++) tx.vout.emplace_back(CENT, multisig);
        for (unsigned int i = 0; i < nSigOps % 20; i++) tx.vout.emplace_back(CENT, p2pkh);
        tx.vout.emplace_back(0, p2shTrue);
        tx.vout.back().nValue = 10 * COIN - CTransaction(tx).GetValueOut() - GetMinFee(Size(tx));
        return CTransaction(tx);
    };
    const CTransaction over = sigops(nLimit + 1);
    CheckRejected(over, 0, REJECT_NONSTANDARD, "bad-txns-too-many-sigops");
    const CTransaction at = sigops(nLimit);
    CheckAccepted(at, GetMinFee(Size(at)));
}

/* The ancestor limit and the script checks */
BOOST_AUTO_TEST_CASE(reject_on_chain_and_scripts)
{
    // A chain of DEFAULT_ANCESTOR_LIMIT transactions fits, one more doesn't
    COutPoint prev = AddCoin(p2shTrue, COIN);
    CAmount nValue = COIN;
    for (unsigned int i = 0; i < DEFAULT_ANCESTOR_LIMIT; i++) {
        nValue -= CENT;
        const CTransaction tx = SpendTrue(prev, nValue);
        CheckAccepted(tx, CENT);
        prev = COutPoint(tx.GetHash(), 0);
    }
    CheckRejected(SpendTrue(prev, nValue - CENT), 0, REJECT_NONSTANDARD, "too-long-mempool-chain");

    // A redeem script that leaves false on the stack
    const CScript falseScript = CScript() << OP_FALSE;
    CMutableTransaction fails = SpendTrue(AddCoin(GetScriptForDestination(CScriptID(falseScript)), COIN), COIN - CENT);
    fails.vin[0].scriptSig = RedeemSig(falseScript);
    CheckRejected(fails, 100, REJECT_INVALID,
                  "mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)");

    // A coinbase spend with a signature over another hash
    CMutableTransaction badSig;
    badSig.vin.emplace_back(COutPoint(coinbaseTxns[0].GetHash(), 0));
    badSig.vout.emplace_back(coinbaseTxns[0].vout[0].nValue - CENT, p2shTrue);
    Sign(badSig, 0, p2pk);
    badSig.vout[0].nValue -= 1;
    CheckRejected(badSig, 100, REJECT_INVALID,
                  "mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)");
}

/* Version 1 transactions are refused once the tip has reached the fork height */
BOOST_AUTO_TEST_CASE(version_1_and_fork_height)
{
    const int nTip = chainActive.Height();
    auto v1 = [&]() {
        CMutableTransaction tx = SpendTrue(AddCoin(p2shTrue, COIN), COIN - CENT);
        tx.nVersion = CTransaction::CURRENT_VERSION_of_Tx_for_yac_old;
        return CTransaction(tx);
    };
    {
        // Before the fork a version 1 transaction is valid
        ConsensusGlobalsGuard fork;
        fork.Set(nTip + 2, nEpochInterval);
        CheckAccepted(v1(), CENT);
    }
    {
        // The tip is one below the fork height, so the next block is past it
        ConsensusGlobalsGuard fork;
        fork.Set(nTip + 1, nEpochInterval);
        const CTransaction tx = v1();
        CValidationState state;
        const bool fAccepted = Submit(tx, state);
        // known defect, MG-046: accepted one block before the fork
        KNOWN_FAILURE("MG-046", fAccepted, !fAccepted && state.IsInvalid(), fAccepted && mempool.exists(tx.GetHash()));
    }
    for (int nFork : {nTip, 0}) {
        // At or past the fork
        ConsensusGlobalsGuard fork;
        fork.Set(nFork, nEpochInterval);
        const CTransaction tx = v1();
        CValidationState state;
        const bool fAccepted = Submit(tx, state);
        BOOST_CHECK(!fAccepted);
        BOOST_CHECK(!mempool.exists(tx.GetHash()));
        // known defect, MG-046: refused without a reject reason
        KNOWN_FAILURE("MG-046", state.GetRejectReason(), state.IsInvalid() && !state.GetRejectReason().empty(),
                      !fAccepted && state.IsValid() && state.GetRejectReason().empty());

        // A version 2 transaction is not affected
        CheckAccepted(SpendTrue(AddCoin(p2shTrue, COIN), COIN - CENT), CENT);
    }
    {
        // Without an active chain the fork counts as not reached; the transaction then
        // fails the first check after the version check. With a fork height of 0 only the
        // missing chain keeps the version check from refusing it.
        ConsensusGlobalsGuard fork;
        fork.Set(0, nEpochInterval);
        CMutableTransaction tx = v1();
        tx.vin.clear();
        NoActiveChain noChain;
        CheckRejected(tx, 10, REJECT_INVALID, "bad-txns-vin-empty");
    }
}

/* Before the token activation height a token output only gets a log line */
BOOST_AUTO_TEST_CASE(token_output_before_activation)
{
    ValueGuard<::int32_t> activation(nTokenSupportBlockNumber, chainActive.Height() + 10);
    BOOST_REQUIRE(!AreTokensDeployed());
    CMutableTransaction tx = SpendTrue(AddCoin(p2shTrue, COIN), COIN - CENT);
    tx.vout.emplace_back(0, TransferTokenScript(CTokenTransfer("NOSUCHTOKEN", 5 * COIN)));
    CheckAccepted(tx, CENT);
    BOOST_CHECK(mempool.mapHashToToken.empty());

    // Removing it doesn't touch the token maps either
    mapReissuedTx[tx.GetHash()] = "NOSUCHTOKEN";
    mapReissuedTokens["NOSUCHTOKEN"] = tx.GetHash();
    mempool.removeRecursive(tx);
    BOOST_CHECK(!mempool.exists(tx.GetHash()));
    BOOST_CHECK_EQUAL(mapReissuedTx.size(), 1U);
    BOOST_CHECK_EQUAL(mapReissuedTokens.size(), 1U);
}

/* After activation: an issue and a reissue are accepted and recorded, a second issue of a name is refused */
BOOST_AUTO_TEST_CASE(token_issue_and_reissue)
{
    ValueGuard<::int32_t> activation(nTokenSupportBlockNumber, 0);
    BOOST_REQUIRE(AreTokensDeployed());
    const std::string name = "MEMPOOLTEST";
    const CAmount nLock = GetLockAmount(ETokenType::YATOKEN);
    const CScript p2pkh = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    CNewToken token(name, 1000 * COIN, 0, 1, 0, "");

    auto issue = [&]() {
        CMutableTransaction tx = SpendTrue(AddCoin(p2shTrue, nLock + COIN), COIN - CENT);
        tx.vout.push_back(TokenLockOutput(ETokenType::YATOKEN));
        CScript owner = p2pkh;
        token.ConstructOwnerTransaction(owner);
        tx.vout.emplace_back(0, owner);
        CScript data = p2pkh;
        token.ConstructTransaction(data);
        tx.vout.emplace_back(0, data);
        return CTransaction(tx);
    };
    const CTransaction tx1 = issue();
    CheckAccepted(tx1, CENT);
    // The new token's name is recorded, the owner token's isn't
    BOOST_CHECK(mempool.mapTokenToHash.at(name) == tx1.GetHash());
    BOOST_CHECK_EQUAL(mempool.mapHashToToken.at(tx1.GetHash()), name);
    BOOST_CHECK_EQUAL(mempool.mapTokenToHash.size(), 1U);

    // A second issue of the name fails CheckTxTokens
    CheckRejected(issue(), 100, REJECT_INVALID, "Token with this name is already in the mempool");

    // Mined: the issue leaves the pool and its names leave the maps
    CreateAndProcessBlock({tx1}, p2pk);
    BOOST_REQUIRE(ptokens->CheckIfTokenExists(name));
    BOOST_CHECK(!mempool.exists(tx1.GetHash()));
    BOOST_CHECK(mempool.mapTokenToHash.empty());
    BOOST_CHECK(mempool.mapHashToToken.empty());

    // A reissue spends the owner token and locks YAC
    CMutableTransaction reissue;
    reissue.vin.emplace_back(COutPoint(tx1.GetHash(), 2));
    reissue.vin.emplace_back(AddCoin(p2shTrue, GetLockAmount(ETokenType::REISSUE) + COIN));
    reissue.vin[1].scriptSig = RedeemSig(trueScript);
    reissue.vout.emplace_back(COIN - CENT, p2shTrue);
    reissue.vout.push_back(TokenLockOutput(ETokenType::REISSUE));
    CScript ownerChange = p2pkh;
    CTokenTransfer(name + OWNER_TAG, OWNER_TOKEN_AMOUNT).ConstructTransaction(ownerChange);
    reissue.vout.emplace_back(0, ownerChange);
    CScript reissueData = p2pkh;
    CReissueToken(name, 10 * COIN, -1, 1, "").ConstructTransaction(reissueData);
    reissue.vout.emplace_back(0, reissueData);
    Sign(reissue, 0, tx1.vout[2].scriptPubKey);
    const CTransaction tx2(reissue);
    CheckAccepted(tx2, CENT);
    BOOST_CHECK(mapReissuedTokens.at(name) == tx2.GetHash());
    BOOST_CHECK_EQUAL(mapReissuedTx.at(tx2.GetHash()), name);

    // Leaving the pool frees the reissue
    mempool.removeRecursive(tx2);
    BOOST_CHECK(mapReissuedTokens.empty());
    BOOST_CHECK(mapReissuedTx.empty());
}

BOOST_AUTO_TEST_SUITE_END()
