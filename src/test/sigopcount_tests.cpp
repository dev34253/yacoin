// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "pubkey.h"
#include "key.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <vector>

#include <boost/test/unit_test.hpp>

// Helpers:
static std::vector<unsigned char>
Serialize(const CScript& s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

BOOST_FIXTURE_TEST_SUITE(sigopcount_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(GetSigOpCount)
{
    // Test CScript::GetSigOpCount()
    CScript s1;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 0U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 0U);

    uint160 dummy;
    s1 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 2U);
    s1 << OP_IF << OP_CHECKSIG << OP_ENDIF;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 21U);

    CScript p2sh = GetScriptForDestination(CScriptID(s1));
    CScript scriptSig;
    scriptSig << OP_0 << Serialize(s1);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig), 3U);

    std::vector<CPubKey> keys;
    for (int i = 0; i < 3; i++)
    {
        CKey k;
        k.MakeNewKey(true);
        keys.push_back(k.GetPubKey());
    }
    CScript s2 = GetScriptForMultisig(1, keys);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(true), 3U);
    BOOST_CHECK_EQUAL(s2.GetSigOpCount(false), 20U);

    p2sh = GetScriptForDestination(CScriptID(s2));
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(true), 0U);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(false), 0U);
    CScript scriptSig2;
    scriptSig2 << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << Serialize(s2);
    BOOST_CHECK_EQUAL(p2sh.GetSigOpCount(scriptSig2), 3U);
}

/**
 * Verifies script execution of the zeroth scriptPubKey of tx output and
 * zeroth scriptSig and witness of tx input.
 */
ScriptError VerifyWithFlag(const CTransaction& output, const CMutableTransaction& input, int flags)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output.vout[0].scriptPubKey, flags, TransactionSignatureChecker(&inputi, 0), &error);
    BOOST_CHECK((ret == true) == (error == SCRIPT_ERR_OK));

    return error;
}

/**
 * Builds a creationTx from scriptPubKey and a spendingTx from scriptSig
 * and witness such that spendingTx spends output zero of creationTx.
 * Also inserts creationTx's output into the coins view.
 */
void BuildTxs(CMutableTransaction& spendingTx, CCoinsViewCache& coins, CMutableTransaction& creationTx, const CScript& scriptPubKey, const CScript& scriptSig)
{
    creationTx.nVersion = 1;
    creationTx.vin.resize(1);
    creationTx.vin[0].prevout.SetNull();
    creationTx.vin[0].scriptSig = CScript();
    creationTx.vout.resize(1);
    creationTx.vout[0].nValue = 1;
    creationTx.vout[0].scriptPubKey = scriptPubKey;

    spendingTx.nVersion = 1;
    spendingTx.vin.resize(1);
    spendingTx.vin[0].prevout.hash = creationTx.GetHash();
    spendingTx.vin[0].prevout.n = 0;
    spendingTx.vin[0].scriptSig = scriptSig;
    spendingTx.vout.resize(1);
    spendingTx.vout[0].nValue = 1;
    spendingTx.vout[0].scriptPubKey = CScript();

    AddCoins(coins, creationTx, 0, uint256());
}

BOOST_AUTO_TEST_CASE(GetTxSigOpCost)
{
    // Transaction creates outputs
    CMutableTransaction creationTx;
    // Transaction that spends outputs and whose
    // sig op cost is going to be tested
    CMutableTransaction spendingTx;

    // Create utxo set
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    // Create key
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    // Default flags
    int flags = SCRIPT_VERIFY_P2SH;

    // Multisig script (legacy counting)
    {
        CScript scriptPubKey = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        // Do not use a valid signature to avoid using wallet operations.
        CScript scriptSig = CScript() << OP_0 << OP_0;

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig);
        // Legacy counting only includes signature operations in scriptSigs and scriptPubKeys
        // of a transaction and does not take the actual executed sig operations into account.
        // spendingTx in itself does not contain a signature operation.
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 0);
        // creationTx contains two signature operations in its scriptPubKey, but legacy counting
        // is not accurate.
        assert(GetTransactionSigOpCost(CTransaction(creationTx), coins, flags) == MAX_PUBKEYS_PER_MULTISIG);
        // Sanity check: script verification fails because of an invalid signature.
        assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }

    // Multisig nested in P2SH
    {
        CScript redeemScript = CScript() << 1 << ToByteVector(pubkey) << ToByteVector(pubkey) << 2 << OP_CHECKMULTISIGVERIFY;
        CScript scriptPubKey = GetScriptForDestination(CScriptID(redeemScript));
        CScript scriptSig = CScript() << OP_0 << OP_0 << ToByteVector(redeemScript);

        BuildTxs(spendingTx, coins, creationTx, scriptPubKey, scriptSig);
        assert(GetTransactionSigOpCost(CTransaction(spendingTx), coins, flags) == 2);
        assert(VerifyWithFlag(creationTx, spendingTx, flags) == SCRIPT_ERR_CHECKMULTISIGVERIFY);
    }
}

BOOST_AUTO_TEST_CASE(GetP2SHSigOpCount_and_cost_by_flags)
{
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();

    // A redeem script with 2 sigops (accurate count), a P2PKH script with 1.
    const CScript redeemScript = CScript() << OP_2 << ToByteVector(pubkey) << ToByteVector(pubkey) << OP_2 << OP_CHECKMULTISIG;
    const CScript p2sh = GetScriptForDestination(CScriptID(redeemScript));
    const CScript p2pkh = GetScriptForDestination(pubkey.GetID());

    CMutableTransaction creationTx;
    creationTx.vin.resize(1);
    creationTx.vin[0].prevout.SetNull();
    creationTx.vin[0].scriptSig = CScript() << OP_1 << OP_1;
    creationTx.vout.resize(2);
    creationTx.vout[0].nValue = 1;
    creationTx.vout[0].scriptPubKey = p2sh;
    creationTx.vout[1].nValue = 1;
    creationTx.vout[1].scriptPubKey = p2pkh;
    const CTransaction creation(creationTx);
    BOOST_REQUIRE(creation.IsCoinBase());
    AddCoins(coins, creation, 0, uint256());

    // A coinbase has no P2SH sigops; its cost is the legacy count of its
    // outputs (1 for the P2PKH output; a P2SH output counts none).
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(creation, coins), 0U);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(creation, coins, SCRIPT_VERIFY_P2SH), 1);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(creation, coins, SCRIPT_VERIFY_NONE), 1);

    // Spending the P2SH output counts the redeem script's sigops.
    CMutableTransaction spendP2SH;
    spendP2SH.vin.resize(1);
    spendP2SH.vin[0].prevout = COutPoint(creation.GetHash(), 0);
    spendP2SH.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << ToByteVector(redeemScript);
    spendP2SH.vout.resize(1);
    spendP2SH.vout[0].nValue = 1;
    spendP2SH.vout[0].scriptPubKey = CScript() << OP_TRUE;
    const CTransaction p2shTx(spendP2SH);
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(p2shTx), 0U);
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(p2shTx, coins), 2U);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(p2shTx, coins, SCRIPT_VERIFY_P2SH), 2);
    // Without the P2SH flag the cost has no P2SH part.
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(p2shTx, coins, SCRIPT_VERIFY_NONE), 0);

    // Spending the P2PKH output: no P2SH sigops.
    CMutableTransaction spendP2PKH(spendP2SH);
    spendP2PKH.vin[0].prevout = COutPoint(creation.GetHash(), 1);
    const CTransaction p2pkhTx(spendP2PKH);
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(p2pkhTx, coins), 0U);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(p2pkhTx, coins, SCRIPT_VERIFY_P2SH), 0);

    // Both inputs together.
    CMutableTransaction spendBoth(spendP2SH);
    spendBoth.vin.push_back(spendP2PKH.vin[0]);
    const CTransaction bothTx(spendBoth);
    BOOST_CHECK_EQUAL(GetP2SHSigOpCount(bothTx, coins), 2U);
    BOOST_CHECK_EQUAL(GetTransactionSigOpCost(bothTx, coins, SCRIPT_VERIFY_P2SH), 2);
}

BOOST_AUTO_TEST_SUITE_END()
