// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Signing of transactions by the wallet, transaction creation and its failures, and a send
// the mempool refuses, on a regtest chain with a mock wallet database.

#include "policy/policy.h"
#include "script/interpreter.h"
#include "tokens/tokens.h"
#include "util.h"
#include "wallet/coincontrol.h"

#include "wallet/test/wallet_chain_setup.h"

#include <boost/test/unit_test.hpp>

namespace {

/** All inputs of tx carry valid signatures for the outputs they spend in wallet */
bool SignaturesValid(const CWallet& wallet, const CTransaction& tx)
{
    LOCK(wallet.cs_wallet);
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prev = wallet.mapWallet.at(tx.vin[i].prevout.hash).tx->vout[tx.vin[i].prevout.n];
        ScriptError error;
        if (!VerifyScript(tx.vin[i].scriptSig, prev.scriptPubKey, STANDARD_SCRIPT_VERIFY_FLAGS,
                          TransactionSignatureChecker(&tx, i), &error))
            return false;
    }
    return true;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_spend_tests, WalletChainSetup)

BOOST_AUTO_TEST_CASE(sign_transaction)
{
    const CKey watchKey = NewWalletTestKey();
    const CScript watched = GetScriptForDestination(watchKey.GetPubKey().GetID());
    BOOST_REQUIRE(wallet->AddWatchOnly(watched, 1));
    const CTransaction fund = Fund({CTxOut(2 * COIN, script), CTxOut(3 * COIN, script), CTxOut(4 * COIN, watched)});
    const CScript other = GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID());

    // Inputs spending outputs of the wallet get valid signatures
    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 0)));
    tx.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 1)));
    tx.vout.push_back(CTxOut(4 * COIN, other));
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->SignTransaction(tx));
    }
    BOOST_CHECK(!tx.vin[0].scriptSig.empty());
    BOOST_CHECK(SignaturesValid(*wallet, tx));

    // An input the wallet does not know, an output index past the end and an output the
    // wallet only watches are refused
    LOCK(wallet->cs_wallet);
    for (const COutPoint& prevout : {COutPoint(InsecureRand256(), 0), COutPoint(fund.GetHash(), 3), COutPoint(fund.GetHash(), 2)}) {
        CTransaction refused;
        refused.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 0)));
        refused.vin.push_back(CTxIn(prevout));
        refused.vout.push_back(CTxOut(COIN, other));
        BOOST_CHECK(!wallet->SignTransaction(refused));
    }
}

BOOST_AUTO_TEST_CASE(create_transaction)
{
    const CTransaction fund = Fund({CTxOut(COIN, script), CTxOut(5 * COIN, script)});
    const CScript other = GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID());
    CReserveKey reservekey(wallet.get());
    CWalletTx wtx;
    CAmount nFee = 0;
    int nChangePos = -1;
    std::string strFailReason;

    // With the fee taken from the amount, the output pays the amount less the fee
    BOOST_CHECK(wallet->CreateTransaction({CRecipient{other, 2 * COIN, true}}, wtx, reservekey, nFee, nChangePos,
                                          strFailReason, CCoinControl()));
    BOOST_CHECK(nFee > 0);
    BOOST_REQUIRE_EQUAL(wtx.tx->vout.size(), 2U);
    BOOST_REQUIRE(nChangePos == 0 || nChangePos == 1);
    BOOST_CHECK(wtx.tx->vout[1 - nChangePos] == CTxOut(2 * COIN - nFee, other));

    // A selected input with other inputs allowed is spent together with another input
    const COutPoint selected(fund.GetHash(), 0);
    CCoinControl withOthers;
    withOthers.Select(selected);
    withOthers.fAllowOtherInputs = true;
    BOOST_CHECK(withOthers.IsSelected(selected));
    BOOST_CHECK(!withOthers.IsSelected(COutPoint(fund.GetHash(), 1)));
    nChangePos = -1;
    BOOST_CHECK(wallet->CreateTransaction({CRecipient{other, 3 * COIN, false}}, wtx, reservekey, nFee, nChangePos,
                                          strFailReason, withOthers));
    BOOST_REQUIRE_EQUAL(wtx.tx->vin.size(), 2U);
    BOOST_CHECK(wtx.tx->vin[0].prevout == selected || wtx.tx->vin[1].prevout == selected);
}

BOOST_AUTO_TEST_CASE(create_transaction_failures)
{
    const CKey watchKey = NewWalletTestKey();
    const CScript watchedRaw = GetScriptForRawPubKey(watchKey.GetPubKey());
    const CScript watchedAddress = GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID());
    BOOST_REQUIRE(wallet->AddWatchOnly(watchedRaw, 1));
    BOOST_REQUIRE(wallet->AddWatchOnly(watchedAddress, 1));
    const CTransaction fund = Fund({CTxOut(5 * COIN, script), CTxOut(6 * COIN, watchedRaw), CTxOut(7 * COIN, watchedAddress)});
    const CScript other = GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID());
    CReserveKey reservekey(wallet.get());
    CWalletTx wtx;
    CAmount nFee = 0;
    int nChangePos = -1;
    std::string strFailReason;

    // A negative amount
    BOOST_CHECK(!wallet->CreateTransaction({CRecipient{other, COIN, false}, CRecipient{other, -1, false}}, wtx, reservekey,
                                           nFee, nChangePos, strFailReason, CCoinControl()));
    BOOST_CHECK_EQUAL(strFailReason, "Transaction amounts must not be negative");

    // A watched output whose script the wallet could sign for, selected with watch-only
    // allowed, is taken, and then cannot be signed
    CCoinControl watchOnly;
    watchOnly.fAllowWatchOnly = true;
    watchOnly.Select(COutPoint(fund.GetHash(), 1));
    BOOST_CHECK(!wallet->CreateTransaction({CRecipient{other, COIN, false}}, wtx, reservekey, nFee, nChangePos,
                                           strFailReason, watchOnly));
    BOOST_CHECK_EQUAL(strFailReason, "Signing transaction failed");

    // A selected watch-only output that is not spendable is not taken
    CCoinControl notSpendable;
    notSpendable.Select(COutPoint(fund.GetHash(), 2));
    BOOST_CHECK(!wallet->CreateTransaction({CRecipient{other, COIN, false}}, wtx, reservekey, nFee, nChangePos,
                                           strFailReason, notSpendable));
    BOOST_CHECK_EQUAL(strFailReason, "Insufficient funds");

    // A selected input past the outputs of a wallet transaction, or one the wallet does not
    // know, with other inputs allowed: insufficient funds
    for (const COutPoint& prevout : {COutPoint(fund.GetHash(), 7), COutPoint(InsecureRand256(), 0)}) {
        CCoinControl withOthers;
        withOthers.Select(prevout);
        withOthers.fAllowOtherInputs = true;
        strFailReason.clear();
        BOOST_CHECK(!wallet->CreateTransaction({CRecipient{other, COIN, false}}, wtx, reservekey, nFee, nChangePos,
                                               strFailReason, withOthers));
        BOOST_CHECK_EQUAL(strFailReason, "Insufficient funds");
    }

    // A change position past the outputs
    nChangePos = 2;
    BOOST_CHECK(!wallet->CreateTransaction({CRecipient{other, COIN, false}}, wtx, reservekey, nFee, nChangePos,
                                           strFailReason, CCoinControl()));
    BOOST_CHECK_EQUAL(strFailReason, "Change index out of range");
    nChangePos = -1;

    // Token flags: refused before tokens are active, and a reissue without data
    const CTxDestination dest = key.GetPubKey().GetID();
    const CNewToken token;
    {
        ValueGuard<int32_t> notActive(nTokenSupportBlockNumber, chainActive.Height() + 10);
        BOOST_CHECK(!wallet->CreateTransactionWithTransferToken({CRecipient{other, COIN, false}}, wtx, reservekey, nFee,
                                                                nChangePos, strFailReason, CCoinControl()));
    }
    BOOST_CHECK(!wallet->CreateTransactionAll({CRecipient{other, COIN, false}}, wtx, reservekey, nFee, nChangePos,
                                              strFailReason, CCoinControl(), nullptr, false, false, token, dest, false,
                                              true, CReissueToken(), ETokenType::REISSUE));

    // Two token flags at once are refused: new and transfer, reissue and transfer, reissue and new
    const CReissueToken reissue("TOKEN", COIN, 0, 1, "");
    const auto createWithFlags = [&](bool fNew, bool fTransfer, bool fReissue) {
        return wallet->CreateTransactionAll({CRecipient{other, COIN, false}}, wtx, reservekey, nFee, nChangePos,
                                            strFailReason, CCoinControl(), nullptr, false, fNew, token, dest, fTransfer,
                                            fReissue, reissue, ETokenType::REISSUE);
    };
    bool created = true;
    BOOST_CHECK_NO_THROW(created = createWithFlags(true, true, false));
    BOOST_CHECK(!created);
    created = true;
    BOOST_CHECK_NO_THROW(created = createWithFlags(false, true, true));
    BOOST_CHECK(!created);
    created = true;
    BOOST_CHECK_NO_THROW(created = createWithFlags(true, false, true));
    BOOST_CHECK(!created);

    // Without a change address and with a locked wallet whose keypool is empty
    CWallet locked;
    BOOST_REQUIRE(locked.LoadCryptedKey(watchKey.GetPubKey(), std::vector<unsigned char>(48, 0x01)));
    CReserveKey lockedReserve(&locked);
    strFailReason.clear();
    BOOST_CHECK(!locked.CreateTransaction({CRecipient{other, COIN, false}}, wtx, lockedReserve, nFee, nChangePos,
                                          strFailReason, CCoinControl()));
    BOOST_CHECK_EQUAL(strFailReason, "Keypool ran out, please call keypoolrefill first");
}

BOOST_AUTO_TEST_CASE(send_money_rejected_by_mempool)
{
    // The wallet's coin is spent by a block the wallet has not seen: the transaction
    // SendMoney builds on it is refused by the mempool, and abandoned.
    const CTransaction fund = Fund(5 * COIN);
    const CScript other = GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID());
    Mine({SpendTx({COutPoint(fund.GetHash(), 0)}, {CTxOut(4 * COIN, other)})}, false);
    wallet->SetBroadcastTransactions(true);
    CWalletTx wtx;
    BOOST_CHECK_EQUAL(wallet->SendMoney(other, COIN, wtx),
                      "Error: The transaction was rejected.  This might happen if some of the coins in your wallet were "
                      "already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not "
                      "marked as spent here.");
    BOOST_REQUIRE(wallet->GetWalletTx(wtx.GetHash()) != nullptr);
    BOOST_CHECK(wallet->GetWalletTx(wtx.GetHash())->isAbandoned());
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
