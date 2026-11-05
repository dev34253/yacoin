// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Fees, funding and signing of transactions by the wallet, failures of transaction
// creation, and a send the mempool refuses, on a regtest chain with a mock wallet database.

#include "policy/feerate.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "tokens/tokens.h"
#include "util.h"
#include "wallet/coincontrol.h"

#include "wallet/test/wallet_chain_setup.h"

#include <set>

#include <boost/test/unit_test.hpp>

extern CFeeRate payTxFee; // defined in wallet.cpp, declared in no header

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

/** Restores the fee settings of the wallet at the end of the scope */
struct FeeSettingsGuard {
    ScopedValue<CFeeRate> payFee{payTxFee, payTxFee};
    ScopedValue<CFeeRate> minFee{CWallet::minTxFee, CWallet::minTxFee};
    ScopedValue<CFeeRate> minRelayFee{::minRelayTxFee, ::minRelayTxFee};
    ScopedValue<CAmount> maxFee{maxTxFee, maxTxFee};
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_spend_tests, WalletChainSetup)

BOOST_AUTO_TEST_CASE(required_and_minimum_fee)
{
    FeeSettingsGuard guard;
    CWallet::minTxFee = CFeeRate(1000);
    ::minRelayTxFee = CFeeRate(2000);
    maxTxFee = 10 * COIN;

    // The required fee is the higher of the wallet's and the relay minimum
    BOOST_CHECK_EQUAL(CWallet::GetRequiredFee(1000), 2000);
    CWallet::minTxFee = CFeeRate(3000);
    BOOST_CHECK_EQUAL(CWallet::GetRequiredFee(1000), 3000);
    BOOST_CHECK_EQUAL(CWallet::GetRequiredFee(500), 1500);

    // A fee rate of the coin control comes first, and with the override it is taken as is
    CCoinControl coinControl;
    coinControl.m_feerate = CFeeRate(5000);
    payTxFee = CFeeRate(4000);
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(1000, coinControl), 5000);
    coinControl.m_feerate = CFeeRate(100);
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(1000, coinControl), 3000);
    coinControl.fOverrideFeeRate = true;
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(1000, coinControl), 100);

    // Without one, the pay fee rate, with the required fee as the floor
    CCoinControl noRate;
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(1000, noRate), 4000);
    payTxFee = CFeeRate(1000);
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(1000, noRate), 3000);

    // The maximum fee caps everything but an override
    maxTxFee = 2500;
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(1000, noRate), 2500);
    coinControl.fOverrideFeeRate = false;
    coinControl.m_feerate = CFeeRate(9000);
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(1000, coinControl), 2500);
}

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

BOOST_AUTO_TEST_CASE(fund_transaction)
{
    const CTransaction fund = Fund({CTxOut(5 * COIN, script), CTxOut(6 * COIN, script)});
    const CScript other = GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID());
    CAmount nFee = 0;
    int nChangePos = -1;
    std::string strFailReason;

    // Inputs and a change output are added to a transaction that has only outputs
    CTransaction tx;
    tx.vout.push_back(CTxOut(2 * COIN, other));
    BOOST_CHECK(wallet->FundTransaction(tx, nFee, nChangePos, strFailReason, false, {}, CCoinControl()));
    BOOST_CHECK_EQUAL(tx.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(tx.vout.size(), 2U);
    BOOST_REQUIRE(nChangePos == 0 || nChangePos == 1);
    BOOST_CHECK(tx.vout[1 - nChangePos] == CTxOut(2 * COIN, other));
    BOOST_CHECK(nFee > 0);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        const CAmount nIn = Wtx(tx.vin[0].prevout.hash).tx->vout[tx.vin[0].prevout.n].nValue;
        BOOST_CHECK_EQUAL(nIn - tx.GetValueOut(), nFee);
        BOOST_CHECK(wallet->IsMine(tx.vout[nChangePos]) == ISMINE_SPENDABLE);
        BOOST_CHECK(!wallet->IsLockedCoin(tx.vin[0].prevout.hash, tx.vin[0].prevout.n));
    }
    // The added inputs come signed for the funded transaction
    BOOST_CHECK(!tx.vin[0].scriptSig.empty());
    BOOST_CHECK(SignaturesValid(*wallet, tx));

    // The fee taken from an output, and the added inputs locked
    CTransaction subtract;
    subtract.vout.push_back(CTxOut(2 * COIN, other));
    nChangePos = -1;
    BOOST_CHECK(wallet->FundTransaction(subtract, nFee, nChangePos, strFailReason, true, {0}, CCoinControl()));
    BOOST_CHECK_EQUAL(subtract.vout[nChangePos == 0 ? 1 : 0].nValue, 2 * COIN - nFee);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->IsLockedCoin(subtract.vin[0].prevout.hash, subtract.vin[0].prevout.n));
        wallet->UnlockAllCoins();
    }

    // An input given by the transaction is used and not added again
    CTransaction preset;
    preset.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 1)));
    preset.vout.push_back(CTxOut(COIN, other));
    nChangePos = -1;
    BOOST_CHECK(wallet->FundTransaction(preset, nFee, nChangePos, strFailReason, false, {}, CCoinControl()));
    BOOST_CHECK_EQUAL(preset.vin.size(), 1U);
    BOOST_CHECK(preset.vin[0].prevout == COutPoint(fund.GetHash(), 1));

    // A preset input past the outputs of a wallet transaction, or one the wallet does not
    // know, fails the coin selection
    for (const COutPoint& prevout : {COutPoint(fund.GetHash(), 7), COutPoint(InsecureRand256(), 0)}) {
        CTransaction bad;
        bad.vin.push_back(CTxIn(prevout));
        bad.vout.push_back(CTxOut(COIN, other));
        nChangePos = -1;
        strFailReason.clear();
        BOOST_CHECK(!wallet->FundTransaction(bad, nFee, nChangePos, strFailReason, false, {}, CCoinControl()));
        BOOST_CHECK_EQUAL(strFailReason, "Insufficient funds");
    }

    // Not enough funds, and a change position past the outputs
    CTransaction tooMuch;
    tooMuch.vout.push_back(CTxOut(100 * COIN, other));
    nChangePos = -1;
    BOOST_CHECK(!wallet->FundTransaction(tooMuch, nFee, nChangePos, strFailReason, false, {}, CCoinControl()));
    BOOST_CHECK_EQUAL(strFailReason, "Insufficient funds");
    BOOST_CHECK(tooMuch.vin.empty());
    CTransaction badPosition;
    badPosition.vout.push_back(CTxOut(COIN, other));
    nChangePos = 2;
    BOOST_CHECK(!wallet->FundTransaction(badPosition, nFee, nChangePos, strFailReason, false, {}, CCoinControl()));
    BOOST_CHECK_EQUAL(strFailReason, "Change index out of range");
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

    // Token flags: refused before tokens are active, and a reissue without data
    const CTxDestination dest = key.GetPubKey().GetID();
    const CNewToken token;
    {
        ScopedValue<int32_t> notActive(nTokenSupportBlockNumber, chainActive.Height() + 10);
        BOOST_CHECK(!wallet->CreateTransactionWithTransferToken({CRecipient{other, COIN, false}}, wtx, reservekey, nFee,
                                                                nChangePos, strFailReason, CCoinControl()));
    }
    BOOST_CHECK(!wallet->CreateTransactionAll({CRecipient{other, COIN, false}}, wtx, reservekey, nFee, nChangePos,
                                              strFailReason, CCoinControl(), nullptr, false, false, token, dest, false,
                                              true, CReissueToken(), ETokenType::REISSUE));

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
