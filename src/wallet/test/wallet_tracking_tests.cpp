// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// How the wallet tracks its transactions (conflicts, double spends seen in
// blocks, replacement, abandoning, relay requests) and what it counts as
// credit, change and balance, on a regtest chain with a mock wallet database.

#include "base58.h"
#include "chain.h"
#include "consensus/consensus.h"
#include "primitives/block.h"
#include "script/ismine.h"
#include "utilmoneystr.h"
#include "wallet/walletdb.h"

#include "wallet/test/wallet_chain_setup.h"

#include <list>
#include <set>

#include <boost/test/unit_test.hpp>

namespace {

/** The wallet transaction of tx, bound to wallet */
CWalletTx WalletTx(const CWallet& wallet, const CTransaction& tx)
{
    return CWalletTx(&wallet, MakeTransactionRef(tx));
}

/** A transaction with the given outputs and one random input; not signed */
CTransaction PaymentTx(const std::vector<CTxOut>& outs)
{
    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256(), 0)));
    tx.vout = outs;
    return tx;
}

/** The values of the received entries of GetAmounts, sorted */
std::vector<CAmount> Received(const CWalletTx& wtx, isminefilter filter, bool fExcludeNotExpiredTimelock)
{
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    CAmount nFee;
    std::string strSentAccount;
    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter, fExcludeNotExpiredTimelock);
    std::vector<CAmount> values;
    for (const COutputEntry& entry : listReceived)
        values.push_back(entry.amount);
    std::sort(values.begin(), values.end());
    return values;
}

/** Counts the transaction-changed notifications of a wallet while it lives */
struct TxNotifications {
    std::vector<std::pair<uint256, ChangeType> > seen;
    boost::signals2::scoped_connection connection;
    explicit TxNotifications(CWallet& wallet)
        : connection(wallet.NotifyTransactionChanged.connect(
              [this](CWallet*, const uint256& hash, ChangeType status) { seen.emplace_back(hash, status); })) {}
    int Count(const uint256& hash, ChangeType status) const
    {
        return std::count(seen.begin(), seen.end(), std::make_pair(hash, status));
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_tracking_tests, WalletChainSetup)

BOOST_AUTO_TEST_CASE(conflicts_and_wallet_spends)
{
    const CTransaction fund = Fund({CTxOut(3 * COIN, script), CTxOut(3 * COIN, script)});
    const COutPoint coin0(fund.GetHash(), 0);
    const COutPoint coin1(fund.GetHash(), 1);

    // Two wallet transactions spend coin0; a third spends coin1 alone
    const CTransaction a = SpendTx({coin0}, {CTxOut(COIN, script)});
    const CTransaction b = SpendTx({coin0}, {CTxOut(2 * COIN, script)});
    const CTransaction single = SpendTx({coin1}, {CTxOut(COIN, script)});
    for (const CTransaction& tx : {a, b, single})
        BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, tx)));

    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_CHECK(wallet->GetConflicts(a.GetHash()) == std::set<uint256>({a.GetHash(), b.GetHash()}));
    BOOST_CHECK(wallet->GetConflicts(b.GetHash()) == std::set<uint256>({a.GetHash(), b.GetHash()}));
    BOOST_CHECK(Wtx(a.GetHash()).GetConflicts() == std::set<uint256>({b.GetHash()}));
    BOOST_CHECK(Wtx(b.GetHash()).GetConflicts() == std::set<uint256>({a.GetHash()}));
    BOOST_CHECK(wallet->GetConflicts(single.GetHash()).empty());
    BOOST_CHECK(Wtx(single.GetHash()).GetConflicts().empty());
    BOOST_CHECK(wallet->GetConflicts(InsecureRand256()).empty());
    // A transaction not bound to a wallet has no conflicts
    BOOST_CHECK(CWalletTx(nullptr, MakeTransactionRef(a)).GetConflicts().empty());

    // A transaction has a wallet spend if a wallet transaction spends one of its outputs
    BOOST_CHECK(wallet->HasWalletSpend(fund.GetHash()));
    BOOST_CHECK(!wallet->HasWalletSpend(a.GetHash()));
    BOOST_CHECK(!wallet->HasWalletSpend(InsecureRand256()));
}

BOOST_AUTO_TEST_CASE(spends_of_one_coin_share_metadata)
{
    // Version 1 transactions that differ only in the signature have different hashes,
    // and the second spend of the coin takes the metadata of the first.
    const CTransaction fund = Fund(3 * COIN);
    CTransaction first = SpendTx({COutPoint(fund.GetHash(), 0)}, {CTxOut(COIN, script)});
    first.nVersion = 1;
    first.vin[0].scriptSig = CScript() << OP_1;
    CTransaction second = first;
    second.vin[0].scriptSig = CScript() << OP_2;
    BOOST_REQUIRE(first.GetHash() != second.GetHash());

    CWalletTx wtxFirst = WalletTx(*wallet, first);
    wtxFirst.mapValue["comment"] = "first";
    wtxFirst.vOrderForm.push_back(std::make_pair("form", "value"));
    wtxFirst.fFromMe = true;
    wtxFirst.strFromAccount = "account";
    BOOST_REQUIRE(wallet->AddToWallet(wtxFirst));
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, second)));

    const CWalletTx& copy = Wtx(second.GetHash());
    BOOST_CHECK_EQUAL(copy.mapValue.at("comment"), "first");
    BOOST_REQUIRE_EQUAL(copy.vOrderForm.size(), 1U);
    BOOST_CHECK_EQUAL(copy.vOrderForm[0].second, "value");
    BOOST_CHECK(copy.fFromMe);
    BOOST_CHECK_EQUAL(copy.strFromAccount, "account");
    BOOST_CHECK_EQUAL(copy.nTimeSmart, Wtx(first.GetHash()).nTimeSmart);
}

BOOST_AUTO_TEST_CASE(block_double_spend_marks_conflicts)
{
    const CTransaction fund = Fund({CTxOut(3 * COIN, script), CTxOut(3 * COIN, script)});
    const COutPoint coin0(fund.GetHash(), 0);
    const COutPoint coin1(fund.GetHash(), 1);
    const CScript other = GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID());

    // a spends coin0 and child spends a; both are only in the wallet
    const CTransaction a = SpendTx({coin0}, {CTxOut(2 * COIN, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, a)));
    const CTransaction child = SpendTx({COutPoint(a.GetHash(), 0)}, {CTxOut(COIN, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, child)));
    {
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_CHECK_EQUAL(Wtx(fund.GetHash()).GetAvailableCredit(), 3 * COIN);
        BOOST_CHECK(Wtx(fund.GetHash()).fAvailableCreditCached);
        BOOST_CHECK_EQUAL(Wtx(a.GetHash()).GetDepthInMainChain(), 0);
    }

    // A block on the active chain that spends coin0 elsewhere: a and its child are
    // conflicted (negative depth) and the spent transaction is recomputed.
    const CTransaction doubleSpend = SpendTx({coin0}, {CTxOut(2 * COIN, other)});
    const CBlock block = Mine({doubleSpend}, false);
    wallet->BlockConnected(std::make_shared<const CBlock>(block), chainActive.Tip(), {});
    {
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_CHECK_EQUAL(Wtx(a.GetHash()).GetDepthInMainChain(), -1);
        BOOST_CHECK_EQUAL(Wtx(child.GetHash()).GetDepthInMainChain(), -1);
        BOOST_CHECK(Wtx(a.GetHash()).hashBlock == block.GetHash());
        BOOST_CHECK_EQUAL(Wtx(a.GetHash()).nIndex, -1);
        BOOST_CHECK(!Wtx(fund.GetHash()).fAvailableCreditCached);
        BOOST_CHECK_EQUAL(Wtx(doubleSpend.GetHash()).GetDepthInMainChain(), 1);
        // The conflicted spends no longer count: coin0 is spent by the block, coin1 is free
        BOOST_CHECK(wallet->IsSpent(fund.GetHash(), 0));
        BOOST_CHECK_EQUAL(Wtx(fund.GetHash()).GetAvailableCredit(), 3 * COIN);
    }

    // A later block deepens the conflict
    Mine({}, false);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_CHECK_EQUAL(Wtx(a.GetHash()).GetDepthInMainChain(), -2);

        // Loading a transaction that spends the output of a conflicted one marks it conflicted
        const CTransaction late = SpendTx({COutPoint(a.GetHash(), 0)}, {CTxOut(COIN / 2, script)});
        CWalletTx wtxLate = WalletTx(*wallet, late);
        BOOST_CHECK(wallet->LoadToWallet(wtxLate));
        BOOST_CHECK_EQUAL(Wtx(late.GetHash()).GetDepthInMainChain(), -2);
    }

    // A block that is not in the block index, and one that is not on the active chain,
    // leave the spend of coin1 as it is.
    const CTransaction b = SpendTx({coin1}, {CTxOut(2 * COIN, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, b)));
    for (int i = 0; i < 2; i++) {
        uint256 hashUnknown = InsecureRand256();
        CBlockIndex unknown;
        unknown.phashBlock = &hashUnknown;
        CBlockIndex* pindex = &unknown;
        if (i == 1) {
            LOCK(cs_main);
            auto inserted = mapBlockIndex.emplace(InsecureRand256(), new CBlockIndex);
            BOOST_REQUIRE(inserted.second);
            pindex = inserted.first->second;
            pindex->phashBlock = &inserted.first->first;
            BOOST_REQUIRE(!chainActive.Contains(pindex));
        }
        CBlock offChain;
        offChain.vtx.push_back(SpendTx({coin1}, {CTxOut(COIN + i, other)}));
        wallet->BlockConnected(std::make_shared<const CBlock>(offChain), pindex, {});
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_CHECK_EQUAL(Wtx(b.GetHash()).GetDepthInMainChain(), 0);
        BOOST_CHECK_EQUAL(Wtx(b.GetHash()).nIndex, -1);
        BOOST_CHECK(Wtx(b.GetHash()).hashUnset());
        BOOST_CHECK(Wtx(offChain.vtx[0].GetHash()).hashBlock == pindex->GetBlockHash());
        BOOST_CHECK_EQUAL(Wtx(offChain.vtx[0].GetHash()).GetDepthInMainChain(), 0);
    }
}

BOOST_AUTO_TEST_CASE(block_connected_syncs_conflicted_list_first)
{
    const CTransaction fund = Fund(3 * COIN);
    const CTransaction spend = SpendTx({COutPoint(fund.GetHash(), 0)}, {CTxOut(2 * COIN, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, spend)));
    {
        LOCK2(cs_main, wallet->cs_wallet);
        BOOST_REQUIRE(wallet->AbandonTransaction(spend.GetHash()));
        BOOST_REQUIRE(Wtx(spend.GetHash()).isAbandoned());
    }
    TxNotifications notifications(*wallet);

    // A payment to the wallet in the list of transactions removed for a conflict is added
    // without a block, and an abandoned wallet transaction in it is no longer abandoned.
    const CTransaction payment = PaymentTx({CTxOut(COIN, script)});
    CBlock empty;
    wallet->BlockConnected(std::make_shared<const CBlock>(empty), chainActive.Tip(),
                           {MakeTransactionRef(payment), MakeTransactionRef(spend)});
    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_REQUIRE(wallet->GetWalletTx(payment.GetHash()) != nullptr);
    BOOST_CHECK(Wtx(payment.GetHash()).hashUnset());
    BOOST_CHECK(!Wtx(spend.GetHash()).isAbandoned());
    BOOST_CHECK(Wtx(spend.GetHash()).hashBlock.IsNull());
    BOOST_CHECK_EQUAL(notifications.Count(payment.GetHash(), CT_NEW), 1);
    BOOST_CHECK_EQUAL(notifications.Count(spend.GetHash(), CT_UPDATED), 1);
}

BOOST_AUTO_TEST_CASE(add_to_wallet_merges_updates)
{
    const CTransaction payment = PaymentTx({CTxOut(COIN, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, payment)));
    TxNotifications notifications(*wallet);

    // Sent by the wallet: fFromMe is set on the stored transaction
    CWalletTx update = WalletTx(*wallet, payment);
    update.fFromMe = true;
    BOOST_CHECK(wallet->AddToWallet(update));
    BOOST_CHECK(Wtx(payment.GetHash()).fFromMe);

    // fFromMe is never cleared by an update
    BOOST_CHECK(wallet->AddToWallet(WalletTx(*wallet, payment)));
    BOOST_CHECK(Wtx(payment.GetHash()).fFromMe);

    // A block hash and an index are taken over
    CWalletTx inBlock = WalletTx(*wallet, payment);
    inBlock.hashBlock = chainActive.Tip()->GetBlockHash();
    inBlock.nIndex = 3;
    BOOST_CHECK(wallet->AddToWallet(inBlock));
    BOOST_CHECK(Wtx(payment.GetHash()).hashBlock == chainActive.Tip()->GetBlockHash());
    BOOST_CHECK_EQUAL(Wtx(payment.GetHash()).nIndex, 3);
    BOOST_CHECK_EQUAL(notifications.Count(payment.GetHash(), CT_UPDATED), 3);
}

BOOST_AUTO_TEST_CASE(replaced_and_abandonable_transactions)
{
    const CTransaction fund = Fund(3 * COIN);
    const CTransaction original = SpendTx({COutPoint(fund.GetHash(), 0)}, {CTxOut(COIN, script)});
    const CTransaction replacement = SpendTx({COutPoint(fund.GetHash(), 0)}, {CTxOut(2 * COIN, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, original)));

    // MarkReplaced records the replacing transaction, in memory and in the database,
    // and notifies an update
    {
        TxNotifications notifications(*wallet);
        BOOST_CHECK(wallet->MarkReplaced(original.GetHash(), replacement.GetHash()));
        BOOST_CHECK_EQUAL(Wtx(original.GetHash()).mapValue.at("replaced_by_txid"), replacement.GetHash().ToString());
        BOOST_CHECK_EQUAL(notifications.Count(original.GetHash(), CT_UPDATED), 1);
        std::vector<uint256> vTxHash;
        std::vector<CWalletTx> vWtx;
        BOOST_REQUIRE_EQUAL(CWalletDB(wallet->GetDBHandle()).FindWalletTx(vTxHash, vWtx), DB_LOAD_OK);
        bool fFound = false;
        for (const CWalletTx& wtx : vWtx) {
            if (wtx.GetHash() == original.GetHash()) {
                fFound = true;
                BOOST_CHECK_EQUAL(wtx.mapValue.at("replaced_by_txid"), replacement.GetHash().ToString());
            }
        }
        BOOST_CHECK(fFound);
    }

    // A transaction can be abandoned while it is unconfirmed, outside the mempool and not
    // abandoned yet
    BOOST_CHECK(!wallet->TransactionCanBeAbandoned(InsecureRand256()));
    BOOST_CHECK(!wallet->TransactionCanBeAbandoned(fund.GetHash()));
    BOOST_CHECK(wallet->TransactionCanBeAbandoned(original.GetHash()));
    AddToMempool(original);
    BOOST_CHECK(!wallet->TransactionCanBeAbandoned(original.GetHash()));
    mempool.clear();
    BOOST_CHECK(wallet->TransactionCanBeAbandoned(original.GetHash()));
    BOOST_CHECK(wallet->AbandonTransaction(original.GetHash()));
    BOOST_CHECK(!wallet->TransactionCanBeAbandoned(original.GetHash()));
}

BOOST_AUTO_TEST_CASE(request_counts)
{
    LOCK2(cs_main, wallet->cs_wallet);
    const uint256 tipHash = chainActive.Tip()->GetBlockHash();

    // A generated transaction counts the requests of its block
    CWalletTx coinbase = WalletTx(*wallet, coinbaseTxns.back());
    BOOST_CHECK_EQUAL(coinbase.GetRequestCount(), -1); // no block
    coinbase.hashBlock = tipHash;
    BOOST_CHECK_EQUAL(coinbase.GetRequestCount(), -1); // block not tracked
    wallet->mapRequestCount[tipHash] = 4;
    BOOST_CHECK_EQUAL(coinbase.GetRequestCount(), 4);

    CTransaction stakeTx;
    stakeTx.vin.push_back(CTxIn(COutPoint(InsecureRand256(), 0)));
    stakeTx.vout.push_back(CTxOut(0, CScript()));
    stakeTx.vout.push_back(CTxOut(COIN, script));
    CWalletTx stake = WalletTx(*wallet, stakeTx);
    BOOST_REQUIRE(stake.IsCoinStake());
    stake.hashBlock = tipHash;
    BOOST_CHECK_EQUAL(stake.GetRequestCount(), 4);

    // Other transactions count their own requests; with none, those of their block,
    // and 1 if their block is not tracked
    CWalletTx payment = WalletTx(*wallet, PaymentTx({CTxOut(COIN, script)}));
    BOOST_CHECK_EQUAL(payment.GetRequestCount(), -1);
    wallet->mapRequestCount[payment.GetHash()] = 2;
    BOOST_CHECK_EQUAL(payment.GetRequestCount(), 2);
    wallet->mapRequestCount[payment.GetHash()] = 0;
    BOOST_CHECK_EQUAL(payment.GetRequestCount(), 0);
    payment.hashBlock = tipHash;
    BOOST_CHECK_EQUAL(payment.GetRequestCount(), 4);
    payment.hashBlock = InsecureRand256();
    BOOST_CHECK_EQUAL(payment.GetRequestCount(), 1);
}

BOOST_AUTO_TEST_CASE(from_me_change_and_value_range)
{
    const CScript multisig = GetScriptForMultisig(1, {key.GetPubKey()});
    const CKey watchKey = NewWalletTestKey();
    const CScript watched = GetScriptForDestination(watchKey.GetPubKey().GetID());
    BOOST_REQUIRE(wallet->AddWatchOnly(watched, 1));
    const CTransaction fund = Fund({CTxOut(COIN, script), CTxOut(2 * COIN, watched)});
    LOCK2(cs_main, wallet->cs_wallet);

    // IsAllFromMe: every input must spend an output of the wallet that passes the filter
    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 0)));
    BOOST_CHECK(wallet->IsAllFromMe(tx, ISMINE_SPENDABLE));
    tx.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 1)));
    BOOST_CHECK(!wallet->IsAllFromMe(tx, ISMINE_SPENDABLE));
    BOOST_CHECK(wallet->IsAllFromMe(tx, ISMINE_ALL));
    tx.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 2)));
    BOOST_CHECK(!wallet->IsAllFromMe(tx, ISMINE_ALL)); // no such output
    tx.vin.back() = CTxIn(COutPoint(InsecureRand256(), 0));
    BOOST_CHECK(!wallet->IsAllFromMe(tx, ISMINE_ALL)); // unknown transaction

    // Change: an output of the wallet, watch-only included, that is not in the address
    // book, including one without an address
    const CTxOut toKey(COIN, script);
    const CTxOut toMultisig(2 * COIN, multisig);
    const CTxOut toWatched(4 * COIN, watched);
    const CTxOut toOther(8 * COIN, GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(wallet->GetChange(toKey), COIN);
    BOOST_CHECK_EQUAL(wallet->GetChange(toMultisig), 2 * COIN);
    BOOST_CHECK_EQUAL(wallet->GetChange(toWatched), 4 * COIN);
    BOOST_CHECK_EQUAL(wallet->GetChange(toOther), 0);
    const CTransaction payment = PaymentTx({toKey, toMultisig, toWatched, toOther});
    BOOST_CHECK_EQUAL(wallet->GetChange(payment), 7 * COIN);
    CWalletTx wtx = WalletTx(*wallet, payment);
    BOOST_CHECK_EQUAL(wtx.GetChange(), 7 * COIN);
    BOOST_CHECK(wallet->SetAddressBook(key.GetPubKey().GetID(), "named", "receive"));
    BOOST_CHECK_EQUAL(wallet->GetChange(toKey), 0);
    BOOST_CHECK_EQUAL(wtx.GetChange(), 7 * COIN); // cached
    wtx.MarkDirty();
    BOOST_CHECK_EQUAL(wtx.GetChange(), 6 * COIN);

    // Values outside the money range are refused, per output and in sums
    const CTxOut tooLarge(MAX_MONEY + 1, script);
    BOOST_CHECK_THROW(wallet->GetChange(tooLarge), std::runtime_error);
    BOOST_CHECK_THROW(wallet->GetCredit(tooLarge, ISMINE_ALL), std::runtime_error);
    const CTransaction twiceMax = PaymentTx({CTxOut(MAX_MONEY, multisig), CTxOut(MAX_MONEY, multisig)});
    BOOST_CHECK_THROW(wallet->GetChange(twiceMax), std::runtime_error);
    BOOST_CHECK_THROW(wallet->GetCredit(twiceMax, ISMINE_ALL), std::runtime_error);
    BOOST_CHECK_THROW(WalletTx(*wallet, twiceMax).GetAvailableCredit(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(debit_sum_outside_money_range)
{
    const CTransaction fund = PaymentTx({CTxOut(MAX_MONEY / 2 + 1, script), CTxOut(MAX_MONEY / 2 + 1, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, fund)));
    CTransaction spend;
    spend.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 0)));
    spend.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 1)));
    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_CHECK_THROW(wallet->GetDebit(spend, ISMINE_ALL), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(watch_only_credit_and_balances)
{
    // A second wallet watches the coinbase script of the chain and the script of the first
    // wallet's key, without holding a key.
    std::unique_ptr<CWallet> watcher = NewMockWallet("wallet_chain_watcher.dat");
    const CScript coinbaseScript = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
    BOOST_REQUIRE(watcher->AddWatchOnly(coinbaseScript, 1));
    BOOST_REQUIRE(watcher->AddWatchOnly(script, 1));
    LOCK2(cs_main, watcher->cs_wallet);

    // An immature coinbase on the active chain is immature watch-only credit
    CWalletTx coinbase = WalletTx(*watcher, coinbaseTxns.back());
    coinbase.hashBlock = chainActive.Tip()->GetBlockHash();
    coinbase.nIndex = 0;
    BOOST_REQUIRE(coinbase.GetBlocksToMaturity() > 0);
    const CAmount nCoinbase = coinbaseTxns.back().GetValueOut();
    BOOST_CHECK_EQUAL(coinbase.GetImmatureWatchOnlyCredit(), nCoinbase);
    BOOST_CHECK(coinbase.fImmatureWatchCreditCached);
    BOOST_CHECK_EQUAL(coinbase.GetImmatureWatchOnlyCredit(true), nCoinbase);
    BOOST_CHECK_EQUAL(coinbase.GetImmatureWatchOnlyCredit(false), nCoinbase);
    BOOST_CHECK_EQUAL(coinbase.GetImmatureCredit(), 0); // no key
    BOOST_CHECK_EQUAL(coinbase.GetAvailableWatchOnlyCredit(), 0); // immature
    BOOST_REQUIRE(watcher->AddToWallet(coinbase));
    BOOST_CHECK_EQUAL(watcher->GetImmatureWatchOnlyBalance(), nCoinbase);

    // A payment in the mempool that is not from the wallet is unconfirmed watch-only balance
    const CTransaction payment = PaymentTx({CTxOut(COIN, script), CTxOut(2 * COIN, script)});
    BOOST_REQUIRE(watcher->AddToWallet(WalletTx(*watcher, payment)));
    BOOST_CHECK_EQUAL(watcher->GetUnconfirmedWatchOnlyBalance(), 0);
    AddToMempool(payment);
    BOOST_CHECK_EQUAL(watcher->GetUnconfirmedWatchOnlyBalance(), 3 * COIN);
    BOOST_CHECK_EQUAL(watcher->GetUnconfirmedBalance(), 0);
    const CWalletTx& wtx = watcher->mapWallet.at(payment.GetHash());
    BOOST_CHECK_EQUAL(wtx.GetImmatureWatchOnlyCredit(), 0); // not a coinbase
    BOOST_CHECK_EQUAL(wtx.GetAvailableWatchOnlyCredit(true), 3 * COIN);
    BOOST_CHECK_EQUAL(wtx.GetCredit(ISMINE_WATCH_ONLY), 3 * COIN);
    BOOST_CHECK_EQUAL(wtx.GetCredit(ISMINE_WATCH_ONLY), 3 * COIN); // cached
    BOOST_CHECK_EQUAL(wtx.GetCredit(ISMINE_SPENDABLE), 0);

    // Without a wallet there is no available credit
    const CWalletTx unbound(nullptr, MakeTransactionRef(payment));
    BOOST_CHECK_EQUAL(unbound.GetAvailableWatchOnlyCredit(), 0);
    BOOST_CHECK_EQUAL(unbound.GetAvailableCredit(), 0);

    // Watch-only outputs whose sum is outside the money range
    const CTransaction twiceMax = PaymentTx({CTxOut(MAX_MONEY, script), CTxOut(MAX_MONEY, script)});
    BOOST_CHECK_THROW(WalletTx(*watcher, twiceMax).GetAvailableWatchOnlyCredit(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(timelocked_outputs_in_amounts_and_balances)
{
    // A CLTV output locked to a height and a CSV output locked for a number of blocks, both
    // paying the wallet's key.
    const int nHeight = chainActive.Height();
    const CKeyID keyID = key.GetPubKey().GetID();
    const CScript cltv = GetScriptForCltvP2PKH(nHeight + 4, keyID);
    const CScript csv = GetScriptForCsvP2PKH(3, keyID);
    const CTransaction fund = Fund({CTxOut(2 * COIN, cltv), CTxOut(3 * COIN, csv), CTxOut(5 * COIN, script)});
    BOOST_REQUIRE_EQUAL(chainActive.Height(), nHeight + 1);

    // With fExcludeNotExpiredTimelock, GetAmounts and GetLegacyBalance count a locked output
    // only once its lock has passed: the relative lock two blocks after the funding block,
    // the absolute one three blocks after.
    auto Check = [&](const std::vector<CAmount>& expected, CAmount nLegacy) {
        LOCK2(cs_main, wallet->cs_wallet);
        const CWalletTx& wtx = Wtx(fund.GetHash());
        BOOST_CHECK(Received(wtx, ISMINE_ALL, true) == expected);
        BOOST_CHECK(Received(wtx, ISMINE_ALL, false) == std::vector<CAmount>({2 * COIN, 3 * COIN, 5 * COIN}));
        BOOST_CHECK_EQUAL(wallet->GetLegacyBalance(ISMINE_SPENDABLE, 0, nullptr, true), nLegacy);
        BOOST_CHECK_EQUAL(wallet->GetLegacyBalance(ISMINE_SPENDABLE, 0, nullptr, false), 10 * COIN);
    };
    Check({5 * COIN}, 5 * COIN);
    Mine({});
    Check({5 * COIN}, 5 * COIN);
    Mine({});
    Check({3 * COIN, 5 * COIN}, 8 * COIN);
    Mine({});
    Check({2 * COIN, 3 * COIN, 5 * COIN}, 10 * COIN);

    // An output that is not time locked counts as expired
    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_CHECK(wallet->IsTimelockUTXOExpired(CInputCoin(&Wtx(fund.GetHash()), 2), TX_PUBKEYHASH, 0));
}

BOOST_AUTO_TEST_CASE(amounts_of_output_without_address)
{
    // An output of the wallet without an address (a 1-of-1 multisig) is received with no
    // destination, and counts as change of a transaction the wallet sent.
    const CScript multisig = GetScriptForMultisig(1, {key.GetPubKey()});
    const CScript other = GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID());
    const CTransaction fund = Fund({CTxOut(4 * COIN, multisig), CTxOut(COIN, script), CTxOut(2 * COIN, other)});
    LOCK2(cs_main, wallet->cs_wallet);
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    CAmount nFee;
    std::string strSentAccount;
    Wtx(fund.GetHash()).GetAmounts(listReceived, listSent, nFee, strSentAccount, ISMINE_ALL, false);
    BOOST_REQUIRE_EQUAL(listReceived.size(), 2U);
    BOOST_CHECK(boost::get<CNoDestination>(&listReceived.front().destination) != nullptr);
    BOOST_CHECK_EQUAL(listReceived.front().amount, 4 * COIN);
    BOOST_CHECK(listSent.empty());

    // Address balances and groupings skip it, as an output and as an input, as well as
    // outputs that are not the wallet's
    const std::map<CTxDestination, CAmount> balances = wallet->GetAddressBalances();
    BOOST_CHECK_EQUAL(balances.size(), 1U);
    BOOST_CHECK_EQUAL(balances.at(CTxDestination(key.GetPubKey().GetID())), COIN);
    const CTransaction spend = SpendTx({COutPoint(fund.GetHash(), 1)}, {CTxOut(COIN / 4, multisig), CTxOut(COIN / 2, script)});
    const CTransaction spendMultisig = SpendTx({COutPoint(fund.GetHash(), 0)}, {CTxOut(COIN, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, spend)));
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, spendMultisig)));
    const std::set<std::set<CTxDestination> > groupings = wallet->GetAddressGroupings();
    BOOST_CHECK(groupings == std::set<std::set<CTxDestination> >({{CTxDestination(key.GetPubKey().GetID())}}));
}

BOOST_AUTO_TEST_CASE(stake_and_non_final_transactions)
{
    LOCK2(cs_main, wallet->cs_wallet);

    // A coinstake-shaped wallet transaction in the tip block is immature, and its credit is 0
    // while immature, so GetStake, which adds up the credit of immature coinstakes on the
    // active chain, gives 0.
    CTransaction stakeTx;
    stakeTx.vin.push_back(CTxIn(COutPoint(InsecureRand256(), 0)));
    stakeTx.vout.push_back(CTxOut(0, CScript()));
    stakeTx.vout.push_back(CTxOut(5 * COIN, script));
    CWalletTx stake = WalletTx(*wallet, stakeTx);
    stake.SetMerkleBranch(chainActive.Tip(), 1);
    BOOST_REQUIRE(wallet->AddToWallet(stake));
    const CWalletTx& stored = Wtx(stakeTx.GetHash());
    BOOST_REQUIRE(stored.IsCoinStake());
    BOOST_CHECK_EQUAL(stored.GetDepthInMainChain(), 1);
    BOOST_CHECK(stored.GetBlocksToMaturity() > 0);
    BOOST_CHECK_EQUAL(stored.GetCredit(ISMINE_ALL), 0);
    BOOST_CHECK_EQUAL(wallet->GetStake(), 0);

    // A transaction that is not final yet (locked to a later height) is not trusted
    CTransaction lockedTx = PaymentTx({CTxOut(COIN, script)});
    lockedTx.nLockTime = chainActive.Height() + 100;
    lockedTx.vin[0].nSequence = 0;
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, lockedTx)));
    BOOST_CHECK(!Wtx(lockedTx.GetHash()).IsTrusted());

    // Neither is spendable
    std::vector<COutput> coins;
    wallet->AvailableCoins(coins, false);
    BOOST_CHECK(coins.empty());

    // How a coin is printed
    const COutput coin(&stored, 1, 1, true, true, true);
    BOOST_CHECK_EQUAL(coin.ToString(), strprintf("COutput(%s, 1, 1) [%s]", stakeTx.GetHash().ToString(), FormatMoney(5 * COIN)));
}

BOOST_AUTO_TEST_CASE(trust_of_unconfirmed_spends)
{
    const CKey watchKey = NewWalletTestKey();
    const CScript watched = GetScriptForDestination(watchKey.GetPubKey().GetID());
    BOOST_REQUIRE(wallet->AddWatchOnly(watched, 1));
    const CTransaction fund = Fund({CTxOut(3 * COIN, script), CTxOut(3 * COIN, watched)});

    // From the wallet and in the mempool, but one input is not from a wallet transaction
    CTransaction unknownParent = SpendTx({COutPoint(fund.GetHash(), 0)}, {CTxOut(COIN, script)});
    unknownParent.vin.insert(unknownParent.vin.begin(), CTxIn(COutPoint(InsecureRand256(), 0)));
    // ... or spends a watch-only output
    CTransaction watchedParent;
    watchedParent.vin.push_back(CTxIn(COutPoint(fund.GetHash(), 1)));
    watchedParent.vout.push_back(CTxOut(2 * COIN, script));
    for (const CTransaction& tx : {unknownParent, watchedParent}) {
        BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, tx)));
        AddToMempool(tx);
    }
    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_REQUIRE(Wtx(unknownParent.GetHash()).IsFromMe(ISMINE_ALL));
    BOOST_CHECK(!Wtx(unknownParent.GetHash()).IsTrusted());
    BOOST_REQUIRE(Wtx(watchedParent.GetHash()).IsFromMe(ISMINE_ALL));
    BOOST_CHECK(!Wtx(watchedParent.GetHash()).IsTrusted());

    // The address balances skip them, and count the coins they spend as spent
    const std::map<CTxDestination, CAmount> balances = wallet->GetAddressBalances();
    BOOST_CHECK_EQUAL(balances.size(), 2U);
    BOOST_CHECK_EQUAL(balances.at(CTxDestination(key.GetPubKey().GetID())), 0);
    BOOST_CHECK_EQUAL(balances.at(CTxDestination(watchKey.GetPubKey().GetID())), 0);
}

BOOST_AUTO_TEST_CASE(key_birth_times)
{
    // A key with a creation time keeps it. A key without one (the fixture's) gets the time
    // of the earliest block paying it, minus the 2-hour window, if that block is at least
    // 144 blocks below the tip; otherwise that of the block 144 blocks below the tip.
    const CKey dated = NewWalletTestKey();
    const CKey late = NewWalletTestKey();
    {
        LOCK(wallet->cs_wallet);
        wallet->mapKeyMetadata[dated.GetPubKey().GetID()].nCreateTime = 1500000000;
    }
    AddWalletTestKey(*wallet, dated);
    AddWalletTestKey(*wallet, late);
    Fund({CTxOut(COIN, script), CTxOut(COIN, GetScriptForDestination(dated.GetPubKey().GetID()))});
    const int nFundHeight = chainActive.Height();
    Fund({CTxOut(COIN, script)}); // a later payment to the same key
    for (int i = 0; i < 144; i++)
        Mine({}, false);
    Fund({CTxOut(COIN, GetScriptForDestination(late.GetPubKey().GetID()))});

    LOCK2(cs_main, wallet->cs_wallet);
    std::map<CTxDestination, int64_t> mapKeyBirth;
    wallet->GetKeyBirthTimes(mapKeyBirth);
    BOOST_CHECK_EQUAL(mapKeyBirth.size(), 3U);
    BOOST_CHECK_EQUAL(mapKeyBirth.at(CTxDestination(dated.GetPubKey().GetID())), 1500000000);
    BOOST_CHECK_EQUAL(mapKeyBirth.at(CTxDestination(key.GetPubKey().GetID())),
                      chainActive[nFundHeight]->GetBlockTime() - TIMESTAMP_WINDOW);
    const CBlockIndex* pindexMax = chainActive[chainActive.Height() - 144];
    BOOST_CHECK_EQUAL(mapKeyBirth.at(CTxDestination(late.GetPubKey().GetID())), pindexMax->GetBlockTime() - TIMESTAMP_WINDOW);
}

BOOST_AUTO_TEST_CASE(smart_time_from_latest_entries)
{
    // The smart time of a transaction in a block is bounded below by the time of the latest
    // entry in the wallet's order: a transaction without a smart time gives its received
    // time, an accounting entry its own time.
    LOCK2(cs_main, wallet->cs_wallet);
    const int64_t nBlockTime = chainActive.Tip()->GetBlockTime();
    SetMockTime(nBlockTime + 1000);

    CWalletTx loaded = WalletTx(*wallet, PaymentTx({CTxOut(COIN, script)}));
    loaded.nOrderPos = wallet->IncOrderPosNext();
    loaded.nTimeReceived = nBlockTime + 500;
    loaded.nTimeSmart = 0;
    BOOST_REQUIRE(wallet->LoadToWallet(loaded));
    CWalletTx first = WalletTx(*wallet, PaymentTx({CTxOut(COIN, script)}));
    first.hashBlock = chainActive.Tip()->GetBlockHash();
    BOOST_REQUIRE(wallet->AddToWallet(first));
    BOOST_CHECK_EQUAL(Wtx(first.GetHash()).nTimeSmart, nBlockTime + 500);

    CAccountingEntry entry;
    entry.strAccount = "account";
    entry.nCreditDebit = COIN;
    entry.nTime = nBlockTime + 700;
    entry.nOrderPos = wallet->IncOrderPosNext();
    BOOST_REQUIRE(wallet->AddAccountingEntry(entry));
    CWalletTx second = WalletTx(*wallet, PaymentTx({CTxOut(COIN, script)}));
    second.hashBlock = chainActive.Tip()->GetBlockHash();
    BOOST_REQUIRE(wallet->AddToWallet(second));
    BOOST_CHECK_EQUAL(Wtx(second.GetHash()).nTimeSmart, nBlockTime + 700);
}

BOOST_AUTO_TEST_CASE(zap_transactions)
{
    const CTransaction fund = Fund(3 * COIN);
    const CTransaction spend = SpendTx({COutPoint(fund.GetHash(), 0)}, {CTxOut(COIN, script)});
    BOOST_REQUIRE(wallet->AddToWallet(WalletTx(*wallet, spend)));
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::vector<uint256> vHashIn = {spend.GetHash(), InsecureRand256()};
        std::vector<uint256> vHashOut;
        BOOST_CHECK_EQUAL(wallet->ZapSelectTx(vHashIn, vHashOut), DB_LOAD_OK);
        BOOST_CHECK(vHashOut == std::vector<uint256>({spend.GetHash()}));
        BOOST_CHECK(wallet->GetWalletTx(spend.GetHash()) == nullptr);
        BOOST_CHECK(wallet->GetWalletTx(fund.GetHash()) != nullptr);
    }
    std::vector<uint256> vTxHash;
    std::vector<CWalletTx> vWtx;
    BOOST_REQUIRE_EQUAL(CWalletDB(wallet->GetDBHandle()).FindWalletTx(vTxHash, vWtx), DB_LOAD_OK);
    BOOST_CHECK(vTxHash == std::vector<uint256>({fund.GetHash()}));

    // A database written by a newer version is refused by both, before any change
    BOOST_REQUIRE(CWalletDB(wallet->GetDBHandle()).WriteMinVersion(CLIENT_VERSION + 1));
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::vector<uint256> vHashIn = {fund.GetHash()};
        std::vector<uint256> vHashOut;
        BOOST_CHECK_EQUAL(wallet->ZapSelectTx(vHashIn, vHashOut), DB_TOO_NEW);
        BOOST_CHECK(vHashOut.empty());
        BOOST_CHECK(wallet->GetWalletTx(fund.GetHash()) != nullptr);
    }
    vWtx.clear();
    BOOST_CHECK_EQUAL(wallet->ZapWalletTx(vWtx), DB_TOO_NEW);
    BOOST_CHECK(vWtx.empty());
}

BOOST_AUTO_TEST_CASE(address_book_and_locked_coins)
{
    const CTxDestination dest = key.GetPubKey().GetID();
    const std::string strAddress = CBitcoinAddress(dest).ToString();
    BOOST_CHECK(wallet->SetAddressBook(dest, "label", "receive"));
    BOOST_CHECK(wallet->AddDestData(dest, "rr0", "request"));
    BOOST_CHECK(wallet->AddDestData(dest, "misc", "value"));
    BOOST_CHECK_EQUAL(wallet->GetAccountName(script), "label");
    BOOST_CHECK_EQUAL(wallet->GetAccountName(CScript() << OP_RETURN), "");
    BOOST_CHECK_EQUAL(wallet->GetAccountName(GetScriptForDestination(NewWalletTestKey().GetPubKey().GetID())), "");

    // Dest data needs a destination
    BOOST_CHECK(!wallet->AddDestData(CNoDestination(), "rr1", "request"));

    // Erasing dest data that does not exist fails; existing dest data is erased
    BOOST_CHECK(!wallet->EraseDestData(dest, "nope"));
    BOOST_CHECK(wallet->EraseDestData(dest, "misc"));
    std::string value;
    BOOST_CHECK(!wallet->GetDestData(dest, "misc", &value));
    BOOST_CHECK(wallet->GetDestData(dest, "rr0", &value));

    // Deleting the entry removes name, purpose and dest data, in memory and in the database
    int nDeleted = 0;
    boost::signals2::scoped_connection connection(wallet->NotifyAddressBookChanged.connect(
        [&](CWallet*, const CTxDestination& address, const std::string&, bool fIsMine, const std::string&, ChangeType status) {
            if (address == dest && fIsMine && status == CT_DELETED) nDeleted++;
        }));
    BOOST_CHECK(wallet->DelAddressBook(dest));
    BOOST_CHECK_EQUAL(nDeleted, 1);
    BOOST_CHECK_EQUAL(wallet->mapAddressBook.count(dest), 0U);
    BOOST_CHECK_EQUAL(wallet->GetAccountName(script), "");
    {
        CWallet reloaded(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "wallet_chain_test.dat")));
        BOOST_CHECK_EQUAL(CWalletDB(reloaded.GetDBHandle(), "cr+").LoadWallet(&reloaded), DB_LOAD_OK);
        BOOST_CHECK_EQUAL(reloaded.mapAddressBook.count(dest), 0U);
    }

    // Locking and unlocking a coin
    const COutPoint outpoint(InsecureRand256(), 1);
    LOCK(wallet->cs_wallet);
    wallet->LockCoin(outpoint);
    BOOST_CHECK(wallet->IsLockedCoin(outpoint.hash, outpoint.n));
    wallet->UnlockCoin(outpoint);
    BOOST_CHECK(!wallet->IsLockedCoin(outpoint.hash, outpoint.n));
    std::vector<COutPoint> locked;
    wallet->ListLockedCoins(locked);
    BOOST_CHECK(locked.empty());
}

BOOST_AUTO_TEST_CASE(dump_and_import_through_the_wallet)
{
    const fs::path path = pathTemp / "wallet_tracking_dump.txt";
    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_CHECK(wallet->DumpWallet(path.string()));

    std::unique_ptr<CWallet> restored = NewMockWallet("wallet_chain_restored.dat");
    LOCK(restored->cs_wallet);
    BOOST_CHECK(restored->ImportWallet(path.string()));
    CKey keyOut;
    BOOST_CHECK(restored->GetKey(key.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut == key);
}

BOOST_AUTO_TEST_SUITE_END()
