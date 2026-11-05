// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_WALLET_TEST_WALLET_CHAIN_SETUP_H
#define YACOIN_WALLET_TEST_WALLET_CHAIN_SETUP_H

#include "coins.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "utiltime.h"
#include "validation.h"
#include "wallet/db.h"
#include "wallet/wallet.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

/** Sets a variable while it lives */
template <typename T>
struct ScopedValue {
    T& m_ref;
    T m_saved;
    ScopedValue(T& ref, T value) : m_ref(ref), m_saved(ref) { m_ref = value; }
    ~ScopedValue() { m_ref = m_saved; }
    ScopedValue(const ScopedValue&) = delete;
    ScopedValue& operator=(const ScopedValue&) = delete;
};

/** The mock wallet database environment for the object's lifetime */
struct MockWalletEnv {
    MockWalletEnv() { bitdb.MakeMock(); }
    ~MockWalletEnv()
    {
        bitdb.Flush(true);
        bitdb.Reset();
    }
    MockWalletEnv(const MockWalletEnv&) = delete;
    MockWalletEnv& operator=(const MockWalletEnv&) = delete;
};

inline CKey NewWalletTestKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

/** A wallet on the file strFile of the mock environment, loaded */
inline std::unique_ptr<CWallet> NewMockWallet(const std::string& strFile)
{
    std::unique_ptr<CWallet> wallet(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, strFile))));
    bool fFirstRun;
    wallet->LoadWallet(fFirstRun);
    return wallet;
}

/** Adds key to wallet (not from the keypool) */
inline void AddWalletTestKey(CWallet& wallet, const CKey& key)
{
    LOCK(wallet.cs_wallet);
    BOOST_REQUIRE(wallet.AddKeyPubKey(key, key.GetPubKey()));
}

/**
 * A regtest chain (TestChain100Setup) and a wallet on the mock database that
 * holds one key. The wallet is not registered for validation callbacks (no
 * scheduler runs in the unit tests): Mine() rescans the new block. Fund()
 * pays outputs through a mined transaction that spends a coin added to the
 * UTXO set directly; the coin's outpoint is random, so no two cases share a
 * transaction. The mempool and the mock time are cleared at the end.
 */
struct WalletChainSetup : public TestChain100Setup {
    MockWalletEnv mockWalletEnv; // declared before the wallet, so it outlives it
    std::unique_ptr<CWallet> wallet;
    CKey key;
    CScript script; // P2PKH of key

    WalletChainSetup()
    {
        wallet = NewMockWallet("wallet_chain_test.dat");
        key = NewWalletTestKey();
        AddWalletTestKey(*wallet, key);
        script = GetScriptForDestination(key.GetPubKey().GetID());
    }

    ~WalletChainSetup()
    {
        mempool.clear();
        wallet.reset();
        SetMockTime(0);
    }

    /** Keep block times increasing (one second per block) */
    void Step()
    {
        SetMockTime(std::max(GetTime(), chainActive.Tip()->GetBlockTime()) + 1);
    }

    /** Mines txs on the tip; fScan: the wallet rescans the new block */
    CBlock Mine(const std::vector<CTransaction>& txs, bool fScan = true)
    {
        Step();
        CBlock block = CreateAndProcessBlock(txs, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
        if (fScan)
            wallet->ScanForWalletTransactions(chainActive.Tip(), true);
        return block;
    }

    /** A signed transaction paying outs, spending a new coin of the UTXO set (not mined) */
    CTransaction FundingTx(const std::vector<CTxOut>& outs)
    {
        CAmount nTotal = COIN; // the fee
        for (const CTxOut& out : outs)
            nTotal += out.nValue;
        const CScript coinScript = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
        const COutPoint coin(InsecureRand256(), 0);
        {
            LOCK(cs_main);
            pcoinsTip->AddCoin(coin, Coin(CTxOut(nTotal, coinScript), chainActive.Height(), false, false,
                                          chainActive.Tip()->GetBlockTime()), false);
        }
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(coin));
        mtx.vout = outs;
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(coinbaseKey.Sign(SignatureHash(coinScript, mtx, 0, SIGHASH_ALL), vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        mtx.vin[0].scriptSig = CScript() << vchSig;
        return CTransaction(mtx);
    }

    /** Mines a funding transaction paying outs; the wallet rescans the block */
    CTransaction Fund(const std::vector<CTxOut>& outs)
    {
        Step();
        CTransaction tx = FundingTx(outs);
        Mine({tx});
        return tx;
    }

    /** Mines a funding transaction paying nValue to the wallet's key */
    CTransaction Fund(CAmount nValue) { return Fund({CTxOut(nValue, script)}); }

    /** A transaction spending the outputs (wallet transactions) to outs, signed by the wallet */
    CTransaction SpendTx(const std::vector<COutPoint>& prevouts, const std::vector<CTxOut>& outs)
    {
        CTransaction tx;
        for (const COutPoint& prevout : prevouts)
            tx.vin.push_back(CTxIn(prevout));
        tx.vout = outs;
        LOCK(wallet->cs_wallet);
        for (unsigned int i = 0; i < prevouts.size(); i++)
            BOOST_REQUIRE(SignSignature(*wallet, *wallet->mapWallet.at(prevouts[i].hash).tx, tx, i, SIGHASH_ALL));
        return tx;
    }

    CWalletTx& Wtx(const uint256& hash)
    {
        LOCK(wallet->cs_wallet);
        return wallet->mapWallet.at(hash);
    }

    /** Puts tx into the mempool without validation */
    static void AddToMempool(const CTransaction& tx)
    {
        LOCK(cs_main);
        TestMemPoolEntryHelper entry;
        mempool.addUnchecked(tx.GetHash(), entry.FromTx(tx));
    }
};

#endif // YACOIN_WALLET_TEST_WALLET_CHAIN_SETUP_H
