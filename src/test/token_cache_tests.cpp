// Copyright (c) 2017-2019 The Raven Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Token cache tests: connecting token transactions (AddCoins, as ConnectBlock
// does) and undoing them again (the token part of DisconnectBlock), in memory
// and after the cache was written to the token database. Reissue and LRU
// cases are adapted from Ravencoin's asset_reissue_tests and cache_tests.

#include "coins.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"

#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <boost/test/unit_test.hpp>

struct TokenCacheSetup : public TokenTestingSetup {
    /** Fresh token state with the token index on or off (it is off by default on nodes) */
    void ResetTokens(bool fIndex)
    {
        fTokenIndex = fIndex;
        ClearTokenGlobals();
        ResetTokenDb();
        ptokensCache->Clear();
    }
};

BOOST_FIXTURE_TEST_SUITE(token_cache_tests, TokenCacheSetup)

static const uint256 BLOCK_HASH = uint256S("0xb10c");
static const int BLOCK_HEIGHT = 10;

/** Token coins a tx spends; spending and restoring them is part of connecting and disconnecting it */
typedef std::vector<std::pair<COutPoint, CTxOut> > SpentCoins;

/** The owner token output of the tx builders in token_test_util.h (always output 1) */
static SpentCoins OwnerCoin(const CTransaction& tx)
{
    return {std::make_pair(COutPoint(tx.GetHash(), 1), tx.vout[1])};
}

/** Token side of ConnectBlock for one tx: spend its token inputs (SpendCoin),
 * then AddCoins with the token cache, collecting reissue undo data.
 * ConnectTokenTx and DisconnectTokenTx are hand copies of validation.cpp
 * (ConnectBlock, DisconnectBlock, ApplyTxInUndo): keep them in sync with it. */
static void ConnectTokenTx(CTokensCache& cache, const CTransaction& tx, std::vector<std::pair<std::string, CBlockTokenUndo> >& vUndo, const SpentCoins& vSpent = {})
{
    for (const auto& spent : vSpent)
        BOOST_CHECK(cache.TrySpendCoin(spent.first, spent.second));
    CCoinsView base;
    CCoinsViewCache view(&base);
    std::pair<std::string, CBlockTokenUndo> undo = std::make_pair("", CBlockTokenUndo());
    AddCoins(view, tx, BLOCK_HEIGHT, BLOCK_HASH, false, &cache, &undo);
    if (!undo.first.empty())
        vUndo.push_back(undo);
}

/** Token side of DisconnectBlock for one tx (mirrors validation.cpp DisconnectBlock):
 * undo its token outputs, then give back the token inputs it spent (ApplyTxInUndo).
 * DisconnectBlock also spends the tx's own outputs, but into a throwaway copy of
 * the cache (tempCache), so that has no effect on the token state and is left out. */
static bool DisconnectTokenTx(CTokensCache& cache, const CTransaction& tx, const std::vector<std::pair<std::string, CBlockTokenUndo> >& vUndo, const SpentCoins& vSpent = {})
{
    std::string strAddress;
    if (tx.IsNewToken()) {
        CNewToken token;
        if (!TokenFromTransaction(tx, token, strAddress)) return false;
        if (cache.ContainsToken(token) && !cache.RemoveNewToken(token, strAddress)) return false;
        std::string ownerName, ownerAddress;
        if (!OwnerFromTransaction(tx, ownerName, ownerAddress)) return false;
        if (!cache.RemoveOwnerToken(ownerName, ownerAddress)) return false;
    } else if (tx.IsReissueToken()) {
        CReissueToken reissue;
        if (!ReissueTokenFromTransaction(tx, reissue, strAddress)) return false;
        if (cache.ContainsToken(reissue.strName) &&
            !cache.RemoveReissueToken(reissue, strAddress, COutPoint(tx.GetHash(), tx.vout.size() - 1), vUndo))
            return false;
    } else if (tx.IsNewUniqueToken()) {
        for (const CTxOut& out : tx.vout) {
            CNewToken token;
            if (IsScriptNewUniqueToken(out.scriptPubKey)) {
                if (!TokenFromScript(out.scriptPubKey, token, strAddress)) return false;
                if (cache.ContainsToken(token.strName) && !cache.RemoveNewToken(token, strAddress)) return false;
            }
        }
    }
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        CTokenTransfer transfer;
        if (IsScriptTransferToken(tx.vout[i].scriptPubKey)) {
            if (!TransferTokenFromScript(tx.vout[i].scriptPubKey, transfer, strAddress)) return false;
            if (!cache.RemoveTransfer(transfer, strAddress, COutPoint(tx.GetHash(), i))) return false;
        }
    }
    for (auto it = vSpent.rbegin(); it != vSpent.rend(); ++it) {
        if (!cache.UndoTokenCoin(Coin(it->second, BLOCK_HEIGHT, false, false, 0), it->first)) return false;
    }
    return true;
}

/** Balance as the cache sees it (memory, ptokens or database), -1 if unknown */
static CAmount Balance(CTokensCache& cache, const std::string& name, const std::string& address)
{
    if (!GetBestTokenAddressAmount(cache, name, address)) return -1;
    return cache.mapTokensAddressAmount.at(std::make_pair(name, address));
}

static void CheckMetaData(CTokensCache& cache, const CNewToken& expected)
{
    CNewToken token;
    BOOST_REQUIRE(cache.GetTokenMetaDataIfExists(expected.strName, token));
    BOOST_CHECK_EQUAL(token.strName, expected.strName);
    BOOST_CHECK_EQUAL(token.nAmount, expected.nAmount);
    BOOST_CHECK_EQUAL((int)token.units, (int)expected.units);
    BOOST_CHECK_EQUAL((int)token.nReissuable, (int)expected.nReissuable);
    BOOST_CHECK_EQUAL((int)token.nHasIPFS, (int)expected.nHasIPFS);
    BOOST_CHECK(token.strIPFSHash == expected.strIPFSHash);
}

/** Write the cache to the database the way a chain state flush does, then forget the LRU copy */
static void FlushToDatabase(CTokensCache& cache)
{
    BOOST_CHECK(cache.Flush());
    BOOST_CHECK(ptokens->DumpCacheToDatabase());
    ptokensCache->Clear();
}

BOOST_AUTO_TEST_CASE(issue_and_undo)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        CTokensCache cache;
        const std::string address = TestTokenAddress();
        CNewToken token("ABC", 1000 * COIN, 2, 1, 1, TestIpfsHash());
        CTransaction tx = IssueTx(token);
        BOOST_CHECK(!cache.ContainsToken("ABC"));

        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        ConnectTokenTx(cache, tx, vUndo);
        BOOST_CHECK(vUndo.empty());
        BOOST_CHECK(cache.ContainsToken("ABC"));
        CheckMetaData(cache, token);
        CNewToken stored;
        int nHeight = 0;
        uint256 blockHash;
        BOOST_CHECK(cache.GetTokenMetaDataIfExists("ABC", stored, nHeight, blockHash));
        BOOST_CHECK_EQUAL(nHeight, BLOCK_HEIGHT);
        BOOST_CHECK(blockHash == BLOCK_HASH);
        BOOST_CHECK_EQUAL(Balance(cache, "ABC", address), fIndex ? 1000 * COIN : -1);
        BOOST_CHECK_EQUAL(Balance(cache, "ABC!", address), fIndex ? OWNER_TOKEN_AMOUNT : -1);

        // The same name can't be issued twice
        BOOST_CHECK(!cache.AddNewToken(token, address, BLOCK_HEIGHT, BLOCK_HASH));

        BOOST_CHECK(DisconnectTokenTx(cache, tx, vUndo));
        BOOST_CHECK(!cache.ContainsToken("ABC"));
        BOOST_CHECK(!cache.GetTokenMetaDataIfExists("ABC", stored));
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", address), 0);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC!", address), 0);
        }
        // Removing a token that doesn't exist fails
        BOOST_CHECK(!cache.RemoveNewToken(token, address));

        // After the undo, the name is free again
        ConnectTokenTx(cache, tx, vUndo);
        BOOST_CHECK(cache.ContainsToken("ABC"));
    }
}

BOOST_AUTO_TEST_CASE(unique_issue_and_undo)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        CTokensCache cache;
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        CTransaction issue = IssueTx(CNewToken("ABC", 1000 * COIN, 0, 1, 0, ""));
        ConnectTokenTx(cache, issue, vUndo);

        CTransaction unique = UniqueTx("ABC", {"ONE", "two"});
        BOOST_CHECK(unique.IsNewUniqueToken());
        ConnectTokenTx(cache, unique, vUndo, OwnerCoin(issue));
        BOOST_CHECK(cache.ContainsToken("ABC#ONE"));
        BOOST_CHECK(cache.ContainsToken("ABC#two"));
        CheckMetaData(cache, CNewToken("ABC#ONE", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""));
        if (fIndex)
            BOOST_CHECK_EQUAL(Balance(cache, "ABC#two", TestTokenAddress()), UNIQUE_TOKEN_AMOUNT);

        BOOST_CHECK(DisconnectTokenTx(cache, unique, vUndo, OwnerCoin(issue)));
        BOOST_CHECK(!cache.ContainsToken("ABC#ONE"));
        BOOST_CHECK(!cache.ContainsToken("ABC#two"));
        BOOST_CHECK(cache.ContainsToken("ABC"));
        if (fIndex)
            BOOST_CHECK_EQUAL(Balance(cache, "ABC!", TestTokenAddress()), OWNER_TOKEN_AMOUNT);
    }
}

/* A sub-token issue spends and returns the parent owner token; the undo removes the
 * sub-token and its owner token and gives the parent owner token back */
BOOST_AUTO_TEST_CASE(sub_issue_and_undo)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        CTokensCache cache;
        const std::string address = TestTokenAddress();
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        CTransaction issue = IssueTx(CNewToken("ABC", 1000 * COIN, 0, 1, 0, ""));
        ConnectTokenTx(cache, issue, vUndo);

        CNewToken sub("ABC/SUB", 50 * COIN, 1, 1, 0, "");
        CTransaction subIssue = SubIssueTx(sub, "ABC");
        BOOST_CHECK(subIssue.IsNewToken());
        ConnectTokenTx(cache, subIssue, vUndo, OwnerCoin(issue));
        BOOST_CHECK(vUndo.empty());
        BOOST_CHECK(cache.ContainsToken("ABC/SUB"));
        CheckMetaData(cache, sub);
        // Balance() is -1 without the token index, so those runs only check metadata
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC/SUB", address), 50 * COIN);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC/SUB!", address), OWNER_TOKEN_AMOUNT);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC!", address), OWNER_TOKEN_AMOUNT);
        }

        BOOST_CHECK(DisconnectTokenTx(cache, subIssue, vUndo, OwnerCoin(issue)));
        BOOST_CHECK(!cache.ContainsToken("ABC/SUB"));
        CNewToken stored;
        BOOST_CHECK(!cache.GetTokenMetaDataIfExists("ABC/SUB", stored));
        BOOST_CHECK(cache.ContainsToken("ABC"));
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC/SUB", address), 0);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC/SUB!", address), 0);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC!", address), OWNER_TOKEN_AMOUNT);
        }

        // The parent owner token is spendable again and the sub name is free
        ConnectTokenTx(cache, subIssue, vUndo, OwnerCoin(issue));
        BOOST_CHECK(cache.ContainsToken("ABC/SUB"));
    }
}

/* Each reissue variant is undone back to the original metadata. The undo
 * data for changed units/IPFS comes from AddCoins, as in ConnectBlock. */
BOOST_AUTO_TEST_CASE(reissue_and_undo)
{
    const std::string ipfs = TestIpfsHash();
    const CNewToken original("ABC", 100 * COIN, 2, 1, 0, "");
    struct Case {
        CReissueToken reissue;
        CNewToken after;
    };
    std::vector<Case> cases = {
        {CReissueToken("ABC", COIN, -1, 1, ""), CNewToken("ABC", 101 * COIN, 2, 1, 0, "")},     // amount only
        {CReissueToken("ABC", 0, 4, 1, ""), CNewToken("ABC", 100 * COIN, 4, 1, 0, "")},         // units
        {CReissueToken("ABC", 0, -1, 1, ipfs), CNewToken("ABC", 100 * COIN, 2, 1, 1, ipfs)},    // IPFS
        {CReissueToken("ABC", 5 * COIN, 6, 0, ipfs), CNewToken("ABC", 105 * COIN, 6, 0, 1, ipfs)}, // everything, then final
    };
    for (bool fIndex : {true, false}) {
        for (const Case& c : cases) {
            ResetTokens(fIndex);
            CTokensCache cache;
            std::vector<std::pair<std::string, CBlockTokenUndo> > vUndoIssue, vUndo;
            CTransaction issue = IssueTx(original);
            ConnectTokenTx(cache, issue, vUndoIssue);

            CTransaction tx = ReissueTx(c.reissue);
            BOOST_CHECK(tx.IsReissueToken());
            ConnectTokenTx(cache, tx, vUndo, OwnerCoin(issue));
            BOOST_CHECK_EQUAL(vUndo.size(), (c.reissue.nUnits != -1 || !c.reissue.strIPFSHash.empty()) ? 1U : 0U);
            CheckMetaData(cache, c.after);
            if (fIndex)
                BOOST_CHECK_EQUAL(Balance(cache, "ABC", TestTokenAddress()), c.after.nAmount);

            BOOST_CHECK(DisconnectTokenTx(cache, tx, vUndo, OwnerCoin(issue)));
            CheckMetaData(cache, original);
            if (fIndex) {
                BOOST_CHECK_EQUAL(Balance(cache, "ABC", TestTokenAddress()), original.nAmount);
                BOOST_CHECK_EQUAL(Balance(cache, "ABC!", TestTokenAddress()), OWNER_TOKEN_AMOUNT);
            }
        }
    }
}

/* Two reissues in consecutive blocks, undone newest first */
BOOST_AUTO_TEST_CASE(reissue_twice_and_undo)
{
    const std::string ipfs = TestIpfsHash();
    const CNewToken original("ABC", 100 * COIN, 2, 1, 0, "");
    CTokensCache cache;
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo0, vUndo1, vUndo2;
    CTransaction issue = IssueTx(original);
    ConnectTokenTx(cache, issue, vUndo0);
    CTransaction tx1 = ReissueTx(CReissueToken("ABC", COIN, 3, 1, ipfs));
    CTransaction tx2 = ReissueTx(CReissueToken("ABC", 2 * COIN, 5, 1, ""));
    ConnectTokenTx(cache, tx1, vUndo1, OwnerCoin(issue));
    ConnectTokenTx(cache, tx2, vUndo2, OwnerCoin(tx1));
    CheckMetaData(cache, CNewToken("ABC", 103 * COIN, 5, 1, 1, ipfs));

    BOOST_CHECK(DisconnectTokenTx(cache, tx2, vUndo2, OwnerCoin(tx1)));
    CheckMetaData(cache, CNewToken("ABC", 101 * COIN, 3, 1, 1, ipfs));
    BOOST_CHECK(DisconnectTokenTx(cache, tx1, vUndo1, OwnerCoin(issue)));
    CheckMetaData(cache, original);
    BOOST_CHECK_EQUAL(Balance(cache, "ABC", TestTokenAddress()), 100 * COIN);
}

/* Spending token coins and undoing the spend (SpendCoin / DisconnectBlock's ApplyTxInUndo) */
BOOST_AUTO_TEST_CASE(spend_and_undo_coins)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        CTokensCache cache;
        const std::string addr1 = TestTokenAddress(1), addr2 = TestTokenAddress(2);
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        CTransaction issue = IssueTx(CNewToken("ABC", 1000 * COIN, 0, 1, 0, ""));
        ConnectTokenTx(cache, issue, vUndo);

        // Spend the issued coin into two transfers
        Coin issued(issue.vout[2], BLOCK_HEIGHT, false, false, 0);
        COutPoint issuedOut(issue.GetHash(), 2);
        BOOST_CHECK(cache.TrySpendCoin(issuedOut, issued.out));
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(issuedOut));
        mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 300 * COIN), 2)));
        mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 700 * COIN), 1)));
        CTransaction transfer(mtx);
        ConnectTokenTx(cache, transfer, vUndo);
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", addr1), 700 * COIN);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", addr2), 300 * COIN);
            BOOST_CHECK_EQUAL(cache.vSpentTokens.size(), 1U);
        } else {
            BOOST_CHECK(cache.vSpentTokens.empty());
        }

        // Undo: remove the transfers, then give the spent coin back
        BOOST_CHECK(DisconnectTokenTx(cache, transfer, vUndo));
        BOOST_CHECK(cache.UndoTokenCoin(issued, issuedOut));
        BOOST_CHECK_EQUAL(cache.vUndoTokenAmount.size(), 1U);
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", addr1), 1000 * COIN);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", addr2), 0);
            // Undoing the same transfer again would make a balance negative
            BOOST_CHECK(!cache.RemoveTransfer(CTokenTransfer("ABC", 300 * COIN), addr2, COutPoint(transfer.GetHash(), 0)));
        }

        // Owner coin: spending it moves the whole owner token
        Coin owner(issue.vout[1], BLOCK_HEIGHT, false, false, 0);
        COutPoint ownerOut(issue.GetHash(), 1);
        BOOST_CHECK(cache.TrySpendCoin(ownerOut, owner.out));
        if (fIndex) BOOST_CHECK_EQUAL(Balance(cache, "ABC!", addr1), 0);
        BOOST_CHECK(cache.UndoTokenCoin(owner, ownerOut));
        if (fIndex) BOOST_CHECK_EQUAL(Balance(cache, "ABC!", addr1), OWNER_TOKEN_AMOUNT);

        // Plain YAC coins are ignored when spent, and can't be "undone" as tokens
        Coin plain(CTxOut(COIN, TestTokenScriptBase()), BLOCK_HEIGHT, false, false, 0);
        BOOST_CHECK(cache.TrySpendCoin(COutPoint(uint256S("0x04"), 0), plain.out));
        BOOST_CHECK(!cache.UndoTokenCoin(plain, COutPoint(uint256S("0x04"), 0)));
    }
}

/* The realistic reorg case: the block was already flushed to the token
 * database, and the undo starts from a fresh cache that reads it back. */
BOOST_AUTO_TEST_CASE(undo_after_flush_to_database)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        const std::string addr1 = TestTokenAddress(1), addr2 = TestTokenAddress(2);
        const CNewToken token("ABC", 1000 * COIN, 0, 1, 0, "");
        CTransaction issue = IssueTx(token);
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        {
            CTokensCache cache;
            ConnectTokenTx(cache, issue, vUndo);
            FlushToDatabase(cache);
        }

        CNewToken stored;
        int nHeight;
        uint256 blockHash;
        BOOST_CHECK(ptokensdb->ReadTokenData("ABC", stored, nHeight, blockHash));
        BOOST_CHECK_EQUAL(stored.nAmount, 1000 * COIN);
        BOOST_CHECK_EQUAL(nHeight, BLOCK_HEIGHT);
        CAmount nQuantity = 0;
        BOOST_CHECK_EQUAL(ptokensdb->ReadTokenAddressQuantity("ABC", addr1, nQuantity), fIndex);
        if (fIndex) BOOST_CHECK_EQUAL(nQuantity, 1000 * COIN);

        // Second block: a transfer, flushed too
        Coin issued(issue.vout[2], BLOCK_HEIGHT, false, false, 0);
        COutPoint issuedOut(issue.GetHash(), 2);
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(issuedOut));
        mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 400 * COIN), 2)));
        mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 600 * COIN), 1)));
        CTransaction transfer(mtx);
        {
            CTokensCache cache;
            BOOST_CHECK(cache.TrySpendCoin(issuedOut, issued.out));
            ConnectTokenTx(cache, transfer, vUndo);
            FlushToDatabase(cache);
        }
        if (fIndex) {
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC", addr2, nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, 400 * COIN);
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC", addr1, nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, 600 * COIN);
        }

        // Disconnect the transfer block from a fresh cache
        {
            CTokensCache cache;
            BOOST_CHECK(cache.ContainsToken("ABC"));
            BOOST_CHECK(DisconnectTokenTx(cache, transfer, vUndo));
            BOOST_CHECK(cache.UndoTokenCoin(issued, issuedOut));
            FlushToDatabase(cache);
        }
        if (fIndex) {
            BOOST_CHECK(!ptokensdb->ReadTokenAddressQuantity("ABC", addr2, nQuantity));
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC", addr1, nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, 1000 * COIN);
        }

        // Disconnect the issue block: the token is gone from the database
        {
            CTokensCache cache;
            BOOST_CHECK(DisconnectTokenTx(cache, issue, vUndo));
            FlushToDatabase(cache);
        }
        BOOST_CHECK(!ptokensdb->ReadTokenData("ABC", stored, nHeight, blockHash));
        BOOST_CHECK(!ptokensdb->ReadTokenAddressQuantity("ABC", addr1, nQuantity));
        BOOST_CHECK(!ptokensdb->ReadTokenAddressQuantity("ABC!", addr1, nQuantity));
        CTokensCache fresh;
        BOOST_CHECK(!fresh.ContainsToken("ABC"));
    }
}

BOOST_AUTO_TEST_CASE(reissue_undo_after_flush_to_database)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        const CNewToken original("ABC", 100 * COIN, 2, 1, 0, "");
        CTransaction issue = IssueTx(original);
        CTransaction reissue = ReissueTx(CReissueToken("ABC", COIN, 4, 1, TestIpfsHash()));
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndoIssue, vUndo;
        {
            CTokensCache cache;
            ConnectTokenTx(cache, issue, vUndoIssue);
            FlushToDatabase(cache);
        }
        {
            CTokensCache cache;
            ConnectTokenTx(cache, reissue, vUndo, OwnerCoin(issue));
            FlushToDatabase(cache);
        }
        // ConnectBlock stores the reissue undo data per block, DisconnectBlock reads it back
        BOOST_REQUIRE_EQUAL(vUndo.size(), 1U);
        BOOST_CHECK(ptokensdb->WriteBlockUndoTokenData(BLOCK_HASH, vUndo));
        vUndo.clear();
        BOOST_CHECK(ptokensdb->ReadBlockUndoTokenData(BLOCK_HASH, vUndo));
        BOOST_REQUIRE_EQUAL(vUndo.size(), 1U);
        BOOST_CHECK_EQUAL(vUndo[0].first, "ABC");
        BOOST_CHECK(vUndo[0].second.fChangedIPFS && vUndo[0].second.fChangedUnits);
        BOOST_CHECK_EQUAL(vUndo[0].second.nUnits, original.units);
        CNewToken stored;
        int nHeight;
        uint256 blockHash;
        BOOST_CHECK(ptokensdb->ReadTokenData("ABC", stored, nHeight, blockHash));
        BOOST_CHECK_EQUAL(stored.nAmount, 101 * COIN);
        BOOST_CHECK_EQUAL((int)stored.units, 4);
        BOOST_CHECK_EQUAL((int)stored.nHasIPFS, 1);
        {
            CTokensCache cache;
            BOOST_CHECK(DisconnectTokenTx(cache, reissue, vUndo, OwnerCoin(issue)));
            FlushToDatabase(cache);
        }
        BOOST_CHECK(ptokensdb->ReadTokenData("ABC", stored, nHeight, blockHash));
        BOOST_CHECK_EQUAL(stored.nAmount, original.nAmount);
        BOOST_CHECK_EQUAL((int)stored.units, (int)original.units);
        BOOST_CHECK_EQUAL((int)stored.nHasIPFS, 0);
        BOOST_CHECK_EQUAL(stored.strIPFSHash, "");
        if (fIndex) {
            CAmount nQuantity = 0;
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC", TestTokenAddress(), nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, 100 * COIN);
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC!", TestTokenAddress(), nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, OWNER_TOKEN_AMOUNT);
        }
    }
}

BOOST_AUTO_TEST_CASE(contextual_checks)
{
    CTokensCache cache;
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
    ConnectTokenTx(cache, IssueTx(CNewToken("ABC", 100 * COIN, 2, 1, 0, "")), vUndo);
    ConnectTokenTx(cache, IssueTx(CNewToken("FIXED", 100 * COIN, 0, 0, 0, "")), vUndo);
    std::string strError;

    // New tokens: the name must be free, also in the mempool when asked to check it
    BOOST_CHECK(ContextualCheckNewToken(&cache, CNewToken("NEW", COIN, 0, 1, 0, ""), strError));
    BOOST_CHECK(!ContextualCheckNewToken(&cache, CNewToken("ABC", COIN, 0, 1, 0, ""), strError));
    mempool.mapTokenToHash["NEW"] = uint256S("0x05");
    BOOST_CHECK(ContextualCheckNewToken(&cache, CNewToken("NEW", COIN, 0, 1, 0, ""), strError, false));
    BOOST_CHECK(!ContextualCheckNewToken(&cache, CNewToken("NEW", COIN, 0, 1, 0, ""), strError, true));
    BOOST_CHECK(ContextualCheckNewToken(&cache, CNewToken("NEWIPFS", COIN, 0, 1, 1, TestIpfsHash()), strError));
    BOOST_CHECK(!ContextualCheckNewToken(&cache, CNewToken("NEWIPFS", COIN, 0, 1, 1, "too short"), strError));
    BOOST_CHECK(!ContextualCheckNewToken(&cache, CNewToken("NEWIPFS", COIN, 0, 1, 1, std::string(34, 'x')), strError));
    BOOST_CHECK(ContextualCheckUniqueToken(&cache, CNewToken("ABC#TAG", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""), strError));

    // Reissues (adapted from Ravencoin's reissue_isvalid_test)
    BOOST_CHECK(ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, 2, 1, TestIpfsHash()), strError));
    BOOST_CHECK(ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, -1, 1, ""), strError));
    BOOST_CHECK(ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, 6, 1, ""), strError));
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("NOTEXIST", COIN, 2, 1, ""), strError));
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("FIXED", COIN, 0, 1, ""), strError));
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, 1, 1, ""), strError)); // fewer units
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN + 1, -1, 1, ""), strError)); // amount vs units
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("ABC", MAX_MONEY - 50 * COIN, -1, 1, ""), strError)); // total > MAX_MONEY
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, -1, 1, "short"), strError));

    // The variant used by CheckTxTokens checks the given reissue, and fails if the tx isn't a reissue
    CTransaction tx = ReissueTx(CReissueToken("ABC", COIN, -1, 1, ""));
    CReissueToken reissue("ABC", COIN, -1, 1, "");
    BOOST_CHECK(ContextualCheckReissueToken(&cache, reissue, strError, tx));
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, reissue, strError, IssueTx(CNewToken("XYZ", COIN))));

    // Transfers only need a valid name and a positive amount here
    BOOST_CHECK(ContextualCheckTransferToken(&cache, CTokenTransfer("ABC", 1), TestTokenAddress(), strError));
    BOOST_CHECK(!ContextualCheckTransferToken(&cache, CTokenTransfer("ABC", 0), TestTokenAddress(), strError));
    BOOST_CHECK(!ContextualCheckTransferToken(&cache, CTokenTransfer("abc", 1), TestTokenAddress(), strError));
}

BOOST_AUTO_TEST_CASE(unique_tx_contextual_check)
{
    CTokensCache cache;
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
    CTransaction issue = IssueTx(CNewToken("ABC", 100 * COIN, 0, 1, 0, ""));
    ConnectTokenTx(cache, issue, vUndo);
    ConnectTokenTx(cache, UniqueTx("ABC", {"TAG1"}), vUndo, OwnerCoin(issue));
    std::string strError;

    // Only unique token outputs are checked: a tx without outputs passes, and so does a
    // plain issue, even of a name that already exists (that is checked elsewhere)
    BOOST_CHECK(ContextualCheckUniqueTokenTx(&cache, strError, CTransaction(CMutableTransaction())));
    BOOST_CHECK_EQUAL(strError, "");
    BOOST_CHECK(ContextualCheckUniqueTokenTx(&cache, strError, issue));
    BOOST_CHECK_EQUAL(strError, "");
    BOOST_CHECK(ContextualCheckUniqueTokenTx(&cache, strError, UniqueTx("ABC", {"NEW1", "NEW2"})));

    // Each unique output must be a new, valid unique token; the second one fails here
    BOOST_CHECK(!ContextualCheckUniqueTokenTx(&cache, strError, UniqueTx("ABC", {"NEW1", "TAG1"})));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: token_name 'ABC#TAG1' has already been used");
    BOOST_CHECK(!ContextualCheckUniqueToken(&cache, CNewToken("ABC#TAG1", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: token_name 'ABC#TAG1' has already been used");

    CMutableTransaction big(UniqueTx("ABC", {"NEW1"}));
    big.vout.back() = CTxOut(0, NewTokenScript(CNewToken("ABC#BIG", 2 * UNIQUE_TOKEN_AMOUNT, 0, 0, 0, "")));
    BOOST_CHECK(!ContextualCheckUniqueTokenTx(&cache, strError, CTransaction(big)));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: amount must be 1000000");
    CMutableTransaction units(UniqueTx("ABC", {"NEW1"}));
    units.vout.back() = CTxOut(0, NewTokenScript(CNewToken("ABC#UNITS", UNIQUE_TOKEN_AMOUNT, 1, 0, 0, "")));
    BOOST_CHECK(!ContextualCheckUniqueTokenTx(&cache, strError, CTransaction(units)));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: units must be 0");
}

/** A token coin of each type at TestTokenAddress(3), with the name and amount it holds */
struct TokenCoinCase {
    CScript script;
    std::string name;
    CAmount nAmount;
};

static std::vector<TokenCoinCase> TokenCoinCases(const std::string& name)
{
    const CNewToken token(name, 7 * COIN);
    return {
        {NewTokenScript(token, 3), name, 7 * COIN},
        {OwnerTokenScript(token, 3), name + OWNER_TAG, OWNER_TOKEN_AMOUNT},
        {TransferTokenScript(CTokenTransfer(name, 2 * COIN), 3), name, 2 * COIN},
        {ReissueTokenScript(CReissueToken(name, 3 * COIN, -1, 1, ""), 3), name, 3 * COIN},
    };
}

static std::vector<CScript> UndecodableTokenScripts(const std::string& name)
{
    return {TruncatedIssueScript(name), TruncatedOwnerScript(name), TruncatedTransferScript(name), TruncatedReissueScript(name)};
}

BOOST_AUTO_TEST_CASE(try_spend_coin)
{
    const std::string addr = TestTokenAddress(3);
    for (bool fIndex : {true, false}) {
        for (const TokenCoinCase& c : TokenCoinCases("TRYSPEND")) {
            ResetTokens(fIndex);
            CTokensCache cache;
            const CTxOut txOut(0, c.script);
            const auto pair = std::make_pair(c.name, addr);
            // No balance known anywhere: nothing to lower
            BOOST_CHECK(cache.TrySpendCoin(COutPoint(InsecureRand256(), 0), txOut));
            BOOST_CHECK(cache.mapTokensAddressAmount.empty());
            BOOST_CHECK(cache.vSpentTokens.empty());

            cache.mapTokensAddressAmount[pair] = 10 * COIN;
            BOOST_CHECK(cache.TrySpendCoin(COutPoint(InsecureRand256(), 0), txOut));
            BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(pair), fIndex ? 10 * COIN - c.nAmount : 10 * COIN);
            // A balance smaller than the coin stops at 0
            cache.mapTokensAddressAmount[pair] = 1;
            BOOST_CHECK(cache.TrySpendCoin(COutPoint(InsecureRand256(), 0), txOut));
            BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(pair), fIndex ? 0 : 1);
            BOOST_REQUIRE_EQUAL(cache.vSpentTokens.size(), fIndex ? 2U : 0U);
            if (fIndex) {
                BOOST_CHECK_EQUAL(cache.vSpentTokens[1].tokenName, c.name);
                BOOST_CHECK_EQUAL(cache.vSpentTokens[1].address, addr);
                BOOST_CHECK_EQUAL(cache.vSpentTokens[1].nAmount, c.nAmount);
            }
        }
    }
    CTokensCache cache;
    for (const CScript& script : UndecodableTokenScripts("TRYSPENDBAD"))
        BOOST_CHECK(!cache.TrySpendCoin(COutPoint(InsecureRand256(), 0), CTxOut(0, script)));
}

BOOST_AUTO_TEST_CASE(undo_token_coin)
{
    const std::string addr = TestTokenAddress(3);
    for (bool fIndex : {true, false}) {
        for (const TokenCoinCase& c : TokenCoinCases("UNDOCOIN")) {
            ResetTokens(fIndex);
            CTokensCache cache;
            const Coin coin(CTxOut(0, c.script), BLOCK_HEIGHT, false, false, 0);
            BOOST_CHECK(cache.UndoTokenCoin(coin, COutPoint(InsecureRand256(), 0)));
            BOOST_CHECK(cache.UndoTokenCoin(coin, COutPoint(InsecureRand256(), 0)));
            BOOST_REQUIRE_EQUAL(cache.vUndoTokenAmount.size(), 2U);
            BOOST_CHECK_EQUAL(cache.vUndoTokenAmount[0].tokenName, c.name);
            BOOST_CHECK_EQUAL(cache.vUndoTokenAmount[0].address, addr);
            BOOST_CHECK_EQUAL(cache.vUndoTokenAmount[0].nAmount, c.nAmount);
            if (fIndex)
                BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(std::make_pair(c.name, addr)), 2 * c.nAmount);
            else
                BOOST_CHECK(cache.mapTokensAddressAmount.empty());
        }
    }
    CTokensCache cache;
    for (const CScript& script : UndecodableTokenScripts("UNDOCOINBAD"))
        BOOST_CHECK(!cache.UndoTokenCoin(Coin(CTxOut(0, script), BLOCK_HEIGHT, false, false, 0), COutPoint(InsecureRand256(), 0)));
    // A zero amount has nothing to give back
    const Coin zero(CTxOut(0, TransferTokenScript(CTokenTransfer("UNDOCOIN", 0))), BLOCK_HEIGHT, false, false, 0);
    BOOST_CHECK(!cache.UndoTokenCoin(zero, COutPoint(InsecureRand256(), 0)));
    BOOST_CHECK(cache.vUndoTokenAmount.empty());
}

/* Undoing a transfer needs the receiver's balance (memory, ptokens or database) to cover it */
BOOST_AUTO_TEST_CASE(remove_transfer_needs_balance)
{
    ResetTokens(true);
    const std::string addr = TestTokenAddress(4);
    const CTokenTransfer transfer("UNDOXFER", 3 * COIN);
    const auto pair = std::make_pair(transfer.strName, addr);
    CTokensCache cache;
    BOOST_CHECK(!cache.RemoveTransfer(transfer, addr, COutPoint(InsecureRand256(), 0)));
    BOOST_CHECK(cache.mapTokensAddressAmount.empty());
    BOOST_CHECK(cache.setNewTransferTokensToRemove.empty());

    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity(transfer.strName, addr, 5 * COIN));
    BOOST_CHECK(cache.RemoveTransfer(transfer, addr, COutPoint(InsecureRand256(), 0)));
    BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(pair), 2 * COIN);
    BOOST_CHECK_EQUAL(cache.setNewTransferTokensToRemove.size(), 1U);
    BOOST_CHECK(!cache.RemoveTransfer(transfer, addr, COutPoint(InsecureRand256(), 0)));
    BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(pair), 2 * COIN);
    BOOST_CHECK_EQUAL(cache.setNewTransferTokensToRemove.size(), 1U);

    // Without the token index no balance is kept or needed
    ResetTokens(false);
    CTokensCache noIndex;
    BOOST_CHECK(noIndex.RemoveTransfer(transfer, addr, COutPoint(InsecureRand256(), 0)));
    BOOST_CHECK(noIndex.mapTokensAddressAmount.empty());
    BOOST_CHECK_EQUAL(noIndex.setNewTransferTokensToRemove.size(), 1U);
}

BOOST_AUTO_TEST_CASE(reissue_cache_entries)
{
    ResetTokens(true);
    const std::string ipfs = TestIpfsHash();
    const std::string addr = TestTokenAddress(5), addrNone = TestTokenAddress(6);
    const auto pair = std::make_pair(std::string("REISSUED"), addr), pairNone = std::make_pair(std::string("REISSUED"), addrNone);
    const CReissueToken first("REISSUED", 2 * COIN, 1, 1, ""), second("REISSUED", 3 * COIN, 2, 0, ipfs);
    const COutPoint out1(InsecureRand256(), 2), out2(InsecureRand256(), 2);
    CTokensCache cache;
    // The token must exist
    BOOST_CHECK(!cache.AddReissueToken(first, addr, out1));
    BOOST_CHECK(!cache.RemoveReissueToken(first, addr, out1, {}));
    BOOST_CHECK(cache.mapReissuedTokenData.empty() && cache.setNewReissueToAdd.empty() && cache.setNewReissueToRemove.empty());

    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
    ConnectTokenTx(cache, IssueTx(CNewToken("REISSUED", 10 * COIN, 0, 1, 0, "")), vUndo);
    // Two reissues to an address without a balance accumulate in the same cache
    BOOST_CHECK(cache.AddReissueToken(first, addr, out1));
    BOOST_CHECK(cache.AddReissueToken(second, addr, out2));
    CheckMetaData(cache, CNewToken("REISSUED", 15 * COIN, 2, 0, 1, ipfs));
    BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(pair), 5 * COIN);
    BOOST_CHECK_EQUAL(cache.setNewReissueToAdd.size(), 2U);

    // The undo data of the token restores the IPFS hash and units; an empty hash clears nHasIPFS
    BOOST_CHECK(cache.RemoveReissueToken(second, addr, out2, {{"OTHER", CBlockTokenUndo{true, true, ipfs, 7}}, {"REISSUED", CBlockTokenUndo{true, true, "", 1}}}));
    CheckMetaData(cache, CNewToken("REISSUED", 12 * COIN, 1, 1, 0, ""));
    BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(pair), 2 * COIN);
    BOOST_CHECK_EQUAL(cache.setNewReissueToAdd.size(), 1U);
    BOOST_CHECK_EQUAL(cache.setNewReissueToRemove.size(), 1U);

    // More than the balance fails, after the metadata and the balance were changed
    BOOST_CHECK(!cache.RemoveReissueToken(CReissueToken("REISSUED", 3 * COIN, -1, 1, ""), addr, COutPoint(InsecureRand256(), 2), {}));
    CheckMetaData(cache, CNewToken("REISSUED", 9 * COIN, 1, 1, 0, ""));
    BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(pair), -COIN);
    // No balance known: only a zero-amount reissue can be undone
    BOOST_CHECK(!cache.RemoveReissueToken(CReissueToken("REISSUED", COIN, -1, 1, ""), addrNone, COutPoint(InsecureRand256(), 2), {}));
    BOOST_CHECK(!cache.mapTokensAddressAmount.count(pairNone));
    BOOST_CHECK(cache.RemoveReissueToken(CReissueToken("REISSUED", 0, -1, 1, ""), addrNone, COutPoint(InsecureRand256(), 2), {}));
    BOOST_CHECK_EQUAL(cache.mapTokensAddressAmount.at(pairNone), 0);

    // Reissuing again cancels the pending removal of the same output
    const CTokenCacheReissueToken entry2(second, addr, out2, 0, uint256());
    BOOST_CHECK(cache.setNewReissueToRemove.count(entry2));
    BOOST_CHECK(cache.AddReissueToken(second, addr, out2));
    BOOST_CHECK(!cache.setNewReissueToRemove.count(entry2));
    BOOST_CHECK(cache.setNewReissueToAdd.count(entry2));
}

/* Where CheckIfTokenExists and GetTokenMetaDataIfExists look: the dirty sets of
 * the cache and of ptokens, the LRU cache, then the database */
BOOST_AUTO_TEST_CASE(token_lookup_order)
{
    ResetTokens(true);
    const std::string addr = TestTokenAddress(7);
    CTokensCache cache;
    cache.setNewTokensToAdd.insert(CTokenCacheNewToken(CNewToken("LOOKOWN", COIN), addr, 11, BLOCK_HASH));
    ptokens->setNewTokensToAdd.insert(CTokenCacheNewToken(CNewToken("LOOKPARENT", COIN), addr, 12, BLOCK_HASH));
    ptokensCache->Put("LOOKLRU", CDatabasedTokenData(CNewToken("LOOKLRU", COIN), 13, BLOCK_HASH));
    BOOST_REQUIRE(ptokensdb->WriteTokenData(CNewToken("LOOKDB", COIN), 14, BLOCK_HASH));
    const std::vector<std::string> names = {"LOOKOWN", "LOOKPARENT", "LOOKLRU", "LOOKDB"};

    // Without fForceDuplicateCheck a token is logged, not found; the database
    // lookup still puts it into the LRU cache
    for (const std::string& name : names)
        BOOST_CHECK_MESSAGE(!cache.CheckIfTokenExists(name, false), name);
    BOOST_CHECK(ptokensCache->Exists("LOOKDB"));
    for (const std::string& name : names)
        BOOST_CHECK_MESSAGE(cache.CheckIfTokenExists(name), name);
    ptokensCache->Erase("LOOKDB");
    BOOST_CHECK(cache.CheckIfTokenExists("LOOKDB"));
    BOOST_CHECK(!cache.CheckIfTokenExists("LOOKNONE"));
    BOOST_CHECK(!cache.CheckIfTokenExists("LOOKNONE", false));

    ptokensCache->Erase("LOOKDB");
    CNewToken token;
    for (size_t i = 0; i < names.size(); i++) {
        int nHeight = 0;
        uint256 hash;
        BOOST_CHECK_MESSAGE(cache.GetTokenMetaDataIfExists(names[i], token, nHeight, hash), names[i]);
        BOOST_CHECK_EQUAL(token.strName, names[i]);
        BOOST_CHECK_EQUAL(nHeight, 11 + (int)i);
        BOOST_CHECK(hash == BLOCK_HASH);
    }
    BOOST_CHECK(ptokensCache->Exists("LOOKDB"));
    BOOST_CHECK(!cache.GetTokenMetaDataIfExists("LOOKNONE", token));

    // Reissued data of the cache and of ptokens comes first
    cache.mapReissuedTokenData["LOOKOWN"] = CNewToken("LOOKOWN", 5 * COIN);
    ptokens->mapReissuedTokenData["LOOKLRU"] = CNewToken("LOOKLRU", 6 * COIN);
    BOOST_CHECK(cache.GetTokenMetaDataIfExists("LOOKOWN", token));
    BOOST_CHECK_EQUAL(token.nAmount, 5 * COIN);
    BOOST_CHECK(cache.GetTokenMetaDataIfExists("LOOKLRU", token));
    BOOST_CHECK_EQUAL(token.nAmount, 6 * COIN);

    // A pending removal in the cache or in ptokens hides the token
    cache.setNewTokensToRemove.insert(CTokenCacheNewToken(CNewToken("LOOKDB", COIN), addr, 0, uint256()));
    ptokens->setNewTokensToRemove.insert(CTokenCacheNewToken(CNewToken("LOOKPARENT", COIN), addr, 0, uint256()));
    for (const std::string& name : {"LOOKDB", "LOOKPARENT"}) {
        BOOST_CHECK_MESSAGE(!cache.CheckIfTokenExists(name), name);
        BOOST_CHECK_MESSAGE(!cache.GetTokenMetaDataIfExists(name, token), name);
    }
}

/* Flush moves a cache's changes into ptokens: an add cancels a pending remove and the other way round */
BOOST_AUTO_TEST_CASE(flush_into_ptokens)
{
    ResetTokens(true);
    const std::string addr = TestTokenAddress(8);
    {
        CTokensCache cache;
        CTokensCache* saved = ptokens;
        ptokens = nullptr;
        const bool fFlushed = cache.Flush();
        ptokens = saved;
        BOOST_CHECK(!fFlushed);
    }
    const COutPoint outA(InsecureRand256(), 1), outR(InsecureRand256(), 1);
    const CTokenCacheNewToken tokenA(CNewToken("FLUSHADD", COIN), addr, 1, BLOCK_HASH), tokenR(CNewToken("FLUSHREM", COIN), addr, 1, BLOCK_HASH);
    const CTokenCacheNewOwner ownerA("FLUSHADD!", addr), ownerR("FLUSHREM!", addr);
    const CTokenCacheReissueToken reissueA(CReissueToken("FLUSHADD", COIN, -1, 1, ""), addr, outA, 1, BLOCK_HASH),
        reissueR(CReissueToken("FLUSHREM", COIN, -1, 1, ""), addr, outR, 1, BLOCK_HASH);
    const CTokenCacheNewTransfer transferA(CTokenTransfer("FLUSHADD", COIN), addr, outA), transferR(CTokenTransfer("FLUSHREM", COIN), addr, outR);
    const auto pair = std::make_pair(std::string("FLUSHADD"), addr);

    CTokensCache& parent = *ptokens;
    parent.setNewTokensToRemove.insert(tokenA);
    parent.setNewTokensToAdd.insert(tokenR);
    parent.setNewOwnerTokensToRemove.insert(ownerA);
    parent.setNewOwnerTokensToAdd.insert(ownerR);
    parent.setNewReissueToRemove.insert(reissueA);
    parent.setNewReissueToAdd.insert(reissueR);
    parent.setNewTransferTokensToRemove.insert(transferA);
    parent.setNewTransferTokensToAdd.insert(transferR);
    parent.mapTokensAddressAmount[pair] = COIN;

    CTokensCache cache;
    cache.setNewTokensToAdd.insert(tokenA);
    cache.setNewTokensToRemove.insert(tokenR);
    cache.setNewOwnerTokensToAdd.insert(ownerA);
    cache.setNewOwnerTokensToRemove.insert(ownerR);
    cache.setNewReissueToAdd.insert(reissueA);
    cache.setNewReissueToRemove.insert(reissueR);
    cache.setNewTransferTokensToAdd.insert(transferA);
    cache.setNewTransferTokensToRemove.insert(transferR);
    cache.mapTokensAddressAmount[pair] = 3 * COIN;
    cache.mapReissuedTokenData["FLUSHADD"] = CNewToken("FLUSHADD", 4 * COIN);
    cache.vSpentTokens.emplace_back("FLUSHADD", addr, COIN);
    cache.vUndoTokenAmount.emplace_back("FLUSHREM", addr, 2 * COIN);
    BOOST_CHECK(cache.Flush());

    BOOST_CHECK(parent.setNewTokensToAdd.size() == 1 && parent.setNewTokensToAdd.count(tokenA));
    BOOST_CHECK(parent.setNewTokensToRemove.size() == 1 && parent.setNewTokensToRemove.count(tokenR));
    BOOST_CHECK(parent.setNewOwnerTokensToAdd.size() == 1 && parent.setNewOwnerTokensToAdd.count(ownerA));
    BOOST_CHECK(parent.setNewOwnerTokensToRemove.size() == 1 && parent.setNewOwnerTokensToRemove.count(ownerR));
    BOOST_CHECK(parent.setNewReissueToAdd.size() == 1 && parent.setNewReissueToAdd.count(reissueA));
    BOOST_CHECK(parent.setNewReissueToRemove.size() == 1 && parent.setNewReissueToRemove.count(reissueR));
    BOOST_CHECK(parent.setNewTransferTokensToAdd.size() == 1 && parent.setNewTransferTokensToAdd.count(transferA));
    BOOST_CHECK(parent.setNewTransferTokensToRemove.size() == 1 && parent.setNewTransferTokensToRemove.count(transferR));
    BOOST_CHECK_EQUAL(parent.mapTokensAddressAmount.at(pair), 3 * COIN);
    BOOST_CHECK_EQUAL(parent.mapReissuedTokenData.at("FLUSHADD").nAmount, 4 * COIN);
    BOOST_REQUIRE_EQUAL(parent.vSpentTokens.size(), 1U);
    BOOST_CHECK_EQUAL(parent.vSpentTokens[0].tokenName, "FLUSHADD");
    BOOST_REQUIRE_EQUAL(parent.vUndoTokenAmount.size(), 1U);
    BOOST_CHECK_EQUAL(parent.vUndoTokenAmount[0].nAmount, 2 * COIN);
}

/** Quantity of a token at an address in both tables of the token database, -1 if absent */
static CAmount DbQuantity(const std::string& name, const std::string& address)
{
    CAmount byToken = -1, byAddress = -1;
    if (!ptokensdb->ReadTokenAddressQuantity(name, address, byToken)) byToken = -1;
    if (!ptokensdb->ReadAddressTokenQuantity(address, name, byAddress)) byAddress = -1;
    BOOST_CHECK_EQUAL(byToken, byAddress);
    return byToken;
}

static void WriteDbQuantity(const std::string& name, const std::string& address, CAmount nAmount)
{
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity(name, address, nAmount));
    BOOST_REQUIRE(ptokensdb->WriteAddressTokenQuantity(address, name, nAmount));
}

/* Each kind of dirty entry of ptokens as the database ends up with it (token index on) */
BOOST_AUTO_TEST_CASE(dump_cache_to_database)
{
    ResetTokens(true);
    std::vector<std::string> a;
    for (unsigned char n = 1; n <= 12; n++)
        a.push_back(TestTokenAddress(n));
    // Before: a token being undone, and DUMPKEPT holders whose entries change
    const CNewToken gone("DUMPGONE", 9 * COIN), kept("DUMPKEPT", 20 * COIN, 0, 1, 0, "");
    for (const CNewToken& token : {gone, kept}) {
        BOOST_REQUIRE(ptokensdb->WriteTokenData(token, 1, BLOCK_HASH));
        ptokensCache->Put(token.strName, CDatabasedTokenData(token, 1, BLOCK_HASH));
    }
    WriteDbQuantity("DUMPGONE", a[0], 9 * COIN);
    WriteDbQuantity("DUMPGONE!", a[0], OWNER_TOKEN_AMOUNT);
    for (size_t i = 1; i < a.size(); i++)
        WriteDbQuantity("DUMPKEPT", a[i], COIN);

    CTokensCache& c = *ptokens;
    auto amount = [&c](const std::string& name, const std::string& address) -> CAmount& {
        return c.mapTokensAddressAmount[std::make_pair(name, address)];
    };
    auto out = [] { return COutPoint(InsecureRand256(), 0); };
    auto reissue = [](const std::string& name, CAmount nAmount, const std::string& address) {
        return CTokenCacheReissueToken(CReissueToken(name, nAmount, -1, 1, ""), address, COutPoint(InsecureRand256(), 2), 1, BLOCK_HASH);
    };
    const CTokenTransfer transfer("DUMPKEPT", COIN);
    c.setNewTokensToRemove.insert(CTokenCacheNewToken(gone, a[0], 0, uint256()));
    c.setNewTokensToAdd.insert(CTokenCacheNewToken(CNewToken("DUMPNEW", 5 * COIN), a[0], 2, BLOCK_HASH));
    c.setNewOwnerTokensToRemove.insert(CTokenCacheNewOwner("DUMPGONE!", a[0]));
    c.setNewOwnerTokensToAdd.insert(CTokenCacheNewOwner("DUMPNEW!", a[0]));
    amount("DUMPNEW!", a[0]) = OWNER_TOKEN_AMOUNT;
    c.setNewOwnerTokensToAdd.insert(CTokenCacheNewOwner("DUMPZERO!", a[0])); // zero balance: not written
    amount("DUMPZERO!", a[0]) = 0;
    // Undone transfers: down to 0 (erased), to a lower balance, without a balance in the cache (skipped)
    c.setNewTransferTokensToRemove.insert(CTokenCacheNewTransfer(transfer, a[1], out()));
    amount("DUMPKEPT", a[1]) = 0;
    c.setNewTransferTokensToRemove.insert(CTokenCacheNewTransfer(transfer, a[2], out()));
    amount("DUMPKEPT", a[2]) = 3 * COIN;
    c.setNewTransferTokensToRemove.insert(CTokenCacheNewTransfer(transfer, a[3], out()));
    // New transfers: written with the cached balance, skipped without one
    c.setNewTransferTokensToAdd.insert(CTokenCacheNewTransfer(transfer, a[4], out()));
    amount("DUMPKEPT", a[4]) = 4 * COIN;
    c.setNewTransferTokensToAdd.insert(CTokenCacheNewTransfer(transfer, a[5], out()));
    // Reissues: written with the cached balance, not with a zero one; skipped without reissued data
    c.mapReissuedTokenData["DUMPKEPT"] = CNewToken("DUMPKEPT", 22 * COIN, 2, 1, 0, "");
    c.setNewReissueToAdd.insert(reissue("DUMPKEPT", 2 * COIN, a[6]));
    amount("DUMPKEPT", a[6]) = 3 * COIN;
    c.setNewReissueToAdd.insert(reissue("DUMPKEPT", 0, a[7]));
    amount("DUMPKEPT", a[7]) = 0;
    c.setNewReissueToAdd.insert(reissue("DUMPNODATA", COIN, a[7]));
    // Undone reissues: down to 0 (erased), to a lower balance; skipped for a token being
    // removed and without reissued data
    c.setNewReissueToRemove.insert(reissue("DUMPKEPT", COIN, a[8]));
    amount("DUMPKEPT", a[8]) = 0;
    c.setNewReissueToRemove.insert(reissue("DUMPKEPT", COIN, a[9]));
    amount("DUMPKEPT", a[9]) = 6 * COIN;
    c.mapReissuedTokenData["DUMPGONE"] = CNewToken("DUMPGONE", 99 * COIN);
    c.setNewReissueToRemove.insert(reissue("DUMPGONE", COIN, a[0]));
    c.setNewReissueToRemove.insert(reissue("DUMPNODATA", COIN, a[9]));
    // Undone spends are written; spends erase a balance that reached 0 and write any other
    c.vUndoTokenAmount.emplace_back("DUMPKEPT", a[10], COIN);
    amount("DUMPKEPT", a[10]) = 7 * COIN;
    c.vUndoTokenAmount.emplace_back("DUMPUNKNOWN", a[10], COIN); // no balance in the cache: skipped
    c.vSpentTokens.emplace_back("DUMPKEPT", a[11], COIN);
    amount("DUMPKEPT", a[11]) = 0;
    c.vSpentTokens.emplace_back("DUMPKEPT", a[3], COIN); // no balance in the cache: skipped
    c.vSpentTokens.emplace_back("DUMPNEW", a[0], COIN);
    amount("DUMPNEW", a[0]) = 4 * COIN;

    BOOST_CHECK(c.DumpCacheToDatabase());

    CNewToken token;
    int nHeight;
    uint256 hash;
    BOOST_CHECK(!ptokensdb->ReadTokenData("DUMPGONE", token, nHeight, hash));
    BOOST_CHECK(!ptokensCache->Exists("DUMPGONE"));
    BOOST_CHECK_EQUAL(DbQuantity("DUMPGONE", a[0]), -1);
    BOOST_CHECK_EQUAL(DbQuantity("DUMPGONE!", a[0]), -1);
    BOOST_REQUIRE(ptokensdb->ReadTokenData("DUMPNEW", token, nHeight, hash));
    BOOST_CHECK_EQUAL(token.nAmount, 5 * COIN);
    BOOST_CHECK_EQUAL(nHeight, 2);
    BOOST_CHECK(ptokensCache->Exists("DUMPNEW"));
    // The new token's quantity, then the spend's
    BOOST_CHECK_EQUAL(DbQuantity("DUMPNEW", a[0]), 4 * COIN);
    BOOST_CHECK_EQUAL(DbQuantity("DUMPNEW!", a[0]), OWNER_TOKEN_AMOUNT);
    BOOST_CHECK_EQUAL(DbQuantity("DUMPZERO!", a[0]), -1);
    // Reissued metadata replaces the database entry, and the LRU copy is dropped
    BOOST_REQUIRE(ptokensdb->ReadTokenData("DUMPKEPT", token, nHeight, hash));
    BOOST_CHECK_EQUAL(token.nAmount, 22 * COIN);
    BOOST_CHECK_EQUAL((int)token.units, 2);
    BOOST_CHECK(!ptokensCache->Exists("DUMPKEPT"));
    BOOST_CHECK(!ptokensdb->ReadTokenData("DUMPNODATA", token, nHeight, hash));
    const std::vector<CAmount> want = {-1, 3 * COIN, COIN, 4 * COIN, COIN, 3 * COIN, COIN, -1, 6 * COIN, 7 * COIN, -1};
    for (size_t i = 1; i < a.size(); i++)
        BOOST_CHECK_MESSAGE(DbQuantity("DUMPKEPT", a[i]) == want[i - 1], "address " << i);
    BOOST_CHECK_EQUAL(DbQuantity("DUMPUNKNOWN", a[10]), -1);
    BOOST_CHECK_EQUAL(c.GetCacheSize(), 0U);
    BOOST_CHECK(c.mapTokensAddressAmount.empty() && c.mapReissuedTokenData.empty());
}

/* The estimate of the bytes a cache will write, per dirty entry */
BOOST_AUTO_TEST_CASE(cache_size_estimate)
{
    const std::string addr = TestTokenAddress(9);
    const CTokenTransfer transfer("SIZE", COIN);
    const CNewToken token("SIZE", COIN);
    const CReissueToken reissue("SIZE", COIN, -1, 1, "");
    CTokensCache cache;
    BOOST_CHECK_EQUAL(cache.GetCacheSize(), 0U);
    cache.vUndoTokenAmount.emplace_back("SIZE", addr, COIN);
    cache.vSpentTokens.emplace_back("SIZE", addr, COIN);
    cache.setNewTransferTokensToAdd.insert(CTokenCacheNewTransfer(transfer, addr, COutPoint(InsecureRand256(), 0)));
    cache.setNewTransferTokensToRemove.insert(CTokenCacheNewTransfer(transfer, addr, COutPoint(InsecureRand256(), 0)));
    cache.setNewOwnerTokensToAdd.insert(CTokenCacheNewOwner("SIZE!", addr));
    cache.setNewOwnerTokensToRemove.insert(CTokenCacheNewOwner("SIZE!", addr));
    cache.setNewTokensToAdd.insert(CTokenCacheNewToken(token, addr, 1, BLOCK_HASH));
    cache.setNewTokensToRemove.insert(CTokenCacheNewToken(token, addr, 1, BLOCK_HASH));
    cache.setNewReissueToAdd.insert(CTokenCacheReissueToken(reissue, addr, COutPoint(InsecureRand256(), 2), 1, BLOCK_HASH));
    cache.setNewReissueToRemove.insert(CTokenCacheReissueToken(reissue, addr, COutPoint(InsecureRand256(), 2), 1, BLOCK_HASH));
    // Undo and spent entries 80 bytes, transfers 112, owners 72, new tokens 152 + int, reissues 184 + int
    BOOST_CHECK_EQUAL(cache.GetCacheSize(), 2 * (80 + 112 + 72 + 152 + 184 + sizeof(int) + sizeof(int)));
}

/* AddCoins logs a failing token cache call and still adds the coins. A node
 * doesn't get there: the mempool and block checks refuse these transactions. */
BOOST_AUTO_TEST_CASE(add_coins_when_the_token_cache_refuses)
{
    ResetTokens(true);
    CTokensCache cache;
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
    const CTransaction issue = IssueTx(CNewToken("ADDCOINS", 100 * COIN, 0, 1, 0, ""));
    ConnectTokenTx(cache, issue, vUndo);
    ConnectTokenTx(cache, UniqueTx("ADDCOINS", {"TAG"}), vUndo, OwnerCoin(issue));
    const size_t nTokensToAdd = cache.setNewTokensToAdd.size();
    const std::vector<CTransaction> refused = {
        IssueTx(CNewToken("ADDCOINS", 7 * COIN, 0, 1, 0, "")),     // the name exists
        ReissueTx(CReissueToken("ADDCOINSNONE", COIN, -1, 1, "")), // the token doesn't exist
        UniqueTx("ADDCOINS", {"TAG"}),                             // the unique token exists
    };
    for (const CTransaction& tx : refused) {
        CCoinsView base;
        CCoinsViewCache view(&base);
        std::pair<std::string, CBlockTokenUndo> undo = std::make_pair("", CBlockTokenUndo());
        AddCoins(view, tx, BLOCK_HEIGHT, BLOCK_HASH, false, &cache, &undo);
        for (size_t i = 0; i < tx.vout.size(); i++)
            BOOST_CHECK(view.HaveCoin(COutPoint(tx.GetHash(), i)));
        BOOST_CHECK(undo.first.empty());
    }
    CheckMetaData(cache, CNewToken("ADDCOINS", 100 * COIN, 0, 1, 0, ""));
    CheckMetaData(cache, CNewToken("ADDCOINS#TAG", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""));
    BOOST_CHECK(!cache.ContainsToken("ADDCOINSNONE"));
    BOOST_CHECK_EQUAL(cache.setNewTokensToAdd.size(), nTokensToAdd);
    BOOST_CHECK(cache.setNewReissueToAdd.empty());
    BOOST_CHECK(cache.mapReissuedTokenData.empty());
}

/* Adapted from Ravencoin's cache_tests, with a small cache */
BOOST_AUTO_TEST_CASE(lru_cache_eviction)
{
    CLRUCache<std::string, CNewToken> cache(10);
    for (int i = 0; i < 10; i++) {
        CNewToken token("TEST" + std::to_string(i), CAmount(1));
        cache.Put(token.strName, token);
    }
    BOOST_CHECK_EQUAL(cache.Size(), 10U);
    BOOST_CHECK(cache.Exists("TEST0"));

    // Reading TEST0 makes TEST1 the least recently used entry
    BOOST_CHECK_EQUAL(cache.Get("TEST0").strName, "TEST0");
    cache.Put("NEW", CNewToken("NEW", CAmount(1)));
    BOOST_CHECK_EQUAL(cache.Size(), 10U);
    BOOST_CHECK(cache.Exists("NEW"));
    BOOST_CHECK(cache.Exists("TEST0"));
    BOOST_CHECK(!cache.Exists("TEST1"));

    cache.Erase("NEW");
    BOOST_CHECK(!cache.Exists("NEW"));
    cache.Clear();
    BOOST_CHECK_EQUAL(cache.Size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
