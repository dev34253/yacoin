// Copyright (c) 2017-2019 The Raven Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Consensus rules for token transactions: the structural checks in
// CheckTransaction (VerifyNewToken, VerifyReissueToken, VerifyNewUniqueToken,
// IsNewOwnerTxValid), the input/output balance in Consensus::CheckTxTokens,
// including the transfer overflow fixed in #112, and its contextual checks of
// token outputs, reissues and unique issues. Balance cases adapted from
// Ravencoin's asset_tx_tests.

#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "tokens/tokens.h"

#include "test/known_failure.h"
#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <limits>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(token_tx_tests, TokenTestingSetup)

static bool CheckTx(const CTransaction& tx, std::string& strReason)
{
    CValidationState state;
    bool fValid = CheckTransaction(tx, state);
    strReason = state.GetRejectReason();
    return fValid;
}

static bool CheckTx(const CMutableTransaction& mtx)
{
    std::string strReason;
    return CheckTx(CTransaction(mtx), strReason);
}

/** CheckTransaction rejects a failed VerifyNewToken without a reject reason; get it directly */
static std::string VerifyIssueError(const CMutableTransaction& mtx)
{
    std::string strError;
    CTransaction(mtx).VerifyNewToken(strError);
    return strError;
}

static bool Contains(const std::string& str, const std::string& part)
{
    return str.find(part) != std::string::npos;
}

BOOST_AUTO_TEST_CASE(issue_structure)
{
    std::string strReason;
    const CNewToken token("ABC", 1000 * COIN, 0, 1, 0, "");
    CTransaction issue = IssueTx(token);
    BOOST_CHECK(issue.IsNewToken());
    BOOST_CHECK(CheckTx(issue, strReason));
    std::string strError;
    BOOST_CHECK(issue.VerifyNewToken(strError));
    BOOST_CHECK(IsNewOwnerTxValid(issue, "ABC", TestTokenAddress(), strError));

    // No YAC lock, or one that is too small
    CMutableTransaction noLock(issue);
    noLock.vout[0] = CTxOut(noLock.vout[0].nValue, TestTokenScriptBase());
    BOOST_CHECK(CTransaction(noLock).IsNewToken());
    BOOST_CHECK(!CheckTx(noLock));
    BOOST_CHECK_EQUAL(VerifyIssueError(noLock), "bad-txns-issue-timelock-not-found");
    CMutableTransaction smallLock(issue);
    smallLock.vout[0].nValue -= 1;
    BOOST_CHECK(!CheckTx(smallLock));
    BOOST_CHECK_EQUAL(VerifyIssueError(smallLock), "bad-txns-issue-timelock-not-found");

    // The owner token must belong to the same token and address
    CMutableTransaction wrongOwner(issue);
    wrongOwner.vout[1].scriptPubKey = OwnerTokenScript(CNewToken("XYZ", COIN));
    BOOST_CHECK(!CheckTx(wrongOwner));
    BOOST_CHECK_EQUAL(VerifyIssueError(wrongOwner), "bad-txns-issue-owner-name-doesn't-match");
    CMutableTransaction ownerElsewhere(issue);
    ownerElsewhere.vout[1].scriptPubKey = OwnerTokenScript(token, 2);
    BOOST_CHECK(!CheckTx(CTransaction(ownerElsewhere), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-owner-address-mismatch");

    // Token outputs carry no YAC
    CMutableTransaction valued(issue);
    valued.vout[2].nValue = 1;
    BOOST_CHECK(!CheckTx(CTransaction(valued), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-token-issued-amount-isn't-zero");

    // Exactly one new token per issue
    CMutableTransaction twoIssues(issue);
    twoIssues.vout.insert(twoIssues.vout.begin(), CTxOut(0, NewTokenScript(CNewToken("XYZ", COIN))));
    BOOST_CHECK(!CheckTx(twoIssues));
    BOOST_CHECK_EQUAL(VerifyIssueError(twoIssues), "bad-txns-failed-issue-token-formatting-check");

    // Invalid token data
    BOOST_CHECK(!CheckTx(IssueTx(CNewToken("ABC", COIN, 7, 1, 0, "")), strReason));
    BOOST_CHECK(Contains(strReason, "units must be between 0-6"));
    BOOST_CHECK(!CheckTx(IssueTx(CNewToken("ABC", COIN + 1, 0, 1, 0, "")), strReason));
    BOOST_CHECK(Contains(strReason, "divisible by the smaller unit"));
}

BOOST_AUTO_TEST_CASE(sub_token_needs_parent_owner)
{
    CTransaction sub = IssueTx(CNewToken("ABC/SUB", COIN, 0, 1, 0, ""));
    BOOST_CHECK(!CheckTx(CMutableTransaction(sub)));
    BOOST_CHECK_EQUAL(VerifyIssueError(CMutableTransaction(sub)), "bad-txns-issue-new-token-missing-owner-token");

    CMutableTransaction withOwner(sub);
    withOwner.vout.insert(withOwner.vout.begin(), CTxOut(0, TransferTokenScript(CTokenTransfer("ABC!", OWNER_TOKEN_AMOUNT))));
    BOOST_CHECK(CheckTx(withOwner));

    // Another token's owner doesn't count
    CMutableTransaction otherOwner(sub);
    otherOwner.vout.insert(otherOwner.vout.begin(), CTxOut(0, TransferTokenScript(CTokenTransfer("XYZ!", OWNER_TOKEN_AMOUNT))));
    BOOST_CHECK(!CheckTx(otherOwner));
    BOOST_CHECK_EQUAL(VerifyIssueError(otherOwner), "bad-txns-issue-new-token-missing-owner-token");
}

BOOST_AUTO_TEST_CASE(reissue_structure)
{
    std::string strReason;
    CTransaction reissue = ReissueTx(CReissueToken("ABC", COIN, -1, 1, ""));
    BOOST_CHECK(reissue.IsReissueToken());
    BOOST_CHECK(CheckTx(reissue, strReason));

    CMutableTransaction noOwner(reissue);
    noOwner.vout[1].scriptPubKey = TransferTokenScript(CTokenTransfer("XYZ!", OWNER_TOKEN_AMOUNT));
    BOOST_CHECK(!CheckTx(CTransaction(noOwner), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-reissue-owner-outpoint-not-found");

    CMutableTransaction noLock(reissue);
    noLock.vout[0].nValue = COIN;
    BOOST_CHECK(!CheckTx(CTransaction(noLock), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-reissue-timelock-outpoint-not-found");

    CMutableTransaction twoReissues(reissue);
    twoReissues.vout.insert(twoReissues.vout.begin(), twoReissues.vout.back());
    BOOST_CHECK(!CheckTx(CTransaction(twoReissues), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-failed-reissue-token-formatting-check");

    // CheckReissueToken rejects amounts >= MAX_MONEY (its message says "must be 0 or larger")
    BOOST_CHECK(!CheckTx(ReissueTx(CReissueToken("ABC", MAX_MONEY, -1, 1, "")), strReason));
    BOOST_CHECK(Contains(strReason, "Unable to reissue token: amount"));
}

BOOST_AUTO_TEST_CASE(unique_structure)
{
    std::string strReason;
    CTransaction unique = UniqueTx("ABC", {"ONE", "TWO", "three"});
    BOOST_CHECK(unique.IsNewUniqueToken());
    BOOST_CHECK(!unique.IsNewToken());
    BOOST_CHECK(CheckTx(unique, strReason));

    CMutableTransaction duplicate(UniqueTx("ABC", {"ONE", "ONE"}));
    BOOST_CHECK(!CheckTx(CTransaction(duplicate), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-issue-unique-duplicate-name-in-same-tx");

    // The lock must cover every new token
    CMutableTransaction shortLock(unique);
    shortLock.vout[0] = TokenLockOutput(ETokenType::UNIQUE, 2);
    BOOST_CHECK(!CheckTx(CTransaction(shortLock), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-issue-unique-token-timelock-outpoints-not-found");

    CMutableTransaction noOwner(unique);
    noOwner.vout[1].scriptPubKey = TransferTokenScript(CTokenTransfer("XYZ!", OWNER_TOKEN_AMOUNT));
    BOOST_CHECK(!CheckTx(CTransaction(noOwner), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-issue-unique-token-missing-owner-token");

    // All unique tokens must share the parent
    CMutableTransaction mixed(unique);
    mixed.vout.back().scriptPubKey = NewTokenScript(CNewToken("XYZ#ONE", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""));
    BOOST_CHECK(!CheckTx(CTransaction(mixed), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-issue-unique-token-compare-failed");
}

/* The structural verifiers called on their own: the outputs they require and
 * the payloads they decode, each with its reason */
static std::string VerifyUniqueError(const CMutableTransaction& mtx)
{
    std::string strError;
    BOOST_CHECK(!CTransaction(mtx).VerifyNewUniqueToken(strError));
    return strError;
}

static std::string VerifyReissueError(const CMutableTransaction& mtx)
{
    std::string strError;
    BOOST_CHECK(!CTransaction(mtx).VerifyReissueToken(strError));
    return strError;
}

BOOST_AUTO_TEST_CASE(verify_new_token_outputs)
{
    const CNewToken token("ISSUED", 10 * COIN, 0, 1, 0, "");
    const CTransaction issue = IssueTx(token);
    std::string strError;
    BOOST_CHECK(issue.VerifyNewToken(strError));

    // At least the lock, the owner token and the new token
    CMutableTransaction twoOutputs(issue);
    twoOutputs.vout.erase(twoOutputs.vout.begin());
    BOOST_CHECK_EQUAL(VerifyIssueError(twoOutputs), "bad-txns-issue-vout-size-to-small");

    // The new token is the last output, the owner token the one before it
    CMutableTransaction issueNotLast(issue);
    issueNotLast.vout.push_back(CTxOut(COIN, TestTokenScriptBase()));
    BOOST_CHECK_EQUAL(VerifyIssueError(issueNotLast), "bad-txns-issue-data-not-found");
    CMutableTransaction ownerNotBeforeIssue(issue);
    std::swap(ownerNotBeforeIssue.vout[0], ownerNotBeforeIssue.vout[1]);
    BOOST_CHECK_EQUAL(VerifyIssueError(ownerNotBeforeIssue), "bad-txns-issue-owner-data-not-found");

    // Payloads that end early
    CMutableTransaction issueTruncated(issue);
    issueTruncated.vout[2].scriptPubKey = TruncatedIssueScript("ISSUED");
    BOOST_CHECK(CTransaction(issueTruncated).IsNewToken());
    BOOST_CHECK_EQUAL(VerifyIssueError(issueTruncated), "bad-txns-issue-serialzation-failed");
    CMutableTransaction ownerTruncated(issue);
    ownerTruncated.vout[1].scriptPubKey = TruncatedOwnerScript("ISSUED");
    BOOST_CHECK(CTransaction(ownerTruncated).IsNewToken());
    BOOST_CHECK_EQUAL(VerifyIssueError(ownerTruncated), "bad-txns-issue-owner-serialzation-failed");
}

BOOST_AUTO_TEST_CASE(verify_reissue_token_outputs)
{
    const CTransaction reissue = ReissueTx(CReissueToken("ABC", COIN, -1, 1, ""));

    // At least the lock, the owner token change and the reissue
    CMutableTransaction twoOutputs(reissue);
    twoOutputs.vout.erase(twoOutputs.vout.begin());
    BOOST_CHECK_EQUAL(VerifyReissueError(twoOutputs), "bad-txns-vout-size-to-small");

    // The reissue is the last output
    CMutableTransaction reissueNotLast(reissue);
    reissueNotLast.vout.push_back(CTxOut(COIN, TestTokenScriptBase()));
    BOOST_CHECK_EQUAL(VerifyReissueError(reissueNotLast), "bad-txns-reissue-data-not-found");

    // A reissue payload that ends early, also through CheckTransaction
    CMutableTransaction truncated(reissue);
    truncated.vout[2].scriptPubKey = TruncatedReissueScript("ABC");
    BOOST_CHECK(CTransaction(truncated).IsReissueToken());
    BOOST_CHECK_EQUAL(VerifyReissueError(truncated), "bad-txns-reissue-serialization-failed");
    CValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(truncated), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-reissue-serialization-failed");
    int nDoS = 0;
    BOOST_CHECK(state.IsInvalid(nDoS));
    BOOST_CHECK_EQUAL(nDoS, 100);
}

BOOST_AUTO_TEST_CASE(verify_unique_token_outputs)
{
    std::string strReason;
    const CTransaction unique = UniqueTx("ABC", {"ONE"});
    std::string strError;
    BOOST_CHECK(unique.VerifyNewUniqueToken(strError));

    // At least the lock, the owner token change and one unique token
    CMutableTransaction twoOutputs(unique);
    twoOutputs.vout.erase(twoOutputs.vout.begin());
    BOOST_CHECK_EQUAL(VerifyUniqueError(twoOutputs), "bad-txns-unique-vout-size-to-small");

    // No unique token output; one whose payload ends early isn't one
    CMutableTransaction noUnique(unique);
    noUnique.vout.back() = CTxOut(COIN, TestTokenScriptBase());
    BOOST_CHECK_EQUAL(VerifyUniqueError(noUnique), "bad-txns-issue-unique-token-bad-outpoint-count");
    CMutableTransaction truncatedUnique(unique);
    truncatedUnique.vout.back().scriptPubKey = TruncatedIssueScript("ABC#ONE");
    BOOST_CHECK(!IsScriptNewUniqueToken(truncatedUnique.vout.back().scriptPubKey));
    BOOST_CHECK_EQUAL(VerifyUniqueError(truncatedUnique), "bad-txns-issue-unique-token-bad-outpoint-count");

    // Only the unique tokens are created: no owner token, no reissue, and every
    // issue output is a unique token that decodes
    CMutableTransaction withOwner(unique);
    withOwner.vout.insert(withOwner.vout.end() - 1, CTxOut(0, OwnerTokenScript(CNewToken("XYZ", COIN))));
    BOOST_CHECK_EQUAL(VerifyUniqueError(withOwner), "bad-txns-failed-unique-token-formatting-check");
    BOOST_CHECK(!CheckTx(CTransaction(withOwner), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-failed-unique-token-formatting-check");
    CMutableTransaction withReissue(unique);
    withReissue.vout.insert(withReissue.vout.end() - 1, CTxOut(0, ReissueTokenScript(CReissueToken("ABC", COIN, -1, 1, ""))));
    BOOST_CHECK_EQUAL(VerifyUniqueError(withReissue), "bad-txns-failed-unique-token-formatting-check");
    CMutableTransaction withTruncatedIssue(unique);
    withTruncatedIssue.vout.insert(withTruncatedIssue.vout.end() - 1, CTxOut(0, TruncatedIssueScript("ABC#TWO")));
    BOOST_CHECK_EQUAL(VerifyUniqueError(withTruncatedIssue), "bad-txns-failed-unique-token-formatting-check");
}

BOOST_AUTO_TEST_CASE(new_owner_tx_valid)
{
    const CTransaction issue = IssueTx(CNewToken("OWNED", COIN));
    std::string strError;
    BOOST_CHECK(IsNewOwnerTxValid(issue, "OWNED", TestTokenAddress(), strError));

    // The owner output must decode, in an issue
    CMutableTransaction ownerTruncated(issue);
    ownerTruncated.vout[1].scriptPubKey = TruncatedOwnerScript("OWNED");
    BOOST_CHECK(!IsNewOwnerTxValid(CTransaction(ownerTruncated), "OWNED", TestTokenAddress(), strError));
    BOOST_CHECK_EQUAL(strError, "bad-txns-bad-owner");
    BOOST_CHECK(!IsNewOwnerTxValid(ReissueTx(CReissueToken("OWNED", COIN, -1, 1, "")), "OWNED", TestTokenAddress(), strError));
    BOOST_CHECK_EQUAL(strError, "bad-txns-bad-owner");

    // It goes to the issue's address
    BOOST_CHECK(!IsNewOwnerTxValid(issue, "OWNED", TestTokenAddress(2), strError));
    BOOST_CHECK_EQUAL(strError, "bad-txns-owner-address-mismatch");

    // Its name has at least 3 characters before the owner tag
    BOOST_CHECK(!IsNewOwnerTxValid(IssueTx(CNewToken("AB", COIN)), "AB", TestTokenAddress(), strError));
    BOOST_CHECK_EQUAL(strError, "bad-txns-owner-token-length");

    // It is the owner token of the issued token
    BOOST_CHECK(!IsNewOwnerTxValid(issue, "OTHER", TestTokenAddress(), strError));
    BOOST_CHECK_EQUAL(strError, "bad-txns-owner-name-mismatch");
}

BOOST_AUTO_TEST_CASE(issue_rejected_without_reason)
{
    CMutableTransaction noLock(IssueTx(CNewToken("NOLOCK", COIN)));
    noLock.vout[0] = CTxOut(noLock.vout[0].nValue, TestTokenScriptBase());
    BOOST_CHECK_EQUAL(VerifyIssueError(noLock), "bad-txns-issue-timelock-not-found");

    CValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(noLock), state));
    int nDoS = 0;
    BOOST_CHECK(state.IsInvalid(nDoS));
    BOOST_CHECK_EQUAL(nDoS, 100);
    // known defect, MG-046: the reason of the failed check is not passed on
    KNOWN_FAILURE_EQUAL("MG-046", state.GetRejectReason(), "bad-txns-issue-timelock-not-found", "");
}

BOOST_AUTO_TEST_CASE(transfer_outputs)
{
    std::string strReason;
    auto transferTx = [](const CTokenTransfer& transfer, CAmount nValue) {
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x06"), 0)));
        mtx.vout.push_back(CTxOut(nValue, TransferTokenScript(transfer)));
        return CTransaction(mtx);
    };
    BOOST_CHECK(CheckTx(transferTx(CTokenTransfer("ABC", 5), 0), strReason));
    BOOST_CHECK(CheckTx(transferTx(CTokenTransfer("ABC!", OWNER_TOKEN_AMOUNT), 0), strReason));

    BOOST_CHECK(!CheckTx(transferTx(CTokenTransfer("ABC", 5), 1), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-token-transfer-amount-isn't-zero");
    BOOST_CHECK(!CheckTx(transferTx(CTokenTransfer("ABC!", 2 * OWNER_TOKEN_AMOUNT), 0), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-owner-amount-was-not-1");
    BOOST_CHECK(!CheckTx(transferTx(CTokenTransfer("ABC#TAG", 2 * UNIQUE_TOKEN_AMOUNT), 0), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-unique-amount-was-not-1");
    BOOST_CHECK(!CheckTx(transferTx(CTokenTransfer("abc", 5), 0), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-name-invalid");

    // Coinbases can't carry tokens
    CMutableTransaction coinbase;
    coinbase.vin.push_back(CTxIn());
    coinbase.vin[0].scriptSig = CScript() << 1 << 2;
    coinbase.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 5))));
    BOOST_CHECK(!CheckTx(CTransaction(coinbase), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-coinbase-contains-token-txes");
}

/* Consensus::CheckTxTokens: token inputs must equal token outputs, per token */
struct TokenBalanceSetup {
    CCoinsView base;
    CCoinsViewCache view;
    CTokensCache cache;
    int nCoins = 0;

    TokenBalanceSetup() : view(&base)
    {
        // ABC allows 6 decimals, which makes the unit check a no-op (as in feature_token_overflow.py)
        BOOST_CHECK(cache.AddNewToken(CNewToken("ABC", 1000 * COIN, 6, 1, 0, ""), TestTokenAddress(), 1, uint256()));
        BOOST_CHECK(cache.AddNewToken(CNewToken("WHOLE", 1000 * COIN, 0, 1, 0, ""), TestTokenAddress(), 1, uint256()));
    }

    COutPoint AddCoin(const CScript& script, CAmount nValue = 0)
    {
        COutPoint out(uint256S("0xc0"), nCoins++);
        view.AddCoin(out, Coin(CTxOut(nValue, script), 1, false, false, 0), false);
        return out;
    }

    COutPoint AddTokenCoin(const std::string& name, CAmount nAmount)
    {
        return AddCoin(TransferTokenScript(CTokenTransfer(name, nAmount)));
    }

    bool Check(const std::vector<COutPoint>& inputs, const std::vector<CTokenTransfer>& outputs, std::string& strReason)
    {
        CMutableTransaction mtx;
        for (const COutPoint& in : inputs) mtx.vin.push_back(CTxIn(in));
        for (const CTokenTransfer& transfer : outputs) mtx.vout.push_back(CTxOut(0, TransferTokenScript(transfer, 2)));
        mtx.vout.push_back(CTxOut(COIN, TestTokenScriptBase()));
        CValidationState state;
        std::vector<std::pair<std::string, uint256> > vReissues;
        bool fValid = Consensus::CheckTxTokens(CTransaction(mtx), state, view, &cache, false, vReissues);
        strReason = state.GetRejectReason();
        return fValid;
    }

    /** CheckTxTokens of a whole tx; the reason, or "" if valid. A rejection has DoS 100 */
    std::string Reject(const CMutableTransaction& mtx)
    {
        CValidationState state;
        std::vector<std::pair<std::string, uint256> > vReissues;
        if (Consensus::CheckTxTokens(CTransaction(mtx), state, view, &cache, false, vReissues))
            return "";
        int nDoS = 0;
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, 100);
        return state.GetRejectReason();
    }

    /** A tx spending a YAC coin with these outputs */
    CMutableTransaction Spend(const std::vector<CScript>& scripts)
    {
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(AddCoin(TestTokenScriptBase(), COIN)));
        for (const CScript& script : scripts)
            mtx.vout.push_back(CTxOut(0, script));
        return mtx;
    }
};

BOOST_AUTO_TEST_CASE(token_balance)
{
    TokenBalanceSetup s;
    std::string strReason;
    COutPoint ten = s.AddTokenCoin("ABC", 10 * COIN);
    COutPoint yac = s.AddCoin(TestTokenScriptBase(), COIN);

    BOOST_CHECK(s.Check({ten}, {CTokenTransfer("ABC", 4 * COIN), CTokenTransfer("ABC", 6 * COIN)}, strReason));
    BOOST_CHECK(s.Check({yac}, {}, strReason));

    // Creating tokens
    BOOST_CHECK(!s.Check({ten}, {CTokenTransfer("ABC", 11 * COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason.substr(0, 30), "bad-tx-inputs-outputs-mismatch");
    BOOST_CHECK(!s.Check({yac}, {CTokenTransfer("ABC", COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason.substr(0, 30), "bad-tx-inputs-outputs-mismatch");
    // Burning some, or all
    BOOST_CHECK(!s.Check({ten}, {CTokenTransfer("ABC", 9 * COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason.substr(0, 30), "bad-tx-inputs-outputs-mismatch");
    BOOST_CHECK(!s.Check({ten}, {}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-tx-token-inputs-size-does-not-match-outputs-size");

    // Unknown token, wrong units, owner amount
    BOOST_CHECK(!s.Check({yac}, {CTokenTransfer("XYZ", COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-not-exist");
    COutPoint whole = s.AddTokenCoin("WHOLE", 10 * COIN);
    BOOST_CHECK(!s.Check({whole}, {CTokenTransfer("WHOLE", 10 * COIN - 1), CTokenTransfer("WHOLE", 1)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-amount-not-match-units");
    COutPoint owner = s.AddTokenCoin("ABC!", OWNER_TOKEN_AMOUNT);
    BOOST_CHECK(s.Check({owner}, {CTokenTransfer("ABC!", OWNER_TOKEN_AMOUNT)}, strReason));
    BOOST_CHECK(!s.Check({owner}, {CTokenTransfer("ABC!", 2 * OWNER_TOKEN_AMOUNT)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-owner-amount-was-not-1");

    // Two tokens in one tx are balanced separately
    BOOST_CHECK(s.Check({ten, whole}, {CTokenTransfer("WHOLE", 10 * COIN), CTokenTransfer("ABC", 10 * COIN)}, strReason));
    BOOST_CHECK(!s.Check({ten, whole}, {CTokenTransfer("WHOLE", 11 * COIN), CTokenTransfer("ABC", 9 * COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason.substr(0, 30), "bad-tx-inputs-outputs-mismatch");

    // Missing inputs (rejected without a DoS score or reject reason)
    BOOST_CHECK(!s.Check({COutPoint(uint256S("0xdead"), 0)}, {}, strReason));
}

/* Regression tests for the Token Transfer Quantity Overflow fixed in #112:
 * without range checks the signed sums of amounts wrap around, so outputs
 * worth ~9.2e12 tokens could be made from a 1-unit input. */
BOOST_AUTO_TEST_CASE(token_amount_overflow)
{
    TokenBalanceSetup s;
    std::string strReason;
    COutPoint one = s.AddTokenCoin("ABC", 1);
    const CAmount nMax = std::numeric_limits<int64_t>::max();

    // The original attack: INT64_MAX + INT64_MAX + 3 wraps to 1
    BOOST_CHECK(!s.Check({one}, {CTokenTransfer("ABC", nMax), CTokenTransfer("ABC", nMax), CTokenTransfer("ABC", 3)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-amount-toolarge");
    BOOST_CHECK(!s.Check({one}, {CTokenTransfer("ABC", MAX_MONEY + 1)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-amount-toolarge");

    // Each output within range, but their sum isn't
    COutPoint max = s.AddTokenCoin("ABC", MAX_MONEY);
    BOOST_CHECK(s.Check({max}, {CTokenTransfer("ABC", MAX_MONEY)}, strReason));
    BOOST_CHECK(!s.Check({max}, {CTokenTransfer("ABC", MAX_MONEY), CTokenTransfer("ABC", MAX_MONEY)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-totalOutputs-toolarge");

    // The same on the input side
    COutPoint max2 = s.AddTokenCoin("ABC", MAX_MONEY);
    BOOST_CHECK(!s.Check({max, max2}, {CTokenTransfer("ABC", MAX_MONEY)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-input-token-totalInputs-toolarge");
    COutPoint tooLarge = s.AddTokenCoin("ABC", MAX_MONEY + 1);
    BOOST_CHECK(!s.Check({tooLarge}, {CTokenTransfer("ABC", MAX_MONEY)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-input-token-amount-toolarge");
    COutPoint negative = s.AddTokenCoin("ABC", -1);
    BOOST_CHECK(!s.Check({negative}, {}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-input-token-amount-negative");

    // Zero and negative outputs are rejected by ContextualCheckTransferToken before the
    // sums, so CheckTxTokens' own "transfer-token-amount-negative" branch is unreachable
    BOOST_CHECK(!s.Check({one}, {CTokenTransfer("ABC", 2), CTokenTransfer("ABC", -1)}, strReason));
    BOOST_CHECK(Contains(strReason, "can't be equal to or less than zero"));
    BOOST_CHECK(!s.Check({one}, {CTokenTransfer("ABC", 1), CTokenTransfer("ABC", 0)}, strReason));
    BOOST_CHECK(Contains(strReason, "can't be equal to or less than zero"));
}

/* Only one reissue of a token may be pending at a time (mapReissuedTokens) */
BOOST_AUTO_TEST_CASE(reissue_chaining)
{
    TokenBalanceSetup s;
    CTransaction reissue = ReissueTx(CReissueToken("ABC", COIN, -1, 1, ""));
    CValidationState state;
    std::vector<std::pair<std::string, uint256> > vReissues;
    // The owner token input that the reissue spends
    CMutableTransaction mtx(reissue);
    mtx.vin[0] = CTxIn(s.AddTokenCoin("ABC!", OWNER_TOKEN_AMOUNT));
    CTransaction tx(mtx);
    BOOST_CHECK(Consensus::CheckTxTokens(tx, state, s.view, &s.cache, false, vReissues));
    BOOST_REQUIRE_EQUAL(vReissues.size(), 1U);
    BOOST_CHECK(vReissues[0].first == "ABC" && vReissues[0].second == tx.GetHash());

    // Another reissue of ABC while that one is recorded
    mapReissuedTokens["ABC"] = tx.GetHash();
    CMutableTransaction other(mtx);
    other.vout[2].scriptPubKey = ReissueTokenScript(CReissueToken("ABC", 2 * COIN, -1, 1, ""));
    vReissues.clear();
    BOOST_CHECK(!Consensus::CheckTxTokens(CTransaction(other), state, s.view, &s.cache, false, vReissues));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-tx-reissue-chaining-not-allowed");
    // The recorded tx itself still passes
    CValidationState state2;
    BOOST_CHECK(Consensus::CheckTxTokens(tx, state2, s.view, &s.cache, false, vReissues));
}

/* CheckTxTokens: every token output decodes, a transfer matches the token's
 * metadata, an issue, reissue or unique issue passes its contextual check, and
 * a tx of no such kind only transfers */
BOOST_AUTO_TEST_CASE(token_outputs_decode_and_match)
{
    TokenBalanceSetup s;

    // Transfer and reissue outputs that don't decode
    BOOST_CHECK_EQUAL(s.Reject(s.Spend({TruncatedTransferScript("ABC")})), "bad-tx-token-transfer-bad-deserialize");
    BOOST_CHECK_EQUAL(s.Reject(s.Spend({TruncatedReissueScript("ABC"), TestTokenScriptBase()})),
                      "bad-tx-token-reissue-bad-deserialize");

    // An issue whose new token doesn't decode
    CMutableTransaction issue = s.Spend({});
    issue.vout = IssueTx(CNewToken("ISSUED", COIN)).vout;
    issue.vout.back().scriptPubKey = TruncatedIssueScript("ISSUED");
    BOOST_CHECK(CTransaction(issue).IsNewToken());
    BOOST_CHECK_EQUAL(s.Reject(issue), "bad-txns-issue-serialzation-failed");

    // The metadata found for a transferred token must be that token's
    tokensCache->Put("CORRUPT", CDatabasedTokenData(CNewToken("OTHER", 10 * COIN, 6, 1, 0, ""), 1, uint256()));
    CMutableTransaction mismatch;
    mismatch.vin.push_back(CTxIn(s.AddTokenCoin("CORRUPT", COIN)));
    mismatch.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("CORRUPT", COIN), 2)));
    BOOST_CHECK_EQUAL(s.Reject(mismatch), "bad-txns-token-database-corrupted");

    // A reissue of a token that doesn't exist
    CMutableTransaction reissue(ReissueTx(CReissueToken("XYZ", COIN, -1, 1, "")));
    reissue.vin[0] = CTxIn(s.AddTokenCoin("XYZ!", OWNER_TOKEN_AMOUNT));
    BOOST_CHECK_EQUAL(s.Reject(reissue),
                      "bad-txns-reissue-contextual-Unable to reissue token: token_name 'XYZ' doesn't exist in the database");

    // A unique token whose name is taken
    BOOST_CHECK(s.cache.AddNewToken(CNewToken("ABC#ONE", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""), TestTokenAddress(), 1, uint256()));
    const COutPoint owner = s.AddTokenCoin("ABC!", OWNER_TOKEN_AMOUNT);
    CMutableTransaction taken(UniqueTx("ABC", {"ONE"}));
    taken.vin[0] = CTxIn(owner);
    BOOST_CHECK_EQUAL(s.Reject(taken),
                      "bad-txns-issue-unique-contextual-Invalid parameter: token_name 'ABC#ONE' has already been used");
    CMutableTransaction fresh(UniqueTx("ABC", {"TWO"}));
    fresh.vin[0] = CTxIn(owner);
    BOOST_CHECK_EQUAL(s.Reject(fresh), "");

    // Outside an issue or reissue, only transfers
    BOOST_CHECK_EQUAL(s.Reject(s.Spend({OwnerTokenScript(CNewToken("ABC", COIN)), TestTokenScriptBase()})),
                      "bad-txns-bad-token-transaction");
    CScript notToken = TestTokenScriptBase();
    notToken << OP_YAC_TOKEN << std::vector<unsigned char>{YAC_Y, YAC_A, YAC_C, 'x', 1, 2, 3, 4, 5, 6, 7, 8} << OP_DROP;
    BOOST_CHECK(!notToken.IsTokenScript());
    BOOST_CHECK_EQUAL(s.Reject(s.Spend({notToken})), "bad-txns-bad-token-script");
    BOOST_CHECK_EQUAL(s.Reject(s.Spend({TestTokenScriptBase()})), "");
}

/* ContextualCheckReissueToken against the reissued token's metadata */
BOOST_AUTO_TEST_CASE(contextual_check_reissue)
{
    TokenBalanceSetup s;
    BOOST_CHECK(s.cache.AddNewToken(CNewToken("FIXED", COIN, 0, 0, 0, ""), TestTokenAddress(), 1, uint256()));
    BOOST_CHECK(s.cache.AddNewToken(CNewToken("UNITS", 1000 * COIN, 3, 1, 0, ""), TestTokenAddress(), 1, uint256()));
    const CTransaction tx = ReissueTx(CReissueToken("UNITS", COIN, -1, 1, ""));
    std::string strNotEncodable;
    BOOST_CHECK(!CheckEncoded(std::string(34, 'x'), strNotEncodable));
    BOOST_CHECK_EQUAL(strNotEncodable, "Invalid parameter: ipfs_hash is not valid");

    auto check = [&](const CReissueToken& reissue, std::string& strError) {
        return ContextualCheckReissueToken(&s.cache, reissue, strError, tx);
    };
    std::string strError;
    BOOST_CHECK(check(CReissueToken("UNITS", COIN, -1, 1, ""), strError));
    BOOST_CHECK(check(CReissueToken("UNITS", MAX_MONEY - 1000 * COIN, 3, 0, TestIpfsHash()), strError));
    BOOST_CHECK(check(CReissueToken("UNITS", 0, 6, 1, ""), strError));

    // The tx must be a reissue
    BOOST_CHECK(!ContextualCheckReissueToken(&s.cache, CReissueToken("UNITS", COIN, -1, 1, ""), strError,
                                             IssueTx(CNewToken("UNITS", COIN))));
    BOOST_CHECK_EQUAL(strError, "bad-txns-reissue-token-contextual-check");

    BOOST_CHECK(!check(CReissueToken("UNITS", -1, -1, 1, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Unable to reissue token: amount must be 0 or larger");
    BOOST_CHECK(!check(CReissueToken("NOSUCH", COIN, -1, 1, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Unable to reissue token: token_name 'NOSUCH' doesn't exist in the database");
    BOOST_CHECK(!check(CReissueToken("FIXED", COIN, -1, 1, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Unable to reissue token: reissuable is set to false");
    // The total after the reissue is at most MAX_MONEY
    BOOST_CHECK(!check(CReissueToken("UNITS", MAX_MONEY - 1000 * COIN + 1000, -1, 1, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Unable to reissue token: token_name 'UNITS' the amount trying to reissue is to large");
    BOOST_CHECK(!check(CReissueToken("UNITS", 1, -1, 1, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Unable to reissue token: amount must be divisible by the smaller unit assigned to the token");
    BOOST_CHECK(!check(CReissueToken("UNITS", COIN, 2, 1, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Unable to reissue token: unit must be larger than current unit selection");
    BOOST_CHECK(!check(CReissueToken("UNITS", COIN, -1, 1, "short"), strError));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: ipfs_hash must be 34 bytes");
    BOOST_CHECK(!check(CReissueToken("UNITS", COIN, -1, 1, std::string(34, 'x')), strError));
    BOOST_CHECK_EQUAL(strError, strNotEncodable);

    // Without the tx; without a cache only the token's own data is checked
    BOOST_CHECK(ContextualCheckReissueToken(&s.cache, CReissueToken("UNITS", COIN, -1, 1, ""), strError));
    BOOST_CHECK(ContextualCheckReissueToken(nullptr, CReissueToken("NOSUCH", COIN, -1, 1, TestIpfsHash()), strError));
    BOOST_CHECK(!ContextualCheckReissueToken(nullptr, CReissueToken("NOSUCH", COIN, 7, 1, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Unable to reissue token: unit must be between 6 and -1");
    BOOST_CHECK(!ContextualCheckReissueToken(nullptr, CReissueToken("NOSUCH", COIN, -1, 1, "short"), strError));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: ipfs_hash must be 34 bytes");
    BOOST_CHECK(!ContextualCheckReissueToken(nullptr, CReissueToken("NOSUCH", COIN, -1, 1, std::string(34, 'x')), strError));
    BOOST_CHECK_EQUAL(strError, strNotEncodable);
}

BOOST_AUTO_TEST_CASE(contextual_check_unique_tx)
{
    TokenBalanceSetup s;
    BOOST_CHECK(s.cache.AddNewToken(CNewToken("ABC#ONE", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""), TestTokenAddress(), 1, uint256()));
    std::string strError;
    BOOST_CHECK(ContextualCheckUniqueTokenTx(&s.cache, strError, UniqueTx("ABC", {"TWO", "THREE"})));
    BOOST_CHECK(!ContextualCheckUniqueTokenTx(&s.cache, strError, UniqueTx("ABC", {"TWO", "ONE"})));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: token_name 'ABC#ONE' has already been used");
}

BOOST_AUTO_TEST_SUITE_END()
