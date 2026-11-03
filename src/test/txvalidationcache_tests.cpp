// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/validation.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "pubkey.h"
#include "txmempool.h"
#include "random.h"
#include "script/standard.h"
#include "script/sign.h"
#include "test/test_bitcoin.h"
#include "utiltime.h"
#include "core_io.h"
#include "keystore.h"
#include "policy/policy.h"
#include "script/sigcache.h"

#include <boost/test/unit_test.hpp>

bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, std::vector<CScriptCheck> *pvChecks);

BOOST_AUTO_TEST_SUITE(tx_validationcache_tests)

static bool
ToMemPool(CTransaction& tx)
{
    LOCK(cs_main);

    CValidationState state;
    return AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), nullptr);
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, TestChain100Setup)
{
    // Make sure skipping validation of transctions that were
    // validated going into the memory pool does not allow
    // double-spends in blocks to pass validation when they should not.

    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Create a double-spend of mature coinbase txn:
    std::vector<CTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++)
    {
        spends[i].nVersion = 2;
        spends[i].vin.resize(1);
        spends[i].vin[0].prevout.hash = coinbaseTxns[0].GetHash();
        spends[i].vin[0].prevout.n = 0;
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = 11*CENT;
        spends[i].vout[0].scriptPubKey = scriptPubKey;

        // Sign:
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(scriptPubKey, spends[i], 0, SIGHASH_ALL);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends[i].vin[0].scriptSig << vchSig;
    }

    CBlock block;

    // Test 1: block with both of those transactions should be rejected.
    block = CreateAndProcessBlock(spends, scriptPubKey);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());
    mempool.clear();

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());
    mempool.clear();

    // Final sanity test: first spend in mempool, second in block, that's OK:
    std::vector<CTransaction> oneSpend;
    oneSpend.push_back(spends[0]);
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(oneSpend, scriptPubKey);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
    // spends[1] should have been removed from the mempool when the
    // block with spends[0] is accepted:
    BOOST_CHECK_EQUAL(mempool.size(), 0);
}

// Run CheckInputs (using pcoinsTip) on the given transaction, for all script
// flags.  Test that CheckInputs passes for all flags that don't overlap with
// the failing_flags argument, but otherwise fails.
// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY (and future NOP codes that may
// get reassigned) have an interaction with DISCOURAGE_UPGRADABLE_NOPS: if
// the script flags used contain DISCOURAGE_UPGRADABLE_NOPS but don't contain
// CHECKLOCKTIMEVERIFY (or CHECKSEQUENCEVERIFY), but the script does contain
// OP_CHECKLOCKTIMEVERIFY (or OP_CHECKSEQUENCEVERIFY), then script execution
// should fail.
// Capture this interaction with the upgraded_nop argument: set it when evaluating
// any script flag that is implemented as an upgraded NOP code.
void ValidateCheckInputsForAllFlags(CTransaction &tx, uint32_t failing_flags, bool add_to_cache, bool upgraded_nop)
{
    // If we add many more flags, this loop can get too expensive, but we can
    // rewrite in the future to randomly pick a set of flags to evaluate.
    for (uint32_t test_flags=0; test_flags < (1U << 16); test_flags += 1) {
        CValidationState state;
        // Filter out incompatible flag choices
        if ((test_flags & SCRIPT_VERIFY_CLEANSTACK)) {
            // CLEANSTACK requires P2SH and WITNESS, see VerifyScript() in
            // script/interpreter.cpp
            test_flags |= SCRIPT_VERIFY_P2SH;
        }
        bool ret = CheckInputs(tx, state, pcoinsTip, true, test_flags, true, add_to_cache, nullptr);
        // CheckInputs should succeed iff test_flags doesn't intersect with
        // failing_flags
        bool expected_return_value = !(test_flags & failing_flags);
        if (expected_return_value && upgraded_nop) {
            // If the script flag being tested corresponds to an upgraded NOP,
            // then script execution should fail if DISCOURAGE_UPGRADABLE_NOPS
            // is set.
            expected_return_value = !(test_flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS);
        }
        BOOST_CHECK_EQUAL(ret, expected_return_value);

        // Test the caching
        if (ret && add_to_cache) {
            // Check that we get a cache hit if the tx was valid
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputs(tx, state, pcoinsTip, true, test_flags, true, add_to_cache, &scriptchecks));
            BOOST_CHECK(scriptchecks.empty());
        } else {
            // Check that we get script executions to check, if the transaction
            // was invalid, or we didn't add to cache.
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputs(tx, state, pcoinsTip, true, test_flags, true, add_to_cache, &scriptchecks));
            BOOST_CHECK_EQUAL(scriptchecks.size(), tx.vin.size());
        }
    }
}

BOOST_FIXTURE_TEST_CASE(checkinputs_test, TestChain100Setup)
{
    // Test that passing CheckInputs with one set of script flags doesn't imply
    // that we would pass again with a different set of flags.
    InitScriptExecutionCache();

    CScript p2pk_scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CScript p2sh_scriptPubKey = GetScriptForDestination(CScriptID(p2pk_scriptPubKey));
    CScript p2pkh_scriptPubKey = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());

    CBasicKeyStore keystore;
    keystore.AddKey(coinbaseKey);
    keystore.AddCScript(p2pk_scriptPubKey);

    // flags to test: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCE_VERIFY, SCRIPT_VERIFY_NULLDUMMY, uncompressed pubkey thing

    // Create 2 outputs that match the three scripts above, spending the first
    // coinbase tx.
    CTransaction spend_tx;

    spend_tx.nVersion = 2;
    spend_tx.vin.resize(1);
    spend_tx.vin[0].prevout.hash = coinbaseTxns[0].GetHash();
    spend_tx.vin[0].prevout.n = 0;
    spend_tx.vout.resize(3);
    spend_tx.vout[0].nValue = 11*CENT;
    spend_tx.vout[0].scriptPubKey = p2sh_scriptPubKey;
    spend_tx.vout[1].nValue = 11*CENT;
    spend_tx.vout[1].scriptPubKey = CScript() << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    spend_tx.vout[2].nValue = 11*CENT;
    spend_tx.vout[2].scriptPubKey = CScript() << OP_CHECKSEQUENCEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Sign, with a non-DER signature
    {
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(p2pk_scriptPubKey, spend_tx, 0, SIGHASH_ALL);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spend_tx.vin[0].scriptSig << vchSig;
    }

    LOCK(cs_main);

    {
        // And if we produce a block with this tx, it should be valid (DERSIG not
        // enabled yet), even though there's no cache entry.
        CBlock block;
        block = CreateAndProcessBlock({spend_tx}, p2pk_scriptPubKey);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
        BOOST_CHECK(pcoinsTip->GetBestBlock() == block.GetHash());
    }

    // Test P2SH: construct a transaction that is valid without P2SH, and
    // then test validity with P2SH.
    {
        CTransaction invalid_under_p2sh_tx;
        invalid_under_p2sh_tx.nVersion = 2;
        invalid_under_p2sh_tx.vin.resize(1);
        invalid_under_p2sh_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_under_p2sh_tx.vin[0].prevout.n = 0;
        invalid_under_p2sh_tx.vout.resize(1);
        invalid_under_p2sh_tx.vout[0].nValue = 11*CENT;
        invalid_under_p2sh_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;
        std::vector<unsigned char> vchSig2(p2pk_scriptPubKey.begin(), p2pk_scriptPubKey.end());
        invalid_under_p2sh_tx.vin[0].scriptSig << vchSig2;

        ValidateCheckInputsForAllFlags(invalid_under_p2sh_tx, SCRIPT_VERIFY_P2SH, true, false);
    }

    // Test CHECKLOCKTIMEVERIFY
    {
        CTransaction invalid_with_cltv_tx;
        invalid_with_cltv_tx.nVersion = 2;
        invalid_with_cltv_tx.nLockTime = 100;
        invalid_with_cltv_tx.vin.resize(1);
        invalid_with_cltv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_cltv_tx.vin[0].prevout.n = 1;
        invalid_with_cltv_tx.vin[0].nSequence = 0;
        invalid_with_cltv_tx.vout.resize(1);
        invalid_with_cltv_tx.vout[0].nValue = 11*CENT;
        invalid_with_cltv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[1].scriptPubKey, invalid_with_cltv_tx, 0, SIGHASH_ALL);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 101;
        CValidationState state;
        BOOST_CHECK(!CheckInputs(invalid_with_cltv_tx, state, pcoinsTip, true, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, true, nullptr));

        // Make it valid, and check again
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        BOOST_CHECK(CheckInputs(invalid_with_cltv_tx, state, pcoinsTip, true, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, true, nullptr));
    }

    // TEST CHECKSEQUENCEVERIFY
    {
        CTransaction invalid_with_csv_tx;
        invalid_with_csv_tx.nVersion = 2;
        invalid_with_csv_tx.vin.resize(1);
        invalid_with_csv_tx.vin[0].prevout.hash = spend_tx.GetHash();
        invalid_with_csv_tx.vin[0].prevout.n = 2;
        invalid_with_csv_tx.vin[0].nSequence = 100;
        invalid_with_csv_tx.vout.resize(1);
        invalid_with_csv_tx.vout[0].nValue = 11*CENT;
        invalid_with_csv_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[2].scriptPubKey, invalid_with_csv_tx, 0, SIGHASH_ALL);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 101;
        CValidationState state;
        BOOST_CHECK(!CheckInputs(invalid_with_csv_tx, state, pcoinsTip, true, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, true, nullptr));

        // Make it valid, and check again
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        BOOST_CHECK(CheckInputs(invalid_with_csv_tx, state, pcoinsTip, true, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, true, nullptr));
    }

    {
        // Test a transaction with multiple inputs.
        CTransaction tx;

        tx.nVersion = 2;
        tx.vin.resize(2);
        tx.vin[0].prevout.hash = spend_tx.GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vin[1].prevout.hash = spend_tx.GetHash();
        tx.vin[1].prevout.n = 1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 22*CENT;
        tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        // Sign
        for (int i=0; i<2; ++i) {
            SignatureData sigdata;
            ProduceSignature(TransactionSignatureCreator(&keystore, &tx, i, SIGHASH_ALL), spend_tx.vout[i].scriptPubKey, sigdata);
            UpdateTransaction(tx, i, sigdata);
        }

        CValidationState state;
        // This transaction is now invalid under segwit, because of the second input.
        BOOST_CHECK(!CheckInputs(tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH, true, true, nullptr));

        std::vector<CScriptCheck> scriptchecks;
        // Make sure this transaction was not cached (ie because the first
        // input was valid)
        BOOST_CHECK(CheckInputs(tx, state, pcoinsTip, true, SCRIPT_VERIFY_P2SH, true, true, &scriptchecks));
        // Should get 2 script checks back -- caching is on a whole-transaction basis.
        BOOST_CHECK_EQUAL(scriptchecks.size(), 2);
    }
}

namespace {

/** Coins paying to scripts of one key, each from its own random funding
 *  outpoint, and spends of them. Random outpoints keep the cases independent
 *  of each other and of their order, since the caches are shared by the
 *  whole test binary. */
struct ScriptCheckSetup : public BasicTestingSetup {
    CCoinsView base;
    CCoinsViewCache view{&base};
    CKey key;
    CScript p2pk;

    ScriptCheckSetup()
    {
        key.MakeNewKey(true);
        p2pk = CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
    }

    COutPoint AddCoin(const CScript& scriptPubKey)
    {
        COutPoint outpoint(GetRandHash(), 0);
        view.AddCoin(outpoint, Coin(CTxOut(COIN, scriptPubKey), 1, false, false, 0), false);
        return outpoint;
    }

    /** A transaction spending prevout, without a scriptSig yet. */
    static CTransaction Spend(const COutPoint& prevout)
    {
        CTransaction tx;
        tx.nVersion = 2;
        tx.vin.resize(1);
        tx.vin[0].prevout = prevout;
        tx.vout.resize(1);
        tx.vout[0].nValue = COIN - CENT;
        tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        return tx;
    }

    /** A DER signature by key over hash, without the hash type byte. */
    std::vector<unsigned char> Sign(const uint256& hash) const
    {
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(key.Sign(hash, vchSig));
        return vchSig;
    }

    /** A spend of a new P2PK coin; with fValid false the signature is over
     *  another hash. */
    CTransaction P2PKSpend(bool fValid)
    {
        CTransaction tx = Spend(AddCoin(p2pk));
        uint256 hash = SignatureHash(p2pk, tx, 0, SIGHASH_ALL);
        if (!fValid) {
            hash = uint256S("01");
        }
        std::vector<unsigned char> vchSig = Sign(hash);
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[0].scriptSig = CScript() << vchSig;
        return tx;
    }

    /** CheckInputs on view with script checks on and the signature cache stored. */
    bool Check(const CTransaction& tx, CValidationState& state, unsigned int flags, bool cacheFullScriptStore,
               std::vector<CScriptCheck>* pvChecks)
    {
        return CheckInputs(tx, state, view, true, flags, true, cacheFullScriptStore, pvChecks);
    }
};

const std::string EVAL_FALSE = "Script evaluated without error but finished with a false/empty top stack element";

void CheckRejected(bool fResult, const CValidationState& state, int nDoSExpected, unsigned int nCode, const std::string& strReason)
{
    BOOST_CHECK(!fResult);
    int nDoS = -1;
    BOOST_CHECK(state.IsInvalid(nDoS));
    BOOST_CHECK_EQUAL(nDoS, nDoSExpected);
    BOOST_CHECK_EQUAL(state.GetRejectCode(), nCode);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), strReason);
}

} // namespace

BOOST_FIXTURE_TEST_CASE(checkinputs_without_script_checks, ScriptCheckSetup)
{
    LOCK(cs_main);

    // A coinbase has no inputs to check: true, nothing pushed, nothing looked up.
    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << OP_1 << OP_1;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = COIN;
    coinbase.vout[0].scriptPubKey = p2pk;
    BOOST_REQUIRE(coinbase.IsCoinBase());
    std::vector<CScriptCheck> checks;
    CValidationState state;
    BOOST_CHECK(Check(coinbase, state, STANDARD_SCRIPT_VERIFY_FLAGS, true, &checks));
    BOOST_CHECK(checks.empty());
    BOOST_CHECK(state.IsValid());

    // With fScriptChecks false the scripts are not run: a bad signature passes.
    const CTransaction bad = P2PKSpend(false);
    BOOST_CHECK(!Check(bad, state, STANDARD_SCRIPT_VERIFY_FLAGS, false, nullptr));
    CValidationState state2;
    BOOST_CHECK(CheckInputs(bad, state2, view, false, STANDARD_SCRIPT_VERIFY_FLAGS, true, true, &checks));
    BOOST_CHECK(checks.empty());
    BOOST_CHECK(CheckInputs(bad, state2, view, false, STANDARD_SCRIPT_VERIFY_FLAGS, true, true, nullptr));
    BOOST_CHECK(state2.IsValid());
}

BOOST_FIXTURE_TEST_CASE(checkinputs_execution_cache_store, ScriptCheckSetup)
{
    LOCK(cs_main);
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    const CTransaction tx = P2PKSpend(true);
    CValidationState state;
    std::vector<CScriptCheck> checks;

    // Valid, but cacheFullScriptStore false: not stored, so a later call
    // returns the input's script check again.
    BOOST_CHECK(Check(tx, state, flags, false, nullptr));
    BOOST_CHECK(Check(tx, state, flags, true, &checks));
    BOOST_CHECK_EQUAL(checks.size(), 1U);

    // With pvChecks the scripts are not run, so nothing is stored either.
    checks.clear();
    BOOST_CHECK(Check(tx, state, flags, true, &checks));
    BOOST_CHECK_EQUAL(checks.size(), 1U);

    // The returned check, run by hand, passes.
    BOOST_CHECK(checks[0]());
    BOOST_CHECK_EQUAL(checks[0].GetScriptError(), SCRIPT_ERR_OK);

    // Run inline with cacheFullScriptStore true: stored, and the next call
    // with the same flags is a cache hit that returns no checks.
    BOOST_CHECK(Check(tx, state, flags, true, nullptr));
    checks.clear();
    BOOST_CHECK(Check(tx, state, flags, true, &checks));
    BOOST_CHECK(checks.empty());

    // The entry is per flags: other flags miss.
    BOOST_CHECK(Check(tx, state, SCRIPT_VERIFY_P2SH, true, &checks));
    BOOST_CHECK_EQUAL(checks.size(), 1U);

    // A lookup with cacheFullScriptStore false is a hit too. It only marks
    // the entry as one the cache may overwrite, so while the cache has room
    // the entry is still found.
    checks.clear();
    BOOST_CHECK(Check(tx, state, flags, false, &checks));
    BOOST_CHECK(checks.empty());
    BOOST_CHECK(Check(tx, state, flags, true, &checks));
    BOOST_CHECK(checks.empty());
    BOOST_CHECK(state.IsValid());

    // A transaction with two inputs gives one check per input.
    CTransaction two = Spend(AddCoin(CScript() << OP_TRUE));
    two.vin.emplace_back(AddCoin(CScript() << OP_TRUE));
    checks.clear();
    BOOST_CHECK(Check(two, state, flags, true, &checks));
    BOOST_CHECK_EQUAL(checks.size(), 2U);
    BOOST_CHECK(checks[0]() && checks[1]());
}

BOOST_FIXTURE_TEST_CASE(checkinputs_reject_reasons, ScriptCheckSetup)
{
    LOCK(cs_main);

    // A script that fails only under the standard-but-not-mandatory CLTV
    // flag: without the flag OP_CHECKLOCKTIMEVERIFY is a NOP.
    BOOST_REQUIRE(STANDARD_NOT_MANDATORY_VERIFY_FLAGS & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY);
    CTransaction cltv = Spend(AddCoin(CScript() << 100 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_TRUE));
    cltv.nLockTime = 0;
    cltv.vin[0].nSequence = 0;
    {
        CValidationState state;
        bool fResult = Check(cltv, state, STANDARD_SCRIPT_VERIFY_FLAGS, true, nullptr);
        CheckRejected(fResult, state, 0, REJECT_NONSTANDARD,
                      "non-mandatory-script-verify-flag (Locktime requirement not satisfied)");
        CValidationState state2;
        BOOST_CHECK(Check(cltv, state2, MANDATORY_SCRIPT_VERIFY_FLAGS, true, nullptr));
    }

    // A bad signature fails the mandatory flags too: DoS 100, with the
    // standard flags set and with no flags at all.
    const CTransaction bad = P2PKSpend(false);
    for (unsigned int flags : {STANDARD_SCRIPT_VERIFY_FLAGS, (unsigned int)SCRIPT_VERIFY_NONE}) {
        CValidationState state;
        bool fResult = Check(bad, state, flags, true, nullptr);
        CheckRejected(fResult, state, 100, REJECT_INVALID, "mandatory-script-verify-flag-failed (" + EVAL_FALSE + ")");
    }

    // With pvChecks the failure shows only when the check runs.
    std::vector<CScriptCheck> checks;
    CValidationState state;
    BOOST_CHECK(Check(bad, state, STANDARD_SCRIPT_VERIFY_FLAGS, true, &checks));
    BOOST_REQUIRE_EQUAL(checks.size(), 1U);
    BOOST_CHECK(!checks[0]());
    BOOST_CHECK_EQUAL(checks[0].GetScriptError(), SCRIPT_ERR_EVAL_FALSE);
    BOOST_CHECK(state.IsValid());
}

BOOST_FIXTURE_TEST_CASE(signature_cache, ScriptCheckSetup)
{
    const CTransaction tx = P2PKSpend(true);
    const uint256 sighash = SignatureHash(p2pk, tx, 0, SIGHASH_ALL);
    const std::vector<unsigned char> vchSig = Sign(sighash);
    const std::vector<unsigned char> vchOther = Sign(uint256S("02"));
    const CPubKey pubkey = key.GetPubKey();

    for (bool store : {false, true}) {
        CachingTransactionSignatureChecker checker(&tx, 0, store);
        BOOST_CHECK(checker.VerifySignature(vchSig, pubkey, sighash));
        BOOST_CHECK(checker.VerifySignature(vchSig, pubkey, sighash));
        // An invalid signature is never stored: it fails every time.
        BOOST_CHECK(!checker.VerifySignature(vchOther, pubkey, sighash));
        BOOST_CHECK(!checker.VerifySignature(vchOther, pubkey, sighash));
    }
    // After a stored check, a lookup without storing still verifies.
    BOOST_CHECK(CachingTransactionSignatureChecker(&tx, 0, false).VerifySignature(vchSig, pubkey, sighash));
    BOOST_CHECK(!CachingTransactionSignatureChecker(&tx, 0, true).VerifySignature(vchSig, CPubKey(), sighash));
}

BOOST_FIXTURE_TEST_CASE(cache_sizes_zero, ScriptCheckSetup)
{
    LOCK(cs_main);
    BOOST_CHECK(!gArgs.IsArgSet("-maxsigcachesize"));
    {
        // -maxsigcachesize=0 gives the smallest caches, which still work.
        // Re-initialising sets the size only: it does not empty a cache,
        // the table keeps the entries that fit.
        ArgGuard size("-maxsigcachesize", "0");
        InitSignatureCache();
        InitScriptExecutionCache();

        const CTransaction tx = P2PKSpend(true);
        const uint256 sighash = SignatureHash(p2pk, tx, 0, SIGHASH_ALL);
        const std::vector<unsigned char> vchSig = Sign(sighash);
        BOOST_CHECK(CachingTransactionSignatureChecker(&tx, 0, true).VerifySignature(vchSig, key.GetPubKey(), sighash));
        BOOST_CHECK(CachingTransactionSignatureChecker(&tx, 0, false).VerifySignature(vchSig, key.GetPubKey(), sighash));

        CValidationState state;
        std::vector<CScriptCheck> checks;
        BOOST_CHECK(Check(tx, state, STANDARD_SCRIPT_VERIFY_FLAGS, true, nullptr));
        BOOST_CHECK(Check(tx, state, STANDARD_SCRIPT_VERIFY_FLAGS, true, &checks));
        BOOST_CHECK(checks.empty());
    }
    // Back to the default sizes for the cases that follow. As above, this
    // sets the size and does not empty the caches.
    BOOST_CHECK(!gArgs.IsArgSet("-maxsigcachesize"));
    InitSignatureCache();
    InitScriptExecutionCache();
    const CTransaction tx = P2PKSpend(true);
    CValidationState state;
    std::vector<CScriptCheck> checks;
    BOOST_CHECK(Check(tx, state, STANDARD_SCRIPT_VERIFY_FLAGS, true, nullptr));
    BOOST_CHECK(Check(tx, state, STANDARD_SCRIPT_VERIFY_FLAGS, true, &checks));
    BOOST_CHECK(checks.empty());
}

BOOST_AUTO_TEST_SUITE_END()
