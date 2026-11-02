// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY in the wallet's P2PKH lock
// scripts, with lock heights, times and durations of the sizes in use.

#include "key.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace {

/** A key and the outputs of GetScriptFor{Cltv,Csv}P2PKH that pay to it */
struct LockSpender {
    CKey key;

    LockSpender() { key.MakeNewKey(true); }

    CScript Cltv(uint32_t nLockTime) const { return GetScriptForCltvP2PKH(nLockTime, key.GetPubKey().GetID()); }
    CScript Csv(uint32_t nSequence) const { return GetScriptForCsvP2PKH(nSequence, key.GetPubKey().GetID()); }

    /** Spends an output with scriptPubKey from a transaction with the given
     *  nLockTime and input nSequence, signed with the key; returns the
     *  script error of the spend */
    ScriptError Spend(const CScript& scriptPubKey, uint32_t nLockTime, uint32_t nSequence,
                      unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS) const
    {
        CMutableTransaction credit;
        credit.vin.push_back(CTxIn(COutPoint(uint256S("0x01"), 0)));
        credit.vout.push_back(CTxOut(COIN, scriptPubKey));

        CMutableTransaction spend;
        spend.nLockTime = nLockTime;
        spend.vin.push_back(CTxIn(COutPoint(credit.GetHash(), 0), CScript(), nSequence));
        spend.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));

        const uint256 hash = SignatureHash(scriptPubKey, spend, 0, SIGHASH_ALL);
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(key.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spend.vin[0].scriptSig = CScript() << vchSig << ToByteVector(key.GetPubKey());

        ScriptError err;
        const bool fOk = VerifyScript(spend.vin[0].scriptSig, scriptPubKey, flags,
                                      MutableTransactionSignatureChecker(&spend, 0), &err);
        BOOST_CHECK_EQUAL(fOk, err == SCRIPT_ERR_OK);
        return err;
    }
};

// Heights of today's mainnet and real block times, all far from LOCKTIME_THRESHOLD
const uint32_t LOCK_HEIGHTS[] = {1950000, 2000000};
const uint32_t LOCK_TIMES[] = {1500000000, 1680000000};

/** nSequence of an input that is not final and has no relative lock */
const uint32_t NOT_FINAL = CTxIn::SEQUENCE_FINAL - 1;

/** CSV operand and input nSequence for a relative lock of nSeconds */
uint32_t CsvSeconds(uint32_t nSeconds)
{
    return CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (nSeconds >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(timelock_tests, BasicTestingSetup)

/* An absolute lock is met from its own height or time on, in an input that is not final */
BOOST_AUTO_TEST_CASE(cltv_p2pkh_heights_and_times)
{
    const LockSpender spender;
    std::vector<uint32_t> locks(std::begin(LOCK_HEIGHTS), std::end(LOCK_HEIGHTS));
    locks.insert(locks.end(), std::begin(LOCK_TIMES), std::end(LOCK_TIMES));
    for (uint32_t nLock : locks) {
        BOOST_TEST_MESSAGE("lock " << nLock);
        const CScript script = spender.Cltv(nLock);
        BOOST_CHECK_EQUAL(spender.Spend(script, nLock, NOT_FINAL), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spender.Spend(script, nLock + 1, NOT_FINAL), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spender.Spend(script, nLock + 21000, 0), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spender.Spend(script, nLock - 1, NOT_FINAL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, NOT_FINAL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        // A final input disables the transaction's nLockTime, so it can't meet the lock
        BOOST_CHECK_EQUAL(spender.Spend(script, nLock, CTxIn::SEQUENCE_FINAL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        // Without the CLTV flag the opcode is a NOP
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, CTxIn::SEQUENCE_FINAL,
                                        STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY),
                          SCRIPT_ERR_OK);
    }
}

/* A height lock is never met by a time in nLockTime, nor a time lock by a height */
BOOST_AUTO_TEST_CASE(cltv_p2pkh_height_and_time_dont_mix)
{
    const LockSpender spender;
    for (uint32_t nHeight : LOCK_HEIGHTS) {
        for (uint32_t nTime : LOCK_TIMES) {
            BOOST_CHECK_EQUAL(spender.Spend(spender.Cltv(nHeight), nTime, NOT_FINAL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
            BOOST_CHECK_EQUAL(spender.Spend(spender.Cltv(nTime), nHeight, NOT_FINAL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        }
    }
}

/* A relative lock in blocks is met by an input nSequence of at least that many blocks */
BOOST_AUTO_TEST_CASE(csv_p2pkh_blocks)
{
    const LockSpender spender;
    for (uint32_t nBlocks : {10U, 100U, 21000U}) {
        BOOST_TEST_MESSAGE("blocks " << nBlocks);
        const CScript script = spender.Csv(nBlocks);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, nBlocks), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, nBlocks + 1), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, nBlocks * 2), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, nBlocks - 1), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, 0), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        // An input with relative locks disabled can't meet the lock
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG | nBlocks),
                          SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, CTxIn::SEQUENCE_FINAL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        // Without the CSV flag the opcode is a NOP
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, CTxIn::SEQUENCE_FINAL,
                                        STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CHECKSEQUENCEVERIFY),
                          SCRIPT_ERR_OK);
    }
}

/* A relative lock in time (type flag, 512-second units) is met by an input nSequence of at least that time */
BOOST_AUTO_TEST_CASE(csv_p2pkh_seconds)
{
    const LockSpender spender;
    for (uint32_t nSeconds : {86400U, 30U * 86400U}) {
        BOOST_TEST_MESSAGE("seconds " << nSeconds);
        const uint32_t nLock = CsvSeconds(nSeconds);
        const CScript script = spender.Csv(nLock);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, nLock), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, CsvSeconds(nSeconds + 512)), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, CsvSeconds(nSeconds - 512)), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG | nLock),
                          SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        // Bits outside the type flag and the 16-bit value don't count
        BOOST_CHECK_EQUAL(spender.Spend(script, 0, nLock | (1U << 16)), SCRIPT_ERR_OK);
    }
}

/* A relative lock in blocks is never met by a time in nSequence, nor a lock in time by blocks */
BOOST_AUTO_TEST_CASE(csv_p2pkh_blocks_and_seconds_dont_mix)
{
    const LockSpender spender;
    const uint32_t nBlocks = 21000, nTime = CsvSeconds(30 * 86400);
    // The same 16-bit value, once as blocks and once as time
    const uint32_t nValue = nTime & CTxIn::SEQUENCE_LOCKTIME_MASK;
    BOOST_CHECK_EQUAL(spender.Spend(spender.Csv(nBlocks), 0, nTime), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(spender.Spend(spender.Csv(nValue), 0, nTime), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(spender.Spend(spender.Csv(nTime), 0, nBlocks), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(spender.Spend(spender.Csv(nTime), 0, nValue), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_SUITE_END()
