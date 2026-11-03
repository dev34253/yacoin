// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The context-free transaction checks (CheckTransaction without the token
// rules, CheckTransactionSize) and the input checks of
// Consensus::CheckTxInputs for transactions that are not coinstakes.

#include "amount.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

namespace {

/** A script of nSize OP_TRUE bytes. */
CScript FilledScript(size_t nSize)
{
    CScript script;
    script.assign(nSize, OP_TRUE);
    return script;
}

/** A transaction that passes CheckTransaction: one input from prevout
 *  (hash, n), one output of nValue to OP_TRUE. */
CTransaction SimpleTx(const uint256& hash, uint32_t n = 0, CAmount nValue = COIN)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(hash, n);
    tx.vin[0].scriptSig = CScript() << OP_TRUE;
    tx.vout.resize(1);
    tx.vout[0].nValue = nValue;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

/** A coinbase with a scriptSig of nScriptSigSize bytes. */
CTransaction Coinbase(size_t nScriptSigSize)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = FilledScript(nScriptSigSize);
    tx.vout.resize(1);
    tx.vout[0].nValue = COIN;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

uint256 Hash(uint8_t n)
{
    uint256 hash;
    *hash.begin() = n;
    return hash;
}

/** Expect a rejection with this DoS score, reject code and reason. */
void CheckRejected(bool fResult, const CValidationState& state, int nDoSExpected,
                   unsigned int nCode, const std::string& strReason)
{
    BOOST_CHECK(!fResult);
    int nDoS = -1;
    BOOST_CHECK(state.IsInvalid(nDoS));
    BOOST_CHECK_EQUAL(nDoS, nDoSExpected);
    BOOST_CHECK_EQUAL(state.GetRejectCode(), nCode);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), strReason);
}

bool Check(const CTransaction& tx, bool fCheckDuplicateInputs = true)
{
    CValidationState state;
    return CheckTransaction(tx, state, fCheckDuplicateInputs) && state.IsValid();
}

void CheckTxRejected(const CTransaction& tx, int nDoS, const std::string& strReason, bool fCheckDuplicateInputs = true)
{
    CValidationState state;
    bool fResult = CheckTransaction(tx, state, fCheckDuplicateInputs);
    CheckRejected(fResult, state, nDoS, REJECT_INVALID, strReason);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(tx_verify_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(check_transaction_inputs_and_outputs)
{
    BOOST_CHECK(Check(SimpleTx(Hash(1))));

    CTransaction tx = SimpleTx(Hash(1));
    tx.vin.clear();
    CheckTxRejected(tx, 10, "bad-txns-vin-empty");

    tx = SimpleTx(Hash(1));
    tx.vout.clear();
    CheckTxRejected(tx, 10, "bad-txns-vout-empty");

    // An empty output (zero value, empty script) after a non-empty one: the
    // transaction is neither a coinbase nor a coinstake.
    tx = SimpleTx(Hash(1));
    tx.vout.push_back(CTxOut());
    tx.vout[1].nValue = 0;
    BOOST_CHECK(tx.vout[1].IsEmpty());
    BOOST_CHECK(!tx.IsCoinStake());
    CheckTxRejected(tx, 100, "bad-txns-vout-empty");

    // A coinbase may have an empty output ...
    tx = Coinbase(2);
    tx.vout.push_back(CTxOut());
    tx.vout[1].nValue = 0;
    BOOST_CHECK(tx.IsCoinBase());
    BOOST_CHECK(Check(tx));

    // ... and so may a coinstake: its first output is the empty one.
    tx = SimpleTx(Hash(1));
    tx.vout.insert(tx.vout.begin(), CTxOut());
    tx.vout[0].nValue = 0;
    BOOST_CHECK(tx.IsCoinStake());
    BOOST_CHECK(Check(tx));

    // A null prevout in a transaction that is not a coinbase.
    tx = SimpleTx(Hash(1));
    tx.vin.resize(2);
    tx.vin[1].prevout.SetNull();
    BOOST_CHECK(!tx.IsCoinBase());
    CheckTxRejected(tx, 10, "bad-txns-prevout-null");
}

BOOST_AUTO_TEST_CASE(check_transaction_output_values)
{
    CTransaction tx = SimpleTx(Hash(1), 0, -1);
    CheckTxRejected(tx, 100, "bad-txns-vout-negative");

    BOOST_CHECK(Check(SimpleTx(Hash(1), 0, 0)));
    BOOST_CHECK(Check(SimpleTx(Hash(1), 0, MAX_MONEY)));

    tx = SimpleTx(Hash(1), 0, MAX_MONEY + 1);
    CheckTxRejected(tx, 100, "bad-txns-vout-toolarge");

    // Each output is in range, their sum is not.
    tx = SimpleTx(Hash(1), 0, MAX_MONEY);
    tx.vout.push_back(tx.vout[0]);
    CheckTxRejected(tx, 100, "bad-txns-txouttotal-toolarge");

    // The sum exactly MAX_MONEY is fine.
    tx = SimpleTx(Hash(1), 0, MAX_MONEY - 1);
    tx.vout.push_back(tx.vout[0]);
    tx.vout[1].nValue = 1;
    BOOST_CHECK(Check(tx));
}

BOOST_AUTO_TEST_CASE(check_transaction_duplicate_inputs)
{
    CTransaction tx = SimpleTx(Hash(1));
    tx.vin.push_back(tx.vin[0]);
    CheckTxRejected(tx, 100, "bad-txns-inputs-duplicate");
    // The check is skipped on request (CheckBlock does it once for the block).
    BOOST_CHECK(Check(tx, false));

    // The same hash with another index is not a duplicate.
    tx.vin[1].prevout.n = 1;
    BOOST_CHECK(Check(tx));
}

BOOST_AUTO_TEST_CASE(check_transaction_coinbase_script_size)
{
    CheckTxRejected(Coinbase(0), 100, "bad-cb-length");
    CheckTxRejected(Coinbase(1), 100, "bad-cb-length");
    BOOST_CHECK(Check(Coinbase(2)));
    BOOST_CHECK(Check(Coinbase(100)));
    CheckTxRejected(Coinbase(101), 100, "bad-cb-length");
}

BOOST_AUTO_TEST_CASE(check_transaction_size)
{
    // Before the fork height the limit is the genesis block size.
    ConsensusGlobalsGuard globals;
    globals.Set(1000, 21000);
    const ::int32_t nHeight = 1;
    const uint64_t nMaxSize = GetMaxSize(MAX_BLOCK_SIZE, nHeight);
    BOOST_CHECK_EQUAL(nMaxSize, MAX_GENESIS_BLOCK_SIZE);

    // Grow one output script until the transaction is exactly nMaxSize bytes.
    // One correction step is enough: both script lengths are above 0xffff,
    // so the compact-size prefix of the length stays 5 bytes.
    CTransaction tx = SimpleTx(Hash(1));
    tx.vout[0].scriptPubKey = FilledScript(nMaxSize - 100);
    const size_t nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    tx.vout[0].scriptPubKey = FilledScript(nMaxSize - 100 + (nMaxSize - nSize));
    BOOST_REQUIRE_EQUAL(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION), nMaxSize);

    CValidationState state;
    BOOST_CHECK(CheckTransactionSize(tx, state, nHeight));
    BOOST_CHECK(state.IsValid());

    tx.vout[0].scriptPubKey.push_back(OP_TRUE);
    BOOST_REQUIRE_EQUAL(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION), nMaxSize + 1);
    CheckRejected(CheckTransactionSize(tx, state, nHeight), state, 100, REJECT_INVALID, "bad-txns-oversize");
}

namespace {

/** A coins view with the given coins, on top of an empty base view. */
struct CoinsFixture
{
    CCoinsView base;
    CCoinsViewCache view{&base};

    COutPoint Add(const uint256& hash, CAmount nValue, int nHeight = 1, bool fCoinBase = false)
    {
        COutPoint outpoint(hash, 0);
        CTxOut out(nValue, CScript() << OP_TRUE);
        view.AddCoin(outpoint, Coin(out, nHeight, fCoinBase, false, 0), false);
        return outpoint;
    }
};

/** A transaction spending the given outpoints, paying nValueOut to OP_TRUE. */
CTransaction Spend(const std::vector<COutPoint>& vPrevouts, CAmount nValueOut)
{
    CTransaction tx;
    for (const COutPoint& prevout : vPrevouts) {
        tx.vin.emplace_back(prevout);
    }
    tx.vout.resize(1);
    tx.vout[0].nValue = nValueOut;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

} // namespace

BOOST_AUTO_TEST_CASE(check_tx_inputs_missing_input)
{
    CoinsFixture coins;
    CTransaction tx = Spend({COutPoint(Hash(1), 0)}, COIN);
    CValidationState state;
    BOOST_CHECK(!Consensus::CheckTxInputs(tx, state, coins.view, 2, nullptr));
    // Invalid, but without a DoS score and without a reject code or reason.
    int nDoS = -1;
    BOOST_CHECK(state.IsInvalid(nDoS));
    BOOST_CHECK_EQUAL(nDoS, 0);
    BOOST_CHECK_EQUAL(state.GetRejectCode(), 0U);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "");
    BOOST_CHECK_EQUAL(state.GetDebugMessage(), "Inputs unavailable");
}

BOOST_AUTO_TEST_CASE(check_tx_inputs_coinbase_maturity)
{
    CoinsFixture coins;
    const int nCoinHeight = 10;
    const COutPoint prevout = coins.Add(Hash(1), COIN, nCoinHeight, true);
    CTransaction tx = Spend({prevout}, COIN);
    const int nMaturity = GetCoinbaseMaturity();
    BOOST_REQUIRE(nMaturity > 0);

    CValidationState state;
    bool fResult = Consensus::CheckTxInputs(tx, state, coins.view, nCoinHeight + nMaturity - 1, nullptr);
    CheckRejected(fResult, state, 0, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase/coinstake");

    CValidationState state2;
    BOOST_CHECK(Consensus::CheckTxInputs(tx, state2, coins.view, nCoinHeight + nMaturity, nullptr));
    BOOST_CHECK(state2.IsValid());

    // A coin that is not a coinbase is spendable at once.
    const COutPoint plain = coins.Add(Hash(2), COIN, nCoinHeight, false);
    CValidationState state3;
    BOOST_CHECK(Consensus::CheckTxInputs(Spend({plain}, COIN), state3, coins.view, nCoinHeight, nullptr));
}

BOOST_AUTO_TEST_CASE(check_tx_inputs_values)
{
    CoinsFixture coins;

    // One input over MAX_MONEY.
    {
        const COutPoint big = coins.Add(Hash(1), MAX_MONEY + 1);
        CValidationState state;
        bool fResult = Consensus::CheckTxInputs(Spend({big}, COIN), state, coins.view, 2, nullptr);
        CheckRejected(fResult, state, 100, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
    }
    // Two inputs of MAX_MONEY: each is in range, the sum is not.
    {
        const COutPoint a = coins.Add(Hash(2), MAX_MONEY);
        const COutPoint b = coins.Add(Hash(3), MAX_MONEY);
        CValidationState state;
        bool fResult = Consensus::CheckTxInputs(Spend({a, b}, COIN), state, coins.view, 2, nullptr);
        CheckRejected(fResult, state, 100, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
    }
    // More out than in.
    const COutPoint coin = coins.Add(Hash(4), 5 * COIN);
    {
        CValidationState state;
        bool fResult = Consensus::CheckTxInputs(Spend({coin}, 5 * COIN + 1), state, coins.view, 2, nullptr);
        CheckRejected(fResult, state, 100, REJECT_INVALID, "bad-txns-in-belowout");
        BOOST_CHECK_EQUAL(state.GetDebugMessage(), "value in (5.00) < value out (5.000001)");
    }
    // In equals out (no fee), and in above out.
    {
        CValidationState state;
        BOOST_CHECK(Consensus::CheckTxInputs(Spend({coin}, 5 * COIN), state, coins.view, 2, nullptr));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(Consensus::CheckTxInputs(Spend({coin}, 0), state, coins.view, 2, nullptr));
        BOOST_CHECK(state.IsValid());
    }
}

BOOST_AUTO_TEST_SUITE_END()
