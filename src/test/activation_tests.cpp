// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Activation heights of the consensus rules: the table, its regtest override, and the CLTV
// and CSV script flags one block below and at their height.
//
// With the new-logic or token height set in regtest's table and the fork and token heights
// set from the table, one below and at the height: the target, the reward, the size limits,
// the coinbase maturity, a version 1 transaction in a block and in the mempool, the version
// of the block template, the default versions and the token deployment.

#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "miner.h"
#include "policy/fees.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "random.h"
#include "script/interpreter.h"
#include "script/sign.h"
#include "script/standard.h"
#include "sync.h"
#include "txmempool.h"
#include "utiltime.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/known_failure.h"
#include "test/test_bitcoin.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

/** The script flags of a block at nHeight, with the selected chain's parameters */
unsigned int FlagsAt(int nHeight)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.nTime = Params().GenesisBlock().nTime + 60;
    LOCK(cs_main);
    return GetBlockScriptFlags(&index, Params().GetConsensus());
}

bool HasCLTV(int nHeight) { return (FlagsAt(nHeight) & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) != 0; }
bool HasCSV(int nHeight) { return (FlagsAt(nHeight) & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) != 0; }

// Local copies: the constants are declared without a definition, and BOOST_CHECK_EQUAL takes
// its arguments by reference.
const int TX_VERSION_OLD = CTransaction::CURRENT_VERSION_of_Tx_for_yac_old;
const int TX_VERSION_NEW = CTransaction::CURRENT_VERSION;
const int BLOCK_VERSION_OLD = CURRENT_VERSION_of_block;
const int BLOCK_VERSION_NEW = VERSION_of_block_for_yac_05x_new;

const unsigned int TEST_BITS = 0x1e0fffff;
const unsigned int TEST_BITS_HARDER = 0x1d0fffff;

/**
 * Changes the new-logic and token entries of the selected chain's activation table and sets
 * the fork and token heights from the table; puts the entries back when the test ends.
 */
class TableHeights
{
public:
    TableHeights()
        : m_newLogic(Params().GetConsensus().ActivationHeight(Consensus::ACTIVATION_NEW_LOGIC)),
          m_tokens(Params().GetConsensus().ActivationHeight(Consensus::ACTIVATION_TOKENS))
    {
        globals.SetFromActivationTable();
    }
    ~TableHeights()
    {
        UpdateActivationHeight(Consensus::ACTIVATION_NEW_LOGIC, m_newLogic);
        UpdateActivationHeight(Consensus::ACTIVATION_TOKENS, m_tokens);
    }
    TableHeights(const TableHeights&) = delete;
    TableHeights& operator=(const TableHeights&) = delete;

    void Set(Consensus::ActivationRule rule, int nHeight)
    {
        UpdateActivationHeight(rule, nHeight);
        globals.SetFromActivationTable();
    }

    ConsensusGlobalsGuard globals;

private:
    const int m_newLogic;
    const int m_tokens;
};

/** Regtest with its genesis block */
struct RegtestSetup : public TestingSetup {
    TableHeights heights;
    RegtestSetup() : TestingSetup(CBaseChainParams::REGTEST) {}
};

/** The regtest chain of TestChain100Setup */
struct RegtestChainSetup : public TestChain100Setup {
    TableHeights heights;
    CScript scriptPubKey; // the coinbases' script

    RegtestChainSetup()
    {
        scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    }

    ~RegtestChainSetup()
    {
        LOCK(cs_main);
        mempool.clear();
    }

    static int ChainHeight()
    {
        LOCK(cs_main);
        return chainActive.Height();
    }

    /** Signed spend of output n of prev to scriptPubKey, with the given version */
    CTransaction Spend(const CTransaction& prev, unsigned int n, int nVersion)
    {
        CMutableTransaction tx;
        tx.nVersion = nVersion;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(prev.GetHash(), n);
        tx.vout.resize(1);
        tx.vout[0].nValue = prev.vout[n].nValue - CENT;
        tx.vout[0].scriptPubKey = scriptPubKey;
        std::vector<unsigned char> vchSig;
        const uint256 hash = SignatureHash(prev.vout[n].scriptPubKey, tx, 0, SIGHASH_ALL);
        BOOST_REQUIRE(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[0].scriptSig = CScript() << vchSig;
        return CTransaction(tx);
    }

    /** A block on top of the chain with these transactions after the coinbase, version 7 as
     *  every block of the chain, with its proof of work */
    CBlock BuildBlock(const std::vector<CTransaction>& txs)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
        CBlock block = pblocktemplate->block;
        block.nVersion = BLOCK_VERSION_NEW;
        block.vtx.resize(1);
        for (const CTransaction& tx : txs) block.vtx.push_back(tx);
        block.nTime = std::max(block.GetBlockTime(), block.GetMaxTransactionTime());
        unsigned int nExtraNonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, chainActive.Tip(), nExtraNonce);
        }
        while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
        return block;
    }

    /** TestBlockValidity on top of the chain: "" if valid, else the reject reason */
    static std::string Validity(const CBlock& block)
    {
        LOCK(cs_main);
        CValidationState state;
        if (TestBlockValidity(state, Params(), block, chainActive.Tip())) return "";
        return state.GetRejectReason().empty() ? "no reason" : state.GetRejectReason();
    }

    /** A pay-to-script-hash OP_TRUE coin in the coins cache under a random outpoint, spent by a
     *  transaction of the given version */
    static CTransaction SpendNewCoin(int nVersion)
    {
        const CScript trueScript = CScript() << OP_TRUE;
        const CScript p2shTrue = GetScriptForDestination(CScriptID(trueScript));
        const COutPoint outpoint(GetRandHash(), 0);
        {
            LOCK(cs_main);
            pcoinsTip->AddCoin(outpoint, Coin(CTxOut(COIN, p2shTrue), 1, false, false, (int)(GetAdjustedTime() - 600)), false);
        }
        CMutableTransaction tx;
        tx.nVersion = nVersion;
        tx.vin.resize(1);
        tx.vin[0].prevout = outpoint;
        tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(trueScript.begin(), trueScript.end());
        tx.vout.resize(1);
        tx.vout[0].nValue = COIN - CENT;
        tx.vout[0].scriptPubKey = p2shTrue;
        return CTransaction(tx);
    }

    static bool Submit(const CTransaction& tx, CValidationState& state)
    {
        LOCK(cs_main);
        return AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), nullptr);
    }

    static bool InPool(const CTransaction& tx)
    {
        LOCK(mempool.cs);
        return mempool.exists(tx.GetHash());
    }
};

/** Entries at heights 1 to nTop on top of genesis, nSpacing seconds apart, all with TEST_BITS;
 *  element h is at height h, element 0 is genesis. */
std::vector<CBlockIndex*> BuildChain(SyntheticChain& chain, int nTop, ::int64_t nSpacing)
{
    std::vector<CBlockIndex*> v{chain.Genesis()};
    for (int h = 1; h <= nTop; h++) {
        v.push_back(chain.Add(v.back(), v.back()->GetBlockTime() + nSpacing, TEST_BITS));
    }
    return v;
}

CBigNum Target(unsigned int nBits) { return CBigNum().SetCompact(nBits); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cltv_boundary)
{
    SelectedParamsGuard restore(CBaseChainParams::REGTEST);
    UpdateActivationHeight(Consensus::ACTIVATION_CLTV, 10);
    BOOST_CHECK(!HasCLTV(9));
    BOOST_CHECK(HasCLTV(10));
    BOOST_CHECK(HasCLTV(11));
    // The CSV entry stays at 0.
    BOOST_CHECK(HasCSV(9));
    BOOST_CHECK(HasCSV(10));
}

BOOST_AUTO_TEST_CASE(csv_boundary)
{
    SelectedParamsGuard restore(CBaseChainParams::REGTEST);
    UpdateActivationHeight(Consensus::ACTIVATION_CSV, 10);
    BOOST_CHECK(!HasCSV(9));
    BOOST_CHECK(HasCSV(10));
    BOOST_CHECK(HasCSV(11));
    // The CLTV entry stays at 0.
    BOOST_CHECK(HasCLTV(9));
    BOOST_CHECK(HasCLTV(10));
}

BOOST_AUTO_TEST_CASE(main_cltv_and_csv_at_their_height)
{
    SelectedParamsGuard restore(CBaseChainParams::MAIN);
    BOOST_CHECK(!HasCLTV(1889999));
    BOOST_CHECK(HasCLTV(1890000));
    BOOST_CHECK(!HasCSV(1889999));
    BOOST_CHECK(HasCSV(1890000));
}

/* GetNextTargetRequired for the block after the given entry, with the fork height F set in
 * the table: for block F-1 the target follows the block spacing; for block F it is the target
 * of block F-1, or the limit if F is a multiple of the difficulty interval. */
BOOST_FIXTURE_TEST_CASE(newlogic_difficulty, RegtestSetup)
{
    heights.globals.Set(0, 10); // difficulty interval 10
    SyntheticChain chain;
    const std::vector<CBlockIndex*> fast = BuildChain(chain, 20, 30);
    const std::vector<CBlockIndex*> slow = BuildChain(chain, 20, 600);
    const unsigned int nLimit = Params().GetConsensus().powLimit.GetCompact();

    // F = 15
    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, 15);
    // Block F-1: a lower target after shorter spacing, a higher one after longer spacing
    BOOST_CHECK(Target(GetNextTargetRequired(fast[13], false)) < Target(TEST_BITS));
    BOOST_CHECK(Target(GetNextTargetRequired(slow[13], false)) > Target(TEST_BITS));
    // Block F: the target of block F-1
    BOOST_CHECK_EQUAL(GetNextTargetRequired(fast[14], false), TEST_BITS);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(slow[14], false), TEST_BITS);

    // F = 20, a multiple of the difficulty interval
    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, 20);
    // Block F-1
    BOOST_CHECK(GetNextTargetRequired(fast[18], false) != nLimit);
    BOOST_CHECK(GetNextTargetRequired(slow[18], false) != nLimit);
    // Block F: the limit
    BOOST_CHECK_EQUAL(GetNextTargetRequired(fast[19], false), nLimit);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(slow[19], false), nLimit);
}

/* GetProofOfWorkReward with a chain of height F-1: for block F-1 the reward depends on nBits
 * and the fees are added; for block F neither changes it. */
BOOST_FIXTURE_TEST_CASE(newlogic_reward, RegtestChainSetup)
{
    const int nFork = ChainHeight() + 1;
    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nFork);
    LOCK(cs_main);

    const ::int64_t nBelow = GetProofOfWorkReward(TEST_BITS, 0, nFork - 1);
    BOOST_CHECK(nBelow > 0);
    BOOST_CHECK(GetProofOfWorkReward(TEST_BITS_HARDER, 0, nFork - 1) != nBelow);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(TEST_BITS, CENT, nFork - 1), nBelow + CENT);

    const ::int64_t nAt = GetProofOfWorkReward(TEST_BITS, 0, nFork);
    BOOST_CHECK(nAt > 0);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(TEST_BITS_HARDER, 0, nFork), nAt);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(TEST_BITS, CENT, nFork), nAt);
}

/* GetMaxSize with a chain of height F-1: for block F-1 the fixed limits; for block F the limits
 * derived from the block's reward. */
BOOST_FIXTURE_TEST_CASE(newlogic_block_size_limits, RegtestChainSetup)
{
    const int nFork = ChainHeight() + 1;
    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nFork);
    LOCK(cs_main);

    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, nFork - 1), 1000000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, nFork - 1), 500000U);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, nFork - 1), 20000U);

    const ::uint64_t nSize = GetProofOfWorkReward(0, 0, nFork) * 1000 / MIN_TX_FEE;
    BOOST_CHECK(nSize > 0);
    BOOST_CHECK(nSize != MAX_GENESIS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, nFork), nSize);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, nFork), nSize / 2);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, nFork), std::max<::uint64_t>(nSize, MAX_GENESIS_BLOCK_SIZE) / 50);
}

/* GetCoinbaseMaturity and GetCoinbaseMaturityOffset with a chain of height F-1 and F */
BOOST_FIXTURE_TEST_CASE(newlogic_coinbase_maturity, RegtestChainSetup)
{
    const int nHeight = ChainHeight();
    LOCK(cs_main);

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight + 1);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturity(), 500);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturityOffset(), 20);

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturity(), 6);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturityOffset(), 0);
}

/* A version 1 transaction in a block at height F-1 and F (TestBlockValidity) */
BOOST_FIXTURE_TEST_CASE(newlogic_tx_version_in_block, RegtestChainSetup)
{
    const CTransaction fund = Spend(coinbaseTxns[0], 0, TX_VERSION_NEW);
    CreateAndProcessBlock({fund}, scriptPubKey);
    const CTransaction v1 = Spend(fund, 0, TX_VERSION_OLD);
    const CTransaction v2 = Spend(fund, 0, TX_VERSION_NEW);
    const int nHeight = ChainHeight() + 1; // the height of BuildBlock's blocks

    // Block F-1: valid
    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight + 1);
    BOOST_CHECK_EQUAL(Validity(BuildBlock({v1})), "");

    // Block F
    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight);
    BOOST_CHECK_EQUAL(Validity(BuildBlock({v1})), "bad-txns-version");
    BOOST_CHECK_EQUAL(Validity(BuildBlock({v2})), "");
}

/* A version 1 transaction for the mempool (AcceptToMemoryPool) with a chain of height F-2, F-1
 * and F */
BOOST_FIXTURE_TEST_CASE(newlogic_tx_version_in_mempool, RegtestChainSetup)
{
    const int nHeight = ChainHeight();

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight + 2);
    {
        const CTransaction tx = SpendNewCoin(TX_VERSION_OLD);
        CValidationState state;
        BOOST_CHECK_MESSAGE(Submit(tx, state), FormatStateMessage(state));
        BOOST_CHECK(InPool(tx));
    }

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight + 1);
    {
        const CTransaction tx = SpendNewCoin(TX_VERSION_OLD);
        CValidationState state;
        const bool fAccepted = Submit(tx, state);
        // known defect, MG-046
        KNOWN_FAILURE("MG-046", fAccepted, !fAccepted && state.IsInvalid(), fAccepted && InPool(tx));
    }

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight);
    {
        const CTransaction tx = SpendNewCoin(TX_VERSION_OLD);
        CValidationState state;
        BOOST_CHECK(!Submit(tx, state));
        BOOST_CHECK(!InPool(tx));

        const CTransaction tx2 = SpendNewCoin(TX_VERSION_NEW);
        CValidationState state2;
        BOOST_CHECK_MESSAGE(Submit(tx2, state2), FormatStateMessage(state2));
        BOOST_CHECK(InPool(tx2));
    }
}

/* The version of CreateNewBlock's block with a chain of height F-2 and F-1 */
BOOST_FIXTURE_TEST_CASE(newlogic_block_template_version, RegtestChainSetup)
{
    const int nHeight = ChainHeight();

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight + 2);
    BOOST_CHECK_EQUAL(BlockAssembler().CreateNewBlock(scriptPubKey)->block.nVersion, BLOCK_VERSION_OLD);

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight + 1);
    BOOST_CHECK_EQUAL(BlockAssembler().CreateNewBlock(scriptPubKey)->block.nVersion, BLOCK_VERSION_NEW);
}

/* The default versions of a new header, block and transaction with a chain of height F-2 and
 * F-1 */
BOOST_FIXTURE_TEST_CASE(newlogic_default_versions, RegtestChainSetup)
{
    const int nHeight = ChainHeight();

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight + 2);
    BOOST_CHECK_EQUAL(CBlockHeader().nVersion, BLOCK_VERSION_OLD);
    BOOST_CHECK_EQUAL(CBlock().nVersion, BLOCK_VERSION_OLD);
    BOOST_CHECK_EQUAL(CTransaction().nVersion, TX_VERSION_OLD);
    BOOST_CHECK_EQUAL(CMutableTransaction().nVersion, TX_VERSION_OLD);

    heights.Set(Consensus::ACTIVATION_NEW_LOGIC, nHeight + 1);
    BOOST_CHECK_EQUAL(CBlockHeader().nVersion, BLOCK_VERSION_NEW);
    BOOST_CHECK_EQUAL(CBlock().nVersion, BLOCK_VERSION_NEW);
    BOOST_CHECK_EQUAL(CTransaction().nVersion, TX_VERSION_NEW);
    BOOST_CHECK_EQUAL(CMutableTransaction().nVersion, TX_VERSION_NEW);
}

/* AreTokensDeployed with a chain of height T-1 and T, with the token height T set in the table */
BOOST_FIXTURE_TEST_CASE(tokens_deployed, RegtestChainSetup)
{
    const int nHeight = ChainHeight();

    heights.Set(Consensus::ACTIVATION_TOKENS, nHeight + 1);
    BOOST_CHECK(!AreTokensDeployed());

    heights.Set(Consensus::ACTIVATION_TOKENS, nHeight);
    BOOST_CHECK(AreTokensDeployed());
}

BOOST_AUTO_TEST_SUITE_END()
