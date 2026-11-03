// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/consensus.h"
#include "main.h"
#include "net.h"
#include "policy/fees.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/stake_test_util.h"
#include "test/test_bitcoin.h"

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

/** Pre-fork reward for a target powLimit / nDivisor */
static ::int64_t PreForkReward(unsigned int nDivisor, ::int64_t nFees = 0)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(Params().GetConsensus().powLimit.GetCompact());
    bnTarget /= nDivisor;
    return GetProofOfWorkReward(bnTarget.GetCompact(), nFees, 1);
}

/** Post-fork reward from a money supply, with the same expression as validation.cpp */
static ::int64_t EpochReward(::int64_t nMoneySupply)
{
    return nMoneySupply * nInflation / nNumberOfBlocksPerYear;
}

static ::int64_t MoneySupplyAt(int nHeight)
{
    return 100000000 * COIN + (::int64_t)nHeight * 1000 * COIN;
}

/** Synthetic chain up to nTipHeight with a known nMoneySupply per height, set as active chain */
static CBlockIndex* BuildSupplyChain(SyntheticChain& chain, int nTipHeight)
{
    CBlockIndex* pindex = chain.Genesis();
    for (int nHeight = 1; nHeight <= nTipHeight; nHeight++) {
        pindex = chain.Add(pindex, pindex->GetBlockTime() + 60, 0x1d0fffff, MoneySupplyAt(nHeight));
    }
    chain.SetActiveTip(pindex);
    return pindex;
}

BOOST_AUTO_TEST_CASE(blocks_per_year)
{
    // 365.25 days of one-minute blocks
    BOOST_CHECK_EQUAL(nNumberOfBlocksPerYear, 525960U);
}

/* Before the fork: 100 YAC at minimum difficulty, halving every 64x difficulty, plus fees */
BOOST_AUTO_TEST_CASE(pre_fork_reward)
{
    ConsensusGlobalsGuard globals;
    globals.Set(1000, 10);

    BOOST_CHECK_EQUAL(PreForkReward(1), MAX_MINT_PROOF_OF_WORK);
    BOOST_CHECK_EQUAL(MAX_MINT_PROOF_OF_WORK, 100 * COIN);
    BOOST_CHECK_EQUAL(PreForkReward(64), 50 * COIN);
    BOOST_CHECK_EQUAL(PreForkReward(64 * 64 * 64 * 64), 625 * CENT);
    BOOST_CHECK_EQUAL(PreForkReward(64, 3 * CENT), 50 * COIN + 3 * CENT);

    // Target 0 bottoms out at the 0.01 YAC search floor
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 1), CENT);

    // Rounded down to whole cents, never rising with difficulty
    ::int64_t nPrevious = MAX_MINT_PROOF_OF_WORK;
    for (unsigned int nShift = 0; nShift < 32; nShift++) {
        ::int64_t nReward = PreForkReward(1U << nShift);
        BOOST_CHECK_EQUAL(nReward % CENT, 0);
        BOOST_CHECK(nReward <= nPrevious);
        BOOST_CHECK(nReward >= CENT);
        nPrevious = nReward;
    }
}

/* The pre-fork reward is the same with its -printcreation log lines on (with
 * -debug) or off; the guards restore -debug and -printcreation */
BOOST_AUTO_TEST_CASE(pre_fork_reward_logged)
{
    ConsensusGlobalsGuard globals;
    globals.Set(1000, 10);
    const bool fDebugBefore = fDebug;
    const bool fPrintSetBefore = gArgs.IsArgSet("-printcreation");

    for (bool fPrint : {false, true}) {
        ValueGuard<bool> debug(fDebug, true);
        ArgGuard print("-printcreation", fPrint ? "1" : "0");
        BOOST_CHECK_EQUAL(gArgs.GetBoolArg("-printcreation", false), fPrint);
        BOOST_CHECK_EQUAL(PreForkReward(1), MAX_MINT_PROOF_OF_WORK);
        BOOST_CHECK_EQUAL(PreForkReward(64), 50 * COIN);
        BOOST_CHECK_EQUAL(PreForkReward(64 * 64 * 64 * 64), 625 * CENT);
        BOOST_CHECK_EQUAL(PreForkReward(64, 3 * CENT), 50 * COIN + 3 * CENT);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 1), CENT);
    }
    BOOST_CHECK_EQUAL(fDebug, fDebugBefore);
    BOOST_CHECK_EQUAL(gArgs.IsArgSet("-printcreation"), fPrintSetBefore);
}

/* Height 0 always takes the pre-fork path, even with the fork at 0 */
BOOST_AUTO_TEST_CASE(reward_height_zero)
{
    ConsensusGlobalsGuard globals;
    globals.Set(0, 10);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(Params().GetConsensus().powLimit.GetCompact(), 0, 0), MAX_MINT_PROOF_OF_WORK);
}

/* After the fork: supply at the end of the previous epoch * 2% / blocks per year,
 * fixed for the whole epoch. Fees are not added: post-fork fees are destroyed, an
 * intended rule (MG-028). */
BOOST_AUTO_TEST_CASE(post_fork_epoch_reward)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;

    // Blocks 20-29: first epoch after the fork, based on the supply at block 19
    for (int nHeight = 20; nHeight <= 29; nHeight++) {
        BuildSupplyChain(chain, nHeight - 1);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, nHeight), EpochReward(MoneySupplyAt(19)));
    }
    // Blocks 30-39: based on the supply at block 29
    for (int nHeight = 30; nHeight <= 39; nHeight++) {
        BuildSupplyChain(chain, nHeight - 1);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, nHeight), EpochReward(MoneySupplyAt(29)));
    }
    BOOST_CHECK(EpochReward(MoneySupplyAt(29)) > EpochReward(MoneySupplyAt(19)));

    // nBits and fees don't matter: the reward never includes the fees (intended, MG-028)
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1c0fffff, 5 * COIN, 39), EpochReward(MoneySupplyAt(29)));

    // Blocks before the fork still use the pre-fork curve
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(Params().GetConsensus().powLimit.GetCompact(), 0, 19), MAX_MINT_PROOF_OF_WORK);

    // Pins the 2% rate: 100,019,000 YAC * 0.02 / 525,960 = 3.803293 YAC
    // (nInflation is a double, so the reward is computed in floating point)
    BuildSupplyChain(chain, 19);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 20), 3803293);
}

/* The epochs that start at 1890000, 1911000, 1932000 and 1953000 (k = 90..93),
 * with the money supply of the block before each start and the coinbase value of
 * every block of the epoch as recorded on mainnet (mainnet reference node, master
 * commit 6d723834; the epoch from 1953000 up to its tip 1964927). The test scales
 * the epoch interval down to 10 blocks with the fork at 900, so epoch k starts at
 * 10 * k instead of 21000 * k: the reward only depends on that money supply. */
BOOST_AUTO_TEST_CASE(post_fork_epoch_reward_mainnet_epochs)
{
    ConsensusGlobalsGuard globals;
    globals.Set(900, 10);
    SyntheticChain chain;

    struct Epoch {
        int nStart;            // first height on mainnet
        ::int64_t nSupply;     // money supply of block nStart - 1
        ::int64_t nReward;     // coinbase value of every block of the epoch
        ::uint64_t nMaxSize;   // GetMaxSize(MAX_BLOCK_SIZE) in the epoch: nReward * 1000 / MIN_TX_FEE
    };
    const Epoch epochs[] = {
        {1890000, 135559014630631, 5154727, 515472},
        {1911000, 135667258614271, 5158843, 515884},
        {1932000, 135775575497237, 5162962, 516296},
        {1953000, 135883984037692, 5167084, 516708},
    };
    const int nEpochs = sizeof(epochs) / sizeof(epochs[0]);

    // Blocks 1..939; the block before each epoch start carries the recorded
    // supply, the blocks after it add the epoch's reward
    CBlockIndex* pindex = chain.Genesis();
    for (int nHeight = 1; nHeight < 900 + 10 * nEpochs; nHeight++) {
        const int i = std::min(std::max((nHeight + 1) / 10 - 90, 0), nEpochs - 1);
        const int nBefore = 899 + 10 * i;
        ::int64_t nSupply = nHeight < nBefore ? (::int64_t)nHeight * COIN
                                              : epochs[i].nSupply + (nHeight - nBefore) * epochs[i].nReward;
        pindex = chain.Add(pindex, pindex->GetBlockTime() + 60, 0x1e0fffff, nSupply);
    }
    chain.SetActiveTip(pindex);

    for (int i = 0; i < nEpochs; i++) {
        BOOST_CHECK_EQUAL(chainActive[899 + 10 * i]->nMoneySupply, epochs[i].nSupply);
        BOOST_CHECK_EQUAL(EpochReward(epochs[i].nSupply), epochs[i].nReward);
        for (int nHeight = 900 + 10 * i; nHeight < 910 + 10 * i; nHeight++) {
            // nBits and fees are ignored
            BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, nHeight), epochs[i].nReward);
            BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1e0fffff, 0, nHeight), epochs[i].nReward);
            BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1c0fffff, 5 * COIN, nHeight), epochs[i].nReward);

            // Below the pre-fork 1 MB, so the sigops limit stays 1 MB / 50
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, nHeight), epochs[i].nMaxSize);
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, nHeight), epochs[i].nMaxSize / 2);
            BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, nHeight), 20000U);
        }
    }
    // The last block of an epoch still gets the old reward, the next one the new
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 909), 5154727);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 910), 5158843);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 929), 5162962);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 930), 5167084);
    // The block before the fork still uses the pre-fork curve
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(Params().GetConsensus().powLimit.GetCompact(), 0, 899), MAX_MINT_PROOF_OF_WORK);
}

/* Fork inside the first epoch interval: the first epoch starts at the fork */
BOOST_AUTO_TEST_CASE(post_fork_epoch_reward_fork_before_first_interval)
{
    ConsensusGlobalsGuard globals;
    globals.Set(5, 10);
    SyntheticChain chain;
    for (int nHeight = 5; nHeight <= 9; nHeight++) {
        BuildSupplyChain(chain, nHeight - 1);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, nHeight), EpochReward(MoneySupplyAt(4)));
    }
    BuildSupplyChain(chain, 9);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 10), EpochReward(MoneySupplyAt(9)));

    // Fork at 0 (the unit-test default): the first epoch reads the genesis block's supply.
    // This is incidental: the epoch-start height - 1 is -1, and FindBlockByHeight
    // returns genesis for any height <= 0.
    globals.Set(0, 10);
    BuildSupplyChain(chain, 2);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 3), EpochReward(chain.Genesis()->nMoneySupply));
    BOOST_CHECK(GetProofOfWorkReward(0, 0, 3) != EpochReward(MoneySupplyAt(2)));
}

/* Block size limits follow the reward after the fork */
BOOST_AUTO_TEST_CASE(max_block_size)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;

    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 10), MAX_GENESIS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, 10), MAX_GENESIS_BLOCK_SIZE / 2);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, 10), MAX_GENESIS_BLOCK_SIZE / 50);

    BuildSupplyChain(chain, 24);
    // About 3.8 YAC per block => 380 kB, below the pre-fork 1 MB
    ::uint64_t nSize = EpochReward(MoneySupplyAt(19)) * 1000 / MIN_TX_FEE;
    BOOST_CHECK(nSize < MAX_GENESIS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 25), nSize);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, 25), nSize / 2);
    // The sigops limit never drops below the pre-fork one
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, 25), MAX_GENESIS_BLOCK_SIZE / 50);
    // Height 0 means "the next block on the active chain"
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 0), nSize);

    // 100x the supply => 38 MB blocks, and the sigops limit follows
    {
        LOCK(cs_main);
        chainActive[19]->nMoneySupply *= 100;
    }
    nSize = EpochReward(MoneySupplyAt(19) * 100) * 1000 / MIN_TX_FEE;
    BOOST_CHECK(nSize > MAX_GENESIS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 25), nSize);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, 25), nSize / 50);
}

BOOST_AUTO_TEST_CASE(coinbase_maturity)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;

    BuildSupplyChain(chain, 19);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturity(), COINBASE_MATURITY_BEFORE_HARDFORK);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturityOffset(), 20);

    BuildSupplyChain(chain, 20);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturity(), COINBASE_MATURITY_AFTER_HARDFORK);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturityOffset(), 0);
}

bool ReturnFalse() { return false; }
bool ReturnTrue() { return true; }

BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool (), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}
BOOST_AUTO_TEST_SUITE_END()
