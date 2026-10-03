// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Synthetic proof-of-stake blocks (task P0-55): the generator in
// test/pos_generator.h produces PoS blocks that the node accepts, and the
// rules it has to work around are pinned (review A9, C8). The kernel and
// fork-choice tests that use it are in kernel_tests and chain_trust_tests.

#include "test/pos_generator.h"

#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "kernel.h"
#include "pow.h"
#include "sync.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <stdexcept>

using namespace synthetic_pos;

extern CBigNum bnProofOfStakeHardLimit; // pow.cpp:21

BOOST_FIXTURE_TEST_SUITE(pos_generator_tests, PosChainSetup)

/* GetNextTargetRequired044 (pow.cpp:108-127) gives the first and second PoS
 * block of a chain initialHashTarget (regtest 0x207fffff), which the header
 * rule (block.h IsProofOfStake: nBits <= 0x1d03ffff) does not count as PoS.
 * A correct PoS block with the PoS limit as nBits passes CheckBlock and
 * CheckProofOfStake but is rejected for its nBits; on mainnet the two
 * hard-coded hashes in IsProofOfStake presumably got past this. Hence
 * SeedProofOfStakeHistory. */
BOOST_AUTO_TEST_CASE(first_pos_blocks_need_seed)
{
    BOOST_CHECK_EQUAL(POS_LIMIT_BITS, bnProofOfStakeHardLimit.GetCompact());
    BOOST_CHECK_EQUAL(REGTEST_INITIAL_BITS, Params().GetConsensus().initialHashTarget.GetCompact());

    // 1-day spacing: block 1's coinbase is 129 days old at the tip.
    CBlockIndex* tip = MinePowChain(130, 24 * 60 * 60);
    BOOST_CHECK_EQUAL(tip->nHeight, 130);
    BOOST_CHECK(tip->GeneratedStakeModifier());
    BOOST_CHECK_EQUAL(GetNextTargetRequired(tip, true), REGTEST_INITIAL_BITS);

    CBlockHeader header;
    header.nTime = tip->GetBlockTime() + 1;
    header.nNonce = 0;
    header.nBits = REGTEST_INITIAL_BITS;
    BOOST_CHECK(!header.IsProofOfStake());
    header.nBits = POS_LIMIT_BITS;
    BOOST_CHECK(header.IsProofOfStake());

    const COutPoint stake = CoinbaseOutPoint(1);
    BOOST_CHECK_THROW(GeneratePosBlock(tip, stake), std::runtime_error);

    const Kernel kernel = FindKernel(tip, stake, POS_LIMIT_BITS);
    const CBlock block = CreatePosBlock(tip, kernel);
    BOOST_CHECK(block.IsProofOfStake());
    BOOST_CHECK(block.vtx[1].IsCoinStake());
    {
        CValidationState state;
        BOOST_CHECK(CheckBlock(block, state, Params().GetConsensus()));
    }
    {
        LOCK(cs_main);
        CValidationState state;
        uint256 hashProof, target;
        BOOST_CHECK(CheckProofOfStake(state, tip, block.vtx[1], block.nBits, hashProof, target));
        BOOST_CHECK(hashProof == kernel.hashProofOfStake);
        BOOST_CHECK(target == kernel.targetProofOfStake);
    }

    CValidationState state;
    BOOST_CHECK(!ProcessNewBlockHeaders({block}, state, Params()));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-diffbits");
    bool fAccepted = true;
    BOOST_CHECK(Submit(block, true, nullptr, &fAccepted) == nullptr);
    BOOST_CHECK(!fAccepted);
    LOCK(cs_main);
    BOOST_CHECK(chainActive.Tip() == tip);
}

/* With the seed, generated PoS blocks pass ProcessNewBlock (AcceptBlock with
 * CheckProofOfStake, ConnectBlock with the coinstake checks) and update the
 * index and the UTXO set. A PoS block on a PoS block has trust 0
 * (chain.cpp:92-93), so its chain trust equals its parent's: it is stored
 * but not activated (CBlockIndexWorkComparator, validation.cpp:112-131,
 * keeps the earlier block) until a block on top of it adds trust. */
BOOST_AUTO_TEST_CASE(generated_pos_blocks_connect)
{
    CBlockIndex* tip = MinePowChain(505);
    {
        LOCK(cs_main);
        SeedProofOfStakeHistory(chainActive[2], chainActive[3]);
    }
    BOOST_CHECK_EQUAL(GetNextTargetRequired(tip, true), POS_LIMIT_BITS);

    // PoS on PoW: stake block 1's coinbase (504 deep, 126 days old).
    const COutPoint stake1 = CoinbaseOutPoint(1);
    Kernel k1;
    const CBlock block1 = GeneratePosBlock(tip, stake1, 0, &k1);
    BOOST_CHECK_EQUAL(block1.nBits, POS_LIMIT_BITS);
    bool fAccepted = false;
    CBlockIndex* pos1 = Submit(block1, true, nullptr, &fAccepted);
    BOOST_REQUIRE(fAccepted);
    BOOST_REQUIRE(pos1 != nullptr);
    {
        LOCK(cs_main);
        BOOST_CHECK(chainActive.Tip() == pos1);
        BOOST_CHECK(pos1->IsProofOfStake());
        BOOST_CHECK(pos1->hashProofOfStake == k1.hashProofOfStake);
        BOOST_CHECK(pos1->nStatus & BLOCK_HAVE_UNDO);
        BOOST_CHECK_EQUAL(pos1->nMint, 0);
        BOOST_CHECK(pos1->GetBlockTrust() == tip->GetBlockTrust() + 1);
        BOOST_CHECK(pos1->bnChainTrust == tip->bnChainTrust + tip->GetBlockTrust() + 1);
        BOOST_CHECK(!pcoinsTip->HaveCoin(stake1));
        const COutPoint out1(block1.vtx[1].GetHash(), 1);
        BOOST_REQUIRE(pcoinsTip->HaveCoin(out1));
        BOOST_CHECK(pcoinsTip->AccessCoin(out1).IsCoinStake());
        BOOST_CHECK_EQUAL(pcoinsTip->AccessCoin(out1).out.nValue, k1.txPrev.vout[0].nValue);
    }

    // PoS on PoS: stake block 2's coinbase.
    const COutPoint stake2 = CoinbaseOutPoint(2);
    Kernel k2;
    const CBlock block2 = GeneratePosBlock(pos1, stake2, 0, &k2);
    BOOST_CHECK_EQUAL(block2.nBits, POS_LIMIT_BITS);
    bool fNewBlock = false;
    CBlockIndex* pos2 = Submit(block2, true, &fNewBlock, &fAccepted);
    BOOST_REQUIRE(fAccepted);
    BOOST_REQUIRE(pos2 != nullptr);
    {
        LOCK(cs_main);
        BOOST_CHECK(fNewBlock);
        BOOST_CHECK(pos2->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(pos2->IsProofOfStake());
        BOOST_CHECK(pos2->hashProofOfStake == k2.hashProofOfStake); // AcceptBlock ran the kernel check
        BOOST_CHECK(pos2->GetBlockTrust() == 0);
        BOOST_CHECK(pos2->bnChainTrust == pos1->bnChainTrust);
        BOOST_CHECK(chainActive.Tip() == pos1); // not activated
        BOOST_CHECK(pcoinsTip->HaveCoin(stake2));
    }

    // A PoW block on it (trust doubled after PoS) activates both.
    CBlockIndex* pow = Submit(MinePowBlock(pos2, pos2->GetBlockTime() + 60), true, nullptr, &fAccepted);
    BOOST_REQUIRE(fAccepted);
    BOOST_REQUIRE(pow != nullptr);
    LOCK(cs_main);
    BOOST_CHECK(chainActive.Tip() == pow);
    BOOST_CHECK(chainActive.Contains(pos2));
    BOOST_CHECK(pow->GetBlockTrust() == tip->GetBlockTrust() * 2);
    BOOST_CHECK(!pcoinsTip->HaveCoin(stake2));
    BOOST_CHECK(pcoinsTip->HaveCoin(COutPoint(block2.vtx[1].GetHash(), 1)));
}

BOOST_AUTO_TEST_SUITE_END()
