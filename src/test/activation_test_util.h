// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_ACTIVATION_TEST_UTIL_H
#define YACOIN_TEST_ACTIVATION_TEST_UTIL_H

#include "chainparams.h"
#include "util.h"

/**
 * Sets the fork height nMainnetNewLogicBlockNumber and the token support
 * height nTokenSupportBlockNumber from the selected chain's activation table.
 * Used by the unit tests and the fuzz binary (which has no Boost.Test).
 */
inline void SetHeightsFromActivationTable()
{
    const Consensus::Params& consensus = Params().GetConsensus();
    nMainnetNewLogicBlockNumber = consensus.ActivationHeight(Consensus::ACTIVATION_NEW_LOGIC);
    nTokenSupportBlockNumber = consensus.ActivationHeight(Consensus::ACTIVATION_TOKENS);
}

#endif // YACOIN_TEST_ACTIVATION_TEST_UTIL_H
