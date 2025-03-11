// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokens/tokens.h"
#include "primitives/transaction.h"
#include "txdb.h"
#include "wallet.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "consensus/consensus.h"

#include <map>

using std::vector;
using std::map;
using std::set;

void CTransaction::SetNull()
{
	// TODO: Need update for mainet
	if (chainActive.Height() != -1 && chainActive.Genesis() && (chainActive.Height() + 1) >= nMainnetNewLogicBlockNumber)
	{
		nVersion = CTransaction::CURRENT_VERSION;
	}
	else
	{
		nVersion = CTransaction::CURRENT_VERSION_of_Tx_for_yac_old;
	}
	nTime = GetAdjustedTime();
	vin.clear();
	vout.clear();
	nLockTime = 0;
}

unsigned int
CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    for (const auto& txin : vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    {
        LOCK(mempool.cs);
        ::int64_t nValueIn = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            COutPoint prevout = vin[i].prevout;
            if (!mempool.exists(prevout.COutPointGetHash()))
                return false;
            const CTransaction& txPrev = mempool.get(prevout.COutPointGetHash());

            if (prevout.COutPointGet_n() >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i, SCRIPT_VERIFY_NOCACHE | SCRIPT_VERIFY_P2SH, 0))
                return error("ClientConnectInputs() : VerifySignature failed");

            ///// this is redundant with the mempool.mapNextTx stuff,
            ///// not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.COutPointGet_n()].nValue;

            if (!MoneyRange(txPrev.vout[prevout.COutPointGet_n()].nValue) || !MoneyRange(nValueIn))
                return error("ClientConnectInputs() : txin values out of range");
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}
