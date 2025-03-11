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

bool CTransaction::ReadFromDisk(COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!pblocktree->ReadTxIndex(prevout.COutPointGetHash(), txindexRet))
        return false;
    if (!ReadFromDisk(txindexRet.pos))
        return false;
    if (prevout.COutPointGet_n() >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(prevout, txindex);
}

bool CTransaction::ReadFromDisk(CDiskTxPos pos, FILE** pfileRet)
{
  //CAutoFile filein = CAutoFile(OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);
    CAutoFile filein(OpenBlockFile(pos.Get_CDiskTxPos_nFile(), 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

    // Read transaction
  //if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
    if (fseek(filein, pos.Get_CDiskTxPos_nTxPos(), SEEK_SET) != 0)
        return error("CTransaction::ReadFromDisk() : fseek failed");

    try {
        filein >> *this;
    }
    catch (std::exception& e)
    //catch (...)
    {
        //(void)e;
        return error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
    }

    // Return file pointer
    if (pfileRet)
    {
      //if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
        if (fseek(filein, pos.Get_CDiskTxPos_nBlockPos(), SEEK_SET) != 0)
            return error("CTransaction::ReadFromDisk() : second fseek failed");
        *pfileRet = filein.release();
    }
    return true;
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

bool CTransaction::DisconnectInputs(CValidationState &state, CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        for(const CTxIn& txin : vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!pblocktree->ReadTxIndex(prevout.COutPointGetHash(), txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.COutPointGet_n() >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.COutPointGet_n()].SetNull();

            // Write back
            if (!pblocktree->UpdateTxIndex(prevout.COutPointGetHash(), txindex))
                return error("DisconnectInputs() : UpdateTxIndex failed");
        }
    }

    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely
    // spent, so erasing it would be a no-op anyway.
    pblocktree->EraseTxIndex(*this);

    return true;
}

const CTxOut& CTransaction::GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.COutPointGetHash());
    if (mi == inputs.end())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.hash not found");

    const CTransaction& txPrev = (mi->second).second;
    if (input.prevout.COutPointGet_n() >= txPrev.vout.size())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.n out of range");

    return txPrev.vout[input.prevout.COutPointGet_n()];
}

::int64_t CTransaction::GetValueIn(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    ::int64_t nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        nResult += GetOutputFor(vin[i], inputs).nValue;
    }
    return nResult;

}

unsigned int CTransaction::GetP2SHSigOpCount(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    }
    return nSigOps;
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

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(::uint64_t& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    for(const CTxIn& txin : vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txin.prevout, txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos(), false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        ::int64_t nValueIn = txPrev.vout[txin.prevout.COutPointGet_n()].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;

        if (fDebug && gArgs.GetBoolArg("-printcoinage"))
            LogPrintf("coin age nValueIn=%" PRId64 " nTimeDiff=%ld bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && gArgs.GetBoolArg("-printcoinage"))
        LogPrintf("coin age bnCoinDay=%s\n", bnCoinDay.ToString());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}
