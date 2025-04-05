// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "main.h"
#include "bitcoinrpc.h"
#include "streams.h"
#include "price.h"
#include "consensus/validation.h"
#include "policy/policy.h"

#include <boost/foreach.hpp>

using namespace json_spirit;

using std::max;
using std::string;
using std::runtime_error;
using std::vector;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (chainActive.Tip() == NULL)
            return 1.0;
        else
            blockindex = GetLastBlockIndex(chainActive.Tip(), false);
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;  // mask to top 8 bits

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);
                                                    // 64k/(mask lower 24 bits)
                                                    // can be <1, >1
    while (nShift < 29)     // can be 0 to 256
    {
        dDiff *= 256.0;     // sort of << 8
        nShift++;
    }                       // nShift is >=30 and <=255
    while (nShift > 29)
    {
        dDiff /= 256.0;     // sort of >>8
        nShift--;
    }

    return dDiff;
}

double GetPoWMHashPS()
{
    int nPoWInterval = 72;
    int64_t nTargetSpacingWorkMin = 30, nTargetSpacingWork = 30;

    CBlockIndex* pindex = chainActive.Genesis();
    CBlockIndex* pindexPrevWork = chainActive.Genesis();

    while (pindex)
    {
        if (pindex->IsProofOfWork())
        {
            int64_t nActualSpacingWork = pindex->GetBlockTime() - pindexPrevWork->GetBlockTime();
            nTargetSpacingWork = ((nPoWInterval - 1) * nTargetSpacingWork + nActualSpacingWork + nActualSpacingWork) / (nPoWInterval + 1);
            nTargetSpacingWork = max(nTargetSpacingWork, nTargetSpacingWorkMin);
            pindexPrevWork = pindex;
        }

        pindex = chainActive.Next(pindex);
    }

    return GetDifficulty() * 4294.967296 / nTargetSpacingWork;
}

double GetPoSKernelPS()
{
    int nPoSInterval = 72;
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    CBlockIndex* pindex = chainActive.Tip();;
    CBlockIndex* pindexPrevStake = NULL;

    while (pindex && nStakesHandled < nPoSInterval)
    {
        if (pindex->IsProofOfStake())
        {
            dStakeKernelsTriedAvg += GetDifficulty(pindex) * 4294967296.0;
            nStakesTime += pindexPrevStake ? (pindexPrevStake->nTime - pindex->nTime) : 0;
            pindexPrevStake = pindex;
            nStakesHandled++;
        }

        pindex = pindex->pprev;
    }

    if (!nStakesHandled)
        return 0;

    return dStakeKernelsTriedAvg / nStakesTime;
}

Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);
    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("mint", ValueFromAmount(blockindex->nMint)));
    result.push_back(Pair("money supply", ValueFromAmount(blockindex->nMoneySupply)));
    result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("blocktrust", leftTrim(blockindex->GetBlockTrust().GetHex(), '0')));
    result.push_back(Pair("chaintrust", leftTrim(blockindex->bnChainTrust.GetHex(), '0')));
    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));

    result.push_back(Pair("flags", strprintf("%s%s", blockindex->IsProofOfStake()? "proof-of-stake" : "proof-of-work", blockindex->GeneratedStakeModifier()? " stake-modifier": "")));
    result.push_back(Pair("proofhash", blockindex->IsProofOfStake()? blockindex->hashProofOfStake.GetHex() : blockindex->GetBlockHash().GetHex()));
    result.push_back(Pair("entropybit", (int)blockindex->GetStakeEntropyBit()));
    result.push_back(Pair("modifier", strprintf("%016" PRIx64, blockindex->nStakeModifier)));
    result.push_back(Pair("modifierchecksum", strprintf("%08x", blockindex->nStakeModifierChecksum)));
    Array txinfo;
    BOOST_FOREACH (const CTransaction& tx, block.vtx)
    {
        if (fPrintTransactionDetail)
        {
            CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
            ssTx << tx;
            string strHex = HexStr(ssTx.begin(), ssTx.end());

            txinfo.push_back(strHex);
        }
        else
            txinfo.push_back(tx.GetHash().GetHex());
    }

    result.push_back(Pair("tx", txinfo));

    if ( block.IsProofOfStake() )
        result.push_back(Pair("signature", HexStr(block.vchBlockSig.begin(), block.vchBlockSig.end())));

    return result;
}

Value getbestblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "Returns the hash of the best block in the longest block chain.");

    return chainActive.Tip()->blockHash.GetHex();
}

Value gettimechaininfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gettimechaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"
            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "}\n"
        );

    Object obj;
    obj.push_back(Pair("blocks",                (int)chainActive.Height()));
    obj.push_back(Pair("headers",               pindexBestHeader ? pindexBestHeader->nHeight : -1));
    obj.push_back(Pair("bestblockhash",         chainActive.Tip()->GetBlockHash().GetHex()));
    obj.push_back(Pair("difficulty",            (double)GetDifficulty()));
    obj.push_back(Pair("bnChainTrust",             chainActive.Tip()->bnChainTrust.getuint64()));
    return obj;
}

Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return chainActive.Height();
}

double doGetYACprice()
{
    // first call gets BTC/YAC ratio
    // second call gets USD/BTC, so the product is USD/YAC
    double
        dPriceRatio = 0.0,
        dUSDperYACprice = 0.0,
        dUSDtoBTCprice = 0.0,
        dBTCtoYACprice = 0.0;

    string
        sDestination = "";

    // if the provider is good, which we could use the next time called
    // we could save which one say in a static index, set to 0 initially
    static int
        nIndexBtcToYac = 0,
        nIndexUsdToBtc = 0; // these both assume that the arrays have >= 1 element each!
    static bool
        fCopied = false;
    if( !fCopied )
    {
        initialize_price_vectors( nIndexBtcToYac, nIndexUsdToBtc );
        fCopied = true;
    }

    if (!GetMyExternalWebPage1( nIndexBtcToYac, sDestination, dPriceRatio ) )
    {
#if defined( QT_GUI )
        dPriceRatio = 0.0;
#else
        throw runtime_error( "getYACprice " "Could not get page 1?" );
#endif
        return dUSDperYACprice;
    }
    if (fPrintToConsole) 
    {
        LogPrintf(
                "\n"
                "b/y %.8lf"
                "\n"
                "\n"
                , dPriceRatio
              );
    }

    //else    //OK, now we have YAC/BTC (Cryptsy's terminology), really BTC/YAC
    dBTCtoYACprice = dPriceRatio;
    sDestination = "";
    dPriceRatio = 0.0;
     if (!GetMyExternalWebPage2( nIndexUsdToBtc, sDestination, dPriceRatio ) )
    {
#if defined( QT_GUI )
        dPriceRatio = 0.0;
#else
        throw runtime_error( "getYACprice " "Could not get page 2?" );
#endif
        return dUSDperYACprice;
    }
    // else USD/BTC is OK
    dUSDtoBTCprice = dPriceRatio;

    dUSDperYACprice = dBTCtoYACprice * dUSDtoBTCprice;
    if (fPrintToConsole) 
    {
        LogPrintf(
                "b/y %lf, $/b %lf, $/y = %lf"
                "\n"
                , dBTCtoYACprice
                , dUSDtoBTCprice 
                , dUSDperYACprice
              );
    }
    return dUSDperYACprice;
}

Value getYACprice(const Array& params, bool fHelp)
{
    if (
        fHelp || 
        (0 < params.size())
       )
    {
        throw runtime_error(
            "getyacprice "
            "Returns the current price of YAC in USD"
                           );
    }

    string sTemp;
    try
    {
        double 
            dPrice = doGetYACprice();

        sTemp = strprintf( "%0.8lf", dPrice );
    }
    catch( std::exception &e )
    {
        LogPrintf( "%s\n", (string("error: ") + e.what()));
        sTemp = "";
    }
    catch (...)
    {
        LogPrintf( "%s\n", "unknown error?" );
        sTemp = "";
    }
    return sTemp;
}



Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the difficulty as a multiple of the minimum difficulty.");

    const CBlockIndex
        *pindex = GetLastBlockIndex( chainActive.Tip(), false ); // means PoW block
    uint256
        nTarget = CBigNum().SetCompact( pindex->nBits ).getuint256();

    Object obj;
    obj.push_back(Pair("proof-of-work",        GetDifficulty()));
    obj.push_back(Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(chainActive.Tip(), true))));
    obj.push_back(Pair("search-interval",      (int)nLastCoinStakeSearchInterval));
    obj.push_back(
                  Pair(
                        "target",
                        nTarget.ToString().substr(0,16).c_str() 
                      ) 
                 );
    return obj;
}


Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1 || AmountFromValue(params[0]) < MIN_TX_FEE)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest " + FormatMoney(MIN_TX_FEE));

    nTransactionFee = AmountFromValue(params[0]);
    nTransactionFee = (nTransactionFee / MIN_TX_FEE) * MIN_TX_FEE;  // round to minimum fee

    return true;
}

Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    Array a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}

Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw runtime_error("Block number out of range.");

    CBlockIndex* pblockindex = chainActive[nHeight];
    return pblockindex->phashBlock->GetHex();
}

Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock <hash> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-hash.");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    ReadBlockFromDisk(block, pblockindex, Params().GetConsensus());

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

Value getblocktimes(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
    {
        throw runtime_error(
            "getblocktimes <number of blocks> "
            "Returns a list of block times starting at the latest."
                           );
    }
    int nNumber = params[0].get_int();
    if ((nNumber < 1) || (nNumber > chainActive.Height()))   // maybe better is 2048?
        throw runtime_error("Number of blocks is out of range.");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[ chainActive.Tip()->blockHash ];
    ReadBlockFromDisk(block, pblockindex, Params().GetConsensus());

    uint32_t
        nDelta,
        nTotal = 0,
        nTimeOfBlock = block.GetBlockTime();
    
    Array ret;
    for( int nCount = nNumber; nCount >= 1; --nCount )
    {
        pblockindex = pblockindex->pprev;
        ReadBlockFromDisk(block, pblockindex, Params().GetConsensus());
        nDelta = nTimeOfBlock - block.GetBlockTime();
        ret.push_back( strprintf( "%d", nDelta) );
        nTotal += nDelta;
        nTimeOfBlock = block.GetBlockTime();
    }
    uint32_t
        nAverage = nTotal / nNumber;

    ret.push_back( strprintf( 
                            "%d blocks, average %d sec", 
                            nNumber, 
                            nAverage
                            ) 
                 );

    return ret;
}

Value getblockbynumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblockbynumber <number> [txinfo] "
            "txinfo optional to print more detailed tx info "
            "Returns details of a block with given block-number.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw runtime_error("Block number out of range.");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[chainActive.Tip()->blockHash];
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;

    uint256 hash = *pblockindex->phashBlock;

    pblockindex = mapBlockIndex[hash];
    ReadBlockFromDisk(block, pblockindex, Params().GetConsensus());

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
