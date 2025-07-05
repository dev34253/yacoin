// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "validation.h"
#include "miner.h"
#include "net.h"
#include "policy/fees.h"
#include "pow.h"
#include "rpc/blockchain.h"
#include "rpc/mining.h"
#include "rpc/server.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "warnings.h"
#include "wallet/rpcwallet.h"

#include <memory>
#include <stdint.h>

#include <univalue.h>

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
            nTargetSpacingWork = std::max(nTargetSpacingWork, nTargetSpacingWorkMin);
            pindexPrevWork = pindex;
        }

        pindex = chainActive.Next(pindex);
    }

    return GetDifficulty() * 4294.967296 / nTargetSpacingWork;
}

UniValue gethashespersec(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "gethashespersec\n"
            "Returns a recent hashes per second performance measurement averaged over 30 seconds while generating.");

    if (GetTimeMillis() - nHPSTimerStart > 30000)
       return (int64_t)dHashesPerSec;
    return (int64_t)0;
}

UniValue getgenerate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getgenerate\n"
            "\nReturn if the server is set to generate coins or not. The default is false.\n"
            "It is set with the command line argument -gen (or " + std::string(YACOIN_CONF_FILENAME) + " setting gen)\n"
            "It can also be set with the setgenerate call.\n"
            "\nResult\n"
            "true|false      (boolean) If the server is set to generate coins or not\n"
            "\nExamples:\n"
            + HelpExampleCli("getgenerate", "")
            + HelpExampleRpc("getgenerate", "")
        );

    LOCK(cs_main);
    return gArgs.GetBoolArg("-gen", DEFAULT_GENERATE);
}

UniValue setgenerate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "setgenerate generate ( genproclimit )\n"
            "\nSet 'generate' true or false to turn generation on or off.\n"
            "Generation is limited to 'genproclimit' processors, -1 is unlimited.\n"
            "See the getgenerate call for the current setting.\n"
            "\nArguments:\n"
            "1. generate         (boolean, required) Set to true to turn on generation, false to turn off.\n"
            "2. genproclimit     (numeric, optional) Set the processor limit for when generation is on. Can be -1 for unlimited.\n"
            "\nExamples:\n"
            "\nSet the generation on with a limit of one processor\n"
            + HelpExampleCli("setgenerate", "true 1") +
            "\nCheck the setting\n"
            + HelpExampleCli("getgenerate", "") +
            "\nTurn off generation\n"
            + HelpExampleCli("setgenerate", "false") +
            "\nUsing json rpc\n"
            + HelpExampleRpc("setgenerate", "true, 1")
        );

    bool fGenerate = true;
    if (request.params.size() > 0)
        fGenerate = request.params[0].get_bool();

    int nGenProcLimit = gArgs.GetArg("-genproclimit", DEFAULT_GENERATE_THREADS);
    if (request.params.size() > 1)
    {
        nGenProcLimit = request.params[1].get_int();
        if (nGenProcLimit == 0)
            fGenerate = false;
    }

    gArgs.ForceSetArg("-gen", (fGenerate ? "1" : "0"));
    gArgs.ForceSetArg("-genproclimit", itostr(nGenProcLimit));
    int numCores = GenerateYacoins(fGenerate, nGenProcLimit);

    nGenProcLimit = nGenProcLimit >= 0 ? nGenProcLimit : numCores;
    std::string msg = std::to_string(nGenProcLimit) + " of " + std::to_string(numCores);
    return msg;
}

UniValue getsubsidy(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getsubsidy [nTarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");

    unsigned int nBits = 0;

    if (request.params.size() != 0)
    {
        CBigNum bnTarget(uint256(request.params[0].get_str()));
        nBits = bnTarget.GetCompact();
    }
    else
    {
        nBits = GetNextTargetRequired(chainActive.Tip(), false);
    }

    return GetProofOfWorkReward(nBits, 0, chainActive.Height() + 1);
}

UniValue generateBlocks(std::shared_ptr<CReserveScript> coinbaseScript, int nGenerate, uint64_t nMaxTries, bool keepScript)
{
    static const int nInnerLoopCount = 0x10000;
    int nHeightEnd = 0;
    int nHeight = 0;

    {   // Don't keep cs_main locked
        LOCK(cs_main);
        nHeight = chainActive.Height();
        nHeightEnd = nHeight+nGenerate;
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);
    while (nHeight < nHeightEnd)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler().CreateNewBlock(coinbaseScript->reserveScript));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, chainActive.Tip(), nExtraNonce);
        }
        while (nMaxTries > 0 && pblock->nNonce < nInnerLoopCount && !CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) {
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0) {
            break;
        }
        if (pblock->nNonce == nInnerLoopCount) {
            continue;
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight;
        blockHashes.push_back(pblock->GetHash().GetHex());

        //mark script as important because it was used at least for one coinbase output if the script came from the wallet
        if (keepScript)
        {
            coinbaseScript->KeepScript();
        }
    }
    return blockHashes;
}

//UniValue generatetoaddress(const JSONRPCRequest& request)
//{
//    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
//        throw std::runtime_error(
//            "generatetoaddress nblocks address (maxtries)\n"
//            "\nMine blocks immediately to a specified address (before the RPC call returns)\n"
//            "\nArguments:\n"
//            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
//            "2. address      (string, required) The address to send the newly generated bitcoin to.\n"
//            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
//            "\nResult:\n"
//            "[ blockhashes ]     (array) hashes of blocks generated\n"
//            "\nExamples:\n"
//            "\nGenerate 11 blocks to myaddress\n"
//            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
//        );
//
//    int nGenerate = request.params[0].get_int();
//    uint64_t nMaxTries = 1000000;
//    if (!request.params[2].isNull()) {
//        nMaxTries = request.params[2].get_int();
//    }
//
//    CBitcoinAddress address(request.params[1].get_str());
//    if (!address.IsValid())
//        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
//
//    std::shared_ptr<CReserveScript> coinbaseScript = std::make_shared<CReserveScript>();
//    coinbaseScript->reserveScript = GetScriptForDestination(address.Get());
//
//    return generateBlocks(coinbaseScript, nGenerate, nMaxTries, false);
//}

UniValue generatetoaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0 || request.params.size() > 3)
            throw std::runtime_error(
                "generatetoaddress\n"
                "nblocks - How many blocks are generated immediately.\n"
                "address - The address to send the newly generated bitcoin to.\n"
                "maxtries - How many iterations to try.");

    int nblocks = request.params[0].get_int();
    uint64_t nMaxTries = 1000000;
    if (!request.params[2].isNull()) {
        nMaxTries = request.params[2].get_int();
    }

    CBitcoinAddress address(request.params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    
    UniValue res(UniValue::VARR);

    gArgs.ForceSetArg("-gen", "1");
    gArgs.ForceSetArg("-genproclimit", "1");
    GenerateYacoins(true, 1, nblocks);
    gArgs.ForceSetArg("-gen", "0");
    return res;
}

UniValue getmininginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblockweight\": nnn, (numeric) The last block weight\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"errors\": \"...\"            (string) Current errors\n"
            "  \"networkhashps\": nnn,      (numeric) The network hashes per second\n"
            "  \"pooledtx\": n              (numeric) The size of the mempool\n"
            "  \"chain\": \"xxxx\",           (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
        );


    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("blocks",           (int)chainActive.Height()));
    obj.push_back(Pair("currentblocksize",(uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",   (uint64_t)nLastBlockTx));
    obj.push_back(Pair("difficulty",       (double)GetDifficulty()));

    uint64_t blockvalue=(uint64_t)GetProofOfWorkReward(GetLastBlockIndex(chainActive.Tip(), false)->nBits, 0, chainActive.Height());
    obj.push_back(Pair("blockvalue", blockvalue)); // for testing purposes, easier to compare than float
    obj.push_back(Pair("powreward", (double)blockvalue / 1000000.0));
    obj.push_back(Pair("netmhashps",     GetPoWMHashPS()));
    obj.push_back(Pair("errors",           GetWarnings("statusbar")));
    obj.push_back(Pair("generate",      gArgs.GetBoolArg("-gen")));
    obj.push_back(Pair("genproclimit",  (int)gArgs.GetArg("-genproclimit", -1)));
    obj.push_back(Pair("hashespersec",  gethashespersec(request)));
    obj.push_back(Pair("pooledtx",         (uint64_t)mempool.size()));
    obj.push_back(Pair("chain",            Params().NetworkIDString()));

    // WM - Tweaks to report current Nfactor and N.
    unsigned char Nfactor = GetNfactor(chainActive.Tip()->GetBlockTime(), chainActive.Height() >= nMainnetNewLogicBlockNumber? true : false);
    uint64_t N = 1 << ( Nfactor + 1 );
    obj.push_back( Pair( "Nfactor", Nfactor ) );
    obj.push_back( Pair( "N", (uint64_t)N ) );
    obj.push_back( Pair( "Epoch Interval", (uint64_t)nEpochInterval ) );
    obj.push_back( Pair( "Difficulty Interval", (uint64_t)nDifficultyInterval ) );
    return obj;
}

UniValue getwork(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Yacoin is downloading blocks...");

    typedef std::map<uint256, std::pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
    static CReserveKey reservekey(pwallet);
    std::shared_ptr<CReserveScript> coinbase_script;
    pwallet->GetScriptForMining(coinbase_script);

    if (request.params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static std::unique_ptr<CBlockTemplate> pblocktemplate;
        unsigned int nTransactionsUpdated = mempool.GetTransactionsUpdated();

        if ((pindexPrev != chainActive.Tip())
            || (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
            || (GetTime() - nStart > nMaxClockDrift*0.75)
            )
        {
            if (pindexPrev != chainActive.Tip())
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = NULL;

            // Store the chainActive.Tip() used before CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = nTransactionsUpdated;
            CBlockIndex* pindexPrevNew = chainActive.Tip();
            nStart = GetTime();

            // Create new block
            pblocktemplate = BlockAssembler().CreateNewBlock(coinbase_script->reserveScript);
            if (!pblocktemplate.get())
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");

            // Need to update only after we know CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }
        CBlock* pblock = &pblocktemplate->block; // pointer for convenience
        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = std::make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        LogPrintf("rpc getwork,\n"
               "params.size() == 0,\n"
               "pblock->nVersion = %d,\n"
               "pblock->hashPrevBlock = %s,\n"
               "pblock->hashMerkleRoot = %s,\n"
               "pblock->nTime = %lld,\n"
               "pblock->nBits = %u,\n"
               "pblock->nNonce = %u\n",
               pblock->nVersion, pblock->hashPrevBlock.ToString(), pblock->hashMerkleRoot.ToString(),
               pblock->nTime, pblock->nBits, pblock->nNonce);

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        if (pblock->nVersion >= VERSION_of_block_for_yac_05x_new)
        {
            FormatHashBuffers_64bit_nTime((char*)pblock, pmidstate, pdata, phash1);
        }
        else
        {
            FormatHashBuffers(pblock, pmidstate, pdata, phash1);
        }

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        UniValue result(UniValue::VOBJ);
        result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

        return result;
    }
    else
    {
        // Parse parameters
        std::vector<unsigned char> vchData = ParseHex(request.params[0].get_str());

        if (vchData.size() != 128)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }

        struct block_header* pdata = (struct block_header*)&vchData[0];

        // Byte reverse
        for (unsigned int i = 0; i < 128/sizeof( uint32_t ); ++i)
      //for (int i = 0; i < 128/4; i++) //really, the limit is sizeof( *pdata ) / sizeof( uint32_t
            ((uint32_t *)pdata)[i] = ByteReverse(((uint32_t *)pdata)[i]);

        LogPrintf("rpc getwork,\n"
               "params.size() != 0,\n"
               "pdata->nVersion = %d,\n"
               "pdata->hashPrevBlock = %s,\n"
               "pdata->hashMerkleRoot = %s,\n"
               "pdata->nTime = %lld,\n"
               "pdata->nBits = %u,\n"
               "pdata->nNonce = %u\n",
               pdata->version, pdata->prev_block.ToString(), pdata->merkle_root.ToString(),
               pdata->timestamp, pdata->bits, pdata->nonce);

        // Get saved block
        if (!mapNewBlock.count(pdata->merkle_root))
        {
            LogPrintf("rpc getwork, No saved block\n");
            return false;
        }

        CBlock* pblock = mapNewBlock[pdata->merkle_root].first;

        // Parse nTime based on block version
        if (pblock->nVersion >= VERSION_of_block_for_yac_05x_new)
        {
            pblock->nTime = pdata->timestamp;
            pblock->nNonce = pdata->nonce;
        }
        else
        {
            pblock->nTime = ((uint32_t *)pdata)[17];
            pblock->nNonce = ((uint32_t *)pdata)[19];
        }
        pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->merkle_root].second;

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        if (!pblock->SignBlock(*pwallet))
        {
            LogPrintf("rpc getwork, Unable to sign block\n");
            throw JSONRPCError(-100, "Unable to sign block, wallet locked?");
        }
        
        return CheckWork(pblock, *pwallet, reservekey);
    }
}

UniValue getblocktemplate(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::string strMode = "template";
    if (request.params.size() > 0)
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Yacoin is downloading blocks...");

    static CReserveKey reservekey(pwallet);
    std::shared_ptr<CReserveScript> coinbase_script;
    pwallet->GetScriptForMining(coinbase_script);

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;
    unsigned int nTransactionsUpdated = mempool.GetTransactionsUpdated();

    if (pindexPrev != chainActive.Tip() ||
        (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the chainActive.Tip() used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrevNew = chainActive.Tip();
        nStart = GetTime();

        pblocktemplate = BlockAssembler().CreateNewBlock(coinbase_script->reserveScript);
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience
    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for(CTransaction& tx : pblock->vtx)
    {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() || tx.IsCoinStake())
            continue;

        UniValue entry(UniValue::VOBJ);

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));
        entry.push_back(Pair("hash", txHash.GetHex()));

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.push_back(Pair("depends", deps));

        int index_in_template = i - 1;
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template]));
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        entry.push_back(Pair("sigops", nTxSigOps));
        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (uint64_t)GetMaxSize(MAX_BLOCK_SIGOPS)));
    result.push_back(Pair("sizelimit", (uint64_t)GetMaxSize(MAX_BLOCK_SIZE)));
    result.push_back(Pair("curtime", (int64_t)pblock->nTime));
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));

    return result;
}

UniValue submitblock(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::vector<unsigned char> blockData(ParseHex(request.params[0].get_str()));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    try {
        ssBlock >> block;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }
    while (pwallet->IsLocked())
    {
        //strMintWarning = strMintMessage;
        Sleep(nMillisecondsPerSecond);
    }

    if (!block.SignBlock(*pwallet))
        throw JSONRPCError(-100, "Unable to sign block, wallet locked?");

    bool fAccepted = ProcessNewBlock(Params(), blockptr, true, nullptr);
    if (!fAccepted)
        return "rejected";

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "gethashespersec",        &gethashespersec,        true,   {} },
    { "mining",             "getmininginfo",          &getmininginfo,          true,  {} },
    { "mining",             "getblocktemplate",       &getsubsidy,             true,  {"nTarget"} },
    { "mining",             "submitblock",            &getwork,                true,  {"data"} },
    { "mining",             "getblocktemplate",       &getblocktemplate,       true,  {"template_request"} },
    { "mining",             "submitblock",            &submitblock,            true,  {"hexdata","dummy"} },

    /* Coin generation */
    { "generating",         "getgenerate",            &getgenerate,            true, {}  },
    { "generating",         "setgenerate",            &setgenerate,            true, {"generate", "genproclimit"}  },
    { "generating",         "generatetoaddress",      &generatetoaddress,      true,  {"nblocks","address","maxtries"} },
};

void RegisterMiningRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
