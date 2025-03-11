// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2024 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_VALIDATION_H
#define YACOIN_VALIDATION_H

#include "amount.h"
#include "coins.h"
#include "consensus/params.h"
#include "chain.h"
#include "chainparams.h"
#include "fs.h"
#include "protocol.h" // For CMessageHeader::MessageStartChars
#include "policy/feerate.h"
#include "sync.h"
#include "uint256.h"
#include "undo.h"
#include "txmempool.h"
#include "timestamps.h"

#include "addressindex.h"
#include "tokens/tokentypes.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"

#include <algorithm>
#include <exception>
#include <map>
#include <unordered_map>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <atomic>

class CBlockIndex;
class CBlockTreeDB;
class CChainParams;
class CCoinsViewDB;
class CInv;
class CConnman;
class CScriptCheck;
class CBlockPolicyEstimator;
class CTxMemPool;
class CValidationState;
struct LockPoints;
class CChain;

/** Headers download timeout expressed in microseconds
 *  Timeout = base + per_header * (expected number of headers) */
extern int64_t HEADERS_DOWNLOAD_TIMEOUT_BASE; // 15 minutes
extern int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE; // 15 minutes
// For YACoin, we don't use this constant because we will reset the timeout at the time we receive the header
//static const int64_t HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER = 1000; // 1ms/header
/** Additional block download timeout per parallel downloading peer (i.e. 5 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 500000;
/** Timeout in seconds during which a peer must stall block download progress before being disconnected. */
static const unsigned int BLOCK_STALLING_TIMEOUT = 2;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached their tip. Changing this value is a protocol upgrade. */
static unsigned int MAX_HEADERS_RESULTS = 2000;
/** Number of blocks that can be requested at any given time from a single peer. */
extern int MAX_BLOCKS_IN_TRANSIT_PER_PEER;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
extern unsigned int BLOCK_DOWNLOAD_WINDOW; //32000
extern unsigned int FETCH_BLOCK_DOWNLOAD; //4000
// Trigger sending getblocks from other peers when header > block + HEADER_BLOCK_DIFFERENCES_TRIGGER_GETDATA
extern unsigned int HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS; //default = 10000
extern int64_t nMaxTipAge;

/** Maximum depth of blocks we're willing to serve as compact blocks to peers
 *  when requested. For older blocks, a regular BLOCK response will be sent. */
static const int MAX_CMPCTBLOCK_DEPTH = 5;

/** Time to wait (in seconds) between writing blocks/block index to disk. */
static const unsigned int DATABASE_WRITE_INTERVAL = 60 * 60; // 60 * 60 for Bitcoin
/** Time to wait (in seconds) between flushing chainstate to disk. */
static const unsigned int DATABASE_FLUSH_INTERVAL = 60 * 60; // 24 * 60 * 60 for Bitcoin
/** Time to wait (in seconds) between flushing to database if in initial block sync interval */
static const unsigned int DATABASE_FLUSH_INTERVAL_INITIAL_SYNC = 10 * 60;

/** Maximum number of headers to announce when relaying blocks with headers message.*/
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;

/** Maximum number of unconnecting headers announcements before DoS score */
static const int MAX_UNCONNECTING_HEADERS = 10;
/** Maximum length of reject messages. */
static const unsigned int MAX_REJECT_MESSAGE_LENGTH = 111;
/** Reject codes greater or equal to this can be returned by AcceptToMemPool
 * for transactions, to signal internal conditions. They cannot and should not
 * be sent over the P2P network.
 */
static const unsigned int REJECT_INTERNAL = 0x100;
/** Too high fee. Can not be triggered by P2P transactions */
static const unsigned int REJECT_HIGHFEE = 0x100;

/** Default for DEFAULT_WHITELISTRELAY. */
static const bool DEFAULT_WHITELISTRELAY = true;
/** Default for DEFAULT_WHITELISTFORCERELAY. */
static const bool DEFAULT_WHITELISTFORCERELAY = true;

/** The maximum size of a blk?????.dat file (since 1.5.0) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 1.5.0) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 1.5.0) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB

/** Average delay between local address broadcasts in seconds. */
static const unsigned int AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24 * 60 * 60;
/** Average delay between peer address broadcasts in seconds. */
static const unsigned int AVG_ADDRESS_BROADCAST_INTERVAL = 30;

/** Average delay between trickled inventory transmissions in seconds.
 *  Blocks and whitelisted receivers bypass this, outbound peers get half this delay. */
static const unsigned int INVENTORY_BROADCAST_INTERVAL = 5;
/** Maximum number of inventory items to send per transmission.
 *  Limits the impact of low-fee transaction floods. */
static const unsigned int INVENTORY_BROADCAST_MAX = 7 * INVENTORY_BROADCAST_INTERVAL;

static const int64_t DEFAULT_MAX_TIP_AGE = 24 * 60 * 60;

static const bool DEFAULT_CHECKPOINTS_ENABLED = true;
static const bool DEFAULT_TXINDEX = true; // ppcoin: txindex is required for PoS calculations (might change in the future)
static const bool DEFAULT_TOKENINDEX = false;
static const bool DEFAULT_ADDRESSINDEX = false;
static const bool DEFAULT_BLOCKHASHINDEX = true; // yac: blockhashindex is necessary to avoid recalculating block hash (very slow !!!) when reading block data from disk

/** Default for -stopatheight */
static const int DEFAULT_STOPATHEIGHT = 0;

struct BlockHasher
{
    size_t operator()(const uint256& hash) const { return hash.GetCheapHash(); }
};

/**
 * Global state
 */
extern size_t nCoinCacheUsage;
extern CCriticalSection cs_main;
extern CCriticalSection cs_vpwalletRegistered;
extern std::vector<CWallet*> vpwalletRegistered;
typedef std::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;
extern BlockMap mapBlockIndex;
/** The currently-connected chain of blocks (protected by cs_main). */
extern CChain chainActive;
// Best header we've seen so far (used for getheaders queries' starting points).
extern CBlockIndex *pindexBestHeader;
extern bool fReindex;
extern bool fTxIndex;
extern bool fRequireStandard;
extern bool fCheckBlockIndex;
extern bool fCheckpointsEnabled;
extern bool fBlockHashIndex;
extern ::uint32_t nMinEase; // minimum ease corresponds to highest difficulty
extern ::int64_t nBlockRewardPrev;

// Mempool
extern CTxMemPool mempool;
extern uint256 hashBestChain;

/** Global variable that points to the coins database (protected by cs_main) */
extern CCoinsViewDB *pcoinsdbview;

/** Global variable that points to the active CCoinsView (protected by cs_main) */
extern CCoinsViewCache *pcoinsTip;

/** Global variable that points to the active block tree (protected by cs_main) */
extern CBlockTreeDB *pblocktree;

// Wallet
extern CCriticalSection cs_vpwalletRegistered;
extern std::vector<CWallet*> vpwalletRegistered;

//
// GLOBAL VARIABLES USED FOR TOKEN MANAGEMENT SYSTEM
//
/** Global variable that point to the active tokens database (protected by cs_main) */
extern CTokensDB *ptokensdb;

/** Global variable that point to the active tokens (protected by cs_main) */
extern CTokensCache *ptokens;

/** Global variable that point to the tokens metadata LRU Cache (protected by cs_main) */
extern CLRUCache<std::string, CDatabasedTokenData> *ptokensCache;
extern bool fTokenIndex;
extern bool fAddressIndex;
//
// END OF GLOBAL VARIABLES USED FOR TOKEN MANAGEMENT SYSTEM
//

const double nInflation = 0.02; // 2%
const ::uint32_t
    nAverageBlocksPerMinute = 1,
    nNumberOfDaysPerYear = 365,
    nNumberOfBlocksPerYear =
        (nAverageBlocksPerMinute * nMinutesperHour * nHoursPerDay *
         nNumberOfDaysPerYear) + // that 1/4 of a day for leap years
        (nAverageBlocksPerMinute * nMinutesperHour * (nHoursPerDay / 4));

/** Block files containing a block-height within MIN_BLOCKS_TO_KEEP of chainActive.Tip() will not be pruned. */
static const unsigned int MIN_BLOCKS_TO_KEEP = 288;

/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * If you want to *possibly* get feedback on whether pblock is valid, you must
 * install a CValidationInterface (see validationinterface.h) - this will have
 * its BlockChecked method called whenever *any* block completes validation.
 *
 * Note that we guarantee that either the proof-of-work is valid on pblock, or
 * (and possibly also) BlockChecked will have been called.
 *
 * Call without cs_main held.
 *
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and whitelisted peers.
 * @param[out]  fNewBlock A boolean which is set to indicate if the block was first received via this call
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool* fNewBlock);

/**
 * Process incoming block headers.
 *
 * Call without cs_main held.
 *
 * @param[in]  block The block headers themselves
 * @param[out] state This may be set to an Error state if any error occurred processing them
 * @param[in]  chainparams The params for the chain we want to connect to
 * @param[out] ppindex If set, the pointer will be set to point to the last new block index object for the given headers
 * @param[out] first_invalid First header that fails validation, if one exists
 */
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& block, CValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex=nullptr, CBlockHeader *first_invalid=nullptr);

/** Check whether enough disk space is available for an incoming block */
bool CheckDiskSpace(uint64_t nAdditionalBytes = 0);
/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);
/** Ensures we have a genesis block in the block tree, possibly writing one to disk. */
bool LoadGenesisBlock(const CChainParams& chainparams);
/** Load the block tree and coins database from disk,
 * initializing state if we're running with -reindex. */
bool LoadBlockIndex(const CChainParams& chainparams);
/** Update the chain tip based on database information. */
bool LoadChainTip(const CChainParams& chainparams);
/** Unload database information */
void UnloadBlockIndex();
/** Check whether we are doing an initial block download (synchronizing from disk or network) */
bool IsInitialBlockDownload();
/** Find the best known block, and make it the tip of the block chain */
bool ActivateBestChain(CValidationState& state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());

/** Guess verification progress (as a fraction between 0.0=genesis and 1.0=current tip). */
double GuessVerificationProgress(const ChainTxData& data, CBlockIndex* pindex);

/** Create a new block index entry for a given block hash */
CBlockIndex* InsertBlockIndex(uint256 hash);
/** Flush all state, indexes and buffers to disk. */
void FlushStateToDisk();

/** (try to) add transaction to memory pool
 * plTxnReplaced will be appended to with all transactions replaced from mempool **/
bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx, bool* pfMissingInputs);

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state);

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo& txundo, int nHeight, uint256 blockHash, CTokensCache* tokenCache = nullptr, std::pair<std::string, CBlockTokenUndo>* undoTokenData = nullptr);

/** Transaction validation functions */

/**
 * Check if transaction will be final in the next block to be created.
 *
 * Calls IsFinalTx() with current block height and appropriate block time.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckFinalTx(const CTransaction &tx, int flags = -1);

/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 *
 * Simulates calling SequenceLocks() with data from the tip of the current active chain.
 * Optionally stores in LockPoints the resulting height and time calculated and the hash
 * of the block needed for calculation or skips the calculation and uses the LockPoints
 * passed in for evaluation.
 * The LockPoints should not be considered valid if CheckSequenceLocks returns false.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp = nullptr, bool useExistingLockPoints = false);

/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction
 */
class CScriptCheck
{
private:
    CScript scriptPubKey;
    const CTransaction *ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    int nHashType;

public:
    CScriptCheck(): ptxTo(0), nIn(0), nFlags(0), nHashType(0) {}
    CScriptCheck(const CTransaction& txFromIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, int nHashTypeIn) :
        scriptPubKey(txFromIn.vout[txToIn.vin[nInIn].prevout.COutPointGet_n()].scriptPubKey),
        ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), nHashType(nHashTypeIn) { }
    CScriptCheck(const CScript& scriptPubKeyIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, int nHashTypeIn) :
        scriptPubKey(scriptPubKeyIn), ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), nHashType(nHashTypeIn) { }

    bool operator()();

    void swap(CScriptCheck &check) {
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(nHashType, check.nHashType);
    }
};

/** Functions for disk access for blocks */
bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams);

/** Functions for validating blocks and updating the block tree */

/** Context-independent validity checks */
bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW=true, bool fCheckMerkleRoot=true, bool fCheckSig=true);

/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB {
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(CCoinsView *coinsview, int nCheckLevel, int nCheckDepth);
};

/** Replay blocks that aren't fully applied to the database. */
bool ReplayBlocks(const CChainParams& params, CCoinsView* view);

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by cs_main)
 * This is also true for mempool checks.
 */
int GetSpendHeight(const CCoinsViewCache& inputs);

bool AbortNode(const std::string &msg);

//
// FUNCTIONS USED FOR TOKEN MANAGEMENT SYSTEM
//
/** Flush all state, indexes and buffers to disk. */
bool FlushTokenToDisk();
bool AreTokensDeployed();
CTokensCache* GetCurrentTokenCache();
bool CheckTxTokens(
    const CTransaction& tx, CValidationState& state, MapPrevTx inputs,
    CTokensCache* tokenCache, bool fCheckMempool,
    std::vector<std::pair<std::string, uint256> >& vPairReissueTokens);
void UpdateTokenInfo(const CTransaction& tx, MapPrevTx& prevInputs, int nHeight, uint256 blockHash, CTokensCache* tokensCache, std::pair<std::string, CBlockTokenUndo>* undoTokenData);
void UpdateTokenInfoFromTxInputs(const COutPoint& out, const CTxOut& txOut, CTokensCache* tokensCache);
void UpdateTokenInfoFromTxOutputs(const CTransaction& tx, int nHeight, uint256 blockHash, CTokensCache* tokensCache, std::pair<std::string, CBlockTokenUndo>* undoTokenData);
bool GetAddressIndex(uint160 addressHash, int type, std::string tokenName,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                     int start = 0, int end = 0);
bool GetAddressIndex(uint160 addressHash, int type,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                     int start = 0, int end = 0);
bool GetAddressUnspent(uint160 addressHash, int type, std::string tokenName,
                       std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs);
bool GetAddressUnspent(uint160 addressHash, int type,
                       std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs);
//
// END OF FUNCTIONS USED FOR TOKEN MANAGEMENT SYSTEM
//

// ppcoin:
bool GetCoinAge(const CTransaction& tx, const CCoinsViewCache &view, uint64_t& nCoinAge); // ppcoin: get transaction coin age
extern void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false, bool fConnect = true);
#endif // YACOIN_VALIDATION_H
