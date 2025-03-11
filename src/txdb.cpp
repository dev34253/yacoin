// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
#include <stdint.h>

#include "msvc_warnings.push.h"
#endif

#include "txdb.h"
#include "hash.h"
#include "random.h"
#include "uint256.h"
#include "util.h"
#include "ui_interface.h"
#include "init.h"

#include "addressindex.h"
#include "checkpoints.h"
#include "kernel.h"
#include "streams.h"
#include "net_processing.h"

#include <map>
#include <string>
#include <vector>
#include <stdint.h>
#include <boost/thread.hpp>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <memenv.h>

using std::make_pair;
using std::map;
using std::pair;
using std::runtime_error;
using std::string;
using std::vector;

// Keys of Block index database (blocks/index/*)
static const char DB_BLOCK_FILES = 'f'; // File information record. Keeps track of the files storing the raw block data (blk????.dat), their sizes, and other related metadata
static const char DB_BLOCK_INDEX = 'b'; // Block index record. Stores metadata about blocks, such as block headers, height, and status
static const char DB_TXINDEX = 't';     // Transaction index record. Stores transaction information to enable fast lookups of transactions by their IDs
static const char DB_FLAG = 'F';        // Currently defined flags include: 'txindex': Whether the transaction index is enabled.
static const char DB_REINDEX_FLAG = 'R';    // whether we're in the process of reindexing.
static const char DB_LAST_BLOCK = 'l';      // The last block file number used
static const char DB_ADDRESSINDEX = 'a';
static const char DB_ADDRESSUNSPENTINDEX = 'u';

// Keys of UTXO set database (chainstate/*)
static const char DB_COIN = 'C';        // UTXO record
static const char DB_BEST_BLOCK = 'B';  // Primarily used to ensures the UTXO set is consistently persisted with the blockchain state
                                        // Tracks the latest block to which the UTXO set is flushed
                                        // Ensures the UTXO set's state corresponds to a specific block in the chain.
                                        // During shutdown or periodic flushing, DB_BEST_BLOCK ensures that the UTXO set on disk corresponds to a consistent state of the blockchain
static const char DB_HEAD_BLOCKS = 'H'; // Primarily used for chain synchronization
                                        // Tracks the latest block of the best chain for chain synchronization
                                        // Helps the node resume syncing from the most recent block
                                        // When a node starts up, it checks DB_HEAD_BLOCKS to know where to resume block synchronization.

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    char key;
    CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe, true)
{
}

bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    return db.Read(CoinEntry(&outpoint), coin);
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return db.Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!db.Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) {
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    size_t batch_size = (size_t)gArgs.GetArg("-dbbatchsize", nDefaultDbBatchSize);
    int crash_simulate = gArgs.GetArg("-dbcrashratio", 0);
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, std::vector<uint256>{hashBlock, old_tip});

    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            CoinEntry entry(&it->first);
            if (it->second.coin.IsSpent())
                batch.Erase(entry);
            else
                batch.Write(entry, it->second.coin);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
        if (batch.SizeEstimate() > batch_size) {
            LogPrint(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
            db.WriteBatch(batch);
            batch.Clear();
            if (crash_simulate) {
                static FastRandomContext rng;
                if (rng.randrange(crash_simulate) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    LogPrint(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
    bool ret = db.WriteBatch(batch);
    LogPrint(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return db.EstimateSize(DB_COIN, (char)(DB_COIN+1));
}


CCoinsViewCursor *CCoinsViewDB::Cursor() const
{
    CCoinsViewDBCursor *i = new CCoinsViewDBCursor(const_cast<CDBWrapper&>(db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    return pcursor->GetValue(coin);
}

unsigned int CCoinsViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}

//! Legacy class to deserialize pre-pertxout database entries without reindex.
class CCoins
{
public:
    //! whether transaction is a coinbase
    bool fCoinBase;

    //! unspent transaction outputs; spent outputs are .IsNull(); spent outputs at the end of the array are dropped
    std::vector<CTxOut> vout;

    //! at which height this transaction was included in the active block chain
    int nHeight;

    //! empty constructor
    CCoins() : fCoinBase(false), vout(0), nHeight(0) { }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        // version
        int nVersionDummy;
        ::Unserialize(s, VARINT(nVersionDummy));
        // header code
        ::Unserialize(s, VARINT(nCode));
        fCoinBase = nCode & 1;
        std::vector<bool> vAvail(2, false);
        vAvail[0] = (nCode & 2) != 0;
        vAvail[1] = (nCode & 4) != 0;
        unsigned int nMaskCode = (nCode / 8) + ((nCode & 6) != 0 ? 0 : 1);
        // spentness bitmask
        while (nMaskCode > 0) {
            unsigned char chAvail = 0;
            ::Unserialize(s, chAvail);
            for (unsigned int p = 0; p < 8; p++) {
                bool f = (chAvail & (1 << p)) != 0;
                vAvail.push_back(f);
            }
            if (chAvail != 0)
                nMaskCode--;
        }
        // txouts themself
        vout.assign(vAvail.size(), CTxOut());
        for (unsigned int i = 0; i < vAvail.size(); i++) {
            if (vAvail[i])
                ::Unserialize(s, REF(CTxOutCompressor(vout[i])));
        }
        // coinbase height
        ::Unserialize(s, VARINT(nHeight));
    }
};

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe) {
}

bool CBlockTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(std::make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CBlockTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int &nFile) {
    return Read(DB_LAST_BLOCK, nFile);
}

bool CBlockTreeDB::ReadTxIndex(const uint256 &txid, CDiskTxPos &pos) {
    return Read(std::make_pair(DB_TXINDEX, txid), pos);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<uint256,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(std::make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::UpdateAddressUnspentIndex(const std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue > >&vect) {
    bool result = true;
    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        if (it->second.IsNull()) {
            result = Erase(std::make_pair(DB_ADDRESSUNSPENTINDEX, it->first));
        } else {
            result = Write(std::make_pair(DB_ADDRESSUNSPENTINDEX, it->first), it->second);
        }

        if (!result)
        {
            break;
        }
    }
    return result;
}

bool CBlockTreeDB::ReadAddressUnspentIndex(uint160 addressHash, int type, std::string tokenName,
                                           std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorTokenKey(type, addressHash, tokenName)));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressUnspentKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSUNSPENTINDEX && key.second.hashBytes == addressHash
                && (tokenName.empty() || key.second.token == tokenName)) {
            CAddressUnspentValue nValue;
            if (pcursor->GetValue(nValue)) {
                unspentOutputs.push_back(std::make_pair(key.second, nValue));
                pcursor->Next();
            } else {
                return error("failed to get address unspent value");
            }
        } else {
            break;
        }
    }

    return true;
}

bool CBlockTreeDB::ReadAddressUnspentIndex(uint160 addressHash, int type,
                                           std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorKey(type, addressHash)));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressUnspentKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSUNSPENTINDEX && key.second.hashBytes == addressHash) {
            CAddressUnspentValue nValue;
            if (pcursor->GetValue(nValue)) {
                if (key.second.token != "YAC") {
                    unspentOutputs.push_back(std::make_pair(key.second, nValue));
                }
                pcursor->Next();
            } else {
                return error("failed to get address unspent value");
            }
        } else {
            break;
        }
    }

    return true;
}


bool CBlockTreeDB::WriteAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount > >&vect) {
    bool result = true;
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
    {
        result = Write(std::make_pair(DB_ADDRESSINDEX, it->first), it->second);
        if (!result)
        {
            break;
        }
    }
    return result;
}

bool CBlockTreeDB::EraseAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount > >&vect) {
    bool result = true;
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
    {
        result = Erase(std::make_pair(DB_ADDRESSINDEX, it->first));
        if (!result)
        {
            break;
        }
    }

    return result;
}

bool CBlockTreeDB::ReadAddressIndex(uint160 addressHash, int type, std::string tokenName,
                                    std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                                    int start, int end) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    if (!tokenName.empty() && start > 0 && end > 0) {
        pcursor->Seek(std::make_pair(DB_ADDRESSINDEX,
                                     CAddressIndexIteratorHeightKey(type, addressHash, tokenName, start)));
    } else if (!tokenName.empty()) {
        pcursor->Seek(std::make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorTokenKey(type, addressHash, tokenName)));
    } else {
        pcursor->Seek(std::make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorKey(type, addressHash)));
    }

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressIndexKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSINDEX && key.second.hashBytes == addressHash
                && (tokenName.empty() || key.second.token == tokenName)) {
            if (end > 0 && key.second.blockHeight > end) {
                break;
            }
            CAmount nValue;
            if (pcursor->GetValue(nValue)) {
                addressIndex.push_back(std::make_pair(key.second, nValue));
                pcursor->Next();
            } else {
                return error("failed to get address index value");
            }
        } else {
            break;
        }
    }

    return true;
}

bool CBlockTreeDB::ReadAddressIndex(uint160 addressHash, int type,
                                    std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                                    int start, int end) {

    return CBlockTreeDB::ReadAddressIndex(addressHash, type, "", addressIndex, start, end);
}


bool CBlockTreeDB::WriteFlag(const std::string &name, bool fValue) {
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string &name, bool &fValue) {
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts(const Consensus::Params& consensusParams, std::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_BLOCK_INDEX, uint256()));

    int newStoredBlock = 0;
    int alreadyStoredBlock = 0;

    // Load mapBlockIndex
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct block index object
                uint256 blockHash = diskindex.GetBlockHash(); // the slow poke!
                CBlockIndex* pindexNew = insertBlockIndex(blockHash);
                pindexNew->pprev          = insertBlockIndex(diskindex.hashPrev);
                pindexNew->nHeight        = diskindex.nHeight;
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->nBits          = diskindex.nBits;
                pindexNew->nNonce         = diskindex.nNonce;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nTx            = diskindex.nTx;

                // Specific for YAC
                pindexNew->nMint = diskindex.nMint;
                pindexNew->nMoneySupply = diskindex.nMoneySupply;
                pindexNew->nFlags = diskindex.nFlags;
                pindexNew->nStakeModifier = diskindex.nStakeModifier;
                pindexNew->prevoutStake = diskindex.prevoutStake;
                pindexNew->nStakeTime = diskindex.nStakeTime;
                pindexNew->hashProofOfStake = diskindex.hashProofOfStake;
                pindexNew->blockHash = blockHash;

                if (!CheckProofOfWork(pindexNew->GetBlockHash(), pindexNew->nBits, consensusParams))
                    return error("%s: CheckProofOfWork failed: %s", __func__, pindexNew->ToString());

                uint256 tmpBlockhash;
                if (fStoreBlockHashToDb && !ReadBlockHash(diskindex.nFile, diskindex.nDataPos, tmpBlockhash))
                {
                    newStoredBlock++;
                    WriteBlockHash(diskindex);
                }
                else
                {
                    alreadyStoredBlock++;
                }

                pcursor->Next();
            } else {
                return error("%s: failed to read value", __func__);
            }
        } else {
            break;
        }
    }

    LogPrintf("CBlockTreeDB::LoadBlockIndexGuts, fStoreBlockHashToDb = %d, "
           "newStoredBlock = %d, "
           "alreadyStoredBlock = %d\n",
           fStoreBlockHashToDb,
           newStoredBlock,
           alreadyStoredBlock);

    return true;
}

// TACA: OLD CODE BEGIN
bool CBlockTreeDB::ReadTxIndex(uint256 hash, CTxIndex &txindex)
{
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CBlockTreeDB::UpdateTxIndex(uint256 hash, const CTxIndex &txindex)
{
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CBlockTreeDB::AddTxIndex(const CTransaction &tx, const CDiskTxPos &pos, int nHeight)
{
    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CBlockTreeDB::EraseTxIndex(const CTransaction &tx)
{
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CBlockTreeDB::ContainsTx(uint256 hash)
{
    return Exists(make_pair(string("tx"), hash));
}

bool CBlockTreeDB::ReadDiskTx(uint256 hash, CTransaction &tx, CTxIndex &txindex)
{
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CBlockTreeDB::ReadDiskTx(uint256 hash, CTransaction &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CBlockTreeDB::ReadDiskTx(COutPoint outpoint, CTransaction &tx, CTxIndex &txindex)
{
    return ReadDiskTx(outpoint.COutPointGetHash(), tx, txindex);
}

bool CBlockTreeDB::ReadDiskTx(COutPoint outpoint, CTransaction &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.COutPointGetHash(), tx, txindex);
}

bool CBlockTreeDB::WriteBlockIndex(const CDiskBlockIndex &blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CBlockTreeDB::WriteBlockHash(const CDiskBlockIndex &blockindex)
{
    return Write(make_pair(string("blockhash"), make_pair(blockindex.nFile, blockindex.nDataPos)), blockindex.GetBlockHash());
}

bool CBlockTreeDB::ReadBlockHash(const unsigned int nFile, const unsigned int nDataPos, uint256 &blockhash)
{
    return Read(make_pair(string("blockhash"), make_pair(nFile, nDataPos)), blockhash);
}

bool CBlockTreeDB::ReadHashBestChain(uint256 &hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CBlockTreeDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

bool CBlockTreeDB::ReadBestInvalidTrust(CBigNum &bnBestInvalidTrust)
{
    return Read(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CBlockTreeDB::WriteBestInvalidTrust(CBigNum bnBestInvalidTrust)
{
    return Write(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CBlockTreeDB::ReadSyncCheckpoint(uint256 &hashCheckpoint)
{
    return Read(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CBlockTreeDB::WriteSyncCheckpoint(uint256 hashCheckpoint)
{
    return Write(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CBlockTreeDB::ReadCheckpointPubKey(string &strPubKey)
{
    return Read(string("strCheckpointPubKey"), strPubKey);
}

bool CBlockTreeDB::WriteCheckpointPubKey(const string &strPubKey)
{
    return Write(string("strCheckpointPubKey"), strPubKey);
}

bool CBlockTreeDB::ReadModifierUpgradeTime(unsigned int &nUpgradeTime)
{
    return Read(string("nUpgradeTime"), nUpgradeTime);
}

bool CBlockTreeDB::WriteModifierUpgradeTime(const unsigned int &nUpgradeTime)
{
    return Write(string("nUpgradeTime"), nUpgradeTime);
}

bool CBlockTreeDB::BuildMapHash()
{
    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into mapBlockIndex.
    leveldb::Iterator
        *iterator = pdb->NewIterator(leveldb::ReadOptions());

    // Seek to start key.
    CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
    ssStartKey << make_pair(string("blockindex"), uint256(0));
    iterator->Seek(ssStartKey.str());
    // Now read each entry.
    while (iterator->Valid())
    {
        // Unpack keys and values.
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.write(iterator->value().data(), iterator->value().size());

        string strType;
        ssKey >> strType;

        // Did we reach the end of the data to read?
        if (fRequestShutdown || strType != "blockindex")
            break;

        CDiskBlockIndex diskindex;
        ssValue >> diskindex;

        uint256 blockHash = diskindex.GetBlockHash();  // the slow poke!
        if (0 == blockHash)
        {
            if (fPrintToConsole)
                LogPrintf(
                    "Error? at nHeight=%d"
                    "\n"
                    "",
                    diskindex.nHeight);
            continue; //?
        }
        mapHash.insert(make_pair( diskindex.GetSHA256Hash(), blockHash));
        iterator->Next();
    }
    delete iterator;
}

bool CBlockTreeDB::LoadBlockIndex()
{
    // Already loaded. But, it can happen during migration from BDB
    if (!mapBlockIndex.empty())
    {
        return true;
    }

    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into mapBlockIndex.
    leveldb::Iterator
        *iterator = pdb->NewIterator(leveldb::ReadOptions());
    // Seek to start key.

    CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
    ssStartKey << make_pair(string("blockindex"), uint256(0));
    iterator->Seek(ssStartKey.str());
    ::int32_t bestEpochIntervalHeight = 0;
    uint256 bestEpochIntervalHash;
    int newStoredBlock = 0;
    int alreadyStoredBlock = 0;
    // Now read each entry.
    while (iterator->Valid()) //what is so slow in this loop of all PoW blocks?
    {                         // 5 minutes for 1400 blocks, ~300 blocks/min or ~5/sec
        // Unpack keys and values.
        CDataStream
            ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());

        CDataStream
            ssValue(SER_DISK, CLIENT_VERSION);

        ssValue.write(iterator->value().data(), iterator->value().size());

        string
            strType;

        ssKey >> strType;
        // Did we reach the end of the data to read?
        if (fRequestShutdown || strType != "blockindex")
            break;

        CDiskBlockIndex diskindex;

        ssValue >> diskindex;

        uint256 blockHash = diskindex.GetBlockHash(); // the slow poke!

        if (0 == blockHash)
        {
            if (fPrintToConsole)
                LogPrintf(
                    "Error? at nHeight=%d"
                    "\n"
                    "",
                    diskindex.nHeight);
            continue;
        }

        // Construct block index object
        CBlockIndex
            *pindexNew = InsertBlockIndex(blockHash);
        // what if null? Can't be, since blockhash is known to be != 0
        if (NULL == pindexNew) // ???
        {
            if (fPrintToConsole)
                LogPrintf(
                    "Error? InsertBlockIndex(...) failed"
                    "\n"
                    "");
            iterator->Next();
            continue;
        }
        pindexNew->pprev = InsertBlockIndex(diskindex.hashPrev);
        pindexNew->pnext = InsertBlockIndex(diskindex.hashNext);

        pindexNew->nFile = diskindex.nFile;
        pindexNew->nBlockPos = diskindex.nBlockPos;
        pindexNew->nHeight = diskindex.nHeight;
        pindexNew->nMint = diskindex.nMint;
        pindexNew->nMoneySupply = diskindex.nMoneySupply;
        pindexNew->nFlags = diskindex.nFlags;
        pindexNew->nStakeModifier = diskindex.nStakeModifier;
        pindexNew->prevoutStake = diskindex.prevoutStake;
        pindexNew->nStakeTime = diskindex.nStakeTime;
        pindexNew->hashProofOfStake = diskindex.hashProofOfStake;
        pindexNew->nVersion = diskindex.nVersion;
        pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
        pindexNew->nTime = diskindex.nTime;
        pindexNew->nBits = diskindex.nBits;
        pindexNew->nNonce = diskindex.nNonce;
        pindexNew->nStatus = diskindex.nStatus;
        pindexNew->blockHash = blockHash;

        if (fReindexOnlyHeaderSync)
        {
            if ((pindexNew->nHeight == 0) || (pindexNew->nFile != 0 && pindexNew->nBlockPos != 0))
            {
                pindexNew->nStatus |= BLOCK_HAVE_DATA;
                pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
            }
            else
            {
                LogPrintf("block height = %d has no block data, nFile = %u, nBlockPost = %u\n", pindexNew->nHeight, pindexNew->nFile, pindexNew->nBlockPos);
            }
        }

        uint256 tmpBlockhash;
        if (fStoreBlockHashToDb && !ReadBlockHash(diskindex.nFile, diskindex.nBlockPos, tmpBlockhash))
        {
            newStoredBlock++;
            WriteBlockHash(diskindex);
        }
        else
        {
            alreadyStoredBlock++;
        }

        // Watch for genesis block
        if (
            (0 == diskindex.nHeight) &&
            (NULL != chainActive.Genesis()))
        {
            if (fPrintToConsole)
                LogPrintf(
                    "Error? an extra null block???"
                    "\n"
                    "");
        }
        if (
            (0 == diskindex.nHeight) && // ought to be faster than a hash check!?
            (NULL == chainActive.Genesis()))
        {
            if (blockHash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)) // check anyway, but only if block 0
            {
                chainActive.SetTip(pindexNew);
            }
            else
            {
                if (fPrintToConsole)
                    LogPrintf(
                        "Error? a extra genesis block with the wrong hash???"
                        "\n"
                        "");
            }
        }
        // there seem to be 2 errant blocks?
        else
        {
            if (
                (NULL != chainActive.Genesis()) &&
                (0 == diskindex.nHeight))
            {
                if (fPrintToConsole)
                    LogPrintf(
                        "Error? a extra genesis null block???"
                        "\n"
                        "");
            }
        }
        iterator->Next();
    }
    delete iterator;

    LogPrintf("CBlockTreeDB::LoadBlockIndex(), fStoreBlockHashToDb = %d, "
           "newStoredBlock = %d, "
           "alreadyStoredBlock = %d\n",
           fStoreBlockHashToDb,
           newStoredBlock,
           alreadyStoredBlock);

    // Load hashBestChain pointer to end of best chain
    if (!ReadHashBestChain(hashBestChain))
    {
        if (chainActive.Genesis() == NULL)
            return true;
        return error("CBlockTreeDB::LoadBlockIndex() : hashBestChain not loaded");
    }
    if (!mapBlockIndex.count(hashBestChain))
        return error("CBlockTreeDB::LoadBlockIndex() : hashBestChain not found in the block index");
    chainActive.SetTip(mapBlockIndex[hashBestChain]);

    // Recalculate block reward and minimum ease (highest difficulty) when starting node
    CBlockIndex* tmpBlockIndex = chainActive[nMainnetNewLogicBlockNumber];
    while (tmpBlockIndex != NULL)
    {
        if (tmpBlockIndex->nHeight >= bestEpochIntervalHeight &&
            ((tmpBlockIndex->nHeight % nEpochInterval == 0) || (tmpBlockIndex->nHeight == nMainnetNewLogicBlockNumber)))
        {
            bestEpochIntervalHeight = tmpBlockIndex->nHeight;
            bestEpochIntervalHash = tmpBlockIndex->blockHash;
        }
        // Find the minimum ease (highest difficulty) when starting node
        // It will be used to calculate min difficulty (maximum ease)
        if ((tmpBlockIndex->nHeight >= nMainnetNewLogicBlockNumber) && (nMinEase > tmpBlockIndex->nBits))
        {
            nMinEase = tmpBlockIndex->nBits;
        }
        tmpBlockIndex = tmpBlockIndex->pnext;
    }
    // Calculate maximum target of all blocks, it corresponds to 1/3 highest difficulty (or 3 minimum ease)
    uint256 bnMaximum = CBigNum().SetCompact(nMinEase).getuint256();
    CBigNum bnMaximumTarget;
    bnMaximumTarget.setuint256(bnMaximum);
    bnMaximumTarget *= 3;

    LogPrintf("Minimum difficulty target %s\n",
              CBigNum(bnMaximumTarget).getuint256().ToString().substr(0, 16));

    if (fReindexOnlyHeaderSync)
    {
        fReindexOnlyHeaderSync = false;
        CBlockIndex* chainTip = chainActive.Tip();
        while (chainTip != NULL)
        {
            chainTip->RaiseValidity(BLOCK_VALID_SCRIPTS);
            chainTip = chainTip->pprev;
        }

        BlockMap::iterator it;
        int numberOfReindexOnlyHeaderSyncBlock = 0;
        for (it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++)
        {
            CBlockIndex* pindexCurrent = (*it).second;
            WriteBlockIndex(CDiskBlockIndex(pindexCurrent));
            mapHash.insert(make_pair(pindexCurrent->GetSHA256Hash(), (*it).first));
            numberOfReindexOnlyHeaderSyncBlock++;
        }
        LogPrintf("CBlockTreeDB::LoadBlockIndex(), fReindexOnlyHeaderSync = 1, "
               "numberOfReindexOnlyHeaderSyncBlock = %d\n",
               fReindexOnlyHeaderSync,
               numberOfReindexOnlyHeaderSyncBlock);
    }
    else
    {
        BlockMap::iterator it;
        for (it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++)
        {
            CBlockIndex* pindexCurrent = (*it).second;
            mapHash.insert(make_pair(pindexCurrent->GetSHA256Hash(), (*it).first)).first;
        }
    }

    // Calculate current block reward
    if (chainActive.Height() >= nMainnetNewLogicBlockNumber) {
        LogPrintf("CBlockTreeDB::LoadBlockIndex(), bestEpochIntervalHash = %s\n", bestEpochIntervalHash.GetHex());
        BlockMap::iterator mi = mapBlockIndex.find(bestEpochIntervalHash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex *pBestEpochIntervalIndex = (*mi).second;
            nBlockRewardPrev =
                (::int64_t)((pBestEpochIntervalIndex->pprev ? pBestEpochIntervalIndex->pprev->nMoneySupply : pBestEpochIntervalIndex->nMoneySupply) /
                            nNumberOfBlocksPerYear) *
                nInflation;
        }
        else
        {
            LogPrintf("There is something wrong, can't find best epoch interval block\n");
        }
    }

    if (fRequestShutdown)
        return true;

    // Calculate bnChainTrust
    {
        LOCK(cs_main);

        LogPrintf("Sorting by height...\n");
        vector< pair< int, CBlockIndex*> > vSortedByHeight;

        vSortedByHeight.reserve(mapBlockIndex.size());
        //vSortedByHeight.resize( mapBlockIndex.size() );

        int
            nUpdatePeriod = 10000;
        for (const std::pair<uint256, CBlockIndex*>& item : mapBlockIndex)
        {
            CBlockIndex
                *pindex = item.second;

            vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
        }
        sort(vSortedByHeight.begin(), vSortedByHeight.end());

        LogPrintf("Initialize memory data of block index ...\n");
        for (const PAIRTYPE(int, CBlockIndex *) & item : vSortedByHeight)
        {
            CBlockIndex *pindex = item.second;
            pindex->bnChainTrust = (pindex->pprev ? pindex->pprev->bnChainTrust : CBigNum(0)) + pindex->GetBlockTrust();
            // NovaCoin: calculate stake modifier checksum
            pindex->nStakeModifierChecksum = GetStakeModifierChecksum(pindex);
            if (!CheckStakeModifierCheckpoints(pindex->nHeight, pindex->nStakeModifierChecksum))
                LogPrintf("CBlockTreeDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016\n" PRIx64, pindex->nHeight, pindex->nStakeModifier);
            if (pindex->nStatus & BLOCK_HAVE_DATA) {
                if (pindex->pprev) {
                    if (pindex->pprev->validTx) {
                        pindex->validTx = true;
                    } else {
                        pindex->validTx = false;
                        mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                    }
                } else {
                    pindex->validTx = true;
                }
            }
            if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->validTx || pindex->pprev == NULL))
                setBlockIndexCandidates.insert(pindex);
            if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->bnChainTrust > pindexBestInvalid->bnChainTrust))
                pindexBestInvalid = pindex;
            if (pindex->pprev)
                pindex->BuildSkip();
            if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == NULL || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
                pindexBestHeader = pindex;
        }
    }

    LogPrintf("Read best chain\n");
    bnBestChainTrust = chainActive.Tip()->bnChainTrust;

    LogPrintf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n",
           hashBestChain.ToString().substr(0, 20), chainActive.Height(), bnBestChainTrust.ToString(),
           DateTimeStrFormat("%x %H:%M:%S", chainActive.Tip()->GetBlockTime()));

    // NovaCoin: load hashSyncCheckpoint
    if (!fTestNet)
    {
        if (!ReadSyncCheckpoint(Checkpoints::hashSyncCheckpoint))
            return error("CBlockTreeDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
        LogPrintf("LoadBlockIndex(): synchronized checkpoint %s\n",
               Checkpoints::hashSyncCheckpoint.ToString());
    }
    // Load bnBestInvalidTrust, OK if it doesn't exist
    //    ReadBestInvalidTrust(bnBestInvalidTrust);

    // Verify blocks in the best chain
    int nCheckLevel = gArgs.GetArg("-checklevel", 1);
    int nCheckDepth = gArgs.GetArg("-checkblocks", 750);
    if (nCheckDepth == 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();

    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex *pindexFork = NULL;
    map<pair<unsigned int, unsigned int>, CBlockIndex *> mapBlockPos;
    for (CBlockIndex *pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (fRequestShutdown || pindex->nHeight < chainActive.Height() - nCheckDepth)
            break;
        CBlock block;
        CValidationState stateDummy;
        if (!block.ReadFromDisk(pindex))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        // check level 1: verify block validity
        // check level 7: verify block signature too
        if (nCheckLevel > 0 && !block.CheckBlock(stateDummy, true, true, (nCheckLevel > 6)))
        {
            LogPrintf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            pindexFork = pindex->pprev;
        }
        // check level 2: verify transaction index validity
        if (nCheckLevel > 1)
        {
            pair<unsigned int, unsigned int> pos = make_pair(pindex->nFile, pindex->nBlockPos);
            mapBlockPos[pos] = pindex;
            for (const CTransaction &tx : block.vtx)
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                if (ReadTxIndex(hashTx, txindex))
                {
                    // check level 3: checker transaction hashes
                    if (nCheckLevel > 2 || pindex->nFile != txindex.pos.Get_CDiskTxPos_nFile() || pindex->nBlockPos != txindex.pos.Get_CDiskTxPos_nBlockPos())
                    {
                        // either an error or a duplicate transaction
                        CTransaction txFound;
                        if (!txFound.ReadFromDisk(txindex.pos))
                        {
                            LogPrintf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString());
                            pindexFork = pindex->pprev;
                        }
                        else if (txFound.GetHash() != hashTx) // not a duplicate tx
                        {
                            LogPrintf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString());
                            pindexFork = pindex->pprev;
                        }
                    }
                    // check level 4: check whether spent txouts were spent within the main chain
                    unsigned int
                        nOutput = 0;
                    if (nCheckLevel > 3)
                    {
                        for (const CDiskTxPos &txpos : txindex.vSpent)
                        {
                            if (!txpos.IsNull())
                            {
                                pair<unsigned int, unsigned int> posFind = make_pair(txpos.Get_CDiskTxPos_nFile(), txpos.Get_CDiskTxPos_nBlockPos());
                                if (!mapBlockPos.count(posFind))
                                {
                                  LogPrintf(
                                      "LoadBlockIndex(): *** found bad spend "
                                      "at %d, hashBlock=%s, hashTx=%s\n",
                                      pindex->nHeight,
                                      pindex->GetBlockHash().ToString(),
                                      hashTx.ToString());
                                  pindexFork = pindex->pprev;
                                }
                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                if (nCheckLevel > 5)
                                {
                                    CTransaction txSpend;
                                    if (!txSpend.ReadFromDisk(txpos))
                                    {
                                      LogPrintf(
                                          "LoadBlockIndex(): *** cannot read "
                                          "spending transaction of %s:%i from "
                                          "disk\n",
                                          hashTx.ToString(), nOutput);
                                      pindexFork = pindex->pprev;
                                    }
                                    else if (!txSpend.CheckTransaction(stateDummy))
                                    {
                                      LogPrintf(
                                          "LoadBlockIndex(): *** spending "
                                          "transaction of %s:%i is invalid\n",
                                          hashTx.ToString(), nOutput);
                                      pindexFork = pindex->pprev;
                                    }
                                    else
                                    {
                                        bool fFound = false;
                                        for (const CTxIn &txin : txSpend.vin)
                                            if (txin.prevout.COutPointGetHash() == hashTx && txin.prevout.COutPointGet_n() == nOutput)
                                                fFound = true;
                                        if (!fFound)
                                        {
                                          LogPrintf(
                                              "LoadBlockIndex(): *** spending "
                                              "transaction of %s:%i does not "
                                              "spend it\n",
                                              hashTx.ToString(),
                                              nOutput);
                                          pindexFork = pindex->pprev;
                                        }
                                    }
                                }
                            }
                            ++nOutput;
                        }
                    }
                }
                // check level 5: check whether all prevouts are marked spent
                if (nCheckLevel > 4)
                {
                    for (const CTxIn &txin : tx.vin)
                    {
                        CTxIndex txindex;
                        if (ReadTxIndex(txin.prevout.COutPointGetHash(), txindex))
                            if (txindex.vSpent.size() - 1 < txin.prevout.COutPointGet_n() || txindex.vSpent[txin.prevout.COutPointGet_n()].IsNull())
                            {
                              LogPrintf(
                                  "LoadBlockIndex(): *** found unspent prevout "
                                  "%s:%i in %s\n",
                                  txin.prevout.COutPointGetHash()
                                      .ToString(),
                                  txin.prevout.COutPointGet_n(),
                                  hashTx.ToString());
                              pindexFork = pindex->pprev;
                            }
                    }
                }
            }
        }
    }

    if (pindexFork && !fRequestShutdown)
    {
        // Reorg back to the fork
        LogPrintf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
        CBlock block;
        if (!block.ReadFromDisk(pindexFork))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        setBlockIndexCandidates.insert(pindexFork);
        CBlockTreeDB txdb;
        CValidationState state;
        ActivateBestChain(state, txdb);
    }

    return true;
}
// TACA: OLD CODE END
#ifdef _MSC_VER
#include "msvc_warnings.pop.h"
#endif
