// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_PRIMITIVES_BLOCK_H
#define YACOIN_PRIMITIVES_BLOCK_H

#include "bignum.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"
#include "scrypt.h"
//#include "tokens/tokens.h"
//#include "checkqueue.h"

class CWallet;
class CTransaction;
class CKeyStore;

#pragma pack(push, 1)
struct block_header
{
    unsigned int version;
    uint256 prev_block;
    uint256 merkle_root;
    ::int64_t timestamp;
    unsigned int bits;
    unsigned int nonce;

};
#pragma pack(pop)

typedef struct
{
    unsigned int version;
    uint256 prev_block;
    uint256 merkle_root;
    unsigned int timestamp;
    unsigned int bits;
    unsigned int nonce;

} old_block_header;

// block version header
static const int
    VERSION_of_block_for_yac_05x_new = 7,
    VERSION_of_block_for_yac_049     = 6,
    VERSION_of_block_for_yac_044_old = 3,
    CURRENT_VERSION_of_block = VERSION_of_block_for_yac_049;

static const unsigned char MAXIMUM_N_FACTOR = 25;  //30; since uint32_t fails on 07 Feb 2106 06:28:15 GMT
                                                   //    when stored as an uint32_t in a block
                                                   //    so there is no point going past Nf = 25

extern const ::int64_t
    nChainStartTime,
    nChainStartTimeTestNet;
extern CBigNum bnProofOfWorkLimit;

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 *
 * Blocks are appended to blk0001.dat files on disk.  Their location on disk
 * is indexed by CBlockIndex objects in memory.
 */
class CBlockHeader
{
public:
    // Block header
    ::int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    mutable ::int64_t nTime;
    ::uint32_t nBits;
    ::uint32_t nNonce;

    // (memory-only) Store following info to avoid calculating hash many times
    mutable struct block_header previousBlockHeader;
    mutable uint256 blockHash;
    mutable uint256 blockSHA256Hash;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        // nTime is extended to 64-bit since yacoin 1.0.0
        if (this->nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
               READWRITE(nTime);
        }
        else // 32-bit nTime
        {
               ::uint32_t time = (::uint32_t)nTime; // needed for GetSerializeSize, Serialize function
               READWRITE(time);
               nTime = time; // needed for Unserialize function
        }
        READWRITE(nBits);
        READWRITE(nNonce);
        previousBlockHeader.version = this->nVersion;
        previousBlockHeader.prev_block = hashPrevBlock;
        previousBlockHeader.merkle_root = hashMerkleRoot;
        previousBlockHeader.timestamp = nTime;
        previousBlockHeader.bits = nBits;
        previousBlockHeader.nonce = nNonce;
    }

    void SetNull();

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // yacoin2015 update
    uint256 CalculateHash() const
    {
        uint256 thash;

        if (nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
            struct block_header block_data;
            block_data.version = nVersion;
            block_data.prev_block = hashPrevBlock;
            block_data.merkle_root = hashMerkleRoot;
            block_data.timestamp = nTime;
            block_data.bits = nBits;
            block_data.nonce = nNonce;
            if (!scrypt_hash(CVOIDBEGIN(block_data),
                             sizeof(struct block_header), UINTBEGIN(thash),
                             nFactorAtHardfork))
            {
                thash = 0;  // perhaps? should error("lack of memory for scrypt hash?");
            }
        }
        else // 32-bit nTime
        {
            const ::uint64_t
                nSpanOf4  = 1368515488 - nChainStartTime,
                nSpanOf5  = 1368777632 - nChainStartTime,
                nSpanOf6  = 1369039776 - nChainStartTime,
                nSpanOf7  = 1369826208 - nChainStartTime,
                nSpanOf8  = 1370088352 - nChainStartTime,
                nSpanOf9  = 1372185504 - nChainStartTime,
                nSpanOf10 = 1373234080 - nChainStartTime,
                nSpanOf11 = 1376379808 - nChainStartTime,
                nSpanOf12 = 1380574112 - nChainStartTime,   // Mon, 30 Sep 2013 20:48:32 GMT
                nSpanOf13 = 1384768416 - nChainStartTime,   // Mon, 18 Nov 2013 09:53:36 GMT
                nSpanOf14 = 1401545632 - nChainStartTime,   // Sat, 31 May 2014 14:13:52 GMT
                nSpanOf15 = 1409934240 - nChainStartTime,   // Fri, 05 Sep 2014 16:24:00 GMT (Nf) 16
                nSpanOf16 = 1435100064 - nChainStartTime,   // Tue, 23 Jun 2015 22:54:24 GMT (Nf) 17
                nSpanOf17 = 1468654496 - nChainStartTime,   // Sat, 16 Jul 2016 07:34:56 GMT (Nf) 18
                nSpanOf18 = 1502208928 - nChainStartTime,   // Tue, 08 Aug 2017 16:15:28 GMT (Nf) 19
                nSpanOf19 = 1602872224 - nChainStartTime,   // Fri, 16 Oct 2020 18:17:04 GMT (Nf) 20
                nSpanOf20 = 1636426656 - nChainStartTime,   // Tue, 09 Nov 2021 02:57:36 GMT (Nf) 21
                nSpanOf21 = 1904862112 - nChainStartTime,   // Mon, 13 May 2030 00:21:52 GMT (Nf) 22
                nSpanOf22 = 2173297568U - nChainStartTime,   // Sat, 13 Nov 2038 21:46:08 GMT (Nf) 23
                nSpanOf23 = 2441733024U - nChainStartTime,   // Fri, 17 May 2047 19:10:24 GMT (Nf) 24
                nSpanOf24 = 3247039392U - nChainStartTime,   // Tue, 22 Nov 2072 11:23:12 GMT (Nf) 25
                nSpanOf25 = 3515474848U - nChainStartTime;   // Mon, 26 May 2081 08:47:28 GMT (Nf) 26

            unsigned char nfactor;
            if( !fTestNet )
            {     // nChainStartTime = 1367991200 is start
    		    if      ( nTime < (nChainStartTime + nSpanOf4 ) ) nfactor = 4;
                else if ( nTime < (nChainStartTime + nSpanOf5 ) ) nfactor = 5;
                else if ( nTime < (nChainStartTime + nSpanOf6 ) ) nfactor = 6;
                else if ( nTime < (nChainStartTime + nSpanOf7 ) ) nfactor = 7;
                else if ( nTime < (nChainStartTime + nSpanOf8 ) ) nfactor = 8;
                else if ( nTime < (nChainStartTime + nSpanOf9 ) ) nfactor = 9;
                else if ( nTime < (nChainStartTime + nSpanOf10) ) nfactor = 10;
                else if ( nTime < (nChainStartTime + nSpanOf11) ) nfactor = 11;
                else if ( nTime < (nChainStartTime + nSpanOf12) ) nfactor = 12;
                else if ( nTime < (nChainStartTime + nSpanOf13) ) nfactor = 13;
                else if ( nTime < (nChainStartTime + nSpanOf14) ) nfactor = 14;
                else if ( nTime < (nChainStartTime + nSpanOf15) ) nfactor = 15;
                else if ( nTime < (nChainStartTime + nSpanOf16) ) nfactor = 16;
                else if ( nTime < (nChainStartTime + nSpanOf17) ) nfactor = 17;
                else if ( nTime < (nChainStartTime + nSpanOf18) ) nfactor = 18;
                else if ( nTime < (nChainStartTime + nSpanOf19) ) nfactor = 19;
                else if ( nTime < (nChainStartTime + nSpanOf20) ) nfactor = 20;
                else if ( nTime < (nChainStartTime + nSpanOf21) ) nfactor = 21;
                else if ( nTime < (nChainStartTime + nSpanOf22) ) nfactor = 22;
                else if ( nTime < (nChainStartTime + nSpanOf23) ) nfactor = 23;
                else if ( nTime < (nChainStartTime + nSpanOf24) ) nfactor = 24;
                else if ( nTime < (nChainStartTime + nSpanOf25) ) nfactor = 25;
                else
                    nfactor = MAXIMUM_N_FACTOR;
            }
            else    // is TestNet
            {
                nfactor = 4;
            }

            old_block_header oldBlock;
            oldBlock.version = nVersion;
            oldBlock.prev_block = hashPrevBlock;
            oldBlock.merkle_root = hashMerkleRoot;
            oldBlock.timestamp = nTime;
            oldBlock.bits = nBits;
            oldBlock.nonce = nNonce;
            if (!scrypt_hash(CVOIDBEGIN(oldBlock), sizeof(old_block_header),
                             UINTBEGIN(thash), nfactor))
            {
              thash = 0;  // perhaps? should error("lack of memory for scrypt hash?");
            }
        }
		return thash;
    }

    bool IsHeaderDifferent() const
    {
      if ((nVersion == previousBlockHeader.version) &&
          (hashPrevBlock == previousBlockHeader.prev_block) &&
          (hashMerkleRoot == previousBlockHeader.merkle_root) &&
          (nTime == previousBlockHeader.timestamp) &&
          (nBits == previousBlockHeader.bits) &&
          (nNonce == previousBlockHeader.nonce))
      {
        return false;
      }
      return true;
    }

    uint256 GetHash(int blockHeight = 0) const
    {
        if(blockHash == 0 || IsHeaderDifferent())
        {
            blockHash = CalculateHash();
            previousBlockHeader.version = nVersion;
            previousBlockHeader.prev_block = hashPrevBlock;
            previousBlockHeader.merkle_root = hashMerkleRoot;
            previousBlockHeader.timestamp = nTime;
            previousBlockHeader.bits = nBits;
            previousBlockHeader.nonce = nNonce;
        }
        return blockHash;
    }

    uint256 GetSHA256Hash() const
    {
        if(blockSHA256Hash == 0 || IsHeaderDifferent())
        {
            previousBlockHeader.version = nVersion;
            previousBlockHeader.prev_block = hashPrevBlock;
            previousBlockHeader.merkle_root = hashMerkleRoot;
            previousBlockHeader.timestamp = nTime;
            previousBlockHeader.bits = nBits;
            previousBlockHeader.nonce = nNonce;
            blockSHA256Hash = Hash(BEGIN(previousBlockHeader.version), END(previousBlockHeader.nonce));
        }
        return blockSHA256Hash;
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
        // The original check ensures that the second transaction in a PoS block
        // is the coinstake transaction.
        // Since Heliopolis hardfork (block 1890000), YAC no longer supports PoS, so the number of PoS blocks remains fixed.
        // Since v1.1.0, this check has been modified to support headers-first synchronization.
//        return (vtx.size() > 1 && vtx[1].IsCoinStake());
        bool proofOfStake = false;
        if (nTime <= nYac10HardforkTime && nNonce == 0 &&
                ((nBits <= 486801407 && blockHash != uint256("0x0000000009415c983b503189080df17423b193176634b6e489120e0189a6829c"))
                                    || (blockHash == uint256("0x5fc9a11b3ffd0118a0031eeb9ed2860bd8ceb8c71e3226e02e6eb82c90cbbf99"))
                                    || (blockHash == uint256("0x5dc2a000963f075f3dec7fa8f220987bff3c4a978528594e5408448155cdc8e4"))))
        {
            proofOfStake = true;
        }
        return proofOfStake;
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    // ppcoin: entropy bit for stake modifier if chosen by modifier
    unsigned int GetStakeEntropyBit(unsigned int nHeight) const
    {

            // Take last bit of block hash as entropy bit
            unsigned int nEntropyBit = ((GetHash().Get64()) & 1ULL);
            if (fDebug && gArgs.GetBoolArg("-printstakemodifier"))
                LogPrintf(
                        "GetStakeEntropyBit: nTime=%" PRId64 " \nhashBlock=%s\nnEntropyBit=%u\n",
                        nTime,
                        GetHash().ToString(),
                        nEntropyBit
                      );
            return nEntropyBit;

    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable std::vector<uint256> vMerkleTree;
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &blockHeader)
    {
        SetNull();
        *((CBlockHeader*)this) = blockHeader;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(s.GetType() & (SER_GETHASH|SER_BLOCKHEADERONLY)))
        {
            READWRITE(vtx);
            READWRITE(vchBlockSig);
        }
        else if (ser_action.ForRead())
        {
            const_cast<CBlock*>(this)->vtx.clear();
            const_cast<CBlock*>(this)->vchBlockSig.clear();
        }
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        vchBlockSig.clear();
        vMerkleTree.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    void UpdateTime(const CBlockIndex* pindexPrev);

    std::pair<COutPoint, unsigned int> GetProofOfStake() const
    {
        return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, (unsigned int)vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }

    // ppcoin: get max transaction timestamp
    ::int64_t GetMaxTransactionTime() const
    {
        ::int64_t maxTransactionTime = 0;
        for(const CTransaction& tx : vtx)
            maxTransactionTime = std::max(maxTransactionTime, (::int64_t)tx.nTime);
        return maxTransactionTime;
    }

    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        for(const CTransaction& tx : vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = (int)vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = std::min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        std::vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = (int)vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = std::min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        for(const uint256& otherside : vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }

    void print() const
    {
        LogPrintf("CBlock(\n"
                "hash=%s,\n"
                "ver=%d,\n"
                "hashPrevBlock=%s,\n"
                "hashMerkleRoot=%s,\n"
                "nTime=%" PRId64 ", "
                "nBits=%08x, "
                "nNonce=%u, "
                "vtx=%" PRIszu ",\n"
                "vchBlockSig=%s\n"
                ")\n",
            GetHash().ToString(),
            nVersion,
            hashPrevBlock.ToString(),
            hashMerkleRoot.ToString(),
            nTime,
            nBits,
            nNonce,
            vtx.size(),
            HexStr(vchBlockSig.begin(), vchBlockSig.end())
              );
        for (unsigned int i = 0; i < vtx.size(); ++i)
        {
            LogPrintf("  ");
            vtx[i].print();
        }
        LogPrintf("  vMerkleTree: ");
        for (unsigned int i = 0; i < vMerkleTree.size(); ++i)
            LogPrintf("%s ", vMerkleTree[i].ToString().substr(0,10));
        LogPrintf("\n");
    }

    bool SignBlock044(const CKeyStore& keystore);
    bool SignBlock(CWallet& keystore);
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{
public:
    std::vector<uint256> vHave;

    CBlockLocator()
    {
    }

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(_nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // YACOIN_PRIMITIVES_BLOCK_H
