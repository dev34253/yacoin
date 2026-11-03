// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// How headers and blocks are classified as proof of stake, and the proof-of-stake block
// rules: the header heuristic, block serialisation and hashes, block signing and the block
// signature check, the proof-of-stake branch of CheckBlock and its contextual check, coin
// age, the coinstake reward and chain trust.
//
// Classification uses real mainnet headers only. A synthetic proof-of-stake block is a real
// proof-of-stake header with replaced transactions: at least two, the second a coinstake
// with at least two outputs; it only goes to the block-level functions. The tests run on
// the main network with the fork height at 1890000.

#if defined(HAVE_CONFIG_H)
#include "config/yacoin-config.h"
#endif

#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "hash.h"
#include "key.h"
#include "keystore.h"
#include "pow.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "streams.h"
#include "timedata.h"
#include "timestamps.h"
#include "utilstrencodings.h"
#include "validation.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include "test/consensus_test_util.h"
#include "test/stake_test_util.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

// Mainnet headers (getblockheader <hash> false) and blocks (getblock <hash> false), read from
// a mainnet node running YAC-v1.11.0.0-6d72383 (synced to height 1964925), with the node's
// block hash and its "flags". A scan of heights 0-1889999 on that node found 223,809
// proof-of-stake blocks, all with nonce 0, and 6,955 proof-of-work blocks with nonce 0; the
// only proof-of-stake blocks with nBits above 0x1d03ffff are 82204 and 82217.

// 67107: proof of work, nonce 0, nBits 0x1c2fb0ca (below 0x1d03ffff); its hash is the one
// the heuristic excludes
const char* const BLOCK_67107_HEX =
    "030000000f8a08870985a6a9684e228ad4ada870b92b697b4f541a0d8d906d18000000005b3cf9c2e37bdc267521c29f7695d0792e2a346e86"
    "4a30c11a891e8535712df5ec0d9a51cab02f1c000000000201000000630d9a51010000000000000000000000000000000000000000000000000"
    "000000000000000ffffffff0d032306010101062f503253482fffffffff01103d200100000000232102de2e0c1671bdba8f5b4c2393a90e01ad"
    "0015670092c117234a01358a5a4fe3f7ac0000000001000000520d9a5102003d3d0982700d017442cece0d73216bab1bb4ee99adca8c036355"
    "89a7ccefa600000000494830450220025de4b1aba5772ee54cb131dbe51ca56b842a16629963a8ca2499f99b8e630f022100efa097f84dae04"
    "950e05a7fdf44bd086fe22cc841c3d18bea6ba89027b1eca6801ffffffffb076a9aa732ad967bfa369917c058df0d96b6f56b7cb811f03e57c"
    "c9c0e55d1900000000494830450220789edcf9da56d377d35511c190f3585ba13a276482dd274b118ce861722fa2cd022100a540085474e9b3"
    "0c5c37bd7fbb0dce3eebd5e5ed72342bc12b941808d4294a2101ffffffff0140ed2502000000001976a9146e45fac7bfdea7e39b734b0f82eb"
    "70cadaa05f9788ac00000000483046022100c1343737e8b038ff55d20ba2e197ba22abdc7afa845af43504d1ff5fc45ba3f40221009afe28cb"
    "46a9906bece9b571e014cb287531b067e6278f75a9b9c4e72d1c65f1";
const char* const HASH_67107 = "0000000009415c983b503189080df17423b193176634b6e489120e0189a6829c";
// 82217: proof of stake, nBits 0x1e0fffff; its hash is one of the two the heuristic forces
const char* const BLOCK_82217_HEX =
    "030000003b9fd65cc463f0007368b724626b0836e5289873d6ba13524c8d10d0000000000c66a03fdbf59ce40bfa80a233e14c0b95183de6c8"
    "399075db12dbd9e8c4e582d695b151ffff0f1e000000000201000000d695b15101000000000000000000000000000000000000000000000000"
    "0000000000000000ffffffff0d032941010110062f503253482fffffffff010000000000000000000000000001000000d695b151019c868cda"
    "004ed82db31f98c34ab851d1e6bc895e1022e86cdfed948e2673cf9b0000000049483045022051b3c2be917b8284f1a6bda2d25b9e45d7b612"
    "eb6b5a17f40bd8335abab01d9602210098a90978f0c39a81f64ac549475f1b5a77211ed334e47512933fbcb5272a3d1701ffffffff03000000"
    "0000000000001057e6020000000023210354c0e1446ae9bd305ae8899a009a44775a31ce0292cad8f6bee00d7263b59685ac1057e602000000"
    "0023210354c0e1446ae9bd305ae8899a009a44775a31ce0292cad8f6bee00d7263b59685ac00000000473045022100caf0782b469112972be7"
    "f16d34399c06f9336e1a1de43efb9e8181720a253a75022056b29f25e52d998dba0657f6d1e0e9c57aebc9ce69dd8b4ad079e75aa2115adc";
const char* const HASH_82217 = "5fc9a11b3ffd0118a0031eeb9ed2860bd8ceb8c71e3226e02e6eb82c90cbbf99";
// 82994: the lowest proof-of-stake block above 82204 with nBits <= 0x1d03ffff (exactly)
const char* const BLOCK_82994_HEX =
    "03000000561e3d3b4718fcba4aadbe36d75efab082a2eff9cafd889fac3d8845010000003bfdf9e789eb72a1e0287a1d4c932205c07d739fe7"
    "50296fe3e6ca9c836a36a14c77b251ffff031d0000000002010000004c77b25101000000000000000000000000000000000000000000000000"
    "0000000000000000ffffffff0d03324401014a062f503253482fffffffff0100000000000000000000000000010000004c77b2510151870f60"
    "60dc87447def052dd436a31ca67df844b3ec63fabcbc8e5c49a29fd4010000006c493046022100c3bb9828037e91a7d9f11a46a64ffaf55411"
    "819b16ae02539567e3376fe2ac6a022100fb74bf1da4c110773d34d0e54a2534217500f70f487a90270b37601537183dcc012102f51d5bf68c"
    "9b983d02a1575e5082096b47a6a6297bd92ee1fbb4f7629e221658ffffffff030000000000000000000042b30a00000000232102f51d5bf68c"
    "9b983d02a1575e5082096b47a6a6297bd92ee1fbb4f7629e221658ac0042b30a00000000232102f51d5bf68c9b983d02a1575e5082096b47a6"
    "a6297bd92ee1fbb4f7629e221658ac00000000473045022020b3ab3dcd90cffbc6d9700ad73ec3c3b90c1aca5f89698f2aaffe6977d2077602"
    "21009cd4e8f1a09cac2b07127187ee9526e609264cf42613dc857f8f8621aeff7be3";
const char* const HASH_82994 = "683ae9d8b201e2ffd9c0b509f7ef053d07fe49e61dbbc7b5931bc5c28d2131a7";
// 151785: proof of work, nonce 0, nBits 0x1d042aad (above 0x1d03ffff)
const char* const HEADER_151785_HEX =
    "030000008a84478075cb9c9215a2ac1a81b3b3d2da507284c0c745e3d6eafc1804000000bf98e3c4d7010334849b124628870bc13ef84f12b4"
    "97637f9cc14ab1d36277297858f851ad2a041d00000000";
const char* const HASH_151785 = "00000000d6e1688909f5397d1d62e6bf1988fa8499a03eef91959c52543301ee";
// 1889995: the highest proof-of-stake block (nBits 0x1d03ffff)
const char* const HEADER_1889995_HEX =
    "030000006bb1114b4634719b0016fbdfe619d65525eeb9f7d002bd6032ab8d349d0d00000d3bd1a6bdca7b2f7b5cc94d7963ed5703b117fe62"
    "bb6c302d0c871a082bc274cba88060ffff031d00000000";
// 1890000: version 7, time exactly the cut-off 1619048730, proof of work (nonce not 0)
const char* const HEADER_1890000_HEX =
    "070000004fe57500aea41715150e9203caac51a4f573df4cd1634251b29a85555400000096194ecdf9ec58586ed6147dc797f72b96c8002820"
    "5baffa6ffd7c27a47d02461ab9806000000000ffff0f1e55555e3d";
// 1890001: the first block after the cut-off
const char* const HEADER_1890001_HEX =
    "07000000d088e0f258fe142a2c7d26f89e38b4a4a84d2772ebefe2d0f3ab02840f030000b045d2b82a877cbc79f317601f8d51319c48701404"
    "d26f75150b25d2174f6590b5cb806000000000ffff0f1e00000011";
// 1891681: the lowest block after the cut-off with nonce 0 (nBits 0x1e0fffff)
const char* const HEADER_1891681_HEX =
    "07000000e216e63a8994f2df04916ceaca83e405a391969c0b9100ed8fe78c4c7e0d0000f273098eb6a96e06a1745ebdd5cc09b8e6efa19780"
    "d0a34ac5fa938f40ca20bd7ac55c6100000000ffff0f1e00000000";
// 60540 (from scrypt_tests): proof of work, nonce not 0, nBits 0x1c1e323d (below 0x1d03ffff)
const char* const HEADER_60540_HEX =
    "03000000062436d8f1fb30595befa369ab6b038a4835f8bffa69d2bdbb675117000000001dff058fc782acb9147c0d79430bb863e9e0841476"
    "9baded2c7fd0b604f3b97227e491513d321e1ce68f0100";
const char* const HASH_60540 = "0000000000074d33875724ae7bd66da3a493dbf4491eba26a796771318b97b3c";

const char* const HASH_644 = "00000af3c7a0d0f5e904aa96dbd39adeb74402aa2dc41e0adcd2a028c4995020";
const char* const HASH_82204 = "5dc2a000963f075f3dec7fa8f220987bff3c4a978528594e5408448155cdc8e4";

/** A header as it is deserialised: the hash cache is empty */
CBlockHeader ParseHeader(const char* hex)
{
    CDataStream ss(ParseHex(hex), SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader header;
    ss >> header;
    BOOST_REQUIRE(ss.empty());
    return header;
}

/** A real block with its hash cached, as the network and block import code have it before
 * they validate it */
CBlock RealBlock(const char* hex)
{
    CBlock block = ParseBlock(hex);
    block.GetHash();
    return block;
}

CScript P2PK(const CPubKey& pubkey) { return CScript() << ToByteVector(pubkey) << OP_CHECKSIG; }
CScript P2PKH(const CPubKey& pubkey) { return GetScriptForDestination(pubkey.GetID()); }
CScript NonStandard() { return CScript() << OP_TRUE; }

CKey NewKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

/** Block 644 (proof of work) with a coinbase paying to the given scripts, unsigned */
CBlock PowBlock(const std::vector<CScript>& scripts)
{
    CBlock block = RealBlock(BLOCK_644_HEX);
    CTransaction& coinbase = block.vtx[0];
    coinbase.vout.clear();
    for (const CScript& script : scripts) coinbase.vout.emplace_back(1000000, script);
    block.vchBlockSig.clear();
    return block;
}

/** Block 82204 (proof of stake) with the coinstake's output 1 paying to script, unsigned */
CBlock PosBlock(const CScript& script)
{
    CBlock block = RealBlock(BLOCK_82204_HEX);
    block.vtx[1].vout[1].scriptPubKey = script;
    block.vchBlockSig.clear();
    return block;
}

struct CheckResult {
    bool fValid;
    int nDoS;
    std::string strReason;
};

/** CheckBlock on a copy of the block */
CheckResult Check(CBlock block, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig)
{
    CValidationState state;
    CheckResult r;
    r.fValid = CheckBlock(block, state, Params().GetConsensus(), fCheckPOW, fCheckMerkleRoot, fCheckSig);
    r.nDoS = 0;
    state.IsInvalid(r.nDoS);
    r.strReason = state.GetRejectReason();
    return r;
}

void CheckRejected(const CBlock& block, bool fCheckSig, int nDoS, const std::string& strReason)
{
    CheckResult r = Check(block, true, false, fCheckSig);
    BOOST_CHECK(!r.fValid);
    BOOST_CHECK_EQUAL(r.nDoS, nDoS);
    BOOST_CHECK_EQUAL(r.strReason, strReason);
}

/** A coins view with block 644's coinbase output, as the coinstake of 82204 spends it */
struct CoinView {
    CCoinsView base;
    CCoinsViewCache view{&base};
    void Add(const COutPoint& outpoint, const CTxOut& out, int nHeight, int nTime)
    {
        view.AddCoin(outpoint, Coin(out, nHeight, true, false, nTime), false);
    }
};

/** Block 644 in block file 7 and the transaction index */
struct CoinOnDisk {
    RealKernel real;
    CDiskBlockPos pos;
    CoinView coins;
    CoinOnDisk()
    {
        pos = WriteBlockFile(real.blockFrom, 7);
        IndexFirstTx(real.blockFrom, pos);
        coins.Add(real.coinstake().vin[0].prevout, real.txPrev().vout[0], 644, real.txPrev().nTime);
    }
};

struct CoinAge {
    bool fOk;
    uint64_t nCoinAge;
};

CoinAge GetAge(const CTransaction& tx, const CCoinsViewCache& view)
{
    CoinAge r;
    r.nCoinAge = 12345;
    r.fOk = GetCoinAge(tx, view, r.nCoinAge);
    return r;
}

/** Heights pindexTop, pindexTop->pprev, ... counting down from nHeight, down to (not
 * including) pindexStop */
void SetHeights(CBlockIndex* pindexTop, int nHeight, const CBlockIndex* pindexStop)
{
    for (CBlockIndex* pindex = pindexTop; pindex != pindexStop; pindex = pindex->pprev) pindex->nHeight = nHeight--;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(block_pos_tests, KernelSetup)

/* IsProofOfStake: time at or before the cut-off, nonce 0, and nBits <= 0x1d03ffff unless the
 * hash is 67107's, or the hash is 82204's or 82217's. The hash is the cached one. */
BOOST_AUTO_TEST_CASE(classification_real_headers)
{
    struct Case {
        const char* pszHeader;
        bool fProofOfStake;
    };
    const Case cases[] = {
        // all conditions hold: the general rule
        {HEADER_1889995_HEX, true},
        // nonce not 0, nBits below and above the threshold
        {HEADER_60540_HEX, false},
        // nonce 0, nBits above the threshold, no forced hash
        {HEADER_151785_HEX, false},
        // at the cut-off, nonce not 0; after it, nonce not 0 and nonce 0
        {HEADER_1890000_HEX, false},
        {HEADER_1890001_HEX, false},
        {HEADER_1891681_HEX, false},
    };
    for (const Case& c : cases) {
        CBlockHeader header = ParseHeader(c.pszHeader);
        BOOST_CHECK_EQUAL(header.IsProofOfStake(), c.fProofOfStake);
        BOOST_CHECK_EQUAL(header.IsProofOfWork(), !c.fProofOfStake);
        BOOST_CHECK_EQUAL(CBlockIndex(header).IsProofOfStake(), c.fProofOfStake);
    }
    BOOST_CHECK_EQUAL(ParseHeader(HEADER_1890000_HEX).nTime, nYac10HardforkTime);
    BOOST_CHECK_EQUAL(ParseHeader(HEADER_1889995_HEX).nBits, 0x1d03ffffU);

    CBlockHeader header644 = ParseBlock(BLOCK_644_HEX);
    BOOST_CHECK_NE(header644.nNonce, 0U);
    BOOST_CHECK(header644.nBits > 0x1d03ffffU);
    BOOST_CHECK(header644.IsProofOfWork());
}

/* Classification before and after the hash is computed: the hard-coded hashes match only once
 * GetHash() has filled the cache */
BOOST_AUTO_TEST_CASE(classification_hash_cache)
{
    struct Case {
        const char* pszBlock;
        const char* pszHash;
        bool fBefore;
        bool fAfter;
    };
    const Case cases[] = {
        {BLOCK_82994_HEX, HASH_82994, true, true},  // general rule
        {BLOCK_67107_HEX, HASH_67107, true, false}, // excluded hash
        {BLOCK_82204_HEX, HASH_82204, false, true}, // forced hash
        {BLOCK_82217_HEX, HASH_82217, false, true}, // forced hash
        {BLOCK_644_HEX, HASH_644, false, false},
    };
    for (const Case& c : cases) {
        CBlock block = ParseBlock(c.pszBlock);
        BOOST_CHECK(block.blockHash.IsNull());
        BOOST_CHECK_EQUAL(block.IsProofOfStake(), c.fBefore);
        BOOST_CHECK_EQUAL(CBlockIndex(block).IsProofOfStake(), c.fBefore);
        BOOST_CHECK_EQUAL(block.GetHash().GetHex(), c.pszHash);
        BOOST_CHECK_EQUAL(block.IsProofOfStake(), c.fAfter);
        BOOST_CHECK_EQUAL(block.IsProofOfWork(), !c.fAfter);
        BOOST_CHECK_EQUAL(CBlockIndex(block).IsProofOfStake(), c.fAfter);
    }
    const CBlockHeader header67107 = ParseBlock(BLOCK_67107_HEX);
    BOOST_CHECK_EQUAL(header67107.nNonce, 0U);
    BOOST_CHECK_EQUAL(header67107.nBits, 0x1c2fb0caU);
    const CBlockHeader header151785 = ParseHeader(HEADER_151785_HEX);
    BOOST_CHECK_EQUAL(header151785.GetHash().GetHex(), HASH_151785);
    BOOST_CHECK(header151785.IsProofOfWork());
    const CBlockHeader header60540 = ParseHeader(HEADER_60540_HEX);
    BOOST_CHECK_EQUAL(header60540.GetHash().GetHex(), HASH_60540);
    BOOST_CHECK(header60540.IsProofOfWork());
}

/* Version 3 and 6 headers have a 32-bit time (80 bytes), version 7 a 64-bit one (84 bytes);
 * a header-only or hash read of a block clears its transactions and signature */
BOOST_AUTO_TEST_CASE(serialisation)
{
    for (const char* hex : {HEADER_1889995_HEX, HEADER_1890001_HEX}) {
        const std::vector<unsigned char> bytes = ParseHex(hex);
        CBlockHeader header = ParseHeader(hex);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << header;
        BOOST_CHECK(std::vector<unsigned char>(ss.begin(), ss.end()) == bytes);
        BOOST_CHECK_EQUAL(::GetSerializeSize(header, SER_NETWORK, PROTOCOL_VERSION), header.nVersion >= 7 ? 84U : 80U);
    }
    // A version 6 proof-of-work header (nonce not 0)
    CBlockHeader header6 = ParseHeader(HEADER_60540_HEX);
    header6.nVersion = VERSION_of_block_for_yac_049;
    CDataStream ss6(SER_NETWORK, PROTOCOL_VERSION);
    ss6 << header6;
    BOOST_CHECK_EQUAL(ss6.size(), 80U);
    CBlockHeader read6;
    ss6 >> read6;
    BOOST_CHECK_EQUAL(read6.nVersion, VERSION_of_block_for_yac_049);
    BOOST_CHECK_EQUAL(read6.nTime, header6.nTime);
    BOOST_CHECK_EQUAL(read6.nNonce, header6.nNonce);

    // The full block round trip
    const CBlock block = RealBlock(BLOCK_82204_HEX);
    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << block;
    BOOST_CHECK_EQUAL(HexStr(ssBlock.begin(), ssBlock.end()), BLOCK_82204_HEX);

    for (int nType : {SER_GETHASH, SER_BLOCKHEADERONLY}) {
        CDataStream ss(nType, PROTOCOL_VERSION);
        ss << block;
        BOOST_CHECK_EQUAL(ss.size(), 80U);
        CBlock read = ParseBlock(BLOCK_644_HEX);
        BOOST_REQUIRE(!read.vtx.empty() && !read.vchBlockSig.empty());
        ss >> read;
        BOOST_CHECK(read.vtx.empty());
        BOOST_CHECK(read.vchBlockSig.empty());
        BOOST_CHECK(read.hashMerkleRoot == block.hashMerkleRoot);
        BOOST_CHECK_EQUAL(read.GetHash().GetHex(), HASH_82204);
    }

    const CBlockHeader header = block.GetBlockHeader();
    BOOST_CHECK_EQUAL(header.nVersion, block.nVersion);
    BOOST_CHECK(header.hashPrevBlock == block.hashPrevBlock);
    BOOST_CHECK(header.hashMerkleRoot == block.hashMerkleRoot);
    BOOST_CHECK_EQUAL(header.nTime, block.nTime);
    BOOST_CHECK_EQUAL(header.nBits, block.nBits);
    BOOST_CHECK_EQUAL(header.nNonce, block.nNonce);
    BOOST_CHECK(header.blockHash.IsNull());
    BOOST_CHECK_EQUAL(header.GetHash().GetHex(), HASH_82204);
}

/* The stake entropy bit is the lowest bit of the hash; the log path gives the same */
BOOST_AUTO_TEST_CASE(stake_entropy_bit)
{
    const CBlock block82204 = RealBlock(BLOCK_82204_HEX); // hash ends in e4
    const CBlock block82217 = RealBlock(BLOCK_82217_HEX); // hash ends in 99
    BOOST_CHECK_EQUAL(block82204.GetStakeEntropyBit(82204), 0U);
    BOOST_CHECK_EQUAL(block82217.GetStakeEntropyBit(82217), 1U);
    for (bool fPrint : {false, true}) {
        StakeLogGuard log(fPrint);
        BOOST_CHECK_EQUAL(block82204.GetStakeEntropyBit(82204), 0U);
        BOOST_CHECK_EQUAL(block82217.GetStakeEntropyBit(82217), 1U);
    }
}

/* GetProofOfStake: the coinstake's first prevout and time for a proof-of-stake block, null for
 * proof of work; GetMaxTransactionTime */
BOOST_AUTO_TEST_CASE(proof_of_stake_and_transaction_times)
{
    RealKernel real;
    real.blockStake.GetHash();
    std::pair<COutPoint, unsigned int> stake = real.blockStake.GetProofOfStake();
    BOOST_CHECK(stake.first == COutPoint(real.txPrev().GetHash(), 0));
    BOOST_CHECK_EQUAL(stake.second, 1370591579U);
    stake = RealBlock(BLOCK_644_HEX).GetProofOfStake();
    BOOST_CHECK(stake.first.IsNull());
    BOOST_CHECK_EQUAL(stake.second, 0U);

    BOOST_CHECK_EQUAL(real.blockStake.GetMaxTransactionTime(), 1370591579);
    BOOST_CHECK_EQUAL(CBlock().GetMaxTransactionTime(), 0);
    CBlock block = PowBlock({NonStandard()});
    const ::int64_t nTime = block.GetBlockTime();
    block.vtx.push_back(block.vtx[0]);
    block.vtx.push_back(block.vtx[0]);
    block.vtx[1].nTime = nTime + 5;
    block.vtx[2].nTime = nTime - 3;
    BOOST_CHECK_EQUAL(block.GetMaxTransactionTime(), nTime + 5);
}

/* Merkle branches: each transaction's branch leads to the root; with an odd count the last
 * hash is paired with itself; index -1 gives 0 */
BOOST_AUTO_TEST_CASE(merkle_branches)
{
    for (const char* hex : {BLOCK_644_HEX, BLOCK_82204_HEX, BLOCK_67107_HEX}) {
        const CBlock block = RealBlock(hex);
        for (unsigned int i = 0; i < block.vtx.size(); i++) {
            BOOST_CHECK(CBlock::CheckMerkleBranch(block.vtx[i].GetHash(), block.GetMerkleBranch(i), i) == block.hashMerkleRoot);
        }
    }
    BOOST_CHECK(CBlock().BuildMerkleTree().IsNull());

    CBlock block = PowBlock({NonStandard()});
    block.vtx.push_back(block.vtx[0]);
    block.vtx[1].nTime += 1;
    block.vtx.push_back(block.vtx[0]);
    block.vtx[2].nTime += 2;
    std::vector<uint256> h;
    for (const CTransaction& tx : block.vtx) h.push_back(tx.GetHash());
    const uint256 h01 = Hash(BEGIN(h[0]), END(h[0]), BEGIN(h[1]), END(h[1]));
    const uint256 h22 = Hash(BEGIN(h[2]), END(h[2]), BEGIN(h[2]), END(h[2]));
    const uint256 root = Hash(BEGIN(h01), END(h01), BEGIN(h22), END(h22));
    // The tree is built on first use of GetMerkleBranch
    BOOST_CHECK(block.vMerkleTree.empty());
    std::vector<uint256> branch = block.GetMerkleBranch(2);
    BOOST_CHECK_EQUAL(block.vMerkleTree.size(), 6U);
    BOOST_REQUIRE_EQUAL(branch.size(), 2U);
    BOOST_CHECK(branch[0] == h[2]);
    BOOST_CHECK(branch[1] == h01);
    BOOST_CHECK(CBlock::CheckMerkleBranch(h[2], branch, 2) == root);
    for (int i = 0; i < 3; i++) BOOST_CHECK(CBlock::CheckMerkleBranch(h[i], block.GetMerkleBranch(i), i) == root);
    BOOST_CHECK(block.BuildMerkleTree() == root);
    BOOST_CHECK(CBlock::CheckMerkleBranch(h[0], block.GetMerkleBranch(0), -1).IsNull());

    // print() runs with and without a merkle tree
    block.print();
    RealBlock(BLOCK_644_HEX).print();
}

/* A block locator: the version is serialised except for hashing */
BOOST_AUTO_TEST_CASE(block_locator)
{
    CBlockLocator locator;
    BOOST_CHECK(locator.IsNull());
    const uint256 hash = uint256S(HASH_82204);
    locator = CBlockLocator(std::vector<uint256>{hash, uint256S(HASH_644)});
    BOOST_CHECK(!locator.IsNull());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << locator;
    BOOST_CHECK_EQUAL(ss.size(), 4U + 1U + 64U);
    CBlockLocator read;
    ss >> read;
    BOOST_CHECK(read.vHave == locator.vHave);
    CDataStream ssHash(SER_GETHASH, PROTOCOL_VERSION);
    ssHash << locator;
    BOOST_CHECK_EQUAL(ssHash.size(), 1U + 64U);
    locator.SetNull();
    BOOST_CHECK(locator.IsNull());
}

/* A new header is version 6, or version 7 once the next block is at or above the fork height */
BOOST_AUTO_TEST_CASE(set_null_version)
{
    BOOST_CHECK_EQUAL(CBlockHeader().nVersion, VERSION_of_block_for_yac_049);
    ConsensusGlobalsGuard globals;
    globals.Set(1, 21000);
    BOOST_CHECK_EQUAL(CBlockHeader().nVersion, VERSION_of_block_for_yac_05x_new);
    CBlock block;
    BOOST_CHECK_EQUAL(block.nVersion, VERSION_of_block_for_yac_05x_new);
    BOOST_CHECK(block.IsNull());
}

/* UpdateTime moves the time forward to the adjusted time, never back */
BOOST_AUTO_TEST_CASE(update_time)
{
    CBlock block = RealBlock(BLOCK_644_HEX);
    const ::int64_t nTime = block.GetBlockTime();
    {
        MockTimeGuard mocktime(nTime + 100);
        block.UpdateTime(nullptr);
        BOOST_CHECK_EQUAL(block.GetBlockTime(), nTime + 100);
    }
    {
        MockTimeGuard mocktime(nTime);
        block.UpdateTime(nullptr);
        BOOST_CHECK_EQUAL(block.GetBlockTime(), nTime + 100);
    }
}

/* SignBlock044 for a proof-of-work block: the first P2PK coinbase output whose key the
 * keystore has signs; other outputs are skipped */
BOOST_AUTO_TEST_CASE(sign_proof_of_work)
{
    const CKey key = NewKey();
    const CKey other = NewKey();
    CBasicKeyStore keystore;
    keystore.AddKey(key);

    CBlock block = PowBlock({P2PKH(key.GetPubKey()), P2PK(key.GetPubKey())});
    BOOST_CHECK(block.SignBlock044(keystore));
    BOOST_CHECK(!block.vchBlockSig.empty());
    BOOST_CHECK(key.GetPubKey().Verify(block.GetHash(), block.vchBlockSig));
    BOOST_CHECK(CheckBlockSignature(block));

    // A non-standard output is skipped when signing, but fails the check
    block = PowBlock({NonStandard(), P2PK(key.GetPubKey())});
    BOOST_CHECK(block.SignBlock044(keystore));
    BOOST_CHECK(key.GetPubKey().Verify(block.GetHash(), block.vchBlockSig));
    BOOST_CHECK(!CheckBlockSignature(block));

    // The key is not in the keystore, or no output is P2PK: "Sign failed"
    block = PowBlock({P2PK(other.GetPubKey())});
    BOOST_CHECK(!block.SignBlock044(keystore));
    BOOST_CHECK(block.vchBlockSig.empty());
    block = PowBlock({P2PKH(key.GetPubKey()), NonStandard()});
    BOOST_CHECK(!block.SignBlock044(keystore));
    BOOST_CHECK(block.vchBlockSig.empty());

    // The keystore has another key under the output key's id
    CBasicKeyStore wrong;
    wrong.AddKeyPubKey(other, key.GetPubKey());
    block = PowBlock({P2PK(key.GetPubKey())});
    BOOST_CHECK(!block.SignBlock044(wrong));
    BOOST_CHECK(block.vchBlockSig.empty());
}

/* SignBlock044 for a proof-of-stake block signs with the key of the coinstake's output 1 */
BOOST_AUTO_TEST_CASE(sign_proof_of_stake)
{
    const CKey key = NewKey();
    const CKey other = NewKey();
    CBasicKeyStore keystore;
    keystore.AddKey(key);

    CBlock block = PosBlock(P2PK(key.GetPubKey()));
    BOOST_REQUIRE(block.IsProofOfStake());
    BOOST_CHECK(block.SignBlock044(keystore));
    BOOST_CHECK(CheckBlockSignature(block));

    block = PosBlock(P2PK(other.GetPubKey()));
    BOOST_CHECK(!block.SignBlock044(keystore));
    BOOST_CHECK(block.vchBlockSig.empty());

    CBasicKeyStore wrong;
    wrong.AddKeyPubKey(other, key.GetPubKey());
    block = PosBlock(P2PK(key.GetPubKey()));
    BOOST_CHECK(!block.SignBlock044(wrong));

    block = PosBlock(P2PKH(key.GetPubKey()));
    BOOST_CHECK(!block.SignBlock044(keystore));
    block = PosBlock(NonStandard());
    BOOST_CHECK(!block.SignBlock044(keystore));
    BOOST_CHECK(block.vchBlockSig.empty());
}

#ifdef ENABLE_WALLET
/* SignBlock with a wallet: proof-of-work blocks and version 3 proof-of-stake blocks are signed
 * as by SignBlock044 */
BOOST_AUTO_TEST_CASE(sign_with_wallet)
{
    const CKey key = NewKey();
    CWallet wallet;
    {
        LOCK(wallet.cs_wallet);
        BOOST_REQUIRE(wallet.AddKeyPubKey(key, key.GetPubKey()));
    }
    CBlock block = PowBlock({P2PK(key.GetPubKey())});
    BOOST_CHECK(block.SignBlock(wallet));
    BOOST_CHECK(CheckBlockSignature(block));

    block = PosBlock(P2PK(key.GetPubKey()));
    BOOST_REQUIRE_EQUAL(block.nVersion, VERSION_of_block_for_yac_044_old);
    BOOST_CHECK(block.SignBlock(wallet));
    BOOST_CHECK(CheckBlockSignature(block));

    block = PosBlock(P2PK(NewKey().GetPubKey()));
    BOOST_CHECK(!block.SignBlock(wallet));
}
#endif

/* CheckBlockSignature: the genesis block needs an empty signature; real blocks verify; a
 * proof-of-work block needs a P2PK coinbase output whose key signed the hash, a proof-of-stake
 * block a P2PK output 1 of the coinstake */
BOOST_AUTO_TEST_CASE(block_signature)
{
    CBlock genesis = Params().GenesisBlock();
    BOOST_CHECK(genesis.vchBlockSig.empty());
    BOOST_CHECK(CheckBlockSignature(genesis));
    genesis.vchBlockSig = RealBlock(BLOCK_644_HEX).vchBlockSig;
    BOOST_CHECK(!CheckBlockSignature(genesis));

    for (const char* hex : {BLOCK_644_HEX, BLOCK_67107_HEX, BLOCK_82204_HEX, BLOCK_82217_HEX, BLOCK_82994_HEX}) {
        CBlock block = RealBlock(hex);
        BOOST_CHECK(CheckBlockSignature(block));
        CBlock changed = block;
        changed.vchBlockSig[10] ^= 1;
        BOOST_CHECK(!CheckBlockSignature(changed));
        CBlock unsigned_block = block;
        unsigned_block.vchBlockSig.clear();
        BOOST_CHECK(!CheckBlockSignature(unsigned_block));
    }

    // Proof of work: the signature does not verify with the only P2PK output's key, a
    // non-standard output, no P2PK output
    const CKey key = NewKey();
    const std::vector<unsigned char> sig644 = RealBlock(BLOCK_644_HEX).vchBlockSig;
    CBlock block = PowBlock({P2PK(key.GetPubKey())});
    block.vchBlockSig = sig644;
    BOOST_CHECK(!CheckBlockSignature(block));
    block = PowBlock({NonStandard()});
    block.vchBlockSig = sig644;
    BOOST_CHECK(!CheckBlockSignature(block));
    block = PowBlock({P2PKH(key.GetPubKey())});
    block.vchBlockSig = sig644;
    BOOST_CHECK(!CheckBlockSignature(block));

    // Proof of stake: output 1 not P2PK, or non-standard, with the real signature
    const std::vector<unsigned char> sig82204 = RealBlock(BLOCK_82204_HEX).vchBlockSig;
    const CScript script82204 = RealBlock(BLOCK_82204_HEX).vtx[1].vout[1].scriptPubKey;
    const CPubKey pubkey82204(std::vector<unsigned char>(script82204.begin() + 1, script82204.begin() + 34));
    block = PosBlock(P2PK(pubkey82204));
    block.vchBlockSig = sig82204;
    BOOST_CHECK(CheckBlockSignature(block));
    block = PosBlock(P2PKH(pubkey82204));
    block.vchBlockSig = sig82204;
    BOOST_CHECK(!CheckBlockSignature(block));
    block = PosBlock(NonStandard());
    block.vchBlockSig = sig82204;
    BOOST_CHECK(!CheckBlockSignature(block));
}

/* CheckBlock on real proof-of-stake blocks: they pass with and without the signature check */
BOOST_AUTO_TEST_CASE(check_block_real)
{
    for (const char* hex : {BLOCK_82204_HEX, BLOCK_82217_HEX, BLOCK_82994_HEX, BLOCK_644_HEX, BLOCK_67107_HEX}) {
        const CBlock block = RealBlock(hex);
        for (bool fCheckSig : {false, true}) {
            CheckResult r = Check(block, true, true, fCheckSig);
            BOOST_CHECK_MESSAGE(r.fValid, block.GetHash().GetHex() << " " << r.strReason);
        }
    }
}

/* The proof-of-stake rules of CheckBlock: an empty coinbase with one output, the coinstake's
 * time equal to the block's and, with fCheckSig, a valid signature */
BOOST_AUTO_TEST_CASE(check_block_proof_of_stake_rules)
{
    const CBlock real = RealBlock(BLOCK_82994_HEX);
    BOOST_REQUIRE(real.IsProofOfStake());

    CBlock block = real;
    block.vtx[0].vout[0] = CTxOut(1, P2PK(NewKey().GetPubKey()));
    CheckRejected(block, false, 100, "bad-cb-notempty");
    block = real;
    block.vtx[0].vout.push_back(block.vtx[0].vout[0]);
    CheckRejected(block, false, 100, "bad-cb-notempty");

    block = real;
    block.vtx[1].nTime -= 1;
    CheckRejected(block, false, 50, "bad-cs-time");

    block = real;
    block.vchBlockSig[10] ^= 1;
    CheckRejected(block, true, 100, "");
    BOOST_CHECK(Check(block, true, true, false).fValid);
    block.vchBlockSig.clear();
    CheckRejected(block, true, 100, "");
    BOOST_CHECK(Check(block, true, true, false).fValid);
}

/* A proof-of-work block takes the proof-of-work branch: the coinbase may be at most 2 hours
 * later than the block */
BOOST_AUTO_TEST_CASE(check_block_proof_of_work_branch)
{
    CBlock block = RealBlock(BLOCK_644_HEX);
    block.vtx[0].nTime = block.GetBlockTime() + 2 * 60 * 60 + 1;
    CheckRejected(block, false, 50, "bad-cb-time");
    // within 2 hours the transaction time check rejects it
    block.vtx[0].nTime = block.GetBlockTime() + 2 * 60 * 60;
    CheckRejected(block, false, 50, "bad-tx-time");
}

/* fChecked is set only when proof of work and the merkle root were checked; then CheckBlock
 * returns at once */
BOOST_AUTO_TEST_CASE(check_block_checked_flag)
{
    for (const char* hex : {BLOCK_644_HEX, BLOCK_82204_HEX}) {
        for (int i = 0; i < 4; i++) {
            const bool fCheckPOW = i & 1, fCheckMerkleRoot = i & 2;
            CBlock block = RealBlock(hex);
            CValidationState state;
            BOOST_CHECK(CheckBlock(block, state, Params().GetConsensus(), fCheckPOW, fCheckMerkleRoot, false));
            BOOST_CHECK_EQUAL(block.fChecked, fCheckPOW && fCheckMerkleRoot);
        }
    }
    CBlock block = RealBlock(BLOCK_82204_HEX);
    BOOST_CHECK(Check(block, true, true, true).fValid);
    CValidationState state;
    BOOST_CHECK(CheckBlock(block, state, Params().GetConsensus()));
    BOOST_CHECK(block.fChecked);
    block.vtx[1].nTime -= 1;
    BOOST_CHECK(CheckBlock(block, state, Params().GetConsensus()));
}

/* ProcessNewBlock with block 82204 whose index entry is known (on a synthetic chain with the
 * kernel's modifier): the proof-of-stake check of AcceptBlock passes and records the kernel
 * hash, or fails and leaves the entry without data and not marked invalid */
BOOST_AUTO_TEST_CASE(contextual_proof_of_stake_check)
{
    ValueGuard<bool> checkBlockIndex(fCheckBlockIndex, false);
    RealKernel real;
    const CDiskBlockPos pos = WriteBlockFile(real.blockFrom, 7);
    IndexFirstTx(real.blockFrom, pos);

    for (bool fPass : {true, false}) {
        SyntheticChain chain;
        KernelChain k = BuildKernelChain(chain, real.blockFrom,
                                         fPass ? BLOCK_82203_TIME : real.blockFrom.GetBlockTime() + 5 * DAY);
        // The coinbase starts with the height
        SetHeights(k.pindexPrev, 82203, chain.Genesis());
        auto pblock = std::make_shared<CBlock>(RealBlock(BLOCK_82204_HEX));
        CBlockIndex* pindex = chain.Add(k.pindexPrev, pblock->GetBlockTime(), pblock->nBits);
        pindex->SetProofOfStake();
        chain.Register(pindex, pblock->GetHash());
        BOOST_REQUIRE_EQUAL(pindex->nHeight, 82204);

        BOOST_CHECK_EQUAL(ProcessNewBlock(Params(), pblock, true, nullptr), fPass);
        BOOST_CHECK(pblock->fChecked);
        BOOST_CHECK_EQUAL((pindex->nStatus & BLOCK_HAVE_DATA) != 0, fPass);
        BOOST_CHECK_EQUAL(pindex->nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_CHECK_EQUAL(pindex->hashProofOfStake.GetHex(), fPass ? PROOF_HASH_82204 : uint256().GetHex());
        BOOST_CHECK(chainActive.Tip() == chain.Genesis());
        // Writes the dirty index entries while they live
        FlushStateToDisk();
    }
}

/* Coin age of the coinstake of 82204: 98.02 coins for 2593446 s (30 days and 1446 s) is 2942
 * coin-days (Python: v * dt // 10**4 * 10**4 // 10**6 // 86400) */
BOOST_AUTO_TEST_CASE(coin_age)
{
    CoinOnDisk disk;
    const CTransaction& coinstake = disk.real.coinstake();
    CoinAge age = GetAge(coinstake, disk.coins.view);
    BOOST_CHECK(age.fOk);
    BOOST_CHECK_EQUAL(age.nCoinAge, 2942U);
    {
        ArgGuard print("-printcoinage", "1");
        age = GetAge(coinstake, disk.coins.view);
        BOOST_CHECK(age.fOk);
        BOOST_CHECK_EQUAL(age.nCoinAge, 2942U);
    }

    // A coinbase has no coin age
    age = GetAge(disk.real.blockStake.vtx[0], disk.coins.view);
    BOOST_CHECK(age.fOk);
    BOOST_CHECK_EQUAL(age.nCoinAge, 0U);

    // A coin not in the view is skipped
    CoinView empty;
    age = GetAge(coinstake, empty.view);
    BOOST_CHECK(age.fOk);
    BOOST_CHECK_EQUAL(age.nCoinAge, 0U);

    // Exactly 30 days after the coin's block the coin counts (2940 coin-days); a second
    // earlier it does not
    CTransaction tx = coinstake;
    tx.nTime = disk.real.blockFrom.GetBlockTime() + 30 * DAY;
    age = GetAge(tx, disk.coins.view);
    BOOST_CHECK(age.fOk);
    BOOST_CHECK_EQUAL(age.nCoinAge, 2940U);
    tx.nTime -= 1;
    age = GetAge(tx, disk.coins.view);
    BOOST_CHECK(age.fOk);
    BOOST_CHECK_EQUAL(age.nCoinAge, 0U);

    // The coin is later than the transaction
    CoinView later;
    later.Add(coinstake.vin[0].prevout, disk.real.txPrev().vout[0], 644, coinstake.nTime + 1);
    BOOST_CHECK(!GetAge(coinstake, later.view).fOk);

    // Without the transaction index
    {
        ValueGuard<bool> txindex(fTxIndex, false);
        BOOST_CHECK(!GetAge(coinstake, disk.coins.view).fOk);
    }

    // A coin without an index entry, an entry that points at another transaction, and one past
    // the end of the block file
    const uint256 hashMissing = uint256S("0101010101010101010101010101010101010101010101010101010101010101");
    const uint256 hashOther = uint256S("0202020202020202020202020202020202020202020202020202020202020202");
    const uint256 hashPastEnd = uint256S("0303030303030303030303030303030303030303030303030303030303030303");
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.emplace_back(hashOther, CDiskTxPos(disk.pos, 1));
    vPos.emplace_back(hashPastEnd, CDiskTxPos(CDiskBlockPos(7, disk.pos.nPos + 100000), 1));
    BOOST_REQUIRE(pblocktree->WriteTxIndex(vPos));
    for (const uint256& hash : {hashMissing, hashOther, hashPastEnd}) {
        CoinView coins;
        CTransaction spend = coinstake;
        spend.vin[0].prevout = COutPoint(hash, 0);
        coins.Add(spend.vin[0].prevout, disk.real.txPrev().vout[0], 644, disk.real.txPrev().nTime);
        BOOST_CHECK(!GetAge(spend, coins.view).fOk);
    }
}

/* The stake reward: 5 % a coin-year, coin age * 50000 * 33 / 12053 in units (Python) */
BOOST_AUTO_TEST_CASE(proof_of_stake_reward)
{
    for (bool fLog : {false, true}) {
        ValueGuard<bool> debug(fDebug, fLog);
        ArgGuard print("-printcreation", fLog ? "1" : "0");
        BOOST_CHECK_EQUAL(GetProofOfStakeReward(0, BITS_82204, 1370591579), 0);
        BOOST_CHECK_EQUAL(GetProofOfStakeReward(1, BITS_82204, 1370591579), 136);
        BOOST_CHECK_EQUAL(GetProofOfStakeReward(365, BITS_82204, 1370591579), 49966);
        BOOST_CHECK_EQUAL(GetProofOfStakeReward(2942, BITS_82204, 1370591579), 402746);
        BOOST_CHECK_EQUAL(GetProofOfStakeReward(1000000, 0x1d03ffff, 0), 136895378);
    }
}

/* CheckTxInputs on the coinstake of 82204 in a block below the fork: the reward may be the
 * coin-age reward plus 0.01 coin (402746 + 10000 units); the real one is 400000 */
BOOST_AUTO_TEST_CASE(coinstake_inputs)
{
    CoinOnDisk disk;
    CBlockIndex indexBlock;
    indexBlock.nHeight = 82204;
    indexBlock.nBits = BITS_82204;

    auto check = [&](const CTransaction& tx, int nExpectedDoS, const std::string& strReason) {
        CValidationState state;
        const bool fValid = Consensus::CheckTxInputs(tx, state, disk.coins.view, 82204, &indexBlock);
        int nDoS = 0;
        BOOST_CHECK_EQUAL(fValid, nExpectedDoS < 0);
        state.IsInvalid(nDoS);
        BOOST_CHECK_EQUAL(nDoS, std::max(nExpectedDoS, 0));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), strReason);
    };
    const CTransaction& coinstake = disk.real.coinstake();
    BOOST_CHECK_EQUAL(coinstake.GetValueOut() - disk.real.txPrev().vout[0].nValue, 400000);
    check(coinstake, -1, "");
    CTransaction tx = coinstake;
    tx.vout[2].nValue += 12746;
    check(tx, -1, "");
    tx.vout[2].nValue += 1;
    check(tx, 100, "bad-txns-coinstake-too-large");
    {
        ValueGuard<bool> txindex(fTxIndex, false);
        check(coinstake, 100, "unable to get coin age for coinstake");
    }
}

/* Chain trust. Known answers (Python): 2**256 // (target + 1) for proof of stake before the
 * switch time; powLimit // target for proof of work after it */
BOOST_AUTO_TEST_CASE(block_trust)
{
    const ::int64_t nBefore = CONSECUTIVE_STAKE_SWITCH_TIME - 1;
    const ::int64_t nAfter = CONSECUTIVE_STAKE_SWITCH_TIME;
    auto entry = [](::int64_t nTime, unsigned int nBits, bool fProofOfStake, CBlockIndex* pprev) {
        CBlockIndex index;
        index.nTime = nTime;
        index.nBits = nBits;
        index.pprev = pprev;
        if (fProofOfStake) index.SetProofOfStake();
        return index;
    };
    // powLimit // target for 0x1d00ffff, that plus 1, and twice it
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    const std::string strPow = "4096", strPowPlusOne = "4097", strPowDoubled = "8192";
#else
    const std::string strPow = "536879104", strPowPlusOne = "536879105", strPowDoubled = "1073758208";
#endif

    // A target of 0 has no trust
    BOOST_CHECK_EQUAL(entry(nAfter, 0, false, nullptr).GetBlockTrust().ToString(), "0");
    BOOST_CHECK_EQUAL(entry(nBefore, 0, true, nullptr).GetBlockTrust().ToString(), "0");

    // Before the switch time
    BOOST_CHECK_EQUAL(entry(nBefore, 0x1e0fffff, true, nullptr).GetBlockTrust().ToString(), "1048577");
    BOOST_CHECK_EQUAL(entry(nBefore, 0x1d00ffff, true, nullptr).GetBlockTrust().ToString(), "4295032833");
    BOOST_CHECK_EQUAL(entry(nBefore, 0x1d00ffff, false, nullptr).GetBlockTrust().ToString(), "1");

    // After it
    CBlockIndex powRoot = entry(nAfter, 0x1d00ffff, false, nullptr);
    CBlockIndex posRoot = entry(nAfter, 0x1d00ffff, true, nullptr);
    BOOST_CHECK_EQUAL(powRoot.GetBlockTrust().ToString(), "1");
    BOOST_CHECK_EQUAL(posRoot.GetBlockTrust().ToString(), "1");
    CBlockIndex pow = entry(nAfter, 0x1d00ffff, false, &powRoot);
    CBlockIndex pos = entry(nAfter, 0x1d00ffff, true, &powRoot);
    BOOST_CHECK_EQUAL(pow.GetBlockTrust().ToString(), strPow);
    BOOST_CHECK_EQUAL(entry(nAfter, 0x1d00ffff, true, &posRoot).GetBlockTrust().ToString(), "0");
    BOOST_CHECK_EQUAL(entry(nAfter, 0x1d00ffff, true, &pow).GetBlockTrust().ToString(),
                      strPowPlusOne);
    BOOST_CHECK_EQUAL(entry(nAfter, 0x1d00ffff, false, &pos).GetBlockTrust().ToString(),
                      strPowDoubled);

    // On testnet the rules after the switch time apply at any time
    ValueGuard<bool> testnet(fTestNet, true);
    BOOST_CHECK_EQUAL(entry(nBefore, 0x1e0fffff, true, nullptr).GetBlockTrust().ToString(), "1");
    BOOST_CHECK_EQUAL(entry(nBefore, 0x1d00ffff, true, &posRoot).GetBlockTrust().ToString(), "0");
}

/* Without an active chain a new header is version 6, whatever the fork height */
BOOST_FIXTURE_TEST_CASE(set_null_without_chain, BasicTestingSetup)
{
    BOOST_REQUIRE_EQUAL(chainActive.Height(), -1);
    ConsensusGlobalsGuard globals;
    globals.Set(0, 21000);
    BOOST_CHECK_EQUAL(CBlockHeader().nVersion, VERSION_of_block_for_yac_049);
}

BOOST_AUTO_TEST_SUITE_END()
