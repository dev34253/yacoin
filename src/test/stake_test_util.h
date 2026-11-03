// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_STAKE_TEST_UTIL_H
#define YACOIN_TEST_STAKE_TEST_UTIL_H

// Helpers of the legacy proof-of-stake tests: guards for globals, arguments and the mock
// time, real mainnet blocks 644 and 82204 (the coin and the coinstake of the lowest
// proof-of-stake block) and synthetic block index entries for their kernel.

#include "chainparams.h"
#include "primitives/block.h"
#include "streams.h"
#include "txdb.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

const ::int64_t DAY = 24 * 60 * 60;
const unsigned int POW_BITS = 0x1e0fffff;

/** Sets the fork height above the genesis block before the chain is loaded */
struct StakeForkHeight {
    ConsensusGlobalsGuard globals;
    StakeForkHeight() { globals.Set(1890000, 21000); }
};

/** Main network, fork height 1890000: the genesis block gets its stake modifier when it is
 * loaded, as on a node */
struct KernelSetup : public StakeForkHeight, public TestingSetup {
    KernelSetup() : StakeForkHeight(), TestingSetup(CBaseChainParams::MAIN) {}
};

/** Sets a variable while it lives */
template <typename T>
struct ValueGuard {
    T& m_ref;
    T m_saved;
    ValueGuard(T& ref, T value) : m_ref(ref), m_saved(ref) { ref = value; }
    ~ValueGuard() { m_ref = m_saved; }
};

/** Reaches the protected maps of gArgs through pointers to members formed in a derived class */
class ArgsAccess : public ArgsManager
{
public:
    static std::map<std::string, std::string>& MapArgs() { return gArgs.*(&ArgsAccess::mapArgs); }
    static std::map<std::string, std::vector<std::string> >& MapMultiArgs() { return gArgs.*(&ArgsAccess::mapMultiArgs); }
};

/** Sets an argument of gArgs while it lives; restores its value, or unsets it if it was unset */
struct ArgGuard {
    const std::string m_arg;
    const bool m_fWasSet;
    std::string m_value;
    std::vector<std::string> m_values;
    ArgGuard(const std::string& arg, const std::string& value) : m_arg(arg), m_fWasSet(gArgs.IsArgSet(arg))
    {
        if (m_fWasSet) {
            m_value = ArgsAccess::MapArgs()[arg];
            m_values = ArgsAccess::MapMultiArgs()[arg];
        }
        gArgs.ForceSetArg(arg, value);
    }
    ~ArgGuard()
    {
        if (m_fWasSet) {
            ArgsAccess::MapArgs()[m_arg] = m_value;
            ArgsAccess::MapMultiArgs()[m_arg] = m_values;
        } else {
            ArgsAccess::MapArgs().erase(m_arg);
            ArgsAccess::MapMultiArgs().erase(m_arg);
        }
    }
};

/** -debug on, and -printstakemodifier if fPrint, while it lives */
struct StakeLogGuard {
    ValueGuard<bool> debug{fDebug, true};
    ArgGuard print;
    explicit StakeLogGuard(bool fPrint) : print("-printstakemodifier", fPrint ? "1" : "0") {}
};

struct MockTimeGuard {
    explicit MockTimeGuard(::int64_t nTime) { SetMockTime(nTime); }
    ~MockTimeGuard() { SetMockTime(0); }
};

/** A registered block index entry on top of pprev (nullptr: genesis) with the given entropy bit */
inline CBlockIndex* AddBlock(SyntheticChain& chain, CBlockIndex* pprev, ::int64_t nTime, unsigned int nEntropyBit = 1)
{
    CBlockIndex* pindex = chain.Add(pprev, nTime, POW_BITS);
    chain.Register(pindex);
    pindex->SetStakeEntropyBit(nEntropyBit);
    return pindex;
}

// Mainnet data, read with getblock <hash> false from a yacoind built from master commit 6d723834
// of 2026-10-18 and synced to height 1964924: block 644, whose coinbase
// is the coin staked in block 82204, the lowest proof-of-stake block, and block 82204. The kernel
// of 82204 uses the stake modifier of block 64327.
const char* const BLOCK_644_HEX =
    "030000004c06edad08eaa0057278e7ad7131c12f7b2aa16c4de2e07866c74f8aaf0b0000f4ed0aafca5b6b9db4708956ec463f"
    "c37910538d31f673856ea2b6450188cc37b5fe895101310e1e901900000101000000b5fe89510100000000000000000000000000"
    "00000000000000000000000000000000000000ffffffff0c028402010e062f503253482fffffffff01a0aad70500000000232103"
    "54c0e1446ae9bd305ae8899a009a44775a31ce0292cad8f6bee00d7263b59685ac00000000473045022065d7bafd8338278ce26a"
    "ed9c92874f0b99a62306b723f27032cd2b90bddea8ee022100a44ac0e94ea3a6faa47c61c43c67e7d7c66689a244072521dca3e6"
    "ee7c068613";
const char* const BLOCK_82204_HEX =
    "0300000091c426b67f34fc33154c1358b76773f504d0d6c9fd0b4c9b34686f1e00000000015a4f248441475b271acbec093226615e"
    "e24d731f721ae8f847841a4d1864fb5b91b151ffff0f1e0000000002010000005b91b1510100000000000000000000000000000000"
    "00000000000000000000000000000000ffffffff0d031c41010138062f503253482fffffffff01000000000000000000000000000100"
    "00005b91b15101f4ed0aafca5b6b9db4708956ec463fc37910538d31f673856ea2b6450188cc37000000004a493046022100e64452"
    "8196f915becc4d2f96e7f166b3c44ad6ce3796be9f919cf473385990b9022100e66d0a45296da31dde405372c91450ffc910a9d7c4"
    "bea4235344e14271f4c3b001ffffffff0300000000000000000090e2ee020000000023210354c0e1446ae9bd305ae8899a009a4477"
    "5a31ce0292cad8f6bee00d7263b59685ac90e2ee020000000023210354c0e1446ae9bd305ae8899a009a44775a31ce0292cad8f6be"
    "e00d7263b59685ac00000000463044022009ff758e92a00c8c9843792ff0054672ba8d3030c619731529ce8a5f86050a7a02205460"
    "2b91e6cefb63579cc455eb47bef4c3b8c510ce0a287afd98efa0a4bc2095";
const ::int64_t MODIFIER_64327_TIME = 1368770430;
const ::uint64_t MODIFIER_64327 = 0x79867109da3e3e5d;
const ::int64_t BLOCK_82203_TIME = 1370591604;
const unsigned int BITS_82204 = 0x1e0fffff;
const char* const PROOF_HASH_82204 = "00000a65a901336eddd0e26e44b9fc42e498cc596563f0c4ad441c813ce2e5c2";
// The coin is the first transaction of block 644: after the 80-byte header and the
// one-byte transaction count
const unsigned int TX_PREV_OFFSET = 81;

inline CBlock ParseBlock(const char* hex)
{
    CDataStream ss(ParseHex(hex), SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    ss >> block;
    return block;
}

/** Blocks 644 and 82204 */
struct RealKernel {
    CBlock blockFrom = ParseBlock(BLOCK_644_HEX);
    CBlock blockStake = ParseBlock(BLOCK_82204_HEX);
    const CTransaction& txPrev() const { return blockFrom.vtx[0]; }
    const CTransaction& coinstake() const { return blockStake.vtx[1]; }
};

/** Index entries for a kernel whose coin is in blockFrom */
struct KernelChain {
    CBlockIndex* pindexFrom = nullptr;
    CBlockIndex* pindexModifier = nullptr;
    CBlockIndex* pindexPrev = nullptr;
};

/** blockFrom under its real hash, then one entry a day up to nTimeEnd (the last entry, the
 * coinstake's parent); the entry a day after blockFrom has a generated modifier too early for
 * the kernel, and an entry at block 64327's time (if before nTimeEnd) has 64327's modifier */
inline KernelChain BuildKernelChain(SyntheticChain& chain, const CBlockHeader& blockFrom, ::int64_t nTimeEnd)
{
    std::vector< ::int64_t> vTimes;
    for (::int64_t nTime = blockFrom.GetBlockTime() + DAY; nTime < nTimeEnd; nTime += DAY) vTimes.push_back(nTime);
    if (MODIFIER_64327_TIME < nTimeEnd) vTimes.push_back(MODIFIER_64327_TIME);
    vTimes.push_back(nTimeEnd);
    std::sort(vTimes.begin(), vTimes.end());

    KernelChain k;
    k.pindexFrom = chain.Add(nullptr, blockFrom.GetBlockTime(), blockFrom.nBits);
    chain.Register(k.pindexFrom, blockFrom.GetHash());
    CBlockIndex* pindex = k.pindexFrom;
    for (::int64_t nTime : vTimes) {
        pindex = AddBlock(chain, pindex, nTime);
        if (nTime == blockFrom.GetBlockTime() + DAY) pindex->SetStakeModifier(0x5e5e5e5e5e5e5e5e, true);
        if (nTime == MODIFIER_64327_TIME) {
            pindex->SetStakeModifier(MODIFIER_64327, true);
            k.pindexModifier = pindex;
        }
    }
    k.pindexPrev = pindex;
    return k;
}

/** Writes a block to block file nFile (at its start, after the network magic and size) */
inline CDiskBlockPos WriteBlockFile(const CBlock& block, int nFile)
{
    CDiskBlockPos pos(nFile, 0);
    CAutoFile file(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    BOOST_REQUIRE(!file.IsNull());
    file << FLATDATA(Params().MessageStart()) << (unsigned int)GetSerializeSize(file, block);
    pos.nPos = (unsigned int)ftell(file.Get());
    file << block;
    return pos;
}

/** Points the transaction index entry of the block's first transaction at the block */
inline void IndexFirstTx(const CBlock& block, const CDiskBlockPos& pos)
{
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.emplace_back(block.vtx[0].GetHash(), CDiskTxPos(pos, GetSizeOfCompactSize(block.vtx.size())));
    BOOST_REQUIRE(pblocktree->WriteTxIndex(vPos));
}

#endif // YACOIN_TEST_STAKE_TEST_UTIL_H
