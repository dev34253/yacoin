// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Header hashing: CBlockHeader::CalculateHash() of the header of main network
// block 1,911,210 (version 7), at N-factor 21 (the main network's) and at
// N-factor 4 (the test networks'). CalculateHash, not GetHash: GetHash keeps
// the result of the first call. Every result is checked against the header's
// known hash at that N-factor.

#include "bench/bench.h"

#include "primitives/block.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include <string>

namespace {
/** Mainnet block 1,911,210, as `getblockheader <hash> false` returns it */
const char* const MAINNET_HEADER_1911210 =
    "07000000bf24dff3e63105d81257ed9842c0aa82d8af213b84115feb9ec8a55e7d0e0000"
    "299e1fcc76f2681623ff40bbbc3b43c780fae691b0dbb7657d7acb3489d55c85"
    "8a7f446400000000ffff0f1e80000a56";

/** Sets nFactorAtHardfork for its lifetime */
class NFactorGuard
{
    const unsigned char nSaved;

public:
    explicit NFactorGuard(unsigned char nFactor) : nSaved(nFactorAtHardfork) { nFactorAtHardfork = nFactor; }
    ~NFactorGuard() { nFactorAtHardfork = nSaved; }
};

CBlockHeader MainnetHeader()
{
    CDataStream stream(ParseHex(MAINNET_HEADER_1911210), SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader header;
    stream >> header;
    benchmark::Require(stream.empty() && header.nVersion == VERSION_of_block_for_yac_05x_new,
                       "the header of block 1,911,210 does not parse as a version 7 header");
    return header;
}

void HashHeader(benchmark::State& state, unsigned char nFactor, const std::string& strExpected)
{
    const CBlockHeader header = MainnetHeader();
    const uint256 expected = uint256S(strExpected);
    const NFactorGuard guard(nFactor);
    while (state.KeepRunning()) {
        const uint256 hash = header.CalculateHash();
        if (hash != expected) {
            throw benchmark::Failure(strprintf("hash at N-factor %d is %s, expected %s", nFactor, hash.GetHex(), strExpected));
        }
    }
}
} // namespace

static void HeaderHashNFactor21(benchmark::State& state)
{
    HashHeader(state, 21, "000009e3b1cc249ba64c3749430b96cf0f3c25acbb2bd3cb0b69e3b28288607b");
}

static void HeaderHashNFactor4(benchmark::State& state)
{
    HashHeader(state, 4, "957765ad62f34a1842a0b3af8eb5dd79e40ef9ea268f0993012aab059e52e956");
}

BENCHMARK(HeaderHashNFactor21);
BENCHMARK(HeaderHashNFactor4);
