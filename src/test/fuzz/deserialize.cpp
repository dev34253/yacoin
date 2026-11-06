// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Fuzz targets that deserialise one object each. An input is read as a
// network stream: its first 4 bytes are the stream version, the rest is the
// object. Inputs over 1 MiB and inputs without a version are ignored, and a
// read past the end of the input ends the run.

#if defined(HAVE_CONFIG_H)
#include "config/yacoin-config.h"
#endif

#include "test/fuzz/fuzz.h"

#include "addrdb.h"
#include "addrman.h"
#include "bloom.h"
#include "chain.h"
#include "coins.h"
#include "compressor.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "streams.h"
#include "undo.h"
#include "version.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ios>

namespace {
const size_t MAX_INPUT_SIZE = 1 << 20;

/** Fills ds with the input and sets its version from the first 4 bytes;
 * false if the input is to be ignored. */
bool OpenInput(const FuzzBufferType& buffer, CDataStream& ds)
{
    if (buffer.size() > MAX_INPUT_SIZE) return false;
    ds = CDataStream(buffer, SER_NETWORK, INIT_PROTO_VERSION);
    try {
        int nVersion;
        ds >> nVersion;
        ds.SetVersion(nVersion);
    } catch (const std::ios_base::failure&) {
        return false;
    }
    return true;
}

/** Deserialises one T from the input */
template <typename T>
void DeserializeInput(const FuzzBufferType& buffer)
{
    CDataStream ds(SER_NETWORK, INIT_PROTO_VERSION);
    if (!OpenInput(buffer, ds)) return;
    try {
        T obj;
        ds >> obj;
    } catch (const std::ios_base::failure&) {
    }
}
} // namespace

FUZZ_TARGET(block_deserialize)
{
    // Planted for a CI run that shows the job fails; never merged.
    if (buffer.size() == 8 && std::memcmp(buffer.data(), "PLANTED!", 8) == 0) std::abort();
    DeserializeInput<CBlock>(buffer);
}

FUZZ_TARGET(transaction_deserialize)
{
    CDataStream ds(SER_NETWORK, INIT_PROTO_VERSION);
    if (!OpenInput(buffer, ds)) return;
    try {
        CTransaction tx(deserialize, ds);
    } catch (const std::ios_base::failure&) {
    }
}

FUZZ_TARGET(block_locator_deserialize)
{
    DeserializeInput<CBlockLocator>(buffer);
}

FUZZ_TARGET(blockmerkleroot)
{
    CDataStream ds(SER_NETWORK, INIT_PROTO_VERSION);
    if (!OpenInput(buffer, ds)) return;
    try {
        CBlock block;
        ds >> block;
        block.BuildMerkleTree();
    } catch (const std::ios_base::failure&) {
    }
}

FUZZ_TARGET(addrman_deserialize)
{
    DeserializeInput<CAddrMan>(buffer);
}

FUZZ_TARGET(block_header_deserialize)
{
    DeserializeInput<CBlockHeader>(buffer);
}

FUZZ_TARGET(banentry_deserialize)
{
    DeserializeInput<CBanEntry>(buffer);
}

FUZZ_TARGET(txundo_deserialize)
{
    DeserializeInput<CTxUndo>(buffer);
}

FUZZ_TARGET(blockundo_deserialize)
{
    DeserializeInput<CBlockUndo>(buffer);
}

FUZZ_TARGET(coins_deserialize)
{
    DeserializeInput<Coin>(buffer);
}

FUZZ_TARGET(netaddr_deserialize)
{
    DeserializeInput<CNetAddr>(buffer);
}

FUZZ_TARGET(service_deserialize)
{
    DeserializeInput<CService>(buffer);
}

FUZZ_TARGET(messageheader_deserialize)
{
    CDataStream ds(SER_NETWORK, INIT_PROTO_VERSION);
    if (!OpenInput(buffer, ds)) return;
    try {
        CMessageHeader mh;
        ds >> mh;
        (void)mh.IsValid();
    } catch (const std::ios_base::failure&) {
    }
}

FUZZ_TARGET(address_deserialize)
{
    DeserializeInput<CAddress>(buffer);
}

FUZZ_TARGET(inv_deserialize)
{
    DeserializeInput<CInv>(buffer);
}

FUZZ_TARGET(bloomfilter_deserialize)
{
    DeserializeInput<CBloomFilter>(buffer);
}

FUZZ_TARGET(diskblockindex_deserialize)
{
    DeserializeInput<CDiskBlockIndex>(buffer);
}

FUZZ_TARGET(txoutcompressor_deserialize)
{
    CDataStream ds(SER_NETWORK, INIT_PROTO_VERSION);
    if (!OpenInput(buffer, ds)) return;
    CTxOut to;
    CTxOutCompressor toc(to);
    try {
        ds >> toc;
    } catch (const std::ios_base::failure&) {
    }
}
