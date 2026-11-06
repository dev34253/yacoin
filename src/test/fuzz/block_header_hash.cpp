// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// A block header, deserialised as deserialize.cpp's targets read their
// objects (the first 4 bytes of the input are the stream version), then
// hashed: its proof-of-work hash and its SHA-256 hash, at the test networks' N-factor.

#include "test/fuzz/fuzz.h"
#include "test/fuzz/fuzz_util.h"

#include "primitives/block.h"
#include "streams.h"
#include "util.h"
#include "version.h"

#include <ios>

namespace {
/** The test networks' N-factor */
void UseTestNetworkNFactor()
{
    fTestNet = true;
    nFactorAtHardfork = 4;
}
} // namespace

FUZZ_TARGET_INIT(block_header_hash, UseTestNetworkNFactor)
{
    CDataStream ds(SER_NETWORK, INIT_PROTO_VERSION);
    if (!OpenInput(buffer, ds)) return;
    CBlockHeader header;
    try {
        ds >> header;
    } catch (const std::ios_base::failure&) {
        return;
    }
    UseTestNetworkNFactor();
    (void)header.GetHash();
    UseTestNetworkNFactor();
    (void)header.GetSHA256Hash();
    // Both again, from the values the first calls kept
    UseTestNetworkNFactor();
    (void)header.GetHash();
    UseTestNetworkNFactor();
    (void)header.GetSHA256Hash();
}
