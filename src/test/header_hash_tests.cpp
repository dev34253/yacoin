// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block-header (proof-of-work) hash known answers, task P0-19 (plan 0.2e,
// review A2, B4). Phase 0 pins what the code does today:
//
// - CBlockHeader::CalculateHash (primitives/block.h:126-219) hashes the raw
//   memory of block_header (v>=7, #pragma pack(1), 84 bytes, 64-bit time)
//   or old_block_header (v<7, 80 bytes) with scrypt_hash (scrypt.cpp:108),
//   i.e. scrypt-jane with Keccak-512 and ChaCha20/8, password = salt =
//   header, N = 2^(Nfactor+1), r = p = 1;
// - v<7: N-factor from the timestamp table (block.h:148-198, 4..25);
//   v>=7: the global nFactorAtHardfork (21 mainnet, 4 functional tests,
//   0 in test_bitcoin);
// - GetNfactor (main.cpp:100-129, display only) and the GetHash() cache.
//
// The expected hashes in test/data/header_hash_vectors.json come from an
// independent Python model (contrib/testing/header_hash_vectors.py) and the
// upstream scrypt-jane, not from this code. Vectors whose N-factor is above
// YACOIN_HEADER_HASH_MAX_NFACTOR (default 21, the highest N-factor of real
// mainnet blocks) are skipped: N-factor 25 needs 8 GiB and ~35 s per hash.
// Format and regeneration: src/test/README.md.

#include "test/consensus_harness.h"
#include "test/test_bitcoin.h"

#include "main.h"
#include "primitives/block.h"
#include "scrypt.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include "data/header_hash_vectors.json.h"

#include <univalue.h>

#include <cstddef>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace consensus_harness;

// Step 4: the hashed layouts. Checked here, not in block.h (Phase 0 does
// not touch production headers). Only block_header is packed; the old
// layout has no padding because every field is 4-byte aligned.
static_assert(sizeof(uint256) == 32, "uint256 must be 32 bytes");
static_assert(std::is_standard_layout<block_header>::value, "block_header layout");
static_assert(std::is_standard_layout<old_block_header>::value, "old_block_header layout");
static_assert(sizeof(block_header) == 84, "v7 hashed header must be 84 bytes");
static_assert(sizeof(old_block_header) == 80, "v<7 hashed header must be 80 bytes");
static_assert(offsetof(block_header, prev_block) == 4, "block_header layout");
static_assert(offsetof(block_header, merkle_root) == 36, "block_header layout");
static_assert(offsetof(block_header, timestamp) == 68, "block_header layout");
static_assert(offsetof(block_header, bits) == 76, "block_header layout");
static_assert(offsetof(block_header, nonce) == 80, "block_header layout");
static_assert(offsetof(old_block_header, prev_block) == 4, "old_block_header layout");
static_assert(offsetof(old_block_header, merkle_root) == 36, "old_block_header layout");
static_assert(offsetof(old_block_header, timestamp) == 68, "old_block_header layout");
static_assert(offsetof(old_block_header, bits) == 72, "old_block_header layout");
static_assert(offsetof(old_block_header, nonce) == 76, "old_block_header layout");

BOOST_FIXTURE_TEST_SUITE(header_hash_tests, BasicTestingSetup)

namespace {

const int DEFAULT_MAX_NFACTOR = 21;
// Up to this N-factor (a few ms per hash) a vector is also hashed directly.
const int CHEAP_NFACTOR = 12;

const UniValue& Vectors()
{
    static UniValue doc;
    if (doc.isNull()) {
        const std::string text(json_tests::header_hash_vectors, json_tests::header_hash_vectors + sizeof(json_tests::header_hash_vectors));
        if (!doc.read(text) || !doc.isObject()) {
            throw std::runtime_error("header_hash_vectors.json: parse error");
        }
        if (find_value(doc, "format").get_str() != "yacoin-header-hash-vectors" || find_value(doc, "version").get_str() != "1") {
            throw std::runtime_error("header_hash_vectors.json: unexpected format or version");
        }
    }
    return find_value(doc, "vectors");
}

/** YACOIN_HEADER_HASH_MAX_NFACTOR, 0..25; default 21. */
int MaxNFactor()
{
    const char* psz = getenv("YACOIN_HEADER_HASH_MAX_NFACTOR");
    if (psz == nullptr || *psz == '\0') {
        return DEFAULT_MAX_NFACTOR;
    }
    char* end = nullptr;
    const long n = strtol(psz, &end, 10);
    if (*end != '\0' || n < 0 || n > MAXIMUM_N_FACTOR) {
        throw std::runtime_error(std::string("YACOIN_HEADER_HASH_MAX_NFACTOR must be 0..25, not ") + psz);
    }
    return (int)n;
}

CBlockHeader HeaderFrom(const UniValue& v)
{
    CBlockHeader h;
    h.nVersion = find_value(v, "version").get_int();
    h.hashPrevBlock = uint256S(find_value(v, "prev_block").get_str());
    h.hashMerkleRoot = uint256S(find_value(v, "merkle_root").get_str());
    h.nTime = find_value(v, "time").get_int64();
    h.nBits = (uint32_t)find_value(v, "bits").get_int64();
    h.nNonce = (uint32_t)find_value(v, "nonce").get_int64();
    return h;
}

std::string Serialized(const CBlockHeader& h)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << h;
    return HexStr(ss.begin(), ss.end());
}

/** The bytes CalculateHash passes to scrypt_hash, built the same way. */
std::string RawHashedBytes(const CBlockHeader& h)
{
    if (h.nVersion >= VERSION_of_block_for_yac_05x_new) {
        block_header b;
        b.version = h.nVersion;
        b.prev_block = h.hashPrevBlock;
        b.merkle_root = h.hashMerkleRoot;
        b.timestamp = h.nTime;
        b.bits = h.nBits;
        b.nonce = h.nNonce;
        const unsigned char* p = (const unsigned char*)&b;
        return HexStr(p, p + sizeof(b));
    }
    old_block_header b;
    b.version = h.nVersion;
    b.prev_block = h.hashPrevBlock;
    b.merkle_root = h.hashMerkleRoot;
    b.timestamp = h.nTime;
    b.bits = h.nBits;
    b.nonce = h.nNonce;
    const unsigned char* p = (const unsigned char*)&b;
    return HexStr(p, p + sizeof(b));
}

uint256 ScryptHash(const std::vector<unsigned char>& data, unsigned char nFactor)
{
    uint256 hash;
    BOOST_REQUIRE(scrypt_hash(data.data(), data.size(), UINTBEGIN(hash), nFactor));
    return hash;
}

/** Runs one vector; returns false if it was skipped for its N-factor. */
bool CheckVector(const UniValue& v, int nMaxNFactor)
{
    const std::string name = find_value(v, "name").get_str();
    const int nFactor = find_value(v, "nfactor").get_int();
    const std::string headerHex = find_value(v, "header_hex").get_str();
    const std::string expected = find_value(v, "hash").get_str();
    BOOST_TEST_MESSAGE("header_hash " << name << ": N-factor " << nFactor);

    const CBlockHeader h = HeaderFrom(v);
    const bool fV7 = h.nVersion >= VERSION_of_block_for_yac_05x_new;
    BOOST_CHECK_MESSAGE(Serialized(h) == headerHex, name << ": serialisation " << Serialized(h));
    BOOST_CHECK_MESSAGE(RawHashedBytes(h) == headerHex, name << ": hashed bytes " << RawHashedBytes(h));
    BOOST_CHECK_EQUAL(headerHex.size(), fV7 ? 168U : 160U);

    const UniValue& getNf = find_value(v, "getnfactor");
    if (fV7) {
        BOOST_CHECK(getNf.isNull());
        BOOST_CHECK_EQUAL(find_value(v, "nfactor_at_hardfork").get_int(), nFactor);
    } else {
        BOOST_CHECK_MESSAGE(GetNfactor(h.nTime, false) == getNf.get_int(),
                            name << ": GetNfactor " << (int)GetNfactor(h.nTime, false));
    }

    if (nFactor > nMaxNFactor) {
        BOOST_TEST_MESSAGE("header_hash " << name << ": skipped, N-factor " << nFactor
                                          << " > YACOIN_HEADER_HASH_MAX_NFACTOR " << nMaxNFactor);
        return false;
    }

    ScopedConsensusGlobals globals;
    if (fV7) {
        globals.SetNFactorAtHardfork((unsigned char)nFactor);
        BOOST_CHECK_EQUAL((int)GetNfactor(h.nTime, true), nFactor);
    }
    // The expected hash was computed with the vector's N-factor, so a match
    // also pins which N-factor CalculateHash picks. GetHash() on a fresh
    // header calls CalculateHash() once; the extra direct checks run only
    // where they are cheap (each hash at N-factor 21 takes ~2 s).
    const std::string hash = h.GetHash().GetHex();
    BOOST_CHECK_MESSAGE(hash == expected, name << ": GetHash " << hash);
    if (nFactor <= CHEAP_NFACTOR) {
        BOOST_CHECK_MESSAGE(h.CalculateHash().GetHex() == expected, name << ": CalculateHash differs");
        BOOST_CHECK_MESSAGE(ScryptHash(ParseHex(headerHex), (unsigned char)nFactor).GetHex() == expected,
                            name << ": scrypt_hash(header_hex) differs");
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(known_answers)
{
    const int nMax = MaxNFactor();
    const UniValue& vectors = Vectors();
    BOOST_REQUIRE(vectors.isArray());
    BOOST_REQUIRE_EQUAL(vectors.size(), 59U);
    int nRun = 0, nSkipped = 0;
    for (size_t i = 0; i < vectors.size(); ++i) {
        if (CheckVector(vectors[i], nMax)) {
            ++nRun;
        } else {
            ++nSkipped;
        }
    }
    BOOST_TEST_MESSAGE("header_hash: " << nRun << " vectors hashed, " << nSkipped
                                       << " skipped (N-factor above " << nMax << ")");
    // With the default every N-factor of real mainnet blocks (4..21) runs.
    BOOST_CHECK(nRun > 0);
    if (nMax >= MAXIMUM_N_FACTOR) {
        BOOST_CHECK_EQUAL(nSkipped, 0);
    }
}

// The table in CalculateHash: every N-factor 4..25 is reached, bounds
// ascend, and the N-factor of each vector matches the bound it sits on.
BOOST_AUTO_TEST_CASE(nfactor_table_coverage)
{
    const UniValue& vectors = Vectors();
    std::vector<bool> seen(MAXIMUM_N_FACTOR + 1, false);
    for (size_t i = 0; i < vectors.size(); ++i) {
        const UniValue& v = vectors[i];
        if (find_value(v, "version").get_int() >= VERSION_of_block_for_yac_05x_new) {
            continue;
        }
        const int nFactor = find_value(v, "nfactor").get_int();
        BOOST_REQUIRE(nFactor >= 4 && nFactor <= MAXIMUM_N_FACTOR);
        seen[nFactor] = true;
        // GetNfactor (display) agrees with the consensus table everywhere.
        BOOST_CHECK_EQUAL(find_value(v, "getnfactor").get_int(), nFactor);
    }
    for (int n = 4; n <= MAXIMUM_N_FACTOR; ++n) {
        BOOST_CHECK_MESSAGE(seen[n], "no v<7 vector with N-factor " << n);
    }
}

// GetHash() caches the hash keyed on the header fields only (block.h:235-248).
// Pinned as is (CLAUDE.md rule 1), see project/known-issues.md.
BOOST_AUTO_TEST_CASE(gethash_cache_quirks)
{
    ScopedConsensusGlobals globals;
    globals.SetNFactorAtHardfork(0);

    CBlockHeader h;
    h.nVersion = VERSION_of_block_for_yac_05x_new;
    h.hashPrevBlock = uint256S("01");
    h.hashMerkleRoot = uint256S("02");
    h.nTime = 1700000000;
    h.nBits = 0x1e0fffff;
    h.nNonce = 1;

    const uint256 hashNf0 = h.GetHash();
    BOOST_CHECK(hashNf0 == h.CalculateHash());
    // The height argument is unused.
    BOOST_CHECK(h.GetHash(123456) == hashNf0);

    // 1. A change of nFactorAtHardfork is not seen by the cache.
    globals.SetNFactorAtHardfork(4);
    const uint256 hashNf4 = h.CalculateHash();
    BOOST_CHECK(hashNf4 != hashNf0);
    BOOST_CHECK(h.GetHash() == hashNf0); // stale
    {
        // A copy carries the cache with it.
        const CBlockHeader copy = h;
        BOOST_CHECK(copy.GetHash() == hashNf0);
    }
    // A field change recomputes.
    h.nNonce = 2;
    const uint256 hashNonce2 = h.GetHash();
    BOOST_CHECK(hashNonce2 == h.CalculateHash());
    BOOST_CHECK(hashNonce2 != hashNf4);

    // 2. Serialising updates the cache key (SerializationOp writes
    //    previousBlockHeader) but not the cached hash: a field change
    //    followed by serialisation leaves GetHash() stale.
    h.nNonce = 3;
    const uint256 hashNonce3 = h.CalculateHash();
    Serialized(h);
    BOOST_CHECK(h.GetHash() == hashNonce2); // stale
    BOOST_CHECK(h.GetHash() != hashNonce3);

    // 3. A deserialised header computes its hash on first use.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << h;
    CBlockHeader h2;
    ss >> h2;
    BOOST_CHECK(h2.GetHash() == hashNonce3);
}

BOOST_AUTO_TEST_SUITE_END()
