// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "hash.h"
#include "main.h"
#include "pow.h"
#include "primitives/block.h"
#include "scrypt.h"
#include "streams.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "version.h"

extern "C" {
#include "scrypt-jane/scrypt-jane.h"
}

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <string.h>

#include <boost/test/unit_test.hpp>

/* Defined in scrypt.cpp, not declared in scrypt.h */
uint256 scrypt_nosalt(const void* input, size_t inputlen, void* scratchpad);

BOOST_FIXTURE_TEST_SUITE(scrypt_tests, BasicTestingSetup)

/* Start of each N-factor for pre-1.0 (32-bit nTime) block headers, copied from
 * CBlockHeader::CalculateHash: from time[i] on, the N-factor is i + 5. */
static const ::int64_t NFACTOR_SCHEDULE[] = {
    1368515488, 1368777632, 1369039776, 1369826208, 1370088352, 1372185504,
    1373234080, 1376379808, 1380574112, 1384768416, 1401545632, 1409934240,
    1435100064, 1468654496, 1502208928, 1602872224, 1636426656, 1904862112,
    2173297568, 2441733024, 3247039392,
};

/* scrypt-jane's own known-answer vectors for keccak512 + chacha20/8, the
 * combination YACoin is built with (SCRYPT_KECCAK512, SCRYPT_CHACHA). */
BOOST_AUTO_TEST_CASE(scrypt_jane_known_answers)
{
    struct {
        const char *pw, *salt;
        unsigned char Nfactor, rfactor, pfactor;
        const char* hex;
    } vectors[] = {
        {"", "", 3, 0, 0,
         "77cb70bfaed44c5bbcd3ec8a82438db37f1ffb7036324da6b7133777300c3cfb"
         "2c208f2af4474d698eae2dadba35e92fe6997af8cf7078bb0c7264958b36773d"},
        {"password", "NaCl", 9, 3, 4,
         "c643171687095f12ed21e2b4ad55a1a149509070ab81837acddf235219c0a2d8"
         "8e98ebf037abadfd1c0497184285f74b182c55d3a9e689fb580ab237b9f8fbc5"},
    };
    for (const auto& v : vectors) {
        unsigned char out[64];
        BOOST_CHECK(scrypt((const unsigned char*)v.pw, strlen(v.pw), (const unsigned char*)v.salt, strlen(v.salt),
                           v.Nfactor, v.rfactor, v.pfactor, out, sizeof(out)));
        BOOST_CHECK_EQUAL(HexStr(out, out + sizeof(out)), v.hex);
    }
}

/* scrypt_hash is scrypt-jane with the input as its own salt and r = p = 1 */
BOOST_AUTO_TEST_CASE(scrypt_hash_matches_scrypt_jane)
{
    const unsigned char input[] = "yacoin block header";
    for (unsigned char nFactor = 4; nFactor <= 6; nFactor++) {
        uint256 hash, expected;
        BOOST_CHECK(scrypt_hash(input, sizeof(input), (::uint32_t*)hash.begin(), nFactor));
        BOOST_CHECK(scrypt(input, sizeof(input), input, sizeof(input), nFactor, 0, 0, expected.begin(), 32));
        BOOST_CHECK(hash == expected);
    }
}

/* The display formula in GetNfactor matches the consensus table at every step */
BOOST_AUTO_TEST_CASE(nfactor_schedule)
{
    BOOST_CHECK_EQUAL(GetNfactor(nChainStartTime), 4);
    BOOST_CHECK_EQUAL(GetNfactor(nChainStartTime - 1000), 4);

    unsigned char nExpected = 4;
    for (::int64_t nStart : NFACTOR_SCHEDULE) {
        BOOST_CHECK_EQUAL(GetNfactor(nStart - 1), nExpected);
        ++nExpected;
        BOOST_CHECK_EQUAL(GetNfactor(nStart), nExpected);
    }
    BOOST_CHECK_EQUAL(nExpected, MAXIMUM_N_FACTOR);
    BOOST_CHECK_EQUAL(GetNfactor(3515474848LL), MAXIMUM_N_FACTOR);
    BOOST_CHECK_EQUAL(GetNfactor(1LL << 40), MAXIMUM_N_FACTOR);
}

/* After the fork every block and tx uses the fixed N-factor (mainnet 21) */
BOOST_AUTO_TEST_CASE(nfactor_after_fork)
{
    ConsensusGlobalsGuard globals;
    nFactorAtHardfork = 21;
    BOOST_CHECK_EQUAL(GetNfactor(nChainStartTime, true), 21);
    BOOST_CHECK_EQUAL(GetNfactor(1LL << 40, true), 21);
    nFactorAtHardfork = 7;
    BOOST_CHECK_EQUAL(GetNfactor(1700000000, true), 7);
}

static CBlockHeader TestHeader(int nVersion, ::int64_t nTime)
{
    CBlockHeader header;
    header.nVersion = nVersion;
    header.hashPrevBlock = uint256S("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5");
    header.hashMerkleRoot = uint256S("0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f");
    header.nTime = nTime;
    header.nBits = 0x1e0fffff;
    header.nNonce = 12345;
    return header;
}

/** The 80-byte pre-1.0 header (32-bit nTime) as CalculateHash hashes it */
static old_block_header OldRaw(const CBlockHeader& header)
{
    old_block_header raw;
    raw.version = header.nVersion;
    raw.prev_block = header.hashPrevBlock;
    raw.merkle_root = header.hashMerkleRoot;
    raw.timestamp = header.nTime;
    raw.bits = header.nBits;
    raw.nonce = header.nNonce;
    return raw;
}

/** The 84-byte header (64-bit nTime) */
static block_header NewRaw(const CBlockHeader& header)
{
    block_header raw;
    raw.version = header.nVersion;
    raw.prev_block = header.hashPrevBlock;
    raw.merkle_root = header.hashMerkleRoot;
    raw.timestamp = header.nTime;
    raw.bits = header.nBits;
    raw.nonce = header.nNonce;
    return raw;
}

/* Pre-1.0 headers (32-bit nTime) hash the 80-byte header with the N-factor of their timestamp */
BOOST_AUTO_TEST_CASE(old_header_hash_uses_nfactor_schedule)
{
    for (int i = 0; i < 4; i++) {
        // Last second of N-factor i + 4
        ::int64_t nTime = NFACTOR_SCHEDULE[i] - 1;
        CBlockHeader header = TestHeader(VERSION_of_block_for_yac_049, nTime);

        old_block_header raw;
        raw.version = header.nVersion;
        raw.prev_block = header.hashPrevBlock;
        raw.merkle_root = header.hashMerkleRoot;
        raw.timestamp = header.nTime;
        raw.bits = header.nBits;
        raw.nonce = header.nNonce;
        BOOST_CHECK_EQUAL(sizeof(raw), 80U);

        uint256 expected, other;
        BOOST_CHECK(scrypt_hash(&raw, sizeof(raw), (::uint32_t*)expected.begin(), GetNfactor(nTime)));
        BOOST_CHECK(scrypt_hash(&raw, sizeof(raw), (::uint32_t*)other.begin(), GetNfactor(nTime) + 1));
        BOOST_CHECK_EQUAL(GetNfactor(nTime), i + 4);
        BOOST_CHECK(header.CalculateHash() == expected);
        BOOST_CHECK(header.CalculateHash() != other);
    }
}

/* 1.0 headers (64-bit nTime) hash the 84-byte header with nFactorAtHardfork, whatever the time */
BOOST_AUTO_TEST_CASE(new_header_hash_uses_hardfork_nfactor)
{
    ConsensusGlobalsGuard globals;
    CBlockHeader header = TestHeader(VERSION_of_block_for_yac_05x_new, NFACTOR_SCHEDULE[0] - 1);

    block_header raw;
    raw.version = header.nVersion;
    raw.prev_block = header.hashPrevBlock;
    raw.merkle_root = header.hashMerkleRoot;
    raw.timestamp = header.nTime;
    raw.bits = header.nBits;
    raw.nonce = header.nNonce;
    BOOST_CHECK_EQUAL(sizeof(raw), 84U);

    for (unsigned char nFactor = 5; nFactor <= 6; nFactor++) {
        nFactorAtHardfork = nFactor;
        uint256 expected;
        BOOST_CHECK(scrypt_hash(&raw, sizeof(raw), (::uint32_t*)expected.begin(), nFactor));
        // CalculateHash, not GetHash: GetHash caches the result per header
        BOOST_CHECK(header.CalculateHash() == expected);
    }
}

/* Mainnet block 1,911,210 (`getblockheader <hash> false`): the real header hashes to
 * its block hash at N-factor 21 and meets its own target */
BOOST_AUTO_TEST_CASE(mainnet_header_hash)
{
    ConsensusGlobalsGuard globals;
    nFactorAtHardfork = 21;

    CDataStream stream(ParseHex("07000000bf24dff3e63105d81257ed9842c0aa82d8af213b84115feb9ec8a55e7d0e0000"
                                "299e1fcc76f2681623ff40bbbc3b43c780fae691b0dbb7657d7acb3489d55c85"
                                "8a7f446400000000ffff0f1e80000a56"),
                       SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader header;
    stream >> header;
    BOOST_CHECK(stream.empty());
    BOOST_CHECK_EQUAL(header.nVersion, VERSION_of_block_for_yac_05x_new);
    BOOST_CHECK_EQUAL(header.hashPrevBlock.GetHex(), "00000e7d5ea5c89eeb5f11843b21afd882aac04298ed5712d80531e6f3df24bf");
    BOOST_CHECK_EQUAL(header.nTime, 1682210698);
    BOOST_CHECK_EQUAL(header.nBits, 0x1e0fffffU);

    const uint256 hash = header.CalculateHash();
    BOOST_CHECK_EQUAL(hash.GetHex(), "000009e3b1cc249ba64c3749430b96cf0f3c25acbb2bd3cb0b69e3b28288607b");
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    BOOST_CHECK(CheckProofOfWork(hash, header.nBits, chainParams->GetConsensus()));

    // The same header at another N-factor hashes differently (a small one, to save memory)
    nFactorAtHardfork = 4;
    BOOST_CHECK(header.CalculateHash() != hash);
}

/* A pre-1.0 header in the last second of N-factor 8 */
BOOST_AUTO_TEST_CASE(old_header_hash_nfactor_8)
{
    const ::int64_t nTime = NFACTOR_SCHEDULE[4] - 1;
    BOOST_CHECK_EQUAL(GetNfactor(nTime), 8);
    CBlockHeader header = TestHeader(VERSION_of_block_for_yac_049, nTime);
    old_block_header raw = OldRaw(header);
    uint256 expected;
    BOOST_CHECK(scrypt_hash(&raw, sizeof(raw), (::uint32_t*)expected.begin(), 8));
    BOOST_CHECK(header.CalculateHash() == expected);
}

/** Restores fTestNet */
struct TestNetGuard {
    bool fWas = fTestNet;
    ~TestNetGuard() { fTestNet = fWas; }
};

/* With fTestNet set, every pre-1.0 header hashes at N-factor 4, whatever its time */
BOOST_AUTO_TEST_CASE(old_header_hash_on_testnet)
{
    TestNetGuard guard;
    CBlockHeader header = TestHeader(VERSION_of_block_for_yac_049, NFACTOR_SCHEDULE[3]); // N-factor 8 on mainnet
    old_block_header raw = OldRaw(header);
    uint256 nf4;
    BOOST_CHECK(scrypt_hash(&raw, sizeof(raw), (::uint32_t*)nf4.begin(), 4));
    fTestNet = true;
    BOOST_CHECK(header.CalculateHash() == nf4);
    fTestNet = false;
    BOOST_CHECK(header.CalculateHash() != nf4);
}

/** SHA-256d of the 84-byte header (64-bit nTime), for every header version */
static uint256 Sha256Header(const CBlockHeader& header)
{
    block_header raw = NewRaw(header);
    return Hash(BEGIN(raw), END(raw));
}

/* GetHash fills the scrypt hash cache on first use and returns the cached value while the
 * header fields stay the same; a change of any field, or an empty cache, recomputes it */
BOOST_AUTO_TEST_CASE(header_hash_cache)
{
    ConsensusGlobalsGuard globals; // nFactorAtHardfork stays 0: cheap hashes
    CBlockHeader header = TestHeader(VERSION_of_block_for_yac_05x_new, 1700000000);
    BOOST_CHECK(header.blockHash == uint256());
    BOOST_CHECK(header.IsHeaderDifferent());
    const uint256 hash = header.GetHash();
    BOOST_CHECK(hash == header.CalculateHash());
    BOOST_CHECK(header.blockHash == hash);
    BOOST_CHECK(!header.IsHeaderDifferent());

    // Reused: a value planted in the cache is returned, so nothing was recomputed
    const uint256 planted = uint256S("0x5e5e");
    header.blockHash = planted;
    BOOST_CHECK(header.GetHash() == planted);
    BOOST_CHECK(header.GetHash() == planted);

    // An empty cache is filled again
    header.blockHash = uint256();
    BOOST_CHECK(header.GetHash() == hash);

    // A copy carries the cache along
    header.blockHash = planted;
    CBlockHeader copy = header;
    BOOST_CHECK(copy.GetHash() == planted);

    // Each field: a change makes the header differ from the cached one, and GetHash
    // recomputes and caches the new hash
    for (int field = 0; field < 6; field++) {
        CBlockHeader changed = header;
        switch (field) {
        case 0: changed.nVersion += 1; break;
        case 1: changed.hashPrevBlock = uint256S("0x01"); break;
        case 2: changed.hashMerkleRoot = uint256S("0x02"); break;
        case 3: changed.nTime += 1; break;
        case 4: changed.nBits -= 1; break;
        case 5: changed.nNonce += 1; break;
        }
        BOOST_CHECK(changed.IsHeaderDifferent());
        const uint256 recomputed = changed.GetHash();
        BOOST_CHECK(recomputed != planted);
        BOOST_CHECK(recomputed != hash);
        BOOST_CHECK(recomputed == changed.CalculateHash());
        BOOST_CHECK(changed.blockHash == recomputed);
        BOOST_CHECK(!changed.IsHeaderDifferent());
    }

    // A pre-1.0 header is cached the same way
    CBlockHeader old = TestHeader(VERSION_of_block_for_yac_049, NFACTOR_SCHEDULE[0] - 1);
    const uint256 oldHash = old.GetHash();
    BOOST_CHECK(oldHash == old.CalculateHash());
    old.blockHash = planted;
    BOOST_CHECK(old.GetHash() == planted);
    old.nTime -= 1;
    BOOST_CHECK(old.GetHash() == old.CalculateHash());
    BOOST_CHECK(old.GetHash() != oldHash);
}

/* GetSHA256Hash: SHA-256d of the header as the 84-byte struct with 64-bit nTime (also for
 * pre-1.0 headers), cached like GetHash */
BOOST_AUTO_TEST_CASE(header_sha256_cache)
{
    for (int nVersion : {VERSION_of_block_for_yac_049, VERSION_of_block_for_yac_05x_new}) {
        CBlockHeader header = TestHeader(nVersion, 1700000000);
        BOOST_CHECK(header.blockSHA256Hash == uint256());
        const uint256 sha = header.GetSHA256Hash();
        BOOST_CHECK(sha == Sha256Header(header));
        BOOST_CHECK(header.blockSHA256Hash == sha);
        BOOST_CHECK(!header.IsHeaderDifferent());
        // Unrelated to the scrypt hash cache, which stays empty
        BOOST_CHECK(header.blockHash == uint256());

        const uint256 planted = uint256S("0x5e5e");
        header.blockSHA256Hash = planted;
        BOOST_CHECK(header.GetSHA256Hash() == planted);
        header.blockSHA256Hash = uint256();
        BOOST_CHECK(header.GetSHA256Hash() == sha);

        header.blockSHA256Hash = planted;
        header.nNonce += 1;
        const uint256 recomputed = header.GetSHA256Hash();
        BOOST_CHECK(recomputed == Sha256Header(header));
        BOOST_CHECK(recomputed != sha);
        BOOST_CHECK(header.blockSHA256Hash == recomputed);
    }
}

static std::string Bytes(const uint256& hash)
{
    return HexStr(hash.begin(), hash.end());
}

/* The Litecoin-style functions in scrypt.cpp are scrypt with N = 1024, r = 1, p = 1 and a
 * 32-byte result. The expected values (in byte order) come from another implementation,
 * Python's hashlib.scrypt(password, salt=salt, n=1024, r=1, p=1, dklen=32). */
BOOST_AUTO_TEST_CASE(scrypt_n1024_known_answers)
{
    unsigned char header[80];
    for (int i = 0; i < 80; i++) header[i] = i;
    // The input is also the salt
    const std::string headerHash = "bc540a1a801df96e493005c71e010e2d387607fbf0fec416fd3c2645aa1ba9d2";
    BOOST_CHECK_EQUAL(Bytes(scrypt_blockhash(header)), headerHash);
    BOOST_CHECK_EQUAL(Bytes(scrypt_hash(header, sizeof(header))), headerHash);
    BOOST_CHECK_EQUAL(Bytes(scrypt_hash("yacoin", 6)), "7eedb3d10c064f90e52aa252c8ae728b78c24b4a1cee37fdd6f513a1b30ff1b5");
    BOOST_CHECK_EQUAL(Bytes(scrypt_hash("", 0)), "b34ab7cd1ce0c308146ab970fa75517bcf20f95c7ed7a34efc0d5f096469b2e1");

    // A scratchpad from scrypt_buffer_alloc is large enough for the 64-byte aligned work area
    void* scratchpad = scrypt_buffer_alloc();
    BOOST_REQUIRE(scratchpad != nullptr);
    BOOST_CHECK_EQUAL(Bytes(scrypt_nosalt(header, sizeof(header), scratchpad)), headerHash);
    scrypt_buffer_free(scratchpad);

    // Salted: the salt is separate; the input as its own salt is the unsalted hash
    const std::string saltedHash = "8bb740a753619bbb66185549639d5f540396aea07bbd123032197014c28f8aff";
    BOOST_CHECK_EQUAL(Bytes(scrypt_salted_hash("password", 8, "NaCl", 4)), saltedHash);
    BOOST_CHECK_EQUAL(Bytes(scrypt_salted_hash(header, sizeof(header), header, sizeof(header))), headerHash);

    // Multiround: every round after the first is salted with the result of the round before;
    // zero rounds hash once, as one round does
    BOOST_CHECK_EQUAL(Bytes(scrypt_salted_multiround_hash("password", 8, "NaCl", 4, 3)),
                      "6c56bd9bbadc52568314cf5c7264030f93a7c31a037c9b2f972abb79de2d5336");
    BOOST_CHECK_EQUAL(Bytes(scrypt_salted_multiround_hash("password", 8, "NaCl", 4, 1)), saltedHash);
    BOOST_CHECK_EQUAL(Bytes(scrypt_salted_multiround_hash("password", 8, "NaCl", 4, 0)), saltedHash);
}

/** Restores the miner's flags that scanhash_scrypt reads */
struct MinerFlagsGuard {
    bool fGenerate = fGenerateYacoins;
    bool fShutdownWas = fShutdown;
    ~MinerFlagsGuard()
    {
        fGenerateYacoins = fGenerate;
        fShutdown = fShutdownWas;
    }
};

/** Header for scanhash_scrypt: zero previous block and merkle root */
static CBlockHeader ScanHeader(int nVersion, ::int64_t nTime, unsigned int nNonce)
{
    CBlockHeader header;
    header.nVersion = nVersion;
    header.hashPrevBlock = uint256();
    header.hashMerkleRoot = uint256();
    header.nTime = nTime;
    header.nBits = 0x1e0fffff;
    header.nNonce = nNonce;
    return header;
}

/* scanhash_scrypt hashes the header (read from a CBlockHeader in memory) with scrypt-jane at
 * the given N-factor, from the next nonce on: the 84-byte header for version 7, the 80-byte
 * one with a 32-bit nTime before. A hash qualifies when its two top bytes are zero and its
 * third byte has zero bits wherever the target's third byte has leading zero bits. Every
 * call here ends after one hash; it returns the nonce and copies the last hash. The nonces
 * were found with a search over the same headers at N-factor 4. */
BOOST_AUTO_TEST_CASE(scanhash_scrypt_one_hash)
{
    ConsensusGlobalsGuard globals;
    MinerFlagsGuard flags;
    CBlockIndex* pindexTip = chainActive.Tip();
    CBlockIndex other; // not the tip
    // Third byte 0xff: only the two top bytes of the hash count
    uint256 targetTwoBytes = ~uint256(0) >> 16;
    // Third byte 0x0f: the hash's third byte must also be below 0x10
    uint256 targetNibble = ~uint256(0) >> 20;

    // Version 7 with nonce 81260 hashes to 0000199a...
    const std::string hash7 = "0000199aad05ca282a46bda3e243ee1d03a02f072d82a26771831d4a95eee84d";
    CBlockHeader header = ScanHeader(VERSION_of_block_for_yac_05x_new, 1700000000, 81259);
    uint256 result;
    ::uint32_t nHashes = 99;
    fGenerateYacoins = true;
    fShutdown = false;
    BOOST_CHECK_EQUAL(scanhash_scrypt((char*)&header, nHashes, result.begin(), 4, pindexTip, &targetTwoBytes), 81260U);
    BOOST_CHECK_EQUAL(nHashes, 100U);
    BOOST_CHECK_EQUAL(result.GetHex(), hash7);
    BOOST_CHECK_EQUAL(header.nNonce, 81259U); // the caller's header is unchanged
    CBlockHeader solved = ScanHeader(VERSION_of_block_for_yac_05x_new, 1700000000, 81260);
    nFactorAtHardfork = 4;
    BOOST_CHECK(solved.CalculateHash() == result);

    // The same hash misses the nibble target (third byte 0x19): the loop stops because
    // pindexPrev is not the tip
    result = uint256();
    nHashes = 0;
    BOOST_CHECK_EQUAL(scanhash_scrypt((char*)&header, nHashes, result.begin(), 4, &other, &targetNibble), 81260U);
    BOOST_CHECK_EQUAL(nHashes, 1U);
    BOOST_CHECK_EQUAL(result.GetHex(), hash7);

    // Version 6 with nonce 9920 hashes to 00009502...; its nTime has N-factor 4
    const std::string hash6 = "0000950272004a8af775be356f19e3dab3925940c593f5640b95356379f81f4e";
    header = ScanHeader(VERSION_of_block_for_yac_049, 1368000000, 9919);
    result = uint256();
    nHashes = 0;
    BOOST_CHECK_EQUAL(scanhash_scrypt((char*)&header, nHashes, result.begin(), 4, pindexTip, &targetTwoBytes), 9920U);
    BOOST_CHECK_EQUAL(result.GetHex(), hash6);
    solved = ScanHeader(VERSION_of_block_for_yac_049, 1368000000, 9920);
    BOOST_CHECK_EQUAL(GetNfactor(solved.nTime), 4);
    BOOST_CHECK(solved.CalculateHash() == result);

    // Missed target (third byte 0x95), on the tip: stops on shutdown...
    fShutdown = true;
    result = uint256();
    nHashes = 0;
    BOOST_CHECK_EQUAL(scanhash_scrypt((char*)&header, nHashes, result.begin(), 4, pindexTip, &targetNibble), 9920U);
    BOOST_CHECK_EQUAL(nHashes, 1U);
    BOOST_CHECK_EQUAL(result.GetHex(), hash6);
    // ... and when mining is switched off
    fShutdown = false;
    fGenerateYacoins = false;
    nHashes = 0;
    BOOST_CHECK_EQUAL(scanhash_scrypt((char*)&header, nHashes, result.begin(), 4, pindexTip, &targetNibble), 9920U);
    BOOST_CHECK_EQUAL(nHashes, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
