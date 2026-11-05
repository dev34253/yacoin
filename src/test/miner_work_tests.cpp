// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The getwork hash buffers (FormatHashBuffers for headers before version 7,
// FormatHashBuffers_64bit_nTime from version 7), SHA256Transform, and the helpers that start,
// stop and check the internal miner, without starting a miner thread.

#include "chain.h"
#include "miner.h"
#include "primitives/block.h"
#include "streams.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "version.h"

#include "test/test_bitcoin.h"

#include <cstring>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

// Defined in miner.cpp, which declares them in no header
bool check_for_stop_mining(CBlockIndex* pindexPrev);
extern int nBlocksToGenerate;
extern uint64_t nHashesPerSec;

namespace {

/** Sets a variable while it lives */
template <typename T>
struct ValueGuard {
    T& m_ref;
    const T m_saved;
    ValueGuard(T& ref, T value) : m_ref(ref), m_saved(ref) { m_ref = value; }
    ~ValueGuard() { m_ref = m_saved; }
    ValueGuard(const ValueGuard&) = delete;
    ValueGuard& operator=(const ValueGuard&) = delete;
};

/** A fixed header; version 7 and later serialise nTime in 64 bits */
CBlock FixedBlock(int nVersion, int64_t nTime)
{
    CBlock block;
    block.nVersion = nVersion;
    block.hashPrevBlock = uint256S("1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988");
    block.hashMerkleRoot = uint256S("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");
    block.nTime = nTime;
    block.nBits = 0x1e0fffff;
    block.nNonce = 0x2468ace0;
    return block;
}

/** The header serialisation in two SHA-256 blocks (0x80, zeros, the length in bits as a
 * 32-bit big-endian number at the end), with the bytes of each 32-bit word reversed */
std::vector<unsigned char> ExpectedData(const CBlock& block)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << block.GetBlockHeader();
    std::vector<unsigned char> padded(ss.begin(), ss.end());
    const uint32_t nBits = padded.size() * 8;
    BOOST_REQUIRE(padded.size() < 120);
    padded.push_back(0x80);
    padded.resize(128, 0);
    padded[124] = nBits >> 24;
    padded[125] = nBits >> 16;
    padded[126] = nBits >> 8;
    padded[127] = nBits;
    std::vector<unsigned char> swapped(padded.size());
    for (size_t i = 0; i < padded.size(); i += 4)
        for (size_t j = 0; j < 4; j++)
            swapped[i + j] = padded[i + 3 - j];
    return swapped;
}

struct HashBuffers {
    std::string midstate, data, hash1;
};

HashBuffers Format(CBlock& block)
{
    char pmidstate[32], pdata[128], phash1[64];
    if (block.nVersion >= VERSION_of_block_for_yac_05x_new)
        FormatHashBuffers_64bit_nTime((char*)&block, pmidstate, pdata, phash1);
    else
        FormatHashBuffers(&block, pmidstate, pdata, phash1);
    return {HexStr(pmidstate, pmidstate + sizeof(pmidstate)), HexStr(pdata, pdata + sizeof(pdata)),
            HexStr(phash1, phash1 + sizeof(phash1))};
}

// The second, empty block of the second hash: 0x80 after 32 bytes, 256 bits as the length
const std::string HASH1 = std::string(64, '0') + "00000080" + std::string(48, '0') + "00010000";

const unsigned int SHA256_INIT[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

} // namespace

BOOST_FIXTURE_TEST_SUITE(miner_work_tests, TestingSetup)

/* From version 7: the 84-byte header with its 64-bit time */
BOOST_AUTO_TEST_CASE(hash_buffers_64bit_time)
{
    CBlock block = FixedBlock(VERSION_of_block_for_yac_05x_new, 1700000123);
    HashBuffers buffers = Format(block);
    const std::vector<unsigned char> expected = ExpectedData(block);
    BOOST_CHECK_EQUAL(buffers.data, HexStr(expected));
    BOOST_CHECK_EQUAL(buffers.data,
                      "000000075b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988"
                      "1f2e3d4c76543210fedcba9889abcdef0123456776543210fedcba9889abcdef"
                      "012345676553f17b000000001e0fffff2468ace0000000800000000000000000"
                      "00000000000000000000000000000000000000000000000000000000a0020000");
    BOOST_CHECK_EQUAL(buffers.hash1, HASH1);
    // The SHA-256 state after the first 64 bytes of the header
    BOOST_CHECK_EQUAL(buffers.midstate, "9208e3a567d837967a323eb5ee869bd315a4622453ba997c09af950f3e2e05c3");

    // Another nonce changes the data's second block only
    block.nNonce += 1;
    const HashBuffers next = Format(block);
    BOOST_CHECK_EQUAL(next.midstate, buffers.midstate);
    BOOST_CHECK_EQUAL(next.hash1, HASH1);
    BOOST_CHECK_EQUAL(next.data.substr(0, 128), buffers.data.substr(0, 128));
    BOOST_CHECK(next.data.substr(128) != buffers.data.substr(128));
    BOOST_CHECK_EQUAL(next.data, HexStr(ExpectedData(block)));
}

/* Before version 7: the 80-byte header with its 32-bit time */
BOOST_AUTO_TEST_CASE(hash_buffers_32bit_time)
{
    CBlock block = FixedBlock(CURRENT_VERSION_of_block, 1400000123);
    BOOST_REQUIRE(block.nVersion < VERSION_of_block_for_yac_05x_new);
    HashBuffers buffers = Format(block);
    BOOST_CHECK_EQUAL(buffers.data, HexStr(ExpectedData(block)));
    BOOST_CHECK_EQUAL(buffers.data,
                      "000000065b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988"
                      "1f2e3d4c76543210fedcba9889abcdef0123456776543210fedcba9889abcdef"
                      "0123456753724e7b1e0fffff2468ace000000080000000000000000000000000"
                      "0000000000000000000000000000000000000000000000000000000080020000");
    BOOST_CHECK_EQUAL(buffers.hash1, HASH1);
    BOOST_CHECK_EQUAL(buffers.midstate, "ac83205597cc795f509f2411bf103a040e90aaf3456644442ee6e8d9a24c94d4");

    block.nNonce += 1;
    const HashBuffers next = Format(block);
    BOOST_CHECK_EQUAL(next.midstate, buffers.midstate);
    BOOST_CHECK_EQUAL(next.data.substr(0, 128), buffers.data.substr(0, 128));
    BOOST_CHECK(next.data.substr(128) != buffers.data.substr(128));
    BOOST_CHECK_EQUAL(next.data, HexStr(ExpectedData(block)));
}

/* One SHA-256 compression: the padded block of "abc" from the initial state gives the
 * digest of "abc". The input's 32-bit words come byte-reversed, as in the getwork data */
BOOST_AUTO_TEST_CASE(sha256_transform_known_answer)
{
    unsigned char block[64] = {'a', 'b', 'c', 0x80};
    block[63] = 24; // length in bits
    unsigned char input[64];
    for (int i = 0; i < 64; i += 4)
        for (int j = 0; j < 4; j++)
            input[i + j] = block[i + 3 - j];
    unsigned int init[8];
    std::memcpy(init, SHA256_INIT, sizeof(init));

    uint32_t state[8];
    SHA256Transform(state, input, init);
    const uint32_t digest[8] = {0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
                                0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad};
    for (int i = 0; i < 8; i++)
        BOOST_CHECK_EQUAL(state[i], digest[i]);
    // The initial state is not changed
    BOOST_CHECK(std::memcmp(init, SHA256_INIT, sizeof(init)) == 0);
}

/* check_for_stop_mining: stop on a new tip, when generation is off, or at shutdown */
BOOST_AUTO_TEST_CASE(check_for_stop_mining_conditions)
{
    CBlockIndex* tip;
    {
        LOCK(cs_main);
        tip = chainActive.Tip();
    }
    BOOST_REQUIRE(tip);
    BOOST_REQUIRE(!fShutdown);
    {
        ValueGuard<bool> generate(fGenerateYacoins, true);
        BOOST_CHECK(!check_for_stop_mining(tip));
        BOOST_CHECK(check_for_stop_mining(nullptr));
        CBlockIndex other;
        BOOST_CHECK(check_for_stop_mining(&other));
        {
            ValueGuard<bool> shutdown(fShutdown, true);
            BOOST_CHECK(check_for_stop_mining(tip));
        }
        BOOST_CHECK(!check_for_stop_mining(tip));
    }
    BOOST_REQUIRE(!fGenerateYacoins);
    BOOST_CHECK(check_for_stop_mining(tip));
}

/* GenerateYacoins starts no thread when generation is off or no thread is asked for; it
 * returns the core count and leaves the miner's state as it was */
BOOST_AUTO_TEST_CASE(generate_yacoins_without_threads)
{
    BOOST_REQUIRE(!fGenerateYacoins);
    ValueGuard<int> blocks(nBlocksToGenerate, nBlocksToGenerate);
    ValueGuard<uint64_t> hashes(nHashesPerSec, 77);
    const int nBlocks = nBlocksToGenerate;
    const int nCores = GetNumCores();

    BOOST_CHECK_EQUAL(GenerateYacoins(false, 0), nCores);
    BOOST_CHECK_EQUAL(GenerateYacoins(false, -1), nCores);
    BOOST_CHECK_EQUAL(GenerateYacoins(false, 2, 5), nCores);
    BOOST_CHECK_EQUAL(GenerateYacoins(true, 0, 5), nCores);
    BOOST_CHECK(!fGenerateYacoins);
    BOOST_CHECK_EQUAL(nBlocksToGenerate, nBlocks);
    // The hash meter is reset only when threads start
    BOOST_CHECK_EQUAL(nHashesPerSec, 77U);
}

BOOST_AUTO_TEST_SUITE_END()
