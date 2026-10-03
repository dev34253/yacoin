// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "random.h"

#include "crypto/common.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <limits>
#include <set>
#include <string.h>
#include <thread>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

#ifndef WIN32
// Not declared in random.h: the /dev/urandom fallback of GetOSRand, used only
// when the getrandom syscall is missing (ENOSYS). It is not static, so the
// test can call it directly (P0-21).
void GetDevURandom(unsigned char* ent32);
#endif

/*
 * P0-21: contract tests for the RNG API before OpenSSL is removed from
 * random.cpp (Phase 3). They catch broken generators (stuck, short, repeating
 * or badly skewed output), not weak ones. Every probabilistic check states
 * its false-positive probability; all of them are far below 1e-9 per run.
 */
namespace {

/** Chi-square statistic of the byte-value histogram of `data` (256 bins). */
double ChiSquare256(const std::vector<unsigned char>& data)
{
    std::vector<uint64_t> counts(256, 0);
    for (unsigned char c : data) ++counts[c];
    const double expected = data.size() / 256.0;
    double chi = 0;
    for (uint64_t c : counts) chi += (c - expected) * (c - expected) / expected;
    return chi;
}

/* Bounds for 256 bins (255 degrees of freedom). For a uniform source the
 * chi-square distribution gives P(X > 450) = 5.8e-13 and P(X < 124) = 2.3e-13
 * (regularized incomplete gamma function). byte_distribution_chisquare checks
 * four sources, so it fails falsely with probability about 3.2e-12; the margin
 * to 1e-9 covers the error of the asymptotic approximation (1024 expected
 * counts per bin). The lower bound catches output that is too uniform, such
 * as a byte counter. */
const double CHI_SQUARE_MIN = 124.0;
const double CHI_SQUARE_MAX = 450.0;
const size_t CHI_SQUARE_BYTES = 256 * 1024;

std::pair<uint64_t, uint64_t> First16(const unsigned char* p)
{
    return std::make_pair(ReadLE64(p), ReadLE64(p + 8));
}

bool AllZero(const unsigned char* p, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(random_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(osrandom_tests)
{
    BOOST_CHECK(Random_SanityCheck());
}

BOOST_AUTO_TEST_CASE(fastrandom_tests)
{
    // Check that deterministic FastRandomContexts are deterministic
    FastRandomContext ctx1(true);
    FastRandomContext ctx2(true);

    BOOST_CHECK_EQUAL(ctx1.rand32(), ctx2.rand32());
    BOOST_CHECK_EQUAL(ctx1.rand32(), ctx2.rand32());
    BOOST_CHECK_EQUAL(ctx1.rand64(), ctx2.rand64());
    BOOST_CHECK_EQUAL(ctx1.randbits(3), ctx2.randbits(3));
    BOOST_CHECK(ctx1.randbytes(17) == ctx2.randbytes(17));
    BOOST_CHECK(ctx1.rand256() == ctx2.rand256());
    BOOST_CHECK_EQUAL(ctx1.randbits(7), ctx2.randbits(7));
    BOOST_CHECK(ctx1.randbytes(128) == ctx2.randbytes(128));
    BOOST_CHECK_EQUAL(ctx1.rand32(), ctx2.rand32());
    BOOST_CHECK_EQUAL(ctx1.randbits(3), ctx2.randbits(3));
    BOOST_CHECK(ctx1.rand256() == ctx2.rand256());
    BOOST_CHECK(ctx1.randbytes(50) == ctx2.randbytes(50));

    // Check that a nondeterministic ones are not
    FastRandomContext ctx3;
    FastRandomContext ctx4;
    BOOST_CHECK(ctx3.rand64() != ctx4.rand64()); // extremely unlikely to be equal
    BOOST_CHECK(ctx3.rand256() != ctx4.rand256());
    BOOST_CHECK(ctx3.randbytes(7) != ctx4.randbytes(7));
}

BOOST_AUTO_TEST_CASE(fastrandom_randbits)
{
    FastRandomContext ctx1;
    FastRandomContext ctx2;
    for (int bits = 0; bits < 63; ++bits) {
        for (int j = 0; j < 1000; ++j) {
            uint64_t rangebits = ctx1.randbits(bits);
            BOOST_CHECK_EQUAL(rangebits >> bits, 0);
            uint64_t range = ((uint64_t)1) << bits | rangebits;
            uint64_t rand = ctx2.randrange(range);
            BOOST_CHECK(rand < range);
        }
    }
}

BOOST_AUTO_TEST_CASE(getrand_ranges)
{
    // nMax 0 and 1 have exactly one result.
    for (int i = 0; i < 10; ++i) {
        BOOST_CHECK_EQUAL(GetRand(0), 0U);
        BOOST_CHECK_EQUAL(GetRand(1), 0U);
        BOOST_CHECK_EQUAL(GetRandInt(0), 0);
        BOOST_CHECK_EQUAL(GetRandInt(1), 0);
    }

    // Results are in [0, nMax), including ranges that force the rejection
    // loop (2^63 + 1 rejects almost half of all 64-bit values).
    const uint64_t ranges[] = {2, 3, 7, 1000, (uint64_t)1 << 32, ((uint64_t)1 << 63) + 1,
                               std::numeric_limits<uint64_t>::max()};
    for (uint64_t range : ranges) {
        bool all_below = true;
        for (int i = 0; i < 100; ++i) {
            if (GetRand(range) >= range) all_below = false;
        }
        BOOST_CHECK_MESSAGE(all_below, "GetRand(" << range << ") out of range");
    }
    const int int_ranges[] = {2, 10, 1000, std::numeric_limits<int>::max()};
    for (int range : int_ranges) {
        bool all_in = true;
        for (int i = 0; i < 100; ++i) {
            int r = GetRandInt(range);
            if (r < 0 || r >= range) all_in = false;
        }
        BOOST_CHECK_MESSAGE(all_in, "GetRandInt(" << range << ") out of range");
    }

    // Every value of a small range occurs: a value is missed in 1000 draws
    // with probability 10 * 0.9^1000 < 1e-44.
    std::set<uint64_t> seen;
    std::set<int> seen_int;
    for (int i = 0; i < 1000; ++i) {
        seen.insert(GetRand(10));
        seen_int.insert(GetRandInt(10));
    }
    BOOST_CHECK_EQUAL(seen.size(), 10U);
    BOOST_CHECK_EQUAL(seen_int.size(), 10U);
}

BOOST_AUTO_TEST_CASE(getrandbytes_and_hash)
{
    // GetRandBytes writes exactly num bytes. P(32 random bytes all zero) = 2^-256.
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    GetRandBytes(buf, 32);
    BOOST_CHECK(!AllZero(buf, 32));
    BOOST_CHECK(AllZero(buf + 32, 32));

    uint256 h1 = GetRandHash();
    uint256 h2 = GetRandHash();
    BOOST_CHECK(!h1.IsNull());
    BOOST_CHECK(!h2.IsNull());
    BOOST_CHECK(h1 != h2);
}

BOOST_AUTO_TEST_CASE(strongrandbytes_no_repeats)
{
    // 1,000,000 outputs, compared on their first 16 bytes: a repeat among
    // 10^6 random 128-bit values has probability n^2 / 2^129 < 1.5e-27.
    const int N = 1000000;
    std::vector<std::pair<uint64_t, uint64_t> > outputs;
    outputs.reserve(N);
    unsigned char buf[32];
    bool any_zero = false;
    for (int i = 0; i < N; ++i) {
        GetStrongRandBytes(buf, 32);
        if (AllZero(buf, 32)) any_zero = true;
        outputs.push_back(First16(buf));
    }
    BOOST_CHECK(!any_zero);
    std::sort(outputs.begin(), outputs.end());
    BOOST_CHECK(std::adjacent_find(outputs.begin(), outputs.end()) == outputs.end());
}

BOOST_AUTO_TEST_CASE(strongrandbytes_lengths_and_threads)
{
    // num bytes are written, nothing after them (canary 0xA5).
    const int lengths[] = {0, 1, 16, 31, 32};
    for (int num : lengths) {
        unsigned char buf[64];
        memset(buf, 0xA5, sizeof(buf));
        GetStrongRandBytes(buf, num);
        bool canary_ok = true;
        for (int i = num; i < 64; ++i) {
            if (buf[i] != 0xA5) canary_ok = false;
        }
        BOOST_CHECK_MESSAGE(canary_ok, "GetStrongRandBytes(buf, " << num << ") wrote past num");
    }
    // 32 bytes: P(all still 0xA5) = 2^-256.
    unsigned char full[32];
    memset(full, 0xA5, sizeof(full));
    GetStrongRandBytes(full, 32);
    std::vector<unsigned char> canary(32, 0xA5);
    BOOST_CHECK(memcmp(full, canary.data(), 32) != 0);

    // Concurrent callers (the shared state is updated under a mutex) get
    // distinct outputs. Boost.Test assertions are not thread-safe, so the
    // threads only collect and the checks run here.
    const int THREADS = 4;
    const int PER_THREAD = 10000;
    std::vector<std::vector<std::pair<uint64_t, uint64_t> > > results(THREADS);
    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&results, t, PER_THREAD]() {
            unsigned char out[32];
            results[t].reserve(PER_THREAD);
            for (int i = 0; i < PER_THREAD; ++i) {
                GetStrongRandBytes(out, 32);
                results[t].push_back(First16(out));
            }
        });
    }
    for (std::thread& th : threads) th.join();
    std::vector<std::pair<uint64_t, uint64_t> > all;
    for (const auto& r : results) all.insert(all.end(), r.begin(), r.end());
    BOOST_CHECK_EQUAL(all.size(), (size_t)(THREADS * PER_THREAD));
    std::sort(all.begin(), all.end());
    BOOST_CHECK(std::adjacent_find(all.begin(), all.end()) == all.end());
}

BOOST_AUTO_TEST_CASE(fastrandom_known_answers)
{
    // FastRandomContext(true) is ChaCha20 (20 rounds) with an all-zero key,
    // nonce 0, block counter 0. Its first block is the RFC 7539 test vector
    // 76b8e0ada0f13d90405d6ae55386bd28... (RFC 7539 section A.1, test 1).
    // Expected values computed with an independent Python model (P0-21 log).
    // The deterministic test helpers (SeedInsecureRand(true)) depend on this
    // stream.
    FastRandomContext ctx(true);
    BOOST_CHECK_EQUAL(ctx.rand64(), 0x903df1a0ade0b876ULL);  // bytes 0-7 of block 0, little endian
    BOOST_CHECK_EQUAL(ctx.rand32(), 0xe56a5d40U);           // low half of bytes 8-15
    BOOST_CHECK_EQUAL(ctx.randbits(3), 3U);                 // next 3 bits of the same 64-bit word
    uint256 r = ctx.rand256();                              // bytes 16-47 of block 0
    BOOST_CHECK_EQUAL(HexStr(r.begin(), r.end()),
                      "bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a37");
    // randbytes() bypasses the byte buffer: it starts at block 1, and a
    // partial block is discarded by ChaCha20::Output.
    BOOST_CHECK_EQUAL(HexStr(ctx.randbytes(17)), "9f07e7be5551387a98ba977c732d080dcb");
    BOOST_CHECK_EQUAL(ctx.rand64(), 0x1ca11815f4b8436aULL); // bytes 48-55 of block 0, still buffered

    // A context seeded with the bytes 0x00, 0x01, ..., 0x1f.
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.begin()[i] = (unsigned char)i;
    FastRandomContext seeded(seed);
    BOOST_CHECK_EQUAL(seeded.rand64(), 0x6a19c5d97d2bfd39ULL);
    BOOST_CHECK_EQUAL(HexStr(seeded.randbytes(32)),
                      "18b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c");
}

BOOST_AUTO_TEST_CASE(fastrandom_seeded)
{
    // Same seed, same sequence (mixed calls).
    uint256 seed = GetRandHash();
    FastRandomContext a(seed);
    FastRandomContext b(seed);
    for (int i = 0; i < 100; ++i) {
        BOOST_CHECK_EQUAL(a.rand64(), b.rand64());
        BOOST_CHECK_EQUAL(a.randbits(i % 65), b.randbits(i % 65));
        BOOST_CHECK_EQUAL(a.randrange(i + 1), b.randrange(i + 1));
        BOOST_CHECK(a.rand256() == b.rand256());
        BOOST_CHECK(a.randbytes(i) == b.randbytes(i));
        BOOST_CHECK_EQUAL(a.randbool(), b.randbool());
    }

    // A zero seed is the same as fDeterministic (SeedInsecureRand(true) uses uint256()).
    FastRandomContext zero_seed{uint256()};
    FastRandomContext deterministic(true);
    BOOST_CHECK(zero_seed.rand256() == deterministic.rand256());
    BOOST_CHECK(zero_seed.randbytes(40) == deterministic.randbytes(40));

    // Different seeds differ (P(equal) = 2^-256 per comparison).
    uint256 seed2 = GetRandHash();
    BOOST_REQUIRE(seed != seed2);
    FastRandomContext c(seed);
    FastRandomContext d(seed2);
    FastRandomContext e(true);
    uint256 rc = c.rand256();
    BOOST_CHECK(rc != d.rand256());
    BOOST_CHECK(rc != e.rand256());

    // Degenerate arguments.
    FastRandomContext ctx(seed);
    BOOST_CHECK_EQUAL(ctx.randbits(0), 0U);
    BOOST_CHECK_EQUAL(ctx.randrange(1), 0U);
    BOOST_CHECK(ctx.randbytes(0).empty());
    BOOST_CHECK_EQUAL(ctx.randbytes(1000).size(), 1000U);
    // randbits(64) returns full 64-bit values: some of 64 draws have the top
    // bit set (P(none) = 2^-64).
    bool top_bit = false;
    for (int i = 0; i < 64; ++i) {
        if (ctx.randbits(64) >> 63) top_bit = true;
    }
    BOOST_CHECK(top_bit);
    // randbool() gives both values (P(one missing in 100) = 2^-99).
    bool seen_true = false, seen_false = false;
    for (int i = 0; i < 100; ++i) {
        if (ctx.randbool()) seen_true = true; else seen_false = true;
    }
    BOOST_CHECK(seen_true && seen_false);
}

BOOST_AUTO_TEST_CASE(osrand_and_devurandom)
{
    // Each byte position is overwritten with a non-zero value at least once
    // in 64 calls (P(a position stays zero) = 256^-64), and two calls differ.
    unsigned char overwritten[NUM_OS_RANDOM_BYTES] = {};
    unsigned char a[NUM_OS_RANDOM_BYTES], b[NUM_OS_RANDOM_BYTES];
    for (int i = 0; i < 64; ++i) {
        memset(a, 0, sizeof(a));
        GetOSRand(a);
        for (int x = 0; x < NUM_OS_RANDOM_BYTES; ++x) overwritten[x] |= (a[x] != 0);
    }
    BOOST_CHECK(std::count(overwritten, overwritten + NUM_OS_RANDOM_BYTES, 0) == 0);
    GetOSRand(a);
    GetOSRand(b);
    BOOST_CHECK(memcmp(a, b, sizeof(a)) != 0);

#ifndef WIN32
    memset(overwritten, 0, sizeof(overwritten));
    for (int i = 0; i < 64; ++i) {
        memset(a, 0, sizeof(a));
        GetDevURandom(a);
        for (int x = 0; x < NUM_OS_RANDOM_BYTES; ++x) overwritten[x] |= (a[x] != 0);
    }
    BOOST_CHECK(std::count(overwritten, overwritten + NUM_OS_RANDOM_BYTES, 0) == 0);
    GetDevURandom(a);
    GetDevURandom(b);
    BOOST_CHECK(memcmp(a, b, sizeof(a)) != 0);
#endif
}

BOOST_AUTO_TEST_CASE(seed_functions)
{
    // Adding entropy must not break the generators.
    RandAddSeed();
    RandAddSeedPerfmon();
    RandAddSeedSleep();
    BOOST_CHECK(GetRandHash() != GetRandHash());
    unsigned char a[32], b[32];
    GetStrongRandBytes(a, 32);
    RandAddSeedSleep();
    GetStrongRandBytes(b, 32);
    BOOST_CHECK(memcmp(a, b, sizeof(a)) != 0);
    BOOST_CHECK(Random_SanityCheck());
}

BOOST_AUTO_TEST_CASE(byte_distribution_chisquare)
{
    // Loose chi-square test of the byte distribution of four sources,
    // 256 KiB each (1024 expected per byte value). Bounds and their
    // false-positive probability: see CHI_SQUARE_MIN/MAX above.
    std::vector<unsigned char> data(CHI_SQUARE_BYTES);

    GetRandBytes(data.data(), data.size());
    double chi = ChiSquare256(data);
    BOOST_CHECK_MESSAGE(chi > CHI_SQUARE_MIN && chi < CHI_SQUARE_MAX, "GetRandBytes chi-square " << chi);

    for (size_t i = 0; i < data.size(); i += 32) GetStrongRandBytes(&data[i], 32);
    chi = ChiSquare256(data);
    BOOST_CHECK_MESSAGE(chi > CHI_SQUARE_MIN && chi < CHI_SQUARE_MAX, "GetStrongRandBytes chi-square " << chi);

    for (size_t i = 0; i < data.size(); i += NUM_OS_RANDOM_BYTES) GetOSRand(&data[i]);
    chi = ChiSquare256(data);
    BOOST_CHECK_MESSAGE(chi > CHI_SQUARE_MIN && chi < CHI_SQUARE_MAX, "GetOSRand chi-square " << chi);

    FastRandomContext ctx; // seeded from GetRandHash() on first use
    for (size_t i = 0; i < data.size(); i += 8) WriteLE64(&data[i], ctx.rand64());
    chi = ChiSquare256(data);
    BOOST_CHECK_MESSAGE(chi > CHI_SQUARE_MIN && chi < CHI_SQUARE_MAX, "FastRandomContext chi-square " << chi);

    // Sanity check of the statistic itself: a byte counter is "too uniform"
    // (chi-square 0), a source with one stuck value is far too skewed.
    for (size_t i = 0; i < data.size(); ++i) data[i] = (unsigned char)i;
    BOOST_CHECK(ChiSquare256(data) < CHI_SQUARE_MIN);
    for (size_t i = 0; i < data.size(); i += 64) data[i] = 0;
    BOOST_CHECK(ChiSquare256(data) > CHI_SQUARE_MAX);
}

BOOST_AUTO_TEST_SUITE_END()
