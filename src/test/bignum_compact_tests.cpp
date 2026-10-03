// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Compact ("nBits") encoding of CBigNum, task P0-11 (plan 0.2a).
//
// CBigNum::SetCompact/GetCompact (bignum.h) go through OpenSSL's MPI format
// (BN_mpi2bn/BN_bn2mpi), unlike the shift-based arith_uint256 versions
// (arith_uint256.cpp). nBits is consensus data (block headers, PoW and PoS
// targets, block trust, reward), so these tests pin the CURRENT behaviour
// exactly, bugs included (CLAUDE.md rule 1), and record every difference
// from arith_uint256, which Phase 4 must treat as a special case:
//
// - a negative compact gives a negative CBigNum (arith_uint256: magnitude
//   plus the fNegative flag);
// - a sign bit with all kept mantissa bytes zero gives a NEGATIVE ZERO
//   (sign flag set, "< 0" true, "== 0" false; arith_uint256: an ordinary 0
//   with fNegative false). nBits comes from block headers, so this is
//   reachable from the network; GetCompact/getuint256 of a negative zero are
//   undefined behaviour (P0-10) and are never called here;
// - values >= 2^256 are exact (SetCompact reaches up to 2^2039 - 2^2016);
//   there is no overflow flag (arith_uint256: truncated mod 2^256,
//   fOverflow set);
// - GetCompact of |v| >= 2^2039 wraps the exponent byte (bug, pinned).
// The full list with examples is in project/done/P0-11-compact-encoding-tests.md.
//
// Expected values are literals generated with an independent Python model
// of both implementations (script in the task file), cross-checked against
// the real code; they are never computed with CBigNum. Like bignum_tests.cpp
// these tests call the CBigNum API directly and are retired in Phase 4
// (plan rule 3, review C9); the durable artefacts are P0-13's golden vectors.
// Behaviour observed with OpenSSL 1.0.1k from depends on x86_64.

#include "arith_uint256.h"
#include "bignum.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <stdint.h>
#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bignum_compact_tests, BasicTestingSetup)

namespace {

/** True if the OpenSSL sign flag is set (also for a "negative zero"). */
bool SignFlag(const CBigNum& bn)
{
    return BN_is_negative(&bn) != 0;
}

/** CBigNum from a compact value. */
CBigNum Compact(uint32_t nCompact)
{
    CBigNum bn;
    bn.SetCompact(nCompact);
    return bn;
}

/** 2^n (CBigNum << is pinned in bignum_tests). */
CBigNum Pow2(unsigned int n)
{
    return CBigNum(1) << n;
}

/** n hex zero digits. */
std::string Zeros(size_t n)
{
    return std::string(n, '0');
}

/** A compact that decodes to a negative zero: sign flag set, value zero. */
void CheckNegativeZero(uint32_t nCompact)
{
    const CBigNum bn = Compact(nCompact);
    BOOST_CHECK_MESSAGE(SignFlag(bn), "compact 0x" << std::hex << nCompact);
    BOOST_CHECK_MESSAGE(!bn, "compact 0x" << std::hex << nCompact);
    BOOST_CHECK_EQUAL(bn.ToString(), "0");
    BOOST_CHECK(bn < CBigNum(0));
    BOOST_CHECK(bn <= CBigNum(0)); // CheckProofOfWork, GetBlockTrust reject it
    BOOST_CHECK(bn != CBigNum(0));
    // Not called (undefined behaviour, P0-10): GetCompact, getuint256.
}

} // namespace

BOOST_AUTO_TEST_CASE(setcompact_every_exponent)
{
    // Every exponent 0-34 with four positive mantissas and one negative one.
    // Expected value = digits followed by nZeroBytes zero bytes; nRoundTrip
    // is GetCompact() of the result (the canonical encoding).
    struct Row {
        uint32_t nCompact;
        const char* pszDigits;
        int nZeroBytes;
        uint32_t nRoundTrip;
    };
    static const Row rows[] = {
    {0x00123456, "0", 0, 0x00000000}, {0x007fffff, "0", 0, 0x00000000}, {0x0000ffff, "0", 0, 0x00000000},
    {0x00000080, "0", 0, 0x00000000}, {0x00923456, "0", 0, 0x00000000},
    {0x01123456, "12", 0, 0x01120000}, {0x017fffff, "7f", 0, 0x017f0000}, {0x0100ffff, "0", 0, 0x00000000},
    {0x01000080, "0", 0, 0x00000000}, {0x01923456, "-12", 0, 0x01920000},
    {0x02123456, "1234", 0, 0x02123400}, {0x027fffff, "7fff", 0, 0x027fff00}, {0x0200ffff, "ff", 0, 0x0200ff00},
    {0x02000080, "0", 0, 0x00000000}, {0x02923456, "-1234", 0, 0x02923400},
    {0x03123456, "123456", 0, 0x03123456}, {0x037fffff, "7fffff", 0, 0x037fffff}, {0x0300ffff, "ffff", 0, 0x0300ffff},
    {0x03000080, "80", 0, 0x02008000}, {0x03923456, "-123456", 0, 0x03923456},
    {0x04123456, "123456", 1, 0x04123456}, {0x047fffff, "7fffff", 1, 0x047fffff}, {0x0400ffff, "ffff", 1, 0x0400ffff},
    {0x04000080, "80", 1, 0x03008000}, {0x04923456, "-123456", 1, 0x04923456},
    {0x05123456, "123456", 2, 0x05123456}, {0x057fffff, "7fffff", 2, 0x057fffff}, {0x0500ffff, "ffff", 2, 0x0500ffff},
    {0x05000080, "80", 2, 0x04008000}, {0x05923456, "-123456", 2, 0x05923456},
    {0x06123456, "123456", 3, 0x06123456}, {0x067fffff, "7fffff", 3, 0x067fffff}, {0x0600ffff, "ffff", 3, 0x0600ffff},
    {0x06000080, "80", 3, 0x05008000}, {0x06923456, "-123456", 3, 0x06923456},
    {0x07123456, "123456", 4, 0x07123456}, {0x077fffff, "7fffff", 4, 0x077fffff}, {0x0700ffff, "ffff", 4, 0x0700ffff},
    {0x07000080, "80", 4, 0x06008000}, {0x07923456, "-123456", 4, 0x07923456},
    {0x08123456, "123456", 5, 0x08123456}, {0x087fffff, "7fffff", 5, 0x087fffff}, {0x0800ffff, "ffff", 5, 0x0800ffff},
    {0x08000080, "80", 5, 0x07008000}, {0x08923456, "-123456", 5, 0x08923456},
    {0x09123456, "123456", 6, 0x09123456}, {0x097fffff, "7fffff", 6, 0x097fffff}, {0x0900ffff, "ffff", 6, 0x0900ffff},
    {0x09000080, "80", 6, 0x08008000}, {0x09923456, "-123456", 6, 0x09923456},
    {0x0a123456, "123456", 7, 0x0a123456}, {0x0a7fffff, "7fffff", 7, 0x0a7fffff}, {0x0a00ffff, "ffff", 7, 0x0a00ffff},
    {0x0a000080, "80", 7, 0x09008000}, {0x0a923456, "-123456", 7, 0x0a923456},
    {0x0b123456, "123456", 8, 0x0b123456}, {0x0b7fffff, "7fffff", 8, 0x0b7fffff}, {0x0b00ffff, "ffff", 8, 0x0b00ffff},
    {0x0b000080, "80", 8, 0x0a008000}, {0x0b923456, "-123456", 8, 0x0b923456},
    {0x0c123456, "123456", 9, 0x0c123456}, {0x0c7fffff, "7fffff", 9, 0x0c7fffff}, {0x0c00ffff, "ffff", 9, 0x0c00ffff},
    {0x0c000080, "80", 9, 0x0b008000}, {0x0c923456, "-123456", 9, 0x0c923456},
    {0x0d123456, "123456", 10, 0x0d123456}, {0x0d7fffff, "7fffff", 10, 0x0d7fffff}, {0x0d00ffff, "ffff", 10, 0x0d00ffff},
    {0x0d000080, "80", 10, 0x0c008000}, {0x0d923456, "-123456", 10, 0x0d923456},
    {0x0e123456, "123456", 11, 0x0e123456}, {0x0e7fffff, "7fffff", 11, 0x0e7fffff}, {0x0e00ffff, "ffff", 11, 0x0e00ffff},
    {0x0e000080, "80", 11, 0x0d008000}, {0x0e923456, "-123456", 11, 0x0e923456},
    {0x0f123456, "123456", 12, 0x0f123456}, {0x0f7fffff, "7fffff", 12, 0x0f7fffff}, {0x0f00ffff, "ffff", 12, 0x0f00ffff},
    {0x0f000080, "80", 12, 0x0e008000}, {0x0f923456, "-123456", 12, 0x0f923456},
    {0x10123456, "123456", 13, 0x10123456}, {0x107fffff, "7fffff", 13, 0x107fffff}, {0x1000ffff, "ffff", 13, 0x1000ffff},
    {0x10000080, "80", 13, 0x0f008000}, {0x10923456, "-123456", 13, 0x10923456},
    {0x11123456, "123456", 14, 0x11123456}, {0x117fffff, "7fffff", 14, 0x117fffff}, {0x1100ffff, "ffff", 14, 0x1100ffff},
    {0x11000080, "80", 14, 0x10008000}, {0x11923456, "-123456", 14, 0x11923456},
    {0x12123456, "123456", 15, 0x12123456}, {0x127fffff, "7fffff", 15, 0x127fffff}, {0x1200ffff, "ffff", 15, 0x1200ffff},
    {0x12000080, "80", 15, 0x11008000}, {0x12923456, "-123456", 15, 0x12923456},
    {0x13123456, "123456", 16, 0x13123456}, {0x137fffff, "7fffff", 16, 0x137fffff}, {0x1300ffff, "ffff", 16, 0x1300ffff},
    {0x13000080, "80", 16, 0x12008000}, {0x13923456, "-123456", 16, 0x13923456},
    {0x14123456, "123456", 17, 0x14123456}, {0x147fffff, "7fffff", 17, 0x147fffff}, {0x1400ffff, "ffff", 17, 0x1400ffff},
    {0x14000080, "80", 17, 0x13008000}, {0x14923456, "-123456", 17, 0x14923456},
    {0x15123456, "123456", 18, 0x15123456}, {0x157fffff, "7fffff", 18, 0x157fffff}, {0x1500ffff, "ffff", 18, 0x1500ffff},
    {0x15000080, "80", 18, 0x14008000}, {0x15923456, "-123456", 18, 0x15923456},
    {0x16123456, "123456", 19, 0x16123456}, {0x167fffff, "7fffff", 19, 0x167fffff}, {0x1600ffff, "ffff", 19, 0x1600ffff},
    {0x16000080, "80", 19, 0x15008000}, {0x16923456, "-123456", 19, 0x16923456},
    {0x17123456, "123456", 20, 0x17123456}, {0x177fffff, "7fffff", 20, 0x177fffff}, {0x1700ffff, "ffff", 20, 0x1700ffff},
    {0x17000080, "80", 20, 0x16008000}, {0x17923456, "-123456", 20, 0x17923456},
    {0x18123456, "123456", 21, 0x18123456}, {0x187fffff, "7fffff", 21, 0x187fffff}, {0x1800ffff, "ffff", 21, 0x1800ffff},
    {0x18000080, "80", 21, 0x17008000}, {0x18923456, "-123456", 21, 0x18923456},
    {0x19123456, "123456", 22, 0x19123456}, {0x197fffff, "7fffff", 22, 0x197fffff}, {0x1900ffff, "ffff", 22, 0x1900ffff},
    {0x19000080, "80", 22, 0x18008000}, {0x19923456, "-123456", 22, 0x19923456},
    {0x1a123456, "123456", 23, 0x1a123456}, {0x1a7fffff, "7fffff", 23, 0x1a7fffff}, {0x1a00ffff, "ffff", 23, 0x1a00ffff},
    {0x1a000080, "80", 23, 0x19008000}, {0x1a923456, "-123456", 23, 0x1a923456},
    {0x1b123456, "123456", 24, 0x1b123456}, {0x1b7fffff, "7fffff", 24, 0x1b7fffff}, {0x1b00ffff, "ffff", 24, 0x1b00ffff},
    {0x1b000080, "80", 24, 0x1a008000}, {0x1b923456, "-123456", 24, 0x1b923456},
    {0x1c123456, "123456", 25, 0x1c123456}, {0x1c7fffff, "7fffff", 25, 0x1c7fffff}, {0x1c00ffff, "ffff", 25, 0x1c00ffff},
    {0x1c000080, "80", 25, 0x1b008000}, {0x1c923456, "-123456", 25, 0x1c923456},
    {0x1d123456, "123456", 26, 0x1d123456}, {0x1d7fffff, "7fffff", 26, 0x1d7fffff}, {0x1d00ffff, "ffff", 26, 0x1d00ffff},
    {0x1d000080, "80", 26, 0x1c008000}, {0x1d923456, "-123456", 26, 0x1d923456},
    {0x1e123456, "123456", 27, 0x1e123456}, {0x1e7fffff, "7fffff", 27, 0x1e7fffff}, {0x1e00ffff, "ffff", 27, 0x1e00ffff},
    {0x1e000080, "80", 27, 0x1d008000}, {0x1e923456, "-123456", 27, 0x1e923456},
    {0x1f123456, "123456", 28, 0x1f123456}, {0x1f7fffff, "7fffff", 28, 0x1f7fffff}, {0x1f00ffff, "ffff", 28, 0x1f00ffff},
    {0x1f000080, "80", 28, 0x1e008000}, {0x1f923456, "-123456", 28, 0x1f923456},
    {0x20123456, "123456", 29, 0x20123456}, {0x207fffff, "7fffff", 29, 0x207fffff}, {0x2000ffff, "ffff", 29, 0x2000ffff},
    {0x20000080, "80", 29, 0x1f008000}, {0x20923456, "-123456", 29, 0x20923456},
    {0x21123456, "123456", 30, 0x21123456}, {0x217fffff, "7fffff", 30, 0x217fffff}, {0x2100ffff, "ffff", 30, 0x2100ffff},
    {0x21000080, "80", 30, 0x20008000}, {0x21923456, "-123456", 30, 0x21923456},
    {0x22123456, "123456", 31, 0x22123456}, {0x227fffff, "7fffff", 31, 0x227fffff}, {0x2200ffff, "ffff", 31, 0x2200ffff},
    {0x22000080, "80", 31, 0x21008000}, {0x22923456, "-123456", 31, 0x22923456},
    };
    BOOST_CHECK_EQUAL(sizeof(rows) / sizeof(rows[0]), 35U * 5U);
    for (const Row& row : rows) {
        const CBigNum bn = Compact(row.nCompact);
        BOOST_CHECK_MESSAGE(bn.GetHex() == row.pszDigits + Zeros(2 * row.nZeroBytes),
                            "compact 0x" << std::hex << row.nCompact << ": " << bn.GetHex());
        BOOST_CHECK_MESSAGE(bn.GetCompact() == row.nRoundTrip,
                            "compact 0x" << std::hex << row.nCompact << " -> 0x" << bn.GetCompact());
    }
    // Exponents 1 and 2 keep only the top one or two mantissa bytes; the
    // bytes dropped do not matter (truncation, as in arith_uint256).
    BOOST_CHECK_EQUAL(Compact(0x01123456).GetHex(), "12");
    BOOST_CHECK_EQUAL(Compact(0x011234ff).GetHex(), "12");
    BOOST_CHECK_EQUAL(Compact(0x021234ff).GetHex(), "1234");
}

BOOST_AUTO_TEST_CASE(setcompact_sign_and_zero)
{
    // Exponent 0: always an ordinary zero, whatever the mantissa (the MPI has
    // length 0; also with the sign bit).
    const uint32_t exponent0[] = {0x00000000, 0x00000001, 0x00123456, 0x007fffff,
                                  0x00800000, 0x00923456, 0x00ffffff};
    for (uint32_t c : exponent0) {
        const CBigNum bn = Compact(c);
        BOOST_CHECK(!SignFlag(bn));
        BOOST_CHECK(bn == CBigNum(0));
        BOOST_CHECK_EQUAL(bn.GetCompact(), 0U);
    }

    // Zero mantissa, every exponent: an ordinary zero.
    for (uint32_t e = 1; e <= 255; ++e) {
        const CBigNum bn = Compact(e << 24);
        BOOST_CHECK(!SignFlag(bn));
        BOOST_CHECK(bn == CBigNum(0));
        BOOST_CHECK_EQUAL(bn.GetCompact(), 0U);
    }

    // pinned: the sign bit with all kept mantissa bytes zero gives a NEGATIVE
    // ZERO for every exponent 1-255 (BN_mpi2bn sets the sign flag and then
    // clears the sign bit, leaving zero). arith_uint256 gives an ordinary zero
    // with fNegative false. For exponents 1 and 2 the dropped bytes do not
    // count, so 0x01800001 and 0x028000ff are negative zeros too.
    for (uint32_t e = 1; e <= 255; ++e) {
        CheckNegativeZero((e << 24) | 0x00800000);
    }
    CheckNegativeZero(0x01800001);
    CheckNegativeZero(0x018000ff);
    CheckNegativeZero(0x01808000);
    CheckNegativeZero(0x02800001);
    CheckNegativeZero(0x028000ff);
    // ...but a kept non-zero byte makes it an ordinary negative number
    BOOST_CHECK_EQUAL(Compact(0x03800001).ToString(), "-1");
    BOOST_CHECK_EQUAL(Compact(0x02800100).ToString(), "-1");
    BOOST_CHECK_EQUAL(Compact(0x01810000).ToString(), "-1");
    BOOST_CHECK_EQUAL(Compact(0x04800001).GetHex(), "-100");
    BOOST_CHECK_EQUAL(Compact(0x01ffffff).GetHex(), "-7f");

    // The stake kernel (kernel.cpp:526,568) multiplies the target; a product
    // with a negative zero is an ordinary zero, so getuint256 is safe there.
    const CBigNum nz = Compact(0x1d800000);
    const CBigNum product = CBigNum(12345) * nz;
    BOOST_CHECK(!SignFlag(product));
    BOOST_CHECK(product == CBigNum(0));
    BOOST_CHECK(product.getuint256() == uint256());

    // SetCompact replaces the previous value, including its sign, and
    // returns *this (used as CBigNum().SetCompact(n).getuint256()).
    CBigNum bn(-5);
    BOOST_CHECK(&bn.SetCompact(0x03123456) == &bn);
    BOOST_CHECK_EQUAL(bn.GetHex(), "123456");
    bn = -5;
    bn.SetCompact(0);
    BOOST_CHECK(!SignFlag(bn));
    BOOST_CHECK(bn == CBigNum(0));
    bn = Pow2(300);
    bn.SetCompact(0x04923456);
    BOOST_CHECK_EQUAL(bn.GetHex(), "-12345600");
    BOOST_CHECK_EQUAL(CBigNum().SetCompact(0x1d00ffff).getuint256().GetHex(),
                      "00000000ffff" + Zeros(52));
}

BOOST_AUTO_TEST_CASE(setcompact_large_values)
{
    // pinned: values >= 2^256 are exact; there is no overflow flag.
    // 2^256 has several encodings; GetCompact gives the canonical one.
    const uint32_t two256[] = {0x21010000, 0x22000100, 0x23000001};
    for (uint32_t c : two256) {
        const CBigNum bn = Compact(c);
        BOOST_CHECK_EQUAL(bn.GetHex(), "1" + Zeros(64));
        BOOST_CHECK(bn == Pow2(256));
        BOOST_CHECK_EQUAL(bn.GetCompact(), 0x21010000U);
        // getuint256 returns the magnitude mod 2^256
        BOOST_CHECK(bn.getuint256() == uint256());
        // as in CheckProofOfWork: larger than any 256-bit limit
        BOOST_CHECK(bn > CBigNum(~uint256()));
    }
    // Largest values below 2^256 with exponent 0x21
    BOOST_CHECK_EQUAL(Compact(0x2100ffff).GetHex(), "ffff" + Zeros(60));
    BOOST_CHECK(Compact(0x2100ffff) < Pow2(256));
    BOOST_CHECK_EQUAL(Compact(0x2100ffff).getuint256().GetHex(), "ffff" + Zeros(60));

    // Mantissa bytes above 2^256 are kept, getuint256 drops them
    const CBigNum bn21 = Compact(0x21123456);
    BOOST_CHECK_EQUAL(bn21.GetHex(), "123456" + Zeros(60));
    BOOST_CHECK_EQUAL(bn21.GetCompact(), 0x21123456U);
    BOOST_CHECK_EQUAL(bn21.getuint256().GetHex(), "3456" + Zeros(60));
    BOOST_CHECK_EQUAL(Compact(0x22123456).GetHex(), "123456" + Zeros(62));
    BOOST_CHECK_EQUAL(Compact(0x22123456).getuint256().GetHex(), "56" + Zeros(62));
    BOOST_CHECK_EQUAL(Compact(0x22008000).GetHex(), "8" + Zeros(65));
    BOOST_CHECK(Compact(0x22008000) == Pow2(263));

    // Every exponent 35-255: mantissa 0x010000 is 2^(8*(e-1)); round trip.
    for (uint32_t e = 35; e <= 255; ++e) {
        const uint32_t c = (e << 24) | 0x010000;
        const CBigNum bn = Compact(c);
        BOOST_CHECK_MESSAGE(bn.GetHex() == "1" + Zeros(2 * (e - 1)), "exponent " << e);
        BOOST_CHECK_MESSAGE(bn == Pow2(8 * (e - 1)), "exponent " << e);
        BOOST_CHECK_MESSAGE(bn.GetCompact() == c, "exponent " << e);
        BOOST_CHECK(bn.getuint256() == uint256());
    }

    // The largest compact values (2039 bits) and negative ones
    BOOST_CHECK_EQUAL(Compact(0xff7fffff).GetHex(), "7fffff" + Zeros(504));
    BOOST_CHECK(Compact(0xff7fffff) == Pow2(2039) - Pow2(2016));
    BOOST_CHECK_EQUAL(Compact(0xff7fffff).GetCompact(), 0xff7fffffU);
    BOOST_CHECK_EQUAL(Compact(0xff123456).GetHex(), "123456" + Zeros(504));
    BOOST_CHECK_EQUAL(Compact(0xff123456).GetCompact(), 0xff123456U);
    BOOST_CHECK_EQUAL(Compact(0xffffffff).GetHex(), "-7fffff" + Zeros(504));
    BOOST_CHECK_EQUAL(Compact(0xffffffff).GetCompact(), 0xffffffffU);
    // 0xff800001: only the low mantissa byte is set, -2^2016 -> 0xfd810000
    BOOST_CHECK(Compact(0xff800001) == -Pow2(2016));
    BOOST_CHECK_EQUAL(Compact(0xff800001).GetCompact(), 0xfd810000U);
    BOOST_CHECK_EQUAL(Compact(0xff800001).getuint256().GetHex(), Zeros(64));
    BOOST_CHECK_EQUAL(Compact(0x80123456).GetHex(), "123456" + Zeros(250));
}

BOOST_AUTO_TEST_CASE(getcompact_encoding)
{
    struct Row {
        const char* pszHex; // SetHex syntax, leading '-' for negative values
        uint32_t nCompact;
    };
    static const Row rows[] = {
        // small values; a top byte >= 0x80 needs a zero byte in front (the
        // 0x00800000 bit is the sign), so the exponent grows by one
        {"0", 0x00000000}, {"1", 0x01010000}, {"7f", 0x017f0000},
        {"80", 0x02008000}, {"ff", 0x0200ff00}, {"100", 0x02010000},
        {"7fff", 0x027fff00}, {"8000", 0x03008000}, {"7fffff", 0x037fffff},
        {"800000", 0x04008000}, {"12345600", 0x04123456},
        // truncation, not rounding
        {"123456ff", 0x04123456}, {"123456789", 0x05012345},
        {"7fffffffff", 0x057fffff}, {"ffffffffff", 0x0600ffff},
        // negative values: the magnitude's encoding plus the sign bit
        {"-1", 0x01810000}, {"-7f", 0x01ff0000}, {"-80", 0x02808000},
        {"-12345600", 0x04923456}, {"-ffffffffff", 0x0680ffff},
    };
    for (const Row& row : rows) {
        CBigNum bn;
        bn.SetHex(row.pszHex);
        BOOST_CHECK_MESSAGE(bn.GetCompact() == row.nCompact,
                            row.pszHex << " -> 0x" << std::hex << bn.GetCompact());
    }

    // Around 2^256 (values >= 2^256 have compact forms, exponent 0x21+)
    BOOST_CHECK_EQUAL((Pow2(255) - 1).GetCompact(), 0x207fffffU);
    BOOST_CHECK_EQUAL(Pow2(255).GetCompact(), 0x21008000U);
    BOOST_CHECK_EQUAL((-Pow2(255)).GetCompact(), 0x21808000U);
    BOOST_CHECK_EQUAL(CBigNum(~uint256()).GetCompact(), 0x2100ffffU);
    BOOST_CHECK_EQUAL(Pow2(256).GetCompact(), 0x21010000U);
    BOOST_CHECK_EQUAL((-Pow2(256)).GetCompact(), 0x21810000U);
    BOOST_CHECK_EQUAL(Pow2(263).GetCompact(), 0x22008000U);
    BOOST_CHECK_EQUAL(Pow2(264).GetCompact(), 0x22010000U);

    // The targets of the chain parameters (chainparams.cpp, pow.cpp:21),
    // built from literals so the values are the same in both builds:
    // mainnet powLimit/initialHashTarget, low-difficulty powLimit,
    // low-difficulty initialHashTarget, PoS limit, testnet powLimit.
    BOOST_CHECK_EQUAL(CBigNum(~uint256() >> 20).GetCompact(), 0x1e0fffffU);
    BOOST_CHECK_EQUAL(CBigNum(~uint256() >> 3).GetCompact(), 0x201fffffU);
    BOOST_CHECK_EQUAL(CBigNum(~uint256() >> 8).GetCompact(), 0x2000ffffU);
    BOOST_CHECK_EQUAL(CBigNum(~uint256() >> 30).GetCompact(), 0x1d03ffffU);
    BOOST_CHECK_EQUAL(CBigNum(~uint256() >> 1).GetCompact(), 0x207fffffU);
    // validation.cpp:940 round-trips powLimit: precision is lost
    BOOST_CHECK_EQUAL(Compact(0x1e0fffff).GetHex(), "fffff" + Zeros(54));
    BOOST_CHECK_EQUAL(Compact(0x201fffff).GetHex(), "1fffff" + Zeros(58));

    // pinned (bug): GetCompact shifts the MPI length (in bytes, including a
    // leading zero byte) into the top 8 bits of a 32-bit word, so for
    // |v| >= 2^2039 (256 or more MPI bytes) the exponent wraps mod 256.
    BOOST_CHECK_EQUAL(Pow2(2031).GetCompact(), 0xff008000U);
    BOOST_CHECK_EQUAL(Pow2(2032).GetCompact(), 0xff010000U);
    BOOST_CHECK_EQUAL((Pow2(2039) - 1).GetCompact(), 0xff7fffffU);
    BOOST_CHECK_EQUAL(Pow2(2039).GetCompact(), 0x00008000U);
    BOOST_CHECK_EQUAL((-Pow2(2039)).GetCompact(), 0x00808000U);
    BOOST_CHECK_EQUAL(Pow2(2040).GetCompact(), 0x00010000U);
    BOOST_CHECK_EQUAL((-Pow2(2040)).GetCompact(), 0x00810000U);
    BOOST_CHECK_EQUAL(Pow2(2048).GetCompact(), 0x01010000U);
    BOOST_CHECK_EQUAL(Pow2(4096).GetCompact(), 0x01010000U);
    // ...and these decode to something else entirely
    BOOST_CHECK(Compact(Pow2(2040).GetCompact()) == CBigNum(0));
    BOOST_CHECK(!SignFlag(Compact(Pow2(2040).GetCompact())));
    BOOST_CHECK(Compact(Pow2(2048).GetCompact()) == CBigNum(1));
}

BOOST_AUTO_TEST_CASE(arith_uint256_tests_ported)
{
    // Bitcoin Core's compact test (arith_uint256_tests.cpp, bignum_SetCompact)
    // run on CBigNum. arith_uint256 returns the magnitude plus fNegative and
    // fOverflow and takes fNegative in GetCompact; CBigNum is signed and has
    // no overflow flag. "differs:" marks a different result.
    BOOST_CHECK_EQUAL(Compact(0).GetHex(), "0");
    BOOST_CHECK_EQUAL(Compact(0).GetCompact(), 0U);
    const uint32_t zeros[] = {0x00123456, 0x01003456, 0x02000056, 0x03000000,
                              0x04000000, 0x00923456};
    for (uint32_t c : zeros) {
        const CBigNum bn = Compact(c);
        BOOST_CHECK(!SignFlag(bn));
        BOOST_CHECK(bn == CBigNum(0));
        BOOST_CHECK_EQUAL(bn.GetCompact(), 0U);
    }
    // differs: arith_uint256 gives 0 with fNegative false; CBigNum a
    // negative zero (GetCompact of it is undefined behaviour, not called).
    CheckNegativeZero(0x01803456);
    CheckNegativeZero(0x02800056);
    CheckNegativeZero(0x03800000);
    CheckNegativeZero(0x04800000);

    BOOST_CHECK_EQUAL(Compact(0x01123456).GetHex(), "12");
    BOOST_CHECK_EQUAL(Compact(0x01123456).GetCompact(), 0x01120000U);

    // "Make sure that we don't generate compacts with the 0x00800000 bit set"
    BOOST_CHECK_EQUAL(CBigNum(0x80).GetCompact(), 0x02008000U);

    // differs: arith_uint256 gives 0x7e with fNegative true; CBigNum -0x7e.
    // GetCompact() then equals arith_uint256's GetCompact(true).
    BOOST_CHECK_EQUAL(Compact(0x01fedcba).GetHex(), "-7e");
    BOOST_CHECK_EQUAL(Compact(0x01fedcba).GetCompact(), 0x01fe0000U);

    BOOST_CHECK_EQUAL(Compact(0x02123456).GetHex(), "1234");
    BOOST_CHECK_EQUAL(Compact(0x02123456).GetCompact(), 0x02123400U);
    BOOST_CHECK_EQUAL(Compact(0x03123456).GetHex(), "123456");
    BOOST_CHECK_EQUAL(Compact(0x03123456).GetCompact(), 0x03123456U);
    BOOST_CHECK_EQUAL(Compact(0x04123456).GetHex(), "12345600");
    BOOST_CHECK_EQUAL(Compact(0x04123456).GetCompact(), 0x04123456U);

    // differs: sign as for 0x01fedcba
    BOOST_CHECK_EQUAL(Compact(0x04923456).GetHex(), "-12345600");
    BOOST_CHECK_EQUAL(Compact(0x04923456).GetCompact(), 0x04923456U);

    BOOST_CHECK_EQUAL(Compact(0x05009234).GetHex(), "92340000");
    BOOST_CHECK_EQUAL(Compact(0x05009234).GetCompact(), 0x05009234U);
    BOOST_CHECK_EQUAL(Compact(0x20123456).GetHex(), "123456" + Zeros(58));
    BOOST_CHECK_EQUAL(Compact(0x20123456).GetCompact(), 0x20123456U);

    // differs: arith_uint256 sets fOverflow (value truncated to 0);
    // CBigNum holds 0x123456 * 2^2016 exactly and re-encodes it unchanged.
    BOOST_CHECK_EQUAL(Compact(0xff123456).GetHex(), "123456" + Zeros(504));
    BOOST_CHECK_EQUAL(Compact(0xff123456).GetCompact(), 0xff123456U);
}

BOOST_AUTO_TEST_CASE(differences_from_arith_uint256)
{
    // Every exponent 0-255 with these mantissas, CBigNum against
    // arith_uint256. The relations checked here are the complete list of
    // differences for SetCompact/GetCompact (see the file comment).
    static const uint32_t mantissas[] = {
        0x000000, 0x000001, 0x000080, 0x0000ff, 0x008000, 0x00ffff, 0x010000, 0x123456,
        0x7fffff, 0x800000, 0x800001, 0x8000ff, 0x808000, 0x923456, 0xffffff};
    const CBigNum bn2pow256 = Pow2(256);
    int nNegativeZero = 0, nZero = 0, nNegative = 0, nOverflow = 0, nOverflowNegative = 0,
        nSameCompact = 0, nTotal = 0;
    for (uint32_t e = 0; e <= 255; ++e) {
        for (uint32_t m : mantissas) {
            const uint32_t c = (e << 24) | m;
            ++nTotal;
            const CBigNum bn = Compact(c);
            arith_uint256 a;
            bool fNegative = true, fOverflow = true;
            a.SetCompact(c, &fNegative, &fOverflow);

            if (SignFlag(bn) && !bn) {
                // Negative zero: exactly when the exponent is >= 1 and the
                // sign bit is set but arith_uint256 reports no fNegative
                // (all kept mantissa bytes zero); arith_uint256 gives 0.
                ++nNegativeZero;
                BOOST_CHECK_MESSAGE(e >= 1 && (c & 0x00800000) && !fNegative && a == 0 && !fOverflow,
                                    "compact 0x" << std::hex << c);
                continue;
            }
            BOOST_CHECK_MESSAGE(!(e >= 1 && (c & 0x00800000) && !fNegative),
                                "compact 0x" << std::hex << c);
            if (!bn) ++nZero;
            if (SignFlag(bn)) ++nNegative;
            // The sign flag is arith_uint256's fNegative.
            BOOST_CHECK_MESSAGE(SignFlag(bn) == fNegative, "compact 0x" << std::hex << c);
            // The magnitude mod 2^256 is arith_uint256's value.
            BOOST_CHECK_MESSAGE(bn.getuint256() == ArithToUint256(a), "compact 0x" << std::hex << c);
            // fOverflow is exactly |value| >= 2^256.
            const CBigNum bnAbs = SignFlag(bn) ? -bn : bn;
            BOOST_CHECK_MESSAGE(fOverflow == (bnAbs >= bn2pow256), "compact 0x" << std::hex << c);
            if (fOverflow) {
                ++nOverflow;
                if (SignFlag(bn)) ++nOverflowNegative;
            } else {
                // Below 2^256 GetCompact is the same as arith_uint256's.
                ++nSameCompact;
                BOOST_CHECK_MESSAGE(bn.GetCompact() == a.GetCompact(fNegative),
                                    "compact 0x" << std::hex << c);
            }
            // Round trip: all these values are below 2^2039, so no wrap.
            BOOST_CHECK_MESSAGE(Compact(bn.GetCompact()) == bn, "compact 0x" << std::hex << c);
        }
    }
    // Literal counts (Python model) so no category is skipped silently.
    BOOST_CHECK_EQUAL(nTotal, 3840);
    BOOST_CHECK_EQUAL(nNegativeZero, 260);
    BOOST_CHECK_EQUAL(nZero, 278);
    BOOST_CHECK_EQUAL(nNegative, 1270);
    BOOST_CHECK_EQUAL(nOverflow, 2886);
    BOOST_CHECK_EQUAL(nOverflowNegative, 1110);
    BOOST_CHECK_EQUAL(nSameCompact, 694);
}

BOOST_AUTO_TEST_SUITE_END()
