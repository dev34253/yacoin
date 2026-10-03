// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Contract tests for CBigNum (src/bignum.h), task P0-10.
//
// These tests pin the CURRENT behaviour of the OpenSSL-based CBigNum class,
// bugs and oddities included (CLAUDE.md rule 1: pin, don't fix). Consensus
// code (chain trust, difficulty, stake kernel, PoW reward) computes with
// CBigNum, so whatever replaces it in Phase 4 must behave the same wherever
// the code relies on it. Checks marked "pinned:" record behaviour that a
// straightforward replacement (e.g. arith_uint256 or a two's-complement
// big integer) would get wrong.
//
// Expected values are literals (decimal or hex strings, byte strings) and
// never computed with CBigNum itself. Inputs above 64 bits are mostly built
// with SetHex (pinned separately in sethex_parsing), a few with
// CBigNum(uint256) or << (pinned in their own cases).
//
// These tests call the CBigNum API directly and are therefore temporary:
// they are retired in Phase 4 (plan rule 3, review C9). The durable,
// implementation-neutral artefacts are the golden vectors of P0-13.
// Related tasks: compact encoding P0-11 (only a smoke test here), values
// above 256 bits in consensus expressions and the method audit P0-12.
//
// Behaviour observed with OpenSSL 1.0.1k from depends on x86_64 (64-bit
// BN_ULONG); see project/done/P0-10-cbignum-contract-tests.md for details.

#include "bignum.h"
#include "streams.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "version.h"
#include "test/test_bitcoin.h"

#include <algorithm>
#include <limits>
#include <sstream>
#include <stdint.h>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bignum_tests, BasicTestingSetup)

namespace {

/** CBigNum from a hex string (SetHex syntax). */
CBigNum Hex(const std::string& str)
{
    CBigNum bn;
    bn.SetHex(str);
    return bn;
}

/** CBigNum from a getvch()-format byte string given as hex. */
CBigNum FromVch(const std::string& hex)
{
    CBigNum bn;
    bn.setvch(ParseHex(hex));
    return bn;
}

/** getvch() as hex. */
std::string VchHex(const CBigNum& bn)
{
    return HexStr(bn.getvch());
}

/** True if the OpenSSL sign flag is set (also for a "negative zero"). */
bool SignFlag(const CBigNum& bn)
{
    return BN_is_negative(&bn) != 0;
}

/** Decimal string and getvch() bytes of one value. */
void CheckValue(const CBigNum& bn, const std::string& dec, const std::string& vch)
{
    BOOST_CHECK_EQUAL(bn.ToString(), dec);
    BOOST_CHECK_EQUAL(VchHex(bn), vch);
}

} // namespace

BOOST_AUTO_TEST_CASE(constructors_integer_widths)
{
    // int8_t
    CheckValue(CBigNum((int8_t)0), "0", "");
    CheckValue(CBigNum((int8_t)1), "1", "01");
    CheckValue(CBigNum((int8_t)-1), "-1", "81");
    CheckValue(CBigNum(std::numeric_limits<int8_t>::min()), "-128", "8080");
    CheckValue(CBigNum(std::numeric_limits<int8_t>::max()), "127", "7f");
    // int16_t
    CheckValue(CBigNum((int16_t)0), "0", "");
    CheckValue(CBigNum((int16_t)1), "1", "01");
    CheckValue(CBigNum((int16_t)-1), "-1", "81");
    CheckValue(CBigNum(std::numeric_limits<int16_t>::min()), "-32768", "008080");
    CheckValue(CBigNum(std::numeric_limits<int16_t>::max()), "32767", "ff7f");
    // int32_t
    CheckValue(CBigNum((int32_t)0), "0", "");
    CheckValue(CBigNum((int32_t)1), "1", "01");
    CheckValue(CBigNum((int32_t)-1), "-1", "81");
    CheckValue(CBigNum(std::numeric_limits<int32_t>::min()), "-2147483648", "0000008080");
    CheckValue(CBigNum(std::numeric_limits<int32_t>::max()), "2147483647", "ffffff7f");
    // int64_t
    CheckValue(CBigNum((int64_t)0), "0", "");
    CheckValue(CBigNum((int64_t)1), "1", "01");
    CheckValue(CBigNum((int64_t)-1), "-1", "81");
    CheckValue(CBigNum(std::numeric_limits<int64_t>::min()), "-9223372036854775808", "000000000000008080");
    CheckValue(CBigNum(std::numeric_limits<int64_t>::max()), "9223372036854775807", "ffffffffffffff7f");
    // uint8_t .. uint64_t
    CheckValue(CBigNum((uint8_t)0), "0", "");
    CheckValue(CBigNum((uint8_t)1), "1", "01");
    CheckValue(CBigNum(std::numeric_limits<uint8_t>::max()), "255", "ff00");
    CheckValue(CBigNum((uint16_t)0), "0", "");
    CheckValue(CBigNum((uint16_t)1), "1", "01");
    CheckValue(CBigNum(std::numeric_limits<uint16_t>::max()), "65535", "ffff00");
    CheckValue(CBigNum((uint32_t)0), "0", "");
    CheckValue(CBigNum((uint32_t)1), "1", "01");
    CheckValue(CBigNum(std::numeric_limits<uint32_t>::max()), "4294967295", "ffffffff00");
    CheckValue(CBigNum((uint64_t)0), "0", "");
    CheckValue(CBigNum((uint64_t)1), "1", "01");
    CheckValue(CBigNum((uint64_t)1 << 63), "9223372036854775808", "000000000000008000");
    CheckValue(CBigNum(std::numeric_limits<uint64_t>::max()), "18446744073709551615", "ffffffffffffffff00");

    // Default constructor is zero. Implicit conversion as used by the
    // consensus code (e.g. "CBigNum bnSubsidyLimit = MAX_MINT_PROOF_OF_WORK;").
    CheckValue(CBigNum(), "0", "");
    CBigNum bnImplicit = (int64_t)100000000;
    CheckValue(bnImplicit, "100000000", "00e1f505");
}

BOOST_AUTO_TEST_CASE(constructor_uint256_and_uint160)
{
    BOOST_CHECK_EQUAL(CBigNum(uint256(0)).ToString(), "0");
    BOOST_CHECK_EQUAL(VchHex(CBigNum(uint256(0))), "");
    BOOST_CHECK_EQUAL(CBigNum(uint256(1)).ToString(), "1");

    // ~uint256(0) >> 20: 236 one bits (the powLimit form used in chainparams.cpp).
    BOOST_CHECK_EQUAL(CBigNum(~uint256(0) >> 20).GetHex(), std::string(59, 'f'));

    // Top bit set: positive, getvch() needs an extra 0x00 sign byte.
    const std::string strTop = "8000000000000000000000000000000000000000000000000000000000000001";
    CBigNum bnTop(uint256S(strTop));
    BOOST_CHECK_EQUAL(bnTop.GetHex(), strTop);
    BOOST_CHECK(!SignFlag(bnTop));
    BOOST_CHECK_EQUAL(VchHex(bnTop), "01" + std::string(60, '0') + "8000");
    BOOST_CHECK(bnTop.getuint256() == uint256S(strTop));

    CBigNum bnAllOnes(~uint256(0));
    BOOST_CHECK_EQUAL(bnAllOnes.GetHex(), std::string(64, 'f'));
    BOOST_CHECK(bnAllOnes.getuint256() == ~uint256(0));

    // There is no CBigNum(uint160) constructor; uint160 goes through
    // setuint160/getuint160.
    const std::string str160 = "ff00000000000000000000000000000000000001";
    CBigNum bn160;
    bn160.setuint160(uint160(str160));
    BOOST_CHECK_EQUAL(bn160.GetHex(), str160);
    BOOST_CHECK(!SignFlag(bn160));
    BOOST_CHECK(bn160.getuint160() == uint160(str160));
    bn160.setuint160(uint160(0));
    BOOST_CHECK_EQUAL(bn160.ToString(), "0");
    BOOST_CHECK(bn160.getuint160() == uint160(0));
    // getuint160 also returns the magnitude mod 2^160.
    BOOST_CHECK(CBigNum(-5).getuint160() == uint160(5));
    BOOST_CHECK(Hex("1" + std::string(40, '0') + "7").getuint160() == uint160(7));
}

BOOST_AUTO_TEST_CASE(set_get_roundtrips)
{
    // setuint32
    CBigNum bn(-9);
    bn.setuint32(7);
    BOOST_CHECK_EQUAL(bn.ToString(), "7");
    BOOST_CHECK(!SignFlag(bn)); // a previous negative sign is cleared
    bn.setuint32(std::numeric_limits<uint32_t>::max());
    BOOST_CHECK_EQUAL(bn.getuint32(), std::numeric_limits<uint32_t>::max());

    // setuint64 / getuint64
    const uint64_t u64s[] = {0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffffffffULL, 0x100000000ULL,
                             0x8000000000000000ULL, std::numeric_limits<uint64_t>::max()};
    for (uint64_t u : u64s) {
        CBigNum b(-9);
        b.setuint64(u);
        BOOST_CHECK(!SignFlag(b));
        BOOST_CHECK_EQUAL(b.getuint64(), u);
    }
    bn.setuint64(std::numeric_limits<uint64_t>::max());
    BOOST_CHECK_EQUAL(bn.ToString(), "18446744073709551615");

    // setint64: value and getvch() bytes (sign in the top bit of the last byte)
    struct { int64_t n; const char* dec; const char* vch; } i64s[] = {
        {0, "0", ""},
        {127, "127", "7f"},
        {-127, "-127", "ff"},
        {128, "128", "8000"},
        {-128, "-128", "8080"},
        {255, "255", "ff00"},
        {-255, "-255", "ff80"},
        {std::numeric_limits<int64_t>::max(), "9223372036854775807", "ffffffffffffff7f"},
        {std::numeric_limits<int64_t>::min(), "-9223372036854775808", "000000000000008080"},
    };
    for (const auto& c : i64s) {
        CBigNum b(-9);
        b.setint64(c.n);
        CheckValue(b, c.dec, c.vch);
    }

    // setuint256 / getuint256
    const std::string hexes[] = {
        "0", "1", "ff", "80", "100",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "8000000000000000000000000000000000000000000000000000000000000000",
        "00000000ffff0000000000000000000000000000000000000000000000000000",
    };
    for (const std::string& h : hexes) {
        const uint256 u = uint256S(h);
        CBigNum b(-9);
        b.setuint256(u);
        BOOST_CHECK(!SignFlag(b));
        BOOST_CHECK(b.getuint256() == u);
        BOOST_CHECK(CBigNum(u).getuint256() == u);
    }
    bn.setuint256(uint256S("00000000ffff0000000000000000000000000000000000000000000000000000"));
    BOOST_CHECK_EQUAL(bn.GetHex(), "ffff" + std::string(52, '0'));
}

BOOST_AUTO_TEST_CASE(getters_magnitude_mod_2n)
{
    const CBigNum bnMinus1(-1);
    const CBigNum bn2p32p5 = Hex("100000005");                 // 2^32 + 5
    const CBigNum bn2p64p5 = Hex("10000000000000005");         // 2^64 + 5
    const CBigNum bn2p256 = Hex("1" + std::string(64, '0'));   // 2^256
    // 2^300 + 2^255 + 7
    const CBigNum bn300 = Hex("1" + std::string(11, '0') + "8" + std::string(61, '0') + "07");
    const CBigNum bnInt64Min(std::numeric_limits<int64_t>::min());

    // pinned: getuint64 returns the magnitude mod 2^64 (sign dropped)
    BOOST_CHECK_EQUAL(CBigNum(bnMinus1).getuint64(), 1U);
    BOOST_CHECK_EQUAL(CBigNum(bn2p64p5).getuint64(), 5U);
    BOOST_CHECK_EQUAL(CBigNum(-bn2p64p5).getuint64(), 5U);
    BOOST_CHECK_EQUAL(CBigNum(bnInt64Min).getuint64(), 0x8000000000000000ULL);
    BOOST_CHECK_EQUAL(CBigNum(bn2p256).getuint64(), 0U);
    BOOST_CHECK_EQUAL(CBigNum(0).getuint64(), 0U);

    // pinned: getuint256 returns the magnitude mod 2^256 (sign dropped)
    const uint256 u300 = uint256S("8000000000000000000000000000000000000000000000000000000000000007");
    BOOST_CHECK(bnMinus1.getuint256() == uint256(1));
    BOOST_CHECK(bn300.getuint256() == u300);
    BOOST_CHECK((-bn300).getuint256() == u300);
    BOOST_CHECK(bn2p256.getuint256() == uint256(0));
    BOOST_CHECK(CBigNum(0).getuint256() == uint256(0));

    // pinned: getuint32 is BN_get_word truncated to 32 bits; BN_get_word
    // returns all ones for values that do not fit 64 bits, so 2^32+5 gives 5
    // but 2^64+5 gives 0xffffffff. Sign dropped.
    BOOST_CHECK_EQUAL(bnMinus1.getuint32(), 1U);
    BOOST_CHECK_EQUAL(bn2p32p5.getuint32(), 5U);
    BOOST_CHECK_EQUAL(bn2p64p5.getuint32(), 0xffffffffU);
    BOOST_CHECK_EQUAL(CBigNum(std::numeric_limits<uint64_t>::max()).getuint32(), 0xffffffffU);

    // pinned: getint32 saturates at INT32_MAX / INT32_MIN
    const int32_t i32max = std::numeric_limits<int32_t>::max();
    const int32_t i32min = std::numeric_limits<int32_t>::min();
    BOOST_CHECK_EQUAL(bnMinus1.getint32(), -1);
    BOOST_CHECK_EQUAL(CBigNum(0).getint32(), 0);
    BOOST_CHECK_EQUAL(CBigNum(i32max).getint32(), i32max);
    BOOST_CHECK_EQUAL(CBigNum(i32min).getint32(), i32min);
    BOOST_CHECK_EQUAL(Hex("80000000").getint32(), i32max);    // 2^31
    BOOST_CHECK_EQUAL(Hex("-80000001").getint32(), i32min);   // -(2^31) - 1
    BOOST_CHECK_EQUAL(bn2p32p5.getint32(), i32max);
    BOOST_CHECK_EQUAL(bn2p64p5.getint32(), i32max);
    BOOST_CHECK_EQUAL((-bn2p64p5).getint32(), i32min);
}

BOOST_AUTO_TEST_CASE(sethex_parsing)
{
    BOOST_CHECK_EQUAL(Hex("0").ToString(), "0");
    BOOST_CHECK_EQUAL(Hex("ff").ToString(), "255");
    BOOST_CHECK_EQUAL(Hex("0xff").ToString(), "255");
    BOOST_CHECK_EQUAL(Hex("0X10").ToString(), "16");
    BOOST_CHECK_EQUAL(Hex("FfFf").ToString(), "65535");
    BOOST_CHECK_EQUAL(Hex("abc").ToString(), "2748");        // odd length
    BOOST_CHECK_EQUAL(Hex("00ff").ToString(), "255");        // leading zeros
    BOOST_CHECK_EQUAL(Hex("").ToString(), "0");
    BOOST_CHECK_EQUAL(Hex("0x").ToString(), "0");
    BOOST_CHECK_EQUAL(Hex("-ff").ToString(), "-255");
    BOOST_CHECK_EQUAL(Hex("-0x1").ToString(), "-1");
    BOOST_CHECK_EQUAL(Hex("\t\n 0xA").ToString(), "10");     // leading whitespace

    // pinned: whitespace is skipped before the sign and after "0x", even
    // between the sign and the digits
    BOOST_CHECK_EQUAL(Hex("  -0x  1fF zz").ToString(), "-511");
    BOOST_CHECK_EQUAL(Hex("- 5").ToString(), "-5");

    // pinned: parsing stops silently at the first non-hex character
    BOOST_CHECK_EQUAL(Hex("1 2").ToString(), "1");
    BOOST_CHECK_EQUAL(Hex("12g4").ToString(), "18");
    BOOST_CHECK_EQUAL(Hex("g1").ToString(), "0");
    BOOST_CHECK_EQUAL(Hex("0x-5").ToString(), "0");          // sign after 0x is invalid
    BOOST_CHECK_EQUAL(Hex("--5").ToString(), "0");
    BOOST_CHECK_EQUAL(Hex("0x1\xff").ToString(), "1");       // 0xff == EOF for isxdigit

    // "-0" gives an ordinary zero (0 - 0), not a negative zero
    CBigNum bnMinus0 = Hex("-0");
    BOOST_CHECK(!SignFlag(bnMinus0));
    BOOST_CHECK(bnMinus0 == CBigNum(0));

    // More than 256 bits
    const std::string str65 = "1" + std::string(64, 'f');
    BOOST_CHECK_EQUAL(Hex(str65).GetHex(), str65);
    BOOST_CHECK_EQUAL(Hex("0x" + std::string(64, 'F')).GetHex(), std::string(64, 'f'));

    // The previous value is replaced, including its sign
    CBigNum bn(-12345);
    bn.SetHex("1");
    BOOST_CHECK_EQUAL(bn.ToString(), "1");
}

BOOST_AUTO_TEST_CASE(tostring_and_gethex)
{
    BOOST_CHECK_EQUAL(CBigNum(0).ToString(), "0");
    BOOST_CHECK_EQUAL(CBigNum(123456789).ToString(), "123456789");
    BOOST_CHECK_EQUAL(CBigNum(-123456789).ToString(10), "-123456789");
    BOOST_CHECK_EQUAL(CBigNum(-10).ToString(2), "-1010");
    BOOST_CHECK_EQUAL(CBigNum(10).ToString(3), "101");
    BOOST_CHECK_EQUAL(CBigNum(64).ToString(8), "100");
    BOOST_CHECK_EQUAL(CBigNum(255).ToString(16), "ff");
    BOOST_CHECK_EQUAL(CBigNum(0).ToString(16), "0");

    // GetHex: lower case, no leading zeros, no "0x", '-' for negatives
    BOOST_CHECK_EQUAL(CBigNum(0).GetHex(), "0");
    BOOST_CHECK_EQUAL(CBigNum(255).GetHex(), "ff");
    BOOST_CHECK_EQUAL(CBigNum(-255).GetHex(), "-ff");
    BOOST_CHECK_EQUAL(CBigNum(4096).GetHex(), "1000");
    BOOST_CHECK_EQUAL(Hex("1" + std::string(64, '0')).GetHex(), "1" + std::string(64, '0'));
    BOOST_CHECK_EQUAL(CBigNum(std::numeric_limits<int64_t>::min()).GetHex(), "-8000000000000000");

    // operator<<(ostream&) prints base 10
    std::ostringstream os;
    os << CBigNum(-42) << " " << CBigNum(0);
    BOOST_CHECK_EQUAL(os.str(), "-42 0");

    // Base 0: BN_div by zero fails and ToString throws.
    // Not tested (undefined): base 1 never terminates, bases > 16 read past
    // the digit table.
    BOOST_CHECK_THROW(CBigNum(5).ToString(0), bignum_error);
    // ...but a zero value returns "0" before dividing.
    BOOST_CHECK_EQUAL(CBigNum(0).ToString(0), "0");
}

BOOST_AUTO_TEST_CASE(vch_mpi_format)
{
    // getvch(): OpenSSL MPI without the 4-byte length, byte-reversed, i.e.
    // little-endian magnitude with the sign in the top bit of the last byte
    // (an extra 0x00/0x80 byte when the top magnitude bit is set).
    CheckValue(CBigNum(0), "0", "");
    CheckValue(CBigNum(1), "1", "01");
    CheckValue(CBigNum(-1), "-1", "81");
    CheckValue(CBigNum(127), "127", "7f");
    CheckValue(CBigNum(-127), "-127", "ff");
    CheckValue(CBigNum(128), "128", "8000");
    CheckValue(CBigNum(-128), "-128", "8080");
    CheckValue(CBigNum(255), "255", "ff00");
    CheckValue(CBigNum(-255), "-255", "ff80");
    CheckValue(CBigNum(256), "256", "0001");
    CheckValue(CBigNum(-256), "-256", "0081");

    // setvch() is the inverse
    const char* vchs[] = {"01", "81", "7f", "ff", "8000", "8080", "ff00", "ff80", "0001", "0081",
                          "ffffffffffffffff00", "000000000000008080"};
    for (const char* v : vchs) {
        BOOST_CHECK_EQUAL(VchHex(FromVch(v)), v);
    }
    BOOST_CHECK_EQUAL(FromVch("8000").ToString(), "128");
    BOOST_CHECK_EQUAL(FromVch("ff80").ToString(), "-255");
    BOOST_CHECK_EQUAL(FromVch("ffffffffffffffff00").ToString(), "18446744073709551615");

    // Empty vector is zero; redundant high zero bytes are accepted and dropped
    BOOST_CHECK_EQUAL(FromVch("").ToString(), "0");
    CBigNum bnPadded = FromVch("010000");
    BOOST_CHECK_EQUAL(bnPadded.ToString(), "1");
    BOOST_CHECK_EQUAL(VchHex(bnPadded), "01");
    // ...also with a sign byte: 01 00 80 is -1
    BOOST_CHECK_EQUAL(FromVch("010080").ToString(), "-1");

    // pinned: a lone sign bit ("80" or "0080") gives a NEGATIVE ZERO. It
    // prints as 0, ! is true and getvch() is empty, but it compares less
    // than an ordinary zero (OpenSSL 1.0.1 BN_cmp checks the sign flag
    // first). Arithmetic results are ordinary zeros again.
    const char* negzeros[] = {"80", "0080"};
    for (const char* v : negzeros) {
        CBigNum nz = FromVch(v);
        BOOST_CHECK(SignFlag(nz));
        BOOST_CHECK_EQUAL(nz.ToString(), "0");
        BOOST_CHECK_EQUAL(nz.GetHex(), "0");
        BOOST_CHECK(!nz);
        BOOST_CHECK_EQUAL(VchHex(nz), "");
        BOOST_CHECK(nz != CBigNum(0));
        BOOST_CHECK(nz < CBigNum(0));
        // Not tested (undefined behaviour): getuint64/getuint160/getuint256/
        // GetCompact of a negative zero. They allocate the 4 bytes that
        // BN_bn2mpi reports for a zero, but BN_bn2mpi then sets the sign bit
        // in d[4], one byte past the buffer (heap overflow, would abort an
        // ASan build). getvch() is safe: it returns early for size <= 4.
        CBigNum nzPlus0 = nz + CBigNum(0);
        BOOST_CHECK(!SignFlag(nzPlus0));
        BOOST_CHECK(nzPlus0 == CBigNum(0));
        BOOST_CHECK(!SignFlag(-nz));
        BOOST_CHECK(!SignFlag(nz * CBigNum(5)));
    }

    // setvch replaces the previous value
    CBigNum bn(-12345);
    bn.setvch(ParseHex("05"));
    BOOST_CHECK_EQUAL(bn.ToString(), "5");
}

BOOST_AUTO_TEST_CASE(bytes_big_endian)
{
    // setBytes/getBytes: big-endian magnitude, no sign
    CBigNum bn;
    bn.setBytes(ParseHex("8001"));
    BOOST_CHECK_EQUAL(bn.ToString(), "32769");
    BOOST_CHECK_EQUAL(HexStr(bn.getBytes()), "8001");
    bn.setBytes(ParseHex("000102"));
    BOOST_CHECK_EQUAL(bn.ToString(), "258");
    BOOST_CHECK_EQUAL(HexStr(bn.getBytes()), "0102");

    // pinned: getBytes drops the sign
    BOOST_CHECK_EQUAL(HexStr(CBigNum(-258).getBytes()), "0102");
    // Not tested (undefined behaviour): getBytes() of zero and setBytes() of
    // an empty vector both take &v[0] of an empty std::vector.

    // setBytes clears a previous negative sign
    CBigNum bnNeg(-5);
    bnNeg.setBytes(ParseHex("07"));
    BOOST_CHECK_EQUAL(bnNeg.ToString(), "7");
}

BOOST_AUTO_TEST_CASE(serialize_roundtrip)
{
    // Serialization is the getvch() bytes as a length-prefixed vector.
    struct { CBigNum bn; std::string ser; } cases[] = {
        {CBigNum(0), "00"},
        {CBigNum(1), "0101"},
        {CBigNum(-1), "0181"},
        {CBigNum(-300), "022c81"},
        {CBigNum(255), "02ff00"},
        {Hex("1" + std::string(64, '0')), "21" + std::string(64, '0') + "01"},
    };
    for (const auto& c : cases) {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << c.bn;
        BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), c.ser);
        BOOST_CHECK_EQUAL(c.bn.GetSerializeSize(), (unsigned int)ss.size());
        CBigNum back(-777);
        ss >> back;
        BOOST_CHECK(back == c.bn);
        BOOST_CHECK(ss.empty());
    }
}

BOOST_AUTO_TEST_CASE(add_sub_mul)
{
    BOOST_CHECK_EQUAL((CBigNum(5) + CBigNum(7)).ToString(), "12");
    BOOST_CHECK_EQUAL((CBigNum(5) + CBigNum(-7)).ToString(), "-2");
    BOOST_CHECK_EQUAL((CBigNum(-5) + CBigNum(-7)).ToString(), "-12");
    BOOST_CHECK_EQUAL((CBigNum(-5) + CBigNum(5)).ToString(), "0");
    BOOST_CHECK(!SignFlag(CBigNum(-5) + CBigNum(5)));
    BOOST_CHECK_EQUAL((CBigNum(3) - CBigNum(10)).ToString(), "-7");
    BOOST_CHECK_EQUAL((CBigNum(-5) - CBigNum(-7)).ToString(), "2");
    BOOST_CHECK_EQUAL((CBigNum(0) - CBigNum(0)).ToString(), "0");
    BOOST_CHECK_EQUAL((CBigNum(-6) * CBigNum(7)).ToString(), "-42");
    BOOST_CHECK_EQUAL((CBigNum(-6) * CBigNum(-7)).ToString(), "42");
    BOOST_CHECK(!SignFlag(CBigNum(-1) * CBigNum(0)));

    // Values above 2^256: (2^200 + 1) * (2^200 - 1) = 2^400 - 1
    const CBigNum a = Hex("1" + std::string(49, '0') + "1");
    const CBigNum b = Hex(std::string(50, 'f'));
    BOOST_CHECK_EQUAL((a * b).GetHex(), std::string(100, 'f'));
    BOOST_CHECK_EQUAL((b + CBigNum(1)).GetHex(), "1" + std::string(50, '0'));
    BOOST_CHECK_EQUAL((CBigNum(0) - a).GetHex(), "-1" + std::string(49, '0') + "1");

    // Unary minus
    BOOST_CHECK_EQUAL((-CBigNum(5)).ToString(), "-5");
    BOOST_CHECK_EQUAL((-CBigNum(-5)).ToString(), "5");
    BOOST_CHECK(!SignFlag(-CBigNum(0))); // OpenSSL keeps zero non-negative
    BOOST_CHECK(-CBigNum(0) == CBigNum(0));

    // Compound assignment
    CBigNum r = 10;
    r += 5;
    BOOST_CHECK_EQUAL(r.ToString(), "15");
    r -= 20;
    BOOST_CHECK_EQUAL(r.ToString(), "-5");
    r *= -3;
    BOOST_CHECK_EQUAL(r.ToString(), "15");
    r += r;
    BOOST_CHECK_EQUAL(r.ToString(), "30");
}

BOOST_AUTO_TEST_CASE(division_truncates_toward_zero)
{
    // pinned: BN_div truncates toward zero (not floor)
    BOOST_CHECK_EQUAL((CBigNum(7) / CBigNum(2)).ToString(), "3");
    BOOST_CHECK_EQUAL((CBigNum(-7) / CBigNum(2)).ToString(), "-3");
    BOOST_CHECK_EQUAL((CBigNum(7) / CBigNum(-2)).ToString(), "-3");
    BOOST_CHECK_EQUAL((CBigNum(-7) / CBigNum(-2)).ToString(), "3");
    BOOST_CHECK_EQUAL((CBigNum(6) / CBigNum(3)).ToString(), "2");
    BOOST_CHECK_EQUAL((CBigNum(2) / CBigNum(5)).ToString(), "0");
    CBigNum q = CBigNum(-2) / CBigNum(5);
    BOOST_CHECK_EQUAL(q.ToString(), "0");
    BOOST_CHECK(!SignFlag(q)); // an ordinary zero
    BOOST_CHECK(q == CBigNum(0));

    // Large values: -(2^256 + 1) / 2 = -(2^255)
    const CBigNum big = Hex("1" + std::string(63, '0') + "1");
    BOOST_CHECK_EQUAL((CBigNum(0) - big).GetHex(), "-1" + std::string(63, '0') + "1");
    BOOST_CHECK_EQUAL(((CBigNum(0) - big) / CBigNum(2)).GetHex(), "-8" + std::string(63, '0'));
    // 2^400 - 1 divided by 2^200 - 1 = 2^200 + 1
    BOOST_CHECK_EQUAL((Hex(std::string(100, 'f')) / Hex(std::string(50, 'f'))).GetHex(),
                      "1" + std::string(49, '0') + "1");

    CBigNum r = 100;
    r /= 7;
    BOOST_CHECK_EQUAL(r.ToString(), "14");
    r = -100;
    r /= 7;
    BOOST_CHECK_EQUAL(r.ToString(), "-14");
}

BOOST_AUTO_TEST_CASE(modulo_non_negative)
{
    // pinned: % uses BN_nnmod, the result is always in [0, |b|)
    BOOST_CHECK_EQUAL((CBigNum(7) % CBigNum(2)).ToString(), "1");
    BOOST_CHECK_EQUAL((CBigNum(-7) % CBigNum(2)).ToString(), "1");
    BOOST_CHECK_EQUAL((CBigNum(7) % CBigNum(-2)).ToString(), "1");
    BOOST_CHECK_EQUAL((CBigNum(-7) % CBigNum(-2)).ToString(), "1");
    BOOST_CHECK_EQUAL((CBigNum(-1) % CBigNum(5)).ToString(), "4");
    BOOST_CHECK_EQUAL((CBigNum(-6) % CBigNum(3)).ToString(), "0");
    BOOST_CHECK_EQUAL((CBigNum(2) % CBigNum(5)).ToString(), "2");

    // pinned consequence: with truncating / and non-negative %,
    // (a/b)*b + a%b != a for negative a: (-7/2)*2 + (-7%2) = -6 + 1 = -5
    const CBigNum a(-7), b(2);
    BOOST_CHECK_EQUAL(((a / b) * b + a % b).ToString(), "-5");

    // Large: -(2^256 + 1) % 2 = 1
    const CBigNum big = Hex("1" + std::string(63, '0') + "1");
    BOOST_CHECK_EQUAL(((CBigNum(0) - big) % CBigNum(2)).ToString(), "1");
    BOOST_CHECK_EQUAL((big % Hex("10000000000000000")).ToString(), "1");

    CBigNum r = -7;
    r %= 3;
    BOOST_CHECK_EQUAL(r.ToString(), "2");
}

BOOST_AUTO_TEST_CASE(division_by_zero_throws)
{
    const CBigNum zero(0);
    BOOST_CHECK_THROW(CBigNum(1) / zero, bignum_error);
    BOOST_CHECK_THROW(CBigNum(0) / zero, bignum_error);
    BOOST_CHECK_THROW(CBigNum(-1) % zero, bignum_error);
    BOOST_CHECK_THROW(CBigNum(0) % zero, bignum_error);

    // The left operand of the compound forms is left unchanged
    CBigNum r = 42;
    BOOST_CHECK_THROW(r /= zero, bignum_error);
    BOOST_CHECK_EQUAL(r.ToString(), "42");
    BOOST_CHECK_THROW(r %= zero, bignum_error);
    BOOST_CHECK_EQUAL(r.ToString(), "42");

    // A negative zero is a zero divisor too
    BOOST_CHECK_THROW(CBigNum(1) / FromVch("80"), bignum_error);
}

BOOST_AUTO_TEST_CASE(shifts)
{
    // Left shift: like multiplying by 2^n, sign kept
    BOOST_CHECK_EQUAL((CBigNum(1) << 0).ToString(), "1");
    BOOST_CHECK_EQUAL((CBigNum(1) << 8).ToString(), "256");
    BOOST_CHECK_EQUAL((CBigNum(-5) << 2).ToString(), "-20");
    BOOST_CHECK_EQUAL((CBigNum(0) << 100).ToString(), "0");
    BOOST_CHECK_EQUAL((CBigNum(1) << 300).GetHex(), "1" + std::string(75, '0'));
    CBigNum l = 3;
    l <<= 256;
    BOOST_CHECK_EQUAL(l.GetHex(), "3" + std::string(64, '0'));

    // Right shift of non-negative values: like a real shift
    BOOST_CHECK_EQUAL((CBigNum(9) >> 3).ToString(), "1");
    BOOST_CHECK_EQUAL((CBigNum(8) >> 3).ToString(), "1");   // value == 2^shift
    BOOST_CHECK_EQUAL((CBigNum(7) >> 3).ToString(), "0");   // value <  2^shift
    BOOST_CHECK_EQUAL((CBigNum(5) >> 0).ToString(), "5");
    BOOST_CHECK_EQUAL((CBigNum(0) >> 0).ToString(), "0");
    BOOST_CHECK_EQUAL((CBigNum(3) >> 1000).ToString(), "0");
    BOOST_CHECK_EQUAL((Hex("10000000000000000") >> 64).ToString(), "1");
    BOOST_CHECK_EQUAL(((CBigNum(1) << 300) >> 299).ToString(), "2");
    BOOST_CHECK_EQUAL((Hex(std::string(64, 'f')) >> 252).ToString(), "15");

    // pinned: right shift of ANY negative value gives 0 (operator>>= returns
    // 0 when 2^shift > value), even for shift 0 and when an arithmetic shift
    // would give -1 or a large negative number.
    BOOST_CHECK_EQUAL((CBigNum(-256) >> 1).ToString(), "0");
    BOOST_CHECK_EQUAL((CBigNum(-8) >> 3).ToString(), "0");
    BOOST_CHECK_EQUAL((CBigNum(-1) >> 0).ToString(), "0");
    BOOST_CHECK_EQUAL(((CBigNum(-1) << 300) >> 1).ToString(), "0");
    BOOST_CHECK(!SignFlag(CBigNum(-256) >> 1));

    CBigNum r = 1;
    r <<= 300;
    r >>= 299;
    BOOST_CHECK_EQUAL(r.ToString(), "2");
    r = -1000;
    r >>= 2;
    BOOST_CHECK_EQUAL(r.ToString(), "0");
}

BOOST_AUTO_TEST_CASE(increment_decrement)
{
    CBigNum p = 5;
    BOOST_CHECK_EQUAL((p++).ToString(), "5");
    BOOST_CHECK_EQUAL(p.ToString(), "6");
    BOOST_CHECK_EQUAL((++p).ToString(), "7");
    BOOST_CHECK_EQUAL((p--).ToString(), "7");
    BOOST_CHECK_EQUAL(p.ToString(), "6");
    BOOST_CHECK_EQUAL((--p).ToString(), "5");

    // Crossing zero
    CBigNum q = 0;
    --q;
    BOOST_CHECK_EQUAL(q.ToString(), "-1");
    BOOST_CHECK_EQUAL((q++).ToString(), "-1");
    BOOST_CHECK_EQUAL(q.ToString(), "0");
    BOOST_CHECK(!SignFlag(q));
    BOOST_CHECK(q == CBigNum(0));

    // Carry across a word boundary
    CBigNum w(std::numeric_limits<uint64_t>::max());
    ++w;
    BOOST_CHECK_EQUAL(w.GetHex(), "10000000000000000");
    w--;
    BOOST_CHECK_EQUAL(w.GetHex(), "ffffffffffffffff");
}

BOOST_AUTO_TEST_CASE(comparisons)
{
    const CBigNum m5(-5), p3(3), big = Hex("1" + std::string(64, '0'));
    BOOST_CHECK(m5 < p3);
    BOOST_CHECK(!(m5 > p3));
    BOOST_CHECK(m5 <= m5);
    BOOST_CHECK(m5 <= p3);
    BOOST_CHECK(!(m5 >= p3));
    BOOST_CHECK(p3 >= p3);
    BOOST_CHECK(m5 == CBigNum(-5));
    BOOST_CHECK(m5 != p3);
    BOOST_CHECK(!(m5 != CBigNum(-5)));
    BOOST_CHECK(!(m5 == p3));

    BOOST_CHECK(big > CBigNum(std::numeric_limits<uint64_t>::max()));
    BOOST_CHECK(CBigNum(0) - big < CBigNum(-1));
    BOOST_CHECK(CBigNum(-1) < CBigNum(0));
    BOOST_CHECK(std::min(big, p3) == p3); // as used in pow.cpp

    BOOST_CHECK(!CBigNum(0));
    BOOST_CHECK(!(!CBigNum(5)));
    BOOST_CHECK(!(!CBigNum(-5)));

    // pinned: negative zero (see vch_mpi_format) is "less than" zero
    BOOST_CHECK(FromVch("80") < CBigNum(0));
    BOOST_CHECK(FromVch("80") > CBigNum(-1));
}

BOOST_AUTO_TEST_CASE(copy_and_assign)
{
    const CBigNum a(-123);
    CBigNum b(a);
    BOOST_CHECK(b == a);
    b += 1000;
    BOOST_CHECK_EQUAL(a.ToString(), "-123"); // copies are independent
    BOOST_CHECK_EQUAL(b.ToString(), "877");

    CBigNum c;
    c = a;
    BOOST_CHECK_EQUAL(c.ToString(), "-123");
    const CBigNum& rc = c;
    c = rc; // self-assignment
    BOOST_CHECK_EQUAL(c.ToString(), "-123");

    const CBigNum big = Hex(std::string(80, 'f'));
    c = big;
    BOOST_CHECK_EQUAL(c.GetHex(), std::string(80, 'f'));
    c = 7; // assignment from an integer through the implicit constructor
    BOOST_CHECK_EQUAL(c.ToString(), "7");
}

BOOST_AUTO_TEST_CASE(compact_smoke)
{
    // Smoke test only; compact encoding is pinned exhaustively in P0-11.
    BOOST_CHECK_EQUAL(CBigNum(~uint256(0) >> 20).GetCompact(), 0x1e0fffffU);
    CBigNum bn;
    bn.SetCompact(0x1d00ffff);
    BOOST_CHECK_EQUAL(bn.GetHex(), "ffff" + std::string(52, '0'));
    BOOST_CHECK_EQUAL(bn.GetCompact(), 0x1d00ffffU);
    BOOST_CHECK_EQUAL(CBigNum().SetCompact(0x1e0fffff).getuint256().GetHex(),
                      "00000fffff" + std::string(54, '0'));
    BOOST_CHECK_EQUAL(CBigNum(0).GetCompact(), 0U);
    BOOST_CHECK_EQUAL(CBigNum().SetCompact(0).ToString(), "0");
}

BOOST_AUTO_TEST_CASE(unused_math_helpers)
{
    // These helpers have no caller outside the tests today (preliminary,
    // the binding audit is P0-12). Known answers only.
    BOOST_CHECK_EQUAL(CBigNum(3).pow(5).ToString(), "243");
    BOOST_CHECK_EQUAL(CBigNum(2).pow(CBigNum(100)).GetHex(), "1" + std::string(25, '0'));
    BOOST_CHECK_EQUAL(CBigNum(7).mul_mod(5, 6).ToString(), "5");
    BOOST_CHECK_EQUAL(CBigNum(3).pow_mod(4, 7).ToString(), "4");
    BOOST_CHECK_EQUAL(CBigNum(3).pow_mod(-1, 7).ToString(), "5"); // via inverse
    BOOST_CHECK_EQUAL(CBigNum(3).inverse(7).ToString(), "5");
    BOOST_CHECK_THROW(CBigNum(2).inverse(4), bignum_error);       // not invertible
    BOOST_CHECK_EQUAL(CBigNum(12).gcd(18).ToString(), "6");
    BOOST_CHECK(CBigNum(97).isPrime());
    BOOST_CHECK(!CBigNum(91).isPrime());
    BOOST_CHECK(CBigNum(1).isOne());
    BOOST_CHECK(!CBigNum(-1).isOne());
    BOOST_CHECK(!CBigNum(0).isOne());
    BOOST_CHECK_EQUAL(CBigNum(0).bitSize(), 0);
    BOOST_CHECK_EQUAL(CBigNum(255).bitSize(), 8);
    BOOST_CHECK_EQUAL(CBigNum(-256).bitSize(), 9); // magnitude only
}

BOOST_AUTO_TEST_SUITE_END()
