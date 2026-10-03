// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Golden vectors for CBigNum, task P0-13 (plan 0.2a, review C9).
//
// test/data/bignum_vectors.json.xz holds about 100,000 operations on the
// CBigNum methods that production code uses (P0-12 audit,
// project/plans/dead-code.md c)), with inputs and outputs written as text
// (signed hex), so any replacement of CBigNum (Phase 4) or a reference
// oracle (P0-51, P0-26) can check itself against them without CBigNum. The
// format, the operations and the OpenSSL quirks they contain (negative zero,
// compact exponent wrap, ...) are described in src/test/README.md;
// contrib/testing/bignum_vectors_check.py checks every vector with an
// independent Python model.
//
// Two test cases:
// - replay: runs every vector through CBigNum and compares;
// - generator_reproduces_vectors: the generator below (fixed seed, its own
//   PRNG, integer arithmetic only) must reproduce the embedded file byte for
//   byte. With YACOIN_BIGNUM_VECTORS_OUT=<path> it also writes the text it
//   generates to <path>; compress that with "xz -9e" into
//   src/test/data/bignum_vectors.json.xz and rebuild (regeneration).
//
// Generator and replay share Execute(), so the vectors record exactly what
// the replay checks. Inputs are built and outputs formatted with raw
// OpenSSL calls (BN_bin2bn, BN_mpi2bn, BN_bn2bin, BN_is_negative), not with
// the CBigNum methods under test. Behaviour recorded with OpenSSL 1.0.1k from
// depends on x86_64. Like the other bignum_*_tests this file calls the
// CBigNum API and is retired in Phase 4 (plan rule 3); the vector file is
// the durable artefact.

#include "bignum.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include "data/bignum_vectors.json.xz.h"

#include <univalue.h>

#include <openssl/bn.h>
#include <openssl/err.h>

#include <stdint.h>
#include <stdlib.h>

#include <chrono>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bignum_vectors_tests, BasicTestingSetup)

namespace {

const char* const VECTORS_FORMAT = "yacoin-bignum-vectors";
const char* const VECTORS_VERSION = "1";
const uint64_t GENERATOR_SEED = 0x50302d3133ULL; // "P0-13"
const size_t GENERATOR_COUNT = 100000;
const unsigned int MAX_SHIFT = 2048;

// ---------------------------------------------------------------------------
// Text <-> value, on raw OpenSSL
// ---------------------------------------------------------------------------

std::runtime_error FormatError(const std::string& what, const std::string& field)
{
    return std::runtime_error(what + ": \"" + field + "\"");
}

bool IsLowerHexDigit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

int HexDigitValue(char c)
{
    return c <= '9' ? c - '0' : c - 'a' + 10;
}

std::string BytesToHex(const std::vector<unsigned char>& bytes)
{
    static const char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (unsigned char b : bytes) {
        s += digits[b >> 4];
        s += digits[b & 0x0f];
    }
    return s;
}

/** Hex digits of a magnitude without leading zeros ("0" for zero). */
std::string TrimHex(const std::string& hex)
{
    size_t i = hex.find_first_not_of('0');
    return i == std::string::npos ? "0" : hex.substr(i);
}

/** Splits "[-]digits" and checks the canonical form: lowercase hex, no
 *  leading zeros; "-0" only if fAllowNegZero. */
void SplitSignedHex(const std::string& s, bool fAllowNegZero, bool& fNegative, std::string& digits)
{
    fNegative = !s.empty() && s[0] == '-';
    digits = fNegative ? s.substr(1) : s;
    if (digits.empty())
        throw FormatError("empty number", s);
    for (char c : digits)
        if (!IsLowerHexDigit(c))
            throw FormatError("not lowercase hex", s);
    if (digits.size() > 1 && digits[0] == '0')
        throw FormatError("leading zero", s);
    if (fNegative && digits == "0" && !fAllowNegZero)
        throw FormatError("negative zero not allowed here", s);
}

/** Value encoding V: "0", "[-]hex" without leading zeros, "-0" = negative zero. */
CBigNum ParseValue(const std::string& s, bool fAllowNegZero)
{
    bool fNegative;
    std::string digits;
    SplitSignedHex(s, fAllowNegZero, fNegative, digits);
    CBigNum bn;
    if (fNegative && digits == "0") {
        // The negative zero exactly as SetCompact makes it (BN_mpi2bn with
        // the sign bit set on a zero magnitude, P0-11).
        const unsigned char mpi[5] = {0, 0, 0, 1, 0x80};
        if (BN_mpi2bn(mpi, sizeof(mpi), &bn) == nullptr)
            throw std::runtime_error("BN_mpi2bn failed");
        return bn;
    }
    if (digits.size() % 2)
        digits = "0" + digits;
    std::vector<unsigned char> bytes(digits.size() / 2);
    for (size_t i = 0; i < bytes.size(); i++)
        bytes[i] = (unsigned char)(HexDigitValue(digits[2 * i]) * 16 + HexDigitValue(digits[2 * i + 1]));
    if (BN_bin2bn(bytes.data(), (int)bytes.size(), &bn) == nullptr)
        throw std::runtime_error("BN_bin2bn failed");
    if (fNegative)
        BN_set_negative(&bn, 1);
    return bn;
}

/** Inverse of ParseValue: sign flag plus magnitude (so "-0" shows). */
std::string FormatValue(const CBigNum& bn)
{
    std::vector<unsigned char> bytes(BN_num_bytes(&bn));
    if (!bytes.empty())
        BN_bn2bin(&bn, bytes.data());
    return (BN_is_negative(&bn) ? "-" : "") + TrimHex(BytesToHex(bytes));
}

/** Integer encoding I/U: signed hex, range checked. */
int64_t ParseInt64(const std::string& s, int64_t nMin, int64_t nMax)
{
    bool fNegative;
    std::string digits;
    SplitSignedHex(s, false, fNegative, digits);
    if (digits.size() > 16)
        throw FormatError("out of range", s);
    uint64_t n = 0;
    for (char c : digits)
        n = n * 16 + HexDigitValue(c);
    // Compare magnitudes as uint64_t, so INT64_MIN is accepted.
    if (fNegative ? n > (uint64_t)0 - (uint64_t)nMin : n > (uint64_t)nMax)
        throw FormatError("out of range", s);
    return fNegative ? (int64_t)((uint64_t)0 - n) : (int64_t)n;
}

uint64_t ParseUInt64(const std::string& s, uint64_t nMax)
{
    bool fNegative;
    std::string digits;
    SplitSignedHex(s, false, fNegative, digits);
    if (fNegative || digits.size() > 16)
        throw FormatError("out of range", s);
    uint64_t n = 0;
    for (char c : digits)
        n = n * 16 + HexDigitValue(c);
    if (n > nMax)
        throw FormatError("out of range", s);
    return n;
}

std::string FormatInt(int64_t n)
{
    std::ostringstream ss;
    if (n < 0)
        ss << "-" << std::hex << ((uint64_t)0 - (uint64_t)n);
    else
        ss << std::hex << (uint64_t)n;
    return ss.str();
}

std::string FormatUInt(uint64_t n)
{
    std::ostringstream ss;
    ss << std::hex << n;
    return ss.str();
}

uint256 ParseUInt256(const std::string& s)
{
    bool fNegative;
    std::string digits;
    SplitSignedHex(s, false, fNegative, digits);
    if (fNegative || digits.size() > 64)
        throw FormatError("not a uint256", s);
    return uint256S(digits);
}

std::string FormatUInt256(const uint256& n)
{
    return TrimHex(n.GetHex());
}

// ---------------------------------------------------------------------------
// The operations (shared by generator and replay)
// ---------------------------------------------------------------------------

struct OpInfo {
    size_t nInputs;
};

const std::map<std::string, OpInfo>& Ops()
{
    static const std::map<std::string, OpInfo> ops = {
        {"int32", {1}}, {"int64", {1}}, {"uint256", {1}},
        {"get_uint256", {1}}, {"get_uint64", {1}},
        {"set_compact", {1}}, {"get_compact", {1}},
        {"to_string", {1}}, {"get_hex", {1}},
        {"add", {2}}, {"sub", {2}}, {"mul", {2}}, {"div", {2}},
        {"shl", {2}}, {"cmp", {2}},
    };
    return ops;
}

void RequireSame(const std::string& a, const std::string& b, const std::string& what)
{
    if (a != b)
        throw std::runtime_error(what + " differ: " + a + " vs " + b);
}

/** Runs one operation on CBigNum; throws std::runtime_error on a malformed
 *  vector or when two forms of the same operation disagree. */
std::string Execute(const std::string& op, const std::vector<std::string>& in)
{
    auto it = Ops().find(op);
    if (it == Ops().end())
        throw std::runtime_error("unknown op " + op);
    if (in.size() != it->second.nInputs)
        throw std::runtime_error("wrong number of inputs for " + op);

    if (op == "int32") {
        int64_t n = ParseInt64(in[0], std::numeric_limits<int32_t>::min(), std::numeric_limits<int32_t>::max());
        return FormatValue(CBigNum((int32_t)n));
    }
    if (op == "int64") {
        int64_t n = ParseInt64(in[0], std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max());
        return FormatValue(CBigNum((int64_t)n));
    }
    if (op == "uint256") {
        const uint256 n = ParseUInt256(in[0]);
        const CBigNum a(n);
        CBigNum b;
        b.setuint256(n);
        RequireSame(FormatValue(a), FormatValue(b), "CBigNum(uint256) and setuint256");
        return FormatValue(a);
    }
    if (op == "get_uint256")
        return FormatUInt256(ParseValue(in[0], false).getuint256());
    if (op == "get_uint64")
        return FormatUInt(ParseValue(in[0], false).getuint64());
    if (op == "set_compact") {
        CBigNum bn;
        bn.SetCompact((uint32_t)ParseUInt64(in[0], 0xffffffffULL));
        return FormatValue(bn);
    }
    if (op == "get_compact")
        return FormatUInt(ParseValue(in[0], false).GetCompact());
    if (op == "to_string")
        return ParseValue(in[0], true).ToString();
    if (op == "get_hex")
        return ParseValue(in[0], true).GetHex();

    if (op == "shl") {
        const CBigNum a = ParseValue(in[0], false);
        const unsigned int n = (unsigned int)ParseUInt64(in[1], MAX_SHIFT);
        return FormatValue(a << n);
    }

    // Binary operations on two values; the negative zero is allowed only
    // where production code can meet it (SetCompact result multiplied in the
    // kernel and compared with <= 0, P0-11).
    const bool fNegZeroOk = (op == "mul" || op == "cmp");
    const CBigNum a = ParseValue(in[0], fNegZeroOk);
    const CBigNum b = ParseValue(in[1], fNegZeroOk);
    if (op == "add")
        return FormatValue(a + b);
    if (op == "sub")
        return FormatValue(a - b);
    if (op == "mul") {
        CBigNum c = a;
        c *= b;
        RequireSame(FormatValue(a * b), FormatValue(c), "a * b and a *= b");
        return FormatValue(c);
    }
    if (op == "div") {
        std::string r1, r2;
        try {
            r1 = FormatValue(a / b);
        } catch (const bignum_error&) {
            r1 = "error";
        }
        try {
            CBigNum c = a;
            c /= b;
            r2 = FormatValue(c);
        } catch (const bignum_error&) {
            r2 = "error";
        }
        ERR_clear_error(); // BN_div queued BN_R_DIV_BY_ZERO
        RequireSame(r1, r2, "a / b and a /= b");
        return r1;
    }
    // cmp
    const bool lt = a < b, le = a <= b, gt = a > b, ge = a >= b;
    std::string r;
    if (lt && le && !gt && !ge)
        r = "-1";
    else if (!lt && le && !gt && ge)
        r = "0";
    else if (!lt && !le && gt && ge)
        r = "1";
    else
        throw std::runtime_error("inconsistent comparison operators");
    return r;
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/** splitmix64 (Steele, Lea, Flood 2014): fixed, portable, integer only. */
class SplitMix64
{
    uint64_t state;

public:
    explicit SplitMix64(uint64_t seed) : state(seed) {}
    uint64_t Next()
    {
        uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    /** In [0, n), n > 0 (modulo bias is irrelevant here). */
    uint64_t Below(uint64_t n) { return Next() % n; }
    /** In [lo, hi]. */
    int64_t Range(int64_t lo, int64_t hi) { return lo + (int64_t)Below((uint64_t)(hi - lo) + 1); }
    bool Percent(unsigned int p) { return Below(100) < p; }
};

std::string Pow2Hex(unsigned int k) // 2^k
{
    static const char* const lead[4] = {"1", "2", "4", "8"};
    return std::string(lead[k % 4]) + std::string(k / 4, '0');
}

std::string Pow2Minus1Hex(unsigned int k) // 2^k - 1, k >= 1
{
    static const char* const lead[4] = {"", "1", "3", "7"};
    return TrimHex(std::string(lead[k % 4]) + std::string(k / 4, 'f'));
}

std::string Neg(const std::string& v)
{
    return v == "0" ? v : (v[0] == '-' ? v.substr(1) : "-" + v);
}

/** Exactly nBits random bits (top bit set), as V. */
std::string RandomBits(SplitMix64& rng, unsigned int nBits)
{
    if (nBits == 0)
        return "0";
    std::vector<unsigned char> bytes((nBits + 7) / 8);
    for (auto& b : bytes)
        b = (unsigned char)rng.Next();
    const unsigned int nTop = nBits - 8 * (bytes.size() - 1); // 1..8
    bytes[0] &= (unsigned char)((1u << nTop) - 1);
    bytes[0] |= (unsigned char)(1u << (nTop - 1));
    return TrimHex(BytesToHex(bytes));
}

class Generator
{
    SplitMix64 rng;
    std::ostringstream out;
    size_t nCount;
    std::vector<std::string> pool;
    const std::vector<std::string> specials;

public:
    explicit Generator(uint64_t seed) : rng(seed), nCount(0), specials(SpecialValues()) {}

    /** Records one vector; returns its output. */
    std::string Emit(const std::string& op, const std::vector<std::string>& in)
    {
        const std::string r = Execute(op, in);
        out << (nCount ? ",\n[\"" : "[\"") << op << "\"";
        for (const std::string& s : in)
            out << ",\"" << s << "\"";
        out << ",\"" << r << "\"]";
        nCount++;
        return r;
    }
    std::string Emit(const std::string& op, const std::string& a) { return Emit(op, std::vector<std::string>{a}); }
    std::string Emit(const std::string& op, const std::string& a, const std::string& b) { return Emit(op, std::vector<std::string>{a, b}); }

    size_t Count() const { return nCount; }

    /** Value of a compact, computed by the same path as set_compact but not
     *  recorded (used to build operands). */
    static std::string Compact(uint32_t n) { return Execute("set_compact", {FormatUInt(n)}); }

    /** Special magnitudes: boundaries of bytes, words, MPI sign padding,
     *  consensus constants and limits. */
    static std::vector<std::string> SpecialMagnitudes()
    {
        std::vector<std::string> v = {
            "1", "2", "7f", "80", "ff", "100", "ffff", "7fffff", "800000",
            "2710",            // CENT
            "f4240",           // COIN
            "5f5e100",         // 100 * COIN, MAX_MINT_PROOF_OF_WORK
            "71afd498d0000",   // MAX_MONEY
            "15180",           // 24 * 60 * 60
        };
        for (unsigned int k : {31u, 32u, 63u, 64u, 256u}) {
            v.push_back(Pow2Minus1Hex(k));
            v.push_back(Pow2Hex(k));
        }
        v.push_back(Pow2Hex(128));
        v.push_back(Pow2Hex(255));
        v.push_back(Pow2Minus1Hex(226));               // PoS hard limit ~uint256(0) >> 30
        v.push_back(Pow2Minus1Hex(236));               // mainnet powLimit ~uint256(0) >> 20
        v.push_back(Pow2Minus1Hex(253));               // low-difficulty powLimit ~uint256(0) >> 3
        v.push_back(Compact(0x1d00ffff));
        v.push_back(Compact(0x1e0fffff));              // mainnet powLimit as compact
        v.push_back("1" + std::string(63, '0') + "1"); // 2^256 + 1 (2^256 is 1 and 64 zeros)
        v.push_back(Pow2Hex(264));
        return v;
    }

    static std::vector<std::string> SpecialValues()
    {
        std::vector<std::string> v = {"0"};
        for (const std::string& m : SpecialMagnitudes()) {
            v.push_back(m);
            v.push_back("-" + m);
        }
        return v;
    }

    /** A random compact-derived target: mantissa << 8 * (exponent - 3). */
    std::string RandomTarget()
    {
        const unsigned int nExp = (unsigned int)rng.Range(0x18, 0x21);
        const std::string m = FormatUInt(rng.Range(1, 0x7fffff));
        return m + std::string(2 * (nExp - 3), '0');
    }

    /** A random nBits with an exponent in the range real targets use. */
    uint32_t RandomBits32Target()
    {
        return ((uint32_t)rng.Range(0x18, 0x21) << 24) | (uint32_t)rng.Range(0x008000, 0x7fffff);
    }

    std::string RandomInt64()
    {
        std::string v = RandomBits(rng, (unsigned int)rng.Range(0, 63));
        return rng.Percent(20) ? Neg(v) : v;
    }

    /** A production-shaped operand. */
    std::string RandomOperand()
    {
        const uint64_t c = rng.Below(100);
        std::string v;
        if (c < 30) {
            v = RandomInt64();
        } else if (c < 58) {
            v = RandomTarget();
            if (rng.Percent(5))
                v = Neg(v);
        } else if (c < 68) {
            // target * amount or weight, as in the kernel and retarget
            v = FormatValue(ParseValue(RandomTarget(), false) * ParseValue(RandomInt64(), false));
        } else if (c < 80) {
            v = rng.Percent(50) ? Pow2Hex((unsigned int)rng.Range(0, 600))
                                : Pow2Minus1Hex((unsigned int)rng.Range(1, 600));
            if (rng.Percent(20))
                v = FormatValue(ParseValue(v, false) + CBigNum((int32_t)rng.Range(-2, 2)));
            if (rng.Percent(20))
                v = Neg(v);
        } else if (c < 86) {
            v = specials[rng.Below(specials.size())];
        } else if (c < 95) {
            v = RandomBits(rng, (unsigned int)rng.Range(200, 256)); // hashes
        } else {
            v = RandomBits(rng, (unsigned int)rng.Range(1, 600));
            if (rng.Percent(20))
                v = Neg(v);
        }
        return v;
    }

    std::string PoolOperand()
    {
        if (pool.empty() || rng.Percent(15))
            return RandomOperand();
        return pool[rng.Below(pool.size())];
    }

    // -- section 1: adversarial ---------------------------------------------

    void Adversarial()
    {
        const std::vector<std::string>& s = specials;

        // Integer constructors at their limits and around zero.
        static const int64_t vInt32[] = {0, 1, -1, 0x7f, 0x80, -0x80, -0x81, 0xff, 0x7fff, 0x8000, -0x8000,
                                         0x7fffff, 0x800000, -0x800000, 0x7fffffff, -0x7fffffff, -0x7fffffff - 1};
        for (int64_t n : vInt32) {
            Emit("int32", FormatInt(n));
            Emit("int64", FormatInt(n));
        }
        static const int64_t vInt64[] = {0x80000000LL, -0x80000001LL, 0xffffffffLL, 0x100000000LL, -0x100000000LL,
                                         0x0080000000000000LL, -0x0080000000000000LL, 0x7fffffffffffffffLL,
                                         -0x7fffffffffffffffLL, -0x7fffffffffffffffLL - 1};
        for (int64_t n : vInt64)
            Emit("int64", FormatInt(n));

        // uint256 constructor and the getters / text on every special value.
        for (const std::string& v : s) {
            if (v[0] != '-' && v.size() <= 64)
                Emit("uint256", v);
            Emit("get_uint256", v);
            Emit("get_uint64", v);
            Emit("get_compact", v);
            Emit("to_string", v);
            Emit("get_hex", v);
        }

        // Every binary operation on every pair of special values.
        for (const std::string& a : s)
            for (const std::string& b : s)
                for (const char* op : {"add", "sub", "mul", "div", "cmp"})
                    Emit(op, a, b);

        // Shifts.
        for (const std::string& a : s)
            for (unsigned int n : {0u, 1u, 7u, 8u, 9u, 31u, 32u, 33u, 63u, 64u, 65u, 255u, 256u, 257u, 1024u, MAX_SHIFT})
                Emit("shl", a, FormatUInt(n));

        // Negative zero (SetCompact with the sign bit and zero mantissa).
        const std::string nz = Emit("set_compact", "1800000");
        for (const std::string& b : s) {
            Emit("cmp", nz, b);
            Emit("cmp", b, nz);
            Emit("mul", nz, b);
            Emit("mul", b, nz);
        }
        Emit("cmp", nz, nz);
        Emit("mul", nz, nz);
        Emit("to_string", nz);
        Emit("get_hex", nz);

        // SetCompact: every exponent with mantissas around the sign bit.
        for (uint32_t nExp = 0; nExp <= 0xff; nExp++)
            for (uint32_t m : {0x000000u, 0x000001u, 0x00007fu, 0x000080u, 0x0000ffu, 0x007fffu, 0x008000u,
                               0x00ffffu, 0x7fffffu, 0x800000u, 0x800001u, 0xffffffu})
                Emit("set_compact", FormatUInt((nExp << 24) | m));

        // GetCompact across MPI length boundaries up to the exponent wrap at
        // 2^2039 (P0-11).
        for (unsigned int k = 0; k <= 2056; k++) {
            Emit("get_compact", Pow2Hex(k));
            Emit("get_compact", Neg(Pow2Hex(k)));
            if (k >= 1) {
                Emit("get_compact", Pow2Minus1Hex(k));
                Emit("get_compact", Neg(Pow2Minus1Hex(k)));
            }
        }
    }

    // -- section 2: production-shaped chains --------------------------------

    /** kernel.cpp:451-461,526,568 */
    void KernelChain()
    {
        const std::string nValueIn = FormatInt(rng.Percent(10) ? rng.Range(0, 2000000000LL * 1000000) : rng.Range(0, 100000LL * 1000000));
        // GetWeight: min(end - begin - nStakeMinAge, nStakeMaxAge), also negative
        const std::string nWeight = FormatInt(rng.Range(-30LL * 86400, 90LL * 86400));
        const uint32_t nBits = rng.Percent(10) ? 0x1d03ffff : RandomBits32Target();
        const std::string v = Emit("int64", nValueIn);
        const std::string w = Emit("int64", nWeight);
        std::string cdw = Emit("mul", v, w);
        cdw = Emit("div", cdw, "f4240");   // / COIN
        cdw = Emit("div", cdw, "15180");   // / (24 * 60 * 60)
        Emit("get_uint64", cdw);
        const std::string target = Emit("set_compact", FormatUInt(nBits));
        const std::string product = Emit("mul", cdw, target);
        const std::string hash = Emit("uint256", RandomBits(rng, (unsigned int)rng.Range(180, 256)));
        Emit("cmp", hash, product);
        Emit("get_uint256", product);
    }

    /** chain.cpp:77-114, accumulated like bnChainTrust */
    void TrustChain(const std::string& two256, const std::string& powLimit, std::string& chainTrust)
    {
        const uint32_t nBits = rng.Percent(5) ? (uint32_t)rng.Range(0x01000000, 0x21ffffff) : RandomBits32Target();
        const std::string target = Emit("set_compact", FormatUInt(nBits));
        if (Emit("cmp", target, "0") != "1")
            return;
        std::string trust;
        if (rng.Percent(50)) {
            trust = Emit("div", two256, Emit("add", target, "1")); // legacy PoS
        } else {
            trust = Emit("div", powLimit, target);                 // PoW
            if (rng.Percent(30))
                trust = Emit("mul", trust, "2");
            if (rng.Percent(10))
                trust = Emit("add", trust, "1");
        }
        chainTrust = Emit("add", chainTrust, trust);
        Emit("get_hex", chainTrust);
        Emit("get_uint256", chainTrust);
        Emit("get_uint64", chainTrust);
    }

    /** pow.cpp:78-103 and 189-202 */
    void RetargetChain(const std::string& powLimit)
    {
        const uint32_t nBits = RandomBits32Target();
        const std::string target = Emit("set_compact", FormatUInt(nBits));
        std::string t;
        if (rng.Percent(50)) {
            const std::string u = Emit("get_uint256", target);
            t = Emit("uint256", u);
            t = Emit("mul", t, Emit("int64", FormatInt(rng.Range(-86400, 7 * 86400))));
            t = Emit("div", t, Emit("int64", FormatInt(rng.Range(1, 7 * 86400))));
        } else {
            const int64_t nInterval = rng.Range(1, 1000), nSpacing = rng.Range(1, 600);
            const int64_t nActual = rng.Range(-3600, 3600 * 24);
            t = Emit("mul", target, Emit("int64", FormatInt((nInterval - 1) * nSpacing + nActual + nActual)));
            t = Emit("div", t, Emit("int64", FormatInt((nInterval + 1) * nSpacing)));
        }
        Emit("cmp", t, powLimit);
        if (t[0] != '-' && t != "0") {
            const std::string c = Emit("get_compact", t);
            Emit("set_compact", c);
        }
    }

    /** validation.cpp:935-977 (pre-fork PoW reward bisection) */
    void RewardChain(bool fLowDifficulty)
    {
        const uint32_t nLimitBits = fLowDifficulty ? 0x201fffff : 0x1e0fffff;
        const uint32_t nBits = rng.Percent(20) ? (uint32_t)rng.Range(0x1a000000, 0x2300ffff) & 0xff7fffff
                                               : RandomBits32Target() & 0xff7fffff;
        const std::string limit = Emit("int64", "5f5e100"); // MAX_MINT_PROOF_OF_WORK
        const std::string cent = Emit("int64", "2710");
        const std::string target = Emit("set_compact", FormatUInt(nBits));
        const std::string targetLimit = Emit("set_compact", FormatUInt(nLimitBits));
        std::string rhs = limit;
        for (int i = 0; i < 5; i++)
            rhs = Emit("mul", rhs, limit);
        rhs = Emit("mul", rhs, target);
        std::string lower = cent, upper = limit;
        for (int nStep = 0; nStep < 32; nStep++) {
            if (Emit("cmp", Emit("add", lower, cent), upper) == "1")
                break;
            const std::string mid = Emit("div", Emit("add", lower, upper), "2");
            std::string lhs = mid;
            for (int i = 0; i < 5; i++)
                lhs = Emit("mul", lhs, mid);
            lhs = Emit("mul", lhs, targetLimit);
            if (Emit("cmp", lhs, rhs) == "1")
                upper = mid;
            else
                lower = mid;
        }
        Emit("get_uint64", upper);
    }

    void Chains()
    {
        for (int i = 0; i < 1000; i++)
            KernelChain();

        const std::string two256 = Emit("shl", "1", "100");
        const std::string powLimitMain = Pow2Minus1Hex(236), powLimitLow = Pow2Minus1Hex(253);
        std::string chainTrust = "0";
        for (int i = 0; i < 1000; i++)
            TrustChain(two256, i % 2 ? powLimitLow : powLimitMain, chainTrust);

        for (int i = 0; i < 1000; i++)
            RetargetChain(i % 2 ? powLimitLow : powLimitMain);

        for (int i = 0; i < 40; i++)
            RewardChain(i % 2 == 1);
    }

    // -- section 3: random --------------------------------------------------

    void Random(size_t nTotal)
    {
        for (int i = 0; i < 4096; i++)
            pool.push_back(RandomOperand());

        // Weights per 100: arithmetic and comparisons dominate, as in
        // production; the integer and uint256 constructors are mostly in
        // sections 1 and 2.
        while (nCount < nTotal) {
            const uint64_t c = rng.Below(100);
            if (c < 14) {
                Emit("add", PoolOperand(), PoolOperand());
            } else if (c < 28) {
                Emit("sub", PoolOperand(), PoolOperand());
            } else if (c < 46) {
                Emit("mul", PoolOperand(), PoolOperand());
            } else if (c < 64) {
                const std::string b = rng.Percent(50) ? RandomInt64() : PoolOperand();
                Emit("div", PoolOperand(), b);
            } else if (c < 78) {
                Emit("cmp", PoolOperand(), PoolOperand());
            } else if (c < 82) {
                Emit("shl", PoolOperand(), FormatUInt(rng.Range(0, 300)));
            } else if (c < 87) {
                const uint32_t n = rng.Percent(70) ? RandomBits32Target() : (uint32_t)rng.Next();
                Emit("set_compact", FormatUInt(n));
            } else if (c < 91) {
                Emit("get_compact", PoolOperand());
            } else if (c < 94) {
                Emit("get_uint256", PoolOperand());
            } else if (c < 96) {
                Emit("get_uint64", PoolOperand());
            } else if (c < 97) {
                Emit("to_string", PoolOperand());
            } else if (c < 98) {
                Emit("get_hex", PoolOperand());
            } else if (c < 99) {
                if (rng.Percent(50))
                    Emit("int32", FormatInt((int32_t)(uint32_t)rng.Next()));
                else
                    Emit("int64", FormatInt((int64_t)rng.Next()));
            } else {
                Emit("uint256", RandomBits(rng, (unsigned int)rng.Range(0, 256)));
            }
        }
    }

    std::string Run(size_t nTotal)
    {
        Adversarial();
        Chains();
        Random(nTotal);
        std::ostringstream doc;
        doc << "{\"format\":\"" << VECTORS_FORMAT << "\",\"version\":\"" << VECTORS_VERSION << "\",\n"
            << "\"generator\":\"src/test/bignum_vectors_tests.cpp\",\"seed\":\"" << FormatUInt(GENERATOR_SEED) << "\",\n"
            << "\"doc\":\"src/test/README.md\",\n"
            << "\"count\":\"" << nCount << "\",\n"
            << "\"vectors\":[\n"
            << out.str() << "\n"
            << "]}\n";
        return doc.str();
    }
};

std::string EmbeddedVectors()
{
    return std::string(json_tests::bignum_vectors, sizeof(json_tests::bignum_vectors) - 1);
}

double SecondsSince(const std::chrono::steady_clock::time_point& start)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

} // namespace

BOOST_AUTO_TEST_CASE(replay)
{
    const auto start = std::chrono::steady_clock::now();
    UniValue doc;
    BOOST_REQUIRE_MESSAGE(doc.read(EmbeddedVectors()) && doc.isObject(), "bignum_vectors.json: parse error");
    BOOST_REQUIRE(doc["format"].isStr() && doc["format"].get_str() == VECTORS_FORMAT);
    BOOST_REQUIRE(doc["version"].isStr() && doc["version"].get_str() == VECTORS_VERSION);
    const UniValue& vectors = doc["vectors"];
    BOOST_REQUIRE(vectors.isArray());
    BOOST_REQUIRE(doc["count"].isStr());
    BOOST_REQUIRE_EQUAL(doc["count"].get_str(), std::to_string(vectors.size()));
    BOOST_REQUIRE_GE(vectors.size(), (size_t)GENERATOR_COUNT);

    std::map<std::string, size_t> counts;
    size_t nFailures = 0;
    for (size_t i = 0; i < vectors.size(); i++) {
        const UniValue& v = vectors[i];
        std::string op, expected, actual;
        std::vector<std::string> in;
        try {
            if (!v.isArray() || v.size() < 3)
                throw std::runtime_error("not an array of at least 3 strings");
            for (size_t j = 0; j < v.size(); j++)
                if (!v[j].isStr())
                    throw std::runtime_error("field is not a string");
            op = v[0].get_str();
            for (size_t j = 1; j + 1 < v.size(); j++)
                in.push_back(v[j].get_str());
            expected = v[v.size() - 1].get_str();
            actual = Execute(op, in);
        } catch (const std::exception& e) {
            actual = std::string("exception: ") + e.what();
        }
        counts[op]++;
        if (actual != expected) {
            if (++nFailures <= 20)
                BOOST_ERROR("vector " << i << ": " << v.write() << " gives " << actual);
        }
    }
    BOOST_CHECK_MESSAGE(nFailures == 0, nFailures << " of " << vectors.size() << " vectors differ");
    BOOST_CHECK_EQUAL(counts.size(), Ops().size()); // every op is covered

    std::ostringstream summary;
    for (const auto& c : counts)
        summary << " " << c.first << "=" << c.second;
    BOOST_TEST_MESSAGE("bignum vectors: " << vectors.size() << " replayed in " << SecondsSince(start) << " s;" << summary.str());
}

BOOST_AUTO_TEST_CASE(generator_reproduces_vectors)
{
    const auto start = std::chrono::steady_clock::now();
    const std::string generated = Generator(GENERATOR_SEED).Run(GENERATOR_COUNT);
    BOOST_TEST_MESSAGE("bignum vectors: generated " << generated.size() << " bytes in " << SecondsSince(start) << " s");

    const char* pszOut = getenv("YACOIN_BIGNUM_VECTORS_OUT");
    if (pszOut && *pszOut) {
        std::ofstream file(pszOut, std::ios::binary | std::ios::trunc);
        file << generated;
        file.close();
        BOOST_REQUIRE_MESSAGE(file.good(), "cannot write " << pszOut);
        BOOST_TEST_MESSAGE("bignum vectors: written to " << pszOut << "; compress with xz -9e into src/test/data/bignum_vectors.json.xz and rebuild");
    }

    const std::string embedded = EmbeddedVectors();
    size_t nLine = 1, i = 0;
    while (i < generated.size() && i < embedded.size() && generated[i] == embedded[i]) {
        if (generated[i] == '\n')
            nLine++;
        i++;
    }
    BOOST_CHECK_MESSAGE(generated == embedded,
                        "generator output differs from test/data/bignum_vectors.json.xz from line " << nLine
                        << " (generated " << generated.size() << " bytes, embedded " << embedded.size() << " bytes)");
}

BOOST_AUTO_TEST_SUITE_END()
