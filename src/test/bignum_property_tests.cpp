// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Property tests for CBigNum arithmetic and compact encoding, task P0-27
// (plan 0.4).
//
// Algebraic identities are checked on random inputs: small and large
// (up to 1100 bits, and about 2400 bits for the compact exponent wrap),
// positive and negative, powers of two and byte patterns that provoke
// carries. Like P0-10 (bignum_tests.cpp) these tests pin the CURRENT
// behaviour, bugs included (CLAUDE.md rule 1). Where a textbook identity
// does not hold for CBigNum the test checks what CBigNum actually does
// instead of leaving the input class out ("pinned:" below):
//
// - operator>> of ANY negative value is an ordinary 0 (operator>>= compares
//   with 2^n), so (a<<n)>>n == a only for a >= 0;
// - / truncates toward zero (BN_div); % is non-negative (BN_nnmod), so for
//   negative a, a % b is a - (a/b)*b + |b| when the remainder is not 0;
// - a negative zero (sign flag set, magnitude 0) comes from SetCompact of a
//   sign-bit compact with zero kept mantissa bytes (P0-11). It compares
//   "< 0" and "> -1"; -0 - 0, -0 + -0 and -0 << n stay negative zeros, and
//   -0 % b is |b|, outside [0, |b|). No operation on ordinary values gives
//   a negative zero. GetCompact, getuint256 and getuint64 of a negative zero
//   are undefined behaviour (open question Q2) and are never called;
// - GetCompact wraps the exponent byte when the MPI needs 256 bytes or more
//   (|v| >= 2^2039, P0-11).
//
// Expected values come from identities between operations or from a
// different computation (powers of two from a table built by doubling,
// truncation with / and *, compacts decoded by hand, arith_uint256), never
// from the operation under test on the same operands.
//
// Random source: each case uses its own FastRandomContext seeded with
// SHA256(base seed || case name). The base seed is fixed, so the default
// run is deterministic. Environment variables (see src/test/README.md):
//   YACOIN_PROPERTY_SEED        "random" or 64 hex digits (replay a seed)
//   YACOIN_PROPERTY_ITERATIONS  samples per case (default 1000)
// Every failure message names the seed, the case, the iteration and the
// operands, so it can be replayed with YACOIN_PROPERTY_SEED=<seed>.
//
// These tests call the CBigNum API directly and are retired in Phase 4
// together with P0-10's (plan rule 3, review C9).
// Behaviour observed with OpenSSL 1.0.1k from depends on x86_64 (64-bit
// BN_ULONG); see project/done/P0-27-property-tests.md.

#include "arith_uint256.h"
#include "bignum.h"
#include "crypto/sha256.h"
#include "random.h"
#include "tinyformat.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <limits>
#include <map>
#include <sstream>
#include <stdint.h>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bignum_property_tests, BasicTestingSetup)

namespace {

/** Base seed of the default (deterministic) run. */
const char* const DEFAULT_SEED = "50302d323720434269674e756d2070726f706572747920746573747300000000";
const int DEFAULT_ITERATIONS = 1000;
/** A case stops after this many failed checks. */
const int MAX_FAILURES = 20;
/** Largest power of two in the table (values up to ~2400 bits). */
const unsigned int MAX_POW2 = 2600;

bool SignFlag(const CBigNum& bn)
{
    return BN_is_negative(&bn) != 0;
}

bool IsNegativeZero(const CBigNum& bn)
{
    return SignFlag(bn) && !bn;
}

CBigNum Hex(const std::string& str)
{
    CBigNum bn;
    bn.SetHex(str);
    return bn;
}

CBigNum Compact(uint32_t nCompact)
{
    CBigNum bn;
    bn.SetCompact(nCompact);
    return bn;
}

/** 2^n from a table built by doubling (independent of operator<<). */
const CBigNum& Pow2(unsigned int n)
{
    static const std::vector<CBigNum> table = [] {
        std::vector<CBigNum> v;
        v.reserve(MAX_POW2 + 1);
        CBigNum p(1);
        for (unsigned int i = 0; i <= MAX_POW2; ++i) {
            v.push_back(p);
            p = p * CBigNum(2);
        }
        return v;
    }();
    BOOST_REQUIRE(n <= MAX_POW2);
    return table[n];
}

/** |x| of an ordinary value. */
CBigNum Abs(const CBigNum& x)
{
    return x < CBigNum(0) ? CBigNum(0) - x : x;
}

int Sign(const CBigNum& x)
{
    return x < CBigNum(0) ? -1 : (x > CBigNum(0) ? 1 : 0);
}

/** Number of bits of |x| (0 for 0), by comparison with the power table. */
unsigned int BitLength(const CBigNum& x)
{
    const CBigNum a = Abs(x);
    unsigned int lo = 0, hi = MAX_POW2; // smallest k with a < 2^k
    while (lo < hi) {
        const unsigned int mid = (lo + hi) / 2;
        if (a < Pow2(mid))
            hi = mid;
        else
            lo = mid + 1;
    }
    return lo;
}

/** Size of the OpenSSL MPI magnitude of x in bytes, including the 0x00 sign
 *  padding byte when the top bit of the top byte is set. */
unsigned int MpiSize(const CBigNum& x)
{
    const unsigned int nBits = BitLength(x);
    return nBits == 0 ? 0 : nBits / 8 + 1;
}

/** Hex for messages; marks a negative zero. */
std::string Hx(const CBigNum& x)
{
    return IsNegativeZero(x) ? std::string("-0 (negative zero)") : x.GetHex();
}

/** The value SetCompact gives for nCompact, decoded by hand. fSign is the
 *  sign of the result (it can be set for a zero magnitude: negative zero). */
CBigNum DecodeCompact(uint32_t nCompact, bool& fSign)
{
    const unsigned int nExp = nCompact >> 24;
    const uint32_t nMantissa = nCompact & 0x007fffff;
    fSign = nExp >= 1 && (nCompact & 0x00800000) != 0;
    CBigNum mag;
    if (nExp == 0)
        mag = CBigNum(0);
    else if (nExp < 3)
        mag = CBigNum((int64_t)(nMantissa >> (8 * (3 - nExp))));
    else
        mag = CBigNum((int64_t)nMantissa) * Pow2(8 * (nExp - 3));
    return fSign ? CBigNum(0) - mag : mag;
}

/** Test options from the environment. */
struct PropertyOptions {
    uint256 seed;
    int nIterations;
    std::string strError;

    PropertyOptions() : seed(uint256S(DEFAULT_SEED)), nIterations(DEFAULT_ITERATIONS)
    {
        const char* pszSeed = getenv("YACOIN_PROPERTY_SEED");
        if (pszSeed && *pszSeed) {
            const std::string s(pszSeed);
            if (s == "random") {
                seed = GetRandHash();
            } else if (s.size() == 64 && IsHex(s)) {
                seed = uint256S(s);
            } else {
                strError = "YACOIN_PROPERTY_SEED must be \"random\" or 64 hex digits, got \"" + s + "\"";
            }
        }
        const char* pszIter = getenv("YACOIN_PROPERTY_ITERATIONS");
        if (pszIter && *pszIter) {
            int32_t n = 0;
            if (!ParseInt32(pszIter, &n) || n <= 0) {
                strError = std::string("YACOIN_PROPERTY_ITERATIONS must be a positive integer, got \"") + pszIter + "\"";
            } else {
                nIterations = n;
            }
        }
    }
};

uint256 CaseSeed(const uint256& base, const std::string& strCase)
{
    uint256 h;
    CSHA256().Write(base.begin(), base.size()).Write((const unsigned char*)strCase.data(), strCase.size()).Finalize(h.begin());
    return h;
}

/** Per-case state: random source, failure reporting, statistics. */
class Property
{
public:
    explicit Property(const std::string& strCaseIn)
        : opts(), strCase(strCaseIn), rng(CaseSeed(opts.seed, strCaseIn)), nIteration(-1), nFailures(0), nChecks(0),
          start(std::chrono::steady_clock::now())
    {
        BOOST_REQUIRE_MESSAGE(opts.strError.empty(), opts.strError);
        BOOST_TEST_MESSAGE("bignum properties: " << strCase << " seed " << opts.seed.GetHex() << ", "
                                                 << opts.nIterations << " iterations");
    }

    int Iterations() const { return opts.nIterations; }
    void SetIteration(int n) { nIteration = n; }
    FastRandomContext& Rng() { return rng; }
    void Count(const std::string& strWhat) { mapCounts[strWhat]++; }
    int GetCount(const std::string& strWhat) const
    {
        auto it = mapCounts.find(strWhat);
        return it == mapCounts.end() ? 0 : it->second;
    }

    void Checked() { nChecks++; }

    void Fail(int nLine, const char* pszExpr, const std::string& strOperands)
    {
        BOOST_ERROR("bignum_property_tests.cpp:" << nLine << ": " << pszExpr << " failed; case " << strCase
                                                 << ", iteration " << nIteration << ", " << strOperands
                                                 << " (replay with YACOIN_PROPERTY_SEED=" << opts.seed.GetHex() << ")");
        if (++nFailures >= MAX_FAILURES)
            BOOST_FAIL("bignum properties: " << strCase << " stopped after " << nFailures << " failures");
    }

    /** Prints the statistics; requires that every listed class was hit at
     *  least once (only with enough iterations to make that certain). */
    void Finish(const std::vector<std::string>& vRequired = {})
    {
        const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        std::ostringstream counts;
        for (const auto& c : mapCounts)
            counts << " " << c.first << "=" << c.second;
        BOOST_TEST_MESSAGE("bignum properties: " << strCase << " " << nChecks << " checks in " << seconds
                                                 << " s;" << counts.str());
        BOOST_CHECK_MESSAGE(nChecks > 0, strCase << ": no checks ran");
        if (opts.nIterations >= DEFAULT_ITERATIONS) {
            for (const std::string& s : vRequired)
                BOOST_CHECK_MESSAGE(GetCount(s) > 0, strCase << ": input class \"" << s << "\" never generated");
        }
    }

    // --- Random inputs ---

    /** n random hex digits with exactly nBits bits (nBits >= 1). */
    std::string RandomHexBits(unsigned int nBits)
    {
        const unsigned int nDigits = (nBits + 3) / 4;
        const unsigned int nTop = nBits - 4 * (nDigits - 1); // 1-4 bits
        std::string s;
        s += "0123456789abcdef"[(1u << (nTop - 1)) | (unsigned int)rng.randbits(nTop - 1)];
        for (unsigned int i = 1; i < nDigits; ++i)
            s += "0123456789abcdef"[rng.randbits(4)];
        return s;
    }

    unsigned int RandomInRange(unsigned int nMin, unsigned int nMax)
    {
        return nMin + (unsigned int)rng.randrange(nMax - nMin + 1);
    }

    /** Random value with exactly nBits bits and a random sign. */
    CBigNum RandomBits(unsigned int nBits)
    {
        return Hex((rng.randbool() ? "-" : "") + RandomHexBits(nBits));
    }

    /** A random ordinary value (never a negative zero) from one of the
     *  input classes; about half are negative. */
    CBigNum RandomValue()
    {
        const bool fNegative = rng.randbool();
        std::string strHex;
        switch (rng.randrange(16)) {
        case 0:
            Count("zero");
            return CBigNum(0);
        case 1: case 2: case 3:
            Count("bits1-64");
            strHex = RandomHexBits(RandomInRange(1, 64));
            break;
        case 4: case 5: case 6:
            Count("bits65-256");
            strHex = RandomHexBits(RandomInRange(65, 256));
            break;
        case 7: case 8: case 9:
            Count("bits257-520");
            strHex = RandomHexBits(RandomInRange(257, 520));
            break;
        case 10: case 11:
            Count("bits521-1100");
            strHex = RandomHexBits(RandomInRange(521, 1100));
            break;
        case 12: case 13: {
            Count("pow2");
            const unsigned int k = RandomInRange(0, 520);
            CBigNum v = Pow2(k);
            const int nVariant = (int)rng.randrange(3);
            if (nVariant == 1)
                v = v - CBigNum(1);
            else if (nVariant == 2)
                v = v + CBigNum(1);
            return fNegative ? CBigNum(0) - v : v;
        }
        default: {
            Count("byte-runs");
            const unsigned int nBytes = RandomInRange(1, 80);
            while (strHex.size() < 2 * nBytes) {
                const unsigned int nRun = RandomInRange(1, 16);
                const int nKind = (int)rng.randrange(3);
                for (unsigned int i = 0; i < nRun && strHex.size() < 2 * nBytes; ++i) {
                    const unsigned int b = nKind == 0 ? 0x00 : nKind == 1 ? 0xff : (unsigned int)rng.randbits(8);
                    strHex += strprintf("%02x", b);
                }
            }
            break;
        }
        }
        if (fNegative)
            Count("negative");
        return Hex((fNegative ? "-" : "") + strHex);
    }

    CBigNum RandomNonZero()
    {
        CBigNum v;
        do {
            v = RandomValue();
        } while (!v);
        return v;
    }

    /** Shift amount 0-600, biased to word and byte boundaries. */
    unsigned int RandomShift()
    {
        static const unsigned int special[] = {0, 1, 7, 8, 31, 32, 63, 64, 65, 127, 128, 255, 256, 257, 511, 512};
        if (rng.randbool())
            return special[rng.randrange(sizeof(special) / sizeof(special[0]))];
        return RandomInRange(0, 600);
    }

    int64_t RandomInt64()
    {
        int64_t n;
        switch (rng.randrange(4)) {
        case 0: n = (int64_t)rng.randrange(1000) - 500; break;
        case 1: n = (int64_t)rng.rand64(); break;
        case 2: n = rng.randbool() ? std::numeric_limits<int64_t>::min() : std::numeric_limits<int64_t>::max(); break;
        default: n = (int64_t)(rng.rand64() >> RandomInRange(1, 63)) * (rng.randbool() ? -1 : 1); break;
        }
        return n;
    }

private:
    const PropertyOptions opts;
    const std::string strCase;
    FastRandomContext rng;
    int nIteration;
    int nFailures;
    uint64_t nChecks;
    std::map<std::string, int> mapCounts;
    const std::chrono::steady_clock::time_point start;
};

/** Checks cond; on failure reports the expression, the line and the
 *  operands (streamed only on failure). */
#define PROP_CHECK(prop, cond, operands)                                    \
    do {                                                                    \
        (prop).Checked();                                                   \
        if (!(cond)) {                                                      \
            std::ostringstream prop_check_ops_;                             \
            prop_check_ops_ << operands;                                    \
            (prop).Fail(__LINE__, #cond, prop_check_ops_.str());            \
        }                                                                   \
    } while (0)

/** True if f() throws bignum_error. */
bool ThrowsBignumError(const std::function<void()>& f)
{
    try {
        f();
    } catch (const bignum_error&) {
        return true;
    }
    return false;
}

const std::vector<std::string> VALUE_CLASSES = {"zero", "bits1-64", "bits65-256", "bits257-520", "bits521-1100",
                                                "pow2", "byte-runs", "negative"};

} // namespace

BOOST_AUTO_TEST_CASE(add_sub_identities)
{
    Property p("add_sub_identities");
    const CBigNum zero(0);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum a = p.RandomValue(), b = p.RandomValue(), c = p.RandomValue();
        const std::string ops = "a=" + Hx(a) + " b=" + Hx(b) + " c=" + Hx(c);
        PROP_CHECK(p, a + b - b == a, ops);
        PROP_CHECK(p, a - b + b == a, ops);
        PROP_CHECK(p, a + b == b + a, ops);
        PROP_CHECK(p, (a + b) + c == a + (b + c), ops);
        PROP_CHECK(p, a - b == -(b - a), ops);
        PROP_CHECK(p, a - b == a + (-b), ops);
        PROP_CHECK(p, -(-a) == a, ops);
        PROP_CHECK(p, a + zero == a && zero + a == a && a - zero == a, ops);
        PROP_CHECK(p, a - a == zero && !SignFlag(a - a), ops);
        PROP_CHECK(p, a + (-a) == zero && !SignFlag(a + (-a)), ops);
        CBigNum r = a;
        r += b;
        PROP_CHECK(p, r == a + b, ops);
        r -= b;
        PROP_CHECK(p, r == a, ops);
    }
    p.Finish(VALUE_CLASSES);
}

BOOST_AUTO_TEST_CASE(mul_div_identities)
{
    Property p("mul_div_identities");
    const CBigNum zero(0), one(1), minusOne(-1);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum a = p.RandomValue(), b = p.RandomNonZero(), c = p.RandomValue();
        const int64_t n = p.RandomInt64();
        const std::string ops = "a=" + Hx(a) + " b=" + Hx(b) + " c=" + Hx(c) + " n=" + strprintf("%d", n);
        PROP_CHECK(p, (a * b) / b == a, ops);
        PROP_CHECK(p, a * b == b * a, ops);
        PROP_CHECK(p, (a * b) * c == a * (b * c), ops);
        PROP_CHECK(p, a * (b + c) == a * b + a * c, ops);
        PROP_CHECK(p, a * one == a && one * a == a, ops);
        PROP_CHECK(p, a * minusOne == -a, ops);
        PROP_CHECK(p, a * zero == zero && !SignFlag(a * zero) && !SignFlag(zero * a), ops);
        PROP_CHECK(p, a / one == a && a / minusOne == -a, ops);
        if (a != zero)
            PROP_CHECK(p, (a * b) / a == b && a / a == one, ops);
        // Compound forms as used in pow.cpp and chain.cpp
        CBigNum r = a;
        r *= b;
        PROP_CHECK(p, r == a * b, ops);
        r /= b;
        PROP_CHECK(p, r == a, ops);
        // int64_t operands (implicit CBigNum(int64_t), as in pow.cpp:81-82,197-198)
        r = a;
        r *= n;
        PROP_CHECK(p, r == a * CBigNum(n), ops);
        if (n != 0) {
            r /= n;
            PROP_CHECK(p, r == a, ops);
            PROP_CHECK(p, a / n == a / CBigNum(n), ops);
        }
    }
    p.Finish(VALUE_CLASSES);
}

BOOST_AUTO_TEST_CASE(division_truncates)
{
    Property p("division_truncates");
    const CBigNum zero(0);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum a = p.RandomValue();
        // Divisors of all sizes, sometimes close to a
        CBigNum b = p.RandomNonZero();
        if (p.Rng().randrange(4) == 0 && a != zero)
            b = a + CBigNum((int64_t)p.Rng().randrange(5) - 2);
        if (!b)
            b = CBigNum(1);
        const std::string ops = "a=" + Hx(a) + " b=" + Hx(b);
        const CBigNum q = a / b;
        const CBigNum r = a - q * b;
        // Truncation toward zero: |r| < |b| and r has the sign of a (or is 0)
        PROP_CHECK(p, Abs(r) < Abs(b), ops);
        PROP_CHECK(p, r == zero || Sign(r) == Sign(a), ops);
        PROP_CHECK(p, (-a) / b == -q && a / (-b) == -q && (-a) / (-b) == q, ops);
        if (Abs(a) < Abs(b)) {
            p.Count("quotient-zero");
            PROP_CHECK(p, q == zero && !SignFlag(q), ops);
        }
        if (r != zero && Sign(a) < 0)
            p.Count("negative-remainder");
        // pinned: % is in [0, |b|) and differs from the truncated remainder
        // by |b| when that is negative (BN_nnmod)
        const CBigNum m = a % b;
        PROP_CHECK(p, m >= zero && m < Abs(b), ops);
        PROP_CHECK(p, m == (r < zero ? r + Abs(b) : r), ops);
        PROP_CHECK(p, a % (-b) == m, ops);
        // Division by zero throws; the compound form leaves the operand alone
        PROP_CHECK(p, ThrowsBignumError([&] { (void)(a / zero); }), ops);
        PROP_CHECK(p, ThrowsBignumError([&] { (void)(a % zero); }), ops);
        CBigNum d = a;
        PROP_CHECK(p, ThrowsBignumError([&] { d /= zero; }) && d == a, ops);
    }
    p.Finish({"quotient-zero", "negative-remainder", "negative"});
}

BOOST_AUTO_TEST_CASE(shift_identities)
{
    Property p("shift_identities");
    const CBigNum zero(0);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum a = p.RandomValue();
        const unsigned int n = p.RandomShift(), m = p.RandomShift();
        const std::string ops = "a=" + Hx(a) + strprintf(" n=%u m=%u", n, m);
        PROP_CHECK(p, (a << n) == a * Pow2(n), ops);
        PROP_CHECK(p, ((a << n) << m) == (a << (n + m)), ops);
        CBigNum r = a;
        r <<= n;
        PROP_CHECK(p, r == (a << n), ops);
        r = a;
        r >>= n;
        PROP_CHECK(p, r == (a >> n), ops);
        if (a >= zero) {
            p.Count("a-non-negative");
            PROP_CHECK(p, ((a << n) >> n) == a, ops);
            PROP_CHECK(p, (a >> n) == a / Pow2(n), ops);
            PROP_CHECK(p, ((a >> n) << n) == a - a % Pow2(n), ops);
            PROP_CHECK(p, ((a >> n) >> m) == (a >> (n + m)), ops);
        } else {
            // pinned: >> of a negative value is an ordinary 0 for every n,
            // including n == 0 (operator>>= returns 0 when 2^n > value)
            p.Count("a-negative");
            PROP_CHECK(p, (a >> n) == zero && !SignFlag(a >> n), ops);
            PROP_CHECK(p, ((a << n) >> n) == zero && !SignFlag((a << n) >> n), ops);
            PROP_CHECK(p, (a >> 0) == zero, ops);
        }
        if (n == 0)
            p.Count("shift0");
    }
    p.Finish({"a-non-negative", "a-negative", "shift0"});
}

BOOST_AUTO_TEST_CASE(ordering_consistency)
{
    Property p("ordering_consistency");
    const CBigNum zero(0);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum a = p.RandomValue();
        CBigNum b;
        switch (p.Rng().randrange(4)) {
        case 0: b = a; p.Count("equal"); break;
        case 1: b = a + CBigNum(p.Rng().randbool() ? 1 : -1); break;
        default: b = p.RandomValue(); break;
        }
        const CBigNum c = p.RandomNonZero();
        const std::string ops = "a=" + Hx(a) + " b=" + Hx(b) + " c=" + Hx(c);
        const bool lt = a < b, eq = a == b, gt = a > b;
        PROP_CHECK(p, (int)lt + (int)eq + (int)gt == 1, ops);
        PROP_CHECK(p, (a <= b) == (lt || eq) && (a >= b) == (gt || eq) && (a != b) == !eq, ops);
        PROP_CHECK(p, (b > a) == lt && (b < a) == gt && (b == a) == eq, ops);
        PROP_CHECK(p, lt == (a - b < zero) && lt == (b - a > zero) && eq == (a - b == zero), ops);
        PROP_CHECK(p, lt == (a + c < b + c) && eq == (a + c == b + c), ops);
        if (c > zero)
            PROP_CHECK(p, lt == (a * c < b * c) && eq == (a * c == b * c), ops);
        else
            PROP_CHECK(p, lt == (a * c > b * c) && eq == (a * c == b * c), ops);
        // std::min / std::max as in pow.cpp
        const CBigNum& mn = std::min(a, b);
        const CBigNum& mx = std::max(a, b);
        PROP_CHECK(p, &mn == (lt || eq ? &a : &b) && &mx == (lt ? &b : &a) && mn <= mx, ops);
        // Transitivity over all orders of (a, b, c)
        const CBigNum* v[3] = {&a, &b, &c};
        for (int x = 0; x < 3; ++x) {
            for (int y = 0; y < 3; ++y) {
                for (int z = 0; z < 3; ++z) {
                    if (x == y || y == z || x == z)
                        continue;
                    if (*v[x] < *v[y] && *v[y] < *v[z])
                        PROP_CHECK(p, *v[x] < *v[z], ops);
                    if (*v[x] <= *v[y] && *v[y] <= *v[z])
                        PROP_CHECK(p, *v[x] <= *v[z], ops);
                }
            }
        }
    }
    p.Finish({"equal", "negative"});
}

BOOST_AUTO_TEST_CASE(no_negative_zero_from_ordinary_inputs)
{
    Property p("no_negative_zero_from_ordinary_inputs");
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum a = p.RandomValue();
        CBigNum b = p.RandomNonZero();
        // Make zero results likely: b == a, b == -a, |b| > |a|
        switch (p.Rng().randrange(4)) {
        case 0: if (a != CBigNum(0)) b = a; break;
        case 1: if (a != CBigNum(0)) b = CBigNum(0) - a; break;
        default: break;
        }
        const unsigned int n = p.RandomShift();
        const std::string ops = "a=" + Hx(a) + " b=" + Hx(b) + strprintf(" n=%u", n);
        const CBigNum results[] = {a + b, a - b, b - a, a * b, a / b, (!a ? b / b : b / a),
                                   a % b, a << n, a >> n, -a, a - a, a + (-a), a * CBigNum(0),
                                   CBigNum(0) * a, Compact(a.GetCompact())};
        for (const CBigNum& r : results)
            PROP_CHECK(p, !IsNegativeZero(r), ops << " r=" << Hx(r));
        if (!(a + b) || !(a - b) || !(a / b))
            p.Count("zero-result");
    }
    p.Finish({"zero-result", "negative"});
}

BOOST_AUTO_TEST_CASE(compact_roundtrip_values)
{
    Property p("compact_roundtrip_values");
    const CBigNum zero(0);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum x = p.RandomValue(), b = p.RandomValue();
        const std::string ops = "x=" + Hx(x) + " b=" + Hx(b);
        const unsigned int n = MpiSize(x);
        BOOST_REQUIRE(n <= 255); // generator values are below 2^1100
        const uint32_t c = x.GetCompact();
        PROP_CHECK(p, (c >> 24) == n, ops << strprintf(" c=%08x n=%u", c, n));
        PROP_CHECK(p, ((c & 0x00800000) != 0) == (x < zero), ops << strprintf(" c=%08x", c));
        // The mantissa is the top three MPI bytes of |x|
        const CBigNum unit = n > 3 ? Pow2(8 * (n - 3)) : CBigNum(1);
        const CBigNum mantissa = n > 3 ? Abs(x) / unit : Abs(x) * Pow2(8 * (3 - n));
        PROP_CHECK(p, CBigNum((int64_t)(c & 0x007fffff)) == mantissa, ops << strprintf(" c=%08x", c));
        // SetCompact(GetCompact(x)) is x truncated toward zero to three bytes
        const CBigNum y = Compact(c);
        const CBigNum mag = n > 3 ? (Abs(x) / unit) * unit : Abs(x);
        const CBigNum expected = x < zero ? zero - mag : mag;
        PROP_CHECK(p, y == expected, ops << " y=" << Hx(y) << strprintf(" c=%08x", c));
        if (n <= 3) {
            p.Count("exact");
            PROP_CHECK(p, y == x, ops);
        } else if (y != x) {
            p.Count("truncated");
        }
        PROP_CHECK(p, y.GetCompact() == c, ops << strprintf(" c=%08x", c));
        // Truncation is monotonic
        const CBigNum yb = Compact(b.GetCompact());
        if (x <= b)
            PROP_CHECK(p, y <= yb, ops << " yb=" << Hx(yb));

        // pinned: from 256 MPI bytes (|w| >= 2^2039) the exponent byte wraps
        // (n mod 256) while the mantissa is still the top three bytes; the
        // compact then decodes to a different, small value or a negative zero
        if (i % 10 == 0) {
            p.Count("wrap");
            const CBigNum w = p.RandomBits(p.RandomInRange(2040, 2400));
            const unsigned int nw = MpiSize(w);
            const uint32_t cw = w.GetCompact();
            const std::string opsw = "w=" + Hx(w) + strprintf(" cw=%08x nw=%u", cw, nw);
            PROP_CHECK(p, nw >= 256 && (cw >> 24) == (nw & 0xff), opsw);
            PROP_CHECK(p, ((cw & 0x00800000) != 0) == (w < zero), opsw);
            PROP_CHECK(p, CBigNum((int64_t)(cw & 0x007fffff)) == Abs(w) / Pow2(8 * (nw - 3)), opsw);
            bool fSign;
            const CBigNum decoded = DecodeCompact(cw, fSign);
            const CBigNum yw = Compact(cw);
            if (fSign && !decoded) {
                p.Count("wrap-negative-zero");
                PROP_CHECK(p, IsNegativeZero(yw), opsw);
            } else {
                PROP_CHECK(p, yw == decoded && !IsNegativeZero(yw), opsw << " yw=" << Hx(yw));
            }
            PROP_CHECK(p, yw != w, opsw);
        }
    }
    p.Finish({"exact", "truncated", "wrap", "negative"});
}

BOOST_AUTO_TEST_CASE(compact_roundtrip_encodings)
{
    Property p("compact_roundtrip_encodings");
    static const uint32_t mantissas[] = {0x000000, 0x800000, 0x000001, 0x800001, 0x7fffff, 0xffffff,
                                         0x008000, 0x808000, 0x0000ff, 0x8000ff, 0x00ffff, 0x80ffff};
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        FastRandomContext& rng = p.Rng();
        uint32_t nExp;
        switch (rng.randrange(4)) {
        case 0: nExp = (uint32_t)rng.randrange(5); break;
        case 1: nExp = 0x18 + (uint32_t)rng.randrange(10); break;
        default: nExp = (uint32_t)rng.randrange(256); break;
        }
        const uint32_t nMantissa = rng.randrange(3) == 0 ? mantissas[rng.randrange(sizeof(mantissas) / sizeof(mantissas[0]))]
                                                         : (uint32_t)rng.randbits(24);
        const uint32_t c = (nExp << 24) | nMantissa;
        const std::string ops = strprintf("c=%08x", c);
        bool fSign;
        const CBigNum expected = DecodeCompact(c, fSign);
        const CBigNum v = Compact(c);
        if (fSign && !expected) {
            // pinned: negative zero (P0-11); GetCompact is not called (UB)
            p.Count("negative-zero");
            PROP_CHECK(p, IsNegativeZero(v), ops);
            PROP_CHECK(p, v < CBigNum(0) && v > CBigNum(-1) && v != CBigNum(0) && !v, ops);
            PROP_CHECK(p, v.ToString() == "0", ops);
            continue;
        }
        if (fSign)
            p.Count("decoded-negative");
        if (!expected)
            p.Count("decoded-zero");
        PROP_CHECK(p, v == expected && !IsNegativeZero(v), ops << " v=" << Hx(v) << " expected=" << Hx(expected));
        // The canonical encoding round-trips exactly
        const uint32_t c2 = v.GetCompact();
        PROP_CHECK(p, Compact(c2) == v, ops << strprintf(" c2=%08x", c2));
        PROP_CHECK(p, Compact(c2).GetCompact() == c2, ops << strprintf(" c2=%08x", c2));
        PROP_CHECK(p, (c2 >> 24) == MpiSize(v), ops << strprintf(" c2=%08x", c2));
        if (c2 == c)
            p.Count("canonical");
    }
    p.Finish({"negative-zero", "decoded-negative", "decoded-zero", "canonical"});
}

BOOST_AUTO_TEST_CASE(uint_getters)
{
    Property p("uint_getters");
    const CBigNum two256 = Pow2(256), two64 = Pow2(64);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum x = p.RandomValue();
        const std::string ops = "x=" + Hx(x);
        // pinned (P0-10): the getters return |x| mod 2^256 and |x| mod 2^64
        const uint256 u = x.getuint256();
        PROP_CHECK(p, CBigNum(u) == Abs(x) % two256, ops);
        CBigNum xc = x; // getuint64 is not const
        PROP_CHECK(p, CBigNum(xc.getuint64()) == Abs(x) % two64, ops);
        if (x >= CBigNum(0) && x < two256) {
            p.Count("uint256-range");
            CBigNum s(-9);
            s.setuint256(u);
            PROP_CHECK(p, s == x && CBigNum(u) == x, ops);
        }
        // Integer constructors agree with SetHex
        const int64_t n = p.RandomInt64();
        const uint64_t nAbs = n < 0 ? (uint64_t)0 - (uint64_t)n : (uint64_t)n;
        const std::string hex = strprintf("%s%x", n < 0 ? "-" : "", nAbs);
        CBigNum bn(n);
        PROP_CHECK(p, bn == Hex(hex) && bn.getuint64() == nAbs, strprintf("n=%d", n));
        const int32_t n32 = (int32_t)p.Rng().rand32();
        PROP_CHECK(p, CBigNum(n32) == CBigNum((int64_t)n32), strprintf("n32=%d", n32));
    }
    p.Finish({"uint256-range", "bits257-520", "negative"});
}

BOOST_AUTO_TEST_CASE(arith_uint256_agreement)
{
    // For 0 <= a, b < 2^256, the range arith_uint256 (the Phase 4
    // replacement) covers, CBigNum agrees with it (products and left shifts
    // mod 2^256).
    Property p("arith_uint256_agreement");
    const CBigNum two256 = Pow2(256);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const CBigNum a = Abs(p.RandomValue()) % two256;
        const CBigNum b = p.Rng().randrange(8) == 0 ? a : Abs(p.RandomValue()) % two256;
        const arith_uint256 A = UintToArith256(a.getuint256()), B = UintToArith256(b.getuint256());
        const unsigned int n = (unsigned int)p.Rng().randrange(256);
        const std::string ops = "a=" + Hx(a) + " b=" + Hx(b) + strprintf(" n=%u", n);
        PROP_CHECK(p, (a < b) == (A < B) && (a == b) == (A == B) && (a > b) == (A > B), ops);
        PROP_CHECK(p, (a + b).getuint256() == ArithToUint256(A + B), ops);
        if (a >= b)
            PROP_CHECK(p, (a - b).getuint256() == ArithToUint256(A - B), ops);
        PROP_CHECK(p, (a * b).getuint256() == ArithToUint256(A * B), ops);
        if (b != CBigNum(0))
            PROP_CHECK(p, (a / b).getuint256() == ArithToUint256(A / B), ops);
        PROP_CHECK(p, (a << n).getuint256() == ArithToUint256(A << n), ops);
        PROP_CHECK(p, (a >> n).getuint256() == ArithToUint256(A >> n), ops);
        PROP_CHECK(p, a.GetCompact() == A.GetCompact(), ops);
        if (a + b >= two256)
            p.Count("sum-overflow");
    }
    p.Finish({"sum-overflow"});
}

BOOST_AUTO_TEST_CASE(negative_zero_operands)
{
    // pinned: results with a negative zero operand nz (from SetCompact,
    // reachable from block headers). Explained from OpenSSL 1.0.1k:
    // BN_add/BN_sub take the result sign from the operand signs, so
    // nz + nz and nz - 0 keep the sign; BN_lshift copies the sign; BN_mul
    // and the BN_div quotient are ordinary zeros; BN_div copies nz into the
    // remainder and BN_nnmod then adds |x|; BN_set_negative never makes a
    // zero negative (unary minus); operator>> returns an ordinary 0.
    Property p("negative_zero_operands");
    const CBigNum zero(0);
    for (int i = 0; i < p.Iterations(); ++i) {
        p.SetIteration(i);
        const uint32_t c = ((uint32_t)p.RandomInRange(1, 255) << 24) | 0x00800000;
        const CBigNum nz = Compact(c);
        const CBigNum x = p.RandomValue();
        const unsigned int n = p.RandomShift();
        const std::string ops = strprintf("nz=SetCompact(%08x) n=%u x=", c, n) + Hx(x);
        PROP_CHECK(p, IsNegativeZero(nz) && IsNegativeZero(CBigNum(nz)), ops);
        // Comparisons: nz sorts between -1 and 0
        PROP_CHECK(p, nz < zero && nz <= zero && nz != zero && !(nz == zero) && nz == Compact(c), ops);
        PROP_CHECK(p, (x < nz) == (x < zero) && (x > nz) == (x >= zero) && !(x == nz), ops);
        PROP_CHECK(p, nz.ToString() == "0" && nz.GetHex() == "0", ops);
        // Addition and subtraction with an ordinary x
        PROP_CHECK(p, nz + x == x && x + nz == x, ops);
        PROP_CHECK(p, x - nz == x, ops);
        if (x != zero) {
            PROP_CHECK(p, nz - x == -x, ops);
        } else {
            p.Count("x-zero");
            PROP_CHECK(p, IsNegativeZero(nz - x), ops); // -0 - 0 stays -0
        }
        PROP_CHECK(p, IsNegativeZero(nz + nz), ops);
        PROP_CHECK(p, nz - nz == zero && !SignFlag(nz - nz), ops);
        // Products and quotients are ordinary zeros
        PROP_CHECK(p, nz * x == zero && x * nz == zero && !SignFlag(nz * x) && !SignFlag(x * nz), ops);
        PROP_CHECK(p, nz * nz == zero, ops);
        if (x != zero) {
            PROP_CHECK(p, nz / x == zero && !SignFlag(nz / x), ops);
            // pinned: nz % x == |x|, outside [0, |x|)
            PROP_CHECK(p, nz % x == Abs(x), ops);
        }
        PROP_CHECK(p, ThrowsBignumError([&] { (void)(x / nz); }), ops);
        PROP_CHECK(p, ThrowsBignumError([&] { (void)(x % nz); }), ops);
        // Shifts and unary minus
        PROP_CHECK(p, IsNegativeZero(nz << n), ops);
        PROP_CHECK(p, (nz >> n) == zero && !SignFlag(nz >> n), ops);
        PROP_CHECK(p, -nz == zero && !SignFlag(-nz), ops);
    }
    p.Finish({"x-zero"});
}

BOOST_AUTO_TEST_SUITE_END()
