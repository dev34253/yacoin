// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Reader for the per-block consensus value dump (task P0-08).

#include "test/consensus_dump_reader.h"

#include "tinyformat.h"

#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace consensus_dump {
namespace {

[[noreturn]] void Fail(const std::string& name, int nLine, const std::string& why)
{
    throw std::runtime_error(strprintf("%s:%d: %s", name, nLine, why));
}

bool IsLowerHex(const std::string& s)
{
    if (s.empty()) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

/** Unsigned decimal without sign or leading zeros (except "0"). */
bool ParseDec(const std::string& s, uint64_t nMax, uint64_t& nOut)
{
    if (s.empty() || (s.size() > 1 && s[0] == '0')) return false;
    uint64_t n = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        const uint64_t d = c - '0';
        if (n > (nMax - d) / 10) return false;
        n = n * 10 + d;
    }
    nOut = n;
    return true;
}

/** Signed decimal: optional '-', no "-0". */
bool ParseSignedDec(const std::string& s, int64_t nMin, int64_t nMax, int64_t& nOut)
{
    if (!s.empty() && s[0] == '-') {
        uint64_t n;
        // |nMin| as unsigned without overflow
        const uint64_t nLimit = (uint64_t)(-(nMin + 1)) + 1;
        if (!ParseDec(s.substr(1), nLimit, n) || n == 0) return false;
        nOut = (n == nLimit) ? nMin : -(int64_t)n;
        return true;
    }
    uint64_t n;
    if (!ParseDec(s, (uint64_t)nMax, n)) return false;
    nOut = (int64_t)n;
    return true;
}

/** "0x" followed by exactly nDigits lowercase hex digits. */
bool ParseHexFixed(const std::string& s, size_t nDigits, uint64_t& nOut)
{
    if (s.size() != nDigits + 2 || s[0] != '0' || s[1] != 'x' || !IsLowerHex(s.substr(2))) return false;
    nOut = std::stoull(s.substr(2), nullptr, 16);
    return true;
}

/** "0x" + 1..64 lowercase hex digits without leading zeros ("0x0" for 0). */
bool ParseBigHex(const std::string& s, arith_uint256& nOut)
{
    if (s.size() < 3 || s.size() > 66 || s[0] != '0' || s[1] != 'x') return false;
    const std::string digits = s.substr(2);
    if (!IsLowerHex(digits) || (digits.size() > 1 && digits[0] == '0')) return false;
    nOut.SetHex(digits);
    return true;
}

bool ParseHash(const std::string& s, uint256& out)
{
    if (s.size() != 64 || !IsLowerHex(s)) return false;
    out = uint256S(s);
    return true;
}

bool ParseOutPoint(const std::string& s, COutPoint& out)
{
    const std::string::size_type colon = s.find(':');
    uint256 hash;
    uint64_t n;
    if (colon == std::string::npos || !ParseHash(s.substr(0, colon), hash) ||
        !ParseDec(s.substr(colon + 1), std::numeric_limits<uint32_t>::max(), n)) {
        return false;
    }
    out = COutPoint(hash, (uint32_t)n);
    return true;
}

std::vector<std::string> Split(const std::string& line, char sep)
{
    std::vector<std::string> fields;
    std::string::size_type start = 0;
    while (true) {
        const std::string::size_type pos = line.find(sep, start);
        if (pos == std::string::npos) {
            fields.push_back(line.substr(start));
            return fields;
        }
        fields.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
}

/** key=value tokens of a comment line ("# a=1 b=2"). */
std::map<std::string, std::string> ParseMeta(const std::string& line)
{
    std::map<std::string, std::string> meta;
    for (const std::string& token : Split(line.substr(1), ' ')) {
        const std::string::size_type eq = token.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        meta[token.substr(0, eq)] = token.substr(eq + 1);
    }
    return meta;
}

class RowParser
{
public:
    RowParser(const std::string& nameIn, int nLineIn, const std::map<std::string, size_t>& columnsIn,
              const std::vector<std::string>& fieldsIn)
        : name(nameIn), nLine(nLineIn), columns(columnsIn), fields(fieldsIn) {}

    const std::string& Field(const std::string& col) const { return fields[columns.at(col)]; }
    bool Empty(const std::string& col) const { return Field(col).empty(); }

    [[noreturn]] void Bad(const std::string& col, const char* what) const
    {
        Fail(name, nLine, strprintf("bad %s in %s: '%s'", what, col, Field(col)));
    }

    uint64_t Unsigned(const std::string& col, uint64_t nMax) const
    {
        uint64_t n;
        if (!ParseDec(Field(col), nMax, n)) Bad(col, "unsigned number");
        return n;
    }
    int64_t Signed(const std::string& col, int64_t nMin = std::numeric_limits<int64_t>::min(),
                   int64_t nMax = std::numeric_limits<int64_t>::max()) const
    {
        int64_t n;
        if (!ParseSignedDec(Field(col), nMin, nMax, n)) Bad(col, "signed number");
        return n;
    }
    uint64_t HexFixed(const std::string& col, size_t nDigits) const
    {
        uint64_t n;
        if (!ParseHexFixed(Field(col), nDigits, n)) Bad(col, "fixed-width hex number");
        return n;
    }
    arith_uint256 BigHex(const std::string& col) const
    {
        arith_uint256 n;
        if (!ParseBigHex(Field(col), n)) Bad(col, "hex number");
        return n;
    }
    uint256 Hash(const std::string& col) const
    {
        uint256 h;
        if (!ParseHash(Field(col), h)) Bad(col, "hash");
        return h;
    }
    COutPoint OutPoint(const std::string& col) const
    {
        COutPoint o;
        if (!ParseOutPoint(Field(col), o)) Bad(col, "outpoint");
        return o;
    }
    bool Bool(const std::string& col) const
    {
        if (Field(col) == "0") return false;
        if (Field(col) == "1") return true;
        Bad(col, "boolean");
    }

    ConsensusDumpRow Parse() const
    {
        static const int64_t I32MIN = std::numeric_limits<int32_t>::min();
        static const int64_t I32MAX = std::numeric_limits<int32_t>::max();
        static const uint64_t U32MAX = std::numeric_limits<uint32_t>::max();
        static const uint64_t U64MAX = std::numeric_limits<uint64_t>::max();
        ConsensusDumpRow r;
        r.nHeight = (int32_t)Unsigned("height", I32MAX);
        r.hash = Hash("hash");
        if (!Empty("prev_hash")) r.hashPrev = Hash("prev_hash");
        r.nTime = Signed("time");
        r.nBits = (uint32_t)HexFixed("bits", 8);
        r.nVersion = (int32_t)Signed("version", I32MIN, I32MAX);
        r.nNonce = (uint32_t)Unsigned("nonce", U32MAX);
        r.hashMerkleRoot = Hash("merkle_root");
        r.nFlags = (uint32_t)Unsigned("flags", U32MAX);
        r.nStakeModifier = HexFixed("stake_modifier", 16);
        if (!Empty("hash_proof_of_stake")) r.hashProofOfStake = Hash("hash_proof_of_stake");
        if (!Empty("prevout_stake")) r.prevoutStake = OutPoint("prevout_stake");
        if (!Empty("stake_time")) r.nStakeTime = (uint32_t)Unsigned("stake_time", U32MAX);

        r.hashHeaderSha256 = Hash("header_sha256");
        r.nFactor = (int)Unsigned("nfactor", 255);
        r.fProofOfStake = Bool("is_pos");
        r.nMedianTimePast = Signed("median_time_past");
        if (!Empty("required_bits")) r.nRequiredBits = (uint32_t)HexFixed("required_bits", 8);
        if (!Empty("min_bits_since_fork")) r.nMinBitsSinceFork = (uint32_t)HexFixed("min_bits_since_fork", 8);

        r.blockTrust = BigHex("block_trust");
        r.chainTrust = BigHex("chain_trust");
        r.nStakeModifierChecksum = (uint32_t)HexFixed("stake_modifier_checksum", 8);

        // The kernel input columns are all present or all empty; the stake
        // modifier, its height, the hash and the target may be empty in a
        // row with a kernel (not found / not hashed / failed), but not
        // without one.
        static const char* const KERNEL[] = {
            "kernel_prevout", "kernel_block_from_hash", "kernel_block_from_time", "kernel_tx_prev_time",
            "kernel_tx_prev_offset", "kernel_value_in", "kernel_tx_time", "kernel_ok"};
        static const char* const KERNEL_OPTIONAL[] = {
            "kernel_stake_modifier", "kernel_modifier_height", "kernel_hash", "kernel_target"};
        int nKernelFields = 0;
        for (const char* col : KERNEL) nKernelFields += Empty(col) ? 0 : 1;
        if (nKernelFields != 0 && nKernelFields != (int)(sizeof(KERNEL) / sizeof(KERNEL[0]))) {
            Fail(name, nLine, "kernel columns are only partly filled");
        }
        if (nKernelFields == 0) {
            for (const char* col : KERNEL_OPTIONAL) {
                if (!Empty(col)) Fail(name, nLine, std::string(col) + " without kernel");
            }
        }
        if (nKernelFields != 0) {
            r.fHasKernel = true;
            r.kernelPrevout = OutPoint("kernel_prevout");
            r.kernelBlockFromHash = Hash("kernel_block_from_hash");
            r.nKernelBlockFromTime = Signed("kernel_block_from_time");
            r.nKernelTxPrevTime = Signed("kernel_tx_prev_time");
            r.nKernelTxPrevOffset = (uint32_t)Unsigned("kernel_tx_prev_offset", U32MAX);
            r.nKernelValueIn = Signed("kernel_value_in");
            r.nKernelTxTime = Signed("kernel_tx_time");
            if (!Empty("kernel_stake_modifier")) r.nKernelStakeModifier = HexFixed("kernel_stake_modifier", 16);
            if (!Empty("kernel_modifier_height")) r.nKernelModifierHeight = (int32_t)Unsigned("kernel_modifier_height", I32MAX);
            if (!Empty("kernel_hash")) r.kernelHash = Hash("kernel_hash");
            if (!Empty("kernel_target")) r.kernelTarget = BigHex("kernel_target");
            r.fKernelOk = Bool("kernel_ok");
        }

        r.nTxCount = (uint32_t)Unsigned("tx_count", U32MAX);
        r.nBlockSize = Unsigned("block_size", U64MAX);
        r.nSigOps = (uint32_t)Unsigned("sigops", U32MAX);
        if (!Empty("max_sigops")) r.nMaxSigOps = Unsigned("max_sigops", U64MAX);
        r.nCoinbaseValue = Signed("coinbase_value");
        if (!Empty("fees")) r.nFees = Signed("fees");
        if (!Empty("pow_reward")) r.nPowReward = Signed("pow_reward");
        if (!Empty("coinstake_value_in")) r.nCoinstakeValueIn = Signed("coinstake_value_in");
        if (!Empty("coinstake_value_out")) r.nCoinstakeValueOut = Signed("coinstake_value_out");
        if (!Empty("coin_age")) r.nCoinAge = Unsigned("coin_age", U64MAX);
        if (!Empty("pos_reward")) r.nPosReward = Signed("pos_reward");
        if (!Empty("pos_reward_limit")) r.nPosRewardLimit = Signed("pos_reward_limit");
        if (!Empty("max_block_size")) r.nMaxBlockSize = Unsigned("max_block_size", U64MAX);
        r.nMint = Signed("mint");
        r.nMoneySupply = Signed("money_supply");
        return r;
    }

private:
    const std::string& name;
    const int nLine;
    const std::map<std::string, size_t>& columns;
    const std::vector<std::string>& fields;
};

} // namespace

ConsensusDump ReadConsensusDump(std::istream& in, const std::string& name)
{
    ConsensusDump dump;
    std::map<std::string, size_t> columns;
    size_t nColumns = 0;
    bool fHaveFormat = false;
    bool fHaveHeader = false;
    bool fHaveTrailer = false;
    int nLine = 0;
    std::string line;
    while (std::getline(in, line)) {
        ++nLine;
        if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
        if (line.empty()) continue;
        if (fHaveTrailer) Fail(name, nLine, "content after the end trailer");

        if (!fHaveFormat) {
            const std::map<std::string, std::string> meta = ParseMeta(line);
            if (line[0] != '#' || !meta.count("format") || meta.at("format") != CONSENSUS_DUMP_FORMAT) {
                Fail(name, nLine, std::string("first line must be '# format=") + CONSENSUS_DUMP_FORMAT + " version=...'");
            }
            if (!meta.count("version") || meta.at("version") != std::to_string(CONSENSUS_DUMP_VERSION)) {
                Fail(name, nLine, "unsupported format version '" + (meta.count("version") ? meta.at("version") : std::string()) + "'");
            }
            dump.meta.insert(meta.begin(), meta.end());
            fHaveFormat = true;
            continue;
        }

        if (line[0] == '#') {
            if (!fHaveHeader) {
                const std::map<std::string, std::string> meta = ParseMeta(line);
                dump.meta.insert(meta.begin(), meta.end());
                continue;
            }
            if (line.compare(0, 6, "# end ") == 0) {
                const std::map<std::string, std::string> meta = ParseMeta(line);
                uint64_t nRows;
                if (!meta.count("rows") || !ParseDec(meta.at("rows"), std::numeric_limits<uint64_t>::max(), nRows)) {
                    Fail(name, nLine, "bad end trailer");
                }
                if (nRows != dump.rows.size()) {
                    Fail(name, nLine, strprintf("end trailer says %u rows, read %u", nRows, dump.rows.size()));
                }
                if (!dump.rows.empty() && (!meta.count("end_hash") || meta.at("end_hash") != dump.rows.back().hash.GetHex())) {
                    Fail(name, nLine, "end trailer hash does not match the last row");
                }
                fHaveTrailer = true;
            }
            continue; // other comments after the header are ignored
        }

        const std::vector<std::string> fields = Split(line, ',');
        if (!fHaveHeader) {
            for (size_t i = 0; i < fields.size(); ++i) {
                if (fields[i].empty()) Fail(name, nLine, "empty column name");
                if (!columns.emplace(fields[i], i).second) Fail(name, nLine, "duplicate column " + fields[i]);
            }
            for (const std::string& col : ConsensusDumpColumns()) {
                if (!columns.count(col)) Fail(name, nLine, "missing column " + col);
            }
            nColumns = fields.size();
            fHaveHeader = true;
            continue;
        }
        if (fields.size() != nColumns) {
            Fail(name, nLine, strprintf("%u fields, header has %u", fields.size(), nColumns));
        }
        ConsensusDumpRow row = RowParser(name, nLine, columns, fields).Parse();
        if (!dump.rows.empty() && row.nHeight <= dump.rows.back().nHeight) {
            Fail(name, nLine, strprintf("height %d does not follow %d", row.nHeight, dump.rows.back().nHeight));
        }
        dump.rows.push_back(row);
    }
    if (in.bad()) Fail(name, nLine, "read error");
    if (!fHaveFormat) Fail(name, nLine, "empty input");
    if (!fHaveHeader) Fail(name, nLine, "no header line");
    dump.fComplete = fHaveTrailer;
    return dump;
}

ConsensusDump ReadConsensusDumpFile(const std::string& path)
{
    std::ifstream file(path.c_str());
    if (!file) throw std::runtime_error("ReadConsensusDumpFile: cannot open " + path);
    return ReadConsensusDump(file, path);
}

} // namespace consensus_dump
