// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Tests of the per-block consensus value dump format, its reader and the
// N-factor column (task P0-08). The dump itself (RPC dumpconsensusvalues)
// is tested in test/functional/rpc_dumpconsensusvalues.py.

#include "consensusdump.h"
#include "test/consensus_dump_reader.h"
#include "test/consensus_harness.h"

#include "data/consensus_dump_mainnet_early.csv.h"
#include "data/consensus_dump_mainnet_fork.csv.h"
#include "data/consensus_dump_mainnet_pos.csv.h"

#include "chain.h"
#include "chainparams.h"
#include "pow.h"
#include "primitives/block.h"
#include "scrypt.h"
#include "util.h"
#include "validation.h"

#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

#include <boost/test/unit_test.hpp>

using consensus_dump::ConsensusDump;
using consensus_dump::ReadConsensusDump;

namespace {

const char* const HASH_A = "00000a1b2c3d4e5f60718293a4b5c6d7e8f9000102030405060708090a0b0c0d";
const char* const HASH_B = "1111111111111111111111111111111111111111111111111111111111111111";
const char* const HASH_C = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const char* const HASH_D = "0000000000000000000000000000000000000000000000000000000000000001";

const char* const FORMAT_LINE = "# format=yacoin-consensus-dump version=1 doc=src/test/README.md";

/** A proof-of-work row like the genesis block: optional fields empty. */
ConsensusDumpRow PowRow(int32_t nHeight)
{
    ConsensusDumpRow r;
    r.nHeight = nHeight;
    r.hash = uint256S(HASH_A);
    r.nTime = 1367991200;
    r.nBits = 0x1e0fffff;
    r.nVersion = 1;
    r.nNonce = 127357;
    r.hashMerkleRoot = uint256S(HASH_B);
    r.nFlags = CBlockIndex::BLOCK_STAKE_MODIFIER;
    r.nStakeModifier = 0;
    r.hashHeaderSha256 = uint256S(HASH_C);
    r.nFactor = 4;
    r.nMedianTimePast = 1367991200;
    r.blockTrust = 1;
    r.chainTrust = 1;
    r.nStakeModifierChecksum = 0x0e00670b;
    r.nTxCount = 1;
    r.nBlockSize = 205;
    r.nSigOps = 1;
    r.nMint = 0;
    r.nMoneySupply = 0;
    return r;
}

/** A proof-of-stake row with every optional field set. */
ConsensusDumpRow PosRow(int32_t nHeight)
{
    ConsensusDumpRow r = PowRow(nHeight);
    r.hash = uint256S(HASH_C);
    r.hashPrev = uint256S(HASH_A);
    r.nNonce = 0;
    r.nFlags = CBlockIndex::BLOCK_PROOF_OF_STAKE | CBlockIndex::BLOCK_STAKE_ENTROPY;
    r.nStakeModifier = 0x0123456789abcdefULL;
    r.hashProofOfStake = uint256S(HASH_D);
    r.prevoutStake = COutPoint(uint256S(HASH_B), 2);
    r.nStakeTime = 1400000000;
    r.fProofOfStake = true;
    r.nMedianTimePast = 1399999000;
    r.nRequiredBits = 0x1d7fffff;
    r.nMinBitsSinceFork = 0x1c00ffff;
    r.blockTrust = arith_uint256("1000000000000000000000000000000000000001");
    r.chainTrust = arith_uint256("abcdef0123456789");
    r.fHasKernel = true;
    r.kernelPrevout = COutPoint(uint256S(HASH_B), 1);
    r.kernelBlockFromHash = uint256S(HASH_A);
    r.nKernelBlockFromTime = 1390000000;
    r.nKernelTxPrevTime = 1390000001;
    r.nKernelTxPrevOffset = 81;
    r.nKernelValueIn = 123456789;
    r.nKernelTxTime = 1400000000;
    r.nKernelStakeModifier = 0xfedcba9876543210ULL;
    r.nKernelModifierHeight = 12345;
    r.kernelHash = uint256S(HASH_D);
    r.kernelTarget = arith_uint256("ffff");
    r.fKernelOk = true;
    r.nTxCount = 2;
    r.nSigOps = 3;
    r.nMaxSigOps = 20000;
    r.nCoinbaseValue = 0;
    r.nFees = 10000;
    r.nCoinstakeValueIn = 123456789;
    r.nCoinstakeValueOut = 124456789;
    r.nCoinAge = 4242;
    r.nPosReward = 1000000;
    r.nPosRewardLimit = 1010000;
    r.nMaxBlockSize = 1000000;
    r.nMint = 1000000;
    r.nMoneySupply = 99000000000000LL;
    return r;
}

void CheckRowsEqual(const ConsensusDumpRow& a, const ConsensusDumpRow& b)
{
    BOOST_CHECK_EQUAL(a.nHeight, b.nHeight);
    BOOST_CHECK(a.hash == b.hash);
    BOOST_CHECK(a.hashPrev == b.hashPrev);
    BOOST_CHECK_EQUAL(a.nTime, b.nTime);
    BOOST_CHECK_EQUAL(a.nBits, b.nBits);
    BOOST_CHECK_EQUAL(a.nVersion, b.nVersion);
    BOOST_CHECK_EQUAL(a.nNonce, b.nNonce);
    BOOST_CHECK(a.hashMerkleRoot == b.hashMerkleRoot);
    BOOST_CHECK_EQUAL(a.nFlags, b.nFlags);
    BOOST_CHECK_EQUAL(a.nStakeModifier, b.nStakeModifier);
    BOOST_CHECK(a.hashProofOfStake == b.hashProofOfStake);
    BOOST_CHECK(a.prevoutStake == b.prevoutStake);
    BOOST_CHECK_EQUAL(a.nStakeTime, b.nStakeTime);
    BOOST_CHECK(a.hashHeaderSha256 == b.hashHeaderSha256);
    BOOST_CHECK_EQUAL(a.nFactor, b.nFactor);
    BOOST_CHECK_EQUAL(a.fProofOfStake, b.fProofOfStake);
    BOOST_CHECK_EQUAL(a.nMedianTimePast, b.nMedianTimePast);
    BOOST_CHECK(a.nRequiredBits == b.nRequiredBits);
    BOOST_CHECK(a.nMinBitsSinceFork == b.nMinBitsSinceFork);
    BOOST_CHECK(a.blockTrust == b.blockTrust);
    BOOST_CHECK(a.chainTrust == b.chainTrust);
    BOOST_CHECK_EQUAL(a.nStakeModifierChecksum, b.nStakeModifierChecksum);
    BOOST_CHECK_EQUAL(a.fHasKernel, b.fHasKernel);
    BOOST_CHECK(a.kernelPrevout == b.kernelPrevout);
    BOOST_CHECK(a.kernelBlockFromHash == b.kernelBlockFromHash);
    BOOST_CHECK_EQUAL(a.nKernelBlockFromTime, b.nKernelBlockFromTime);
    BOOST_CHECK_EQUAL(a.nKernelTxPrevTime, b.nKernelTxPrevTime);
    BOOST_CHECK_EQUAL(a.nKernelTxPrevOffset, b.nKernelTxPrevOffset);
    BOOST_CHECK_EQUAL(a.nKernelValueIn, b.nKernelValueIn);
    BOOST_CHECK_EQUAL(a.nKernelTxTime, b.nKernelTxTime);
    BOOST_CHECK(a.nKernelStakeModifier == b.nKernelStakeModifier);
    BOOST_CHECK(a.nKernelModifierHeight == b.nKernelModifierHeight);
    BOOST_CHECK(a.kernelHash == b.kernelHash);
    BOOST_CHECK(a.kernelTarget == b.kernelTarget);
    BOOST_CHECK_EQUAL(a.fKernelOk, b.fKernelOk);
    BOOST_CHECK_EQUAL(a.nTxCount, b.nTxCount);
    BOOST_CHECK_EQUAL(a.nBlockSize, b.nBlockSize);
    BOOST_CHECK_EQUAL(a.nSigOps, b.nSigOps);
    BOOST_CHECK(a.nMaxSigOps == b.nMaxSigOps);
    BOOST_CHECK_EQUAL(a.nCoinbaseValue, b.nCoinbaseValue);
    BOOST_CHECK(a.nFees == b.nFees);
    BOOST_CHECK(a.nPowReward == b.nPowReward);
    BOOST_CHECK(a.nCoinstakeValueIn == b.nCoinstakeValueIn);
    BOOST_CHECK(a.nCoinstakeValueOut == b.nCoinstakeValueOut);
    BOOST_CHECK(a.nCoinAge == b.nCoinAge);
    BOOST_CHECK(a.nPosReward == b.nPosReward);
    BOOST_CHECK(a.nPosRewardLimit == b.nPosRewardLimit);
    BOOST_CHECK(a.nMaxBlockSize == b.nMaxBlockSize);
    BOOST_CHECK_EQUAL(a.nMint, b.nMint);
    BOOST_CHECK_EQUAL(a.nMoneySupply, b.nMoneySupply);
}

std::string DumpText(const std::vector<ConsensusDumpRow>& rows, bool fTrailer)
{
    std::string text = std::string(FORMAT_LINE) + "\n# client=test chain=main fork_height=1890000\n" +
                       ConsensusDumpHeaderLine() + "\n";
    for (const ConsensusDumpRow& r : rows) text += FormatConsensusDumpRow(r) + "\n";
    if (fTrailer) {
        text += strprintf("# end rows=%u end_hash=%s\n", rows.size(), rows.empty() ? "" : rows.back().hash.GetHex());
    }
    return text;
}

ConsensusDump Read(const std::string& text)
{
    std::istringstream in(text);
    return ReadConsensusDump(in, "test.csv");
}

/** True if reading text throws an error that contains what. */
bool ReadFails(const std::string& text, const std::string& what)
{
    try {
        Read(text);
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        if (msg.find(what) == std::string::npos) {
            BOOST_TEST_MESSAGE("unexpected error: " << msg << " (expected '" << what << "')");
            return false;
        }
        return true;
    }
    BOOST_TEST_MESSAGE("no error, expected '" << what << "'");
    return false;
}

/** Scrypt header hash of a version < 7 header at the given N-factor (the
 *  layout CBlockHeader::CalculateHash uses). */
uint256 OldHeaderHash(const CBlockHeader& h, unsigned char nFactor)
{
    old_block_header data;
    data.version = h.nVersion;
    data.prev_block = h.hashPrevBlock;
    data.merkle_root = h.hashMerkleRoot;
    data.timestamp = (unsigned int)h.nTime;
    data.bits = h.nBits;
    data.nonce = h.nNonce;
    uint256 thash;
    BOOST_REQUIRE(scrypt_hash(CVOIDBEGIN(data), sizeof(data), UINTBEGIN(thash), nFactor));
    return thash;
}

uint256 NewHeaderHash(const CBlockHeader& h, unsigned char nFactor)
{
    struct block_header data;
    data.version = h.nVersion;
    data.prev_block = h.hashPrevBlock;
    data.merkle_root = h.hashMerkleRoot;
    data.timestamp = h.nTime;
    data.bits = h.nBits;
    data.nonce = h.nNonce;
    uint256 thash;
    BOOST_REQUIRE(scrypt_hash(CVOIDBEGIN(data), sizeof(data), UINTBEGIN(thash), nFactor));
    return thash;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_dump_tests, ConsensusTestingSetup)

BOOST_AUTO_TEST_CASE(columns_and_format)
{
    // The column list is the format: pin it. The first 13 columns are the
    // P0-47 index-chain CSV columns (src/test/README.md).
    BOOST_CHECK_EQUAL(ConsensusDumpHeaderLine(),
        "height,hash,prev_hash,time,bits,version,nonce,merkle_root,flags,stake_modifier,hash_proof_of_stake,"
        "prevout_stake,stake_time,header_sha256,nfactor,is_pos,median_time_past,required_bits,min_bits_since_fork,"
        "block_trust,chain_trust,stake_modifier_checksum,kernel_prevout,kernel_block_from_hash,"
        "kernel_block_from_time,kernel_tx_prev_time,kernel_tx_prev_offset,kernel_value_in,kernel_tx_time,"
        "kernel_stake_modifier,kernel_modifier_height,kernel_hash,kernel_target,kernel_ok,tx_count,block_size,"
        "sigops,max_sigops,coinbase_value,fees,pow_reward,coinstake_value_in,coinstake_value_out,coin_age,"
        "pos_reward,pos_reward_limit,max_block_size,mint,money_supply");
    BOOST_CHECK_EQUAL(ConsensusDumpColumns().size(), 49U);

    // Exact text of a row with empty optional fields and one with all set.
    BOOST_CHECK_EQUAL(FormatConsensusDumpRow(PowRow(0)),
        std::string("0,") + HASH_A + ",,1367991200,0x1e0fffff,1,127357," + HASH_B + ",4,0x0000000000000000,,,," +
        HASH_C + ",4,0,1367991200,,,0x1,0x1,0x0e00670b,,,,,,,,,,,,,1,205,1,,0,,,,,,,,,0,0");
    BOOST_CHECK_EQUAL(FormatConsensusDumpRow(PosRow(7)),
        std::string("7,") + HASH_C + "," + HASH_A + ",1367991200,0x1e0fffff,1,0," + HASH_B + ",3,0x0123456789abcdef," +
        HASH_D + "," + HASH_B + ":2,1400000000," + HASH_C + ",4,1,1399999000,0x1d7fffff,0x1c00ffff," +
        "0x1000000000000000000000000000000000000001,0xabcdef0123456789,0x0e00670b," + HASH_B + ":1," + HASH_A +
        ",1390000000,1390000001,81,123456789,1400000000,0xfedcba9876543210,12345," + HASH_D +
        ",0xffff,1,2,205,3,20000,0,10000,,123456789,124456789,4242,1000000,1010000,1000000,1000000,99000000000000");

    BOOST_CHECK_EQUAL(FormatConsensusDumpBigHex(arith_uint256(0)), "0x0");
    BOOST_CHECK_EQUAL(FormatConsensusDumpBigHex(arith_uint256(0x10)), "0x10");
    BOOST_CHECK_EQUAL(FormatConsensusDumpBigHex(~arith_uint256(0)), "0x" + std::string(64, 'f'));
}

BOOST_AUTO_TEST_CASE(format_round_trip)
{
    std::vector<ConsensusDumpRow> rows;
    rows.push_back(PowRow(0));
    rows.push_back(PosRow(1));
    ConsensusDumpRow failed = PosRow(2);
    failed.kernelTarget = boost::none;
    failed.fKernelOk = false;
    rows.push_back(failed);
    // Kernel that failed before hashing, modifier not found.
    ConsensusDumpRow early = PosRow(3);
    early.kernelTarget = boost::none;
    early.kernelHash = boost::none;
    early.nKernelStakeModifier = boost::none;
    early.nKernelModifierHeight = boost::none;
    early.fKernelOk = false;
    rows.push_back(early);
    // Extremes of every numeric type.
    ConsensusDumpRow ext = PosRow(std::numeric_limits<int32_t>::max());
    ext.nTime = std::numeric_limits<int64_t>::min();
    ext.nBits = 0xffffffff;
    ext.nVersion = std::numeric_limits<int32_t>::min();
    ext.nNonce = 0xffffffff;
    ext.nFlags = 0xffffffff;
    ext.nStakeModifier = std::numeric_limits<uint64_t>::max();
    ext.nStakeTime = 0xffffffff;
    ext.nFactor = 255;
    ext.nMedianTimePast = std::numeric_limits<int64_t>::min();
    ext.nRequiredBits = 0;
    ext.nMinBitsSinceFork = 0xffffffff;
    ext.blockTrust = 0;
    ext.chainTrust = ~arith_uint256(0);
    ext.nStakeModifierChecksum = 0xffffffff;
    ext.kernelPrevout = COutPoint(uint256S(HASH_B), 0xffffffff);
    ext.nKernelBlockFromTime = std::numeric_limits<int64_t>::max();
    ext.nKernelTxPrevOffset = 0xffffffff;
    ext.nKernelValueIn = std::numeric_limits<int64_t>::min();
    ext.kernelTarget = ~arith_uint256(0);
    ext.nKernelStakeModifier = std::numeric_limits<uint64_t>::max();
    ext.nKernelModifierHeight = std::numeric_limits<int32_t>::max();
    ext.nSigOps = 0xffffffff;
    ext.nMaxSigOps = std::numeric_limits<uint64_t>::max();
    ext.nPosRewardLimit = std::numeric_limits<int64_t>::min();
    ext.nBlockSize = std::numeric_limits<uint64_t>::max();
    ext.nCoinbaseValue = std::numeric_limits<int64_t>::min();
    ext.nFees = -1;
    ext.nPowReward = std::numeric_limits<int64_t>::max();
    ext.nCoinAge = std::numeric_limits<uint64_t>::max();
    ext.nMaxBlockSize = 0;
    ext.nMint = std::numeric_limits<int64_t>::min();
    ext.nMoneySupply = std::numeric_limits<int64_t>::max();
    rows.push_back(ext);

    for (bool fTrailer : {false, true}) {
        ConsensusDump dump = Read(DumpText(rows, fTrailer));
        BOOST_CHECK_EQUAL(dump.fComplete, fTrailer);
        BOOST_CHECK_EQUAL(dump.meta.at("format"), "yacoin-consensus-dump");
        BOOST_CHECK_EQUAL(dump.meta.at("version"), "1");
        BOOST_CHECK_EQUAL(dump.meta.at("client"), "test");
        BOOST_CHECK_EQUAL(dump.meta.at("fork_height"), "1890000");
        BOOST_REQUIRE_EQUAL(dump.rows.size(), rows.size());
        for (size_t i = 0; i < rows.size(); ++i) CheckRowsEqual(dump.rows[i], rows[i]);
    }

    // Columns in another order, an unknown extra column, CRLF and blank
    // lines are accepted.
    std::vector<std::string> cols = ConsensusDumpColumns();
    std::string header = "extra";
    for (auto it = cols.rbegin(); it != cols.rend(); ++it) header += "," + *it;
    std::string text = std::string(FORMAT_LINE) + "\r\n\r\n" + header + "\r\n";
    for (const ConsensusDumpRow& r : rows) {
        std::vector<std::string> f;
        std::string line = FormatConsensusDumpRow(r);
        std::string::size_type start = 0, pos;
        while ((pos = line.find(',', start)) != std::string::npos) {
            f.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
        f.push_back(line.substr(start));
        std::string reversed = "x";
        for (auto it = f.rbegin(); it != f.rend(); ++it) reversed += "," + *it;
        text += reversed + "\r\n";
    }
    ConsensusDump dump = Read(text);
    BOOST_REQUIRE_EQUAL(dump.rows.size(), rows.size());
    for (size_t i = 0; i < rows.size(); ++i) CheckRowsEqual(dump.rows[i], rows[i]);
}

BOOST_AUTO_TEST_CASE(index_chain_loader_reads_dump)
{
    // The P0-47 loader reads a dump directly (extra columns are ignored).
    std::vector<ConsensusDumpRow> rows;
    ConsensusDumpRow a = PowRow(500);
    a.hashPrev = uint256S(HASH_B); // not in mapBlockIndex: starts a segment
    ConsensusDumpRow b = PosRow(501);
    b.hashPrev = a.hash;
    rows.push_back(a);
    rows.push_back(b);
    std::istringstream in(DumpText(rows, true));
    CBlockIndex* tip = consensus_harness::LoadIndexChainCsv(in, chain, "dump.csv");
    BOOST_REQUIRE(tip != nullptr);
    BOOST_CHECK_EQUAL(tip->nHeight, 501);
    BOOST_CHECK(tip->GetBlockHash() == b.hash);
    BOOST_CHECK(tip->pprev->GetBlockHash() == a.hash);
    BOOST_CHECK_EQUAL(tip->nTime, b.nTime);
    BOOST_CHECK_EQUAL(tip->nBits, b.nBits);
    BOOST_CHECK_EQUAL(tip->nFlags, b.nFlags);
    BOOST_CHECK_EQUAL(tip->nStakeModifier, b.nStakeModifier);
    BOOST_CHECK(tip->hashProofOfStake == b.hashProofOfStake);
    BOOST_CHECK(tip->prevoutStake == b.prevoutStake);
    BOOST_CHECK_EQUAL(tip->nStakeTime, b.nStakeTime);
    BOOST_CHECK_EQUAL(tip->pprev->nFlags, a.nFlags);
}

BOOST_AUTO_TEST_CASE(reader_errors)
{
    const std::vector<ConsensusDumpRow> rows = {PowRow(0), PosRow(1)};
    const std::string good = DumpText(rows, true);
    BOOST_CHECK_NO_THROW(Read(good));

    auto replace = [](std::string s, const std::string& from, const std::string& to) {
        const std::string::size_type pos = s.find(from);
        BOOST_REQUIRE(pos != std::string::npos);
        return s.replace(pos, from.size(), to);
    };
    const std::string powLine = FormatConsensusDumpRow(PowRow(0));

    BOOST_CHECK(ReadFails("", "test.csv:0: empty input"));
    BOOST_CHECK(ReadFails(ConsensusDumpHeaderLine() + "\n", "test.csv:1: first line must be"));
    BOOST_CHECK(ReadFails(replace(good, "version=1", "version=2"), "test.csv:1: unsupported format version '2'"));
    BOOST_CHECK(ReadFails(std::string(FORMAT_LINE) + "\n", "no header line"));
    BOOST_CHECK(ReadFails(replace(good, ",kernel_ok,", ",kernel_okay,"), "test.csv:3: missing column kernel_ok"));
    BOOST_CHECK(ReadFails(replace(good, ",nfactor,", ",nfactor,nfactor,"), "duplicate column nfactor"));
    BOOST_CHECK(ReadFails(replace(good, powLine, powLine + ","), "test.csv:4: 50 fields, header has 49"));
    BOOST_CHECK(ReadFails(replace(good, ",0x1e0fffff,", ",0x1e0ffff,"), "test.csv:4: bad fixed-width hex number in bits"));
    BOOST_CHECK(ReadFails(replace(good, ",0x1e0fffff,", ",0x1E0FFFFF,"), "bad fixed-width hex number in bits"));
    BOOST_CHECK(ReadFails(replace(good, ",127357,", ",0127357,"), "bad unsigned number in nonce"));
    BOOST_CHECK(ReadFails(replace(good, ",127357,", ",4294967296,"), "bad unsigned number in nonce"));
    BOOST_CHECK(ReadFails(replace(good, ",1367991200,", ",-0,"), "bad signed number in time"));
    BOOST_CHECK(ReadFails(replace(good, ",0x1,0x1,", ",0x01,0x1,"), "bad hex number in block_trust"));
    BOOST_CHECK(ReadFails(replace(good, std::string(",") + HASH_B + ",", ",xyz,"), "bad hash in merkle_root"));
    BOOST_CHECK(ReadFails(replace(good, std::string(HASH_B) + ":2", std::string(HASH_B) + ":-2"), "bad outpoint in prevout_stake"));
    BOOST_CHECK(ReadFails(replace(good, ",0x0e00670b,,", ",0x0e00670b," + std::string(HASH_B) + ":1,"), "kernel columns are only partly filled"));
    BOOST_CHECK(ReadFails(replace(good, ",4,1,1399999000,", ",4,2,1399999000,"), "bad boolean in is_pos"));
    BOOST_CHECK(ReadFails(replace(good, ",0x0e00670b,,,,,,,,,,,,,", ",0x0e00670b,,,,,,,,,," + std::string(HASH_D) + ",,,"),
                          "kernel_hash without kernel"));
    // Heights must ascend; the trailer must match.
    BOOST_CHECK(ReadFails(DumpText({PosRow(1), PowRow(1)}, false), "test.csv:5: height 1 does not follow 1"));
    BOOST_CHECK(ReadFails(replace(good, "# end rows=2", "# end rows=3"), "test.csv:6: end trailer says 3 rows, read 2"));
    BOOST_CHECK(ReadFails(replace(good, std::string("end_hash=") + HASH_C, std::string("end_hash=") + HASH_A), "end trailer hash does not match"));
    BOOST_CHECK(ReadFails(good + powLine + "\n", "test.csv:7: content after the end trailer"));
}

BOOST_AUTO_TEST_CASE(nfactor_table)
{
    // ConsensusDumpNFactor copies the N-factor selection of
    // CBlockHeader::CalculateHash. For every step up to N-factor 15 (cheap
    // to hash) the hash at the returned N-factor must equal CalculateHash,
    // one second before and at the step, and the neighbouring N-factor
    // must give a different hash (so the check can fail). Higher steps are
    // checked against mainnet block hashes by dumpconsensusvalues itself.
    static const int64_t STEPS[] = {1368515488, 1368777632, 1369039776, 1369826208, 1370088352, 1372185504,
                                    1373234080, 1376379808, 1380574112, 1384768416, 1401545632};
    CBlockHeader h;
    h.nVersion = 6;
    h.hashPrevBlock = uint256S(HASH_A);
    h.hashMerkleRoot = uint256S(HASH_B);
    h.nBits = 0x1e0fffff;
    h.nNonce = 12345;
    for (size_t i = 0; i < sizeof(STEPS) / sizeof(STEPS[0]); ++i) {
        for (int64_t nTime : {STEPS[i] - 1, STEPS[i]}) {
            h.nTime = nTime;
            const unsigned char nExpected = (unsigned char)(4 + i + (nTime == STEPS[i] ? 1 : 0));
            const unsigned char nFactor = ConsensusDumpNFactor(h.nVersion, h.nTime);
            BOOST_CHECK_EQUAL((int)nFactor, (int)nExpected);
            const uint256 hash = h.CalculateHash();
            BOOST_CHECK(OldHeaderHash(h, nFactor) == hash);
            BOOST_CHECK(OldHeaderHash(h, nFactor - 1) != hash);
        }
    }
    // Pure table checks for the remaining steps (no hashing).
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(6, 0), 4);
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(6, 1602872223), 19);
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(6, 1602872224), 20);
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(6, 1636426656), 21);
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(6, 3515474847LL), 25);
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(6, 3515474848LL), (int)MAXIMUM_N_FACTOR);

    // Version >= 7 uses nFactorAtHardfork whatever the time.
    globals.SetNFactorAtHardfork(4);
    h.nVersion = VERSION_of_block_for_yac_05x_new;
    h.nTime = 1700000000;
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(h.nVersion, h.nTime), 4);
    BOOST_CHECK(NewHeaderHash(h, 4) == h.CalculateHash());
    BOOST_CHECK(NewHeaderHash(h, 5) != h.CalculateHash());
    globals.SetNFactorAtHardfork(21);
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(h.nVersion, 0), 21);

    // Testnet: always 4 for old headers.
    globals.SetTestNet(true);
    BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(6, 1700000000), 4);
}

BOOST_AUTO_TEST_CASE(dump_errors_and_cleanup)
{
    // DumpConsensusValues on a chain whose entries above the genesis have no
    // block data: the run fails part-way and leaves no file behind; the
    // checks before the run refuse bad ranges, existing files (also a stale
    // ".incomplete") and a node without -txindex. The genesis alone (on disk
    // since TestingSetup) dumps and reads back.
    struct RestoreTxIndex {
        const bool fSaved = fTxIndex;
        ~RestoreTxIndex() { fTxIndex = fSaved; }
    } restore;
    fTxIndex = true;

    CBlockIndex* genesis = chain.StartOnExistingGenesis();
    chain.AppendMany(3, 60, 0x1e0fffff);
    chain.SetActiveTip(chain.Tip());

    const fs::path path = GetDataDir() / "consensus-dump-test.csv";
    const fs::path pathTmp = path.string() + ".incomplete";
    auto fails = [&](int nStart, int nEnd, const std::string& what) {
        try {
            LOCK(cs_main);
            DumpConsensusValues(path, nStart, nEnd);
        } catch (const std::runtime_error& e) {
            BOOST_TEST_MESSAGE("expected error: " << e.what());
            return std::string(e.what()).find(what) != std::string::npos;
        }
        return false;
    };

    BOOST_CHECK(fails(1, 3, "no block data for height 1"));
    BOOST_CHECK(!fs::exists(path));
    BOOST_CHECK(!fs::exists(pathTmp));
    BOOST_CHECK(fails(2, 1, "invalid height range 2..1 (tip 3)"));
    BOOST_CHECK(fails(-1, 1, "invalid height range -1..1"));
    BOOST_CHECK(fails(0, 4, "invalid height range 0..4 (tip 3)"));
    fTxIndex = false;
    BOOST_CHECK(fails(0, 0, "-txindex is required"));
    fTxIndex = true;
    {
        std::ofstream(pathTmp.string()) << "stale";
    }
    BOOST_CHECK(fails(0, 0, "file already exists: " + pathTmp.string()));
    BOOST_CHECK(fs::exists(pathTmp)); // not deleted
    fs::remove(pathTmp);

    // The genesis row.
    ConsensusDumpResult result;
    ConsensusDumpRow row;
    {
        LOCK(cs_main);
        // Unit tests run with fork height 0: the genesis gets
        // min_bits_since_fork, the powLimit compact (nothing before it).
        row = ComputeConsensusDumpRow(genesis, Params().GetConsensus().powLimit.GetCompact(), result);
    }
    BOOST_CHECK(row.hash == genesis->GetBlockHash());
    BOOST_CHECK(row.hashPrev.IsNull());
    BOOST_CHECK_EQUAL(row.nTxCount, 1U);
    BOOST_CHECK(!row.nRequiredBits && !row.nFees && !row.nPowReward && !row.nMaxBlockSize);
    BOOST_CHECK(!row.fHasKernel);

    {
        LOCK(cs_main);
        result = DumpConsensusValues(path, 0, 0);
    }
    BOOST_CHECK_EQUAL(result.nRows, 1U);
    BOOST_CHECK(result.hashEnd == genesis->GetBlockHash());
    BOOST_CHECK(fs::exists(path));
    BOOST_CHECK(!fs::exists(pathTmp));
    const ConsensusDump dump = consensus_dump::ReadConsensusDumpFile(path.string());
    BOOST_CHECK(dump.fComplete);
    BOOST_REQUIRE_EQUAL(dump.rows.size(), 1U);
    CheckRowsEqual(dump.rows[0], row);
    BOOST_CHECK(fails(0, 0, "file already exists: " + path.string()));
    fs::remove(path);
}

BOOST_AUTO_TEST_CASE(mainnet_samples)
{
    // Three ranges of the full mainnet dump, written by dumpconsensusvalues
    // on the P0-08 snapshot (src/test/data/README.md): both readers accept
    // them and they are consistent in themselves. The values are mainnet
    // values whatever the build, so nothing here depends on its powLimit.
    globals.UseMainnetGlobals();
    struct Sample {
        const char* name;
        const char* text;
        int nStart;
        int nEnd;
        int nMinPos; // at least this many PoS rows
    };
    const Sample samples[] = {
        {"consensus_dump_mainnet_early.csv", csv_tests::consensus_dump_mainnet_early, 1, 60, 0},
        {"consensus_dump_mainnet_pos.csv", csv_tests::consensus_dump_mainnet_pos, 500040, 500099, 3},
        {"consensus_dump_mainnet_fork.csv", csv_tests::consensus_dump_mainnet_fork, 1889990, 1890010, 0},
    };
    for (const Sample& sample : samples) {
        BOOST_TEST_MESSAGE("sample " << sample.name);
        std::istringstream in(sample.text);
        const ConsensusDump dump = ReadConsensusDump(in, sample.name);
        BOOST_CHECK(dump.fComplete);
        BOOST_CHECK_EQUAL(dump.meta.at("chain"), "main");
        BOOST_CHECK_EQUAL(dump.meta.at("lowdiff"), "0");
        BOOST_CHECK_EQUAL(dump.meta.at("fork_height"), "1890000");
        BOOST_CHECK_EQUAL(dump.meta.at("nfactor_at_hardfork"), "21");
        BOOST_REQUIRE_EQUAL(dump.rows.size(), (size_t)(sample.nEnd - sample.nStart + 1));
        BOOST_CHECK_EQUAL(dump.rows.front().nHeight, sample.nStart);
        int nPos = 0;
        for (size_t i = 0; i < dump.rows.size(); ++i) {
            const ConsensusDumpRow& r = dump.rows[i];
            BOOST_CHECK_EQUAL(r.nHeight, sample.nStart + (int)i);
            BOOST_CHECK_EQUAL((int)ConsensusDumpNFactor(r.nVersion, r.nTime), r.nFactor);
            BOOST_CHECK_EQUAL(r.fProofOfStake, (r.nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE) != 0);
            // No epoch boundary after the fork in these ranges: the
            // required target is the block's nBits (at 1,890,000 powLimit).
            BOOST_REQUIRE(r.nRequiredBits);
            BOOST_CHECK_EQUAL(*r.nRequiredBits, r.nBits);
            BOOST_CHECK_EQUAL((bool)r.nMinBitsSinceFork, r.nHeight >= 1890000);
            BOOST_REQUIRE(r.nFees && r.nMaxBlockSize && r.nMaxSigOps);
            BOOST_CHECK(r.nBlockSize <= *r.nMaxBlockSize);
            BOOST_CHECK(r.nSigOps <= *r.nMaxSigOps);
            if (r.fProofOfStake) {
                ++nPos;
                BOOST_REQUIRE(r.fHasKernel && r.kernelHash && r.nKernelStakeModifier && r.nCoinAge);
                BOOST_CHECK(r.fKernelOk);
                BOOST_CHECK(*r.kernelHash == r.hashProofOfStake);
                BOOST_CHECK_EQUAL(*r.nPosReward, GetProofOfStakeReward(*r.nCoinAge, r.nBits, r.nKernelTxTime));
                BOOST_CHECK(*r.nCoinstakeValueOut - *r.nCoinstakeValueIn <= *r.nPosRewardLimit);
                BOOST_CHECK(!r.nPowReward);
            } else {
                BOOST_CHECK(!r.fHasKernel);
                BOOST_REQUIRE(r.nPowReward);
                BOOST_CHECK(r.nCoinbaseValue <= *r.nPowReward);
                BOOST_CHECK_EQUAL(r.nMint, r.nCoinbaseValue);
            }
            if (i == 0) continue;
            const ConsensusDumpRow& p = dump.rows[i - 1];
            BOOST_CHECK(r.hashPrev == p.hash);
            BOOST_CHECK(r.chainTrust == p.chainTrust + r.blockTrust);
            BOOST_CHECK_EQUAL(*r.nFees, r.nMint - (r.nMoneySupply - p.nMoneySupply));
            if (r.nMinBitsSinceFork && p.nMinBitsSinceFork) {
                BOOST_CHECK_EQUAL(*r.nMinBitsSinceFork, std::min(*p.nMinBitsSinceFork, p.nBits));
            }
        }
        BOOST_CHECK(nPos >= sample.nMinPos);

        // The P0-47 loader reads the same text.
        consensus_harness::TestChain loaded(1 + sample.nStart);
        std::istringstream in2(sample.text);
        CBlockIndex* tip = consensus_harness::LoadIndexChainCsv(in2, loaded, sample.name);
        BOOST_REQUIRE(tip != nullptr);
        BOOST_CHECK_EQUAL(tip->nHeight, sample.nEnd);
        BOOST_CHECK(tip->GetBlockHash() == dump.rows.back().hash);
        BOOST_CHECK_EQUAL(tip->nStakeModifier, dump.rows.back().nStakeModifier);
    }
}

BOOST_AUTO_TEST_SUITE_END()
