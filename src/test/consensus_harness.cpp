// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/consensus_harness.h"

#include "chainparams.h"
#include "clientversion.h"
#include "hash.h"
#include "streams.h"
#include "sync.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"

#include <cstdio>
#include <fstream>
#include <limits>
#include <map>
#include <stdexcept>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace consensus_harness {

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

ConsensusGlobals ConsensusGlobals::Capture()
{
    ConsensusGlobals g;
    g.nMainnetNewLogicBlockNumber = ::nMainnetNewLogicBlockNumber;
    g.nTokenSupportBlockNumber = ::nTokenSupportBlockNumber;
    g.nFactorAtHardfork = ::nFactorAtHardfork;
    g.nEpochInterval = ::nEpochInterval;
    g.nDifficultyInterval = ::nDifficultyInterval;
    g.fTestNet = ::fTestNet;
    g.nYac10HardforkTime = ::nYac10HardforkTime;
    g.nMockTime = GetMockTime();
    return g;
}

void ConsensusGlobals::Apply() const
{
    ::nMainnetNewLogicBlockNumber = nMainnetNewLogicBlockNumber;
    ::nTokenSupportBlockNumber = nTokenSupportBlockNumber;
    ::nFactorAtHardfork = nFactorAtHardfork;
    ::nEpochInterval = nEpochInterval;
    ::nDifficultyInterval = nDifficultyInterval;
    ::fTestNet = fTestNet;
    ::nYac10HardforkTime = nYac10HardforkTime;
    ::SetMockTime(nMockTime);
}

bool ConsensusGlobals::operator==(const ConsensusGlobals& o) const
{
    return nMainnetNewLogicBlockNumber == o.nMainnetNewLogicBlockNumber &&
           nTokenSupportBlockNumber == o.nTokenSupportBlockNumber &&
           nFactorAtHardfork == o.nFactorAtHardfork &&
           nEpochInterval == o.nEpochInterval &&
           nDifficultyInterval == o.nDifficultyInterval &&
           fTestNet == o.fTestNet &&
           nYac10HardforkTime == o.nYac10HardforkTime &&
           nMockTime == o.nMockTime;
}

std::string ConsensusGlobals::ToString() const
{
    return strprintf("nMainnetNewLogicBlockNumber=%d nTokenSupportBlockNumber=%d nFactorAtHardfork=%d "
                     "nEpochInterval=%u nDifficultyInterval=%u fTestNet=%d nYac10HardforkTime=%d nMockTime=%d",
                     nMainnetNewLogicBlockNumber, nTokenSupportBlockNumber, (int)nFactorAtHardfork,
                     nEpochInterval, nDifficultyInterval, fTestNet, nYac10HardforkTime, nMockTime);
}

ScopedConsensusGlobals::ScopedConsensusGlobals() : saved(ConsensusGlobals::Capture())
{
}

ScopedConsensusGlobals::~ScopedConsensusGlobals()
{
    saved.Apply();
}

void ScopedConsensusGlobals::SetNewLogicBlockNumber(int32_t nHeight)
{
    BOOST_TEST_MESSAGE("consensus harness: nMainnetNewLogicBlockNumber = " << nHeight);
    ::nMainnetNewLogicBlockNumber = nHeight;
}

void ScopedConsensusGlobals::SetTokenSupportBlockNumber(int32_t nHeight)
{
    BOOST_TEST_MESSAGE("consensus harness: nTokenSupportBlockNumber = " << nHeight);
    ::nTokenSupportBlockNumber = nHeight;
}

void ScopedConsensusGlobals::SetNFactorAtHardfork(unsigned char nFactor)
{
    BOOST_TEST_MESSAGE("consensus harness: nFactorAtHardfork = " << (int)nFactor);
    ::nFactorAtHardfork = nFactor;
}

void ScopedConsensusGlobals::SetEpochInterval(uint32_t nInterval)
{
    BOOST_TEST_MESSAGE("consensus harness: nEpochInterval = nDifficultyInterval = " << nInterval);
    ::nEpochInterval = nInterval;
    ::nDifficultyInterval = nInterval;
}

void ScopedConsensusGlobals::SetDifficultyInterval(uint32_t nInterval)
{
    BOOST_TEST_MESSAGE("consensus harness: nDifficultyInterval = " << nInterval);
    ::nDifficultyInterval = nInterval;
}

void ScopedConsensusGlobals::SetTestNet(bool fTestNetIn)
{
    BOOST_TEST_MESSAGE("consensus harness: fTestNet = " << fTestNetIn);
    ::fTestNet = fTestNetIn;
}

void ScopedConsensusGlobals::SetYac10HardforkTime(int64_t nTime)
{
    BOOST_TEST_MESSAGE("consensus harness: nYac10HardforkTime = " << nTime);
    ::nYac10HardforkTime = nTime;
}

void ScopedConsensusGlobals::SetMockTime(int64_t nTime)
{
    BOOST_TEST_MESSAGE("consensus harness: mock time = " << nTime);
    ::SetMockTime(nTime);
}

void ScopedConsensusGlobals::UseUnitTestGlobals()
{
    SetNewLogicBlockNumber(0);
    SetTokenSupportBlockNumber(0);
    SetNFactorAtHardfork(0);
    SetEpochInterval(MAINNET_EPOCH_INTERVAL);
    SetTestNet(false);
    SetYac10HardforkTime(DEFAULT_YAC10_HARDFORK_TIME);
}

void ScopedConsensusGlobals::UseMainnetGlobals()
{
    SetNewLogicBlockNumber(MAINNET_NEW_LOGIC_BLOCK_NUMBER);
    SetTokenSupportBlockNumber(MAINNET_TOKEN_SUPPORT_BLOCK_NUMBER);
    SetNFactorAtHardfork(MAINNET_N_FACTOR_AT_HARDFORK);
    SetEpochInterval(MAINNET_EPOCH_INTERVAL);
    SetTestNet(false);
    SetYac10HardforkTime(DEFAULT_YAC10_HARDFORK_TIME);
}

void ScopedConsensusGlobals::UseFunctionalTestGlobals(int32_t nForkHeight)
{
    SetNewLogicBlockNumber(nForkHeight);
    SetTokenSupportBlockNumber(MAINNET_TOKEN_SUPPORT_BLOCK_NUMBER);
    SetNFactorAtHardfork(FUNCTIONAL_N_FACTOR_AT_HARDFORK);
    SetEpochInterval(FUNCTIONAL_EPOCH_INTERVAL);
    SetTestNet(false);
    SetYac10HardforkTime(DEFAULT_YAC10_HARDFORK_TIME);
}

// ---------------------------------------------------------------------------
// TestChain
// ---------------------------------------------------------------------------

TestChain::TestChain(uint32_t nSaltIn)
    : nSalt(nSaltIn), nCounter(0), pindexTip(nullptr), fChangedActiveChain(false), pindexSavedActiveTip(nullptr)
{
}

TestChain::~TestChain()
{
    LOCK(cs_main);
    if (fChangedActiveChain) {
        chainActive.SetTip(nullptr); // see SetActiveTip
        chainActive.SetTip(pindexSavedActiveTip);
    }
    for (const auto& entry : entries) {
        // Only erase the map entry if it still points to our object.
        BlockMap::iterator it = mapBlockIndex.find(entry->GetBlockHash());
        if (it != mapBlockIndex.end() && it->second == entry.get()) {
            mapBlockIndex.erase(it);
        }
    }
    entries.clear();
}

namespace {

// Copies of the file-static helpers in chain.cpp:117-131 (CBlockIndex::pskip
// target height), so skip pointers match BuildSkip() exactly.
int InvertLowestOne(int n) { return n & (n - 1); }
int GetSkipHeight(int height)
{
    if (height < 2)
        return 0;
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

// Like CBlockIndex::GetAncestor, but returns nullptr instead of asserting
// when nHeight lies below the start of a segment (pprev == nullptr above
// height 0).
CBlockIndex* SafeAncestor(CBlockIndex* pindex, int nHeight)
{
    if (nHeight < 0) return nullptr;
    while (pindex != nullptr && pindex->nHeight > nHeight) {
        if (pindex->pskip != nullptr && pindex->pskip->nHeight >= nHeight)
            pindex = pindex->pskip;
        else
            pindex = pindex->pprev;
    }
    return (pindex != nullptr && pindex->nHeight == nHeight) ? pindex : nullptr;
}

} // namespace

uint256 TestChain::NextSyntheticHash()
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("P0-47 TestChain") << nSalt << nCounter++;
    return ss.GetHash();
}

CBlockIndex* TestChain::Insert(std::unique_ptr<CBlockIndex> pindex, const uint256& hash, CBlockIndex* prev, int32_t nSegmentHeight)
{
    LOCK(cs_main);
    if (mapBlockIndex.count(hash)) {
        throw std::runtime_error("TestChain: block hash already in mapBlockIndex: " + hash.ToString());
    }
    if (prev == nullptr && nSegmentHeight < 0) {
        throw std::runtime_error(strprintf("TestChain: negative segment height %d", nSegmentHeight));
    }
    CBlockIndex* p = pindex.get();
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, p)).first;
    p->phashBlock = &mi->first;
    p->blockHash = hash;
    p->pprev = prev;
    p->nHeight = prev ? prev->nHeight + 1 : nSegmentHeight;
    // Same pointer as BuildSkip(), but nullptr when the target lies below a
    // segment start (BuildSkip would hit GetAncestor's assert there).
    p->pskip = prev ? SafeAncestor(prev, GetSkipHeight(p->nHeight)) : nullptr;
    p->nTimeMax = prev ? std::max(prev->nTimeMax, p->nTime) : p->nTime;
    // Same as AddToBlockIndex (validation.cpp:2934).
    p->bnChainTrust = (prev ? prev->bnChainTrust : CBigNum(0)) + p->GetBlockTrust();
    p->RaiseValidity(BLOCK_VALID_TREE);
    entries.push_back(std::move(pindex));
    pindexTip = p;
    return p;
}

CBlockIndex* TestChain::StartOnExistingGenesis()
{
    LOCK(cs_main);
    if (pindexTip != nullptr) {
        throw std::runtime_error("TestChain::StartOnExistingGenesis: chain is not empty");
    }
    BlockMap::iterator it = mapBlockIndex.find(Params().GetConsensus().hashGenesisBlock);
    if (it == mapBlockIndex.end()) {
        throw std::runtime_error("TestChain::StartOnExistingGenesis: genesis not in mapBlockIndex (use TestingSetup)");
    }
    pindexTip = it->second;
    BOOST_TEST_MESSAGE("consensus harness: chain starts on genesis " << pindexTip->GetBlockHash().ToString());
    return pindexTip;
}

CBlockIndex* TestChain::Append(const BlockSpec& spec)
{
    return Append(pindexTip, spec);
}

CBlockIndex* TestChain::Append(CBlockIndex* prev, const BlockSpec& spec)
{
    if (prev != nullptr && spec.nHeight != -1 && spec.nHeight != prev->nHeight + 1) {
        throw std::runtime_error(strprintf("TestChain::Append: height %d does not follow %d", spec.nHeight, prev->nHeight));
    }
    std::unique_ptr<CBlockIndex> pindex(new CBlockIndex());
    pindex->nVersion = spec.nVersion;
    pindex->hashMerkleRoot = spec.hashMerkleRoot;
    pindex->nTime = spec.nTime;
    pindex->nBits = spec.nBits;
    pindex->nNonce = spec.nNonce;
    if (spec.fProofOfStake) {
        pindex->SetProofOfStake();
    }
    if (!pindex->SetStakeEntropyBit(spec.nEntropyBit)) {
        throw std::runtime_error(strprintf("TestChain::Append: entropy bit %u is not 0 or 1", spec.nEntropyBit));
    }
    pindex->SetStakeModifier(spec.nStakeModifier, spec.fGeneratedStakeModifier);
    pindex->hashProofOfStake = spec.hashProofOfStake;
    pindex->prevoutStake = spec.prevoutStake;
    pindex->nStakeTime = spec.nStakeTime;
    const uint256 hash = spec.hash.IsNull() ? NextSyntheticHash() : spec.hash;
    return Insert(std::move(pindex), hash, prev, spec.nHeight < 0 ? 0 : spec.nHeight);
}

CBlockIndex* TestChain::AppendMany(int n, int64_t nSpacing, uint32_t nBits, bool fProofOfStake, int64_t nFirstTime)
{
    for (int i = 0; i < n; ++i) {
        const int64_t nTime = pindexTip ? pindexTip->GetBlockTime() + nSpacing : nFirstTime;
        Append(BlockSpec(nTime, nBits, fProofOfStake));
    }
    return pindexTip;
}

CBlockIndex* TestChain::AppendBlock(const CBlock& block, bool fWriteToDisk, int32_t nSegmentHeight)
{
    CBlockIndex* prev = nullptr;
    {
        LOCK(cs_main);
        BlockMap::iterator it = mapBlockIndex.find(block.hashPrevBlock);
        if (it != mapBlockIndex.end()) prev = it->second;
    }
    const int32_t nHeight = prev ? prev->nHeight + 1 : nSegmentHeight;
    // Like AddToBlockIndex: header fields and PoS flag from the header,
    // entropy bit from the block hash.
    std::unique_ptr<CBlockIndex> pindex(new CBlockIndex(block));
    if (!pindex->SetStakeEntropyBit(block.GetStakeEntropyBit(nHeight))) {
        throw std::runtime_error("TestChain::AppendBlock: SetStakeEntropyBit failed");
    }
    if (fWriteToDisk) {
        const CDiskBlockPos pos = WriteBlockToTestFile(block);
        pindex->nFile = pos.nFile;
        pindex->nDataPos = pos.nPos;
        pindex->nUndoPos = 0;
        pindex->nTx = block.vtx.size();
        pindex->nStatus |= BLOCK_HAVE_DATA;
    }
    return Insert(std::move(pindex), block.GetHash(), prev, nSegmentHeight);
}

void TestChain::SetActiveTip(CBlockIndex* pindex)
{
    LOCK(cs_main);
    if (!fChangedActiveChain) {
        pindexSavedActiveTip = chainActive.Tip();
        fChangedActiveChain = true;
    }
    // CChain::SetTip only overwrites slots down to the first null pprev or
    // the first slot that already matches, so clear first: otherwise a
    // segment would keep the old genesis (and other stale entries) below
    // its start.
    chainActive.SetTip(nullptr);
    chainActive.SetTip(pindex);
    BOOST_TEST_MESSAGE("consensus harness: chainActive tip = height " << (pindex ? pindex->nHeight : -1));
}

CBlockIndex* TestChain::AtHeight(int nHeight) const
{
    return SafeAncestor(pindexTip, nHeight);
}

// ---------------------------------------------------------------------------
// Block files
// ---------------------------------------------------------------------------

CDiskBlockPos WriteBlockToTestFile(const CBlock& block)
{
    CDiskBlockPos pos(TEST_BLOCK_FILE, 0);
    // Opens (or creates) blocks/blk09000.dat at offset 0; append at the end.
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        throw std::runtime_error("WriteBlockToTestFile: OpenBlockFile failed");
    }
    if (fseek(fileout.Get(), 0, SEEK_END) != 0) {
        throw std::runtime_error("WriteBlockToTestFile: fseek failed");
    }
    // Same layout as WriteBlockToDisk (validation.cpp:821).
    unsigned int nSize = GetSerializeSize(fileout, block);
    fileout << FLATDATA(Params().MessageStart()) << nSize;
    long nFilePos = ftell(fileout.Get());
    if (nFilePos < 0) {
        throw std::runtime_error("WriteBlockToTestFile: ftell failed");
    }
    pos.nPos = (unsigned int)nFilePos;
    fileout << block;
    BOOST_TEST_MESSAGE("consensus harness: wrote block " << block.GetHash().ToString() << " to " << pos.ToString());
    return pos;
}

// ---------------------------------------------------------------------------
// Index-chain CSV loader
// ---------------------------------------------------------------------------

namespace {

[[noreturn]] void Fail(const std::string& name, int nLine, const std::string& msg)
{
    throw std::runtime_error(strprintf("%s:%d: %s", name, nLine, msg));
}

std::vector<std::string> SplitCsv(const std::string& line)
{
    std::vector<std::string> fields;
    std::string::size_type start = 0;
    while (true) {
        std::string::size_type comma = line.find(',', start);
        if (comma == std::string::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, comma - start));
        start = comma + 1;
    }
    return fields;
}

/** Unsigned integer: decimal, or hex with 0x prefix; nothing else. */
bool ParseUnsigned(const std::string& s, uint64_t nMax, uint64_t& nOut)
{
    if (s.empty()) return false;
    std::string digits = s;
    int nBase = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        digits = s.substr(2);
        nBase = 16;
    }
    uint64_t n = 0;
    for (char c : digits) {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (nBase == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (nBase == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        if ((uint64_t)d > nMax || n > (nMax - d) / nBase) return false; // overflow
        n = n * nBase + d;
    }
    nOut = n;
    return true;
}

bool ParseHash(const std::string& s, uint256& out)
{
    if (s.size() != 64 || !IsHex(s)) return false;
    out = uint256S(s);
    return true;
}

} // namespace

CBlockIndex* LoadIndexChainCsv(std::istream& in, TestChain& chain, const std::string& name)
{
    static const char* const REQUIRED[] = {"height", "hash", "time", "bits"};
    std::map<std::string, size_t> columns;
    size_t nColumns = 0;
    bool fHaveHeader = false;
    CBlockIndex* pindexLast = nullptr;
    int nLine = 0;
    int nRows = 0;
    std::string line;
    while (std::getline(in, line)) {
        ++nLine;
        if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> fields = SplitCsv(line);
        if (!fHaveHeader) {
            for (size_t i = 0; i < fields.size(); ++i) {
                if (fields[i].empty()) Fail(name, nLine, "empty column name");
                if (!columns.emplace(fields[i], i).second) Fail(name, nLine, "duplicate column " + fields[i]);
            }
            for (const char* req : REQUIRED) {
                if (!columns.count(req)) Fail(name, nLine, std::string("missing required column ") + req);
            }
            nColumns = fields.size();
            fHaveHeader = true;
            continue;
        }
        if (fields.size() != nColumns) {
            Fail(name, nLine, strprintf("%u fields, header has %u", (unsigned)fields.size(), (unsigned)nColumns));
        }
        auto field = [&](const char* col) -> std::string {
            auto it = columns.find(col);
            return it == columns.end() ? std::string() : fields[it->second];
        };
        auto number = [&](const char* col, uint64_t nMax, bool fRequired) -> uint64_t {
            std::string s = field(col);
            if (s.empty()) {
                if (fRequired) Fail(name, nLine, std::string("empty ") + col);
                return 0;
            }
            uint64_t n;
            if (!ParseUnsigned(s, nMax, n)) Fail(name, nLine, std::string("bad number in ") + col + ": '" + s + "'");
            return n;
        };
        auto hash = [&](const char* col, bool fRequired) -> uint256 {
            std::string s = field(col);
            uint256 h;
            if (s.empty()) {
                if (fRequired) Fail(name, nLine, std::string("empty ") + col);
                return h;
            }
            if (!ParseHash(s, h)) Fail(name, nLine, std::string("bad hash in ") + col + ": '" + s + "'");
            return h;
        };

        const int32_t nHeight = (int32_t)number("height", std::numeric_limits<int32_t>::max(), true);
        BlockSpec spec;
        spec.hash = hash("hash", true);
        spec.nTime = (int64_t)number("time", std::numeric_limits<int64_t>::max(), true);
        spec.nBits = (uint32_t)number("bits", std::numeric_limits<uint32_t>::max(), true);
        if (!field("version").empty()) {
            spec.nVersion = (int32_t)number("version", std::numeric_limits<int32_t>::max(), false);
        }
        spec.nNonce = (uint32_t)number("nonce", std::numeric_limits<uint32_t>::max(), false);
        spec.hashMerkleRoot = hash("merkle_root", false);
        const uint64_t nFlags = number("flags", CBlockIndex::BLOCK_PROOF_OF_STAKE | CBlockIndex::BLOCK_STAKE_ENTROPY | CBlockIndex::BLOCK_STAKE_MODIFIER, false);
        spec.fProofOfStake = (nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE) != 0;
        spec.nEntropyBit = (nFlags & CBlockIndex::BLOCK_STAKE_ENTROPY) ? 1 : 0;
        spec.fGeneratedStakeModifier = (nFlags & CBlockIndex::BLOCK_STAKE_MODIFIER) != 0;
        spec.nStakeModifier = number("stake_modifier", std::numeric_limits<uint64_t>::max(), false);
        spec.hashProofOfStake = hash("hash_proof_of_stake", false);
        spec.nStakeTime = (uint32_t)number("stake_time", std::numeric_limits<uint32_t>::max(), false);
        const std::string strPrevout = field("prevout_stake");
        if (!strPrevout.empty()) {
            std::string::size_type colon = strPrevout.find(':');
            uint256 txid;
            uint64_t n;
            if (colon == std::string::npos || !ParseHash(strPrevout.substr(0, colon), txid) ||
                !ParseUnsigned(strPrevout.substr(colon + 1), std::numeric_limits<uint32_t>::max(), n)) {
                Fail(name, nLine, "bad prevout_stake: '" + strPrevout + "'");
            }
            spec.prevoutStake = COutPoint(txid, (uint32_t)n);
        }
        const uint256 hashPrev = hash("prev_hash", false);

        CBlockIndex* prev = nullptr;
        if (pindexLast == nullptr) {
            if (!hashPrev.IsNull()) {
                LOCK(cs_main);
                BlockMap::iterator it = mapBlockIndex.find(hashPrev);
                if (it != mapBlockIndex.end()) prev = it->second;
            }
            if (prev != nullptr && nHeight != prev->nHeight + 1) {
                Fail(name, nLine, strprintf("height %d does not follow prev_hash at height %d", nHeight, prev->nHeight));
            }
        } else {
            if (nHeight != pindexLast->nHeight + 1) {
                Fail(name, nLine, strprintf("height %d does not follow %d", nHeight, pindexLast->nHeight));
            }
            if (!hashPrev.IsNull() && hashPrev != pindexLast->GetBlockHash()) {
                Fail(name, nLine, "prev_hash does not match the previous row");
            }
            prev = pindexLast;
        }
        spec.nHeight = nHeight;
        try {
            pindexLast = chain.Append(prev, spec);
        } catch (const std::runtime_error& e) {
            Fail(name, nLine, e.what());
        }
        ++nRows;
    }
    if (!fHaveHeader) Fail(name, nLine, "no header line");
    BOOST_TEST_MESSAGE("consensus harness: loaded " << nRows << " index entries from " << name);
    return pindexLast;
}

CBlockIndex* LoadIndexChainCsvFile(const std::string& path, TestChain& chain)
{
    std::ifstream file(path.c_str());
    if (!file) {
        throw std::runtime_error("LoadIndexChainCsvFile: cannot open " + path);
    }
    return LoadIndexChainCsv(file, chain, path);
}

} // namespace consensus_harness

ConsensusTestingSetup::ConsensusTestingSetup(const std::string& chainName) : TestingSetup(chainName)
{
}
