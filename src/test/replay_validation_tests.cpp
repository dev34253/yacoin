// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Validation for replays of the block history (-replayvalidation): while a block is
// connected, the script of every input is run with the block's script flags and the
// signature of a proof-of-stake block is checked; each failure is logged as one line, and
// with "reject" a block with a failure is invalid. The block signature part is tested on
// real mainnet blocks through CheckReplayBlockSignature.

#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "miner.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "validationinterface.h"

#include "test/log_test_util.h"
#include "test/stake_test_util.h"
#include "test/test_bitcoin.h"

#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

bool CheckInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, std::vector<CScriptCheck>* pvChecks);

namespace {

// Mainnet blocks 82217 and 82994 (proof of stake), as in block_pos_tests
const char* const BLOCK_82217_HEX =
    "030000003b9fd65cc463f0007368b724626b0836e5289873d6ba13524c8d10d0000000000c66a03fdbf59ce40bfa80a233e14c0b95183de6c8"
    "399075db12dbd9e8c4e582d695b151ffff0f1e000000000201000000d695b15101000000000000000000000000000000000000000000000000"
    "0000000000000000ffffffff0d032941010110062f503253482fffffffff010000000000000000000000000001000000d695b151019c868cda"
    "004ed82db31f98c34ab851d1e6bc895e1022e86cdfed948e2673cf9b0000000049483045022051b3c2be917b8284f1a6bda2d25b9e45d7b612"
    "eb6b5a17f40bd8335abab01d9602210098a90978f0c39a81f64ac549475f1b5a77211ed334e47512933fbcb5272a3d1701ffffffff03000000"
    "0000000000001057e6020000000023210354c0e1446ae9bd305ae8899a009a44775a31ce0292cad8f6bee00d7263b59685ac1057e602000000"
    "0023210354c0e1446ae9bd305ae8899a009a44775a31ce0292cad8f6bee00d7263b59685ac00000000473045022100caf0782b469112972be7"
    "f16d34399c06f9336e1a1de43efb9e8181720a253a75022056b29f25e52d998dba0657f6d1e0e9c57aebc9ce69dd8b4ad079e75aa2115adc";
const char* const BLOCK_82994_HEX =
    "03000000561e3d3b4718fcba4aadbe36d75efab082a2eff9cafd889fac3d8845010000003bfdf9e789eb72a1e0287a1d4c932205c07d739fe7"
    "50296fe3e6ca9c836a36a14c77b251ffff031d0000000002010000004c77b25101000000000000000000000000000000000000000000000000"
    "0000000000000000ffffffff0d03324401014a062f503253482fffffffff0100000000000000000000000000010000004c77b2510151870f60"
    "60dc87447def052dd436a31ca67df844b3ec63fabcbc8e5c49a29fd4010000006c493046022100c3bb9828037e91a7d9f11a46a64ffaf55411"
    "819b16ae02539567e3376fe2ac6a022100fb74bf1da4c110773d34d0e54a2534217500f70f487a90270b37601537183dcc012102f51d5bf68c"
    "9b983d02a1575e5082096b47a6a6297bd92ee1fbb4f7629e221658ffffffff030000000000000000000042b30a00000000232102f51d5bf68c"
    "9b983d02a1575e5082096b47a6a6297bd92ee1fbb4f7629e221658ac0042b30a00000000232102f51d5bf68c9b983d02a1575e5082096b47a6"
    "a6297bd92ee1fbb4f7629e221658ac00000000473045022020b3ab3dcd90cffbc6d9700ad73ec3c3b90c1aca5f89698f2aaffe6977d2077602"
    "21009cd4e8f1a09cac2b07127187ee9526e609264cf42613dc857f8f8621aeff7be3";

const std::string REPORT_PREFIX = "replayvalidation: failure ";

/** The report lines of a log, each from its prefix on */
std::vector<std::string> ReportLines(const std::string& log)
{
    std::vector<std::string> lines;
    std::istringstream in(log);
    std::string line;
    while (std::getline(in, line)) {
        const size_t pos = line.find(REPORT_PREFIX);
        if (pos != std::string::npos) lines.push_back(line.substr(pos));
    }
    return lines;
}

/** The report line of a failing input */
std::string ScriptReport(int nHeight, const CBlock& block, const CTransaction& tx, unsigned int nIn, ScriptError err)
{
    return strprintf("%sheight=%d block=%s check=script tx=%s input=%u error=%s", REPORT_PREFIX, nHeight,
                     block.GetHash().GetHex(), tx.GetHash().GetHex(), nIn, ScriptErrorString(err));
}

std::string Lines(const std::vector<std::string>& lines)
{
    std::string result;
    for (const std::string& line : lines) result += line + "\n";
    return result;
}

/** The state of every block BlockChecked reports, by hash */
struct CheckedBlocks : public CValidationInterface {
    struct Result {
        bool fValid;
    };
    std::map<uint256, Result> results;
    CheckedBlocks() { RegisterValidationInterface(this); }
    ~CheckedBlocks() { UnregisterValidationInterface(this); }
    void BlockChecked(const CBlock& block, const CValidationState& state) override
    {
        results[block.GetHash()] = Result{state.IsValid()};
    }
};

/** Regtest chain with mature coinbases; log output captured per block; the mode's globals
 *  restored at the end */
struct ReplaySetup : public ConsoleLogging, public TestChain100Setup {
    ValueGuard<bool> replay{fReplayValidation, false};
    ValueGuard<bool> reject{fReplayValidationReject, false};
    CScript scriptPubKey;
    CKey otherKey;
    CheckedBlocks checked;

    ReplaySetup()
    {
        scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        otherKey.MakeNewKey(true);
        for (int i = 0; i < COINBASE_MATURITY_AFTER_HARDFORK; i++)
            coinbaseTxns.push_back(CreateAndProcessBlock({}, scriptPubKey).vtx[0]);
    }

    void SetMode(bool fOn, bool fReject)
    {
        fReplayValidation = fOn;
        fReplayValidationReject = fReject;
    }

    /** A spend of output 0 of each of prevs; input i is signed with keys[i] */
    CTransaction Spend(const std::vector<CTransaction>& prevs, const std::vector<const CKey*>& keys)
    {
        CMutableTransaction tx;
        for (const CTransaction& prev : prevs) tx.vin.emplace_back(COutPoint(prev.GetHash(), 0));
        tx.vout.emplace_back(CENT, scriptPubKey);
        for (unsigned int i = 0; i < prevs.size(); i++) {
            std::vector<unsigned char> vchSig;
            const uint256 hash = SignatureHash(prevs[i].vout[0].scriptPubKey, tx, i, SIGHASH_ALL);
            BOOST_REQUIRE(keys[i]->Sign(hash, vchSig));
            vchSig.push_back((unsigned char)SIGHASH_ALL);
            tx.vin[i].scriptSig = CScript() << vchSig;
        }
        return CTransaction(tx);
    }

    /** Mines and processes a block with tx, returning it and the log of its processing */
    CBlock Process(const CTransaction& tx, std::string& log)
    {
        LogCapture capture(pathTemp / "replay.log");
        CBlock block = CreateAndProcessBlock({tx}, scriptPubKey);
        log = capture.Stop();
        return block;
    }

    bool IsTip(const CBlock& block)
    {
        LOCK(cs_main);
        return chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    int Height()
    {
        LOCK(cs_main);
        return chainActive.Height();
    }

    /** The coin an input spends, as the tip's view has it now */
    Coin CoinOf(const CTxIn& in)
    {
        LOCK(cs_main);
        return pcoinsTip->AccessCoin(in.prevout);
    }
};

/** The number of script checks CheckInputs returns for tx against coins (without storing to
 *  a cache), for every combination of the script flags a block can have: tx.vin.size() each,
 *  unless the script execution cache holds an entry for tx and those flags */
std::vector<size_t> ChecksPerFlags(const CTransaction& tx, const std::vector<Coin>& coins)
{
    CCoinsView base;
    CCoinsViewCache view(&base);
    for (unsigned int i = 0; i < tx.vin.size(); i++) view.AddCoin(tx.vin[i].prevout, Coin(coins[i]), false);
    std::vector<size_t> counts;
    LOCK(cs_main);
    for (unsigned int f = 0; f < 8; f++) {
        const unsigned int flags = ((f & 1) ? SCRIPT_VERIFY_P2SH : 0) | ((f & 2) ? SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY : 0) |
                                   ((f & 4) ? SCRIPT_VERIFY_CHECKSEQUENCEVERIFY : 0);
        CValidationState state;
        std::vector<CScriptCheck> checks;
        BOOST_CHECK(CheckInputs(tx, state, view, true, flags, false, false, &checks));
        counts.push_back(checks.size());
    }
    return counts;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(replay_validation_tests, ReplaySetup)

/* report: every input with an invalid signature gives one report line */
BOOST_AUTO_TEST_CASE(report_invalid_signature)
{
    SetMode(true, false);
    const CTransaction tx = Spend({coinbaseTxns[0], coinbaseTxns[1]}, {&otherKey, &otherKey});
    const int nHeight = Height() + 1;
    std::string log;
    const CBlock block = Process(tx, log);

    BOOST_CHECK_EQUAL(Lines(ReportLines(log)),
                      Lines({ScriptReport(nHeight, block, tx, 0, SCRIPT_ERR_EVAL_FALSE),
                             ScriptReport(nHeight, block, tx, 1, SCRIPT_ERR_EVAL_FALSE)}));
}

/* reject: the same report lines; the block is invalid, not connected and marked failed */
BOOST_AUTO_TEST_CASE(reject_invalid_signature)
{
    SetMode(true, true);
    const CTransaction tx = Spend({coinbaseTxns[0], coinbaseTxns[1]}, {&otherKey, &otherKey});
    const int nHeight = Height() + 1;
    std::string log;
    const CBlock block = Process(tx, log);

    BOOST_CHECK_EQUAL(Lines(ReportLines(log)),
                      Lines({ScriptReport(nHeight, block, tx, 0, SCRIPT_ERR_EVAL_FALSE),
                             ScriptReport(nHeight, block, tx, 1, SCRIPT_ERR_EVAL_FALSE)}));
    BOOST_CHECK(!IsTip(block));
    BOOST_CHECK_EQUAL(Height(), nHeight - 1);
    const auto it = checked.results.find(block.GetHash());
    BOOST_REQUIRE(it != checked.results.end());
    BOOST_CHECK(!it->second.fValid);
    {
        LOCK(cs_main);
        const auto mi = mapBlockIndex.find(block.GetHash());
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        BOOST_CHECK(mi->second->nStatus & BLOCK_FAILED_VALID);
    }
}

/* report and reject: a block whose inputs are signed correctly connects without a report line */
BOOST_AUTO_TEST_CASE(valid_block_passes)
{
    for (const bool fReject : {false, true}) {
        SetMode(true, fReject);
        const CTransaction tx = Spend({coinbaseTxns[fReject ? 2 : 0], coinbaseTxns[fReject ? 3 : 1]},
                                      {&coinbaseKey, &coinbaseKey});
        std::string log;
        const CBlock block = Process(tx, log);
        BOOST_CHECK_MESSAGE(IsTip(block), (fReject ? "reject" : "report"));
        BOOST_CHECK_EQUAL(Lines(ReportLines(log)), "");
        const auto it = checked.results.find(block.GetHash());
        BOOST_REQUIRE(it != checked.results.end());
        BOOST_CHECK(it->second.fValid);
    }
}

/* Mode off: a valid block connects without a report line */
BOOST_AUTO_TEST_CASE(off_valid_block)
{
    SetMode(false, false);
    const CTransaction tx = Spend({coinbaseTxns[0], coinbaseTxns[1]}, {&coinbaseKey, &coinbaseKey});
    std::string log;
    const CBlock block = Process(tx, log);
    BOOST_CHECK(IsTip(block));
    BOOST_CHECK_EQUAL(Lines(ReportLines(log)), "");
}

/* report: of two inputs only the one with an invalid signature is reported */
BOOST_AUTO_TEST_CASE(one_invalid_input_of_two)
{
    SetMode(true, false);
    const CTransaction tx = Spend({coinbaseTxns[0], coinbaseTxns[1]}, {&otherKey, &coinbaseKey});
    const int nHeight = Height() + 1;
    std::string log;
    const CBlock block = Process(tx, log);
    BOOST_CHECK_EQUAL(Lines(ReportLines(log)), Lines({ScriptReport(nHeight, block, tx, 0, SCRIPT_ERR_EVAL_FALSE)}));
}

/* The mode's checks leave the script execution cache as it is: after a valid block connected
 * under report, as after one connected with the mode off, CheckInputs of its transaction
 * returns a script check per input for every combination of block script flags */
BOOST_AUTO_TEST_CASE(caches_unchanged)
{
    const std::vector<size_t> expected(8, 2);
    for (const bool fOn : {true, false}) {
        SetMode(fOn, false);
        const unsigned int nFirst = fOn ? 0 : 2;
        const CTransaction tx = Spend({coinbaseTxns[nFirst], coinbaseTxns[nFirst + 1]}, {&coinbaseKey, &coinbaseKey});
        const std::vector<Coin> coins{CoinOf(tx.vin[0]), CoinOf(tx.vin[1])};
        std::string log;
        const CBlock block = Process(tx, log);
        BOOST_REQUIRE(IsTip(block));
        const std::vector<size_t> counts = ChecksPerFlags(tx, coins);
        BOOST_CHECK_MESSAGE(counts == expected, (fOn ? "report" : "off"));
    }
}

/* CheckReplayBlockSignature: real proof-of-stake blocks pass, and fail with one signature byte
 * changed; proof-of-work blocks pass, also with a changed signature byte */
BOOST_FIXTURE_TEST_CASE(block_signature_helper, BasicTestingSetup)
{
    for (const char* hex : {BLOCK_82204_HEX, BLOCK_82217_HEX, BLOCK_82994_HEX}) {
        CBlock block = ParseBlock(hex);
        block.GetHash();
        BOOST_REQUIRE(block.IsProofOfStake());
        BOOST_CHECK(CheckReplayBlockSignature(block));
        CBlock changed = block;
        changed.vchBlockSig[10] ^= 1;
        BOOST_CHECK(!CheckReplayBlockSignature(changed));
    }

    CBlock block644 = ParseBlock(BLOCK_644_HEX);
    BOOST_REQUIRE(block644.IsProofOfWork());
    BOOST_CHECK(CheckReplayBlockSignature(block644));
    block644.vchBlockSig[10] ^= 1;
    BOOST_CHECK(CheckReplayBlockSignature(block644));

    const CBlock genesis = Params().GenesisBlock();
    BOOST_REQUIRE(genesis.IsProofOfWork());
    BOOST_CHECK(CheckReplayBlockSignature(genesis));
}

BOOST_AUTO_TEST_SUITE_END()
