// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Snapshot of the chain parameters (task P0-20, plan section 0.2h).
//
// Every value below is copied by hand from chainparams.cpp, chainparamsbase.cpp,
// chainparamsseeds.h, kernel.cpp, primitives/block.cpp and util.cpp. The tests exist so that an accidental
// change of a parameter fails loudly: a deliberate change has to edit both
// places. Values that differ between the mainnet build and the
// low-difficulty build (--enable-low-difficulty-for-development) are pinned
// per build with LOW_DIFFICULTY_FOR_DEVELOPMENT; nothing is skipped.
//
// The other parameter sets are pinned elsewhere:
//  - unit-test globals (fork height 0, N-factor 0, ...): consensus_harness_tests
//    (P0-47, globals_at_defaults_*);
//  - the compiled-in AppInit defaults (fork height 1,890,000, token height
//    1,911,210, N-factor 21, epoch 21000) and the functional-test values
//    (epoch 10, N-factor 4, per-test fork height): only debug.log shows them,
//    see test/functional/feature_params_snapshot.py.
// The parameter table is in project/plans/phase0-test-safety-net.md (0.2h).

#include "chainparams.h"
#include "chainparamsbase.h"
#include "kernel.h"
#include "test/consensus_harness.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace consensus_harness;

namespace {

// Note: CreateChainParams() checks the genesis hash with Yassert. In a release
// build a failed Yassert calls StartShutdown(), which the test_bitcoin stub
// (test_bitcoin_main.cpp) turns into a failed run. The explicit hash checks
// below give the readable message.

std::string Hex(const std::vector<unsigned char>& v)
{
    return HexStr(v.begin(), v.end());
}

// "<16 address bytes in hex>:<port>"
std::string SeedString(const SeedSpec6& seed)
{
    return HexStr(seed.addr, seed.addr + sizeof(seed.addr)) + ":" + std::to_string(seed.port);
}

std::string Repeat(char c, size_t n)
{
    return std::string(n, c);
}

struct Checkpoint {
    int nHeight;
    const char* hash;
};

// Mainnet checkpoints (chainparams.cpp). Height 0 is the build's genesis and
// is checked separately. Note 1,750,000: no leading zeros, recorded as is.
const Checkpoint MAIN_CHECKPOINTS[] = {
    {15000, "00000082cab82d04354692fac3b83d19cbe3c3ab4b73610d0e73397545eb012e"},
    {30000, "0000000af2f6e71951d6e8befbd43a3dac36681b5095cb822b5c9c8de626e371"},
    {45000, "00000000591110a1411cf37739cde0c558c0c070aa38686d89b2e70fe39b654f"},
    {60000, "000000000c067c5df98a8285ff045c3ffee46eb64b248bc6622f6bdceb8558be"},
    {75000, "000000004ab2d277c8a056f55f32efa515a9931cb0404d60d0efc4f573412e66"},
    {90000, "000000000cfe2ec9d27b784c2627c3864d26e5829cc5b18b4eff37d863ed0675"},
    {105000, "00000000b0480b6a15fee32ee47d4b30dc82dc44ab680f1debb2ce2b13f73aab"},
    {120000, "00000000d843c5c818620d00c9352e0cc3bbf7fdb9d69093795fbfffff13c92a"},
    {135000, "0000000292cb16d5935e015a786d33f3228da23d92dfeb6ddff7249a3227f956"},
    {150000, "000000035d01ee7f75032c0293a7e6b1217d447fe3e000ede7911cb0520c60c7"},
    {165000, "00000001e790d65de9541af419465338220de69e3ffcbda427af2fc94741d321"},
    {180000, "000000054595380eb246887c79ff25fd997eebd3e59385830e4987c11153a31d"},
    {195000, "00000007c12dc0533ab2dbf66c56308ee0b259e1a5f09435381ea6d541b6a2c5"},
    {214998, "000000054e1a96d68bddda9b63276d604f33b6679d7dab079e4d241a1ee31be9"},
    {236895, "00000000a103442adaf96aa2af5cbc083e74cddbea558a7740c7a6781f561c08"},
    {259405, "00000019f67b00bc3482208d5b82393df96c648b510f24ab0d3318294a9bcde5"},
    {281002, "0000003076d627bd2e13e914a3032c2ef8a69de4792452c697bc23a6e158be2b"},
    {303953, "0000007c2fd3ca884a5b77e9b2a508cb617b75f2162beacafffa7193d2db7069"},
    {388314, "0000001d9a76c3a52288638568dad601a8a69ba7dc1038ff4d12b614de73a49a"},
    {420000, "000000368f2f40e3d2d9ed2a2220c8a424e3d80871c0b72c2bdeea35863aa779"},
    {465000, "0000000826f7b8b504fde92ba0388b647b2179d4b2c7cdfd232505cd7d79ac61"},
    {487658, "00000008dee4518a08084c5b65d647a57faf7ff28bc7d8786719ac13d21356d4"},
    {550177, "000000087d507052cb66d5a3770cf62f8ff9196ab861ffec3452d939b818567b"},
    {612177, "0000004bc02ebb045398fd8cdb249b790892a4fa3a8b03dbbbf5743c53f2a508"},
    {712177, "000001881da9ee73de48a54ebae7d0dec3b453d795b6704d62414e4b581e3aea"},
    {750000, "000001d36056e88f70b27d1415cdf7cedbafb4a7c1f2f78d5a8d9f713aee4a5a"},
    {800000, "000000ca19b5cd837c373f40b5e511866c90ce37945fd43fe13e55fe51c22c06"},
    {850000, "0000003aa373b33950c52daf60c82f6e5dae67dba2b7affd0e0a95560ace68ce"},
    {900000, "0000029f3ce6e19adbf7c08e051b91c55d4586d99223964abc0387170c375bfd"},
    {950000, "0000031c836162928d81fd50bc8db3e995a80cbdef27785f7b11f46c86b327bb"},
    {1000000, "00000173fff346c1f83138ee23c15debb96eea78b63c8dea5e02da5e1a775a54"},
    {1050000, "00000118eb156fca5d4cea18ccc56d51175c9fa03e2301adc96d36dedbc4dd39"},
    {1100000, "000001875f4f515559d683c750db1952a1e5b896f6f4390023c6d445fef63f64"},
    {1150000, "00000979215bbb8205c42961b10b22900aa5c127e3a61061f340541295e65bf1"},
    {1200000, "0000084191c31d1c27cba87fbc4308b7e67cff8e89f13fcee51958db0e3918ee"},
    {1250000, "00000d72f9b23ae645eb875af19aa30279c597429ec5652da0e39a0edd5bd4f9"},
    {1300000, "00000a3336e2c336c0182945837573c5ffe68550f77393244d4bf26d36ae0f6c"},
    {1350000, "00000b6d09db4e5443094d05f8ea061e2305c44a787b5b4e3cdab9ddfa78034b"},
    {1400000, "0000061aa7e66eb0a1adcf5f4cf773eb6351a5e0905a3794cca135edc72799ab"},
    {1450000, "00000a99ea3603a90460600e8c1f4cb688abf8fcb8fc9d6a1848917690df049f"},
    {1500000, "0000072187440ce4016fa230c177a8967840d475278eff633dce66837e550f9e"},
    {1550000, "000005b5842fe8e453b7360c50cbe580ef4874d2b8976a3e5d336dc5e34b4683"},
    {1600000, "0000088ced0e7c97afb9635b315f286f94a25eb5d0490ce7b12e2ce0905c3f31"},
    {1650000, "000007439ff054f2307766a5a30eff4fc0268de68e72c76efde767ccee91830c"},
    {1700000, "00000797ae41dbf32c6cb73c1254fbd804b068263ef2de77755fb1829dd2ab1d"},
    {1750000, "d1806e1fa74087ef43fe0a8b37e558c1f9b523529f17b8cb91ca619dd90e4eec"},
    {1800000, "00000670c3f5b879d8b2b0c403c824af78cf95f536d2da66b198efcf9d9ff355"},
    {1850000, "00000e1b13b2b08d36598664d508a38500c59fcff4cf3d3746de0738b6eef457"},
    {1890005, "00000dfd4e2286daee184a67b9266e40b8c1c5daf3a29a2321fd23e6c2da62e2"},
    {1911210, "000009e3b1cc249ba64c3749430b96cf0f3c25acbb2bd3cb0b69e3b28288607b"},
};

struct StakeCheckpoint {
    int nHeight;
    uint32_t nChecksum;
};

// Stake-modifier checkpoints (mapStakeModifierCheckpoints, kernel.cpp).
const StakeCheckpoint STAKE_CHECKPOINTS[] = {
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    {0, 0x0e00670bu},
#else
    {0, 0xfd11f4e7u},
#endif
    {15000, 0x085e9cafu},
    {30000, 0x3f123e2cu},
    {45000, 0x3e2ecf4fu},
    {60000, 0x1e8458eau},
    {75000, 0xd72d1395u},
    {90000, 0x7dce92ffu},
    {105000, 0x57cc71e0u},
    {120000, 0x4442fccbu},
    {135000, 0x4cea240fu},
    {150000, 0xd06bea80u},
    {165000, 0x697caae6u},
    {180000, 0x5d6f2627u},
    {195000, 0x054b2756u},
    {214998, 0xcbb62f73u},
    {236895, 0x05ee6bd6u},
    {259405, 0xb31abd61u},
    {281002, 0x95174906u},
    {303953, 0x4ba15dbcu},
    {388314, 0x97f8e820u},
    {420000, 0x9b6c9d80u},
    {465000, 0x1b1a219cu},
    {487658, 0xe7d5a3bcu},
    {550177, 0x8a1e3994u},
    {612177, 0x949c4dc0u},
    {712177, 0xad692cc0u},
};

const int64_t CHAIN_START_TIME = 1367991200;
const char* GENESIS_MERKLE_ROOT = "678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f";

// Fields that main and regtest share (both builds).
void CheckSharedFields(const CChainParams& params)
{
    const Consensus::Params& c = params.GetConsensus();
    BOOST_CHECK_EQUAL(c.nPowTargetSpacing, 60);
    BOOST_CHECK_EQUAL(c.nMinerConfirmationWindow, 6U);
    BOOST_CHECK_EQUAL(c.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit, 28);
    BOOST_CHECK_EQUAL(c.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime, 1199145601);
    BOOST_CHECK_EQUAL(c.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout, 1230767999);
    BOOST_CHECK_EQUAL(c.vDeployments[Consensus::DEPLOYMENT_CSV].bit, 0);
    BOOST_CHECK_EQUAL(c.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime, 1462060800);
    BOOST_CHECK_EQUAL(c.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout, 1493596800);
    BOOST_CHECK_EQUAL(c.nStakeMaxAge, 60 * 60 * 24 * 90);
    BOOST_CHECK_EQUAL(c.nStakeMinAge, 60 * 60 * 24 * 30);
    BOOST_CHECK_EQUAL(c.nModifierInterval, 6 * 60 * 60);

    // Message start and P2P port: regtest uses the same as main (review A3).
    const CMessageHeader::MessageStartChars& start = params.MessageStart();
    BOOST_CHECK_EQUAL(HexStr(start, start + CMessageHeader::MESSAGE_START_SIZE), "d9e6e7e5");
    BOOST_CHECK_EQUAL(params.GetDefaultPort(), 7688);
    BOOST_CHECK_EQUAL(params.PruneAfterHeight(), 100000U);

    BOOST_CHECK_EQUAL(Hex(params.Base58Prefix(CChainParams::PUBKEY_ADDRESS)), "4d");  // 77
    BOOST_CHECK_EQUAL(Hex(params.Base58Prefix(CChainParams::SCRIPT_ADDRESS)), "8b");  // 139
    BOOST_CHECK_EQUAL(Hex(params.Base58Prefix(CChainParams::SECRET_KEY)), "cd");      // 205
    BOOST_CHECK_EQUAL(Hex(params.Base58Prefix(CChainParams::EXT_PUBLIC_KEY)), "0488b21e");
    BOOST_CHECK_EQUAL(Hex(params.Base58Prefix(CChainParams::EXT_SECRET_KEY)), "0488ade4");

    // No DNS seeds (all commented out); fixed seeds from pnSeed6_main, which
    // is empty in the low-difficulty build (chainparamsseeds.h).
    BOOST_CHECK(params.DNSSeeds().empty());
    std::vector<std::string> seeds;
    for (const SeedSpec6& seed : params.FixedSeeds())
        seeds.push_back(SeedString(seed));
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    const std::vector<std::string> expectedSeeds = {
        "00000000000000000000ffff6020d23a:7688", // 96.32.210.58
        "00000000000000000000ffff3e92e0f5:7688", // 62.146.224.245
        "00000000000000000000ffff444f623e:7688", // 68.79.98.62
        "00000000000000000000ffff4c61d152:7688", // 76.97.209.82
        "00000000000000000000ffff62fb5c94:7688", // 98.251.92.148
        "00000000000000000000ffff496adad5:7688", // 73.106.218.213
        "00000000000000000000ffff2d1e2d79:7688", // 45.30.45.121
    };
#else
    const std::vector<std::string> expectedSeeds;
#endif
    BOOST_CHECK_EQUAL_COLLECTIONS(seeds.begin(), seeds.end(), expectedSeeds.begin(), expectedSeeds.end());

    BOOST_CHECK(!params.DefaultConsistencyChecks());
    BOOST_CHECK(params.RequireStandard());
    BOOST_CHECK(!params.MineBlocksOnDemand());
}

// Genesis block built by CreateGenesisBlock (chainparams.cpp).
void CheckGenesis(const CChainParams& params, const std::string& hash, uint32_t nBits, uint32_t nNonce)
{
    const CBlock& genesis = params.GenesisBlock();
    BOOST_CHECK_EQUAL(genesis.GetHash().GetHex(), hash);
    BOOST_CHECK_EQUAL(params.GetConsensus().hashGenesisBlock.GetHex(), hash);
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.GetHex(), GENESIS_MERKLE_ROOT);
    BOOST_CHECK(genesis.hashPrevBlock.IsNull());
    BOOST_CHECK_EQUAL(genesis.nVersion, 1);
    BOOST_CHECK_EQUAL(genesis.nTime, CHAIN_START_TIME + 20);
    BOOST_CHECK_EQUAL(genesis.nBits, nBits);
    BOOST_CHECK_EQUAL(genesis.nBits, params.GetConsensus().powLimit.GetCompact());
    BOOST_CHECK_EQUAL(genesis.nNonce, nNonce);
    BOOST_REQUIRE_EQUAL(genesis.vtx.size(), 1U);
    const CTransaction& tx = genesis.vtx[0];
    BOOST_CHECK_EQUAL(tx.nVersion, 1);
    BOOST_CHECK_EQUAL(tx.nTime, CHAIN_START_TIME);
    BOOST_CHECK_EQUAL(tx.vin.size(), 1U);
    BOOST_CHECK_EQUAL(tx.vout.size(), 1U);
    BOOST_CHECK_EQUAL(tx.GetHash().GetHex(), GENESIS_MERKLE_ROOT);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainparams_snapshot_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(main_consensus_params)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(params->NetworkIDString(), "main");
    const Consensus::Params& c = params->GetConsensus();

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(c.powLimit.getuint256().GetHex(), Repeat('0', 5) + Repeat('f', 59)); // ~0 >> 20
    BOOST_CHECK_EQUAL(c.powLimit.GetCompact(), 0x1e0fffffU);
    BOOST_CHECK_EQUAL(c.initialHashTarget.getuint256().GetHex(), Repeat('0', 5) + Repeat('f', 59));
    BOOST_CHECK_EQUAL(c.initialHashTarget.GetCompact(), 0x1e0fffffU);
    BOOST_CHECK_EQUAL(c.initialMoneySupply, 0);
#else
    BOOST_CHECK_EQUAL(c.powLimit.getuint256().GetHex(), "1" + Repeat('f', 63)); // ~0 >> 3
    BOOST_CHECK_EQUAL(c.powLimit.GetCompact(), 0x201fffffU);
    BOOST_CHECK_EQUAL(c.initialHashTarget.getuint256().GetHex(), Repeat('0', 2) + Repeat('f', 62)); // ~0 >> 8
    BOOST_CHECK_EQUAL(c.initialHashTarget.GetCompact(), 0x2000ffffU);
    BOOST_CHECK_EQUAL(c.initialMoneySupply, 100000000000000LL); // 1E14
#endif
    BOOST_CHECK_EQUAL(c.BIP65Height, 1890000);
    BOOST_CHECK_EQUAL(c.BIP68Height, 1890000);
    BOOST_CHECK_EQUAL(c.HeliopolisHardforkHeight, 1890000);
    BOOST_CHECK_EQUAL(c.nPowTargetTimespan, 21000 * 60);
    BOOST_CHECK_EQUAL(c.DifficultyAdjustmentInterval(), 21000);
    BOOST_CHECK(!c.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK(!c.fPowNoRetargeting);
    BOOST_CHECK_EQUAL(c.nRuleChangeActivationThreshold, 19950U);
    CheckSharedFields(*params);
}

BOOST_AUTO_TEST_CASE(main_genesis)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::MAIN);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    CheckGenesis(*params, "0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5", 0x1e0fffff, 127357);
#else
    CheckGenesis(*params, "1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848", 0x201fffff, 127358);
#endif
}

BOOST_AUTO_TEST_CASE(main_network_flags_and_tx_data)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::MAIN);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK(params->MiningRequiresPeers());
#else
    BOOST_CHECK(!params->MiningRequiresPeers());
#endif
    const ChainTxData& txData = params->TxData();
    BOOST_CHECK_EQUAL(txData.nTime, 1749704574);
    BOOST_CHECK_EQUAL(txData.nTxCount, 2525586);
    BOOST_CHECK_EQUAL(txData.dTxRate, 0.0005);
}

BOOST_AUTO_TEST_CASE(main_checkpoints)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::MAIN);
    const MapCheckpoints& checkpoints = params->Checkpoints().mapCheckpoints;

    std::vector<std::string> actual;
    for (const auto& entry : checkpoints)
        actual.push_back(std::to_string(entry.first) + ":" + entry.second.GetHex());
    std::vector<std::string> expected;
    expected.push_back("0:" + params->GetConsensus().hashGenesisBlock.GetHex());
    for (const Checkpoint& cp : MAIN_CHECKPOINTS)
        expected.push_back(std::to_string(cp.nHeight) + ":" + cp.hash);

    BOOST_CHECK_EQUAL(checkpoints.size(), 51U);
    BOOST_CHECK_EQUAL_COLLECTIONS(actual.begin(), actual.end(), expected.begin(), expected.end());
}

// CRegTestParams: never used by the functional tests (they run main params,
// review A3), but selectable with -regtest. Same message start and P2P port
// as main; not affected by the low-difficulty flag except for the fixed
// seeds, which it takes from pnSeed6_main.
BOOST_AUTO_TEST_CASE(regtest_params)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(params->NetworkIDString(), "regtest");
    const Consensus::Params& c = params->GetConsensus();

    BOOST_CHECK_EQUAL(c.powLimit.getuint256().GetHex(), "7" + Repeat('f', 63));
    BOOST_CHECK_EQUAL(c.powLimit.GetCompact(), 0x207fffffU);
    BOOST_CHECK_EQUAL(c.initialHashTarget.getuint256().GetHex(), "7" + Repeat('f', 63));
    BOOST_CHECK_EQUAL(c.initialMoneySupply, 100000000000000LL); // 1E14
    BOOST_CHECK_EQUAL(c.BIP65Height, 0);
    BOOST_CHECK_EQUAL(c.BIP68Height, 0);
    BOOST_CHECK_EQUAL(c.HeliopolisHardforkHeight, 0);
    BOOST_CHECK_EQUAL(c.nPowTargetTimespan, 10);
    BOOST_CHECK_EQUAL(c.DifficultyAdjustmentInterval(), 0); // 10 / 60
    BOOST_CHECK(c.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK(c.fPowNoRetargeting);
    BOOST_CHECK_EQUAL(c.nRuleChangeActivationThreshold, 2U);
    CheckSharedFields(*params);

    CheckGenesis(*params, "08603b3b7020256db3a4a1e2e1d18cebd51f7000d0ba1a32e65eabeb449f4e2e", 0x207fffff, 127357);
    BOOST_CHECK(!params->MiningRequiresPeers());

    const MapCheckpoints& checkpoints = params->Checkpoints().mapCheckpoints;
    BOOST_REQUIRE_EQUAL(checkpoints.size(), 1U);
    BOOST_CHECK_EQUAL(checkpoints.begin()->first, 0);
    BOOST_CHECK(checkpoints.begin()->second == c.hashGenesisBlock);

    BOOST_CHECK_EQUAL(params->TxData().nTime, 0);
    BOOST_CHECK_EQUAL(params->TxData().nTxCount, 0);
    BOOST_CHECK_EQUAL(params->TxData().dTxRate, 0);
}

// Base parameters (RPC port, data directory). -testnet has base parameters
// but no chain parameters: CreateChainParams("test") throws.
BOOST_AUTO_TEST_CASE(base_params_and_chain_names)
{
    const std::unique_ptr<CBaseChainParams> mainnet = CreateBaseChainParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(mainnet->RPCPort(), 7687);
    BOOST_CHECK_EQUAL(mainnet->DataDir(), "");
    const std::unique_ptr<CBaseChainParams> test = CreateBaseChainParams(CBaseChainParams::TESTNET);
    BOOST_CHECK_EQUAL(test->RPCPort(), 17687);
    BOOST_CHECK_EQUAL(test->DataDir(), "testnet3");
    const std::unique_ptr<CBaseChainParams> regtest = CreateBaseChainParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(regtest->RPCPort(), 17687);
    BOOST_CHECK_EQUAL(regtest->DataDir(), "regtest");
    BOOST_CHECK_THROW(CreateBaseChainParams("foo"), std::runtime_error);

    BOOST_CHECK_EQUAL(CBaseChainParams::TESTNET, "test");
    BOOST_CHECK_THROW(CreateChainParams(CBaseChainParams::TESTNET), std::runtime_error);
    BOOST_CHECK_THROW(CreateChainParams("foo"), std::runtime_error);
}

// Time constants that consensus code reads: chain start (genesis time - 20)
// and the compiled-in nYac10HardforkTime (util.cpp; AppInit does not change
// it). consensus_harness_tests compares nYac10HardforkTime with the harness
// constant only; this pins the literal.
BOOST_AUTO_TEST_CASE(time_constants)
{
    BOOST_CHECK_EQUAL(nChainStartTime, CHAIN_START_TIME);
    BOOST_CHECK_EQUAL(CHAIN_START_TIME, 1367991200);
    BOOST_CHECK_EQUAL(nYac10HardforkTime, 1619048730);
    BOOST_CHECK_EQUAL(DEFAULT_YAC10_HARDFORK_TIME, 1619048730);
}

/* Stake-modifier checkpoints (kernel.cpp). The table is file-static, so it
 * is read through CheckStakeModifierCheckpoints, which only checks it while
 * the next height is below the fork height (review A4): mainnet globals.
 * Every pinned checksum is accepted and a changed one rejected; a sweep over
 * all heights up to 2,000,000 finds exactly the pinned heights (no
 * checkpoint value is 0 or 0xffffffff, so a checkpoint height rejects at
 * least one of the two). With fTestNet the testnet table (height 0 only)
 * is used. Extends the spot checks in kernel_tests. */
BOOST_FIXTURE_TEST_CASE(stake_modifier_checkpoints, ConsensusTestingSetup)
{
    chain.StartOnExistingGenesis();
    chain.SetActiveTip(chain.Tip());
    globals.UseMainnetGlobals();

    std::vector<int> expectedHeights;
    for (const StakeCheckpoint& cp : STAKE_CHECKPOINTS) {
        BOOST_CHECK_MESSAGE(CheckStakeModifierCheckpoints(cp.nHeight, cp.nChecksum),
                            "checksum not accepted at height " << cp.nHeight);
        BOOST_CHECK_MESSAGE(!CheckStakeModifierCheckpoints(cp.nHeight, cp.nChecksum ^ 1),
                            "changed checksum accepted at height " << cp.nHeight);
        expectedHeights.push_back(cp.nHeight);
    }
    BOOST_CHECK_EQUAL(expectedHeights.size(), 26U);

    const int nSweepEnd = 2000000;
    std::vector<int> foundHeights;
    for (int nHeight = 0; nHeight <= nSweepEnd; ++nHeight) {
        if (!CheckStakeModifierCheckpoints(nHeight, 0) || !CheckStakeModifierCheckpoints(nHeight, 0xffffffffu))
            foundHeights.push_back(nHeight);
    }
    BOOST_CHECK_EQUAL_COLLECTIONS(foundHeights.begin(), foundHeights.end(), expectedHeights.begin(), expectedHeights.end());

    globals.SetTestNet(true);
    BOOST_CHECK(CheckStakeModifierCheckpoints(0, 0x0e00670bu));
    BOOST_CHECK(!CheckStakeModifierCheckpoints(0, 0x0e00670bu ^ 1));
    std::vector<int> foundTestNet;
    for (int nHeight = 0; nHeight <= nSweepEnd; ++nHeight) {
        if (!CheckStakeModifierCheckpoints(nHeight, 0) || !CheckStakeModifierCheckpoints(nHeight, 0xffffffffu))
            foundTestNet.push_back(nHeight);
    }
    BOOST_REQUIRE_EQUAL(foundTestNet.size(), 1U);
    BOOST_CHECK_EQUAL(foundTestNet[0], 0);
}

BOOST_AUTO_TEST_SUITE_END()
