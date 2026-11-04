// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The chain parameters of mainnet and regtest (CreateChainParams), the base parameters of
// every chain name (CreateBaseChainParams), how a chain is selected (SelectParams,
// ChainNameFromCommandLine), the chain selection help text and the version bits overrides.
//
// The low-difficulty build has its own mainnet proof-of-work limit, genesis block, initial
// money supply and fixed seeds; those values have their own part for that build.

#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/params.h"
#include "uint256.h"
#include "util.h"

#include "test/test_bitcoin.h"

#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

/** Selects mainnet again when it goes out of scope, as the fixture left it. */
struct SelectMainOnExit {
    ~SelectMainOnExit() { SelectParams(CBaseChainParams::MAIN); }
};

/** Predicate for BOOST_CHECK_EXCEPTION: the exception's message is exactly the expected one. */
struct HasMessage {
    explicit HasMessage(const std::string& message) : m_message(message) {}
    bool operator()(const std::runtime_error& e) const
    {
        BOOST_CHECK_EQUAL(e.what(), m_message);
        return m_message == e.what();
    }
    const std::string m_message;
};

std::vector<unsigned char> Bytes(std::initializer_list<unsigned char> bytes) { return bytes; }

const std::string LAST_MAIN_CHECKPOINT = "000009e3b1cc249ba64c3749430b96cf0f3c25acbb2bd3cb0b69e3b28288607b";
const std::string GENESIS_MERKLE_ROOT = "678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f";

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainparams_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(main_identity_and_genesis)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(params->NetworkIDString(), "main");

    const CBlock& genesis = params->GenesisBlock();
    BOOST_CHECK(genesis.GetHash() == params->GetConsensus().hashGenesisBlock);
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.GetHex(), GENESIS_MERKLE_ROOT);
    BOOST_CHECK(genesis.hashPrevBlock.IsNull());
    BOOST_CHECK_EQUAL(genesis.nVersion, 1);
    BOOST_CHECK_EQUAL(genesis.nTime, 1367991220U);
    BOOST_REQUIRE_EQUAL(genesis.vtx.size(), 1U);
    BOOST_CHECK_EQUAL(genesis.vtx[0].nTime, 1367991200U);
    BOOST_CHECK_EQUAL(genesis.vtx[0].nVersion, 1);
    BOOST_REQUIRE_EQUAL(genesis.vtx[0].vout.size(), 1U);
    BOOST_CHECK(genesis.vtx[0].vout[0].IsEmpty());
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    const CMessageHeader::MessageStartChars& start = params->MessageStart();
    BOOST_CHECK_EQUAL(int(start[0]), 0xd9);
    BOOST_CHECK_EQUAL(int(start[1]), 0xe6);
    BOOST_CHECK_EQUAL(int(start[2]), 0xe7);
    BOOST_CHECK_EQUAL(int(start[3]), 0xe5);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 7688);
    BOOST_CHECK_EQUAL(params->GetConsensus().hashGenesisBlock.GetHex(),
                      "0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5");
    BOOST_CHECK_EQUAL(genesis.nNonce, 127357U);
    BOOST_CHECK_EQUAL(genesis.nBits, 0x1e0fffffU);
#else
    BOOST_CHECK_EQUAL(params->GetConsensus().hashGenesisBlock.GetHex(),
                      "1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848");
    BOOST_CHECK_EQUAL(genesis.nNonce, 127358U);
    BOOST_CHECK_EQUAL(genesis.nBits, 0x201fffffU);
#endif
}

BOOST_AUTO_TEST_CASE(main_consensus)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.BIP65Height, 1890000);
    BOOST_CHECK_EQUAL(consensus.BIP68Height, 1890000);
    BOOST_CHECK_EQUAL(consensus.HeliopolisHardforkHeight, 1890000);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 60);
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan, 21000 * 60);
    BOOST_CHECK_EQUAL(consensus.DifficultyAdjustmentInterval(), 21000);
    BOOST_CHECK(!consensus.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK(!consensus.fPowNoRetargeting);
    BOOST_CHECK_EQUAL(consensus.nRuleChangeActivationThreshold, 19950U);
    BOOST_CHECK_EQUAL(consensus.nMinerConfirmationWindow, 6U);
    BOOST_CHECK_EQUAL(consensus.nStakeMaxAge, 90 * 24 * 60 * 60);
    BOOST_CHECK_EQUAL(consensus.nStakeMinAge, 30 * 24 * 60 * 60);
    BOOST_CHECK_EQUAL(consensus.nModifierInterval, 6 * 60 * 60);

    const Consensus::BIP9Deployment& dummy = consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY];
    BOOST_CHECK_EQUAL(dummy.bit, 28);
    BOOST_CHECK_EQUAL(dummy.nStartTime, 1199145601);
    BOOST_CHECK_EQUAL(dummy.nTimeout, 1230767999);
    const Consensus::BIP9Deployment& csv = consensus.vDeployments[Consensus::DEPLOYMENT_CSV];
    BOOST_CHECK_EQUAL(csv.bit, 0);
    BOOST_CHECK_EQUAL(csv.nStartTime, 1462060800);
    BOOST_CHECK_EQUAL(csv.nTimeout, 1493596800);

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(consensus.powLimit.GetCompact(), 0x1e0fffffU);
    BOOST_CHECK_EQUAL(consensus.initialHashTarget.GetCompact(), 0x1e0fffffU);
    BOOST_CHECK_EQUAL(consensus.initialMoneySupply, 0);
#else
    BOOST_CHECK_EQUAL(consensus.powLimit.GetCompact(), 0x201fffffU);
    BOOST_CHECK_EQUAL(consensus.initialHashTarget.GetCompact(), 0x2000ffffU);
    BOOST_CHECK_EQUAL(consensus.initialMoneySupply, 100000000000000LL);
#endif
}

BOOST_AUTO_TEST_CASE(main_policy_and_addresses)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::MAIN);

    BOOST_CHECK(!params->DefaultConsistencyChecks());
    BOOST_CHECK(params->RequireStandard());
    BOOST_CHECK(!params->MineBlocksOnDemand());
    BOOST_CHECK_EQUAL(params->PruneAfterHeight(), 100000U);
    BOOST_CHECK(params->DNSSeeds().empty());
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK(params->MiningRequiresPeers());
    BOOST_CHECK_EQUAL(params->FixedSeeds().size(), 7U);
#else
    BOOST_CHECK(!params->MiningRequiresPeers());
    BOOST_CHECK(params->FixedSeeds().empty());
#endif

    BOOST_CHECK(params->Base58Prefix(CChainParams::PUBKEY_ADDRESS) == Bytes({77}));
    BOOST_CHECK(params->Base58Prefix(CChainParams::SCRIPT_ADDRESS) == Bytes({139}));
    BOOST_CHECK(params->Base58Prefix(CChainParams::SECRET_KEY) == Bytes({205}));
    BOOST_CHECK(params->Base58Prefix(CChainParams::EXT_PUBLIC_KEY) == Bytes({0x04, 0x88, 0xB2, 0x1E}));
    BOOST_CHECK(params->Base58Prefix(CChainParams::EXT_SECRET_KEY) == Bytes({0x04, 0x88, 0xAD, 0xE4}));
}

BOOST_AUTO_TEST_CASE(main_checkpoints_and_tx_data)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::MAIN);

    const MapCheckpoints& checkpoints = params->Checkpoints().mapCheckpoints;
    BOOST_REQUIRE_EQUAL(checkpoints.size(), 51U);
    BOOST_CHECK_EQUAL(checkpoints.begin()->first, 0);
    BOOST_CHECK(checkpoints.begin()->second == params->GetConsensus().hashGenesisBlock);
    BOOST_CHECK_EQUAL(checkpoints.rbegin()->first, 1911210);
    BOOST_CHECK_EQUAL(checkpoints.rbegin()->second.GetHex(), LAST_MAIN_CHECKPOINT);
    BOOST_CHECK_EQUAL(checkpoints.at(15000).GetHex(), "00000082cab82d04354692fac3b83d19cbe3c3ab4b73610d0e73397545eb012e");

    const ChainTxData& txData = params->TxData();
    BOOST_CHECK_EQUAL(txData.nTime, 1749704574);
    BOOST_CHECK_EQUAL(txData.nTxCount, 2525586);
    BOOST_CHECK_EQUAL(txData.dTxRate, 0.0005);
}

BOOST_AUTO_TEST_CASE(regtest_parameters)
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(params->NetworkIDString(), "regtest");
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock.GetHex(),
                      "08603b3b7020256db3a4a1e2e1d18cebd51f7000d0ba1a32e65eabeb449f4e2e");
    BOOST_CHECK(params->GenesisBlock().GetHash() == consensus.hashGenesisBlock);
    BOOST_CHECK_EQUAL(params->GenesisBlock().hashMerkleRoot.GetHex(), GENESIS_MERKLE_ROOT);
    BOOST_CHECK_EQUAL(params->GenesisBlock().nNonce, 127357U);
    BOOST_CHECK_EQUAL(params->GenesisBlock().nBits, 0x207fffffU);
    BOOST_CHECK_EQUAL(consensus.powLimit.GetCompact(), 0x207fffffU);
    BOOST_CHECK_EQUAL(consensus.initialHashTarget.GetCompact(), 0x207fffffU);
    BOOST_CHECK_EQUAL(consensus.initialMoneySupply, 100000000000000LL);

    BOOST_CHECK_EQUAL(consensus.BIP65Height, 0);
    BOOST_CHECK_EQUAL(consensus.BIP68Height, 0);
    BOOST_CHECK_EQUAL(consensus.HeliopolisHardforkHeight, 0);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 60);
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan, 10);
    BOOST_CHECK(consensus.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK(consensus.fPowNoRetargeting);
    BOOST_CHECK_EQUAL(consensus.nRuleChangeActivationThreshold, 2U);
    BOOST_CHECK_EQUAL(consensus.nMinerConfirmationWindow, 6U);

    BOOST_CHECK(!params->MiningRequiresPeers());
    BOOST_CHECK(!params->DefaultConsistencyChecks());
    BOOST_CHECK(params->RequireStandard());
    BOOST_CHECK(!params->MineBlocksOnDemand());

    const MapCheckpoints& checkpoints = params->Checkpoints().mapCheckpoints;
    BOOST_REQUIRE_EQUAL(checkpoints.size(), 1U);
    BOOST_CHECK_EQUAL(checkpoints.begin()->first, 0);
    BOOST_CHECK(checkpoints.begin()->second == consensus.hashGenesisBlock);

    const ChainTxData& txData = params->TxData();
    BOOST_CHECK_EQUAL(txData.nTime, 0);
    BOOST_CHECK_EQUAL(txData.nTxCount, 0);
    BOOST_CHECK_EQUAL(txData.dTxRate, 0);
}

BOOST_AUTO_TEST_CASE(create_chain_params_unknown_chain)
{
    // The base parameters know a testnet, the chain parameters do not.
    BOOST_CHECK_EXCEPTION(CreateChainParams(CBaseChainParams::TESTNET), std::runtime_error,
                          HasMessage("CreateChainParams: Unknown chain test."));
    BOOST_CHECK_EXCEPTION(CreateChainParams("nosuchchain"), std::runtime_error,
                          HasMessage("CreateChainParams: Unknown chain nosuchchain."));
    BOOST_CHECK_EXCEPTION(CreateChainParams(""), std::runtime_error,
                          HasMessage("CreateChainParams: Unknown chain ."));
}

BOOST_AUTO_TEST_CASE(base_params)
{
    BOOST_CHECK_EQUAL(CBaseChainParams::MAIN, "main");
    BOOST_CHECK_EQUAL(CBaseChainParams::TESTNET, "test");
    BOOST_CHECK_EQUAL(CBaseChainParams::REGTEST, "regtest");

    const std::unique_ptr<CBaseChainParams> main = CreateBaseChainParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(main->RPCPort(), 7687);
    BOOST_CHECK_EQUAL(main->DataDir(), "");

    const std::unique_ptr<CBaseChainParams> test = CreateBaseChainParams(CBaseChainParams::TESTNET);
    BOOST_CHECK_EQUAL(test->RPCPort(), 17687);
    BOOST_CHECK_EQUAL(test->DataDir(), "testnet3");

    const std::unique_ptr<CBaseChainParams> regtest = CreateBaseChainParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(regtest->RPCPort(), 17687);
    BOOST_CHECK_EQUAL(regtest->DataDir(), "regtest");

    BOOST_CHECK_EXCEPTION(CreateBaseChainParams("nosuchchain"), std::runtime_error,
                          HasMessage("CreateBaseChainParams: Unknown chain nosuchchain."));
}

BOOST_AUTO_TEST_CASE(select_params)
{
    SelectMainOnExit restore;

    BOOST_CHECK_EQUAL(Params().NetworkIDString(), "main");
    BOOST_CHECK_EQUAL(BaseParams().DataDir(), "");

    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().NetworkIDString(), "regtest");
    BOOST_CHECK_EQUAL(Params().GetConsensus().HeliopolisHardforkHeight, 0);
    BOOST_CHECK_EQUAL(BaseParams().DataDir(), "regtest");
    BOOST_CHECK_EQUAL(BaseParams().RPCPort(), 17687);

    SelectBaseParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(BaseParams().DataDir(), "");
    BOOST_CHECK_EQUAL(BaseParams().RPCPort(), 7687);
    BOOST_CHECK_EQUAL(Params().NetworkIDString(), "regtest");

    // The base parameters are switched before the chain parameters are created, so a failed
    // selection of testnet leaves testnet's base parameters with the earlier chain parameters.
    BOOST_CHECK_EXCEPTION(SelectParams(CBaseChainParams::TESTNET), std::runtime_error,
                          HasMessage("CreateChainParams: Unknown chain test."));
    BOOST_CHECK_EQUAL(BaseParams().DataDir(), "testnet3");
    BOOST_CHECK_EQUAL(BaseParams().RPCPort(), 17687);
    BOOST_CHECK_EQUAL(Params().NetworkIDString(), "regtest");

    BOOST_CHECK_EXCEPTION(SelectBaseParams("nosuchchain"), std::runtime_error,
                          HasMessage("CreateBaseChainParams: Unknown chain nosuchchain."));
    BOOST_CHECK_EQUAL(BaseParams().DataDir(), "testnet3");

    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(Params().NetworkIDString(), "main");
    BOOST_CHECK_EQUAL(BaseParams().DataDir(), "");
    BOOST_CHECK_EQUAL(BaseParams().RPCPort(), 7687);
}

BOOST_AUTO_TEST_CASE(chain_name_from_command_line)
{
    BOOST_REQUIRE(!gArgs.IsArgSet("-regtest"));
    BOOST_REQUIRE(!gArgs.IsArgSet("-testnet"));
    BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::MAIN);
    {
        ArgGuard regtest("-regtest", "");
        BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::REGTEST);
    }
    {
        ArgGuard testnet("-testnet", "1");
        BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::TESTNET);
    }
    {
        ArgGuard regtest("-regtest", "1");
        ArgGuard testnet("-testnet", "1");
        BOOST_CHECK_EXCEPTION(ChainNameFromCommandLine(), std::runtime_error,
                              HasMessage("Invalid combination of -regtest and -testnet."));
    }
    {
        ArgGuard regtest("-regtest", "0");
        ArgGuard testnet("-testnet", "0");
        BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::MAIN);
    }
    {
        // One of the two switched off leaves the other in charge.
        ArgGuard regtest("-regtest", "1");
        ArgGuard testnet("-testnet", "0");
        BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::REGTEST);
    }
    BOOST_CHECK(!gArgs.IsArgSet("-regtest"));
    BOOST_CHECK(!gArgs.IsArgSet("-testnet"));
    BOOST_CHECK_EQUAL(ChainNameFromCommandLine(), CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(params_help_messages)
{
    const std::string group = HelpMessageGroup("Chain selection options:");
    const std::string testnet = HelpMessageOpt("-testnet", "Use the test chain");

    std::string withDebug = "before\n";
    AppendParamsHelpMessages(withDebug, true);
    BOOST_CHECK_EQUAL(withDebug.substr(0, 7), "before\n");
    BOOST_CHECK_EQUAL(withDebug.find(group), 7U);
    BOOST_CHECK(withDebug.find(testnet) != std::string::npos);
    BOOST_CHECK(withDebug.find("-regtest") != std::string::npos);
    BOOST_CHECK(withDebug.find("Enter regression test mode") != std::string::npos);
    BOOST_CHECK(withDebug.find("-regtest") > withDebug.find("-testnet"));

    std::string withoutDebug;
    AppendParamsHelpMessages(withoutDebug, false);
    BOOST_CHECK_EQUAL(withoutDebug, group + testnet);

    std::string byDefault;
    AppendParamsHelpMessages(byDefault);
    BOOST_CHECK_EQUAL(byDefault, withDebug.substr(7));
}

BOOST_AUTO_TEST_CASE(update_version_bits_parameters_member)
{
    std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::REGTEST);
    params->UpdateVersionBitsParameters(Consensus::DEPLOYMENT_TESTDUMMY, 100, 200);

    const Consensus::Params& consensus = params->GetConsensus();
    const Consensus::BIP9Deployment& dummy = consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY];
    BOOST_CHECK_EQUAL(dummy.bit, 28);
    BOOST_CHECK_EQUAL(dummy.nStartTime, 100);
    BOOST_CHECK_EQUAL(dummy.nTimeout, 200);
    const Consensus::BIP9Deployment& csv = consensus.vDeployments[Consensus::DEPLOYMENT_CSV];
    BOOST_CHECK_EQUAL(csv.bit, 0);
    BOOST_CHECK_EQUAL(csv.nStartTime, 1462060800);
    BOOST_CHECK_EQUAL(csv.nTimeout, 1493596800);

    // Other instances keep their values.
    const std::unique_ptr<CChainParams> fresh = CreateChainParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(fresh->GetConsensus().vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime, 1199145601);
    BOOST_CHECK_EQUAL(fresh->GetConsensus().vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout, 1230767999);
}

BOOST_AUTO_TEST_CASE(update_version_bits_parameters_selected)
{
    SelectMainOnExit restore;
    SelectParams(CBaseChainParams::MAIN);

    UpdateVersionBitsParameters(Consensus::DEPLOYMENT_CSV, 300, 400);
    const Consensus::Params& consensus = Params().GetConsensus();
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit, 0);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime, 300);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout, 400);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime, 1199145601);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout, 1230767999);

    // Selecting the chain again creates its parameters again.
    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(Params().GetConsensus().vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime, 1462060800);
    BOOST_CHECK_EQUAL(Params().GetConsensus().vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout, 1493596800);
}

BOOST_AUTO_TEST_SUITE_END()
