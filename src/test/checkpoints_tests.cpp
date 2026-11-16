// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The checkpoint functions (CheckHardened, GetTotalBlocksEstimate,
// GetLastCheckpointTime, GetLastCheckpoint) on mainnet and on regtest, and with
// the chain selected at run time.
//
// The low-difficulty build has its own mainnet genesis block and checkpoint
// data; its values have their own part for that build.

#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "primitives/block.h"
#include "uint256.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
/** Mainnet's checkpoints: height and block hash */
const std::vector<std::pair<int, std::string>> MAIN_CHECKPOINTS = {
    {0, "0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5"},
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

/** Height and time of mainnet's last checkpoint */
const int MAIN_LAST_HEIGHT = 1911210;
const unsigned int MAIN_LAST_TIME = 1682210698;
#else
const int MAIN_LAST_HEIGHT = 0;
const unsigned int MAIN_LAST_TIME = 1367991220;
#endif

/** Time of the genesis blocks of every chain */
const unsigned int GENESIS_TIME = 1367991220;

uint256 MainGenesisHash()
{
    return CreateChainParams(CBaseChainParams::MAIN)->GetConsensus().hashGenesisBlock;
}

uint256 RegtestGenesisHash()
{
    return CreateChainParams(CBaseChainParams::REGTEST)->GetConsensus().hashGenesisBlock;
}

/** The hash of a header at height 1 on regtest's genesis block */
uint256 RegtestBlockOneHash()
{
    const std::unique_ptr<CChainParams> params = CreateChainParams(CBaseChainParams::REGTEST);
    const CBlock& genesis = params->GenesisBlock();
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = genesis.GetHash();
    header.hashMerkleRoot = genesis.hashMerkleRoot;
    header.nTime = genesis.nTime + 60;
    header.nBits = genesis.nBits;
    header.nNonce = 1;
    return header.GetHash();
}

/** A block index map with an entry of the given height for each hash */
class IndexMap
{
public:
    void Add(const uint256& hash, int nHeight)
    {
        std::unique_ptr<CBlockIndex> index(new CBlockIndex());
        index->nHeight = nHeight;
        m_map[hash] = index.get();
        m_entries.push_back(std::move(index));
    }
    CBlockIndex* At(const uint256& hash) const { return m_map.at(hash); }
    const BlockMap& Map() const { return m_map; }

private:
    BlockMap m_map;
    std::vector<std::unique_ptr<CBlockIndex>> m_entries;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(checkpoints_tests, BasicTestingSetup)

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
BOOST_AUTO_TEST_CASE(main_data)
{
    BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(), 1911210);
    BOOST_CHECK_EQUAL(Checkpoints::GetLastCheckpointTime(), 1682210698U);

    BOOST_REQUIRE_EQUAL(MAIN_CHECKPOINTS.size(), 51U);
    BOOST_CHECK_EQUAL(MAIN_CHECKPOINTS.front().second, MainGenesisHash().GetHex());
    for (size_t i = 0; i < MAIN_CHECKPOINTS.size(); i++) {
        const int nHeight = MAIN_CHECKPOINTS[i].first;
        const uint256 hash = uint256S(MAIN_CHECKPOINTS[i].second);
        const uint256 other = uint256S(MAIN_CHECKPOINTS[(i + 1) % MAIN_CHECKPOINTS.size()].second);
        BOOST_CHECK_MESSAGE(Checkpoints::CheckHardened(nHeight, hash), "height " << nHeight);
        BOOST_CHECK_MESSAGE(!Checkpoints::CheckHardened(nHeight, uint256()), "height " << nHeight);
        BOOST_CHECK_MESSAGE(!Checkpoints::CheckHardened(nHeight, other), "height " << nHeight);
    }
}
#else
BOOST_AUTO_TEST_CASE(low_difficulty_data)
{
    BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(), 0);
    BOOST_CHECK_EQUAL(Checkpoints::GetLastCheckpointTime(), 1367991220U);

    const uint256 genesis = MainGenesisHash();
    BOOST_CHECK_EQUAL(genesis.GetHex(), "1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848");
    BOOST_CHECK(Checkpoints::CheckHardened(0, genesis));
    BOOST_CHECK(!Checkpoints::CheckHardened(0, uint256()));
    BOOST_CHECK(!Checkpoints::CheckHardened(0, RegtestGenesisHash()));
}
#endif

BOOST_AUTO_TEST_CASE(last_checkpoint_lookup)
{
    const uint256 genesis = MainGenesisHash();

    IndexMap empty;
    BOOST_CHECK(Checkpoints::GetLastCheckpoint(empty.Map()) == nullptr);

    IndexMap unlisted;
    unlisted.Add(RegtestGenesisHash(), 0);
    unlisted.Add(uint256S("01"), 1);
    BOOST_CHECK(Checkpoints::GetLastCheckpoint(unlisted.Map()) == nullptr);

    IndexMap withGenesis;
    withGenesis.Add(genesis, 0);
    withGenesis.Add(uint256S("01"), 1);
    BOOST_CHECK(Checkpoints::GetLastCheckpoint(withGenesis.Map()) == withGenesis.At(genesis));

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    const uint256 hash15000 = uint256S(MAIN_CHECKPOINTS[1].second);
    IndexMap twoListed;
    twoListed.Add(genesis, 0);
    twoListed.Add(hash15000, 15000);
    BOOST_CHECK(Checkpoints::GetLastCheckpoint(twoListed.Map()) == twoListed.At(hash15000));
#endif
}

BOOST_AUTO_TEST_CASE(regtest_data)
{
    const uint256 mainGenesis = MainGenesisHash();
    const uint256 blockOne = RegtestBlockOneHash();

    SelectedParamsGuard regtest(CBaseChainParams::REGTEST);
    const uint256 genesis = Params().GetConsensus().hashGenesisBlock;
    BOOST_CHECK_EQUAL(Params().GenesisBlock().nTime, GENESIS_TIME);

    BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(), 0);
    BOOST_CHECK_EQUAL(Checkpoints::GetLastCheckpointTime(), GENESIS_TIME);
    BOOST_CHECK(Checkpoints::CheckHardened(0, genesis));
    BOOST_CHECK(!Checkpoints::CheckHardened(0, mainGenesis));
    BOOST_CHECK(Checkpoints::CheckHardened(1, blockOne));

    IndexMap regtestIndex;
    regtestIndex.Add(genesis, 0);
    regtestIndex.Add(blockOne, 1);
    BOOST_CHECK(Checkpoints::GetLastCheckpoint(regtestIndex.Map()) == regtestIndex.At(genesis));

    IndexMap mainIndex;
    mainIndex.Add(mainGenesis, 0);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    mainIndex.Add(uint256S(MAIN_CHECKPOINTS[1].second), 15000);
#endif
    BOOST_CHECK(Checkpoints::GetLastCheckpoint(mainIndex.Map()) == nullptr);
}

BOOST_AUTO_TEST_CASE(chain_switch)
{
    const uint256 mainGenesis = MainGenesisHash();
    const uint256 regtestGenesis = RegtestGenesisHash();

    for (int round = 0; round < 2; round++) {
        {
            SelectedParamsGuard regtest(CBaseChainParams::REGTEST);
            BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(), 0);
            BOOST_CHECK(Checkpoints::CheckHardened(0, regtestGenesis));
        }
        BOOST_CHECK_EQUAL(Params().NetworkIDString(), CBaseChainParams::MAIN);
        BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(), MAIN_LAST_HEIGHT);
        BOOST_CHECK_EQUAL(Checkpoints::GetLastCheckpointTime(), MAIN_LAST_TIME);
        BOOST_CHECK(Checkpoints::CheckHardened(0, mainGenesis));
        BOOST_CHECK(!Checkpoints::CheckHardened(0, regtestGenesis));
    }
}

BOOST_AUTO_TEST_SUITE_END()
