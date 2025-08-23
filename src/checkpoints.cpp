// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include "msvc_warnings.push.h"
#endif

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#ifndef BITCOIN_CHECKPOINT_H
 #include "checkpoints.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb-leveldb.h"
#endif
#include "streams.h"
#include "reverse_iterator.h"

namespace Checkpoints
{
    typedef std::map<int, std::pair<uint256, unsigned int> > MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
        ( 0, std::make_pair(uint256("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5"), 1367991220) )
        ( 15000, std::make_pair(uint256("0x00000082cab82d04354692fac3b83d19cbe3c3ab4b73610d0e73397545eb012e"), 1368024582) )
        ( 30000, std::make_pair(uint256("0x0000000af2f6e71951d6e8befbd43a3dac36681b5095cb822b5c9c8de626e371"), 1368071548) )
        ( 45000, std::make_pair(uint256("0x00000000591110a1411cf37739cde0c558c0c070aa38686d89b2e70fe39b654f"), 1368188743) )
        ( 60000, std::make_pair(uint256("0x000000000c067c5df98a8285ff045c3ffee46eb64b248bc6622f6bdceb8558be"), 1368486465) )
        ( 75000, std::make_pair(uint256("0x000000004ab2d277c8a056f55f32efa515a9931cb0404d60d0efc4f573412e66"), 1369894448) )
        ( 90000, std::make_pair(uint256("0x000000000cfe2ec9d27b784c2627c3864d26e5829cc5b18b4eff37d863ed0675"), 1371070047) )
        ( 105000, std::make_pair(uint256("0x00000000b0480b6a15fee32ee47d4b30dc82dc44ab680f1debb2ce2b13f73aab"), 1371870193) )
        ( 120000, std::make_pair(uint256("0x00000000d843c5c818620d00c9352e0cc3bbf7fdb9d69093795fbfffff13c92a"), 1372878458) )
        ( 135000, std::make_pair(uint256("0x0000000292cb16d5935e015a786d33f3228da23d92dfeb6ddff7249a3227f956"), 1374104602) )
        ( 150000, std::make_pair(uint256("0x000000035d01ee7f75032c0293a7e6b1217d447fe3e000ede7911cb0520c60c7"), 1375119379) )
        ( 165000, std::make_pair(uint256("0x00000001e790d65de9541af419465338220de69e3ffcbda427af2fc94741d321"), 1375961238) )
        ( 180000, std::make_pair(uint256("0x000000054595380eb246887c79ff25fd997eebd3e59385830e4987c11153a31d"), 1377139488) )
        ( 195000, std::make_pair(uint256("0x00000007c12dc0533ab2dbf66c56308ee0b259e1a5f09435381ea6d541b6a2c5"), 1378153929) )
        ( 214998, std::make_pair(uint256("0x000000054e1a96d68bddda9b63276d604f33b6679d7dab079e4d241a1ee31be9"), 1379316207) )
        ( 236895, std::make_pair(uint256("0x00000000a103442adaf96aa2af5cbc083e74cddbea558a7740c7a6781f561c08"), 1380923756) )
        ( 259405, std::make_pair(uint256("0x00000019f67b00bc3482208d5b82393df96c648b510f24ab0d3318294a9bcde5"), 1382451651) )
        ( 281002, std::make_pair(uint256("0x0000003076d627bd2e13e914a3032c2ef8a69de4792452c697bc23a6e158be2b"), 1383844777) )
        ( 303953, std::make_pair(uint256("0x0000007c2fd3ca884a5b77e9b2a508cb617b75f2162beacafffa7193d2db7069"), 1385560454) )
        ( 388314, std::make_pair(uint256("0x0000001d9a76c3a52288638568dad601a8a69ba7dc1038ff4d12b614de73a49a"), 1390167524) )
        ( 420000, std::make_pair(uint256("0x000000368f2f40e3d2d9ed2a2220c8a424e3d80871c0b72c2bdeea35863aa779"), 1392241857) )
        ( 465000, std::make_pair(uint256("0x0000000826f7b8b504fde92ba0388b647b2179d4b2c7cdfd232505cd7d79ac61"), 1394854385) )
        ( 487658, std::make_pair(uint256("0x00000008dee4518a08084c5b65d647a57faf7ff28bc7d8786719ac13d21356d4"), 1396181452) )
        ( 550177, std::make_pair(uint256("0x000000087d507052cb66d5a3770cf62f8ff9196ab861ffec3452d939b818567b"), 1399962064) )
        ( 612177, std::make_pair(uint256("0x0000004bc02ebb045398fd8cdb249b790892a4fa3a8b03dbbbf5743c53f2a508"), 1404141665) )
        ( 712177, std::make_pair(uint256("0x000001881da9ee73de48a54ebae7d0dec3b453d795b6704d62414e4b581e3aea"), 1410900724) )
        ( 750000, std::make_pair(uint256("0x000001d36056e88f70b27d1415cdf7cedbafb4a7c1f2f78d5a8d9f713aee4a5a"), 1413175439) )
        ( 800000, std::make_pair(uint256("0x000000ca19b5cd837c373f40b5e511866c90ce37945fd43fe13e55fe51c22c06"), 1416125155) )
        ( 850000, std::make_pair(uint256("0x0000003aa373b33950c52daf60c82f6e5dae67dba2b7affd0e0a95560ace68ce"), 1419136669) )
        ( 900000, std::make_pair(uint256("0x0000029f3ce6e19adbf7c08e051b91c55d4586d99223964abc0387170c375bfd"), 1422263737) )
        ( 950000, std::make_pair(uint256("0x0000031c836162928d81fd50bc8db3e995a80cbdef27785f7b11f46c86b327bb"), 1425401174) )
        ( 1000000, std::make_pair(uint256("0x00000173fff346c1f83138ee23c15debb96eea78b63c8dea5e02da5e1a775a54"), 1428428793) )
        ( 1050000, std::make_pair(uint256("0x00000118eb156fca5d4cea18ccc56d51175c9fa03e2301adc96d36dedbc4dd39"), 1431318185) )
        ( 1100000, std::make_pair(uint256("0x000001875f4f515559d683c750db1952a1e5b896f6f4390023c6d445fef63f64"), 1434336775) )
        ( 1150000, std::make_pair(uint256("0x00000979215bbb8205c42961b10b22900aa5c127e3a61061f340541295e65bf1"), 1437858183) )
        ( 1200000, std::make_pair(uint256("0x0000084191c31d1c27cba87fbc4308b7e67cff8e89f13fcee51958db0e3918ee"), 1441219249) )
        ( 1250000, std::make_pair(uint256("0x00000d72f9b23ae645eb875af19aa30279c597429ec5652da0e39a0edd5bd4f9"), 1445030340) )
        ( 1300000, std::make_pair(uint256("0x00000a3336e2c336c0182945837573c5ffe68550f77393244d4bf26d36ae0f6c"), 1449046459) )
        ( 1350000, std::make_pair(uint256("0x00000b6d09db4e5443094d05f8ea061e2305c44a787b5b4e3cdab9ddfa78034b"), 1452114905) )
        ( 1400000, std::make_pair(uint256("0x0000061aa7e66eb0a1adcf5f4cf773eb6351a5e0905a3794cca135edc72799ab"), 1455489021) )
        ( 1450000, std::make_pair(uint256("0x00000a99ea3603a90460600e8c1f4cb688abf8fcb8fc9d6a1848917690df049f"), 1458978981) )
        ( 1500000, std::make_pair(uint256("0x0000072187440ce4016fa230c177a8967840d475278eff633dce66837e550f9e"), 1462246823) )
        ( 1550000, std::make_pair(uint256("0x000005b5842fe8e453b7360c50cbe580ef4874d2b8976a3e5d336dc5e34b4683"), 1465161192) )
        ( 1600000, std::make_pair(uint256("0x0000088ced0e7c97afb9635b315f286f94a25eb5d0490ce7b12e2ce0905c3f31"), 1468137164) )
        ( 1650000, std::make_pair(uint256("0x000007439ff054f2307766a5a30eff4fc0268de68e72c76efde767ccee91830c"), 1474542850) )
        ( 1700000, std::make_pair(uint256("0x00000797ae41dbf32c6cb73c1254fbd804b068263ef2de77755fb1829dd2ab1d"), 1485082994) )
        ( 1750000, std::make_pair(uint256("0xd1806e1fa74087ef43fe0a8b37e558c1f9b523529f17b8cb91ca619dd90e4eec"), 1502581866) )
        ( 1800000, std::make_pair(uint256("0x00000670c3f5b879d8b2b0c403c824af78cf95f536d2da66b198efcf9d9ff355"), 1538122573) )
        ( 1850000, std::make_pair(uint256("0x00000e1b13b2b08d36598664d508a38500c59fcff4cf3d3746de0738b6eef457"), 1581200065) )
        ( 1890005, std::make_pair(uint256("0x00000dfd4e2286daee184a67b9266e40b8c1c5daf3a29a2321fd23e6c2da62e2"), 1619355152) ) // Heliopolis hardfork at block 1890000
        ( 1911210, std::make_pair(uint256("000009e3b1cc249ba64c3749430b96cf0f3c25acbb2bd3cb0b69e3b28288607b"), 1682210698) ) // Support token at block 1911210
#else
        ( 0, std::make_pair(uint256("0x1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848"), 1367991220) )
#endif
        ;

    // TestNet has no checkpoints

// YACOIN TODO CHANGE
    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = mapCheckpoints;
        MapCheckpoints::const_iterator 
            i = checkpoints.find(nHeight);

        if (i == checkpoints.end()) 
            return true;
        return (hash == i->second.first);
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = mapCheckpoints;
        return checkpoints.rbegin()->first;
    }

    unsigned int GetLastCheckpointTime()
    {
        MapCheckpoints& checkpoints = mapCheckpoints;
        return checkpoints.rbegin()->second.second;
    }

    CBlockIndex* GetLastCheckpoint(const BlockMap& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = mapCheckpoints;
        for (const MapCheckpoints::value_type& i : reverse_iterate(checkpoints)) {
            const uint256& hash = i.second.first;
            BlockMap::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return nullptr;
    }
}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
