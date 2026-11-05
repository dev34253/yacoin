// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/walletdb.h"

#include "base58.h"
#include "clientversion.h"
#include "key.h"
#include "script/standard.h"
#include "streams.h"
#include "test/known_failure.h"
#include "test/test_bitcoin.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"
#include "wallet/crypter.h"
#include "wallet/db.h"
#include "wallet/test/wallet_test_fixture.h"
#include "wallet/wallet.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(walletdb_tests, WalletTestingSetup)

namespace {

const std::string TYPE_NAME("name");
const std::string TYPE_KEY("key");

/** A wallet whose database is the file strFile of the mock environment. */
std::unique_ptr<CWallet> WalletOnFile(const std::string& strFile)
{
    return std::unique_ptr<CWallet>(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, strFile))));
}

/** Loads the wallet's database file into the wallet. */
DBErrors Load(CWallet& wallet)
{
    return CWalletDB(wallet.GetDBHandle(), "cr+").LoadWallet(&wallet);
}

CKey NewKey(bool fCompressed = true)
{
    CKey key;
    key.MakeNewKey(fCompressed);
    return key;
}

std::string AddressOf(const CTxDestination& dest)
{
    return CBitcoinAddress(dest).ToString();
}

/** Hash(public key ‖ private key), the checksum of a "key" record. */
uint256 KeyChecksum(const CPubKey& pubkey, const CPrivKey& privkey)
{
    std::vector<unsigned char> vchKey(pubkey.begin(), pubkey.end());
    vchKey.insert(vchKey.end(), privkey.begin(), privkey.end());
    return Hash(vchKey.begin(), vchKey.end());
}

/** A transaction that passes CheckTransaction; the random outpoint makes its hash unique. */
CWalletTx NewWalletTx(int64_t nOrderPos)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(InsecureRand256(), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    CWalletTx wtx(nullptr, MakeTransactionRef(mtx));
    wtx.nOrderPos = nOrderPos;
    return wtx;
}

/** A wallet transaction value followed by the fields written after it by old versions. */
struct TxWithTrailer {
    const CWalletTx& wtx;
    char fTimeReceivedIsTxTime;
    char fUnused;
    std::string strFromAccount;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << wtx << fTimeReceivedIsTxTime << fUnused << strFromAccount;
    }
};

std::string LabelOf(const CWallet& wallet, const CTxDestination& dest)
{
    auto it = wallet.mapAddressBook.find(dest);
    return it == wallet.mapAddressBook.end() ? "(no entry)" : it->second.name;
}

std::vector<std::string> ReadLines(const fs::path& path)
{
    std::ifstream file(path.string());
    std::vector<std::string> vLines;
    std::string line;
    while (std::getline(file, line))
        vLines.push_back(line);
    return vLines;
}

bool Contains(const std::vector<std::string>& vLines, const std::string& line)
{
    return std::find(vLines.begin(), vLines.end(), line) != vLines.end();
}

} // namespace

BOOST_AUTO_TEST_CASE(write_read_and_erase_records)
{
    CWalletDBWrapper dbw(&bitdb, "walletdb_records.dat");
    CWalletDB walletdb(dbw, "cr+");
    CDB batch(dbw, "r+");

    const CKey key = NewKey();
    const CPubKey pubkey = key.GetPubKey();
    const std::string strAddress = AddressOf(pubkey.GetID());
    std::string strValue;

    // Address book name and purpose.
    const unsigned int nUpdatesBefore = dbw.nUpdateCounter;
    BOOST_CHECK(walletdb.WriteName(strAddress, "label"));
    BOOST_CHECK(dbw.nUpdateCounter > nUpdatesBefore);
    BOOST_CHECK(batch.Read(std::make_pair(TYPE_NAME, strAddress), strValue));
    BOOST_CHECK_EQUAL(strValue, "label");
    BOOST_CHECK(walletdb.EraseName(strAddress));
    BOOST_CHECK(!batch.Exists(std::make_pair(TYPE_NAME, strAddress)));
    BOOST_CHECK(walletdb.WritePurpose(strAddress, "receive"));
    BOOST_CHECK(batch.Read(std::make_pair(std::string("purpose"), strAddress), strValue));
    BOOST_CHECK_EQUAL(strValue, "receive");
    BOOST_CHECK(walletdb.ErasePurpose(strAddress));
    BOOST_CHECK(!batch.Exists(std::make_pair(std::string("purpose"), strAddress)));

    // Transaction.
    const CWalletTx wtx = NewWalletTx(0);
    BOOST_CHECK(walletdb.WriteTx(wtx));
    CWalletTx wtxRead;
    BOOST_CHECK(batch.Read(std::make_pair(std::string("tx"), wtx.GetHash()), wtxRead));
    BOOST_CHECK(wtxRead.GetHash() == wtx.GetHash());
    BOOST_CHECK(walletdb.EraseTx(wtx.GetHash()));
    BOOST_CHECK(!batch.Exists(std::make_pair(std::string("tx"), wtx.GetHash())));

    // Plain key with its metadata and the checksum; it is not overwritten.
    const CKeyMetadata meta(1234567);
    BOOST_CHECK(walletdb.WriteKey(pubkey, key.GetPrivKey(), meta));
    std::pair<CPrivKey, uint256> keyValue;
    BOOST_CHECK(batch.Read(std::make_pair(TYPE_KEY, pubkey), keyValue));
    BOOST_CHECK(keyValue.first == key.GetPrivKey());
    BOOST_CHECK(keyValue.second == KeyChecksum(pubkey, key.GetPrivKey()));
    CKeyMetadata metaRead;
    BOOST_CHECK(batch.Read(std::make_pair(std::string("keymeta"), pubkey), metaRead));
    BOOST_CHECK_EQUAL(metaRead.nCreateTime, 1234567);
    BOOST_CHECK(!walletdb.WriteKey(pubkey, key.GetPrivKey(), meta));

    // An encrypted key replaces the plain "key" and "wkey" records of its public key; it is not
    // overwritten either.
    BOOST_CHECK(batch.Write(std::make_pair(std::string("wkey"), pubkey), CWalletKey()));
    const std::vector<unsigned char> vchCrypted(48, 0x42);
    BOOST_CHECK(walletdb.WriteCryptedKey(pubkey, vchCrypted, CKeyMetadata(7654321)));
    std::vector<unsigned char> vchCryptedRead;
    BOOST_CHECK(batch.Read(std::make_pair(std::string("ckey"), pubkey), vchCryptedRead));
    BOOST_CHECK(vchCryptedRead == vchCrypted);
    BOOST_CHECK(!batch.Exists(std::make_pair(TYPE_KEY, pubkey)));
    BOOST_CHECK(!batch.Exists(std::make_pair(std::string("wkey"), pubkey)));
    BOOST_CHECK(batch.Read(std::make_pair(std::string("keymeta"), pubkey), metaRead));
    BOOST_CHECK_EQUAL(metaRead.nCreateTime, 7654321);
    BOOST_CHECK(!walletdb.WriteCryptedKey(pubkey, vchCrypted, CKeyMetadata(7654321)));
    BOOST_CHECK(walletdb.EraseCryptedKey(pubkey));
    BOOST_CHECK(!batch.Exists(std::make_pair(std::string("ckey"), pubkey)));

    // Master key.
    CMasterKey masterKey;
    masterKey.vchCryptedKey = std::vector<unsigned char>(48, 0x01);
    masterKey.vchSalt = std::vector<unsigned char>(WALLET_CRYPTO_SALT_SIZE, 0x02);
    masterKey.nDeriveIterations = 30000;
    BOOST_CHECK(walletdb.WriteMasterKey(3, masterKey));
    CMasterKey masterKeyRead;
    BOOST_CHECK(batch.Read(std::make_pair(std::string("mkey"), 3U), masterKeyRead));
    BOOST_CHECK(masterKeyRead.vchCryptedKey == masterKey.vchCryptedKey);
    BOOST_CHECK(masterKeyRead.vchSalt == masterKey.vchSalt);
    BOOST_CHECK_EQUAL(masterKeyRead.nDerivationMethod, 0U);
    BOOST_CHECK_EQUAL(masterKeyRead.nDeriveIterations, 30000U);
    BOOST_CHECK(walletdb.EraseMasterKey(3));
    BOOST_CHECK(!batch.Exists(std::make_pair(std::string("mkey"), 3U)));

    // Redeem script, not overwritten.
    const CScript redeemScript = GetScriptForCltvP2SH(1000, pubkey);
    BOOST_CHECK(walletdb.WriteCScript(Hash160(redeemScript), redeemScript));
    CScript scriptRead;
    BOOST_CHECK(batch.Read(std::make_pair(std::string("cscript"), Hash160(redeemScript)), scriptRead));
    BOOST_CHECK(scriptRead == redeemScript);
    BOOST_CHECK(!walletdb.WriteCScript(Hash160(redeemScript), redeemScript));

    // Watch-only script and its metadata.
    const CScript watchScript = GetScriptForDestination(NewKey().GetPubKey().GetID());
    BOOST_CHECK(walletdb.WriteWatchOnly(watchScript, CKeyMetadata(42)));
    char fYes = 0;
    BOOST_CHECK(batch.Read(std::make_pair(std::string("watchs"), watchScript), fYes));
    BOOST_CHECK_EQUAL(fYes, '1');
    BOOST_CHECK(batch.Read(std::make_pair(std::string("watchmeta"), watchScript), metaRead));
    BOOST_CHECK_EQUAL(metaRead.nCreateTime, 42);
    BOOST_CHECK(walletdb.EraseWatchOnly(watchScript));
    BOOST_CHECK(!batch.Exists(std::make_pair(std::string("watchs"), watchScript)));
    BOOST_CHECK(!batch.Exists(std::make_pair(std::string("watchmeta"), watchScript)));

    // Best block: an empty "bestblock" and the locator in "bestblock_nomerkle"; a non-empty
    // "bestblock" is read first.
    const CBlockLocator locator(std::vector<uint256>{InsecureRand256(), InsecureRand256()});
    BOOST_CHECK(walletdb.WriteBestBlock(locator));
    CBlockLocator locatorRead;
    BOOST_CHECK(batch.Read(std::string("bestblock"), locatorRead));
    BOOST_CHECK(locatorRead.vHave.empty());
    BOOST_CHECK(walletdb.ReadBestBlock(locatorRead));
    BOOST_CHECK(locatorRead.vHave == locator.vHave);
    const CBlockLocator locatorOld(std::vector<uint256>{InsecureRand256()});
    BOOST_CHECK(batch.Write(std::string("bestblock"), locatorOld));
    BOOST_CHECK(walletdb.ReadBestBlock(locatorRead));
    BOOST_CHECK(locatorRead.vHave == locatorOld.vHave);

    // Order position, default key and key pool.
    BOOST_CHECK(walletdb.WriteOrderPosNext(17));
    int64_t nOrderPosNext = 0;
    BOOST_CHECK(batch.Read(std::string("orderposnext"), nOrderPosNext));
    BOOST_CHECK_EQUAL(nOrderPosNext, 17);
    BOOST_CHECK(walletdb.WriteDefaultKey(pubkey));
    CPubKey pubkeyRead;
    BOOST_CHECK(batch.Read(std::string("defaultkey"), pubkeyRead));
    BOOST_CHECK(pubkeyRead == pubkey);
    BOOST_CHECK(walletdb.WritePool(5, CKeyPool(pubkey, true)));
    CKeyPool keypool;
    BOOST_CHECK(walletdb.ReadPool(5, keypool));
    BOOST_CHECK(keypool.vchPubKey == pubkey);
    BOOST_CHECK(keypool.fInternal);
    BOOST_CHECK(walletdb.ErasePool(5));
    BOOST_CHECK(!walletdb.ReadPool(5, keypool));

    // Minimum and file version.
    BOOST_CHECK(walletdb.WriteMinVersion(FEATURE_COMPRPUBKEY));
    int nVersion = 0;
    BOOST_CHECK(batch.Read(std::string("minversion"), nVersion));
    BOOST_CHECK_EQUAL(nVersion, FEATURE_COMPRPUBKEY);
    BOOST_CHECK(walletdb.ReadVersion(nVersion));
    BOOST_CHECK_EQUAL(nVersion, CLIENT_VERSION);
    BOOST_CHECK(walletdb.WriteVersion(300));
    BOOST_CHECK(walletdb.ReadVersion(nVersion));
    BOOST_CHECK_EQUAL(nVersion, 300);

    // Account and accounting entries.
    CAccount account;
    account.vchPubKey = pubkey;
    BOOST_CHECK(walletdb.WriteAccount("savings", account));
    CAccount accountRead;
    BOOST_CHECK(walletdb.ReadAccount("savings", accountRead));
    BOOST_CHECK(accountRead.vchPubKey == pubkey);
    BOOST_CHECK(!walletdb.ReadAccount("unknown", accountRead));
    BOOST_CHECK(!accountRead.vchPubKey.IsValid());
    CAccountingEntry entry;
    entry.strAccount = "savings";
    entry.nCreditDebit = 5 * COIN;
    entry.nOrderPos = 0;
    BOOST_CHECK(walletdb.WriteAccountingEntry(1, entry));
    entry.nCreditDebit = -2 * COIN;
    BOOST_CHECK(walletdb.WriteAccountingEntry(2, entry));
    entry.strAccount = "spending";
    entry.nCreditDebit = 7 * COIN;
    BOOST_CHECK(walletdb.WriteAccountingEntry(3, entry));
    BOOST_CHECK_EQUAL(walletdb.GetAccountCreditDebit("savings"), 3 * COIN);
    BOOST_CHECK_EQUAL(walletdb.GetAccountCreditDebit("spending"), 7 * COIN);
    BOOST_CHECK_EQUAL(walletdb.GetAccountCreditDebit("none"), 0);
    std::list<CAccountingEntry> entries;
    walletdb.ListAccountCreditDebit("*", entries);
    BOOST_CHECK_EQUAL(entries.size(), 3U);

    // Destination data.
    BOOST_CHECK(walletdb.WriteDestData(strAddress, "rr0", "request"));
    BOOST_CHECK(batch.Read(std::make_pair(std::string("destdata"), std::make_pair(strAddress, std::string("rr0"))), strValue));
    BOOST_CHECK_EQUAL(strValue, "request");
    BOOST_CHECK(walletdb.EraseDestData(strAddress, "rr0"));
    BOOST_CHECK(!batch.Exists(std::make_pair(std::string("destdata"), std::make_pair(strAddress, std::string("rr0")))));

    // HD chain.
    CHDChain chain;
    chain.nExternalChainCounter = 4;
    chain.nInternalChainCounter = 2;
    chain.masterKeyID = pubkey.GetID();
    BOOST_CHECK(walletdb.WriteHDChain(chain));
    CHDChain chainRead;
    BOOST_CHECK(batch.Read(std::string("hdchain"), chainRead));
    BOOST_CHECK_EQUAL(chainRead.nExternalChainCounter, 4U);
    BOOST_CHECK_EQUAL(chainRead.nInternalChainCounter, 2U);
    BOOST_CHECK(chainRead.masterKeyID == pubkey.GetID());

    // A transaction that is aborted drops its writes; a committed one keeps them.
    BOOST_CHECK(walletdb.TxnBegin());
    BOOST_CHECK(walletdb.WriteName(strAddress, "aborted"));
    BOOST_CHECK(walletdb.TxnAbort());
    BOOST_CHECK(!batch.Exists(std::make_pair(TYPE_NAME, strAddress)));
    BOOST_CHECK(walletdb.TxnBegin());
    BOOST_CHECK(walletdb.WriteName(strAddress, "committed"));
    BOOST_CHECK(walletdb.TxnCommit());
    BOOST_CHECK(batch.Read(std::make_pair(TYPE_NAME, strAddress), strValue));
    BOOST_CHECK_EQUAL(strValue, "committed");
    BOOST_CHECK(!walletdb.TxnAbort());
    BOOST_CHECK(!walletdb.TxnCommit());
}

BOOST_AUTO_TEST_CASE(dummy_database)
{
    // A wallet database without a file: writes succeed without effect, erases and reads fail,
    // and the scans find no cursor.
    CWalletDBWrapper dbw;
    CWalletDB walletdb(dbw);
    const CPubKey pubkey = NewKey().GetPubKey();
    const CScript script = GetScriptForDestination(pubkey.GetID());
    BOOST_CHECK(walletdb.WriteName("address", "label"));
    BOOST_CHECK(walletdb.WriteWatchOnly(script, CKeyMetadata(1)));
    BOOST_CHECK(!walletdb.EraseWatchOnly(script));
    BOOST_CHECK(!walletdb.EraseTx(uint256()));
    int nVersion = 1;
    BOOST_CHECK(!walletdb.ReadVersion(nVersion));
    BOOST_CHECK_EQUAL(nVersion, 0);
    BOOST_CHECK(!walletdb.TxnBegin());

    CWallet wallet;
    BOOST_CHECK_EQUAL(walletdb.LoadWallet(&wallet), DB_CORRUPT);
    std::vector<uint256> vTxHash;
    std::vector<CWalletTx> vWtx;
    BOOST_CHECK_EQUAL(walletdb.FindWalletTx(vTxHash, vWtx), DB_CORRUPT);
    BOOST_CHECK_EQUAL(walletdb.ZapWalletTx(vWtx), DB_CORRUPT);
    std::vector<uint256> vTxHashOut;
    BOOST_CHECK_EQUAL(walletdb.ZapSelectTx(vTxHash, vTxHashOut), DB_CORRUPT);
    std::list<CAccountingEntry> entries;
    BOOST_CHECK_THROW(walletdb.ListAccountCreditDebit("*", entries), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(load_every_record_type)
{
    const std::string strFile = "walletdb_load.dat";
    const CKey key = NewKey();                // "key" with checksum and metadata
    const CKey keyNoChecksum = NewKey(false); // "key" without checksum
    const CKey keyLegacy = NewKey();          // "wkey"
    const CPubKey poolKey = NewKey().GetPubKey();
    const CScript watchScript = GetScriptForDestination(NewKey().GetPubKey().GetID());
    const CScript notWatched = GetScriptForDestination(NewKey().GetPubKey().GetID());
    const CScript redeemScript = GetScriptForCltvP2SH(500, key.GetPubKey());
    const CWalletTx wtx = NewWalletTx(4);
    const std::string strAddress = AddressOf(key.GetPubKey().GetID());
    {
        CWalletDBWrapper dbw(&bitdb, strFile);
        CWalletDB walletdb(dbw, "cr+");
        CDB batch(dbw, "r+");
        BOOST_CHECK(walletdb.WriteName(strAddress, "my label"));
        BOOST_CHECK(walletdb.WritePurpose(strAddress, "receive"));
        BOOST_CHECK(walletdb.WriteTx(wtx));
        BOOST_CHECK(walletdb.WriteKey(key.GetPubKey(), key.GetPrivKey(), CKeyMetadata(1500000000)));
        BOOST_CHECK(batch.Write(std::make_pair(TYPE_KEY, keyNoChecksum.GetPubKey()), keyNoChecksum.GetPrivKey()));
        CWalletKey wkey;
        wkey.vchPrivKey = keyLegacy.GetPrivKey();
        BOOST_CHECK(batch.Write(std::make_pair(std::string("wkey"), keyLegacy.GetPubKey()), wkey));
        BOOST_CHECK(walletdb.WriteWatchOnly(watchScript, CKeyMetadata(1400000000)));
        BOOST_CHECK(batch.Write(std::make_pair(std::string("watchs"), notWatched), '0'));
        BOOST_CHECK(walletdb.WriteDefaultKey(key.GetPubKey()));
        BOOST_CHECK(walletdb.WritePool(9, CKeyPool(poolKey)));
        BOOST_CHECK(walletdb.WriteOrderPosNext(5));
        BOOST_CHECK(walletdb.WriteDestData(strAddress, "rr0", "request"));
        CHDChain chain;
        chain.nExternalChainCounter = 3;
        chain.masterKeyID = key.GetPubKey().GetID();
        BOOST_CHECK(walletdb.WriteHDChain(chain));
        BOOST_CHECK(walletdb.WriteCScript(Hash160(redeemScript), redeemScript));
        CAccountingEntry entry;
        entry.strAccount = "savings";
        entry.nOrderPos = 3;
        BOOST_CHECK(walletdb.WriteAccountingEntry(6, entry));
        BOOST_CHECK(walletdb.WriteAccountingEntry(2, entry));
        BOOST_CHECK(walletdb.WriteMinVersion(FEATURE_COMPRPUBKEY));
    }

    std::unique_ptr<CWallet> wallet = WalletOnFile(strFile);
    BOOST_CHECK_EQUAL(Load(*wallet), DB_LOAD_OK);

    LOCK(wallet->cs_wallet);
    BOOST_CHECK_EQUAL(LabelOf(*wallet, key.GetPubKey().GetID()), "my label");
    BOOST_CHECK_EQUAL(wallet->mapAddressBook[key.GetPubKey().GetID()].purpose, "receive");
    BOOST_REQUIRE(wallet->mapWallet.count(wtx.GetHash()));
    BOOST_CHECK_EQUAL(wallet->mapWallet[wtx.GetHash()].nOrderPos, 4);
    for (const CKey& k : {key, keyNoChecksum, keyLegacy}) {
        CKey keyOut;
        BOOST_CHECK(wallet->GetKey(k.GetPubKey().GetID(), keyOut));
        BOOST_CHECK(keyOut == k);
        BOOST_CHECK_EQUAL(keyOut.IsCompressed(), k.IsCompressed());
    }
    BOOST_CHECK_EQUAL(wallet->mapKeyMetadata[key.GetPubKey().GetID()].nCreateTime, 1500000000);
    BOOST_CHECK_EQUAL(wallet->mapKeyMetadata[CScriptID(watchScript)].nCreateTime, 1400000000);
    BOOST_CHECK(wallet->HaveWatchOnly(watchScript));
    BOOST_CHECK(!wallet->HaveWatchOnly(notWatched));
    BOOST_CHECK(wallet->vchDefaultKey == key.GetPubKey());
    BOOST_CHECK_EQUAL(wallet->GetAllReserveKeys().count(poolKey.GetID()), 1U);
    BOOST_CHECK_EQUAL(wallet->GetAllReserveKeys().at(poolKey.GetID()), 9);
    BOOST_CHECK_EQUAL(wallet->nOrderPosNext, 5);
    std::string strValue;
    BOOST_CHECK(wallet->GetDestData(key.GetPubKey().GetID(), "rr0", &strValue));
    BOOST_CHECK_EQUAL(strValue, "request");
    BOOST_CHECK(wallet->GetHDChain().masterKeyID == key.GetPubKey().GetID());
    BOOST_CHECK_EQUAL(wallet->GetHDChain().nExternalChainCounter, 3U);
    BOOST_CHECK(wallet->HaveCScript(CScriptID(redeemScript)));
    BOOST_CHECK_EQUAL(wallet->nAccountingEntryNumber, 6U);
    BOOST_CHECK_EQUAL(wallet->GetVersion(), FEATURE_COMPRPUBKEY);
    BOOST_CHECK(!wallet->IsCrypted());
}

BOOST_AUTO_TEST_CASE(load_rewrites_old_versions)
{
    // An older file version of a wallet without encrypted keys is rewritten to the current one.
    int nVersion = 0;
    for (int nFileVersion : {10300, 40000}) {
        const std::string strFile = strprintf("walletdb_version_plain_%d.dat", nFileVersion);
        {
            CWalletDBWrapper dbw(&bitdb, strFile);
            BOOST_CHECK(CWalletDB(dbw, "cr+").WriteVersion(nFileVersion));
        }
        std::unique_ptr<CWallet> wallet = WalletOnFile(strFile);
        BOOST_CHECK_EQUAL(Load(*wallet), DB_LOAD_OK);
        CWalletDBWrapper dbw(&bitdb, strFile);
        BOOST_CHECK(CWalletDB(dbw).ReadVersion(nVersion));
        BOOST_CHECK_EQUAL(nVersion, CLIENT_VERSION);
    }

    // An encrypted wallet of file version 40000 or 50000 needs a rewrite; its version is kept.
    for (int nFileVersion : {40000, 50000}) {
        const std::string strCrypted = strprintf("walletdb_version_%d.dat", nFileVersion);
        {
            CWalletDBWrapper dbwCrypted(&bitdb, strCrypted);
            CWalletDB walletdb(dbwCrypted, "cr+");
            BOOST_CHECK(walletdb.WriteVersion(nFileVersion));
            BOOST_CHECK(walletdb.WriteCryptedKey(NewKey().GetPubKey(), std::vector<unsigned char>(48, 0x01), CKeyMetadata(1)));
        }
        std::unique_ptr<CWallet> crypted = WalletOnFile(strCrypted);
        BOOST_CHECK_EQUAL(Load(*crypted), DB_NEED_REWRITE);
        BOOST_CHECK(crypted->IsCrypted());
        CWalletDBWrapper dbwCrypted(&bitdb, strCrypted);
        BOOST_CHECK(CWalletDB(dbwCrypted).ReadVersion(nVersion));
        BOOST_CHECK_EQUAL(nVersion, nFileVersion);
    }
}

BOOST_AUTO_TEST_CASE(load_repairs_transactions)
{
    // A transaction whose fTimeReceivedIsTxTime is in 31404..31703 is repaired and written
    // again: without trailing fields the flag becomes 0, with them it takes the first trailing
    // byte, and the account is taken from the last.
    const std::string strFile = "walletdb_repair.dat";
    CWalletTx wtxBare = NewWalletTx(0);
    wtxBare.fTimeReceivedIsTxTime = 31404;
    CWalletTx wtxTrailer = NewWalletTx(1);
    wtxTrailer.fTimeReceivedIsTxTime = 31703;
    CWalletTx wtxKept = NewWalletTx(2);
    wtxKept.fTimeReceivedIsTxTime = 31704;
    {
        CWalletDBWrapper dbw(&bitdb, strFile);
        CWalletDB walletdb(dbw, "cr+");
        CDB batch(dbw, "r+");
        BOOST_CHECK(walletdb.WriteTx(wtxBare));
        BOOST_CHECK(batch.Write(std::make_pair(std::string("tx"), wtxTrailer.GetHash()), TxWithTrailer{wtxTrailer, 1, 0, "old account"}));
        BOOST_CHECK(walletdb.WriteTx(wtxKept));
    }
    std::unique_ptr<CWallet> wallet = WalletOnFile(strFile);
    BOOST_CHECK_EQUAL(Load(*wallet), DB_LOAD_OK);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet[wtxBare.GetHash()].fTimeReceivedIsTxTime, 0U);
        BOOST_CHECK_EQUAL(wallet->mapWallet[wtxTrailer.GetHash()].fTimeReceivedIsTxTime, 1U);
        BOOST_CHECK_EQUAL(wallet->mapWallet[wtxTrailer.GetHash()].strFromAccount, "old account");
        BOOST_CHECK_EQUAL(wallet->mapWallet[wtxKept.GetHash()].fTimeReceivedIsTxTime, 31704U);
    }

    CWalletDBWrapper dbw(&bitdb, strFile);
    CDB batch(dbw, "r");
    CWalletTx wtxRead;
    BOOST_CHECK(batch.Read(std::make_pair(std::string("tx"), wtxBare.GetHash()), wtxRead));
    BOOST_CHECK_EQUAL(wtxRead.fTimeReceivedIsTxTime, 0U);
    BOOST_CHECK(batch.Read(std::make_pair(std::string("tx"), wtxTrailer.GetHash()), wtxRead));
    BOOST_CHECK_EQUAL(wtxRead.fTimeReceivedIsTxTime, 1U);
    BOOST_CHECK_EQUAL(wtxRead.strFromAccount, "old account");
}

BOOST_AUTO_TEST_CASE(load_orders_unordered_entries)
{
    // A transaction without an order position makes LoadWallet order all transactions.
    {
        const std::string strFile = "walletdb_unordered_tx.dat";
        const CWalletTx wtx = NewWalletTx(-1);
        {
            CWalletDBWrapper dbw(&bitdb, strFile);
            BOOST_CHECK(CWalletDB(dbw, "cr+").WriteTx(wtx));
        }
        std::unique_ptr<CWallet> wallet = WalletOnFile(strFile);
        BOOST_CHECK_EQUAL(Load(*wallet), DB_LOAD_OK);
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet[wtx.GetHash()].nOrderPos, 0);
        BOOST_CHECK_EQUAL(wallet->nOrderPosNext, 1);
    }
    // So does an accounting entry without one.
    {
        const std::string strFile = "walletdb_unordered_acentry.dat";
        const CWalletTx wtx = NewWalletTx(0);
        CAccountingEntry entry;
        entry.strAccount = "";
        entry.nTime = 1;
        entry.nOrderPos = -1;
        {
            CWalletDBWrapper dbw(&bitdb, strFile);
            CWalletDB walletdb(dbw, "cr+");
            BOOST_CHECK(walletdb.WriteTx(wtx));
            BOOST_CHECK(walletdb.WriteAccountingEntry(1, entry));
        }
        std::unique_ptr<CWallet> wallet = WalletOnFile(strFile);
        BOOST_CHECK_EQUAL(Load(*wallet), DB_LOAD_OK);
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->nOrderPosNext, 2);
        std::list<CAccountingEntry> entries;
        CWalletDB(wallet->GetDBHandle()).ListAccountCreditDebit("", entries);
        BOOST_REQUIRE_EQUAL(entries.size(), 1U);
        BOOST_CHECK(entries.front().nOrderPos != -1);
    }
}

BOOST_AUTO_TEST_CASE(load_too_new)
{
    const std::string strFile = "walletdb_too_new.dat";
    {
        CWalletDBWrapper dbw(&bitdb, strFile);
        CWalletDB walletdb(dbw, "cr+");
        BOOST_CHECK(walletdb.WriteMinVersion(CLIENT_VERSION + 1));
        BOOST_CHECK(walletdb.WriteTx(NewWalletTx(0)));
    }
    std::unique_ptr<CWallet> wallet = WalletOnFile(strFile);
    BOOST_CHECK_EQUAL(Load(*wallet), DB_TOO_NEW);
    BOOST_CHECK(wallet->mapWallet.empty());
    std::vector<uint256> vTxHash;
    std::vector<CWalletTx> vWtx;
    CWalletDB walletdb(wallet->GetDBHandle());
    BOOST_CHECK_EQUAL(walletdb.FindWalletTx(vTxHash, vWtx), DB_TOO_NEW);
    BOOST_CHECK_EQUAL(walletdb.ZapWalletTx(vWtx), DB_TOO_NEW);
    std::vector<uint256> vTxHashOut;
    BOOST_CHECK_EQUAL(walletdb.ZapSelectTx(vTxHash, vTxHashOut), DB_TOO_NEW);
    BOOST_CHECK(vWtx.empty());
}

namespace {

/** Loads a new file holding the given records into the wallet. */
template <typename Write>
DBErrors LoadRecords(CWallet& wallet, const std::string& strFile, Write write)
{
    {
        CWalletDBWrapper dbw(&bitdb, strFile);
        CDB batch(dbw, "cr+");
        write(batch);
    }
    return Load(wallet);
}

} // namespace

BOOST_AUTO_TEST_CASE(load_corrupt_key_records)
{
    const CKey key = NewKey();
    const CPubKey pubkey = key.GetPubKey();
    const CPrivKey privkey = key.GetPrivKey();
    const CKey other = NewKey();

    // Each failing key record makes the wallet corrupt.
    struct Case {
        std::string strFile;
        std::function<void(CDB&)> write;
    };
    const std::vector<Case> cases{
        {"walletdb_key_bad_pubkey.dat", [&](CDB& batch) { batch.Write(std::make_pair(TYPE_KEY, CPubKey()), std::make_pair(privkey, KeyChecksum(pubkey, privkey))); }},
        {"walletdb_key_bad_checksum.dat", [&](CDB& batch) { batch.Write(std::make_pair(TYPE_KEY, pubkey), std::make_pair(privkey, KeyChecksum(other.GetPubKey(), privkey))); }},
        {"walletdb_key_bad_privkey.dat", [&](CDB& batch) { batch.Write(std::make_pair(TYPE_KEY, pubkey), CPrivKey(10, 0x01)); }},
        {"walletdb_key_other_privkey.dat", [&](CDB& batch) { batch.Write(std::make_pair(TYPE_KEY, pubkey), std::make_pair(other.GetPrivKey(), KeyChecksum(pubkey, other.GetPrivKey()))); }},
        {"walletdb_key_other_privkey_no_checksum.dat", [&](CDB& batch) { batch.Write(std::make_pair(TYPE_KEY, pubkey), other.GetPrivKey()); }},
        {"walletdb_wkey_truncated.dat", [&](CDB& batch) { batch.Write(std::make_pair(std::string("wkey"), pubkey), 1); }},
        {"walletdb_ckey_bad_pubkey.dat", [&](CDB& batch) { batch.Write(std::make_pair(std::string("ckey"), CPubKey()), std::vector<unsigned char>(48, 0x01)); }},
        {"walletdb_ckey_after_key.dat", [&](CDB& batch) {
             batch.Write(std::make_pair(TYPE_KEY, pubkey), std::make_pair(privkey, KeyChecksum(pubkey, privkey)));
             batch.Write(std::make_pair(std::string("ckey"), other.GetPubKey()), std::vector<unsigned char>(48, 0x01));
         }},
        {"walletdb_mkey_truncated.dat", [&](CDB& batch) { batch.Write(std::make_pair(std::string("mkey"), 1U), 'x'); }},
    };
    for (const Case& c : cases) {
        std::unique_ptr<CWallet> wallet = WalletOnFile(c.strFile);
        BOOST_CHECK_MESSAGE(LoadRecords(*wallet, c.strFile, c.write) == DB_CORRUPT, c.strFile);
    }

    // A plain key is refused by a wallet that is encrypted and locked.
    {
        std::unique_ptr<CWallet> wallet = WalletOnFile("walletdb_key_into_locked.dat");
        BOOST_CHECK(wallet->LoadCryptedKey(other.GetPubKey(), std::vector<unsigned char>(48, 0x01)));
        BOOST_CHECK_EQUAL(LoadRecords(*wallet, "walletdb_key_into_locked.dat", [&](CDB& batch) {
            batch.Write(std::make_pair(TYPE_KEY, pubkey), std::make_pair(privkey, KeyChecksum(pubkey, privkey)));
        }), DB_CORRUPT);
        BOOST_CHECK(!wallet->HaveKey(pubkey.GetID()));
    }
    // A master key id that the wallet has already.
    {
        std::unique_ptr<CWallet> wallet = WalletOnFile("walletdb_mkey_duplicate.dat");
        wallet->mapMasterKeys[1] = CMasterKey();
        CMasterKey masterKey;
        masterKey.nDeriveIterations = 30000;
        BOOST_CHECK_EQUAL(LoadRecords(*wallet, "walletdb_mkey_duplicate.dat", [&](CDB& batch) {
            batch.Write(std::make_pair(std::string("mkey"), 1U), masterKey);
        }), DB_CORRUPT);
        BOOST_CHECK_EQUAL(wallet->mapMasterKeys[1].nDeriveIterations, 25000U);
    }
    // Master keys are loaded, and the highest id is kept.
    {
        std::unique_ptr<CWallet> wallet = WalletOnFile("walletdb_mkey.dat");
        BOOST_CHECK_EQUAL(LoadRecords(*wallet, "walletdb_mkey.dat", [&](CDB& batch) {
            batch.Write(std::make_pair(std::string("mkey"), 4U), CMasterKey());
            batch.Write(std::make_pair(std::string("mkey"), 2U), CMasterKey());
            batch.Write(std::make_pair(std::string("ckey"), pubkey), std::vector<unsigned char>(48, 0x01));
        }), DB_LOAD_OK);
        BOOST_CHECK_EQUAL(wallet->mapMasterKeys.size(), 2U);
        BOOST_CHECK_EQUAL(wallet->nMasterKeyMaxID, 4U);
        BOOST_CHECK(wallet->IsCrypted());
        BOOST_CHECK(wallet->HaveKey(pubkey.GetID()));
    }
}

BOOST_AUTO_TEST_CASE(load_noncritical_errors)
{
    // A transaction stored under another hash is skipped, and a rescan is asked for.
    {
        ArgsSnapshot args;
        BOOST_REQUIRE(!gArgs.IsArgSet("-rescan"));
        const CWalletTx wtx = NewWalletTx(0);
        std::unique_ptr<CWallet> wallet = WalletOnFile("walletdb_tx_bad_hash.dat");
        BOOST_CHECK_EQUAL(LoadRecords(*wallet, "walletdb_tx_bad_hash.dat", [&](CDB& batch) {
            batch.Write(std::make_pair(std::string("tx"), InsecureRand256()), wtx);
        }), DB_NONCRITICAL_ERROR);
        BOOST_CHECK(wallet->mapWallet.empty());
        BOOST_CHECK(gArgs.GetBoolArg("-rescan", false));
    }
    // Another record that cannot be read is skipped without a rescan; the records after it load.
    {
        ArgsSnapshot args;
        BOOST_REQUIRE(!gArgs.IsArgSet("-rescan"));
        const CKey key = NewKey();
        std::unique_ptr<CWallet> wallet = WalletOnFile("walletdb_name_truncated.dat");
        BOOST_CHECK_EQUAL(LoadRecords(*wallet, "walletdb_name_truncated.dat", [&](CDB& batch) {
            batch.Write(std::make_pair(TYPE_NAME, AddressOf(key.GetPubKey().GetID())), uint8_t(10));
            batch.Write(std::make_pair(TYPE_KEY, key.GetPubKey()), std::make_pair(key.GetPrivKey(), KeyChecksum(key.GetPubKey(), key.GetPrivKey())));
        }), DB_NONCRITICAL_ERROR);
        BOOST_CHECK(!gArgs.IsArgSet("-rescan"));
        BOOST_CHECK(wallet->HaveKey(key.GetPubKey().GetID()));
    }
}

BOOST_AUTO_TEST_CASE(find_and_zap_transactions)
{
    const std::string strFile = "walletdb_zap.dat";
    std::vector<CWalletTx> vCreated;
    for (int i = 0; i < 4; ++i)
        vCreated.push_back(NewWalletTx(i));
    CWalletDBWrapper dbw(&bitdb, strFile);
    {
        CWalletDB walletdb(dbw, "cr+");
        for (const CWalletTx& wtx : vCreated)
            BOOST_CHECK(walletdb.WriteTx(wtx));
        BOOST_CHECK(walletdb.WriteName("address", "label"));
    }

    // Every transaction record is found, in key order, with its value.
    std::vector<uint256> vTxHash;
    std::vector<CWalletTx> vWtx;
    BOOST_CHECK_EQUAL(CWalletDB(dbw).FindWalletTx(vTxHash, vWtx), DB_LOAD_OK);
    BOOST_REQUIRE_EQUAL(vTxHash.size(), 4U);
    BOOST_REQUIRE_EQUAL(vWtx.size(), 4U);
    for (size_t i = 0; i < vTxHash.size(); ++i)
        BOOST_CHECK(vWtx[i].GetHash() == vTxHash[i]);
    std::vector<uint256> vSorted = vTxHash;
    std::sort(vSorted.begin(), vSorted.end());
    std::vector<uint256> vCreatedHashes;
    for (const CWalletTx& wtx : vCreated)
        vCreatedHashes.push_back(wtx.GetHash());
    std::sort(vCreatedHashes.begin(), vCreatedHashes.end());
    BOOST_CHECK(vSorted == vCreatedHashes);

    // Nothing to select erases nothing.
    std::vector<uint256> vSelect;
    std::vector<uint256> vErased;
    BOOST_CHECK_EQUAL(CWalletDB(dbw).ZapSelectTx(vSelect, vErased), DB_LOAD_OK);
    BOOST_CHECK(vErased.empty());

    // An unsorted selection with an unknown hash erases exactly the known ones, and returns them.
    vSelect = {vCreatedHashes[3], InsecureRand256(), vCreatedHashes[0], vCreatedHashes[2]};
    BOOST_CHECK_EQUAL(CWalletDB(dbw).ZapSelectTx(vSelect, vErased), DB_LOAD_OK);
    BOOST_CHECK(vErased == (std::vector<uint256>{vCreatedHashes[0], vCreatedHashes[2], vCreatedHashes[3]}));
    vTxHash.clear();
    vWtx.clear();
    BOOST_CHECK_EQUAL(CWalletDB(dbw).FindWalletTx(vTxHash, vWtx), DB_LOAD_OK);
    BOOST_CHECK(vTxHash == std::vector<uint256>{vCreatedHashes[1]});

    // ZapWalletTx erases every transaction and returns them.
    {
        CWalletDB walletdb(dbw);
        for (const CWalletTx& wtx : vCreated) {
            if (wtx.GetHash() == vCreatedHashes[0])
                BOOST_CHECK(walletdb.WriteTx(wtx));
        }
    }
    vWtx.clear();
    BOOST_CHECK_EQUAL(CWalletDB(dbw).ZapWalletTx(vWtx), DB_LOAD_OK);
    std::vector<uint256> vZapped;
    for (const CWalletTx& wtx : vWtx)
        vZapped.push_back(wtx.GetHash());
    std::sort(vZapped.begin(), vZapped.end());
    BOOST_CHECK(vZapped == (std::vector<uint256>{vCreatedHashes[0], vCreatedHashes[1]}));
    vTxHash.clear();
    std::vector<CWalletTx> vLeft;
    BOOST_CHECK_EQUAL(CWalletDB(dbw).FindWalletTx(vTxHash, vLeft), DB_LOAD_OK);
    BOOST_CHECK(vTxHash.empty());
    CDB batch(dbw, "r");
    BOOST_CHECK(batch.Exists(std::make_pair(TYPE_NAME, std::string("address"))));
}

BOOST_AUTO_TEST_CASE(find_transactions_corrupt)
{
    // A transaction value that cannot be read makes the scan fail.
    const std::string strFile = "walletdb_find_corrupt.dat";
    CWalletDBWrapper dbw(&bitdb, strFile);
    {
        CDB batch(dbw, "cr+");
        BOOST_CHECK(batch.Write(std::make_pair(std::string("tx"), InsecureRand256()), std::string("x")));
    }
    std::vector<uint256> vTxHash;
    std::vector<CWalletTx> vWtx;
    BOOST_CHECK_EQUAL(CWalletDB(dbw).FindWalletTx(vTxHash, vWtx), DB_CORRUPT);
    BOOST_CHECK_EQUAL(CWalletDB(dbw).ZapWalletTx(vWtx), DB_CORRUPT);
    std::vector<uint256> vTxHashOut;
    BOOST_CHECK_EQUAL(CWalletDB(dbw).ZapSelectTx(vTxHash, vTxHashOut), DB_CORRUPT);
}

namespace {

/** RecoverKeysOnlyFilter on one record, read into a wallet of its own. */
template <typename K, typename V>
bool Filter(const std::string& strType, const K& keyRest, const V& value)
{
    CWallet dummyWallet;
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssKey << strType << keyRest;
    ssValue << value;
    return CWalletDB::RecoverKeysOnlyFilter(&dummyWallet, ssKey, ssValue);
}

} // namespace

BOOST_AUTO_TEST_CASE(recover_keys_only_filter)
{
    const CKey key = NewKey();
    const CPubKey pubkey = key.GetPubKey();

    // Key records and the HD chain pass.
    BOOST_CHECK(Filter(TYPE_KEY, pubkey, std::make_pair(key.GetPrivKey(), KeyChecksum(pubkey, key.GetPrivKey()))));
    BOOST_CHECK(Filter("ckey", pubkey, std::vector<unsigned char>(48, 0x01)));
    BOOST_CHECK(Filter("mkey", 1U, CMasterKey()));
    CWalletKey wkey;
    wkey.vchPrivKey = key.GetPrivKey();
    BOOST_CHECK(Filter("wkey", pubkey, wkey));
    {
        CWallet dummyWallet;
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssKey << std::string("hdchain");
        ssValue << CHDChain();
        BOOST_CHECK(CWalletDB::RecoverKeysOnlyFilter(&dummyWallet, ssKey, ssValue));
    }

    // Other records do not, nor does a key record that cannot be read.
    BOOST_CHECK(!Filter(TYPE_NAME, AddressOf(pubkey.GetID()), std::string("label")));
    const CWalletTx wtx = NewWalletTx(0);
    BOOST_CHECK(!Filter("tx", wtx.GetHash(), wtx));
    BOOST_CHECK(!Filter(TYPE_KEY, CPubKey(), std::make_pair(key.GetPrivKey(), KeyChecksum(pubkey, key.GetPrivKey()))));
    BOOST_CHECK(!Filter(TYPE_KEY, pubkey, std::make_pair(key.GetPrivKey(), KeyChecksum(NewKey().GetPubKey(), key.GetPrivKey()))));
}

BOOST_AUTO_TEST_CASE(maybe_compact_wallet_db)
{
    ArgsSnapshot args;
    gArgs.ForceSetArg("-flushwallet", "1");
    const std::vector<CWalletRef> vpwalletsBefore = vpwallets;
    std::unique_ptr<CWallet> wallet = WalletOnFile("walletdb_compact.dat");
    CWalletDBWrapper& dbw = wallet->GetDBHandle();
    BOOST_CHECK(CWalletDB(dbw, "cr+").WriteName("address", "label"));
    const unsigned int nCounter = dbw.nUpdateCounter;
    BOOST_CHECK(nCounter > 0);
    vpwallets.assign(1, wallet.get());

    // A changed counter is noted with the time; the file is flushed two seconds after the
    // last change.
    const int64_t nTime = 1700000000;
    SetMockTime(nTime);
    MaybeCompactWalletDB();
    BOOST_CHECK_EQUAL(dbw.nLastSeen, nCounter);
    BOOST_CHECK_EQUAL(dbw.nLastWalletUpdate, nTime);
    BOOST_CHECK_EQUAL(dbw.nLastFlushed, 0U);
    SetMockTime(nTime + 1);
    MaybeCompactWalletDB();
    BOOST_CHECK_EQUAL(dbw.nLastWalletUpdate, nTime);
    BOOST_CHECK_EQUAL(dbw.nLastFlushed, 0U);
    SetMockTime(nTime + 2);
    MaybeCompactWalletDB();
    BOOST_CHECK_EQUAL(dbw.nLastFlushed, nCounter);
    BOOST_CHECK_EQUAL(dbw.nLastWalletUpdate, nTime);

    // With -flushwallet=0 a change is not noted. This part runs last: the function returns
    // there with its one-thread flag still set.
    BOOST_CHECK(CWalletDB(dbw, "cr+").WriteName("address", "other"));
    BOOST_CHECK(dbw.nUpdateCounter != nCounter);
    gArgs.ForceSetArg("-flushwallet", "0");
    MaybeCompactWalletDB();
    BOOST_CHECK_EQUAL(dbw.nLastSeen, nCounter);
    BOOST_CHECK_EQUAL(dbw.nLastFlushed, nCounter);

    SetMockTime(0);
    vpwallets = vpwalletsBefore;
}

BOOST_FIXTURE_TEST_CASE(dump_wallet, TestChain100Setup)
{
    LOCK(cs_main);
    CWallet wallet;
    LOCK(wallet.cs_wallet);

    auto AddKeyAt = [&wallet](const CKey& key, int64_t nTime) {
        wallet.mapKeyMetadata[key.GetPubKey().GetID()].nCreateTime = nTime;
        BOOST_CHECK(wallet.AddKeyPubKey(key, key.GetPubKey()));
    };
    const CKey labelled = NewKey();
    const CKey reserve = NewKey();
    const CKey change = NewKey(false);
    AddKeyAt(labelled, 1500000000);
    AddKeyAt(reserve, 1500000100);
    AddKeyAt(change, 1500000200);
    BOOST_CHECK(wallet.SetAddressBook(labelled.GetPubKey().GetID(), "my label%", "receive"));
    wallet.LoadKeyPool(1, CKeyPool(reserve.GetPubKey()));

    // The active HD master key and an older one.
    const CPubKey inactiveMaster = wallet.GenerateNewHDMasterKey();
    const CPubKey master = wallet.GenerateNewHDMasterKey();
    BOOST_CHECK(wallet.SetHDMasterKey(master));

    // Two redeem scripts of compressed wallet keys, one with a label.
    const CScript cltvScript = GetScriptForCltvP2SH(1000, labelled.GetPubKey());
    const CScript csvScript = GetScriptForCsvP2SH(2000, reserve.GetPubKey());
    BOOST_CHECK(wallet.AddCScript(cltvScript));
    BOOST_CHECK(wallet.AddCScript(csvScript));
    BOOST_CHECK(wallet.SetAddressBook(CScriptID(cltvScript), "time lock", "receive"));
    // A redeem script of an uncompressed wallet key.
    const CScript uncompressedScript = GetScriptForCltvP2SH(3000, change.GetPubKey());
    BOOST_CHECK(wallet.AddCScript(uncompressedScript));

    const fs::path path = pathTemp / "walletdb_dump.txt";
    BOOST_CHECK(DumpWallet(&wallet, path.string()));
    const std::vector<std::string> vLines = ReadLines(path);

    auto Wif = [](const CKey& key) { return CBitcoinSecret(key).ToString(); };
    auto Line = [&](const CKey& key, const std::string& strTag, const std::string& strKeypath) {
        const CKeyID keyid = key.GetPubKey().GetID();
        return strprintf("%s %s %s # addr=%s%s", Wif(key), EncodeDumpTime(wallet.mapKeyMetadata[keyid].nCreateTime), strTag,
                         AddressOf(keyid), strKeypath);
    };
    CKey masterKey;
    CKey inactiveMasterKey;
    BOOST_REQUIRE(wallet.GetKey(master.GetID(), masterKey));
    BOOST_REQUIRE(wallet.GetKey(inactiveMaster.GetID(), inactiveMasterKey));

    BOOST_REQUIRE(!vLines.empty());
    BOOST_CHECK_EQUAL(vLines[0].substr(0, 31), "# Wallet dump created by Yacoin");
    BOOST_CHECK(Contains(vLines, strprintf("# * Best block at time of backup was %i (%s),", chainActive.Height(),
                                           chainActive.Tip()->GetBlockHash().ToString())));
    BOOST_CHECK(Contains(vLines, "# BELOW ARE LIST OF P2PKH ADDRESSES AND THEIR PRIVATE KEYS:"));
    CExtKey extMaster;
    extMaster.SetMaster(masterKey.begin(), masterKey.size());
    CBitcoinExtKey b58extMaster;
    b58extMaster.SetKey(extMaster);
    BOOST_CHECK(Contains(vLines, "# extended private masterkey: " + b58extMaster.ToString()));
    BOOST_CHECK(Contains(vLines, Line(labelled, "label=my%20label%25", "")));
    BOOST_CHECK(Contains(vLines, Line(reserve, "reserve=1", "")));
    BOOST_CHECK(Contains(vLines, Line(change, "change=1", "")));
    BOOST_CHECK(Contains(vLines, Line(masterKey, "hdmaster=1", " hdkeypath=m")));
    BOOST_CHECK(Contains(vLines, Line(inactiveMasterKey, "inactivehdmaster=1", " hdkeypath=m")));
    BOOST_CHECK(Contains(vLines, "# BELOW ARE LIST OF P2SH ADDRESSES AND THEIR PRIVATE KEYS:"));
    BOOST_CHECK(Contains(vLines, strprintf("%s type=CLTV_P2SH_timelock label=time%%20lock redeemscript=%s # addr=%s", Wif(labelled),
                                           HexStr(cltvScript.begin(), cltvScript.end()), AddressOf(CScriptID(cltvScript)))));
    BOOST_CHECK(Contains(vLines, strprintf("%s type=CSV_P2SH_timelock change=1 redeemscript=%s # addr=%s", Wif(reserve),
                                           HexStr(csvScript.begin(), csvScript.end()), AddressOf(CScriptID(csvScript)))));
    BOOST_CHECK_EQUAL(vLines.back(), "# End of dump");

    // known defect, MG-046: the P2SH lines always give the key in compressed form, whatever
    // form the redeem script uses
    const std::string strUncompressedSuffix = strprintf(" type=CLTV_P2SH_timelock change=1 redeemscript=%s # addr=%s",
        HexStr(uncompressedScript.begin(), uncompressedScript.end()), AddressOf(CScriptID(uncompressedScript)));
    std::string strUncompressedWif = "(no line)";
    for (const std::string& line : vLines) {
        const size_t nSpace = line.find(' ');
        if (nSpace != std::string::npos && line.substr(nSpace) == strUncompressedSuffix)
            strUncompressedWif = line.substr(0, nSpace);
    }
    CKey changeCompressed;
    changeCompressed.Set(change.begin(), change.end(), true);
    KNOWN_FAILURE_EQUAL("MG-046", strUncompressedWif, Wif(change), Wif(changeCompressed));

    // The P2PKH keys are sorted by birth time.
    auto Position = [&vLines](const std::string& line) { return std::find(vLines.begin(), vLines.end(), line) - vLines.begin(); };
    BOOST_CHECK(Position(Line(labelled, "label=my%20label%25", "")) < Position(Line(reserve, "reserve=1", "")));
    BOOST_CHECK(Position(Line(reserve, "reserve=1", "")) < Position(Line(change, "change=1", "")));

    // A path that cannot be opened.
    BOOST_CHECK(!DumpWallet(&wallet, (pathTemp / "no-such-directory" / "dump.txt").string()));
}

BOOST_FIXTURE_TEST_CASE(dump_wallet_master_key_not_held, TestChain100Setup)
{
    // An HD chain whose master key the wallet does not hold gives no extended key line.
    LOCK(cs_main);
    CWallet wallet;
    LOCK(wallet.cs_wallet);
    CHDChain chain;
    chain.masterKeyID = NewKey().GetPubKey().GetID();
    BOOST_CHECK(wallet.SetHDChain(chain, true));
    const fs::path path = pathTemp / "walletdb_dump_no_master.txt";
    BOOST_CHECK(DumpWallet(&wallet, path.string()));
    for (const std::string& line : ReadLines(path))
        BOOST_CHECK(line.find("extended private masterkey") == std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(import_wallet_sections, TestChain100Setup)
{
    LOCK(cs_main);
    CWallet wallet;
    LOCK(wallet.cs_wallet);

    const CKey labelled = NewKey();
    const CKey change = NewKey();
    const CKey reserve = NewKey();
    const CKey untagged = NewKey(false);
    const CKey scriptKey = NewKey();
    const CScript cltvScript = GetScriptForCltvP2SH(1000, scriptKey.GetPubKey());
    const CScript csvScript = GetScriptForCsvP2SH(2000, labelled.GetPubKey());
    auto Wif = [](const CKey& key) { return CBitcoinSecret(key).ToString(); };
    auto Hex = [](const CScript& script) { return HexStr(script.begin(), script.end()); };

    const fs::path path = pathTemp / "walletdb_import.txt";
    {
        std::ofstream file(path.string());
        file << "# a comment\n\n";
        file << "@ P2PKH\n";
        file << Wif(labelled) << " 2017-07-14T02:40:00Z label=first%20label # addr=x\n";
        file << Wif(change) << " 2017-07-14T02:40:01Z change=1\n";
        file << Wif(reserve) << " 2017-07-14T02:40:02Z reserve=1 # label=ignored\n";
        file << Wif(untagged) << " 2017-07-14T02:40:03Z\n";
        file << Wif(labelled) << " 2017-07-14T02:40:04Z label=again\n";
        file << "short\n";
        file << "notasecret 2017-07-14T02:40:05Z label=bad\n";
        file << "@ P2SH\n";
        file << Wif(scriptKey) << " type=CLTV_P2SH_timelock label=time%20lock redeemscript=" << Hex(cltvScript) << " # addr=y\n";
        file << Wif(labelled) << " type=CSV_P2SH_timelock label=second redeemscript=" << Hex(csvScript) << "\n";
        file << Wif(labelled) << " type=CSV_P2SH_timelock label=third redeemscript=" << Hex(csvScript) << "\n";
    }
    BOOST_CHECK(ImportWallet(&wallet, path.string()));

    // P2PKH section: keys with their birth times; a label unless the line says change=1 or
    // reserve=1; a line without a tag gets an empty label. A key that is present is skipped.
    for (const CKey& key : {labelled, change, reserve, untagged, scriptKey})
        BOOST_CHECK(wallet.HaveKey(key.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(wallet.mapKeyMetadata[labelled.GetPubKey().GetID()].nCreateTime, 1500000000);
    BOOST_CHECK_EQUAL(wallet.mapKeyMetadata[change.GetPubKey().GetID()].nCreateTime, 1500000001);
    BOOST_CHECK_EQUAL(wallet.mapKeyMetadata[untagged.GetPubKey().GetID()].nCreateTime, 1500000003);
    BOOST_CHECK_EQUAL(LabelOf(wallet, labelled.GetPubKey().GetID()), "first label");
    BOOST_CHECK_EQUAL(wallet.mapAddressBook[labelled.GetPubKey().GetID()].purpose, "receive");
    BOOST_CHECK_EQUAL(LabelOf(wallet, change.GetPubKey().GetID()), "(no entry)");
    BOOST_CHECK_EQUAL(LabelOf(wallet, reserve.GetPubKey().GetID()), "(no entry)");
    BOOST_CHECK_EQUAL(LabelOf(wallet, untagged.GetPubKey().GetID()), "");

    // P2SH section: the redeem script with its label; for a key that is present only the script
    // and its label are added, once.
    BOOST_CHECK(wallet.HaveCScript(CScriptID(cltvScript)));
    BOOST_CHECK_EQUAL(LabelOf(wallet, CScriptID(cltvScript)), "time lock");
    BOOST_CHECK_EQUAL(LabelOf(wallet, scriptKey.GetPubKey().GetID()), "(no entry)");
    BOOST_CHECK_EQUAL(wallet.mapKeyMetadata[scriptKey.GetPubKey().GetID()].nCreateTime, 0);
    BOOST_CHECK(wallet.HaveCScript(CScriptID(csvScript)));
    BOOST_CHECK_EQUAL(LabelOf(wallet, CScriptID(csvScript)), "second");

    // A file that cannot be opened.
    BOOST_CHECK(!ImportWallet(&wallet, (pathTemp / "walletdb_missing.txt").string()));
}

BOOST_FIXTURE_TEST_CASE(import_wallet_locked, TestChain100Setup)
{
    // A wallet that is encrypted and locked takes no key: the import fails.
    LOCK(cs_main);
    CWallet wallet;
    LOCK(wallet.cs_wallet);
    BOOST_CHECK(wallet.LoadCryptedKey(NewKey().GetPubKey(), std::vector<unsigned char>(48, 0x01)));
    BOOST_CHECK(wallet.IsLocked());
    const CKey key = NewKey();
    const fs::path path = pathTemp / "walletdb_import_locked.txt";
    {
        std::ofstream file(path.string());
        file << "@\n" << CBitcoinSecret(key).ToString() << " 2017-07-14T02:40:00Z label=x\n";
    }
    BOOST_CHECK(!ImportWallet(&wallet, path.string()));
    BOOST_CHECK(!wallet.HaveKey(key.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(LabelOf(wallet, key.GetPubKey().GetID()), "(no entry)");
}

BOOST_FIXTURE_TEST_CASE(dump_import_round_trip, TestChain100Setup)
{
    LOCK(cs_main);
    const CKey key = NewKey();
    const CScript script = GetScriptForCltvP2SH(1000, key.GetPubKey());
    const int64_t nBirthTime = 1500000000;
    const fs::path path = pathTemp / "walletdb_round_trip.txt";
    {
        CWallet source;
        LOCK(source.cs_wallet);
        source.mapKeyMetadata[key.GetPubKey().GetID()].nCreateTime = nBirthTime;
        BOOST_CHECK(source.AddKeyPubKey(key, key.GetPubKey()));
        BOOST_CHECK(source.SetAddressBook(key.GetPubKey().GetID(), "round trip", "receive"));
        BOOST_CHECK(source.AddCScript(script));
        BOOST_CHECK(DumpWallet(&source, path.string()));
    }

    CWallet restored;
    LOCK(restored.cs_wallet);
    BOOST_CHECK(ImportWallet(&restored, path.string()));
    CKey keyOut;
    BOOST_CHECK(restored.GetKey(key.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut == key);

    // known defect, MG-046: the import does not restore the label, the birth time and the
    // redeem script of a dump
    KNOWN_FAILURE_EQUAL("MG-046", LabelOf(restored, key.GetPubKey().GetID()), "round trip", "(no entry)");
    KNOWN_FAILURE_EQUAL("MG-046", restored.mapKeyMetadata[key.GetPubKey().GetID()].nCreateTime, nBirthTime, 0);
    KNOWN_FAILURE("MG-046", restored.HaveCScript(CScriptID(script)), restored.HaveCScript(CScriptID(script)),
                  !restored.HaveCScript(CScriptID(script)));
}

BOOST_AUTO_TEST_SUITE_END()
