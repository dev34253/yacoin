// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// CWallet's encryption (encrypt, change the passphrase, decrypt), its key, script
// and watch-only bookkeeping, and its keypool, on the mock wallet database.

#include "random.h"
#include "script/standard.h"
#include "support/allocators/secure.h"
#include "wallet/crypter.h"
#include "wallet/walletdb.h"

#include "wallet/test/wallet_chain_setup.h"
#include "wallet/test/wallet_test_fixture.h"

#include <set>

#include <boost/test/unit_test.hpp>

namespace {

const SecureString PASSPHRASE("first passphrase");

/** A wallet on strFile of the mock environment, holding the keys of a second wallet object
 *  that loads the file, as a restart would */
struct Reloaded {
    CWallet wallet;
    DBErrors result;
    explicit Reloaded(const std::string& strFile)
        : wallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, strFile))),
          result(CWalletDB(wallet.GetDBHandle(), "cr+").LoadWallet(&wallet)) {}
};

/** A master key record for vMasterKey under passphrase, as EncryptWallet writes it (with the
 *  smallest number of rounds EncryptWallet uses) */
CMasterKey MasterKeyFor(const CKeyingMaterial& vMasterKey, const SecureString& passphrase)
{
    CMasterKey masterKey;
    masterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetRandBytes(masterKey.vchSalt.data(), WALLET_CRYPTO_SALT_SIZE);
    masterKey.nDeriveIterations = 25000;
    CCrypter crypter;
    BOOST_REQUIRE(crypter.SetKeyFromPassphrase(passphrase, masterKey.vchSalt, masterKey.nDeriveIterations, masterKey.nDerivationMethod));
    BOOST_REQUIRE(crypter.Encrypt(vMasterKey, masterKey.vchCryptedKey));
    return masterKey;
}

/** The secret of key encrypted under vMasterKey, as the key store stores it */
std::vector<unsigned char> CryptedSecret(const CKeyingMaterial& vMasterKey, const CKey& key)
{
    const uint256 hash = key.GetPubKey().GetHash();
    CCrypter crypter;
    BOOST_REQUIRE(crypter.SetKey(vMasterKey, std::vector<unsigned char>(hash.begin(), hash.begin() + WALLET_CRYPTO_IV_SIZE)));
    std::vector<unsigned char> vchCrypted;
    BOOST_REQUIRE(crypter.Encrypt(CKeyingMaterial(key.begin(), key.end()), vchCrypted));
    return vchCrypted;
}

/** The index of the oldest external keypool entry (the entry is given back) */
int64_t OldestPoolIndex(CWallet& wallet)
{
    int64_t nIndex;
    CKeyPool keypool;
    wallet.ReserveKeyFromKeyPool(nIndex, keypool, false);
    if (nIndex != -1)
        wallet.ReturnKey(nIndex, false, keypool.vchPubKey);
    return nIndex;
}

/** An encrypted, locked wallet object without a database */
struct LockedWallet {
    CWallet wallet;
    CKey key;
    LockedWallet() : key(NewWalletTestKey())
    {
        BOOST_REQUIRE(wallet.LoadCryptedKey(key.GetPubKey(), std::vector<unsigned char>(48, 0x01)));
        BOOST_REQUIRE(wallet.IsLocked());
    }
};

/** Makes path the current directory while it lives */
struct CurrentPathGuard {
    const fs::path saved;
    explicit CurrentPathGuard(const fs::path& path) : saved(fs::current_path()) { fs::current_path(path); }
    ~CurrentPathGuard() { fs::current_path(saved); }
    CurrentPathGuard(const CurrentPathGuard&) = delete;
    CurrentPathGuard& operator=(const CurrentPathGuard&) = delete;
};

/**
 * The wallet test setup, run in the test's temporary directory: on the mock database
 * environment the rewrite of a wallet file (after encryption, for example) copies the
 * file into the current directory, and fails since the original is not a file there.
 * The copy's cached pages are written out before the directory changes back.
 */
struct EncryptionTestingSetup : public WalletTestingSetup {
    CurrentPathGuard currentPath{pathTemp};
    ~EncryptionTestingSetup() { bitdb.dbenv->txn_checkpoint(0, 0, 0); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(wallet_encryption_tests, EncryptionTestingSetup)

BOOST_AUTO_TEST_CASE(encrypt_wallet)
{
    ArgGuard keypool("-keypool", "2");
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_encrypt.dat");
    const CKey key = NewWalletTestKey();
    AddWalletTestKey(*wallet, key);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->SetHDMasterKey(wallet->GenerateNewHDMasterKey()));
    }
    BOOST_REQUIRE(wallet->TopUpKeyPool());
    const CKeyID oldMaster = wallet->GetHDChain().masterKeyID;
    const int64_t nOldestBefore = OldestPoolIndex(*wallet);
    BOOST_REQUIRE_EQUAL(nOldestBefore, 1);
    int nStatusChanged = 0;
    boost::signals2::scoped_connection connection(
        wallet->NotifyStatusChanged.connect([&nStatusChanged](CCryptoKeyStore*) { nStatusChanged++; }));

    // The wallet ends up encrypted and locked, with its keys, a new HD seed and a new keypool
    BOOST_CHECK(wallet->EncryptWallet(PASSPHRASE));
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK(nStatusChanged > 0);
    BOOST_CHECK_EQUAL(wallet->mapMasterKeys.size(), 1U);
    BOOST_CHECK(wallet->mapMasterKeys.begin()->second.nDeriveIterations >= 25000U);
    BOOST_CHECK(wallet->HaveKey(key.GetPubKey().GetID()));
    BOOST_CHECK(wallet->HaveKey(oldMaster));
    BOOST_CHECK(wallet->GetHDChain().masterKeyID != oldMaster);
    BOOST_CHECK(wallet->HaveKey(wallet->GetHDChain().masterKeyID));
    BOOST_CHECK(wallet->GetVersion() >= FEATURE_WALLETCRYPT);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->GetKeyPoolSize(), 2U);
    }
    CKey keyOut;
    BOOST_CHECK(!wallet->GetKey(key.GetPubKey().GetID(), keyOut));

    // An encrypted wallet is not encrypted again
    BOOST_CHECK(!wallet->EncryptWallet(SecureString("second passphrase")));
    BOOST_CHECK_EQUAL(wallet->mapMasterKeys.size(), 1U);

    // Only the passphrase unlocks it; the keys come back as they were
    BOOST_CHECK(!wallet->Unlock(SecureString("wrong passphrase")));
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK(wallet->Unlock(PASSPHRASE));
    BOOST_CHECK(wallet->GetKey(key.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut == key);
    BOOST_CHECK(OldestPoolIndex(*wallet) > nOldestBefore + 1);

    // The database holds the master key and the encrypted keys
    Reloaded reloaded("wallet_encrypt.dat");
    BOOST_CHECK_EQUAL(reloaded.result, DB_LOAD_OK);
    BOOST_CHECK(reloaded.wallet.IsCrypted());
    BOOST_CHECK_EQUAL(reloaded.wallet.mapMasterKeys.size(), 1U);
    BOOST_CHECK(reloaded.wallet.Unlock(PASSPHRASE));
    BOOST_CHECK(reloaded.wallet.GetKey(key.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut == key);
}

BOOST_AUTO_TEST_CASE(encrypt_wallet_without_database)
{
    // Without a database the transaction cannot begin: EncryptWallet fails after keeping
    // the new master key in memory, and the keys stay unencrypted.
    CWallet wallet;
    const CKey key = NewWalletTestKey();
    AddWalletTestKey(wallet, key);
    BOOST_CHECK(!wallet.EncryptWallet(PASSPHRASE));
    BOOST_CHECK(!wallet.IsCrypted());
    BOOST_CHECK_EQUAL(wallet.mapMasterKeys.size(), 1U);
    CKey keyOut;
    BOOST_CHECK(wallet.GetKey(key.GetPubKey().GetID(), keyOut));
}

BOOST_AUTO_TEST_CASE(change_wallet_passphrase)
{
    ArgGuard keypool("-keypool", "1");
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_passphrase.dat");
    const CKey key = NewWalletTestKey();
    AddWalletTestKey(*wallet, key);

    // A wallet that is not encrypted has no passphrase to change
    BOOST_CHECK(!wallet->ChangeWalletPassphrase(PASSPHRASE, SecureString("new")));

    BOOST_REQUIRE(wallet->EncryptWallet(PASSPHRASE));
    const CMasterKey before = wallet->mapMasterKeys.begin()->second;

    // A wrong old passphrase changes nothing
    BOOST_CHECK(!wallet->ChangeWalletPassphrase(SecureString("wrong"), SecureString("new")));
    BOOST_CHECK(wallet->mapMasterKeys.begin()->second.vchCryptedKey == before.vchCryptedKey);
    BOOST_CHECK(wallet->IsLocked());

    // The right one: the new passphrase unlocks, the old one does not, and a locked wallet
    // stays locked
    const SecureString second("second passphrase");
    BOOST_CHECK(wallet->ChangeWalletPassphrase(PASSPHRASE, second));
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK(wallet->mapMasterKeys.begin()->second.vchSalt == before.vchSalt);
    BOOST_CHECK(wallet->mapMasterKeys.begin()->second.nDeriveIterations >= 25000U);
    BOOST_CHECK(!wallet->Unlock(PASSPHRASE));
    BOOST_CHECK(wallet->Unlock(second));

    // An unlocked wallet stays unlocked
    const SecureString third("third passphrase");
    BOOST_CHECK(wallet->ChangeWalletPassphrase(second, third));
    BOOST_CHECK(!wallet->IsLocked());
    CKey keyOut;
    BOOST_CHECK(wallet->GetKey(key.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut == key);

    // The database holds the master key under the last passphrase
    Reloaded reloaded("wallet_passphrase.dat");
    BOOST_CHECK(!reloaded.wallet.Unlock(second));
    BOOST_CHECK(reloaded.wallet.Unlock(third));
}

BOOST_AUTO_TEST_CASE(decrypt_wallet)
{
    ArgGuard keypool("-keypool", "1");
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_decrypt.dat");
    const CKey key = NewWalletTestKey();
    AddWalletTestKey(*wallet, key);

    // A wallet that is not encrypted is not decrypted
    BOOST_CHECK(!wallet->DecryptWallet(PASSPHRASE));

    BOOST_REQUIRE(wallet->EncryptWallet(PASSPHRASE));

    // A master key whose parameters the key derivation refuses, and a wrong passphrase, fail
    // before anything changes
    {
        LOCK(wallet->cs_wallet);
        CMasterKey refused = wallet->mapMasterKeys.begin()->second;
        refused.nDeriveIterations = 0;
        wallet->mapMasterKeys[0] = refused;
    }
    BOOST_CHECK(!wallet->DecryptWallet(PASSPHRASE));
    {
        LOCK(wallet->cs_wallet);
        wallet->mapMasterKeys.erase(0);
    }
    BOOST_CHECK(!wallet->DecryptWallet(SecureString("wrong passphrase")));
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK(wallet->HaveKey(key.GetPubKey().GetID()));
}

BOOST_AUTO_TEST_CASE(decrypt_wallet_with_keys_in_memory)
{
    // A wallet on the database whose master key and encrypted key are only in memory. With
    // the passphrase DecryptWallet returns true, but the keys are decrypted through the key
    // store, which is still marked as encrypted: it encrypts each key again (and writes the
    // encrypted key record) into the map it clears at the end. The wallet is left marked as
    // encrypted, unlocked and without any key, and the database holds the encrypted key and
    // no master key.
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_decrypt_memory.dat");
    const CKey key = NewWalletTestKey();
    CKeyingMaterial vMasterKey(WALLET_CRYPTO_KEY_SIZE);
    GetRandBytes(vMasterKey.data(), vMasterKey.size());
    wallet->mapMasterKeys[1] = MasterKeyFor(vMasterKey, PASSPHRASE);
    BOOST_REQUIRE(wallet->LoadCryptedKey(key.GetPubKey(), CryptedSecret(vMasterKey, key)));
    int nStatusChanged = 0;
    boost::signals2::scoped_connection connection(
        wallet->NotifyStatusChanged.connect([&nStatusChanged](CCryptoKeyStore*) { nStatusChanged++; }));

    BOOST_CHECK(wallet->DecryptWallet(PASSPHRASE));
    BOOST_CHECK(nStatusChanged > 0);
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(!wallet->IsLocked());
    BOOST_CHECK(!wallet->HaveKey(key.GetPubKey().GetID()));
    std::set<CKeyID> setKeys;
    wallet->GetKeys(setKeys);
    BOOST_CHECK(setKeys.empty());
    BOOST_CHECK_EQUAL(wallet->mapMasterKeys.size(), 1U);

    Reloaded reloaded("wallet_decrypt_memory.dat");
    BOOST_CHECK(reloaded.wallet.mapMasterKeys.empty());
    BOOST_CHECK(reloaded.wallet.IsCrypted());
    BOOST_CHECK(reloaded.wallet.HaveKey(key.GetPubKey().GetID()));
    CKey keyOut;
    BOOST_CHECK(!reloaded.wallet.GetKey(key.GetPubKey().GetID(), keyOut));
}

BOOST_AUTO_TEST_CASE(decrypt_wallet_without_database)
{
    // An encrypted wallet object without a database: the transaction cannot begin and
    // DecryptWallet fails with the keys unchanged.
    CWallet wallet;
    const CKey key = NewWalletTestKey();
    CKeyingMaterial vMasterKey(WALLET_CRYPTO_KEY_SIZE);
    GetRandBytes(vMasterKey.data(), vMasterKey.size());
    wallet.mapMasterKeys[1] = MasterKeyFor(vMasterKey, PASSPHRASE);
    BOOST_REQUIRE(wallet.LoadCryptedKey(key.GetPubKey(), CryptedSecret(vMasterKey, key)));
    BOOST_CHECK(!wallet.DecryptWallet(PASSPHRASE));
    BOOST_CHECK(wallet.IsCrypted());
    CKey keyOut;
    BOOST_CHECK(wallet.GetKey(key.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut == key);
}

BOOST_AUTO_TEST_CASE(crypted_keys_and_scripts)
{
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_crypted_keys.dat");
    const CKey key = NewWalletTestKey();

    // An encrypted key is refused by a wallet that holds a plain key, and stored by one that
    // holds none, which is then encrypted
    {
        CWallet plain;
        AddWalletTestKey(plain, NewWalletTestKey());
        BOOST_CHECK(!plain.AddCryptedKey(key.GetPubKey(), std::vector<unsigned char>(48, 0x01)));
    }
    BOOST_CHECK(wallet->AddCryptedKey(key.GetPubKey(), std::vector<unsigned char>(48, 0x01)));
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->HaveKey(key.GetPubKey().GetID()));
    Reloaded reloaded("wallet_crypted_keys.dat");
    BOOST_CHECK(reloaded.wallet.IsCrypted());
    BOOST_CHECK(reloaded.wallet.HaveKey(key.GetPubKey().GetID()));

    // A redeem script above the size limit is accepted when loaded, but not kept
    CScript oversized;
    oversized.insert(oversized.end(), MAX_SCRIPT_ELEMENT_SIZE + 1, OP_NOP);
    BOOST_CHECK(wallet->LoadCScript(oversized));
    BOOST_CHECK(!wallet->HaveCScript(CScriptID(oversized)));
    const CScript redeem = GetScriptForMultisig(1, {key.GetPubKey()});
    BOOST_CHECK(wallet->LoadCScript(redeem));
    BOOST_CHECK(wallet->HaveCScript(CScriptID(redeem)));
}

BOOST_AUTO_TEST_CASE(watch_only_scripts)
{
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_watch_only.dat");
    const CKey key = NewWalletTestKey();
    AddWalletTestKey(*wallet, key);
    std::vector<bool> notified;
    boost::signals2::scoped_connection connection(
        wallet->NotifyWatchonlyChanged.connect([&notified](bool fHaveWatchOnly) { notified.push_back(fHaveWatchOnly); }));

    // The script of a key the wallet holds is not watched
    BOOST_CHECK(!wallet->AddWatchOnly(GetScriptForDestination(key.GetPubKey().GetID()), 1));

    // Removing a script succeeds whether or not it is watched, and notifies when no script
    // is watched any more
    const CKey other = NewWalletTestKey();
    const CScript watched = GetScriptForDestination(other.GetPubKey().GetID());
    const CScript watchedRaw = GetScriptForRawPubKey(other.GetPubKey());
    LOCK(wallet->cs_wallet);
    BOOST_CHECK(wallet->RemoveWatchOnly(watched));
    BOOST_CHECK(wallet->AddWatchOnly(watched, 1));
    BOOST_CHECK(wallet->AddWatchOnly(watchedRaw, 1));
    BOOST_CHECK(wallet->RemoveWatchOnly(watched));
    BOOST_CHECK(wallet->HaveWatchOnly());
    BOOST_CHECK(notified == std::vector<bool>({false, true, true}));

    // Adding the key removes the watch-only scripts of its address and its public key
    BOOST_CHECK(wallet->AddWatchOnly(watched, 1));
    BOOST_CHECK(wallet->AddKeyPubKey(other, other.GetPubKey()));
    BOOST_CHECK(!wallet->HaveWatchOnly(watched));
    BOOST_CHECK(!wallet->HaveWatchOnly(watchedRaw));
    BOOST_CHECK(!wallet->HaveWatchOnly());
    BOOST_CHECK(notified == std::vector<bool>({false, true, true, true, false}));

    // Without a database the record cannot be erased: the script is removed in memory and
    // RemoveWatchOnly fails
    CWallet noDatabase;
    LOCK(noDatabase.cs_wallet);
    BOOST_CHECK(noDatabase.AddWatchOnly(watched, 1));
    BOOST_CHECK(!noDatabase.RemoveWatchOnly(watched));
    BOOST_CHECK(!noDatabase.HaveWatchOnly(watched));
}

BOOST_AUTO_TEST_CASE(wallet_versions)
{
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_versions.dat");
    LOCK(wallet->cs_wallet);
    BOOST_REQUIRE_EQUAL(wallet->GetVersion(), FEATURE_BASE);

    // An explicit upgrade past the maximum goes all the way to the latest version
    BOOST_CHECK(wallet->SetMaxVersion(FEATURE_WALLETCRYPT));
    BOOST_CHECK(wallet->SetMinVersion(FEATURE_COMPRPUBKEY, nullptr, true));
    BOOST_CHECK_EQUAL(wallet->GetVersion(), FEATURE_LATEST);
    BOOST_CHECK(wallet->CanSupportFeature(FEATURE_LATEST));

    // The maximum cannot go below the current version; a lower minimum changes nothing
    BOOST_CHECK(!wallet->SetMaxVersion(FEATURE_BASE));
    BOOST_CHECK(wallet->SetMinVersion(FEATURE_WALLETCRYPT));
    BOOST_CHECK_EQUAL(wallet->GetVersion(), FEATURE_LATEST);
}

BOOST_AUTO_TEST_CASE(keypool_of_locked_wallet)
{
    LockedWallet locked;
    CWallet& wallet = locked.wallet;
    SetMockTime(1600000000);

    // Nothing can be taken from or added to an empty keypool while locked
    CPubKey pubkey;
    BOOST_CHECK(!wallet.GetKeyFromPool(pubkey));
    BOOST_CHECK(!wallet.NewKeyPool());
    std::shared_ptr<CReserveScript> script;
    wallet.GetScriptForMining(script);
    BOOST_CHECK(!script);
    // The oldest key time of an empty keypool is the current time
    BOOST_CHECK_EQUAL(wallet.GetOldestKeyPoolTime(), 1600000000);
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(keypool_entries_that_do_not_match)
{
    ArgGuard keypoolSize("-keypool", "1");
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_keypool_entries.dat");
    const CKey held = NewWalletTestKey();
    AddWalletTestKey(*wallet, held);
    int64_t nIndex;
    CKeyPool keypool;
    LOCK(wallet->cs_wallet);

    // An entry that is not in the database
    wallet->LoadKeyPool(10, CKeyPool(held.GetPubKey(), false));
    BOOST_CHECK_THROW(wallet->GetOldestKeyPoolTime(), std::runtime_error);
    BOOST_CHECK_THROW(wallet->ReserveKeyFromKeyPool(nIndex, keypool, false), std::runtime_error);

    // An entry for a key the wallet does not hold
    const CKey unknown = NewWalletTestKey();
    BOOST_REQUIRE(CWalletDB(wallet->GetDBHandle()).WritePool(11, CKeyPool(unknown.GetPubKey(), false)));
    wallet->LoadKeyPool(11, CKeyPool(unknown.GetPubKey(), false));
    BOOST_CHECK_THROW(wallet->ReserveKeyFromKeyPool(nIndex, keypool, false), std::runtime_error);

    // An internal entry in the external keypool
    BOOST_REQUIRE(CWalletDB(wallet->GetDBHandle()).WritePool(12, CKeyPool(held.GetPubKey(), true)));
    wallet->LoadKeyPool(12, CKeyPool(held.GetPubKey(), false));
    BOOST_CHECK_THROW(wallet->ReserveKeyFromKeyPool(nIndex, keypool, false), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(used_keypool_key_in_locked_wallet)
{
    // A transaction paying a keypool key marks the keys up to it as used; a locked wallet
    // cannot top the keypool up again and keeps the transaction.
    ArgGuard keypool("-keypool", "3");
    std::unique_ptr<CWallet> wallet = NewMockWallet("wallet_used_keypool.dat");
    AddWalletTestKey(*wallet, NewWalletTestKey());
    BOOST_REQUIRE(wallet->EncryptWallet(PASSPHRASE));
    BOOST_REQUIRE(wallet->Unlock(PASSPHRASE));
    int64_t nIndex;
    CKeyPool entry;
    wallet->ReserveKeyFromKeyPool(nIndex, entry, false);
    BOOST_REQUIRE(nIndex != -1);
    wallet->ReturnKey(nIndex, false, entry.vchPubKey);
    BOOST_REQUIRE(wallet->Lock());
    unsigned int nPoolSize;
    {
        LOCK(wallet->cs_wallet);
        nPoolSize = wallet->GetKeyPoolSize();
    }

    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(InsecureRand256(), 0)));
    tx.vout.push_back(CTxOut(COIN, GetScriptForDestination(entry.vchPubKey.GetID())));
    wallet->TransactionAddedToMempool(MakeTransactionRef(tx));
    BOOST_CHECK(wallet->GetWalletTx(tx.GetHash()) != nullptr);
    LOCK(wallet->cs_wallet);
    BOOST_CHECK_EQUAL(wallet->GetKeyPoolSize(), nPoolSize - 1);
    BOOST_CHECK(wallet->IsLocked());
}

BOOST_AUTO_TEST_CASE(send_money_refusals)
{
    // A locked wallet, and a wallet unlocked for minting only, refuse to send
    {
        LockedWallet locked;
        CWalletTx wtx;
        BOOST_CHECK_EQUAL(locked.wallet.SendMoney(CScript() << OP_TRUE, COIN, wtx),
                          "Error: Wallet locked, unable to create transaction  ");
    }
    CWallet wallet;
    AddWalletTestKey(wallet, NewWalletTestKey());
    CWalletTx wtx;
    {
        ScopedValue<bool> mintOnly(fWalletUnlockMintOnly, true);
        BOOST_CHECK_EQUAL(wallet.SendMoney(CScript() << OP_TRUE, COIN, wtx),
                          "Error: Wallet unlocked for block minting only, unable to create transaction.");
    }

    // The amount is checked against the balance before anything else
    const CTxDestination dest = NewWalletTestKey().GetPubKey().GetID();
    BOOST_CHECK_EQUAL(wallet.SendMoneyToDestination(dest, 0, wtx), "Invalid amount");
    BOOST_CHECK_EQUAL(wallet.SendMoneyToDestination(dest, COIN, wtx), "Insufficient funds");
    BOOST_CHECK(wtx.tx->IsNull());
}


BOOST_AUTO_TEST_CASE(load_wallet_needing_rewrite)
{
    // An encrypted wallet of file version 40000 needs a rewrite, which LoadWallet reports
    // after trying it (the rewrite itself does not succeed on the mock database).
    const std::string strFile = "wallet_needs_rewrite.dat";
    {
        CWalletDBWrapper dbw(&bitdb, strFile);
        CWalletDB walletdb(dbw, "cr+");
        BOOST_REQUIRE(walletdb.WriteVersion(40000));
        BOOST_REQUIRE(walletdb.WriteCryptedKey(NewWalletTestKey().GetPubKey(), std::vector<unsigned char>(48, 0x01), CKeyMetadata(1)));
    }
    CWallet wallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, strFile)));
    bool fFirstRun = true;
    BOOST_CHECK_EQUAL(wallet.LoadWallet(fFirstRun), DB_NEED_REWRITE);
    BOOST_CHECK(wallet.IsCrypted());
    BOOST_CHECK(!fFirstRun);
}

BOOST_AUTO_TEST_SUITE_END()
