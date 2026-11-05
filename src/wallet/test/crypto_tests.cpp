// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"
#include "wallet/crypter.h"

#include <map>
#include <set>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <openssl/aes.h>
#include <openssl/evp.h>

BOOST_FIXTURE_TEST_SUITE(wallet_crypto, BasicTestingSetup)

bool OldSetKeyFromPassphrase(const SecureString& strKeyData, const std::vector<unsigned char>& chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod, unsigned char* chKey, unsigned char* chIV)
{
    if (nRounds < 1 || chSalt.size() != WALLET_CRYPTO_SALT_SIZE)
        return false;

    int i = 0;
    if (nDerivationMethod == 0)
        i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &chSalt[0],
                          (unsigned char *)&strKeyData[0], strKeyData.size(), nRounds, chKey, chIV);

    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memory_cleanse(chKey, WALLET_CRYPTO_KEY_SIZE);
        memory_cleanse(chIV, WALLET_CRYPTO_IV_SIZE);
        return false;
    }
    return true;
}

bool OldEncrypt(const CKeyingMaterial& vchPlaintext, std::vector<unsigned char> &vchCiphertext, const unsigned char chKey[32], const unsigned char chIV[16])
{
    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCK_SIZE - 1 bytes
    int nLen = vchPlaintext.size();
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    vchCiphertext = std::vector<unsigned char> (nCLen);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) return false;

    bool fOk = true;

    EVP_CIPHER_CTX_init(ctx);
    if (fOk) fOk = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, chKey, chIV) != 0;
    if (fOk) fOk = EVP_EncryptUpdate(ctx, &vchCiphertext[0], &nCLen, &vchPlaintext[0], nLen) != 0;
    if (fOk) fOk = EVP_EncryptFinal_ex(ctx, (&vchCiphertext[0]) + nCLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(ctx);

    EVP_CIPHER_CTX_free(ctx);

    if (!fOk) return false;

    vchCiphertext.resize(nCLen + nFLen);
    return true;
}

bool OldDecrypt(const std::vector<unsigned char>& vchCiphertext, CKeyingMaterial& vchPlaintext, const unsigned char chKey[32], const unsigned char chIV[16])
{
    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = vchCiphertext.size();
    int nPLen = nLen, nFLen = 0;

    vchPlaintext = CKeyingMaterial(nPLen);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) return false;

    bool fOk = true;

    EVP_CIPHER_CTX_init(ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, chKey, chIV) != 0;
    if (fOk) fOk = EVP_DecryptUpdate(ctx, &vchPlaintext[0], &nPLen, &vchCiphertext[0], nLen) != 0;
    if (fOk) fOk = EVP_DecryptFinal_ex(ctx, (&vchPlaintext[0]) + nPLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(ctx);

    EVP_CIPHER_CTX_free(ctx);

    if (!fOk) return false;

    vchPlaintext.resize(nPLen + nFLen);
    return true;
}

class TestCrypter
{
public:
static void TestPassphraseSingle(const std::vector<unsigned char>& vchSalt, const SecureString& passphrase, uint32_t rounds,
                 const std::vector<unsigned char>& correctKey = std::vector<unsigned char>(),
                 const std::vector<unsigned char>& correctIV=std::vector<unsigned char>())
{
    unsigned char chKey[WALLET_CRYPTO_KEY_SIZE];
    unsigned char chIV[WALLET_CRYPTO_IV_SIZE];

    CCrypter crypt;
    crypt.SetKeyFromPassphrase(passphrase, vchSalt, rounds, 0);

    OldSetKeyFromPassphrase(passphrase, vchSalt, rounds, 0, chKey, chIV);

    BOOST_CHECK_MESSAGE(memcmp(chKey, crypt.vchKey.data(), crypt.vchKey.size()) == 0, \
        HexStr(chKey, chKey+sizeof(chKey)) + std::string(" != ") + HexStr(crypt.vchKey));
    BOOST_CHECK_MESSAGE(memcmp(chIV, crypt.vchIV.data(), crypt.vchIV.size()) == 0, \
        HexStr(chIV, chIV+sizeof(chIV)) + std::string(" != ") + HexStr(crypt.vchIV));

    if(!correctKey.empty())
        BOOST_CHECK_MESSAGE(memcmp(chKey, &correctKey[0], sizeof(chKey)) == 0, \
            HexStr(chKey, chKey+sizeof(chKey)) + std::string(" != ") + HexStr(correctKey.begin(), correctKey.end()));
    if(!correctIV.empty())
        BOOST_CHECK_MESSAGE(memcmp(chIV, &correctIV[0], sizeof(chIV)) == 0,
            HexStr(chIV, chIV+sizeof(chIV)) + std::string(" != ") + HexStr(correctIV.begin(), correctIV.end()));
}

static void TestPassphrase(const std::vector<unsigned char>& vchSalt, const SecureString& passphrase, uint32_t rounds,
                 const std::vector<unsigned char>& correctKey = std::vector<unsigned char>(),
                 const std::vector<unsigned char>& correctIV=std::vector<unsigned char>())
{
    TestPassphraseSingle(vchSalt, passphrase, rounds, correctKey, correctIV);
    for(SecureString::const_iterator i(passphrase.begin()); i != passphrase.end(); ++i)
        TestPassphraseSingle(vchSalt, SecureString(i, passphrase.end()), rounds);
}


static void TestDecrypt(const CCrypter& crypt, const std::vector<unsigned char>& vchCiphertext, \
                        const std::vector<unsigned char>& vchPlaintext = std::vector<unsigned char>())
{
    CKeyingMaterial vchDecrypted1;
    CKeyingMaterial vchDecrypted2;
    int result1, result2;
    result1 = crypt.Decrypt(vchCiphertext, vchDecrypted1);
    result2 = OldDecrypt(vchCiphertext, vchDecrypted2, crypt.vchKey.data(), crypt.vchIV.data());
    BOOST_CHECK(result1 == result2);

    // These two should be equal. However, OpenSSL 1.0.1j introduced a change
    // that would zero all padding except for the last byte for failed decrypts.
    // This behavior was reverted for 1.0.1k.
    if (vchDecrypted1 != vchDecrypted2 && vchDecrypted1.size() >= AES_BLOCK_SIZE && SSLeay() == 0x100010afL)
    {
        for(CKeyingMaterial::iterator it = vchDecrypted1.end() - AES_BLOCK_SIZE; it != vchDecrypted1.end() - 1; it++)
            *it = 0;
    }

    BOOST_CHECK_MESSAGE(vchDecrypted1 == vchDecrypted2, HexStr(vchDecrypted1.begin(), vchDecrypted1.end()) + " != " + HexStr(vchDecrypted2.begin(), vchDecrypted2.end()));

    if (vchPlaintext.size())
        BOOST_CHECK(CKeyingMaterial(vchPlaintext.begin(), vchPlaintext.end()) == vchDecrypted2);
}

static void TestEncryptSingle(const CCrypter& crypt, const CKeyingMaterial& vchPlaintext,
                       const std::vector<unsigned char>& vchCiphertextCorrect = std::vector<unsigned char>())
{
    std::vector<unsigned char> vchCiphertext1;
    std::vector<unsigned char> vchCiphertext2;
    int result1 = crypt.Encrypt(vchPlaintext, vchCiphertext1);

    int result2 = OldEncrypt(vchPlaintext, vchCiphertext2, crypt.vchKey.data(), crypt.vchIV.data());
    BOOST_CHECK(result1 == result2);
    BOOST_CHECK(vchCiphertext1 == vchCiphertext2);

    if (!vchCiphertextCorrect.empty())
        BOOST_CHECK(vchCiphertext2 == vchCiphertextCorrect);

    const std::vector<unsigned char> vchPlaintext2(vchPlaintext.begin(), vchPlaintext.end());

    if(vchCiphertext1 == vchCiphertext2)
        TestDecrypt(crypt, vchCiphertext1, vchPlaintext2);
}

static void TestEncrypt(const CCrypter& crypt, const std::vector<unsigned char>& vchPlaintextIn, \
                       const std::vector<unsigned char>& vchCiphertextCorrect = std::vector<unsigned char>())
{
    TestEncryptSingle(crypt, CKeyingMaterial(vchPlaintextIn.begin(), vchPlaintextIn.end()), vchCiphertextCorrect);
    for(std::vector<unsigned char>::const_iterator i(vchPlaintextIn.begin()); i != vchPlaintextIn.end(); ++i)
        TestEncryptSingle(crypt, CKeyingMaterial(i, vchPlaintextIn.end()));
}

};

BOOST_AUTO_TEST_CASE(passphrase) {
    // These are expensive.

    TestCrypter::TestPassphrase(ParseHex("0000deadbeef0000"), "test", 25000, \
                                ParseHex("fc7aba077ad5f4c3a0988d8daa4810d0d4a0e3bcb53af662998898f33df0556a"), \
                                ParseHex("cf2f2691526dd1aa220896fb8bf7c369"));

    std::string hash(GetRandHash().ToString());
    std::vector<unsigned char> vchSalt(8);
    GetRandBytes(&vchSalt[0], vchSalt.size());
    uint32_t rounds = InsecureRand32();
    if (rounds > 30000)
        rounds = 30000;
    TestCrypter::TestPassphrase(vchSalt, SecureString(hash.begin(), hash.end()), rounds);
}

BOOST_AUTO_TEST_CASE(encrypt) {
    std::vector<unsigned char> vchSalt = ParseHex("0000deadbeef0000");
    BOOST_CHECK(vchSalt.size() == WALLET_CRYPTO_SALT_SIZE);
    CCrypter crypt;
    crypt.SetKeyFromPassphrase("passphrase", vchSalt, 25000, 0);
    TestCrypter::TestEncrypt(crypt, ParseHex("22bcade09ac03ff6386914359cfe885cfeb5f77ff0d670f102f619687453b29d"));

    for (int i = 0; i != 100; i++)
    {
        uint256 hash(GetRandHash());
        TestCrypter::TestEncrypt(crypt, std::vector<unsigned char>(hash.begin(), hash.end()));
    }

}

BOOST_AUTO_TEST_CASE(decrypt) {
    std::vector<unsigned char> vchSalt = ParseHex("0000deadbeef0000");
    BOOST_CHECK(vchSalt.size() == WALLET_CRYPTO_SALT_SIZE);
    CCrypter crypt;
    crypt.SetKeyFromPassphrase("passphrase", vchSalt, 25000, 0);

    // Some corner cases the came up while testing
    TestCrypter::TestDecrypt(crypt,ParseHex("795643ce39d736088367822cdc50535ec6f103715e3e48f4f3b1a60a08ef59ca"));
    TestCrypter::TestDecrypt(crypt,ParseHex("de096f4a8f9bd97db012aa9d90d74de8cdea779c3ee8bc7633d8b5d6da703486"));
    TestCrypter::TestDecrypt(crypt,ParseHex("32d0a8974e3afd9c6c3ebf4d66aa4e6419f8c173de25947f98cf8b7ace49449c"));
    TestCrypter::TestDecrypt(crypt,ParseHex("e7c055cca2faa78cb9ac22c9357a90b4778ded9b2cc220a14cea49f931e596ea"));
    TestCrypter::TestDecrypt(crypt,ParseHex("b88efddd668a6801d19516d6830da4ae9811988ccbaf40df8fbb72f3f4d335fd"));
    TestCrypter::TestDecrypt(crypt,ParseHex("8cae76aa6a43694e961ebcb28c8ca8f8540b84153d72865e8561ddd93fa7bfa9"));

    for (int i = 0; i != 100; i++)
    {
        uint256 hash(GetRandHash());
        TestCrypter::TestDecrypt(crypt, std::vector<unsigned char>(hash.begin(), hash.end()));
    }
}

namespace {

/** Exposes the protected members of CCryptoKeyStore and records the encrypted secrets that
 *  reach AddCryptedKey; with fRefuseCryptedKeys set, AddCryptedKey refuses every key. */
class TestCryptoKeyStore : public CCryptoKeyStore
{
public:
    using CCryptoKeyStore::DecryptKeys;
    using CCryptoKeyStore::EncryptKeys;
    using CCryptoKeyStore::SetCrypted;
    using CCryptoKeyStore::Unlock;

    bool fRefuseCryptedKeys = false;
    std::map<CKeyID, std::vector<unsigned char>> mapAdded;

    bool AddCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret) override
    {
        if (fRefuseCryptedKeys)
            return false;
        mapAdded[vchPubKey.GetID()] = vchCryptedSecret;
        return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
    }

    size_t PlainKeyCount() const
    {
        std::set<CKeyID> setAddress;
        CBasicKeyStore::GetKeys(setAddress);
        return setAddress.size();
    }
};

CKey NewKey(bool fCompressed)
{
    CKey key;
    key.MakeNewKey(fCompressed);
    return key;
}

CKeyingMaterial NewMasterKey()
{
    CKeyingMaterial vMasterKey(WALLET_CRYPTO_KEY_SIZE);
    GetRandBytes(vMasterKey.data(), vMasterKey.size());
    return vMasterKey;
}

std::vector<unsigned char> IVFromHash(const uint256& hash)
{
    return std::vector<unsigned char>(hash.begin(), hash.begin() + WALLET_CRYPTO_IV_SIZE);
}

/** The secret encrypted under the master key with the IV the key store uses for pubkey: the
 *  first bytes of the public key's hash. */
std::vector<unsigned char> EncryptFor(const CKeyingMaterial& vMasterKey, const CKeyingMaterial& vchSecret, const CPubKey& pubkey)
{
    CCrypter crypter;
    BOOST_REQUIRE(crypter.SetKey(vMasterKey, IVFromHash(pubkey.GetHash())));
    std::vector<unsigned char> vchCiphertext;
    BOOST_REQUIRE(crypter.Encrypt(vchSecret, vchCiphertext));
    return vchCiphertext;
}

CKeyingMaterial SecretOf(const CKey& key)
{
    return CKeyingMaterial(key.begin(), key.end());
}

} // namespace

BOOST_AUTO_TEST_CASE(crypter_key_and_iv_sizes)
{
    const CKeyingMaterial vKey = NewMasterKey();
    const std::vector<unsigned char> vIV(WALLET_CRYPTO_IV_SIZE, 0x5a);
    const CKeyingMaterial vchPlaintext(40, 0x11);
    std::vector<unsigned char> vchCiphertext;
    CKeyingMaterial vchDecrypted;

    // Without a key nothing is encrypted or decrypted.
    CCrypter crypter;
    BOOST_CHECK(!crypter.Encrypt(vchPlaintext, vchCiphertext));
    BOOST_CHECK(!crypter.Decrypt(std::vector<unsigned char>(32, 0x22), vchDecrypted));

    // A key or IV of the wrong size is refused and sets no key.
    BOOST_CHECK(!crypter.SetKey(CKeyingMaterial(WALLET_CRYPTO_KEY_SIZE - 1, 0x01), vIV));
    BOOST_CHECK(!crypter.SetKey(CKeyingMaterial(WALLET_CRYPTO_KEY_SIZE + 1, 0x01), vIV));
    BOOST_CHECK(!crypter.SetKey(vKey, std::vector<unsigned char>(WALLET_CRYPTO_IV_SIZE - 1, 0x01)));
    BOOST_CHECK(!crypter.SetKey(vKey, std::vector<unsigned char>(WALLET_CRYPTO_IV_SIZE + 1, 0x01)));
    BOOST_CHECK(!crypter.Encrypt(vchPlaintext, vchCiphertext));

    // The right sizes give a key that encrypts and decrypts.
    BOOST_CHECK(crypter.SetKey(vKey, vIV));
    BOOST_CHECK(crypter.Encrypt(vchPlaintext, vchCiphertext));
    BOOST_CHECK_EQUAL(vchCiphertext.size(), 48U);
    BOOST_CHECK(crypter.Decrypt(vchCiphertext, vchDecrypted));
    BOOST_CHECK(vchDecrypted == vchPlaintext);

    // A ciphertext that is not a whole number of blocks does not decrypt.
    BOOST_CHECK(!crypter.Decrypt(std::vector<unsigned char>(vchCiphertext.begin(), vchCiphertext.end() - 1), vchDecrypted));

    // CleanKey removes the key.
    crypter.CleanKey();
    BOOST_CHECK(!crypter.Encrypt(vchPlaintext, vchCiphertext));
}

BOOST_AUTO_TEST_CASE(crypter_passphrase_parameters)
{
    const std::vector<unsigned char> vchSalt = ParseHex("0000deadbeef0000");

    // No rounds, a salt of the wrong size and a derivation method other than 0 are refused.
    CCrypter crypter;
    BOOST_CHECK(!crypter.SetKeyFromPassphrase("passphrase", vchSalt, 0, 0));
    BOOST_CHECK(!crypter.SetKeyFromPassphrase("passphrase", std::vector<unsigned char>(WALLET_CRYPTO_SALT_SIZE - 1, 0x00), 1, 0));
    BOOST_CHECK(!crypter.SetKeyFromPassphrase("passphrase", std::vector<unsigned char>(WALLET_CRYPTO_SALT_SIZE + 1, 0x00), 1, 0));
    BOOST_CHECK(!crypter.SetKeyFromPassphrase("passphrase", vchSalt, 1, 1));
    BOOST_CHECK(crypter.SetKeyFromPassphrase("passphrase", vchSalt, 1, 0));
}

BOOST_AUTO_TEST_CASE(keystore_plain)
{
    TestCryptoKeyStore store;
    BOOST_CHECK(!store.IsCrypted());
    BOOST_CHECK(!store.IsLocked());

    const CKey key = NewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(store.AddKeyPubKey(key, pubkey));
    BOOST_CHECK(store.HaveKey(pubkey.GetID()));
    BOOST_CHECK_EQUAL(store.PlainKeyCount(), 1U);
    CKey keyOut;
    BOOST_CHECK(store.GetKey(pubkey.GetID(), keyOut));
    BOOST_CHECK(keyOut == key);
    CPubKey pubkeyOut;
    BOOST_CHECK(store.GetPubKey(pubkey.GetID(), pubkeyOut));
    BOOST_CHECK(pubkeyOut == pubkey);
    std::set<CKeyID> setAddress;
    store.GetKeys(setAddress);
    BOOST_CHECK(setAddress == std::set<CKeyID>{pubkey.GetID()});
    BOOST_CHECK(!store.HaveKey(NewKey(true).GetPubKey().GetID()));

    // A store with plain keys can be neither locked nor marked as encrypted, and takes no
    // encrypted key.
    BOOST_CHECK(!store.Lock());
    BOOST_CHECK(!store.SetCrypted());
    const CKey other = NewKey(true);
    BOOST_CHECK(!store.AddCryptedKey(other.GetPubKey(), std::vector<unsigned char>(48, 0x01)));
    BOOST_CHECK(!store.IsCrypted());
    BOOST_CHECK(!store.IsLocked());
    BOOST_CHECK(!store.HaveKey(other.GetPubKey().GetID()));

    // An empty store is marked as encrypted, and stays so.
    TestCryptoKeyStore empty;
    BOOST_CHECK(empty.SetCrypted());
    BOOST_CHECK(empty.IsCrypted());
    BOOST_CHECK(empty.IsLocked());
    BOOST_CHECK(empty.SetCrypted());
}

BOOST_AUTO_TEST_CASE(keystore_encrypt_keys)
{
    TestCryptoKeyStore store;
    const CKey compressed = NewKey(true);
    const CKey uncompressed = NewKey(false);
    BOOST_CHECK(store.AddKey(compressed));
    BOOST_CHECK(store.AddKey(uncompressed));

    CKeyingMaterial vMasterKey = NewMasterKey();
    BOOST_CHECK(store.EncryptKeys(vMasterKey));
    BOOST_CHECK(store.IsCrypted());
    BOOST_CHECK(store.IsLocked());
    BOOST_CHECK_EQUAL(store.PlainKeyCount(), 0U);

    for (const CKey& key : {compressed, uncompressed}) {
        const CPubKey pubkey = key.GetPubKey();
        BOOST_CHECK(store.HaveKey(pubkey.GetID()));
        CPubKey pubkeyOut;
        BOOST_CHECK(store.GetPubKey(pubkey.GetID(), pubkeyOut));
        BOOST_CHECK(pubkeyOut == pubkey);
        CKey keyOut;
        BOOST_CHECK(!store.GetKey(pubkey.GetID(), keyOut));

        // Each secret is encrypted under the master key with the IV taken from the hash of
        // its public key.
        BOOST_REQUIRE(store.mapAdded.count(pubkey.GetID()));
        const std::vector<unsigned char>& vchCrypted = store.mapAdded[pubkey.GetID()];
        BOOST_CHECK(vchCrypted == EncryptFor(vMasterKey, SecretOf(key), pubkey));
        CCrypter crypter;
        CKeyingMaterial vchSecret;
        BOOST_CHECK(crypter.SetKey(vMasterKey, IVFromHash(pubkey.GetHash())));
        BOOST_CHECK(crypter.Decrypt(vchCrypted, vchSecret));
        BOOST_CHECK(vchSecret == SecretOf(key));

        // Another IV or another master key does not give the secret back.
        BOOST_CHECK(crypter.SetKey(vMasterKey, IVFromHash(Hash(pubkey.begin(), pubkey.end() - 1))));
        BOOST_CHECK(!crypter.Decrypt(vchCrypted, vchSecret) || vchSecret != SecretOf(key));
        BOOST_CHECK(crypter.SetKey(NewMasterKey(), IVFromHash(pubkey.GetHash())));
        BOOST_CHECK(!crypter.Decrypt(vchCrypted, vchSecret) || vchSecret != SecretOf(key));
    }

    std::set<CKeyID> setAddress;
    store.GetKeys(setAddress);
    BOOST_CHECK(setAddress == (std::set<CKeyID>{compressed.GetPubKey().GetID(), uncompressed.GetPubKey().GetID()}));

    // An unknown key is neither present nor readable.
    const CKeyID unknown = NewKey(true).GetPubKey().GetID();
    CKey keyOut;
    CPubKey pubkeyOut;
    BOOST_CHECK(!store.HaveKey(unknown));
    BOOST_CHECK(!store.GetKey(unknown, keyOut));
    BOOST_CHECK(!store.GetPubKey(unknown, pubkeyOut));

    // The keys are encrypted only once.
    BOOST_CHECK(!store.EncryptKeys(vMasterKey));
}

BOOST_AUTO_TEST_CASE(keystore_encrypt_keys_failures)
{
    // A master key of the wrong size encrypts nothing; the store is left marked as encrypted
    // with its plain keys.
    {
        TestCryptoKeyStore store;
        BOOST_CHECK(store.AddKey(NewKey(true)));
        CKeyingMaterial vShortKey(WALLET_CRYPTO_KEY_SIZE - 1, 0x01);
        BOOST_CHECK(!store.EncryptKeys(vShortKey));
        BOOST_CHECK(store.IsCrypted());
        BOOST_CHECK(store.mapAdded.empty());
        BOOST_CHECK_EQUAL(store.PlainKeyCount(), 1U);
    }
    // A key that AddCryptedKey refuses ends the encryption.
    {
        TestCryptoKeyStore store;
        BOOST_CHECK(store.AddKey(NewKey(true)));
        store.fRefuseCryptedKeys = true;
        CKeyingMaterial vMasterKey = NewMasterKey();
        BOOST_CHECK(!store.EncryptKeys(vMasterKey));
        BOOST_CHECK(store.IsCrypted());
        BOOST_CHECK_EQUAL(store.PlainKeyCount(), 1U);
    }
    // A store that holds encrypted keys is not encrypted again.
    {
        TestCryptoKeyStore store;
        const CKey key = NewKey(true);
        CKeyingMaterial vMasterKey = NewMasterKey();
        BOOST_CHECK(store.AddCryptedKey(key.GetPubKey(), EncryptFor(vMasterKey, SecretOf(key), key.GetPubKey())));
        BOOST_CHECK(!store.EncryptKeys(vMasterKey));
    }
}

BOOST_AUTO_TEST_CASE(keystore_unlock_and_lock)
{
    TestCryptoKeyStore store;
    const CKey compressed = NewKey(true);
    const CKey uncompressed = NewKey(false);
    BOOST_CHECK(store.AddKey(compressed));
    BOOST_CHECK(store.AddKey(uncompressed));
    CKeyingMaterial vMasterKey = NewMasterKey();
    BOOST_CHECK(store.EncryptKeys(vMasterKey));

    int nStatusChanges = 0;
    store.NotifyStatusChanged.connect([&nStatusChanges](CCryptoKeyStore*) { ++nStatusChanges; });

    // A wrong master key, or one of the wrong size, does not unlock.
    BOOST_CHECK(!store.Unlock(NewMasterKey()));
    BOOST_CHECK(!store.Unlock(CKeyingMaterial(WALLET_CRYPTO_KEY_SIZE + 1, 0x01)));
    BOOST_CHECK(store.IsLocked());
    BOOST_CHECK_EQUAL(nStatusChanges, 0);

    // The right one unlocks, and the keys are readable.
    BOOST_CHECK(store.Unlock(vMasterKey));
    BOOST_CHECK(!store.IsLocked());
    BOOST_CHECK_EQUAL(nStatusChanges, 1);
    for (const CKey& key : {compressed, uncompressed}) {
        CKey keyOut;
        BOOST_CHECK(store.GetKey(key.GetPubKey().GetID(), keyOut));
        BOOST_CHECK(keyOut == key);
        BOOST_CHECK_EQUAL(keyOut.IsCompressed(), key.IsCompressed());
    }

    // Lock clears the master key.
    BOOST_CHECK(store.Lock());
    BOOST_CHECK(store.IsLocked());
    BOOST_CHECK_EQUAL(nStatusChanges, 2);
    CKey keyOut;
    BOOST_CHECK(!store.GetKey(compressed.GetPubKey().GetID(), keyOut));

    // After the first unlock a wrong key still does not unlock, and the right one does again.
    BOOST_CHECK(!store.Unlock(NewMasterKey()));
    BOOST_CHECK(store.IsLocked());
    BOOST_CHECK(store.Unlock(vMasterKey));
    BOOST_CHECK(!store.IsLocked());
    BOOST_CHECK_EQUAL(nStatusChanges, 3);
    BOOST_CHECK(store.GetKey(uncompressed.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut == uncompressed);
    BOOST_CHECK(store.Lock());
    BOOST_CHECK_EQUAL(nStatusChanges, 4);

    // A store with plain keys does not unlock, and an encrypted store without keys neither.
    TestCryptoKeyStore plain;
    BOOST_CHECK(plain.AddKey(NewKey(true)));
    BOOST_CHECK(!plain.Unlock(vMasterKey));
    BOOST_CHECK(!plain.IsCrypted());
    TestCryptoKeyStore empty;
    BOOST_CHECK(empty.SetCrypted());
    BOOST_CHECK(!empty.Unlock(vMasterKey));
    BOOST_CHECK(empty.IsLocked());
}

BOOST_AUTO_TEST_CASE(keystore_add_key_when_encrypted)
{
    TestCryptoKeyStore store;
    BOOST_CHECK(store.AddKey(NewKey(true)));
    CKeyingMaterial vMasterKey = NewMasterKey();
    BOOST_CHECK(store.EncryptKeys(vMasterKey));

    // A locked store takes no key.
    const CKey locked = NewKey(true);
    BOOST_CHECK(!store.AddKeyPubKey(locked, locked.GetPubKey()));
    BOOST_CHECK(!store.HaveKey(locked.GetPubKey().GetID()));

    // An unlocked store encrypts the key it takes.
    BOOST_CHECK(store.Unlock(vMasterKey));
    const CKey key = NewKey(false);
    BOOST_CHECK(store.AddKeyPubKey(key, key.GetPubKey()));
    BOOST_CHECK(store.HaveKey(key.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(store.PlainKeyCount(), 0U);
    BOOST_CHECK(store.mapAdded[key.GetPubKey().GetID()] == EncryptFor(vMasterKey, SecretOf(key), key.GetPubKey()));
    CKey keyOut;
    BOOST_CHECK(store.GetKey(key.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut == key);

    // A key that AddCryptedKey refuses is not added.
    store.fRefuseCryptedKeys = true;
    const CKey refused = NewKey(true);
    BOOST_CHECK(!store.AddKeyPubKey(refused, refused.GetPubKey()));
    BOOST_CHECK(!store.HaveKey(refused.GetPubKey().GetID()));
}

BOOST_AUTO_TEST_CASE(keystore_get_key_decrypt_failures)
{
    TestCryptoKeyStore store;
    BOOST_CHECK(store.AddKey(NewKey(true)));
    CKeyingMaterial vMasterKey = NewMasterKey();
    BOOST_CHECK(store.EncryptKeys(vMasterKey));
    BOOST_CHECK(store.Unlock(vMasterKey));

    // A secret that decrypts to fewer than 32 bytes.
    const CKey shortSecret = NewKey(true);
    const CKeyingMaterial vchShort(16, 0x07);
    BOOST_CHECK(store.AddCryptedKey(shortSecret.GetPubKey(), EncryptFor(vMasterKey, vchShort, shortSecret.GetPubKey())));
    // A secret of another key.
    const CKey mismatched = NewKey(true);
    BOOST_CHECK(store.AddCryptedKey(mismatched.GetPubKey(), EncryptFor(vMasterKey, SecretOf(NewKey(true)), mismatched.GetPubKey())));
    // A ciphertext that is not a whole number of blocks.
    const CKey truncated = NewKey(true);
    BOOST_CHECK(store.AddCryptedKey(truncated.GetPubKey(), std::vector<unsigned char>(47, 0x01)));

    for (const CKey& key : {shortSecret, mismatched, truncated}) {
        BOOST_CHECK(store.HaveKey(key.GetPubKey().GetID()));
        CKey keyOut;
        BOOST_CHECK(!store.GetKey(key.GetPubKey().GetID(), keyOut));
    }
}

BOOST_AUTO_TEST_CASE(keystore_decrypt_keys)
{
    // A store that is not encrypted has nothing to decrypt.
    {
        TestCryptoKeyStore plain;
        BOOST_CHECK(plain.AddKey(NewKey(true)));
        BOOST_CHECK(!plain.DecryptKeys(NewMasterKey()));
        BOOST_CHECK_EQUAL(plain.PlainKeyCount(), 1U);
    }

    const CKey key = NewKey(true);
    CKeyingMaterial vMasterKey = NewMasterKey();

    // A master key of the wrong size, or a secret that decrypts to fewer than 32 bytes, fails.
    {
        TestCryptoKeyStore store;
        BOOST_CHECK(store.AddKey(key));
        BOOST_CHECK(store.EncryptKeys(vMasterKey));
        BOOST_CHECK(!store.DecryptKeys(CKeyingMaterial(WALLET_CRYPTO_KEY_SIZE - 1, 0x01)));
        BOOST_CHECK(store.HaveKey(key.GetPubKey().GetID()));
    }
    {
        TestCryptoKeyStore store;
        BOOST_CHECK(store.SetCrypted());
        BOOST_CHECK(store.AddCryptedKey(key.GetPubKey(), EncryptFor(vMasterKey, CKeyingMaterial(16, 0x07), key.GetPubKey())));
        BOOST_CHECK(!store.DecryptKeys(vMasterKey));
        BOOST_CHECK(store.HaveKey(key.GetPubKey().GetID()));
    }

    // With the right master key the decrypted keys are added through AddKeyPubKey, which on
    // this store, still marked as encrypted, refuses them while it is locked.
    {
        TestCryptoKeyStore store;
        BOOST_CHECK(store.AddKey(key));
        BOOST_CHECK(store.EncryptKeys(vMasterKey));
        BOOST_CHECK(!store.DecryptKeys(vMasterKey));
        BOOST_CHECK(store.IsCrypted());
        BOOST_CHECK(store.HaveKey(key.GetPubKey().GetID()));
        BOOST_CHECK_EQUAL(store.PlainKeyCount(), 0U);
    }
    // Unlocked, AddKeyPubKey encrypts each decrypted key again into the encrypted map, which
    // DecryptKeys then clears: it returns true, and the store, still marked as encrypted and
    // unlocked, holds no key at all.
    {
        TestCryptoKeyStore store;
        BOOST_CHECK(store.AddKey(key));
        BOOST_CHECK(store.EncryptKeys(vMasterKey));
        BOOST_CHECK(store.Unlock(vMasterKey));
        BOOST_CHECK(store.DecryptKeys(vMasterKey));
        BOOST_CHECK(store.IsCrypted());
        BOOST_CHECK(!store.IsLocked());
        BOOST_CHECK_EQUAL(store.PlainKeyCount(), 0U);
        BOOST_CHECK(!store.HaveKey(key.GetPubKey().GetID()));
        std::set<CKeyID> setAddress;
        store.GetKeys(setAddress);
        BOOST_CHECK(setAddress.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
