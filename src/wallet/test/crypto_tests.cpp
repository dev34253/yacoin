// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"
#include "pubkey.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"
#include "version.h"
#include "wallet/crypter.h"

#include "test/data/crypter_vectors.json.h"

#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <univalue.h>

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

// Access to the private parts of CCrypter for the known-answer cases below
// (task P0-22). These use no OpenSSL.
static int BytesToKey(const CCrypter& crypt, const std::vector<unsigned char>& chSalt, const SecureString& strKeyData, int count, unsigned char* key, unsigned char* iv)
{
    return crypt.BytesToKeySHA512AES(chSalt, strKeyData, count, key, iv);
}
static std::vector<unsigned char> Key(const CCrypter& crypt) { return std::vector<unsigned char>(crypt.vchKey.begin(), crypt.vchKey.end()); }
static std::vector<unsigned char> IV(const CCrypter& crypt) { return std::vector<unsigned char>(crypt.vchIV.begin(), crypt.vchIV.end()); }
static bool KeySet(const CCrypter& crypt) { return crypt.fKeySet; }

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

// ---------------------------------------------------------------------------
// Known-answer tests (task P0-22). The expected values in
// test/data/crypter_vectors.json come from an independent Python model
// (contrib/testing/crypter_vectors.py: hashlib, FIPS-197 AES, secp256k1),
// cross-checked against the OpenSSL 3 CLI when they were generated. The
// cases below use no OpenSSL, so the oracle cases above (passphrase,
// encrypt, decrypt and the Old* helpers) can be removed without losing
// coverage. Format: src/test/README.md, "Wallet crypter".
// ---------------------------------------------------------------------------

static const UniValue& CrypterVectors()
{
    static UniValue doc;
    if (doc.isNull()) {
        const std::string text(json_tests::crypter_vectors, json_tests::crypter_vectors + sizeof(json_tests::crypter_vectors));
        // On an error doc is reset, so every case that uses it fails.
        if (!doc.read(text) || !doc.isObject()) {
            doc = UniValue();
            throw std::runtime_error("crypter_vectors.json: parse error");
        }
        if (!find_value(doc, "format").isStr() || find_value(doc, "format").get_str() != "yacoin-crypter-vectors" ||
            !find_value(doc, "version").isStr() || find_value(doc, "version").get_str() != "1") {
            doc = UniValue();
            throw std::runtime_error("crypter_vectors.json: unexpected format or version");
        }
    }
    return doc;
}

static std::vector<unsigned char> Hex(const UniValue& obj, const std::string& name)
{
    const UniValue& v = find_value(obj, name);
    if (!v.isStr()) {
        throw std::runtime_error("crypter_vectors.json: missing string " + name);
    }
    return ParseHex(v.get_str());
}

static SecureString HexSecure(const UniValue& obj, const std::string& name)
{
    const std::vector<unsigned char> v = Hex(obj, name);
    return SecureString(v.begin(), v.end());
}

static CKeyingMaterial HexKeying(const UniValue& obj, const std::string& name)
{
    const std::vector<unsigned char> v = Hex(obj, name);
    return CKeyingMaterial(v.begin(), v.end());
}

static std::string HexOf(const CKeyingMaterial& v)
{
    return HexStr(v.begin(), v.end());
}

// The crypter keyed with the aes_cbc key/IV of the vector file.
static void AesCrypter(CCrypter& crypt)
{
    const UniValue& aes = find_value(CrypterVectors(), "aes_cbc");
    BOOST_REQUIRE(crypt.SetKey(HexKeying(aes, "key"), Hex(aes, "iv")));
}

BOOST_AUTO_TEST_CASE(kdf_vectors)
{
    const UniValue& kdf = find_value(CrypterVectors(), "kdf");
    BOOST_REQUIRE(kdf.isArray() && kdf.size() >= 10);
    for (unsigned int i = 0; i < kdf.size(); i++) {
        const UniValue& v = kdf[i];
        const std::string comment = find_value(v, "comment").get_str();
        const std::vector<unsigned char> salt = Hex(v, "salt");
        const SecureString passphrase = HexSecure(v, "passphrase");
        const int rounds = find_value(v, "rounds").get_int();

        CCrypter crypt;
        unsigned char key[WALLET_CRYPTO_KEY_SIZE];
        unsigned char iv[WALLET_CRYPTO_IV_SIZE];
        BOOST_CHECK_MESSAGE(TestCrypter::BytesToKey(crypt, salt, passphrase, rounds, key, iv) == (int)WALLET_CRYPTO_KEY_SIZE, comment);
        BOOST_CHECK_MESSAGE(HexStr(key, key + sizeof(key)) == find_value(v, "key").get_str(), comment);
        BOOST_CHECK_MESSAGE(HexStr(iv, iv + sizeof(iv)) == find_value(v, "iv").get_str(), comment);

        if (salt.size() == WALLET_CRYPTO_SALT_SIZE) {
            BOOST_CHECK_MESSAGE(crypt.SetKeyFromPassphrase(passphrase, salt, rounds, 0), comment);
            BOOST_CHECK(TestCrypter::KeySet(crypt));
            BOOST_CHECK_MESSAGE(HexStr(TestCrypter::Key(crypt)) == find_value(v, "key").get_str(), comment);
            BOOST_CHECK_MESSAGE(HexStr(TestCrypter::IV(crypt)) == find_value(v, "iv").get_str(), comment);
        } else {
            // SetKeyFromPassphrase accepts only 8-byte salts.
            BOOST_CHECK_MESSAGE(!crypt.SetKeyFromPassphrase(passphrase, salt, rounds, 0), comment);
            BOOST_CHECK(!TestCrypter::KeySet(crypt));
        }
    }
}

BOOST_AUTO_TEST_CASE(kdf_invalid_arguments)
{
    const UniValue& v = find_value(CrypterVectors(), "kdf")[0];
    const std::vector<unsigned char> salt = Hex(v, "salt");
    const SecureString passphrase = HexSecure(v, "passphrase");
    const std::vector<unsigned char> zero_key(WALLET_CRYPTO_KEY_SIZE, 0), zero_iv(WALLET_CRYPTO_IV_SIZE, 0);

    CCrypter crypt;
    unsigned char key[WALLET_CRYPTO_KEY_SIZE];
    unsigned char iv[WALLET_CRYPTO_IV_SIZE];
    BOOST_CHECK_EQUAL(TestCrypter::BytesToKey(crypt, salt, passphrase, 0, key, iv), 0);
    BOOST_CHECK_EQUAL(TestCrypter::BytesToKey(crypt, salt, passphrase, 1, nullptr, iv), 0);
    BOOST_CHECK_EQUAL(TestCrypter::BytesToKey(crypt, salt, passphrase, 1, key, nullptr), 0);

    // Rejected arguments leave a fresh crypter without a key.
    CKeyingMaterial plain(32, 0x42), plain_out;
    std::vector<unsigned char> cipher;
    BOOST_CHECK(!crypt.SetKeyFromPassphrase(passphrase, salt, 0, 0));                                       // 0 rounds
    BOOST_CHECK(!crypt.SetKeyFromPassphrase(passphrase, std::vector<unsigned char>(), 1, 0));               // salt 0 bytes
    BOOST_CHECK(!crypt.SetKeyFromPassphrase(passphrase, std::vector<unsigned char>(salt.begin(), salt.begin() + 7), 1, 0)); // 7 bytes
    std::vector<unsigned char> salt9(salt);
    salt9.push_back(0);
    BOOST_CHECK(!crypt.SetKeyFromPassphrase(passphrase, salt9, 1, 0));                                      // 9 bytes
    BOOST_CHECK(!crypt.SetKeyFromPassphrase(passphrase, salt, 1, 1));                                       // unknown method
    BOOST_CHECK(!TestCrypter::KeySet(crypt));
    BOOST_CHECK(!crypt.Encrypt(plain, cipher));
    BOOST_CHECK(!crypt.Decrypt(std::vector<unsigned char>(16, 0), plain_out));

    // SetKey checks both sizes.
    BOOST_CHECK(!crypt.SetKey(CKeyingMaterial(31, 1), std::vector<unsigned char>(16, 2)));
    BOOST_CHECK(!crypt.SetKey(CKeyingMaterial(33, 1), std::vector<unsigned char>(16, 2)));
    BOOST_CHECK(!crypt.SetKey(CKeyingMaterial(32, 1), std::vector<unsigned char>(15, 2)));
    BOOST_CHECK(!crypt.SetKey(CKeyingMaterial(32, 1), std::vector<unsigned char>(17, 2)));
    BOOST_CHECK(!TestCrypter::KeySet(crypt));

    // Current behaviour on a crypter that already has a key (pinned, not
    // judged; project/known-issues.md): 0 rounds or a bad salt return false
    // and keep the old key; an unknown method returns false, zeroes key and
    // IV, but fKeySet stays true.
    BOOST_REQUIRE(crypt.SetKeyFromPassphrase(passphrase, salt, find_value(v, "rounds").get_int(), 0));
    BOOST_CHECK(!crypt.SetKeyFromPassphrase(passphrase, salt, 0, 0));
    BOOST_CHECK(!crypt.SetKeyFromPassphrase(passphrase, salt9, 1, 0));
    BOOST_CHECK(TestCrypter::KeySet(crypt));
    BOOST_CHECK_EQUAL(HexStr(TestCrypter::Key(crypt)), find_value(v, "key").get_str());
    BOOST_CHECK_EQUAL(HexStr(TestCrypter::IV(crypt)), find_value(v, "iv").get_str());
    BOOST_CHECK(!crypt.SetKeyFromPassphrase(passphrase, salt, 1, 1));
    BOOST_CHECK(TestCrypter::KeySet(crypt));
    BOOST_CHECK(TestCrypter::Key(crypt) == zero_key);
    BOOST_CHECK(TestCrypter::IV(crypt) == zero_iv);

    // CleanKey zeroes and unsets.
    BOOST_REQUIRE(crypt.SetKeyFromPassphrase(passphrase, salt, 1, 0));
    crypt.CleanKey();
    BOOST_CHECK(!TestCrypter::KeySet(crypt));
    BOOST_CHECK(TestCrypter::Key(crypt) == zero_key);
    BOOST_CHECK(TestCrypter::IV(crypt) == zero_iv);
    BOOST_CHECK(!crypt.Encrypt(plain, cipher));
}

BOOST_AUTO_TEST_CASE(aes_cbc_vectors)
{
    const UniValue& vectors = find_value(find_value(CrypterVectors(), "aes_cbc"), "vectors");
    BOOST_REQUIRE(vectors.isArray() && vectors.size() >= 9);
    CCrypter crypt;
    AesCrypter(crypt);
    for (unsigned int i = 0; i < vectors.size(); i++) {
        const UniValue& v = vectors[i];
        const CKeyingMaterial plain = HexKeying(v, "plaintext");
        const std::vector<unsigned char> expected = Hex(v, "ciphertext");
        BOOST_CHECK_EQUAL(expected.size(), plain.size() + find_value(v, "padding").get_int());
        std::vector<unsigned char> cipher;
        CKeyingMaterial decrypted;
        if (plain.empty()) {
            // Current behaviour, unlike OpenSSL (project/known-issues.md):
            // an empty plaintext encrypts to an empty ciphertext, and the
            // standard ciphertext of an empty plaintext (one padding block)
            // does not decrypt. No wallet path encrypts empty data.
            BOOST_CHECK(crypt.Encrypt(plain, cipher));
            BOOST_CHECK(cipher.empty());
            BOOST_CHECK(!crypt.Decrypt(expected, decrypted));
            continue;
        }
        BOOST_CHECK(crypt.Encrypt(plain, cipher));
        BOOST_CHECK_EQUAL(HexStr(cipher), HexStr(expected));
        BOOST_CHECK(crypt.Decrypt(expected, decrypted));
        BOOST_CHECK_EQUAL(HexOf(decrypted), HexOf(plain));
    }
}

BOOST_AUTO_TEST_CASE(decrypt_vectors)
{
    const UniValue& aes = find_value(CrypterVectors(), "aes_cbc");
    const UniValue& vectors = find_value(CrypterVectors(), "decrypt");
    BOOST_REQUIRE(vectors.isArray() && vectors.size() >= 13);
    unsigned int n_ok = 0;
    for (unsigned int i = 0; i < vectors.size(); i++) {
        const UniValue& v = vectors[i];
        const std::string comment = find_value(v, "comment").get_str();
        CCrypter crypt;
        BOOST_REQUIRE(crypt.SetKey(HexKeying(find_value(v, "key").isNull() ? aes : v, "key"),
                                   Hex(find_value(v, "iv").isNull() ? aes : v, "iv")));
        CKeyingMaterial decrypted;
        const bool ok = crypt.Decrypt(Hex(v, "ciphertext"), decrypted);
        BOOST_CHECK_MESSAGE(ok == find_value(v, "ok").get_bool(), comment);
        if (ok) {
            BOOST_CHECK_MESSAGE(HexOf(decrypted) == find_value(v, "plaintext").get_str(), comment);
            n_ok++;
        }
    }
    // Both outcomes are covered by the file.
    BOOST_CHECK(n_ok > 0 && n_ok < vectors.size());
}

BOOST_AUTO_TEST_CASE(masterkey_vectors)
{
    const UniValue& m = find_value(CrypterVectors(), "masterkey");

    // The wallet "mkey" record value.
    CMasterKey mk;
    mk.vchCryptedKey = Hex(m, "crypted_key");
    mk.vchSalt = Hex(m, "salt");
    mk.nDerivationMethod = find_value(m, "derivation_method").get_int();
    mk.nDeriveIterations = find_value(m, "rounds").get_int();
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << mk;
    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), find_value(m, "serialized").get_str());
    CMasterKey mk2;
    ss >> mk2;
    BOOST_CHECK(mk2.vchCryptedKey == mk.vchCryptedKey);
    BOOST_CHECK(mk2.vchSalt == mk.vchSalt);
    BOOST_CHECK_EQUAL(mk2.nDerivationMethod, mk.nDerivationMethod);
    BOOST_CHECK_EQUAL(mk2.nDeriveIterations, mk.nDeriveIterations);
    BOOST_CHECK(mk2.vchOtherDerivationParameters.empty());

    // Unlock: passphrase -> key -> master key (CWallet::Unlock).
    CCrypter crypt;
    BOOST_REQUIRE(crypt.SetKeyFromPassphrase(HexSecure(m, "passphrase"), mk2.vchSalt, mk2.nDeriveIterations, mk2.nDerivationMethod));
    CKeyingMaterial master;
    BOOST_CHECK(crypt.Decrypt(mk2.vchCryptedKey, master));
    BOOST_CHECK_EQUAL(HexOf(master), find_value(m, "master_key").get_str());

    // EncryptWallet: the same key encrypts the master key to the stored value.
    std::vector<unsigned char> crypted;
    BOOST_CHECK(crypt.Encrypt(HexKeying(m, "master_key"), crypted));
    BOOST_CHECK_EQUAL(HexStr(crypted), find_value(m, "crypted_key").get_str());

    // Wrong passphrase: the recorded outcome (the padding check fails).
    CCrypter wrong;
    BOOST_REQUIRE(wrong.SetKeyFromPassphrase(HexSecure(m, "wrong_passphrase"), mk2.vchSalt, mk2.nDeriveIterations, mk2.nDerivationMethod));
    CKeyingMaterial wrong_master;
    BOOST_CHECK_EQUAL(wrong.Decrypt(mk2.vchCryptedKey, wrong_master), find_value(m, "wrong_passphrase_ok").get_bool());
    BOOST_CHECK(!find_value(m, "wrong_passphrase_ok").get_bool());
}

/** CCryptoKeyStore with the protected wallet-level operations exposed and
 *  every crypted secret it stores recorded (CWallet writes them to the
 *  database at the same place). */
class TestCryptoKeyStore : public CCryptoKeyStore
{
public:
    std::map<CPubKey, std::vector<unsigned char>> stored;

    bool AddCryptedKey(const CPubKey& pubkey, const std::vector<unsigned char>& secret) override
    {
        if (!CCryptoKeyStore::AddCryptedKey(pubkey, secret)) return false;
        stored[pubkey] = secret;
        return true;
    }
    using CCryptoKeyStore::DecryptKeys;
    using CCryptoKeyStore::EncryptKeys;
    using CCryptoKeyStore::Unlock;
};

struct VectorKey {
    CKey key;
    CPubKey pubkey;
    std::vector<unsigned char> crypted;
};

static std::vector<VectorKey> VectorKeys()
{
    std::vector<VectorKey> out;
    const UniValue& keys = find_value(CrypterVectors(), "keys");
    for (unsigned int i = 0; i < keys.size(); i++) {
        const UniValue& v = keys[i];
        VectorKey k;
        const std::vector<unsigned char> secret = Hex(v, "secret");
        k.key.Set(secret.begin(), secret.end(), find_value(v, "compressed").get_bool());
        BOOST_REQUIRE(k.key.IsValid());
        k.pubkey = k.key.GetPubKey();
        BOOST_CHECK_EQUAL(HexStr(k.pubkey), find_value(v, "pubkey").get_str());
        BOOST_CHECK_EQUAL(k.pubkey.GetHash().GetHex(), uint256(Hex(v, "pubkey_hash")).GetHex());
        k.crypted = Hex(v, "crypted_secret");
        out.push_back(k);
    }
    return out;
}

BOOST_AUTO_TEST_CASE(keystore_encrypt_unlock)
{
    const CKeyingMaterial master = HexKeying(find_value(CrypterVectors(), "masterkey"), "master_key");
    const std::vector<VectorKey> keys = VectorKeys();
    BOOST_REQUIRE_EQUAL(keys.size(), 3U);
    CKey out;
    CPubKey pubout;

    // A plain store: keys kept in the clear; it cannot be marked crypted.
    TestCryptoKeyStore store;
    BOOST_CHECK(!store.IsCrypted());
    BOOST_CHECK(!store.IsLocked());
    BOOST_CHECK(store.AddKeyPubKey(keys[0].key, keys[0].pubkey));
    BOOST_CHECK(store.AddKeyPubKey(keys[1].key, keys[1].pubkey));
    BOOST_CHECK(store.GetKey(keys[0].pubkey.GetID(), out) && out == keys[0].key);
    BOOST_CHECK(store.GetPubKey(keys[1].pubkey.GetID(), pubout) && pubout == keys[1].pubkey);
    BOOST_CHECK(!store.Lock());                                               // keys in the clear
    BOOST_CHECK(!store.Unlock(master));                                       // likewise
    BOOST_CHECK(!store.AddCryptedKey(keys[2].pubkey, keys[2].crypted));
    BOOST_CHECK(!store.IsCrypted());

    // EncryptKeys with a master key of the wrong size fails.
    {
        TestCryptoKeyStore bad;
        BOOST_CHECK(bad.AddKeyPubKey(keys[0].key, keys[0].pubkey));
        CKeyingMaterial short_master(master.begin(), master.begin() + 31);
        BOOST_CHECK(!bad.EncryptKeys(short_master));
    }

    // EncryptKeys stores exactly the known crypted secrets and clears the
    // plain keys. The store is crypted and locked afterwards (EncryptKeys
    // does not keep the master key).
    CKeyingMaterial master_copy(master);
    BOOST_CHECK(store.EncryptKeys(master_copy));
    BOOST_CHECK(store.IsCrypted());
    BOOST_CHECK(store.IsLocked());
    BOOST_CHECK_EQUAL(store.stored.size(), 2U);
    BOOST_CHECK_EQUAL(HexStr(store.stored[keys[0].pubkey]), HexStr(keys[0].crypted));
    BOOST_CHECK_EQUAL(HexStr(store.stored[keys[1].pubkey]), HexStr(keys[1].crypted));
    BOOST_CHECK(!store.EncryptKeys(master_copy));                             // only once
    std::set<CKeyID> ids;
    store.GetKeys(ids);
    BOOST_CHECK_EQUAL(ids.size(), 2U);
    BOOST_CHECK(store.HaveKey(keys[0].pubkey.GetID()));
    BOOST_CHECK(!store.HaveKey(keys[2].pubkey.GetID()));

    // Locked: public keys only.
    BOOST_CHECK(!store.GetKey(keys[0].pubkey.GetID(), out));
    BOOST_CHECK(store.GetPubKey(keys[0].pubkey.GetID(), pubout) && pubout == keys[0].pubkey);
    BOOST_CHECK(!store.GetPubKey(keys[2].pubkey.GetID(), pubout));            // unknown
    BOOST_CHECK(!store.AddKeyPubKey(keys[2].key, keys[2].pubkey));

    // Unlock needs the right master key.
    CKeyingMaterial wrong_master(master);
    wrong_master[0] ^= 1;
    BOOST_CHECK(!store.Unlock(wrong_master));
    BOOST_CHECK(store.IsLocked());
    BOOST_CHECK(store.Unlock(master));
    BOOST_CHECK(!store.IsLocked());
    BOOST_CHECK(store.Unlock(master));                                        // again: checks only one key now
    for (int i = 0; i < 2; i++) {
        BOOST_CHECK(store.GetKey(keys[i].pubkey.GetID(), out));
        BOOST_CHECK(out == keys[i].key);
        BOOST_CHECK_EQUAL(out.IsCompressed(), keys[i].key.IsCompressed());
    }

    // Unlocked: a new key is encrypted under the master key.
    BOOST_CHECK(store.AddKeyPubKey(keys[2].key, keys[2].pubkey));
    BOOST_CHECK_EQUAL(HexStr(store.stored[keys[2].pubkey]), HexStr(keys[2].crypted));
    BOOST_CHECK(store.GetKey(keys[2].pubkey.GetID(), out) && out == keys[2].key);

    // Lock forgets the master key.
    BOOST_CHECK(store.Lock());
    BOOST_CHECK(store.IsLocked());
    BOOST_CHECK(!store.GetKey(keys[2].pubkey.GetID(), out));

    // Crypted secrets that decrypt but are wrong: a 31-byte secret, and a
    // secret stored under another key's public key.
    {
        TestCryptoKeyStore bad;
        BOOST_CHECK(bad.AddCryptedKey(keys[0].pubkey, Hex(find_value(CrypterVectors(), "short_secret"), "crypted_secret")));
        BOOST_CHECK(bad.IsCrypted());
        BOOST_CHECK(!bad.Unlock(master));
    }
    {
        TestCryptoKeyStore bad;
        BOOST_CHECK(bad.AddCryptedKey(keys[0].pubkey, keys[2].crypted));      // wrong IV and key
        BOOST_CHECK(!bad.Unlock(master));
    }

    // An empty store becomes crypted by Lock(); Unlock without keys fails.
    TestCryptoKeyStore empty;
    BOOST_CHECK(empty.Lock());
    BOOST_CHECK(empty.IsCrypted());
    BOOST_CHECK(empty.IsLocked());
    BOOST_CHECK(!empty.Unlock(master));
}

BOOST_AUTO_TEST_CASE(keystore_decrypt_keys)
{
    const CKeyingMaterial master = HexKeying(find_value(CrypterVectors(), "masterkey"), "master_key");
    const std::vector<VectorKey> keys = VectorKeys();
    CKeyingMaterial wrong_master(master);
    wrong_master[31] ^= 0x80;

    TestCryptoKeyStore plain;
    BOOST_CHECK(!plain.DecryptKeys(master));                                  // not crypted

    TestCryptoKeyStore store;
    for (const VectorKey& k : keys) {
        BOOST_CHECK(store.AddCryptedKey(k.pubkey, k.crypted));
    }
    BOOST_CHECK(!store.DecryptKeys(wrong_master));
    {
        TestCryptoKeyStore bad;
        BOOST_CHECK(bad.AddCryptedKey(keys[0].pubkey, Hex(find_value(CrypterVectors(), "short_secret"), "crypted_secret")));
        BOOST_CHECK(!bad.DecryptKeys(master));                                // 31-byte secret
    }
    // Current behaviour (pinned, project/known-issues.md): DecryptKeys puts
    // each decrypted key back through CBasicKeyStore::AddKey, which calls
    // the virtual AddKeyPubKey, i.e. CCryptoKeyStore's. Locked, that fails;
    // unlocked, it encrypts the key again into the crypted map, which
    // DecryptKeys then clears: it returns true and the keys are gone from
    // both maps. Its only caller, CWallet::DecryptWallet, is never called.
    BOOST_CHECK(store.IsLocked());
    BOOST_CHECK(!store.DecryptKeys(master));
    BOOST_REQUIRE(store.Unlock(master));
    store.stored.clear();
    BOOST_CHECK(store.DecryptKeys(master));
    BOOST_CHECK(store.IsCrypted());
    BOOST_CHECK_EQUAL(store.stored.size(), keys.size());                     // encrypted again ...
    for (const VectorKey& k : keys) {
        BOOST_CHECK_EQUAL(HexStr(store.stored[k.pubkey]), HexStr(k.crypted));
    }
    std::set<CKeyID> ids;
    store.GetKeys(ids);
    BOOST_CHECK(ids.empty());                                                 // ... and cleared
    CKey out;
    for (const VectorKey& k : keys) {
        BOOST_CHECK(!store.GetKey(k.pubkey.GetID(), out));
        BOOST_CHECK(!store.CBasicKeyStore::GetKey(k.pubkey.GetID(), out));
    }
}

BOOST_AUTO_TEST_SUITE_END()
