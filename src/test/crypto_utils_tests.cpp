#include <boost/test/unit_test.hpp>
#include <vector>
#include <string>
#include <algorithm>
#include "test_common.h"

using namespace std;

// Simple cryptographic utility functions for testing
// These are basic implementations for testing purposes

// Simple XOR cipher for testing
vector<unsigned char> XORCipher(const vector<unsigned char>& data, const vector<unsigned char>& key) {
    if (key.empty()) return data;
    
    vector<unsigned char> result;
    result.reserve(data.size());
    
    for (size_t i = 0; i < data.size(); ++i) {
        result.push_back(data[i] ^ key[i % key.size()]);
    }
    
    return result;
}

// Simple checksum calculation
uint32_t SimpleChecksum(const vector<unsigned char>& data) {
    uint32_t checksum = 0;
    for (unsigned char byte : data) {
        checksum += byte;
    }
    return checksum;
}

// Simple hash function (not cryptographically secure - for testing only)
vector<unsigned char> SimpleHash(const vector<unsigned char>& data) {
    vector<unsigned char> hash(4, 0); // 4-byte hash
    
    uint32_t h = 0x12345678;
    for (size_t i = 0; i < data.size(); ++i) {
        h = h * 31 + data[i];
        h ^= (h >> 16);
    }
    
    hash[0] = (h >> 24) & 0xFF;
    hash[1] = (h >> 16) & 0xFF;
    hash[2] = (h >> 8) & 0xFF;
    hash[3] = h & 0xFF;
    
    return hash;
}

// Byte array utilities
bool IsValidHexChar(char c) {
    return (c >= '0' && c <= '9') || 
           (c >= 'a' && c <= 'f') || 
           (c >= 'A' && c <= 'F');
}

unsigned char HexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

string ByteToHex(unsigned char byte) {
    const char hex_chars[] = "0123456789abcdef";
    string result;
    result += hex_chars[(byte >> 4) & 0x0F];
    result += hex_chars[byte & 0x0F];
    return result;
}

vector<unsigned char> HexStringToBytes(const string& hex) {
    vector<unsigned char> result;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        if (i + 1 < hex.length() && 
            IsValidHexChar(hex[i]) && 
            IsValidHexChar(hex[i + 1])) {
            unsigned char byte = (HexCharToValue(hex[i]) << 4) | HexCharToValue(hex[i + 1]);
            result.push_back(byte);
        }
    }
    
    return result;
}

BOOST_AUTO_TEST_SUITE(crypto_utility_tests)

BOOST_AUTO_TEST_CASE(xor_cipher_test)
{
    vector<unsigned char> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    vector<unsigned char> key = {0xAB, 0xCD, 0xEF};
    
    // Encrypt
    vector<unsigned char> encrypted = XORCipher(data, key);
    BOOST_CHECK_NE(encrypted, data); // Should be different
    
    // Decrypt (XOR is symmetric)
    vector<unsigned char> decrypted = XORCipher(encrypted, key);
    BOOST_CHECK_EQUAL_COLLECTIONS(decrypted.begin(), decrypted.end(),
                                  data.begin(), data.end());
}

BOOST_AUTO_TEST_CASE(xor_cipher_empty_key)
{
    vector<unsigned char> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    vector<unsigned char> empty_key;
    
    vector<unsigned char> result = XORCipher(data, empty_key);
    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                  data.begin(), data.end());
}

BOOST_AUTO_TEST_CASE(simple_checksum_test)
{
    vector<unsigned char> data1 = {0x01, 0x02, 0x03, 0x04};
    uint32_t checksum1 = SimpleChecksum(data1);
    BOOST_CHECK_EQUAL(checksum1, 10);
    
    vector<unsigned char> data2 = {0xFF, 0xFF, 0xFF, 0xFF};
    uint32_t checksum2 = SimpleChecksum(data2);
    BOOST_CHECK_EQUAL(checksum2, 1020);
    
    vector<unsigned char> empty_data;
    uint32_t checksum_empty = SimpleChecksum(empty_data);
    BOOST_CHECK_EQUAL(checksum_empty, 0);
}

BOOST_AUTO_TEST_CASE(simple_hash_test)
{
    vector<unsigned char> data1 = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    vector<unsigned char> hash1 = SimpleHash(data1);
    BOOST_CHECK_EQUAL(hash1.size(), 4);
    
    vector<unsigned char> data2 = {0x48, 0x65, 0x6C, 0x6C, 0x70}; // "Hellp"
    vector<unsigned char> hash2 = SimpleHash(data2);
    BOOST_CHECK_EQUAL(hash2.size(), 4);
    
    // Different inputs should produce different hashes
    BOOST_CHECK_NE(hash1, hash2);
    
    // Same input should produce same hash
    vector<unsigned char> hash1_again = SimpleHash(data1);
    BOOST_CHECK_EQUAL_COLLECTIONS(hash1.begin(), hash1.end(),
                                  hash1_again.begin(), hash1_again.end());
}

BOOST_AUTO_TEST_CASE(hex_char_validation)
{
    // Valid hex characters
    BOOST_CHECK(IsValidHexChar('0'));
    BOOST_CHECK(IsValidHexChar('9'));
    BOOST_CHECK(IsValidHexChar('a'));
    BOOST_CHECK(IsValidHexChar('f'));
    BOOST_CHECK(IsValidHexChar('A'));
    BOOST_CHECK(IsValidHexChar('F'));
    
    // Invalid hex characters
    BOOST_CHECK(!IsValidHexChar('g'));
    BOOST_CHECK(!IsValidHexChar('G'));
    BOOST_CHECK(!IsValidHexChar(' '));
    BOOST_CHECK(!IsValidHexChar('/'));
    BOOST_CHECK(!IsValidHexChar(':'));
}

BOOST_AUTO_TEST_CASE(hex_char_to_value)
{
    BOOST_CHECK_EQUAL(HexCharToValue('0'), 0);
    BOOST_CHECK_EQUAL(HexCharToValue('9'), 9);
    BOOST_CHECK_EQUAL(HexCharToValue('a'), 10);
    BOOST_CHECK_EQUAL(HexCharToValue('f'), 15);
    BOOST_CHECK_EQUAL(HexCharToValue('A'), 10);
    BOOST_CHECK_EQUAL(HexCharToValue('F'), 15);
}

BOOST_AUTO_TEST_CASE(byte_to_hex_conversion)
{
    BOOST_CHECK_EQUAL(ByteToHex(0x00), "00");
    BOOST_CHECK_EQUAL(ByteToHex(0xFF), "ff");
    BOOST_CHECK_EQUAL(ByteToHex(0xAB), "ab");
    BOOST_CHECK_EQUAL(ByteToHex(0x12), "12");
}

BOOST_AUTO_TEST_CASE(hex_string_to_bytes_conversion)
{
    string hex = "48656c6c6f";
    vector<unsigned char> result = HexStringToBytes(hex);
    vector<unsigned char> expected = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    
    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                  expected.begin(), expected.end());
    
    // Test empty string
    string empty_hex = "";
    vector<unsigned char> empty_result = HexStringToBytes(empty_hex);
    BOOST_CHECK(empty_result.empty());
    
    // Test odd length (should handle gracefully)
    string odd_hex = "123";
    vector<unsigned char> odd_result = HexStringToBytes(odd_hex);
    vector<unsigned char> odd_expected = {0x12};
    BOOST_CHECK_EQUAL_COLLECTIONS(odd_result.begin(), odd_result.end(),
                                  odd_expected.begin(), odd_expected.end());
}

BOOST_AUTO_TEST_SUITE_END()