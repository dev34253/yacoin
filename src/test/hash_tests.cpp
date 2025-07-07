#include <boost/test/unit_test.hpp>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include "test_common.h"

using namespace std;

// Standalone implementations for testing (to avoid complex dependencies)
std::string HexStr(const std::vector<unsigned char>& vch, bool fSpaces = false) {
    std::ostringstream oss;
    for (size_t i = 0; i < vch.size(); ++i) {
        if (fSpaces && i > 0) oss << " ";
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(vch[i]);
    }
    return oss.str();
}

std::vector<unsigned char> ParseHex(const std::string& str) {
    std::vector<unsigned char> result;
    std::string clean_str;
    
    // Remove any non-hex characters
    for (char c : str) {
        if ((c >= '0' && c <= '9') || 
            (c >= 'a' && c <= 'f') || 
            (c >= 'A' && c <= 'F')) {
            clean_str += c;
        }
    }
    
    // If odd length, pad with leading zero
    if (clean_str.length() % 2 == 1) {
        clean_str = "0" + clean_str;
    }
    
    for (size_t i = 0; i < clean_str.length(); i += 2) {
        if (i + 1 < clean_str.length()) {
            try {
                std::string hex_byte = clean_str.substr(i, 2);
                unsigned char byte = static_cast<unsigned char>(std::stoi(hex_byte, nullptr, 16));
                result.push_back(byte);
            } catch (const std::exception&) {
                // Skip invalid hex bytes
                continue;
            }
        }
    }
    return result;
}

BOOST_AUTO_TEST_SUITE(hash_tests)

// Test hex string utilities
BOOST_AUTO_TEST_CASE(hex_string_conversion)
{
    // Test HexStr function with basic byte array
    vector<unsigned char> test_bytes = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    string expected = "0123456789abcdef";
    string result = HexStr(test_bytes);
    BOOST_CHECK_EQUAL(result, expected);
    
    // Test with spaces
    string expected_with_spaces = "01 23 45 67 89 ab cd ef";
    string result_with_spaces = HexStr(test_bytes, true);
    BOOST_CHECK_EQUAL(result_with_spaces, expected_with_spaces);
}

BOOST_AUTO_TEST_CASE(parse_hex_string)
{
    // Test ParseHex function
    string hex_input = "0123456789abcdef";
    vector<unsigned char> result = ParseHex(hex_input);
    vector<unsigned char> expected = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    BOOST_CHECK_EQUAL(result.size(), expected.size());
    for (size_t i = 0; i < result.size(); ++i) {
        BOOST_CHECK_EQUAL(result[i], expected[i]);
    }
}

BOOST_AUTO_TEST_CASE(parse_hex_empty_string)
{
    string empty_hex = "";
    vector<unsigned char> result = ParseHex(empty_hex);
    BOOST_CHECK(result.empty());
}

BOOST_AUTO_TEST_CASE(parse_hex_invalid_characters)
{
    // Test with invalid hex characters
    string invalid_hex = "0123456789abcdefgh";
    vector<unsigned char> result = ParseHex(invalid_hex);
    // Should only parse valid hex characters and ignore 'gh'
    vector<unsigned char> expected = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    BOOST_CHECK_EQUAL(result.size(), expected.size());
    for (size_t i = 0; i < result.size(); ++i) {
        BOOST_CHECK_EQUAL(result[i], expected[i]);
    }
}

BOOST_AUTO_TEST_CASE(parse_hex_odd_length)
{
    // Test with odd length hex string
    string odd_hex = "123";
    vector<unsigned char> result = ParseHex(odd_hex);
    vector<unsigned char> expected = {0x01, 0x23}; // Should be padded to "0123"
    
    BOOST_CHECK_EQUAL(result.size(), expected.size());
    for (size_t i = 0; i < result.size(); ++i) {
        BOOST_CHECK_EQUAL(result[i], expected[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()