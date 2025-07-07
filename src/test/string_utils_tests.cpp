#include <boost/test/unit_test.hpp>
#include <string>
#include <sstream>
#include <cmath>

using namespace std;

// Standalone implementations for testing
std::string i64tostr(int64_t n) {
    std::ostringstream oss;
    oss << n;
    return oss.str();
}

std::string itostr(int n) {
    std::ostringstream oss;
    oss << n;
    return oss.str();
}

int64_t atoi64(const std::string& str) {
    return std::stoll(str);
}

std::string leftTrim(std::string src, char chr) {
    while (!src.empty() && src[0] == chr) {
        src.erase(0, 1);
    }
    return src;
}

int roundint(double d) {
    return static_cast<int>(std::round(d));
}

int64_t roundint64(double d) {
    return static_cast<int64_t>(std::round(d));
}

int64_t abs64(int64_t n) {
    return (n < 0) ? -n : n;
}

BOOST_AUTO_TEST_SUITE(string_utility_tests)

// Test string conversion utilities
BOOST_AUTO_TEST_CASE(integer_to_string_conversion)
{
    // Test i64tostr function
    int64_t test_positive = 123456789;
    string result_positive = i64tostr(test_positive);
    BOOST_CHECK_EQUAL(result_positive, "123456789");
    
    int64_t test_negative = -987654321;
    string result_negative = i64tostr(test_negative);
    BOOST_CHECK_EQUAL(result_negative, "-987654321");
    
    int64_t test_zero = 0;
    string result_zero = i64tostr(test_zero);
    BOOST_CHECK_EQUAL(result_zero, "0");
}

BOOST_AUTO_TEST_CASE(regular_integer_to_string)
{
    // Test itostr function
    int test_int = 42;
    string result = itostr(test_int);
    BOOST_CHECK_EQUAL(result, "42");
    
    int test_negative = -123;
    string result_negative = itostr(test_negative);
    BOOST_CHECK_EQUAL(result_negative, "-123");
}

BOOST_AUTO_TEST_CASE(string_to_integer_conversion)
{
    // Test atoi64 function
    string test_string = "123456789";
    int64_t result = atoi64(test_string);
    BOOST_CHECK_EQUAL(result, 123456789);
    
    string test_negative = "-987654321";
    int64_t result_negative = atoi64(test_negative);
    BOOST_CHECK_EQUAL(result_negative, -987654321);
    
    string test_zero = "0";
    int64_t result_zero = atoi64(test_zero);
    BOOST_CHECK_EQUAL(result_zero, 0);
}

BOOST_AUTO_TEST_CASE(string_trimming)
{
    // Test leftTrim function
    string test_string = "   hello world";
    string result = leftTrim(test_string, ' ');
    BOOST_CHECK_EQUAL(result, "hello world");
    
    string test_no_trim = "hello world";
    string result_no_trim = leftTrim(test_no_trim, ' ');
    BOOST_CHECK_EQUAL(result_no_trim, "hello world");
    
    string test_custom_char = "xxxhello world";
    string result_custom = leftTrim(test_custom_char, 'x');
    BOOST_CHECK_EQUAL(result_custom, "hello world");
}

BOOST_AUTO_TEST_CASE(rounding_functions)
{
    // Test roundint function
    double test_positive = 3.7;
    int result_positive = roundint(test_positive);
    BOOST_CHECK_EQUAL(result_positive, 4);
    
    double test_negative = -2.3;
    int result_negative = roundint(test_negative);
    BOOST_CHECK_EQUAL(result_negative, -2);
    
    // Test roundint64 function
    double test_large = 1234567890.6;
    int64_t result_large = roundint64(test_large);
    BOOST_CHECK_EQUAL(result_large, 1234567891);
}

BOOST_AUTO_TEST_CASE(absolute_value_function)
{
    // Test abs64 function
    int64_t test_positive = 12345;
    int64_t result_positive = abs64(test_positive);
    BOOST_CHECK_EQUAL(result_positive, 12345);
    
    int64_t test_negative = -67890;
    int64_t result_negative = abs64(test_negative);
    BOOST_CHECK_EQUAL(result_negative, 67890);
    
    int64_t test_zero = 0;
    int64_t result_zero = abs64(test_zero);
    BOOST_CHECK_EQUAL(result_zero, 0);
}

BOOST_AUTO_TEST_SUITE_END()