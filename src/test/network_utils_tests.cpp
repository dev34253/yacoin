#include <boost/test/unit_test.hpp>
#include <vector>
#include <string>

// Test network utility functions
using namespace std;

// Simple helper functions for networking tests
bool IsValidIP(const string& ip) {
    // Simple IP validation - check for basic format
    int dots = 0;
    int digit_count = 0;
    bool in_number = false;
    int current_number = 0;
    
    for (char c : ip) {
        if (c == '.') {
            if (!in_number || digit_count == 0 || current_number > 255) {
                return false;
            }
            dots++;
            in_number = false;
            digit_count = 0;
            current_number = 0;
        } else if (c >= '0' && c <= '9') {
            if (!in_number) {
                in_number = true;
            }
            digit_count++;
            if (digit_count > 3) {
                return false;
            }
            current_number = current_number * 10 + (c - '0');
        } else {
            return false;
        }
    }
    
    // Check final number
    if (!in_number || digit_count == 0 || current_number > 255 || dots != 3) {
        return false;
    }
    
    return true;
}

// Simple port validation
bool IsValidPort(int port) {
    return port >= 1 && port <= 65535;
}

// Simple URL parsing
struct ParsedURL {
    string protocol;
    string host;
    int port;
    string path;
    bool valid;
};

ParsedURL ParseURL(const string& url) {
    ParsedURL result = {"", "", 0, "", false};
    
    size_t protocol_end = url.find("://");
    if (protocol_end == string::npos) {
        return result;
    }
    
    result.protocol = url.substr(0, protocol_end);
    
    size_t host_start = protocol_end + 3;
    size_t path_start = url.find('/', host_start);
    if (path_start == string::npos) {
        path_start = url.length();
        result.path = "/";
    } else {
        result.path = url.substr(path_start);
    }
    
    string host_port = url.substr(host_start, path_start - host_start);
    size_t port_start = host_port.find(':');
    
    if (port_start == string::npos) {
        result.host = host_port;
        result.port = (result.protocol == "https") ? 443 : 80;
    } else {
        result.host = host_port.substr(0, port_start);
        string port_str = host_port.substr(port_start + 1);
        try {
            result.port = stoi(port_str);
        } catch (...) {
            return result;
        }
    }
    
    result.valid = !result.host.empty() && IsValidPort(result.port);
    return result;
}

BOOST_AUTO_TEST_SUITE(network_utility_tests)

BOOST_AUTO_TEST_CASE(ip_address_validation)
{
    // Test valid IP addresses
    BOOST_CHECK(IsValidIP("192.168.1.1"));
    BOOST_CHECK(IsValidIP("127.0.0.1"));
    BOOST_CHECK(IsValidIP("8.8.8.8"));
    BOOST_CHECK(IsValidIP("255.255.255.255"));
    BOOST_CHECK(IsValidIP("0.0.0.0"));
    
    // Test invalid IP addresses
    BOOST_CHECK(!IsValidIP("256.1.1.1"));
    BOOST_CHECK(!IsValidIP("192.168.1"));
    BOOST_CHECK(!IsValidIP("192.168.1.1.1"));
    BOOST_CHECK(!IsValidIP("192.168.-1.1"));
    BOOST_CHECK(!IsValidIP("192.168.abc.1"));
    BOOST_CHECK(!IsValidIP(""));
    BOOST_CHECK(!IsValidIP("..."));
}

BOOST_AUTO_TEST_CASE(port_validation)
{
    // Test valid ports
    BOOST_CHECK(IsValidPort(80));
    BOOST_CHECK(IsValidPort(443));
    BOOST_CHECK(IsValidPort(8080));
    BOOST_CHECK(IsValidPort(1));
    BOOST_CHECK(IsValidPort(65535));
    
    // Test invalid ports
    BOOST_CHECK(!IsValidPort(0));
    BOOST_CHECK(!IsValidPort(-1));
    BOOST_CHECK(!IsValidPort(65536));
    BOOST_CHECK(!IsValidPort(100000));
}

BOOST_AUTO_TEST_CASE(url_parsing)
{
    // Test valid URLs
    ParsedURL result1 = ParseURL("http://example.com/path");
    BOOST_CHECK(result1.valid);
    BOOST_CHECK_EQUAL(result1.protocol, "http");
    BOOST_CHECK_EQUAL(result1.host, "example.com");
    BOOST_CHECK_EQUAL(result1.port, 80);
    BOOST_CHECK_EQUAL(result1.path, "/path");
    
    ParsedURL result2 = ParseURL("https://example.com:8080/");
    BOOST_CHECK(result2.valid);
    BOOST_CHECK_EQUAL(result2.protocol, "https");
    BOOST_CHECK_EQUAL(result2.host, "example.com");
    BOOST_CHECK_EQUAL(result2.port, 8080);
    BOOST_CHECK_EQUAL(result2.path, "/");
    
    ParsedURL result3 = ParseURL("http://192.168.1.1:9333");
    BOOST_CHECK(result3.valid);
    BOOST_CHECK_EQUAL(result3.protocol, "http");
    BOOST_CHECK_EQUAL(result3.host, "192.168.1.1");
    BOOST_CHECK_EQUAL(result3.port, 9333);
    BOOST_CHECK_EQUAL(result3.path, "/");
    
    // Test invalid URLs
    ParsedURL result4 = ParseURL("invalid-url");
    BOOST_CHECK(!result4.valid);
    
    ParsedURL result5 = ParseURL("http://");
    BOOST_CHECK(!result5.valid);
}

BOOST_AUTO_TEST_SUITE_END()