#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE YaCoinNewTestSuite
#include <boost/test/unit_test.hpp>

// Note: This is a standalone test runner for the new unit tests
// It doesn't require the full YaCoin build system to work

// The test files will be included automatically by the boost test framework
// since they use BOOST_AUTO_TEST_SUITE