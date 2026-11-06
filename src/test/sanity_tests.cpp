// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "compat/sanity.h"
#include "key.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sanity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(basic_sanity)
{
  BOOST_CHECK_MESSAGE(glibc_sanity_test() == true, "libc sanity test");
  BOOST_CHECK_MESSAGE(glibcxx_sanity_test() == true, "stdlib sanity test");
  BOOST_CHECK_MESSAGE(ECC_InitSanityCheck() == true, "openssl ECC test");
}

// Planted leak: shows that the sanitizer job fails on a LeakSanitizer report. Not for merge.
BOOST_AUTO_TEST_CASE(planted_leak)
{
    char* planted = new char[64];
    planted[0] = 1;
    BOOST_CHECK(planted[0] == 1);
    planted = nullptr;
}

BOOST_AUTO_TEST_SUITE_END()
