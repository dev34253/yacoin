// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "compat/sanity.h"
#include "key.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <thread>

BOOST_FIXTURE_TEST_SUITE(sanity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(basic_sanity)
{
  BOOST_CHECK_MESSAGE(glibc_sanity_test() == true, "libc sanity test");
  BOOST_CHECK_MESSAGE(glibcxx_sanity_test() == true, "stdlib sanity test");
  BOOST_CHECK_MESSAGE(ECC_InitSanityCheck() == true, "openssl ECC test");
}

// Planted on a scratch branch only: two threads write one plain int.
BOOST_AUTO_TEST_CASE(planted_race)
{
  int counter = 0;
  std::thread other([&counter] { for (int i = 0; i < 1000; ++i) ++counter; });
  for (int i = 0; i < 1000; ++i) ++counter;
  other.join();
  BOOST_CHECK(counter > 0);
}

BOOST_AUTO_TEST_SUITE_END()
