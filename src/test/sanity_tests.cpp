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

// A planted leak and a planted UBSan error (scratch branch only).
static int* volatile planted_pointer;

BOOST_AUTO_TEST_CASE(planted_leak)
{
  planted_pointer = new int[4];
  planted_pointer = nullptr;
}

BOOST_AUTO_TEST_CASE(planted_ubsan_error)
{
  volatile int amount = 40;
  volatile int value = 1 << amount;
  (void)value;
}

BOOST_AUTO_TEST_SUITE_END()
