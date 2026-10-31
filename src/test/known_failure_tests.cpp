// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The known-failure check (known_failure.h): it passes while the defect is present, fails
// asking for its removal once the correct behaviour holds, and fails on any other outcome.

#include "test/known_failure.h"

#include <boost/test/unit_test.hpp>

namespace {

std::string Message(boost::test_tools::predicate_result& r) { return r.message().str(); }

/** A stand-in for code with a known defect: it should return 2 * n, today it returns 2 * n + 1
 *  for odd n; `variant` simulates a fix (1) or a different wrong result (2). */
int Doubled(int n, int variant = 0)
{
    if (variant == 1) return 2 * n;
    if (variant == 2) return 0;
    return n % 2 ? 2 * n + 1 : 2 * n;
}

} // namespace

BOOST_AUTO_TEST_SUITE(known_failure_tests)

BOOST_AUTO_TEST_CASE(passes_while_the_defect_is_present)
{
    boost::test_tools::predicate_result r = known_failure::CheckEqual("MG-999", Doubled(3), 6, 7);
    BOOST_CHECK(r);
    BOOST_CHECK_EQUAL(Message(r), "MG-999: known failure still present (7)");

    boost::test_tools::predicate_result p = known_failure::Check("MG-999", false, true, "7", "7");
    BOOST_CHECK(p);
    BOOST_CHECK_EQUAL(Message(p), "MG-999: known failure still present (7)");

    // The macros pass too, and so leave no failure in this test case
    KNOWN_FAILURE_EQUAL("MG-999", Doubled(3), 6, 7);
    KNOWN_FAILURE_EQUAL("MG-999", std::string("0.00000001"), "0.000001", "0.00000001");
    const int n = Doubled(3);
    KNOWN_FAILURE("MG-999", n, n == 6, n == 7);
}

BOOST_AUTO_TEST_CASE(fails_once_the_defect_is_fixed)
{
    boost::test_tools::predicate_result r = known_failure::CheckEqual("MG-999", Doubled(3, 1), 6, 7);
    BOOST_CHECK(!r);
    BOOST_CHECK_EQUAL(Message(r), "MG-999 no longer fails; remove the known-failure check (now 6)");

    const int n = Doubled(3, 1);
    boost::test_tools::predicate_result p = known_failure::Check("MG-999", n == 6, n == 7, known_failure::Show(n), "n == 7");
    BOOST_CHECK(!p);
    BOOST_CHECK_EQUAL(Message(p), "MG-999 no longer fails; remove the known-failure check (now 6)");

    // The removal message wins over any other: correct is all that matters
    boost::test_tools::predicate_result s = known_failure::CheckEqual("MG-999", std::string("0.000001"), "0.000001", "0.00000001");
    BOOST_CHECK(!s);
    BOOST_CHECK_EQUAL(Message(s), "MG-999 no longer fails; remove the known-failure check (now \"0.000001\")");
}

BOOST_AUTO_TEST_CASE(fails_on_another_outcome)
{
    boost::test_tools::predicate_result r = known_failure::CheckEqual("MG-999", Doubled(3, 2), 6, 7);
    BOOST_CHECK(!r);
    BOOST_CHECK_EQUAL(Message(r), "MG-999: not the expected known failure: got 0, expected 7");

    const int n = Doubled(3, 2);
    boost::test_tools::predicate_result p = known_failure::Check("MG-999", n == 6, n == 7, known_failure::Show(n), "n == 7");
    BOOST_CHECK(!p);
    BOOST_CHECK_EQUAL(Message(p), "MG-999: not the expected known failure: got 0, expected n == 7");

    // Strings are quoted, so an empty value shows
    boost::test_tools::predicate_result s = known_failure::CheckEqual("MG-999", std::string(), "a", "b");
    BOOST_CHECK(!s);
    BOOST_CHECK_EQUAL(Message(s), "MG-999: not the expected known failure: got \"\", expected \"b\"");
}

BOOST_AUTO_TEST_CASE(fails_when_correct_and_current_are_the_same)
{
    // A pin whose correct and current outcome coincide could never show the fix
    boost::test_tools::predicate_result r = known_failure::CheckEqual("MG-999", 6, 6, 6);
    BOOST_CHECK(!r);
    BOOST_CHECK_EQUAL(Message(r), "MG-999: the correct and the known-failure outcome both hold (6), so the check can't tell a fix from the defect");
}

BOOST_AUTO_TEST_SUITE_END()
