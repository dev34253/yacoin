// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_KNOWN_FAILURE_H
#define YACOIN_TEST_KNOWN_FAILURE_H

#include <sstream>
#include <string>

#include <boost/test/unit_test.hpp>

/**
 * Known-failure checks: how a unit test pins a known defect.
 *
 * The test states the correct behaviour and the outcome the defect gives today. The check
 * passes only while the correct behaviour does not hold and the outcome is exactly today's
 * wrong one. It fails
 *  - with "<row> no longer fails; remove the known-failure check" once the correct
 *    behaviour holds, so the fix replaces the check with a plain assertion of the correct
 *    behaviour in the same change;
 *  - with "<row>: not the expected known failure" when the outcome is anything else,
 *    showing the actual value.
 *
 * `row` names the defect's row in the modernisation gap register, e.g. "MG-045". Behaviour
 * that is intended is asserted with plain checks, not with these. The functional tests have
 * the same check: known_failure() in test/functional/test_framework/util.py.
 *
 *   // Equality form: the actual value, the correct value, today's value
 *   KNOWN_FAILURE_EQUAL("MG-011", rate.ToString(), "0.000001 YAC/kB", "0.00000001 YAC/kB");
 *   // Predicate form: a value to show, the correct condition, today's condition
 *   KNOWN_FAILURE("MG-046", message, !message.empty(), message.empty() && code == RPC_WALLET_ERROR);
 *
 * Both report through BOOST_CHECK_MESSAGE, so a failure points at the line that uses them,
 * and the test goes on after it.
 */
namespace known_failure {

/** A value as the messages show it; strings are quoted, so that an empty one is visible. */
template <typename T>
std::string Show(const T& value)
{
    std::ostringstream ss;
    ss << value;
    return ss.str();
}

std::string Show(const std::string& value);
std::string Show(const char* value);

/**
 * The check. `correct`: the correct behaviour holds; `current`: the outcome is today's wrong
 * one; `actual`: the observed value as shown in the messages; `expected`: today's outcome as
 * shown in the messages. On success the result's message says that the known failure is
 * still present.
 */
boost::test_tools::predicate_result Check(const std::string& row, bool correct, bool current,
                                          const std::string& actual, const std::string& expected);

/** A value as the equality form compares it: C strings as std::string, so that their contents
 *  are compared, not their addresses. */
template <typename T>
const T& Comparable(const T& value) { return value; }
inline std::string Comparable(const char* value) { return value; }
inline std::string Comparable(char* value) { return value; }

/** Equality form: correct if actual == correct, today's outcome if actual == current. */
template <typename A, typename C, typename K>
boost::test_tools::predicate_result CheckEqual(const std::string& row, const A& actual, const C& correct, const K& current)
{
    return Check(row, Comparable(actual) == Comparable(correct), Comparable(actual) == Comparable(current),
                 Show(Comparable(actual)), Show(Comparable(current)));
}

} // namespace known_failure

// The result is passed on as a bool: BOOST_CHECK_MESSAGE would append a predicate_result's
// message to its own, and show it twice.
#define KNOWN_FAILURE_REPORT(result)                                                      \
    do {                                                                                  \
        ::boost::test_tools::predicate_result kf_result_ = (result);                      \
        BOOST_CHECK_MESSAGE(static_cast<bool>(kf_result_), kf_result_.message().str());   \
    } while (0)

/** Passes while actual == current (today's value) and actual != correct. */
#define KNOWN_FAILURE_EQUAL(row, actual, correct, current) \
    KNOWN_FAILURE_REPORT(::known_failure::CheckEqual((row), (actual), (correct), (current)))

/** Passes while `current` (today's condition) holds and `correct` doesn't; `actual` is shown. */
#define KNOWN_FAILURE(row, actual, correct, current)                                          \
    KNOWN_FAILURE_REPORT(::known_failure::Check((row), static_cast<bool>(correct),            \
                                                static_cast<bool>(current),                   \
                                                ::known_failure::Show(actual), #current))

#endif // YACOIN_TEST_KNOWN_FAILURE_H
