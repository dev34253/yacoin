// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/known_failure.h"

namespace known_failure {

std::string Show(const std::string& value)
{
    return "\"" + value + "\"";
}

std::string Show(const char* value)
{
    return Show(std::string(value));
}

boost::test_tools::predicate_result Check(const std::string& row, bool correct, bool current,
                                          const std::string& actual, const std::string& expected)
{
    boost::test_tools::predicate_result result(current && !correct);
    if (correct && current) {
        result.message() << row << ": the correct and the known-failure outcome both hold (" << actual
                         << "), so the check can't tell a fix from the defect";
    } else if (correct) {
        result.message() << row << " no longer fails; remove the known-failure check (now " << actual << ")";
    } else if (current) {
        result.message() << row << ": known failure still present (" << actual << ")";
    } else {
        result.message() << row << ": not the expected known failure: got " << actual << ", expected " << expected;
    }
    return result;
}

} // namespace known_failure
