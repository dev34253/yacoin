// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_LOG_TEST_UTIL_H
#define YACOIN_TEST_LOG_TEST_UTIL_H

// Capturing the node's log output in unit tests: log output goes to stdout, and stdout is
// pointed at a file while a capture runs.

#include "fs.h"

#include <string>

/** Sends log output to stdout (fPrintToConsole) for the fixture's lifetime. A base class listed
 *  before the fixture's, so the setting is made before the fixture's threads start, which log
 *  and so read it, and restored after they have ended. Meanwhile stdout goes to the null device
 *  except while a LogCapture runs, and Boost.Test's log, which is written to std::cout by default,
 *  goes to std::cerr, so it stays in the suite's output. */
struct ConsoleLogging {
    const bool m_prevConsole;
    int m_savedStdout;
    ConsoleLogging();
    ~ConsoleLogging();
};

/** Sends log output, which goes to stdout under ConsoleLogging, into a file while alive */
class LogCapture
{
public:
    explicit LogCapture(const fs::path& path);
    ~LogCapture();

    /** Ends the capture and returns what was captured */
    std::string Stop();

private:
    void Restore();

    fs::path m_path;
    int m_saved;
};

/** The rest of the log line that starts with prefix ("" if there is none) */
std::string LogValue(const std::string& log, const std::string& prefix);

#endif // YACOIN_TEST_LOG_TEST_UTIL_H
