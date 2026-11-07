// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// One LogPrintf call of a fixed short line, with logging on (to debug.log in
// the data directory of BenchDataDir(), with the default timestamps) and off.
// Both run without mock time, whichever benchmarks ran before, and with
// debug.log open, and check afterwards that logging on wrote to debug.log
// and logging off did not.

#include "bench/bench.h"
#include "bench/bench_util.h"

#include "fs.h"
#include "util.h"
#include "utiltime.h"

#include <cstdint>

namespace {
/** Sets where log lines go, and no mock time, for its lifetime */
class LoggingGuard
{
    const bool fSavedDebugLog;
    const bool fSavedConsole;
    const int64_t nSavedMockTime;

public:
    explicit LoggingGuard(bool fDebugLog)
        : fSavedDebugLog(fPrintToDebugLog), fSavedConsole(fPrintToConsole), nSavedMockTime(GetMockTime())
    {
        fPrintToDebugLog = fDebugLog;
        fPrintToConsole = false;
        SetMockTime(0);
    }
    ~LoggingGuard()
    {
        fPrintToDebugLog = fSavedDebugLog;
        fPrintToConsole = fSavedConsole;
        SetMockTime(nSavedMockTime);
    }
};

fs::path DebugLogPath()
{
    return BenchDataDir() / "debug.log";
}

/** The size of debug.log, 0 if there is none */
uintmax_t DebugLogSize()
{
    boost::system::error_code ec;
    const uintmax_t nSize = fs::file_size(DebugLogPath(), ec);
    return ec ? 0 : nSize;
}

/** Opens debug.log in the data directory once per process */
void OpenBenchDebugLog()
{
    static bool fOpen = false;
    if (fOpen) return;
    benchmark::Require(!fs::exists(DebugLogPath()), "debug.log exists before it is opened");
    OpenDebugLog();
    benchmark::Require(fs::exists(DebugLogPath()), "cannot open " + DebugLogPath().string());
    fOpen = true;
}
} // namespace

static void LogPrintfLoggingOn(benchmark::State& state)
{
    OpenBenchDebugLog();
    const uintmax_t nSizeBefore = DebugLogSize();
    {
        const LoggingGuard guard(true);
        while (state.KeepRunning()) {
            LogPrintf("bench_yacoin: a fixed line of the logging benchmark\n");
        }
    }
    benchmark::Require(DebugLogSize() > nSizeBefore, "logging on wrote nothing to debug.log");
}

static void LogPrintfLoggingOff(benchmark::State& state)
{
    OpenBenchDebugLog();
    const uintmax_t nSizeBefore = DebugLogSize();
    {
        const LoggingGuard guard(false);
        while (state.KeepRunning()) {
            LogPrintf("bench_yacoin: a fixed line of the logging benchmark\n");
        }
    }
    benchmark::Require(DebugLogSize() == nSizeBefore, "logging off wrote to debug.log");
}

BENCHMARK(LogPrintfLoggingOn);
BENCHMARK(LogPrintfLoggingOff);
