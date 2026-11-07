// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The benchmark binary: runs the benchmarks that -filter matches, each for
// about -time seconds, and prints one CSV line per benchmark. See
// doc/benchmarking.md.

#include "bench/bench.h"

#include "chainparams.h"
#include "chainparamsbase.h"
#include "crypto/sha256.h"
#include "key.h"
#include "pubkey.h"
#include "random.h"
#include "util.h"

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <regex>
#include <string>

namespace {
const char* const DEFAULT_FILTER = ".*";
const double DEFAULT_TIME = 1.0;

void PrintUsage()
{
    std::cout << "Usage: bench_yacoin [options]\n"
                 "\n"
                 "Runs the benchmarks in the order of their names and prints one CSV line per\n"
                 "benchmark: name, count (runs timed), min, max and average (seconds per run).\n"
                 "\n"
                 "Options:\n"
                 "  -help            Print this help and exit\n"
                 "  -list            Print the names of the benchmarks -filter matches, one per\n"
                 "                   line, and exit\n"
                 "  -filter=<regex>  Run only the benchmarks whose whole name matches <regex>\n"
                 "                   (ECMAScript syntax; default: "
              << DEFAULT_FILTER << ")\n"
                 "  -time=<seconds>  Run each benchmark for about <seconds>, at least once\n"
                 "                   (a positive number; default: "
              << DEFAULT_TIME << ")\n";
}

[[noreturn]] void UsageError(const std::string& message)
{
    std::cerr << "error: " << message << " (bench_yacoin -help shows the options)" << std::endl;
    std::exit(2);
}

/** Parses a positive, finite number of seconds; false if s is not one */
bool ParseSeconds(const std::string& s, double& seconds)
{
    if (s.empty()) return false;
    size_t pos = 0;
    try {
        seconds = std::stod(s, &pos);
    } catch (const std::exception&) {
        return false;
    }
    return pos == s.size() && std::isfinite(seconds) && seconds > 0;
}
} // namespace

int main(int argc, char** argv)
{
    bool fList = false;
    std::string strFilter = DEFAULT_FILTER;
    double nTime = DEFAULT_TIME;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        // As yacoind: -option and --option are the same
        if (arg.size() > 2 && arg[0] == '-' && arg[1] == '-') arg = arg.substr(1);
        const size_t nEquals = arg.find('=');
        const std::string strKey = arg.substr(0, nEquals);
        const bool fValue = nEquals != std::string::npos;
        const std::string strValue = fValue ? arg.substr(nEquals + 1) : "";
        if ((strKey == "-help" || strKey == "-h" || strKey == "-?") && !fValue) {
            PrintUsage();
            return 0;
        } else if (strKey == "-list" && !fValue) {
            fList = true;
        } else if (strKey == "-filter" && fValue) {
            strFilter = strValue;
        } else if (strKey == "-time" && fValue) {
            if (!ParseSeconds(strValue, nTime)) UsageError("-time needs a positive number of seconds, not '" + strValue + "'");
        } else {
            UsageError("unknown option '" + std::string(argv[i]) + "'");
        }
    }

    std::regex filter;
    try {
        filter = std::regex(strFilter, std::regex::ECMAScript);
    } catch (const std::regex_error& e) {
        UsageError("-filter: invalid regular expression '" + strFilter + "': " + e.what());
    }

    if (fList) {
        benchmark::BenchRunner::List(filter);
        return 0;
    }

    SHA256AutoDetect();
    RandomInit();
    ECC_Start();
    SetupEnvironment();
    ECCVerifyHandle globalVerifyHandle;
    SelectParams(CBaseChainParams::MAIN);
    fPrintToDebugLog = false; // don't want to write to debug.log file

    const int nFailed = benchmark::BenchRunner::RunAll(filter, nTime);

    ECC_Stop();
    if (nFailed != 0) {
        std::cerr << "error: " << nFailed << " benchmark(s) failed" << std::endl;
        return 1;
    }
    return 0;
}
