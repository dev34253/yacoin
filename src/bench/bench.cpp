// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench/bench.h"

#include <cassert>
#include <exception>
#include <iomanip>
#include <ios>
#include <iostream>
#include <limits>
#include <utility>

namespace {
template <typename Duration>
double Seconds(Duration d)
{
    return std::chrono::duration_cast<std::chrono::duration<double> >(d).count();
}
} // namespace

benchmark::BenchRunner::BenchmarkMap& benchmark::BenchRunner::benchmarks()
{
    static std::map<std::string, benchmark::BenchFunction> benchmarks_map;
    return benchmarks_map;
}

benchmark::BenchRunner::BenchRunner(const std::string& name, benchmark::BenchFunction func)
{
    benchmarks().insert(std::make_pair(name, func));
}

void benchmark::BenchRunner::List(const std::regex& filter)
{
    for (const auto& p : benchmarks()) {
        if (std::regex_match(p.first, filter)) std::cout << p.first << "\n";
    }
    std::cout.flush();
}

int benchmark::BenchRunner::RunAll(const std::regex& filter, double elapsedTimeForOne)
{
    int nFailed = 0;
    std::cout << "#Benchmark" << "," << "count" << "," << "min" << "," << "max" << "," << "average" << std::endl;

    for (const auto& p : benchmarks()) {
        if (!std::regex_match(p.first, filter)) continue;
        State state(p.first, elapsedTimeForOne);
        try {
            p.second(state);
        } catch (const std::exception& e) {
            std::cout.flush();
            std::cerr << "error: benchmark " << p.first << " failed: " << e.what() << std::endl;
            ++nFailed;
        }
    }
    return nFailed;
}

benchmark::State::State(const std::string& _name, double _maxElapsed) : name(_name), maxElapsed(_maxElapsed), count(0)
{
    minTime = std::numeric_limits<double>::max();
    maxTime = std::numeric_limits<double>::min();
    // Every run of the timed code is timed until the runs prove short
    // (see below), so a slow benchmark is done after its first run.
    countMask = 0;
    countMaskInv = 1. / (countMask + 1);
}

bool benchmark::State::KeepRunning()
{
    if (count & countMask) {
        ++count;
        return true;
    }
    Clock::time_point now;
    if (count == 0) {
        lastTime = beginTime = now = Clock::now();
    } else {
        now = Clock::now();
        double elapsed = Seconds(now - lastTime);
        double elapsedOne = elapsed * countMaskInv;
        if (elapsedOne < minTime) minTime = elapsedOne;
        if (elapsedOne > maxTime) maxTime = elapsedOne;

        if (elapsed * 128 < maxElapsed) {
            // If the execution was much too fast (1/128th of maxElapsed), increase the count mask by 8x and restart timing.
            // The restart avoids including the overhead of this code in the measurement.
            countMask = ((countMask << 3) | 7) & ((1ULL << 60) - 1);
            countMaskInv = 1. / (countMask + 1);
            count = 0;
            minTime = std::numeric_limits<double>::max();
            maxTime = std::numeric_limits<double>::min();
            return true;
        }
        if (elapsed * 16 < maxElapsed) {
            uint64_t newCountMask = ((countMask << 1) | 1) & ((1ULL << 60) - 1);
            if ((count & newCountMask) == 0) {
                countMask = newCountMask;
                countMaskInv = 1. / (countMask + 1);
            }
        }
    }
    lastTime = now;
    ++count;

    if (Seconds(now - beginTime) < maxElapsed) return true; // Keep going

    --count;

    assert(count != 0 && "count == 0 => now == beginTime => maxElapsed <= 0, which main refuses");

    // Output results
    double average = Seconds(now - beginTime) / count;
    std::cout << std::fixed << std::setprecision(15) << name << "," << count << "," << minTime << "," << maxTime << "," << average << std::endl;
    std::cout.copyfmt(std::ios(nullptr));

    return false;
}
