// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_BENCH_BENCH_H
#define YACOIN_BENCH_BENCH_H

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <regex>
#include <stdexcept>
#include <string>

#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/stringize.hpp>

// A small micro-benchmarking framework, without a further dependency; its
// API is a subset of the Google Benchmark framework
// (https://github.com/google/benchmark). See doc/benchmarking.md.

/*
 * Usage:

static void CODE_TO_TIME(benchmark::State& state)
{
    ... do any setup needed...
    while (state.KeepRunning()) {
       ... do stuff you want to time...
    }
    ... do any cleanup needed...
}

BENCHMARK(CODE_TO_TIME);

 */

namespace benchmark {

/** A benchmark's set-up or result check failed; the runner reports what. */
class Failure : public std::runtime_error
{
public:
    explicit Failure(const std::string& what) : std::runtime_error(what) {}
};

/** Throws Failure(what) unless fOk */
inline void Require(bool fOk, const std::string& what)
{
    if (!fOk) throw Failure(what);
}

class State
{
    typedef std::chrono::steady_clock Clock;

    std::string name;
    double maxElapsed;
    Clock::time_point beginTime;
    Clock::time_point lastTime;
    double minTime, maxTime, countMaskInv;
    uint64_t count;
    uint64_t countMask;

public:
    State(const std::string& _name, double _maxElapsed);

    /** True while the benchmark is to run its timed code once more. Runs it
     * at least once and until maxElapsed seconds have passed; then prints the
     * result line (name, count, min, max, average) and returns false. */
    bool KeepRunning();
};

typedef std::function<void(State&)> BenchFunction;

class BenchRunner
{
    typedef std::map<std::string, BenchFunction> BenchmarkMap;
    static BenchmarkMap& benchmarks();

public:
    BenchRunner(const std::string& name, BenchFunction func);

    /** Prints the names of the benchmarks that filter matches, one per line */
    static void List(const std::regex& filter);

    /** Runs the benchmarks that filter matches, in the order of their names,
     * each for about elapsedTimeForOne seconds, and prints a CSV header and
     * one line per benchmark. A benchmark that throws is reported on stderr
     * and the others still run. Returns the number of failed benchmarks. */
    static int RunAll(const std::regex& filter, double elapsedTimeForOne);
};
} // namespace benchmark

// BENCHMARK(foo) expands to:  benchmark::BenchRunner bench_11foo("foo", foo);
#define BENCHMARK(n) \
    benchmark::BenchRunner BOOST_PP_CAT(bench_, BOOST_PP_CAT(__LINE__, n))(BOOST_PP_STRINGIZE(n), n);

#endif // YACOIN_BENCH_BENCH_H
