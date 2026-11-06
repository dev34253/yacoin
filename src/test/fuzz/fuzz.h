// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_FUZZ_H
#define BITCOIN_TEST_FUZZ_FUZZ_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

/** One input of a fuzz target */
using FuzzBufferType = std::vector<uint8_t>;

using TypeTestOneInput = std::function<void(const FuzzBufferType&)>;

/** Registers a fuzz target under its name; called before main by FUZZ_TARGET. */
void FuzzFrameworkRegisterTarget(const std::string& name, TypeTestOneInput target);

/**
 * Defines the fuzz target `name`: the block that follows the macro runs once
 * per input, which it gets as `buffer`. The fuzz binary runs the target named
 * by the FUZZ environment variable.
 */
#define FUZZ_TARGET(name)                                                                \
    static void name##_fuzz_target(const FuzzBufferType& buffer);                        \
    namespace {                                                                          \
    struct name##_Before_Main {                                                          \
        name##_Before_Main() { FuzzFrameworkRegisterTarget(#name, name##_fuzz_target); } \
    } const g_##name##_before_main;                                                      \
    }                                                                                    \
    static void name##_fuzz_target(const FuzzBufferType& buffer)

#endif // BITCOIN_TEST_FUZZ_FUZZ_H
