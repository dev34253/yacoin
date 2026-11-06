// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The libFuzzer entry points of the fuzz binary. The target is chosen by the
// FUZZ environment variable; with PRINT_ALL_FUZZ_TARGETS_AND_ABORT set, the
// binary prints the names of all targets, one per line, and exits with
// status 0. See doc/fuzzing.md.

#include "test/fuzz/fuzz.h"

#include "chainparams.h"
#include "chainparamsbase.h"
#include "pubkey.h"
#include "util.h"

#include <cstdlib>
#include <iostream>
#include <map>
#include <utility>

namespace {
std::map<std::string, TypeTestOneInput>& FuzzTargets()
{
    static std::map<std::string, TypeTestOneInput> g_fuzz_targets;
    return g_fuzz_targets;
}

const TypeTestOneInput* g_test_one_input = nullptr;

void Initialize()
{
    if (std::getenv("PRINT_ALL_FUZZ_TARGETS_AND_ABORT")) {
        for (const auto& target : FuzzTargets()) {
            std::cout << target.first << std::endl;
        }
        std::exit(EXIT_SUCCESS);
    }
    const char* name = std::getenv("FUZZ");
    if (name == nullptr || *name == '\0') {
        std::cerr << "error: set FUZZ to the name of a fuzz target "
                     "(PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1 lists them)" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    const auto it = FuzzTargets().find(name);
    if (it == FuzzTargets().end()) {
        std::cerr << "error: no fuzz target named '" << name << "' "
                     "(PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1 lists them)" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    g_test_one_input = &it->second;

    static ECCVerifyHandle global_verify_handle;
    // Select the main network's parameters, as the node does at start.
    SelectParams(CBaseChainParams::MAIN);
    // The process runs for a long time: log messages are neither written to
    // a debug log nor kept in memory for one.
    fPrintToDebugLog = false;
}
} // namespace

void FuzzFrameworkRegisterTarget(const std::string& name, TypeTestOneInput target)
{
    if (!FuzzTargets().emplace(name, std::move(target)).second) {
        std::cerr << "error: fuzz target '" << name << "' defined twice" << std::endl;
        std::abort();
    }
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    Initialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const FuzzBufferType buffer(data, data + size);
    (*g_test_one_input)(buffer);
    return 0;
}
