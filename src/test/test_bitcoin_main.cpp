// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bitcoin Test Suite

#include "net.h"

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <cstdlib>

std::unique_ptr<CConnman> g_connman;

// The unit tests run no node that could shut down. A shutdown request means
// that the code under test gave up, for example after a failed release-mode
// assertion, so the run ends with a failure before any further test can pass
// on that state.
static void ExitOnShutdownRequest(const char* function)
{
    fprintf(stderr, "test_bitcoin: %s() called during the unit tests (for example after a failed release-mode assertion); exiting with failure\n", function);
    exit(EXIT_FAILURE);
}

void Shutdown(void* parg)
{
    ExitOnShutdownRequest("Shutdown");
}

void StartShutdown()
{
    ExitOnShutdownRequest("StartShutdown");
}

bool ShutdownRequested()
{
  return false;
}
