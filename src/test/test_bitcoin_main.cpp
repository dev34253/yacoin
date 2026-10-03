// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bitcoin Test Suite

#include "net.h"

#include <cstdio>
#include <cstdlib>

#include <boost/test/unit_test.hpp>

std::unique_ptr<CConnman> g_connman;

// Like StartShutdown() below: a run that ends here has no Boost test summary,
// so it must not exit with status 0 (task P0-61, open question Q8). No test
// calls it today.
void Shutdown(void* parg)
{
  fprintf(stderr, "test_bitcoin: Shutdown() called; failing the run\n");
  exit(EXIT_FAILURE);
}

// Node code calls StartShutdown() when it gives up, e.g. a failed Yassert in a
// release build (releaseModeAssertionfailure, main.cpp) such as the genesis
// check in chainparams.cpp. Exit with failure so that the run does not end
// with status 0 and without a test summary (task P0-20).
void StartShutdown()
{
  fprintf(stderr, "test_bitcoin: StartShutdown() called (e.g. a failed Yassert, see debug output); failing the run\n");
  exit(EXIT_FAILURE);
}

bool ShutdownRequested()
{
  return false;
}
