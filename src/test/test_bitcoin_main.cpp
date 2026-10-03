// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bitcoin Test Suite

#include "net.h"

#include <cstdio>
#include <cstdlib>

#include <boost/test/unit_test.hpp>

std::unique_ptr<CConnman> g_connman;

void Shutdown(void* parg)
{
  exit(EXIT_SUCCESS);
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
