// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bitcoin Test Suite

#include "net.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>

std::unique_ptr<CConnman> g_connman;

// The unit tests run no node that could shut down. A shutdown request means
// that the code under test gave up, for example after a failed release-mode
// assertion, so the run ends with a failure before any further test can pass
// on that state. A test of a path that requests a shutdown on purpose records
// the request with a ShutdownRequestRecorder instead.
static std::atomic<bool> g_recording_shutdown(false);
static std::atomic<bool> g_shutdown_requested(false);

ShutdownRequestRecorder::ShutdownRequestRecorder()
{
    assert(!g_recording_shutdown);
    g_shutdown_requested = false;
    g_recording_shutdown = true;
}

ShutdownRequestRecorder::~ShutdownRequestRecorder()
{
    g_recording_shutdown = false;
    g_shutdown_requested = false;
}

void ShutdownRequestRecorder::Reset()
{
    g_shutdown_requested = false;
}

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
    if (g_recording_shutdown) {
        g_shutdown_requested = true;
        return;
    }
    ExitOnShutdownRequest("StartShutdown");
}

bool ShutdownRequested()
{
    return g_recording_shutdown && g_shutdown_requested;
}
