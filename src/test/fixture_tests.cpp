// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The shared test fixtures and guards of test_bitcoin.h. The suite has no fixture of its own,
// so the cases can construct fixtures one after another.

#include "test/test_bitcoin.h"

#include "fs.h"
#include "ui_interface.h"
#include "util.h"
#include "warnings.h"

#include <stdexcept>
#include <string>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(fixture_tests)

/* The no-UI handlers are connected once per process: further fixtures add no handler to the
 * three signals noui_connect() connects */
BOOST_AUTO_TEST_CASE(ui_signals_connected_once)
{
    {
        BasicTestingSetup setup;
    }
    const size_t nMessageBox = uiInterface.ThreadSafeMessageBox.num_slots();
    const size_t nQuestion = uiInterface.ThreadSafeQuestion.num_slots();
    const size_t nInitMessage = uiInterface.InitMessage.num_slots();
    BOOST_CHECK(nMessageBox > 0);
    BOOST_CHECK(nQuestion > 0);
    BOOST_CHECK(nInitMessage > 0);

    for (int i = 0; i < 2; i++) {
        BasicTestingSetup setup;
    }
    BOOST_CHECK_EQUAL(uiInterface.ThreadSafeMessageBox.num_slots(), nMessageBox);
    BOOST_CHECK_EQUAL(uiInterface.ThreadSafeQuestion.num_slots(), nQuestion);
    BOOST_CHECK_EQUAL(uiInterface.InitMessage.num_slots(), nInitMessage);
}

/* TestingSetup's temp directory name starts with the process id */
BOOST_AUTO_TEST_CASE(temp_directory_names_the_process)
{
#ifdef WIN32
    const unsigned long nProcessId = GetCurrentProcessId();
#else
    const unsigned long nProcessId = getpid();
#endif
    TestingSetup setup;
    const std::string name = setup.pathTemp.filename().string();
    const std::string prefix = strprintf("test_bitcoin_%lu_", nProcessId);
    BOOST_CHECK_MESSAGE(name.compare(0, prefix.size(), prefix) == 0, name);
}

/* MiscWarningGuard puts back the misc warning it found: Restore() now, the destructor when it
 * goes out of scope, also when the guarded block throws */
BOOST_AUTO_TEST_CASE(misc_warning_guard_restores)
{
    MiscWarningGuard outer;
    SetMiscWarning("earlier warning");
    {
        MiscWarningGuard guard;
        SetMiscWarning("later warning");
        guard.Restore();
        BOOST_CHECK_EQUAL(GetWarnings("statusbar"), "earlier warning");
        SetMiscWarning("later warning");
    }
    BOOST_CHECK_EQUAL(GetWarnings("statusbar"), "earlier warning");

    try {
        MiscWarningGuard guard;
        SetMiscWarning("later warning");
        throw std::runtime_error("thrown in the guarded block");
    } catch (const std::runtime_error&) {
    }
    BOOST_CHECK_EQUAL(GetWarnings("statusbar"), "earlier warning");
}

BOOST_AUTO_TEST_SUITE_END()
