// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The shared test fixtures and guards of test_bitcoin.h. The suite has no fixture of its own,
// so the cases can construct fixtures one after another.

#include "test/test_bitcoin.h"

#include "fs.h"
#include "sync.h"
#include "ui_interface.h"
#include "util.h"
#include "utiltime.h"
#include "warnings.h"

#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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

namespace {

/** Whether cs can be taken from elsewhere now */
bool ProbeTakesLock(CCriticalSection& cs)
{
    bool fTaken = false;
    std::thread probe([&cs, &fTaken] {
        TRY_LOCK(cs, lock);
        fTaken = lock;
    });
    probe.join();
    return fTaken;
}

/** A number whose assignment records whether the probe could take cs at that moment */
struct ProbedValue {
    CCriticalSection* cs;
    std::vector<bool>* pTaken;
    int n;

    ProbedValue(CCriticalSection* csIn, std::vector<bool>* pTakenIn, int nIn) : cs(csIn), pTaken(pTakenIn), n(nIn) {}
    ProbedValue(const ProbedValue&) = default;
    ProbedValue& operator=(const ProbedValue& other)
    {
        n = other.n;
        pTaken->push_back(ProbeTakesLock(*cs));
        return *this;
    }
};

} // namespace

/* ValueGuard sets the variable while it lives and puts back the value it found: at the end of
 * its scope, when the scope is left by an exception, and for nested guards on one variable */
BOOST_AUTO_TEST_CASE(value_guard_restores)
{
    int n = 1;
    {
        ValueGuard<int> guard(n, 2);
        BOOST_CHECK_EQUAL(n, 2);
    }
    BOOST_CHECK_EQUAL(n, 1);

    try {
        ValueGuard<int> guard(n, 3);
        BOOST_CHECK_EQUAL(n, 3);
        throw std::runtime_error("thrown in the guarded block");
    } catch (const std::runtime_error&) {
    }
    BOOST_CHECK_EQUAL(n, 1);

    {
        ValueGuard<int> outer(n, 4);
        {
            ValueGuard<int> inner(n, 5);
            BOOST_CHECK_EQUAL(n, 5);
        }
        BOOST_CHECK_EQUAL(n, 4);
    }
    BOOST_CHECK_EQUAL(n, 1);

    int target = 0;
    int* p = &target;
    {
        ValueGuard<int*> guard(p, nullptr);
        BOOST_CHECK(p == nullptr);
    }
    BOOST_CHECK(p == &target);
}

/* ValueGuard with a lock: the lock is held at set and at restore and free while the guard lives
 * and afterwards; the value is set and put back */
BOOST_AUTO_TEST_CASE(value_guard_holds_the_lock)
{
    CCriticalSection cs;
    std::vector<bool> taken;
    ProbedValue value(&cs, &taken, 1);
    {
        ValueGuard<ProbedValue> guard(cs, value, ProbedValue(&cs, &taken, 2));
        BOOST_CHECK_EQUAL(value.n, 2);
        BOOST_CHECK(ProbeTakesLock(cs));
    }
    BOOST_CHECK_EQUAL(value.n, 1);
    BOOST_CHECK(taken == std::vector<bool>({false, false})); // at set, at restore
    BOOST_CHECK(ProbeTakesLock(cs));
}

/* MockTimeGuard puts back the mock time it found, 0 or another time, also when its scope is left
 * by an exception; Set() changes the time while it lives; the guard without a time sets nothing */
BOOST_AUTO_TEST_CASE(mock_time_guard_restores)
{
    MockTimeGuard caseGuard;
    SetMockTime(0);
    {
        MockTimeGuard guard(1600000000);
        BOOST_CHECK_EQUAL(GetMockTime(), 1600000000);
        guard.Set(1600000060);
        BOOST_CHECK_EQUAL(GetMockTime(), 1600000060);
    }
    BOOST_CHECK_EQUAL(GetMockTime(), 0);

    MockTimeGuard outer(1600000000);
    {
        MockTimeGuard inner(1700000000);
        BOOST_CHECK_EQUAL(GetMockTime(), 1700000000);
    }
    BOOST_CHECK_EQUAL(GetMockTime(), 1600000000);

    try {
        MockTimeGuard guard(1700000000);
        throw std::runtime_error("thrown in the guarded block");
    } catch (const std::runtime_error&) {
    }
    BOOST_CHECK_EQUAL(GetMockTime(), 1600000000);

    {
        MockTimeGuard guard;
        BOOST_CHECK_EQUAL(GetMockTime(), 1600000000);
        SetMockTime(1700000000);
    }
    BOOST_CHECK_EQUAL(GetMockTime(), 1600000000);
}

BOOST_AUTO_TEST_SUITE_END()
