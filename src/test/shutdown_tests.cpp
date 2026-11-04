// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// A shutdown request in test_bitcoin (test_bitcoin_main.cpp) ends the process with a failure
// status and a message on stderr, so that a test run that the code under test gave up on, for
// example in a failed release-mode assertion (Yassert), cannot be counted as passed. While a
// ShutdownRequestRecorder lives, the request is recorded instead.

#ifndef WIN32

#include "Yassert.h"
#include "init.h"
#include "test/test_bitcoin.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>

#include <sys/wait.h>
#include <unistd.h>

#include <boost/test/unit_test.hpp>

void Shutdown(void* parg);

namespace {

struct ChildEnd {
    bool exited = false; // ended through exit or _exit, not a signal
    int status = -1;     // the exit status if exited
    std::string err;     // what the child wrote to stderr
};

/** Runs body in a child process with stderr on a pipe. The child leaves with _exit(0) if body
 *  returns, so only an exit inside body gives another status. body must not use Boost.Test. */
ChildEnd RunInChild(const std::function<void()>& body)
{
    ChildEnd end;
    int fds[2];
    if (pipe(fds) != 0) return end;
    fflush(nullptr);
    const pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return end;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);
        body();
        _exit(0);
    }
    close(fds[1]);
    char buf[512];
    ssize_t n;
    while ((n = read(fds[0], buf, sizeof(buf))) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        end.err.append(buf, n);
    }
    close(fds[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return end;
    }
    end.exited = WIFEXITED(status);
    if (end.exited) end.status = WEXITSTATUS(status);
    return end;
}

void CheckFailedWith(const ChildEnd& end, const std::string& function)
{
    BOOST_CHECK(end.exited);
    BOOST_CHECK_EQUAL(end.status, EXIT_FAILURE);
    BOOST_CHECK_MESSAGE(end.err.find(function + "() called during the unit tests") != std::string::npos,
                        "stderr: " + end.err);
}

} // namespace

BOOST_AUTO_TEST_SUITE(shutdown_tests)

BOOST_AUTO_TEST_CASE(start_shutdown_exits_with_failure)
{
    CheckFailedWith(RunInChild([] { StartShutdown(); }), "StartShutdown");
}

BOOST_AUTO_TEST_CASE(shutdown_exits_with_failure)
{
    CheckFailedWith(RunInChild([] { Shutdown(nullptr); }), "Shutdown");
}

BOOST_AUTO_TEST_CASE(failed_yassert_exits_with_failure)
{
    const ChildEnd end = RunInChild([] {
        volatile bool fFalse = false;
        Yassert(fFalse);
    });
#ifndef _DEBUG
    CheckFailedWith(end, "StartShutdown");
#else
    BOOST_CHECK(!end.exited);
#endif
}

BOOST_AUTO_TEST_CASE(passing_yassert_does_not_exit)
{
    const ChildEnd end = RunInChild([] {
        volatile bool fTrue = true;
        Yassert(fTrue);
    });
    BOOST_CHECK(end.exited);
    BOOST_CHECK_EQUAL(end.status, 0);
    BOOST_CHECK_EQUAL(end.err, "");
}

BOOST_AUTO_TEST_CASE(recorder_records_without_exit)
{
    const ChildEnd end = RunInChild([] {
        ShutdownRequestRecorder recorder;
        if (ShutdownRequested()) _exit(3);
        StartShutdown();
        if (!ShutdownRequested()) _exit(4);
        ShutdownRequestRecorder::Reset();
        if (ShutdownRequested()) _exit(5);
        StartShutdown();
        if (!ShutdownRequested()) _exit(6);
    });
    BOOST_CHECK(end.exited);
    BOOST_CHECK_EQUAL(end.status, 0);
    BOOST_CHECK_EQUAL(end.err, "");
}

BOOST_AUTO_TEST_CASE(start_shutdown_exits_again_after_recorder)
{
    const ChildEnd end = RunInChild([] {
        {
            ShutdownRequestRecorder recorder;
            StartShutdown();
        }
        if (ShutdownRequested()) _exit(3);
        StartShutdown();
    });
    CheckFailedWith(end, "StartShutdown");
}

BOOST_AUTO_TEST_SUITE_END()

#endif // WIN32
