// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/log_test_util.h"

#include "util.h"

#include <fcntl.h>
#ifdef WIN32
#include <io.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#endif

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>

#include <boost/test/unit_test.hpp>

namespace {

// File descriptor calls: the C runtime's underscore names on Windows (as util.cpp uses), POSIX
// elsewhere
#ifdef WIN32
int StdoutFd() { return _fileno(stdout); }
int DupFd(int fd) { return _dup(fd); }
int Dup2Fd(int from, int to) { return _dup2(from, to); }
int CloseFd(int fd) { return _close(fd); }
int OpenForWrite(const char* path) { return _open(path, _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE); }
const char* const NULL_DEVICE = "NUL";
#else
int StdoutFd() { return fileno(stdout); }
int DupFd(int fd) { return dup(fd); }
int Dup2Fd(int from, int to) { return dup2(from, to); }
int CloseFd(int fd) { return close(fd); }
int OpenForWrite(const char* path) { return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600); }
const char* const NULL_DEVICE = "/dev/null";
#endif

/** Points stdout at path; returns the descriptor stdout had, for RestoreStdout */
int RedirectStdout(const char* path)
{
    fflush(stdout);
    const int saved = DupFd(StdoutFd());
    const int fd = OpenForWrite(path);
    Dup2Fd(fd, StdoutFd());
    CloseFd(fd);
    return saved;
}

void RestoreStdout(int saved)
{
    fflush(stdout);
    Dup2Fd(saved, StdoutFd());
    CloseFd(saved);
}

} // namespace

ConsoleLogging::ConsoleLogging() : m_prevConsole(fPrintToConsole)
{
    boost::unit_test::unit_test_log.set_stream(std::cerr);
    m_savedStdout = RedirectStdout(NULL_DEVICE);
    fPrintToConsole = true;
}

ConsoleLogging::~ConsoleLogging()
{
    fPrintToConsole = m_prevConsole;
    RestoreStdout(m_savedStdout);
    boost::unit_test::unit_test_log.set_stream(std::cout);
}

LogCapture::LogCapture(const fs::path& path) : m_path(path)
{
    BOOST_REQUIRE(fPrintToConsole);
    m_saved = RedirectStdout(path.string().c_str());
}

LogCapture::~LogCapture() { Restore(); }

std::string LogCapture::Stop()
{
    Restore();
    std::ifstream in(m_path.string());
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void LogCapture::Restore()
{
    if (m_saved < 0) return;
    RestoreStdout(m_saved);
    m_saved = -1;
}

std::string LogValue(const std::string& log, const std::string& prefix)
{
    size_t pos = log.find(prefix);
    if (pos == std::string::npos) return "";
    pos += prefix.size();
    return log.substr(pos, log.find('\n', pos) - pos);
}
