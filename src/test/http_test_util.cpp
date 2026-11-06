// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/http_test_util.h"

#include "httprpc.h"
#include "netbase.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <algorithm>
#include <chrono>
#include <errno.h>
#include <memory>
#include <stdlib.h>

#include <event2/http.h>
#include <event2/util.h>

#if !defined(HAVE_MSG_NOSIGNAL) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

// Defined in httpserver.cpp
extern std::vector<evhttp_bound_socket*> boundSockets;

void SetHTTPTestArgs(const std::vector<std::string>& args)
{
    const bool fHadDataDir = gArgs.IsArgSet("-datadir");
    const std::string strDataDir = gArgs.GetArg("-datadir", "");
    std::vector<const char*> argv{"test_bitcoin"};
    for (const std::string& arg : args)
        argv.push_back(arg.c_str());
    gArgs.ParseParameters(argv.size(), argv.data());
    if (fHadDataDir && !gArgs.IsArgSet("-datadir"))
        gArgs.ForceSetArg("-datadir", strDataDir);
}

std::vector<CService> HTTPBoundAddresses()
{
    std::vector<CService> addresses;
    for (evhttp_bound_socket* socket : boundSockets) {
        const evutil_socket_t fd = evhttp_bound_socket_get_fd(socket);
        struct sockaddr_storage storage;
        socklen_t len = sizeof(storage);
        if (getsockname(fd, (struct sockaddr*)&storage, &len) != 0)
            continue;
        CService address;
        if (address.SetSockAddr((const struct sockaddr*)&storage))
            addresses.push_back(address);
    }
    return addresses;
}

std::string HTTPTestResponse::Header(const std::string& name) const
{
    std::string lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    const auto it = headers.find(lower);
    return it == headers.end() ? "<absent>" : it->second;
}

std::string HTTPTestRequestText(const std::string& method, const std::string& uri, const std::string& body,
                                const std::vector<std::string>& headers, bool fKeepAlive)
{
    std::string text = method + " " + uri + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    if (!fKeepAlive)
        text += "Connection: close\r\n";
    for (const std::string& header : headers)
        text += header + "\r\n";
    text += strprintf("Content-Length: %u\r\n\r\n", body.size());
    return text + body;
}

HTTPTestClient::HTTPTestClient(const CService& server) : m_socket(INVALID_SOCKET)
{
    // A connection of its own rather than ConnectSocket, which would go through a proxy if one
    // were set in the process. The socket stays non-blocking; every connect, read and write
    // waits in select().
    struct sockaddr_storage storage;
    socklen_t len = sizeof(storage);
    if (!server.IsValid() || !server.GetSockAddr((struct sockaddr*)&storage, &len))
        return;
    SOCKET hSocket = socket(((struct sockaddr*)&storage)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return;
#ifdef SO_NOSIGPIPE
    int set = 1;
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif
    if (!SetSocketNonBlocking(hSocket, true)) {
        CloseSocket(hSocket);
        return;
    }
    m_socket = hSocket;
    if (connect(m_socket, (struct sockaddr*)&storage, len) == SOCKET_ERROR) {
        const int nErr = WSAGetLastError();
        int nSocketError = 0;
        socklen_t nErrLen = sizeof(nSocketError);
        if ((nErr != WSAEINPROGRESS && nErr != WSAEWOULDBLOCK) ||
            !WaitReady(true, GetTimeMillis() + HTTP_TEST_TIMEOUT_MS) ||
            getsockopt(m_socket, SOL_SOCKET, SO_ERROR, (char*)&nSocketError, &nErrLen) == SOCKET_ERROR ||
            nSocketError != 0) {
            CloseSocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
    }
}

HTTPTestClient::~HTTPTestClient()
{
    if (m_socket != INVALID_SOCKET)
        CloseSocket(m_socket);
}

CService HTTPTestClient::LocalAddress() const
{
    CService address;
    struct sockaddr_storage storage;
    socklen_t len = sizeof(storage);
    if (m_socket != INVALID_SOCKET && getsockname(m_socket, (struct sockaddr*)&storage, &len) == 0)
        address.SetSockAddr((const struct sockaddr*)&storage);
    return address;
}

bool HTTPTestClient::WaitReady(bool fWrite, int64_t nDeadline)
{
    while (true) {
        const int64_t nRemaining = nDeadline - GetTimeMillis();
        if (nRemaining <= 0)
            return false;
        struct timeval timeout = MillisToTimeval(nRemaining);
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(m_socket, &fdset);
        const int nRet = fWrite ? select(m_socket + 1, nullptr, &fdset, nullptr, &timeout)
                                : select(m_socket + 1, &fdset, nullptr, nullptr, &timeout);
        if (nRet > 0)
            return true;
        if (nRet == SOCKET_ERROR && WSAGetLastError() == WSAEINTR)
            continue;
        return false;
    }
}

bool HTTPTestClient::Send(const std::string& data)
{
    if (m_socket == INVALID_SOCKET)
        return false;
    const int64_t nDeadline = GetTimeMillis() + HTTP_TEST_TIMEOUT_MS;
    size_t nSent = 0;
    while (nSent < data.size()) {
        if (!WaitReady(true, nDeadline))
            return false;
        const int nRet = send(m_socket, data.data() + nSent, data.size() - nSent, MSG_NOSIGNAL);
        if (nRet > 0) {
            nSent += nRet;
        } else {
            const int nErr = WSAGetLastError();
            if (nErr != WSAEWOULDBLOCK && nErr != WSAEINTR)
                return false;
        }
    }
    return true;
}

HTTPTestClient::ReceiveResult HTTPTestClient::Receive(int64_t nDeadline)
{
    while (true) {
        if (!WaitReady(false, nDeadline))
            return FAILED;
        char buf[4096];
        const int nRet = recv(m_socket, buf, sizeof(buf), 0);
        if (nRet > 0) {
            m_buffer.append(buf, nRet);
            return RECEIVED;
        }
        if (nRet == 0)
            return CLOSED;
        const int nErr = WSAGetLastError();
#ifdef WIN32
        if (nErr == WSAECONNRESET)
#else
        if (nErr == ECONNRESET)
#endif
            return CLOSED;
        if (nErr != WSAEWOULDBLOCK && nErr != WSAEINTR)
            return FAILED;
    }
}

bool HTTPTestClient::ReadResponse(HTTPTestResponse& response, bool fHeadRequest)
{
    response = HTTPTestResponse();
    if (m_socket == INVALID_SOCKET)
        return false;
    const int64_t nDeadline = GetTimeMillis() + HTTP_TEST_TIMEOUT_MS;
    size_t nHeaderEnd;
    while ((nHeaderEnd = m_buffer.find("\r\n\r\n")) == std::string::npos) {
        if (Receive(nDeadline) != RECEIVED)
            return false;
    }
    const std::string head = m_buffer.substr(0, nHeaderEnd);
    m_buffer.erase(0, nHeaderEnd + 4);

    size_t nLineStart = 0;
    bool fStatusLine = true;
    while (nLineStart <= head.size()) {
        size_t nLineEnd = head.find("\r\n", nLineStart);
        if (nLineEnd == std::string::npos)
            nLineEnd = head.size();
        const std::string line = head.substr(nLineStart, nLineEnd - nLineStart);
        nLineStart = nLineEnd + 2;
        if (fStatusLine) {
            // "HTTP/1.1 200 OK"
            const size_t nSpace = line.find(' ');
            if (nSpace == std::string::npos)
                return false;
            response.status = atoi(line.substr(nSpace + 1).c_str());
            fStatusLine = false;
            continue;
        }
        const size_t nColon = line.find(':');
        if (nColon == std::string::npos)
            continue;
        std::string name = line.substr(0, nColon);
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        std::string value = line.substr(nColon + 1);
        value.erase(0, value.find_first_not_of(' '));
        response.headers[name] = value;
    }

    if (fHeadRequest) {
        response.fComplete = true;
        return true;
    }
    const auto itLength = response.headers.find("content-length");
    if (itLength != response.headers.end()) {
        const size_t nLength = atoi(itLength->second.c_str());
        while (m_buffer.size() < nLength) {
            if (Receive(nDeadline) != RECEIVED)
                return false;
        }
        response.body = m_buffer.substr(0, nLength);
        m_buffer.erase(0, nLength);
    } else {
        // The body ends where the server closes the connection
        if (WaitForClose(nDeadline) != CLOSED)
            return false;
        response.body = m_buffer;
        m_buffer.clear();
    }
    response.fComplete = true;
    return true;
}

bool HTTPTestClient::ShutdownSend()
{
    if (m_socket == INVALID_SOCKET)
        return false;
#ifdef WIN32
    return shutdown(m_socket, SD_SEND) == 0;
#else
    return shutdown(m_socket, SHUT_WR) == 0;
#endif
}

bool HTTPTestClient::WaitForClose()
{
    if (m_socket == INVALID_SOCKET)
        return false;
    return WaitForClose(GetTimeMillis() + HTTP_TEST_TIMEOUT_MS) == CLOSED;
}

HTTPTestClient::ReceiveResult HTTPTestClient::WaitForClose(int64_t nDeadline)
{
    ReceiveResult result;
    while ((result = Receive(nDeadline)) == RECEIVED) {
    }
    return result;
}

HTTPTestResponse HTTPTestRequest(const CService& server, const std::string& method, const std::string& uri,
                                 const std::string& body, const std::vector<std::string>& headers)
{
    HTTPTestResponse response;
    HTTPTestClient client(server);
    if (client.Send(HTTPTestRequestText(method, uri, body, headers)))
        client.ReadResponse(response, method == "HEAD");
    return response;
}

LoopbackListener::LoopbackListener() : m_socket(INVALID_SOCKET), m_port(0)
{
    SOCKET hSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    socklen_t len = sizeof(addr);
    if (bind(hSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(hSocket, 1) == SOCKET_ERROR ||
        getsockname(hSocket, (struct sockaddr*)&addr, &len) == SOCKET_ERROR) {
        CloseSocket(hSocket);
        return;
    }
    m_socket = hSocket;
    m_port = ntohs(addr.sin_port);
}

LoopbackListener::~LoopbackListener()
{
    if (m_socket != INVALID_SOCKET)
        CloseSocket(m_socket);
}

bool HTTPTestServer::Init()
{
    m_endpoint = CService();
    m_fInit = InitHTTPServer();
    if (m_fInit) {
        for (const CService& address : HTTPBoundAddresses()) {
            if (address.IsIPv4() && address.IsLocal())
                m_endpoint = address;
        }
    }
    return m_fInit;
}

bool HTTPTestServer::StartJSONRPC()
{
    m_fRPC = true;
    ::StartRPC();
    return StartHTTPRPC();
}

namespace {
/** Where Start() sends one request per worker thread */
const std::string WORKERS_PATH = "/http_test_util/workers";

/** The worker threads that have taken a request of WORKERS_PATH */
struct WorkerBarrier {
    std::mutex mutex;
    std::condition_variable cond;
    int nArrived = 0;
    int nExpected = 0;
};
} // namespace

bool HTTPTestServer::Start()
{
    // Each worker thread counts itself in the work queue only once it runs, and StopHTTPServer
    // waits only for the counted ones. So Start() returns once every worker thread has taken a
    // request: each handler waits until all have arrived, so no worker takes two.
    auto barrier = std::make_shared<WorkerBarrier>();
    barrier->nExpected = std::max<int64_t>(gArgs.GetArg("-rpcthreads", DEFAULT_HTTP_THREADS), 1);
    RegisterHandler(WORKERS_PATH, true, [barrier](HTTPRequest* req, const std::string&) {
        std::unique_lock<std::mutex> lock(barrier->mutex);
        barrier->nArrived++;
        barrier->cond.notify_all();
        const bool fAll = WaitForHTTPTest(barrier->cond, lock,
                                          [&barrier] { return barrier->nArrived >= barrier->nExpected; });
        lock.unlock();
        req->WriteReply(fAll ? HTTP_OK : HTTP_INTERNAL_SERVER_ERROR);
        return fAll;
    });
    m_fStarted = StartHTTPServer();
    if (!m_fStarted)
        return false;

    std::vector<std::unique_ptr<HTTPTestClient> > clients;
    for (int i = 0; i < barrier->nExpected; i++) {
        clients.emplace_back(new HTTPTestClient(m_endpoint));
        if (!clients.back()->Send(HTTPTestRequestText("GET", WORKERS_PATH)))
            return false;
        // One request at a time waits in the queue, whose depth may be 1
        std::unique_lock<std::mutex> lock(barrier->mutex);
        if (!WaitForHTTPTest(barrier->cond, lock, [&barrier, i] { return barrier->nArrived > i; }))
            return false;
    }
    for (const auto& client : clients) {
        HTTPTestResponse response;
        if (!client->ReadResponse(response) || response.status != HTTP_OK)
            return false;
    }
    return true;
}

void HTTPTestServer::Interrupt()
{
    if (!m_fInit || m_fInterrupted)
        return;
    InterruptHTTPServer();
    if (m_fRPC) {
        InterruptHTTPRPC();
        InterruptRPC();
    }
    m_fInterrupted = true;
}

void HTTPTestServer::Stop()
{
    if (m_fInit) {
        // StopHTTPServer joins the event thread, which StartHTTPServer creates, so a server
        // that was initialised but not started is started before it is stopped
        if (!m_fStarted)
            Start();
        Interrupt();
        if (m_fRPC) {
            StopHTTPRPC();
            // Also clears the RPC timers, which use the event base StopHTTPServer frees
            ::StopRPC();
        }
        StopHTTPServer();
    }
    // StopHTTPServer frees the listening sockets but keeps the list of them, and StopHTTPRPC
    // keeps the "/wallet/" handler
    boundSockets.clear();
    UnregisterHTTPHandler("/wallet/", false);
    for (const auto& handler : m_handlers)
        UnregisterHTTPHandler(handler.first, handler.second);
    m_handlers.clear();
    m_fInit = m_fStarted = m_fRPC = m_fInterrupted = false;
}

void HTTPTestServer::RegisterHandler(const std::string& prefix, bool fExactMatch, const HTTPRequestHandler& handler)
{
    RegisterHTTPHandler(prefix, fExactMatch, handler);
    m_handlers.emplace_back(prefix, fExactMatch);
}

HandlerSteps::~HandlerSteps()
{
    Finish();
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_fServing)
        WaitForHTTPTest(m_cond, lock, [this] { return m_fReturned; });
}

void HandlerSteps::Serve(HTTPRequest* req)
{
    std::unique_lock<std::mutex> lock(m_mutex);
    m_fServing = true;
    m_cond.notify_all();
    while (true) {
        m_cond.wait(lock, [this] { return m_fHaveStep || m_fFinished; });
        if (!m_fHaveStep)
            break;
        const Step step = m_step;
        m_fHaveStep = false;
        lock.unlock();
        const std::string result = step(req);
        lock.lock();
        m_result = result;
        m_fHaveResult = true;
        m_cond.notify_all();
    }
    m_fReturned = true;
    m_cond.notify_all();
}

bool HandlerSteps::WaitServing()
{
    std::unique_lock<std::mutex> lock(m_mutex);
    return WaitForHTTPTest(m_cond, lock, [this] { return m_fServing; });
}

std::string HandlerSteps::Run(const Step& step)
{
    std::unique_lock<std::mutex> lock(m_mutex);
    m_step = step;
    m_fHaveStep = true;
    m_fHaveResult = false;
    m_cond.notify_all();
    if (!WaitForHTTPTest(m_cond, lock, [this] { return m_fHaveResult; }))
        return "<timeout>";
    return m_result;
}

void HandlerSteps::Finish()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_fFinished = true;
    m_cond.notify_all();
}
