// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_HTTP_TEST_UTIL_H
#define YACOIN_TEST_HTTP_TEST_UTIL_H

#include "compat.h"
#include "httpserver.h"
#include "netaddress.h"

#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

/** Upper bound for every socket operation and every wait of the HTTP test helpers */
static const int HTTP_TEST_TIMEOUT_MS = 30000;

/** Sets gArgs to exactly the given "-name=value" arguments, as the command line would; -datadir
 * keeps its value. The caller holds an ArgsSnapshot that puts the previous arguments back. */
void SetHTTPTestArgs(const std::vector<std::string>& args);

/** The addresses and ports the HTTP server's listening sockets are bound to */
std::vector<CService> HTTPBoundAddresses();

/** One HTTP response as the client read it */
struct HTTPTestResponse {
    bool fComplete = false; //!< status line, headers and the whole body were read
    int status = 0;
    std::map<std::string, std::string> headers; //!< names in lower case
    std::string body;

    /** The value of a header, or "<absent>" */
    std::string Header(const std::string& name) const;
};

/** The text of an HTTP/1.1 request with a Content-Length header. Without fKeepAlive it asks the
 * server to close the connection after the reply. */
std::string HTTPTestRequestText(const std::string& method, const std::string& uri, const std::string& body = "",
                                const std::vector<std::string>& headers = {}, bool fKeepAlive = false);

/** A blocking HTTP client on one direct TCP connection (no proxy). Every operation gives up
 * after HTTP_TEST_TIMEOUT_MS. */
class HTTPTestClient
{
public:
    explicit HTTPTestClient(const CService& server);
    ~HTTPTestClient();
    HTTPTestClient(const HTTPTestClient&) = delete;
    HTTPTestClient& operator=(const HTTPTestClient&) = delete;

    bool IsConnected() const { return m_socket != INVALID_SOCKET; }
    /** The client's own address and port */
    CService LocalAddress() const;
    /** Sends all of data */
    bool Send(const std::string& data);
    /** Reads the next response; the response to a HEAD request has no body */
    bool ReadResponse(HTTPTestResponse& response, bool fHeadRequest = false);
    /** Shuts down the sending side: the server reads the end of the stream */
    bool ShutdownSend();
    /** Reads until the server closes the connection; true if it did */
    bool WaitForClose();

private:
    enum ReceiveResult {
        RECEIVED, //!< bytes were appended to m_buffer
        CLOSED,   //!< the server closed the connection (end of stream or reset)
        FAILED,   //!< another error, or the deadline passed
    };

    /** Waits until the socket is writable or readable; false on an error or at the deadline */
    bool WaitReady(bool fWrite, int64_t nDeadline);
    /** Appends what the socket has to m_buffer */
    ReceiveResult Receive(int64_t nDeadline);
    /** Reads until something other than bytes comes */
    ReceiveResult WaitForClose(int64_t nDeadline);

    SOCKET m_socket;
    std::string m_buffer;
};

/** Sends one request on a new connection that the server closes after the reply */
HTTPTestResponse HTTPTestRequest(const CService& server, const std::string& method, const std::string& uri,
                                 const std::string& body = "", const std::vector<std::string>& headers = {});

/** A listening TCP socket on 127.0.0.1 with a port the kernel picked, so that port is taken */
class LoopbackListener
{
public:
    LoopbackListener();
    ~LoopbackListener();
    LoopbackListener(const LoopbackListener&) = delete;
    LoopbackListener& operator=(const LoopbackListener&) = delete;

    bool IsListening() const { return m_socket != INVALID_SOCKET; }
    uint16_t Port() const { return m_port; }

private:
    SOCKET m_socket;
    uint16_t m_port;
};

/**
 * The node's HTTP server (and on request its JSON-RPC layer) on loopback, started and stopped in
 * the node's order: InitHTTPServer, StartRPC, StartHTTPRPC, StartHTTPServer; InterruptHTTPServer,
 * InterruptHTTPRPC, InterruptRPC; StopHTTPRPC, StopRPC, StopHTTPServer. Stop() then removes what
 * the server leaves behind for the next one in the process: the list of bound sockets, the
 * "/wallet/" handler and the handlers registered through this object. The destructor stops a
 * server that still runs.
 */
class HTTPTestServer
{
public:
    HTTPTestServer() = default;
    ~HTTPTestServer() { Stop(); }
    HTTPTestServer(const HTTPTestServer&) = delete;
    HTTPTestServer& operator=(const HTTPTestServer&) = delete;

    /** InitHTTPServer with the current arguments; reads the IPv4 loopback endpoint */
    bool Init();
    /** StartRPC and StartHTTPRPC. StopRPC deletes the cookie file (-rpccookiefile, by default in
     * GetDataDir()), so the arguments must name a data directory of the test. */
    bool StartJSONRPC();
    /** StartHTTPServer; returns once every worker thread has handled a request */
    bool Start();
    /** The interrupt steps of the node */
    void Interrupt();
    /** The remaining stop steps of the node, then the clean-up */
    void Stop();

    /** RegisterHTTPHandler; Stop() unregisters it */
    void RegisterHandler(const std::string& prefix, bool fExactMatch, const HTTPRequestHandler& handler);

    /** The 127.0.0.1 endpoint the server listens on (invalid if none) */
    const CService& Endpoint() const { return m_endpoint; }

private:
    bool m_fInit = false;
    bool m_fStarted = false;
    bool m_fRPC = false;
    bool m_fInterrupted = false;
    CService m_endpoint;
    std::vector<std::pair<std::string, bool> > m_handlers;
};

/**
 * Lets a case run steps on the worker thread that handles one request. The request's handler
 * calls Serve(): it signals that it runs, then runs each step the case posts with Run() and
 * hands back its result, until the case calls Finish() or the object is destroyed (which waits
 * for Serve() to return).
 */
class HandlerSteps
{
public:
    typedef std::function<std::string(HTTPRequest*)> Step;

    HandlerSteps() = default;
    ~HandlerSteps();
    HandlerSteps(const HandlerSteps&) = delete;
    HandlerSteps& operator=(const HandlerSteps&) = delete;

    /** Called by the handler on its worker thread */
    void Serve(HTTPRequest* req);
    /** Waits until a handler is in Serve() */
    bool WaitServing();
    /** Runs step on the handler's thread and returns its result ("<timeout>" if none came) */
    std::string Run(const Step& step);
    /** Lets Serve() return */
    void Finish();

private:
    std::mutex m_mutex;
    std::condition_variable m_cond;
    bool m_fServing = false;
    bool m_fFinished = false;
    bool m_fReturned = false;
    bool m_fHaveStep = false;
    Step m_step;
    bool m_fHaveResult = false;
    std::string m_result;
};

#endif // YACOIN_TEST_HTTP_TEST_UTIL_H
