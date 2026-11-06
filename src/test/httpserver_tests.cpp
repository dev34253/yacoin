// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "httpserver.h"

#include "netbase.h"
#include "rpc/protocol.h"
#include "test/http_test_util.h"
#include "test/test_bitcoin.h"
#include "util.h"
#include "utiltime.h"

#include "support/events.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/test/unit_test.hpp>

namespace {

/** The HTTP server on loopback ports the kernel picks; arguments and log categories are put back
 * after each case */
struct HTTPServerTestingSetup : public BasicTestingSetup {
    ArgsSnapshot args;
    const uint32_t savedLogCategories;
    HTTPTestServer server;

    HTTPServerTestingSetup() : savedLogCategories(logCategories) {}
    ~HTTPServerTestingSetup()
    {
        server.Stop();
        logCategories = savedLogCategories;
    }

    /** Sets the arguments (with -rpcport=0 in front) and initialises the server */
    bool InitServer(std::vector<std::string> extraArgs = {})
    {
        extraArgs.insert(extraArgs.begin(), "-rpcport=0");
        SetHTTPTestArgs(extraArgs);
        return server.Init();
    }

    /** Initialises the server, registers the echo handler under "/echo" and starts it */
    bool StartServer(const std::vector<std::string>& extraArgs = {});

    /** Starts the server with the arguments and checks one worker thread and a work queue of depth 1 */
    void CheckOneWorkerAndQueueOfOne(const std::vector<std::string>& extraArgs);
};

std::string MethodName(HTTPRequest::RequestMethod method)
{
    switch (method) {
    case HTTPRequest::GET: return "GET";
    case HTTPRequest::POST: return "POST";
    case HTTPRequest::HEAD: return "HEAD";
    case HTTPRequest::PUT: return "PUT";
    case HTTPRequest::UNKNOWN: return "UNKNOWN";
    }
    return "?";
}

/** Answers with what the request looks like to a handler: the body as the body, the rest in headers */
bool EchoHandler(HTTPRequest* req, const std::string& path)
{
    const std::pair<bool, std::string> testHeader = req->GetHeader("X-Test-In");
    req->WriteHeader("X-Method", MethodName(req->GetRequestMethod()));
    req->WriteHeader("X-Path", "[" + path + "]");
    req->WriteHeader("X-URI", req->GetURI());
    req->WriteHeader("X-Peer", req->GetPeer().ToString());
    req->WriteHeader("X-Test-In", testHeader.first ? "present " + testHeader.second : "absent");
    req->WriteHeader("X-Unsent-Header", req->GetHeader("X-Never-Sent").first ? "present" : "absent");
    req->WriteReply(HTTP_OK, req->ReadBody());
    return true;
}

/** A handler that answers with its tag in the body and the path it got in a header */
HTTPRequestHandler TaggedHandler(const std::string& tag)
{
    return [tag](HTTPRequest* req, const std::string& path) {
        req->WriteHeader("X-Path", "[" + path + "]");
        req->WriteReply(HTTP_OK, tag);
        return true;
    };
}

bool HTTPServerTestingSetup::StartServer(const std::vector<std::string>& extraArgs)
{
    if (!InitServer(extraArgs))
        return false;
    server.RegisterHandler("/echo", false, EchoHandler);
    return server.Start();
}

bool IsLoopback(const CService& address)
{
    return address.ToStringIP() == "127.0.0.1" || address.ToStringIP() == "::1";
}

/** Whether a 127.0.0.1 socket is among the server's listening sockets */
bool HasIPv4Loopback(const std::vector<CService>& addresses)
{
    for (const CService& address : addresses) {
        if (address.ToStringIP() == "127.0.0.1")
            return true;
    }
    return false;
}

/** A step for HandlerSteps: asks IsClientConnected() until it gives expected, for at most
 * HTTP_TEST_TIMEOUT_MS; returns the last answer. Nothing notifies a change of the socket's
 * state, so the step polls the condition, with a bound. */
HandlerSteps::Step ProbeUntil(bool expected)
{
    return [expected](HTTPRequest* req) {
        const int64_t nDeadline = GetTimeMillis() + HTTP_TEST_TIMEOUT_MS;
        bool fConnected = req->IsClientConnected();
        while (fConnected != expected && GetTimeMillis() < nDeadline) {
            // the client's bytes or its end of stream travel through the kernel to this socket
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            fConnected = req->IsClientConnected();
        }
        return std::string(fConnected ? "connected" : "disconnected");
    };
}

/** Starts the server with the arguments and shows that it has one worker thread and a work
 * queue of depth 1: the worker blocks on a first request, and of two more requests one waits
 * in the queue and the other is rejected */
void HTTPServerTestingSetup::CheckOneWorkerAndQueueOfOne(const std::vector<std::string>& extraArgs)
{
    struct BlockState {
        std::promise<void> release;
        std::shared_future<void> released;
        std::promise<void> entered;
        std::atomic<bool> fEntered{false};
    };
    const auto state = std::make_shared<BlockState>();
    state->released = state->release.get_future().share();

    BOOST_REQUIRE(InitServer(extraArgs));
    server.RegisterHandler("/block", true, [state](HTTPRequest* req, const std::string&) {
        if (!state->fEntered.exchange(true))
            state->entered.set_value();
        state->released.wait_for(std::chrono::milliseconds(HTTP_TEST_TIMEOUT_MS));
        req->WriteReply(HTTP_OK, "released");
        return true;
    });
    BOOST_REQUIRE(server.Start());

    // The only worker takes the first request and blocks
    HTTPTestClient first(server.Endpoint());
    BOOST_REQUIRE(first.Send(HTTPTestRequestText("GET", "/block")));
    BOOST_REQUIRE(state->entered.get_future().wait_for(std::chrono::milliseconds(HTTP_TEST_TIMEOUT_MS)) == std::future_status::ready);

    // Of two more requests one fills the queue of depth 1 and the other is rejected; which one
    // depends on the order the event thread reads them
    std::mutex mutex;
    std::condition_variable cond;
    std::vector<HTTPTestResponse> responses;
    auto readOne = [&](HTTPTestClient& client) {
        HTTPTestResponse response;
        client.ReadResponse(response);
        std::lock_guard<std::mutex> lock(mutex);
        responses.push_back(response);
        cond.notify_all();
    };
    HTTPTestClient second(server.Endpoint());
    HTTPTestClient third(server.Endpoint());
    BOOST_CHECK(second.Send(HTTPTestRequestText("GET", "/block")));
    BOOST_CHECK(third.Send(HTTPTestRequestText("GET", "/block")));
    std::thread readSecond(readOne, std::ref(second));
    std::thread readThird(readOne, std::ref(third));
    {
        std::unique_lock<std::mutex> lock(mutex);
        BOOST_CHECK(WaitForHTTPTest(cond, lock, [&] { return !responses.empty(); }));
        BOOST_CHECK_EQUAL(responses.size(), 1U);
        if (!responses.empty()) {
            BOOST_CHECK_EQUAL(responses[0].status, HTTP_INTERNAL_SERVER_ERROR);
            BOOST_CHECK_EQUAL(responses[0].body, "Work queue depth exceeded");
        }
    }

    // Released, the worker answers the first request and then the queued one
    state->release.set_value();
    HTTPTestResponse response;
    BOOST_CHECK(first.ReadResponse(response));
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);
    BOOST_CHECK_EQUAL(response.body, "released");
    readSecond.join();
    readThird.join();
    BOOST_REQUIRE_EQUAL(responses.size(), 2U);
    BOOST_CHECK_EQUAL(responses[1].status, HTTP_OK);
    BOOST_CHECK_EQUAL(responses[1].body, "released");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(httpserver_tests, HTTPServerTestingSetup)

// Life cycle

BOOST_AUTO_TEST_CASE(init_binds_loopback_and_start_answers)
{
    BOOST_REQUIRE(InitServer());
    BOOST_CHECK(EventBase() != nullptr);
    BOOST_CHECK(HasIPv4Loopback(HTTPBoundAddresses()));
    BOOST_REQUIRE(server.Endpoint().IsValid());
    BOOST_CHECK(server.Endpoint().GetPort() != 0);
    server.RegisterHandler("/echo", false, EchoHandler);
    BOOST_REQUIRE(server.Start());

    const HTTPTestResponse response = HTTPTestRequest(server.Endpoint(), "GET", "/echo");
    BOOST_CHECK(response.fComplete);
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);

    server.Stop();
    BOOST_CHECK(EventBase() == nullptr);
}

BOOST_AUTO_TEST_CASE(server_starts_again_after_stop)
{
    for (int nRound = 0; nRound < 2; nRound++) {
        BOOST_REQUIRE(StartServer());
        const HTTPTestResponse response = HTTPTestRequest(server.Endpoint(), "POST", "/echo", "round");
        BOOST_CHECK_EQUAL(response.status, HTTP_OK);
        BOOST_CHECK_EQUAL(response.body, "round");
        server.Stop();
        BOOST_CHECK(EventBase() == nullptr);
    }
}

BOOST_AUTO_TEST_CASE(threads_and_queue_depth_below_one_are_raised_to_one)
{
    CheckOneWorkerAndQueueOfOne({"-rpcthreads=0", "-rpcworkqueue=-3"});
    server.Stop();
    CheckOneWorkerAndQueueOfOne({"-rpcthreads=-2", "-rpcworkqueue=0"});
}

// Bind addresses and the allow list

BOOST_AUTO_TEST_CASE(default_binds_only_loopback)
{
    BOOST_REQUIRE(InitServer());
    const std::vector<CService> addresses = HTTPBoundAddresses();
    BOOST_CHECK(!addresses.empty());
    BOOST_CHECK(addresses.size() <= 2);
    for (const CService& address : addresses)
        BOOST_CHECK_MESSAGE(IsLoopback(address), address.ToString());
    BOOST_CHECK(HasIPv4Loopback(addresses));
}

BOOST_AUTO_TEST_CASE(rpcbind_without_rpcallowip_still_binds_only_loopback)
{
    BOOST_REQUIRE(InitServer({"-rpcbind=192.0.2.1"}));
    const std::vector<CService> addresses = HTTPBoundAddresses();
    BOOST_CHECK(!addresses.empty());
    for (const CService& address : addresses)
        BOOST_CHECK_MESSAGE(IsLoopback(address), address.ToString());
    BOOST_CHECK(HasIPv4Loopback(addresses));
}

BOOST_AUTO_TEST_CASE(rpcbind_with_rpcallowip_binds_the_given_address)
{
    BOOST_REQUIRE(StartServer({"-rpcallowip=127.0.0.1", "-rpcbind=127.0.0.1"}));
    const std::vector<CService> addresses = HTTPBoundAddresses();
    BOOST_REQUIRE_EQUAL(addresses.size(), 1U);
    BOOST_CHECK_EQUAL(addresses[0].ToStringIP(), "127.0.0.1");
    BOOST_CHECK_EQUAL(HTTPTestRequest(server.Endpoint(), "GET", "/echo").status, HTTP_OK);
}

BOOST_AUTO_TEST_CASE(rpcbind_port_in_use_is_skipped)
{
    LoopbackListener taken;
    BOOST_REQUIRE(taken.IsListening());
    const std::string strTaken = strprintf("-rpcbind=127.0.0.1:%u", taken.Port());

    // One of two addresses cannot be bound: the server runs on the other
    BOOST_REQUIRE(StartServer({"-rpcallowip=127.0.0.1", strTaken, "-rpcbind=127.0.0.1"}));
    const std::vector<CService> addresses = HTTPBoundAddresses();
    BOOST_REQUIRE_EQUAL(addresses.size(), 1U);
    BOOST_CHECK(addresses[0].GetPort() != taken.Port());
    BOOST_CHECK_EQUAL(HTTPTestRequest(server.Endpoint(), "GET", "/echo").status, HTTP_OK);
    server.Stop();

    // No address can be bound: InitHTTPServer fails
    BOOST_CHECK(!InitServer({"-rpcallowip=127.0.0.1", strTaken}));
    BOOST_CHECK(HTTPBoundAddresses().empty());
    BOOST_CHECK(EventBase() == nullptr);
}

BOOST_AUTO_TEST_CASE(rpcallowip_forms)
{
    // A single IP, a network with a netmask and a network with a CIDR prefix length
    BOOST_CHECK(StartServer({"-rpcallowip=10.1.2.3", "-rpcallowip=10.0.0.0/255.0.0.0", "-rpcallowip=10.0.0.0/8",
                             "-rpcallowip=fd00::/8", "-rpcbind=127.0.0.1"}));
    BOOST_CHECK_EQUAL(HTTPTestRequest(server.Endpoint(), "GET", "/echo").status, HTTP_OK);
    server.Stop();

    BOOST_CHECK(!InitServer({"-rpcallowip=10.0.0.0/33", "-rpcbind=127.0.0.1"}));
    BOOST_CHECK(!InitServer({"-rpcallowip=not-an-address", "-rpcbind=127.0.0.1"}));
    BOOST_CHECK(EventBase() == nullptr);
    BOOST_CHECK(HTTPBoundAddresses().empty());
}

// Dispatch

BOOST_AUTO_TEST_CASE(no_handler_gives_404)
{
    BOOST_REQUIRE(StartServer());
    const HTTPTestResponse response = HTTPTestRequest(server.Endpoint(), "GET", "/no-handler-here");
    BOOST_CHECK(response.fComplete);
    BOOST_CHECK_EQUAL(response.status, HTTP_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(exact_and_prefix_handlers)
{
    BOOST_REQUIRE(InitServer());
    server.RegisterHandler("/exact", true, TaggedHandler("exact"));
    server.RegisterHandler("/prefix/", false, TaggedHandler("prefix"));
    BOOST_REQUIRE(server.Start());
    const CService& endpoint = server.Endpoint();

    HTTPTestResponse response = HTTPTestRequest(endpoint, "GET", "/exact");
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);
    BOOST_CHECK_EQUAL(response.body, "exact");
    BOOST_CHECK_EQUAL(response.Header("X-Path"), "[]");

    // An exact handler matches nothing longer, not even a query string
    BOOST_CHECK_EQUAL(HTTPTestRequest(endpoint, "GET", "/exact/more").status, HTTP_NOT_FOUND);
    BOOST_CHECK_EQUAL(HTTPTestRequest(endpoint, "GET", "/exact?x=1").status, HTTP_NOT_FOUND);
    BOOST_CHECK_EQUAL(HTTPTestRequest(endpoint, "GET", "/exac").status, HTTP_NOT_FOUND);

    // A prefix handler gets the rest of the URI as its path
    response = HTTPTestRequest(endpoint, "GET", "/prefix/a/b?c=d");
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);
    BOOST_CHECK_EQUAL(response.body, "prefix");
    BOOST_CHECK_EQUAL(response.Header("X-Path"), "[a/b?c=d]");
    response = HTTPTestRequest(endpoint, "GET", "/prefix/");
    BOOST_CHECK_EQUAL(response.body, "prefix");
    BOOST_CHECK_EQUAL(response.Header("X-Path"), "[]");
    BOOST_CHECK_EQUAL(HTTPTestRequest(endpoint, "GET", "/prefix").status, HTTP_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(first_registered_handler_wins_and_unregister)
{
    BOOST_REQUIRE(InitServer());
    server.RegisterHandler("/order/", false, TaggedHandler("first"));
    server.RegisterHandler("/order/sub", false, TaggedHandler("second"));
    BOOST_REQUIRE(server.Start());
    const CService& endpoint = server.Endpoint();

    HTTPTestResponse response = HTTPTestRequest(endpoint, "GET", "/order/sub");
    BOOST_CHECK_EQUAL(response.body, "first");
    BOOST_CHECK_EQUAL(response.Header("X-Path"), "[sub]");

    // Unregistering needs the prefix and the match kind of a registered handler
    UnregisterHTTPHandler("/order/never-registered", false);
    UnregisterHTTPHandler("/order/", true);
    BOOST_CHECK_EQUAL(HTTPTestRequest(endpoint, "GET", "/order/sub").body, "first");

    UnregisterHTTPHandler("/order/", false);
    response = HTTPTestRequest(endpoint, "GET", "/order/sub");
    BOOST_CHECK_EQUAL(response.body, "second");
    BOOST_CHECK_EQUAL(response.Header("X-Path"), "[]");
    BOOST_CHECK_EQUAL(HTTPTestRequest(endpoint, "GET", "/order/other").status, HTTP_NOT_FOUND);

    UnregisterHTTPHandler("/order/sub", false);
    BOOST_CHECK_EQUAL(HTTPTestRequest(endpoint, "GET", "/order/sub").status, HTTP_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(request_methods)
{
    BOOST_REQUIRE(StartServer());
    const CService& endpoint = server.Endpoint();

    // Run once without and once with the HTTP log category, whose messages name the method
    for (const bool fLogHTTP : {false, true}) {
        if (fLogHTTP)
            logCategories |= BCLog::HTTP;
        for (const std::string method : {"GET", "POST", "PUT", "HEAD"}) {
            const HTTPTestResponse response = HTTPTestRequest(endpoint, method, "/echo");
            BOOST_CHECK_MESSAGE(response.fComplete, method);
            BOOST_CHECK_EQUAL(response.status, HTTP_OK);
            BOOST_CHECK_EQUAL(response.Header("X-Method"), method);
        }
        // libevent knows DELETE, the server takes only the four methods above
        const HTTPTestResponse response = HTTPTestRequest(endpoint, "DELETE", "/echo");
        BOOST_CHECK(response.fComplete);
        BOOST_CHECK_EQUAL(response.status, HTTP_BAD_METHOD);
        BOOST_CHECK_EQUAL(response.Header("X-Method"), "<absent>");
    }
}

// The request object

BOOST_AUTO_TEST_CASE(request_headers_body_uri_and_peer)
{
    BOOST_REQUIRE(StartServer());
    HTTPTestClient client(server.Endpoint());
    BOOST_REQUIRE(client.IsConnected());
    BOOST_REQUIRE(client.Send(HTTPTestRequestText("POST", "/echo/x%20y?q=1", "request body", {"X-Test-In: some value"})));
    HTTPTestResponse response;
    BOOST_REQUIRE(client.ReadResponse(response));
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);
    BOOST_CHECK_EQUAL(response.body, "request body");
    BOOST_CHECK_EQUAL(response.Header("X-Test-In"), "present some value");
    BOOST_CHECK_EQUAL(response.Header("X-Unsent-Header"), "absent");
    BOOST_CHECK_EQUAL(response.Header("X-URI"), "/echo/x%20y?q=1");
    BOOST_CHECK_EQUAL(response.Header("X-Path"), "[/x%20y?q=1]");
    BOOST_CHECK_EQUAL(response.Header("X-Peer"), client.LocalAddress().ToString());
    BOOST_CHECK_EQUAL(response.Header("X-Peer").compare(0, 10, "127.0.0.1:"), 0);

    // Without a body, and without the header
    response = HTTPTestRequest(server.Endpoint(), "POST", "/echo");
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);
    BOOST_CHECK_EQUAL(response.body, "");
    BOOST_CHECK_EQUAL(response.Header("X-Test-In"), "absent");
}

BOOST_AUTO_TEST_CASE(reply_status_and_body_reach_the_client)
{
    BOOST_REQUIRE(InitServer());
    server.RegisterHandler("/teapot", true, [](HTTPRequest* req, const std::string&) {
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(418, "short and stout");
        return true;
    });
    BOOST_REQUIRE(server.Start());
    const HTTPTestResponse response = HTTPTestRequest(server.Endpoint(), "GET", "/teapot");
    BOOST_CHECK_EQUAL(response.status, 418);
    BOOST_CHECK_EQUAL(response.body, "short and stout");
    BOOST_CHECK_EQUAL(response.Header("Content-Type"), "text/plain");
}

BOOST_AUTO_TEST_CASE(handler_without_reply_gives_500)
{
    BOOST_REQUIRE(InitServer());
    server.RegisterHandler("/silent", true, [](HTTPRequest*, const std::string&) { return false; });
    BOOST_REQUIRE(server.Start());
    const HTTPTestResponse response = HTTPTestRequest(server.Endpoint(), "GET", "/silent");
    BOOST_CHECK_EQUAL(response.status, HTTP_INTERNAL_SERVER_ERROR);
    BOOST_CHECK_EQUAL(response.body, "Unhandled request");
}

BOOST_AUTO_TEST_CASE(is_client_connected)
{
    HandlerSteps steps;
    BOOST_REQUIRE(InitServer());
    server.RegisterHandler("/wait", true, [&steps](HTTPRequest* req, const std::string&) {
        steps.Serve(req);
        return true;
    });
    BOOST_REQUIRE(server.Start());

    HTTPTestClient client(server.Endpoint());
    BOOST_REQUIRE(client.Send(HTTPTestRequestText("POST", "/wait", "{}")));
    BOOST_REQUIRE(steps.WaitServing());

    // The client waits for the answer
    BOOST_CHECK_EQUAL(steps.Run(ProbeUntil(true)), "connected");

    // A further byte from the client waits unread on the socket
    BOOST_REQUIRE(client.Send("X"));
    BOOST_CHECK_EQUAL(steps.Run(ProbeUntil(true)), "connected");

    // The handler returns without a reply
    steps.Finish();
    HTTPTestResponse response;
    BOOST_REQUIRE(client.ReadResponse(response));
    BOOST_CHECK_EQUAL(response.status, HTTP_INTERNAL_SERVER_ERROR);
}

BOOST_AUTO_TEST_CASE(is_client_connected_after_shutdown_and_after_reply)
{
    HandlerSteps steps;
    BOOST_REQUIRE(InitServer());
    server.RegisterHandler("/wait", true, [&steps](HTTPRequest* req, const std::string&) {
        steps.Serve(req);
        return true;
    });
    BOOST_REQUIRE(server.Start());

    HTTPTestClient client(server.Endpoint());
    BOOST_REQUIRE(client.Send(HTTPTestRequestText("POST", "/wait", "{}")));
    BOOST_REQUIRE(steps.WaitServing());
    BOOST_CHECK_EQUAL(steps.Run(ProbeUntil(true)), "connected");

    // The client shuts down its sending side
    BOOST_REQUIRE(client.ShutdownSend());
    BOOST_CHECK_EQUAL(steps.Run(ProbeUntil(false)), "disconnected");

    // Once the handler has replied, the request no longer counts as connected
    BOOST_CHECK_EQUAL(steps.Run([](HTTPRequest* req) {
        req->WriteReply(HTTP_OK, "late answer");
        return std::string(req->IsClientConnected() ? "connected" : "disconnected");
    }), "disconnected");
    steps.Finish();

    // The server closes the connection
    BOOST_CHECK(client.WaitForClose());
}

// The work queue

BOOST_AUTO_TEST_CASE(full_work_queue_rejects_with_500)
{
    CheckOneWorkerAndQueueOfOne({"-rpcthreads=1", "-rpcworkqueue=1"});
}

// Shutdown

BOOST_AUTO_TEST_CASE(interrupt_rejects_requests_and_stop_closes_connections)
{
    BOOST_REQUIRE(StartServer());
    const CService endpoint = server.Endpoint();

    // Two connections the server keeps open after their first request
    HTTPTestClient first(endpoint);
    HTTPTestClient second(endpoint);
    HTTPTestResponse response;
    for (HTTPTestClient* client : {&first, &second}) {
        BOOST_REQUIRE(client->Send(HTTPTestRequestText("GET", "/echo", "", {}, true)));
        BOOST_REQUIRE(client->ReadResponse(response));
        BOOST_CHECK_EQUAL(response.status, HTTP_OK);
        BOOST_CHECK_EQUAL(response.Header("Connection"), "<absent>");
    }

    server.Interrupt();

    // A request on an open connection is refused with 503
    BOOST_REQUIRE(first.Send(HTTPTestRequestText("GET", "/echo", "", {}, true)));
    BOOST_REQUIRE(first.ReadResponse(response));
    BOOST_CHECK_EQUAL(response.status, HTTP_SERVICE_UNAVAILABLE);

    // Nothing listens any more
    HTTPTestClient late(endpoint);
    BOOST_CHECK(!late.IsConnected());

    // The second connection keeps the event loop running: StopHTTPServer breaks it and closes
    // the connection
    server.Stop();
    BOOST_CHECK(EventBase() == nullptr);
    BOOST_CHECK(second.WaitForClose());
}

// HTTPEvent

BOOST_AUTO_TEST_CASE(http_event_on_own_event_base)
{
    raii_event_base base = obtain_event_base();
    std::thread::id runThread;
    int nRuns = 0;
    auto handler = [&] {
        nRuns++;
        runThread = std::this_thread::get_id();
    };

    // Kept after it ran: triggered at once and later again after a delay
    HTTPEvent* kept = new HTTPEvent(base.get(), false, handler);
    kept->trigger(nullptr);
    BOOST_CHECK_EQUAL(nRuns, 0);
    BOOST_CHECK_EQUAL(event_base_loop(base.get(), EVLOOP_ONCE), 0);
    BOOST_CHECK_EQUAL(nRuns, 1);
    BOOST_CHECK(runThread == std::this_thread::get_id());
    struct timeval delay = {1, 0};
    kept->trigger(&delay);
    // Not before the delay has passed
    BOOST_CHECK_EQUAL(event_base_loop(base.get(), EVLOOP_NONBLOCK), 0);
    BOOST_CHECK_EQUAL(nRuns, 1);
    BOOST_CHECK_EQUAL(event_base_loop(base.get(), EVLOOP_ONCE), 0);
    BOOST_CHECK_EQUAL(nRuns, 2);
    delete kept;

    // Deletes itself when it has run: the handler's captures are freed with it
    std::shared_ptr<int> token = std::make_shared<int>(0);
    const std::weak_ptr<int> watch = token;
    HTTPEvent* once = new HTTPEvent(base.get(), true, [token, &nRuns] { nRuns++; });
    token.reset();
    once->trigger(nullptr);
    BOOST_CHECK(!watch.expired());
    BOOST_CHECK_EQUAL(event_base_loop(base.get(), EVLOOP_ONCE), 0);
    BOOST_CHECK_EQUAL(nRuns, 3);
    BOOST_CHECK(watch.expired());
}

// libevent's logging

BOOST_AUTO_TEST_CASE(libevent_logging)
{
    BOOST_CHECK(UpdateHTTPServerLogging(true));
    BOOST_CHECK(UpdateHTTPServerLogging(false));

    // With libevent 2.1 the server keeps the LIBEVENT category
    logCategories |= BCLog::LIBEVENT;
    BOOST_REQUIRE(StartServer());
    BOOST_CHECK(logCategories & BCLog::LIBEVENT);
    BOOST_CHECK_EQUAL(HTTPTestRequest(server.Endpoint(), "GET", "/echo").status, HTTP_OK);
    server.Stop();
    BOOST_CHECK(UpdateHTTPServerLogging(false));
}

// urlDecode

BOOST_AUTO_TEST_CASE(url_decode)
{
    BOOST_CHECK_EQUAL(urlDecode(""), "");
    BOOST_CHECK_EQUAL(urlDecode("plain-text_1.2~"), "plain-text_1.2~");
    BOOST_CHECK_EQUAL(urlDecode("a%20b%2Fc%3d"), "a b/c=");
    BOOST_CHECK_EQUAL(urlDecode("a+b"), "a+b");
    BOOST_CHECK_EQUAL(urlDecode("%zz%4"), "%zz%4");
    BOOST_CHECK_EQUAL(urlDecode("%41%42"), "AB");
}

BOOST_AUTO_TEST_SUITE_END()
