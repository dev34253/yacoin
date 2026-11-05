// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "httprpc.h"

#include "crypto/hmac_sha256.h"
#include "httpserver.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "test/http_test_util.h"
#include "test/test_bitcoin.h"
#include "util.h"
#include "utilstrencodings.h"

#include <chrono>
#include <fstream>
#include <future>
#include <memory>
#include <stdexcept>
#include <thread>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

// Defined in httpserver.cpp
extern std::thread threadHTTP;

namespace {

const std::string TEST_USER = "httprpc_user";
const std::string TEST_PASSWORD = "httprpc_password";

/** Test-only commands: a dot never appears in a product command's name, and "help" without
 * arguments leaves out the "hidden" category */
const std::string CMD_URI = "test.httprpc.uri";
const std::string CMD_CONNECTED = "test.httprpc.connected";
const std::string CMD_PRECOMMAND_THROWS = "test.httprpc.precommand_throws";

UniValue test_httprpc_uri(const JSONRPCRequest& request)
{
    return request.URI;
}

UniValue test_httprpc_connected(const JSONRPCRequest& request)
{
    return request.IsClientConnected();
}

const CRPCCommand testCommands[] = {
    {"hidden", CMD_URI, &test_httprpc_uri, true, {}},
    {"hidden", CMD_CONNECTED, &test_httprpc_connected, true, {}},
    {"hidden", CMD_PRECOMMAND_THROWS, &test_httprpc_uri, true, {}},
};

/** The JSON-RPC handler on a loopback HTTP server, started and stopped in the node's order;
 * arguments and log categories are put back after each case */
struct HTTPRPCTestingSetup : public TestingSetup {
    ArgsSnapshot args;
    const uint32_t savedLogCategories;
    HTTPTestServer server;

    HTTPRPCTestingSetup() : savedLogCategories(logCategories)
    {
        // tableRPC.execute answers every call with RPC_IN_WARMUP until the warm-up ends, which
        // happens once per process. No suite depends on the warm-up, so it ends here.
        if (RPCIsInWarmup(nullptr))
            SetRPCWarmupFinished();
        // Commands can only be added while the RPC server is not running
        for (const CRPCCommand& command : testCommands)
            tableRPC.appendCommand(command.name, &command);
        // A pre-command hook that throws reaches the HTTP handler past CRPCTable::execute's
        // conversion of handler exceptions; it is connected once per process
        static bool fHookConnected = false;
        if (!fHookConnected) {
            RPCServer::OnPreCommand([](const CRPCCommand& command) {
                if (command.name == CMD_PRECOMMAND_THROWS)
                    throw std::runtime_error("refused before the command ran");
            });
            fHookConnected = true;
        }
    }
    ~HTTPRPCTestingSetup()
    {
        server.Stop();
        logCategories = savedLogCategories;
    }

    /** Sets the arguments (with -rpcport=0 in front) and starts the HTTP server and the
     * JSON-RPC handler */
    bool StartServer(std::vector<std::string> extraArgs)
    {
        extraArgs.insert(extraArgs.begin(), "-rpcport=0");
        SetHTTPTestArgs(extraArgs);
        return server.Init() && server.StartJSONRPC() && server.Start();
    }

    /** Starts with -rpcuser and -rpcpassword */
    bool StartServer() { return StartServer({"-rpcuser=" + TEST_USER, "-rpcpassword=" + TEST_PASSWORD}); }

    /** POSTs body to uri with the given credentials */
    HTTPTestResponse Post(const std::string& body, const std::string& uri = "/",
                          const std::string& userColonPassword = TEST_USER + ":" + TEST_PASSWORD)
    {
        return HTTPTestRequest(server.Endpoint(), "POST", uri, body, {"Authorization: Basic " + EncodeBase64(userColonPassword)});
    }
};

/** The body of a response, parsed as JSON */
UniValue ParseBody(const HTTPTestResponse& response)
{
    UniValue value;
    BOOST_CHECK_MESSAGE(value.read(response.body), "not JSON: " + response.body);
    return value;
}

/** The checks for an error reply: HTTP status, JSON-RPC code and message, and the request id */
void CheckErrorReply(const HTTPTestResponse& response, int status, int code, const std::string& message,
                     const UniValue& id = NullUniValue)
{
    BOOST_CHECK(response.fComplete);
    BOOST_CHECK_EQUAL(response.status, status);
    BOOST_CHECK_EQUAL(response.Header("Content-Type"), "application/json");
    const UniValue reply = ParseBody(response);
    BOOST_CHECK(find_value(reply, "result").isNull());
    BOOST_CHECK_EQUAL(find_value(find_value(reply, "error"), "code").get_int(), code);
    BOOST_CHECK_EQUAL(find_value(find_value(reply, "error"), "message").get_str(), message);
    BOOST_CHECK_EQUAL(find_value(reply, "id").write(), id.write());
}

/** The checks for a refused login */
void CheckUnauthorized(const HTTPTestResponse& response)
{
    BOOST_CHECK(response.fComplete);
    BOOST_CHECK_EQUAL(response.status, HTTP_UNAUTHORIZED);
    BOOST_CHECK_EQUAL(response.Header("WWW-Authenticate"), "Basic realm=\"jsonrpc\"");
    BOOST_CHECK_EQUAL(response.body, "");
}

/** An -rpcauth value for user and password with the given salt */
std::string RPCAuthValue(const std::string& user, const std::string& salt, const std::string& password)
{
    unsigned char hash[CHMAC_SHA256::OUTPUT_SIZE];
    CHMAC_SHA256(reinterpret_cast<const unsigned char*>(salt.data()), salt.size())
        .Write(reinterpret_cast<const unsigned char*>(password.data()), password.size())
        .Finalize(hash);
    return user + ":" + salt + "$" + HexStr(hash, hash + sizeof(hash));
}

const std::string GETBLOCKCOUNT = "{\"method\":\"getblockcount\",\"params\":[],\"id\":7}";

} // namespace

BOOST_FIXTURE_TEST_SUITE(httprpc_tests, HTTPRPCTestingSetup)

// HTTP methods and authentication

BOOST_AUTO_TEST_CASE(only_post_is_handled)
{
    BOOST_REQUIRE(StartServer());
    for (const std::string method : {"GET", "PUT"}) {
        const HTTPTestResponse response = HTTPTestRequest(server.Endpoint(), method, "/", GETBLOCKCOUNT,
                                                          {"Authorization: Basic " + EncodeBase64(TEST_USER + ":" + TEST_PASSWORD)});
        BOOST_CHECK_EQUAL(response.status, HTTP_BAD_METHOD);
        BOOST_CHECK_EQUAL(response.body, "JSONRPC server handles only POST requests");
    }
}

BOOST_AUTO_TEST_CASE(missing_or_non_basic_authorization_is_refused)
{
    BOOST_REQUIRE(StartServer());
    CheckUnauthorized(HTTPTestRequest(server.Endpoint(), "POST", "/", GETBLOCKCOUNT));
    CheckUnauthorized(HTTPTestRequest(server.Endpoint(), "POST", "/", GETBLOCKCOUNT,
                                      {"Authorization: Bearer " + EncodeBase64(TEST_USER + ":" + TEST_PASSWORD)}));
}

BOOST_AUTO_TEST_CASE(rpcuser_and_rpcpassword)
{
    BOOST_REQUIRE(StartServer());
    HTTPTestResponse response = Post(GETBLOCKCOUNT);
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);

    // Spaces around the encoded credentials are ignored
    response = HTTPTestRequest(server.Endpoint(), "POST", "/", GETBLOCKCOUNT,
                               {"Authorization: Basic   " + EncodeBase64(TEST_USER + ":" + TEST_PASSWORD) + "  "});
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);

    CheckUnauthorized(Post(GETBLOCKCOUNT, "/", TEST_USER + ":wrong"));
    CheckUnauthorized(Post(GETBLOCKCOUNT, "/", "other_user:" + TEST_PASSWORD));
    CheckUnauthorized(Post(GETBLOCKCOUNT, "/", TEST_USER + TEST_PASSWORD));
}

BOOST_AUTO_TEST_CASE(rpcauth)
{
    // A user name with a password, one whose password holds colons, an entry with too few
    // fields before them, and the cookie as the single-user credential
    BOOST_REQUIRE(StartServer({"-rpcauth=alice:salt_without_hash",
                               "-rpcauth=" + RPCAuthValue("alice", "a1b2c3", "alice's password"),
                               "-rpcauth=" + RPCAuthValue("bob", "d4e5f6", "with:two:colons")}));

    BOOST_CHECK_EQUAL(Post(GETBLOCKCOUNT, "/", "alice:alice's password").status, HTTP_OK);
    BOOST_CHECK_EQUAL(Post(GETBLOCKCOUNT, "/", "bob:with:two:colons").status, HTTP_OK);

    CheckUnauthorized(Post(GETBLOCKCOUNT, "/", "alice:with:two:colons"));
    CheckUnauthorized(Post(GETBLOCKCOUNT, "/", "carol:alice's password"));
    CheckUnauthorized(Post(GETBLOCKCOUNT, "/", "alice"));
}

BOOST_AUTO_TEST_CASE(cookie_file_authenticates)
{
    const fs::path cookiePath = GetDataDir() / "httprpc_tests.cookie";
    BOOST_REQUIRE(StartServer({"-rpccookiefile=httprpc_tests.cookie"}));
    BOOST_REQUIRE(fs::exists(cookiePath));
    std::ifstream file(cookiePath.string().c_str());
    std::string cookie;
    std::getline(file, cookie);
    BOOST_CHECK_EQUAL(Post(GETBLOCKCOUNT, "/", cookie).status, HTTP_OK);
    CheckUnauthorized(Post(GETBLOCKCOUNT, "/", TEST_USER + ":" + TEST_PASSWORD));
}

BOOST_AUTO_TEST_CASE(cookie_in_missing_directory_fails_the_start)
{
    const fs::path cookiePath = GetDataDir() / "missing-directory" / "httprpc_tests.cookie";
    SetHTTPTestArgs({"-rpcport=0", "-rpccookiefile=" + cookiePath.string()});
    BOOST_REQUIRE(server.Init());
    BOOST_CHECK(!server.StartJSONRPC());
    BOOST_CHECK(!fs::exists(cookiePath));
}

// Requests and replies

BOOST_AUTO_TEST_CASE(single_request)
{
    BOOST_REQUIRE(StartServer());
    const HTTPTestResponse response = Post(GETBLOCKCOUNT);
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);
    BOOST_CHECK_EQUAL(response.Header("Content-Type"), "application/json");
    const UniValue reply = ParseBody(response);
    BOOST_CHECK_EQUAL(find_value(reply, "result").write(), "0");
    BOOST_CHECK(find_value(reply, "error").isNull());
    BOOST_CHECK_EQUAL(find_value(reply, "id").write(), "7");
    BOOST_CHECK_EQUAL(response.body.back(), '\n');

    // The handler sees the client as connected
    BOOST_CHECK_EQUAL(find_value(ParseBody(Post("{\"method\":\"" + CMD_CONNECTED + "\",\"id\":1}")), "result").write(), "true");
}

BOOST_AUTO_TEST_CASE(parse_errors)
{
    BOOST_REQUIRE(StartServer());
    CheckErrorReply(Post("{\"method\":"), HTTP_INTERNAL_SERVER_ERROR, RPC_PARSE_ERROR, "Parse error");
    CheckErrorReply(Post(""), HTTP_INTERNAL_SERVER_ERROR, RPC_PARSE_ERROR, "Parse error");
    // UniValue::read accepts only an object or an array at the top level
    CheckErrorReply(Post("42"), HTTP_INTERNAL_SERVER_ERROR, RPC_PARSE_ERROR, "Parse error");
    CheckErrorReply(Post("\"getblockcount\""), HTTP_INTERNAL_SERVER_ERROR, RPC_PARSE_ERROR, "Parse error");
}

BOOST_AUTO_TEST_CASE(invalid_request_objects)
{
    BOOST_REQUIRE(StartServer());
    CheckErrorReply(Post("{\"params\":[],\"id\":1}"), HTTP_BAD_REQUEST, RPC_INVALID_REQUEST, "Missing method", 1);
    CheckErrorReply(Post("{\"method\":5,\"id\":\"a\"}"), HTTP_BAD_REQUEST, RPC_INVALID_REQUEST, "Method must be a string", "a");
    CheckErrorReply(Post("{\"method\":\"getblockcount\",\"params\":\"x\",\"id\":2}"), HTTP_BAD_REQUEST, RPC_INVALID_REQUEST,
                    "Params must be an array or object", 2);
}

BOOST_AUTO_TEST_CASE(command_errors)
{
    BOOST_REQUIRE(StartServer());
    CheckErrorReply(Post("{\"method\":\"no_such_command\",\"id\":3}"), HTTP_NOT_FOUND, RPC_METHOD_NOT_FOUND, "Method not found", 3);
    // Any other code gives 500
    CheckErrorReply(Post("{\"method\":\"getblockhash\",\"params\":[99],\"id\":4}"), HTTP_INTERNAL_SERVER_ERROR,
                    RPC_INVALID_PARAMETER, "Block height out of range", 4);
    CheckErrorReply(Post("{\"method\":\"getblockhash\",\"params\":[\"x\"],\"id\":5}"), HTTP_INTERNAL_SERVER_ERROR,
                    RPC_MISC_ERROR, "JSON value is not an integer as expected", 5);
    // An exception that leaves the dispatch is answered as a parse error with its text
    CheckErrorReply(Post("{\"method\":\"" + CMD_PRECOMMAND_THROWS + "\",\"id\":6}"), HTTP_INTERNAL_SERVER_ERROR,
                    RPC_PARSE_ERROR, "refused before the command ran", 6);
}

BOOST_AUTO_TEST_CASE(batches)
{
    BOOST_REQUIRE(StartServer());
    const HTTPTestResponse response = Post("[" + GETBLOCKCOUNT +
                                           ",{\"method\":\"no_such_command\",\"id\":2}"
                                           ",5"
                                           ",{\"method\":\"getblockhash\",\"params\":[99],\"id\":\"x\"}"
                                           ",{\"method\":\"" + CMD_PRECOMMAND_THROWS + "\",\"id\":3}]");
    BOOST_CHECK_EQUAL(response.status, HTTP_OK);
    BOOST_CHECK_EQUAL(response.Header("Content-Type"), "application/json");
    const UniValue replies = ParseBody(response);
    BOOST_REQUIRE(replies.isArray());
    BOOST_REQUIRE_EQUAL(replies.size(), 5U);
    BOOST_CHECK_EQUAL(replies[0].write(), "{\"result\":0,\"error\":null,\"id\":7}");
    BOOST_CHECK_EQUAL(replies[1].write(), "{\"result\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":2}");
    BOOST_CHECK_EQUAL(replies[2].write(), "{\"result\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid Request object\"},\"id\":null}");
    BOOST_CHECK_EQUAL(replies[3].write(), "{\"result\":null,\"error\":{\"code\":-8,\"message\":\"Block height out of range\"},\"id\":\"x\"}");
    BOOST_CHECK_EQUAL(replies[4].write(), "{\"result\":null,\"error\":{\"code\":-32700,\"message\":\"refused before the command ran\"},\"id\":3}");

    const HTTPTestResponse empty = Post("[]");
    BOOST_CHECK_EQUAL(empty.status, HTTP_OK);
    BOOST_CHECK_EQUAL(empty.body, "[]\n");
}

BOOST_AUTO_TEST_CASE(request_uri_reaches_the_command)
{
    BOOST_REQUIRE(StartServer());
    const std::string body = "{\"method\":\"" + CMD_URI + "\",\"id\":1}";
    BOOST_CHECK_EQUAL(find_value(ParseBody(Post(body)), "result").get_str(), "/");
#ifdef ENABLE_WALLET
    BOOST_CHECK_EQUAL(find_value(ParseBody(Post(body, "/wallet/some_wallet")), "result").get_str(), "/wallet/some_wallet");
#else
    BOOST_CHECK_EQUAL(Post(body, "/wallet/some_wallet").status, HTTP_NOT_FOUND);
#endif
    BOOST_CHECK_EQUAL(Post(body, "/other").status, HTTP_NOT_FOUND);
}

// Timers

BOOST_AUTO_TEST_CASE(rpc_timers_run_on_the_event_thread)
{
    BOOST_REQUIRE(StartServer());
    // With the RPC log category, RPCRunLater also logs the timer interface's name
    logCategories |= BCLog::RPC;
    auto ran = std::make_shared<std::promise<std::thread::id> >();
    std::future<std::thread::id> ranOn = ran->get_future();
    RPCRunLater("httprpc_tests", [ran] { ran->set_value(std::this_thread::get_id()); }, 1);
    BOOST_REQUIRE(ranOn.wait_for(std::chrono::milliseconds(HTTP_TEST_TIMEOUT_MS)) == std::future_status::ready);
    BOOST_CHECK(ranOn.get() == threadHTTP.get_id());

    // StopHTTPRPC removes the timer interface
    StopHTTPRPC();
    bool fThrown = false;
    try {
        RPCRunLater("httprpc_tests", [] {}, 1);
    } catch (const UniValue& error) {
        fThrown = true;
        BOOST_CHECK_EQUAL(find_value(error, "code").get_int(), RPC_INTERNAL_ERROR);
        BOOST_CHECK_EQUAL(find_value(error, "message").get_str(), "No timer handler registered for RPC");
    }
    BOOST_CHECK(fThrown);
}

// Stop

BOOST_AUTO_TEST_CASE(stop_unregisters_the_root_handler)
{
    BOOST_REQUIRE(StartServer());
    StopHTTPRPC();
    BOOST_CHECK_EQUAL(Post(GETBLOCKCOUNT).status, HTTP_NOT_FOUND);
#ifdef ENABLE_WALLET
    // "/wallet/" stays registered
    const HTTPTestResponse response = HTTPTestRequest(server.Endpoint(), "GET", "/wallet/some_wallet");
    BOOST_CHECK_EQUAL(response.status, HTTP_BAD_METHOD);
    BOOST_CHECK_EQUAL(response.body, "JSONRPC server handles only POST requests");
#endif
}

BOOST_AUTO_TEST_SUITE_END()
