// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_RPC_TEST_UTIL_H
#define YACOIN_TEST_RPC_TEST_UTIL_H

#include "net.h"
#include "rpc/server.h"
#include "test/test_bitcoin.h"

#include <stdexcept>
#include <string>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

/** Calls the handler of method in tableRPC with params (a JSON array) as the HTTP layer would */
inline UniValue CallRPCHandler(const std::string& method, const UniValue& params = UniValue(UniValue::VARR), bool fHelp = false)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = params;
    request.fHelp = fHelp;
    const CRPCCommand* command = tableRPC[method];
    BOOST_REQUIRE_MESSAGE(command, "no RPC command " + method);
    return command->actor(request);
}

/** How a call failed: an RPC error (code and message) or another exception (help texts and
 * parameter type errors are std::runtime_error) */
struct RPCFailure {
    bool fThrown = false;
    bool fRPCError = false;
    int code = 0;
    std::string message;
};

inline RPCFailure CallRPCFailure(const std::string& method, const UniValue& params = UniValue(UniValue::VARR), bool fHelp = false)
{
    RPCFailure failure;
    try {
        CallRPCHandler(method, params, fHelp);
    } catch (const UniValue& objError) {
        failure.fThrown = true;
        failure.fRPCError = true;
        failure.code = find_value(objError, "code").get_int();
        failure.message = find_value(objError, "message").get_str();
    } catch (const std::exception& e) {
        failure.fThrown = true;
        failure.message = e.what();
    }
    return failure;
}

/** The call throws an RPC error with code and message */
inline void CheckRPCError(const std::string& method, const UniValue& params, int code, const std::string& message)
{
    const RPCFailure failure = CallRPCFailure(method, params);
    BOOST_CHECK_MESSAGE(failure.fRPCError, method + ": no RPC error, got \"" + failure.message + "\"");
    BOOST_CHECK_EQUAL(failure.code, code);
    BOOST_CHECK_EQUAL(failure.message, message);
}

/** The call throws its help text, which starts with the method's name */
inline void CheckRPCHelp(const std::string& method, const UniValue& params, bool fHelp)
{
    const RPCFailure failure = CallRPCFailure(method, params, fHelp);
    BOOST_CHECK_MESSAGE(failure.fThrown && !failure.fRPCError, method + ": no help text");
    BOOST_CHECK_MESSAGE(failure.message.compare(0, method.size() + 1, method + " ") == 0 ||
                            failure.message.compare(0, method.size() + 1, method + "\n") == 0,
                        method + ": help starts with \"" + failure.message.substr(0, 40) + "\"");
}

/** A JSON array of the given values */
template <typename... Args>
UniValue RPCParams(const Args&... args)
{
    UniValue params(UniValue::VARR);
    for (const UniValue& value : {UniValue(args)...})
        params.push_back(value);
    return params;
}

/** One peer in g_connman's node list while it lives */
class ScopedPeer
{
public:
    ScopedPeer()
        : m_node(1000, NODE_NETWORK, 0, INVALID_SOCKET, CAddress(CService(CNetAddr(), 0), NODE_NONE), 0, 0, CAddress(), "", false)
    {
        CConnmanTest::AddNode(m_node);
    }
    ~ScopedPeer() { CConnmanTest::ClearNodes(); }
    ScopedPeer(const ScopedPeer&) = delete;
    ScopedPeer& operator=(const ScopedPeer&) = delete;

private:
    CNode m_node;
};

#endif // YACOIN_TEST_RPC_TEST_UTIL_H
