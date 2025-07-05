// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"

#include <set>
#include <stdint.h>

#include <univalue.h>

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
};

/**
 * Specify a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] =
{
    // tokens
    { "issue", 1, "qty" },
    { "issue", 2, "units" },
    { "issue", 3, "reissuable" },
    { "issue", 4, "has_ipfs" },
    { "transfer", 1, "qty"},
    { "transferfromaddress", 2, "qty"},
    { "reissue", 1, "qty"},
    { "reissue", 2, "reissuable"},
    { "reissue", 5, "new_unit"},
    { "listmytokens", 1, "verbose" },
    { "listmytokens", 2, "count" },
    { "listmytokens", 3, "start"},
    { "listmytokens", 4, "confs"},
    { "listtokens", 1, "verbose" },
    { "listtokens", 2, "count" },
    { "listtokens", 3, "start" },
    { "listaddressesbytoken", 1, "onlytotal"},
    { "listaddressesbytoken", 2, "count"},
    { "listaddressesbytoken", 3, "start"},
    { "listtokenbalancesbyaddress", 1, "onlytotal"},
    { "listtokenbalancesbyaddress", 2, "count"},
    { "listtokenbalancesbyaddress", 3, "start"},

    // mining
    { "generate", 0, "nblocks" },
    { "generate", 1, "maxtries" },
    { "setgenerate", 0, "generate" },
    { "setgenerate", 1, "genproclimit" },
    { "generatetoaddress", 0, "nblocks" },
    { "generatetoaddress", 2, "maxtries" },
    { "getsubsidy", 0, "ntarget" },
    { "getblocktemplate", 0, "template_request" },

    // misc
    { "setmocktime", 0, "timestamp" },
    { "getaddressbalance", 0, "addresses"},
    { "getaddressbalance", 1, "includeTokens"},
    { "getaddressdeltas", 0, "addresses"},
    { "getaddressutxos", 0, "addresses"},
    { "getaddresstxids", 0, "addresses"},
    { "getaddresstxids", 1, "includeTokens"},
    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    // Echo with conversion (For testing only)
    { "echojson", 0, "arg0" },
    { "echojson", 1, "arg1" },
    { "echojson", 2, "arg2" },
    { "echojson", 3, "arg3" },
    { "echojson", 4, "arg4" },
    { "echojson", 5, "arg5" },
    { "echojson", 6, "arg6" },
    { "echojson", 7, "arg7" },
    { "echojson", 8, "arg8" },
    { "echojson", 9, "arg9" },
    { "stop", 0, "wait"},

    // blockchain
    { "getblockhash", 0, "height" },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitforblock", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "getblock", 1, "verbosity" },
    { "getblock", 1, "verbose" },
    { "getblockbynumber", 0, "number" },
    { "getblockbynumber", 1, "verbose" },
    { "getblockheader", 1, "verbose" },
    { "getchaintxstats", 0, "nblocks" },
    { "gettransaction", 1, "include_watchonly" },
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "getrawmempool", 0, "verbose" },
    { "getmempoolancestors", 1, "verbose" },
    { "getmempooldescendants", 1, "verbose" },

    // wallet
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 2, "useexpiredtimelockutxo" },
    { "sendtoaddress", 5, "subtractfeefromamount" },
    { "settxfee", 0, "amount" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbyaccount", 1, "minconf" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbyaccount", 0, "minconf" },
    { "listreceivedbyaccount", 1, "include_empty" },
    { "listreceivedbyaccount", 2, "include_watchonly" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getavailablebalance", 1, "minconf" },
    { "getavailablebalance", 2, "include_watchonly" },
    { "move", 2, "amount" },
    { "move", 3, "minconf" },
    { "sendfrom", 2, "amount" },
    { "sendfrom", 3, "useexpiredtimelockutxo" },
    { "sendfrom", 4, "minconf" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "listaccounts", 0, "minconf" },
    { "listaccounts", 1, "include_watchonly" },
    { "walletpassphrase", 1, "timeout" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listsinceblock", 3, "include_removed" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "useExpiredTimelockUTXO" },
    { "sendmany", 3, "minconf" },
    { "sendmany", 5, "subtractfeefrom" },
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    { "spendcltv", 2, "amount" },
    { "spendcsv", 2, "amount" },
    { "createcltvaddress", 0, "locktime" },
    { "createcsvaddress", 0, "locktime" },
    { "createcsvaddress", 1, "isblockheightlock" },
    { "timelockcoins", 0, "amount" },
    { "timelockcoins", 1, "locktime" },
    { "timelockcoins", 2, "isrealtivetimelock" },
    { "timelockcoins", 3, "isblockheightlock" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "include_unsafe" },
    { "listunspent", 4, "query_options" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "keypoolrefill", 0, "newsize" },

    // dump
    { "importprivkey", 2, "rescan" },
    { "importaddress", 2, "rescan" },
    { "importaddress", 3, "p2sh" },
    { "importpubkey", 2, "rescan" },

    // rawtransaction
    { "getrawtransaction", 1, "verbose" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "signrawtransaction", 1, "prevtxs" },
    { "signrawtransaction", 2, "privkeys" },

    // network
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setnetworkactive", 0, "state" },
    { "disconnectnode", 1, "nodeid" },
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int>> members;
    std::set<std::pair<std::string, std::string>> membersByName;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
    bool convert(const std::string& method, const std::string& name) {
        return (membersByName.count(std::make_pair(method, name)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
        membersByName.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                            vRPCConvertParams[i].paramName));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw std::runtime_error(std::string("Error parsing JSON:")+strVal);
    return jVal[0];
}

UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);

    for (const std::string &s: strParams) {
        size_t pos = s.find("=");
        if (pos == std::string::npos) {
            throw(std::runtime_error("No '=' in named argument '"+s+"', this needs to be present for every argument (even if it is empty)"));
        }

        std::string name = s.substr(0, pos);
        std::string value = s.substr(pos+1);

        if (!rpcCvtTable.convert(strMethod, name)) {
            // insert string value directly
            params.pushKV(name, value);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.pushKV(name, ParseNonRFCJSONValue(value));
        }
    }

    return params;
}
