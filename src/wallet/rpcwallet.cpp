// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "consensus/validation.h"
//#include "core_io.h"
#include "init.h"
//#include "httpserver.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/fees.h"
#include "policy/policy.h"
//#include "policy/rbf.h"
//#include "rpc/mining.h"
//#include "rpc/server.h"
#include "script/sign.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet/coincontrol.h"
//#include "wallet/feebumper.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <stdint.h>

//#include <univalue.h>

// TACA: OLD LOGIC BEGIN
#include "bitcoinrpc.h"
#include "streams.h"
#include "script/standard.h"
#include "warnings.h"

#include <sstream>

using namespace json_spirit;

using std::runtime_error;
using std::string;
using std::map;
using std::list;
using std::vector;
using std::set;
using std::pair;
using std::max;
using std::min;

int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;
static const ::int64_t MIN_TXOUT_AMOUNT = CENT/100;
extern ::int64_t nUpTimeStart;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);
// TACA: OLD LOGIC END

CWallet *GetWalletForJSONRPCRequest()
{
    // TODO: Some way to access secondary wallets
    return vpwallets.empty() ? nullptr : vpwallets[0];
}

std::string HelpRequiringPassphrase(CWallet * const pwallet)
{
    return pwallet && pwallet->IsCrypted()
        ? "\nRequires wallet passphrase to be set with walletpassphrase call."
        : "";
}

bool EnsureWalletIsAvailable(CWallet * const pwallet, bool avoidException)
{
    if (pwallet) return true;
    if (avoidException) return false;
    if (::vpwallets.empty()) {
        // Note: It isn't currently possible to trigger this error because
        // wallet RPC methods aren't registered unless a wallet is loaded. But
        // this error is being kept as a precaution, because it's possible in
        // the future that wallet RPC methods might get or remain registered
        // when no wallets are loaded.
        throw JSONRPCError(
            RPC_METHOD_NOT_FOUND, "Method not found (wallet method is disabled because no wallet is loaded)");
    }
    throw JSONRPCError(RPC_WALLET_NOT_SPECIFIED,
        "Wallet file not specified (must request wallet RPC through /wallet/<filename> uri-path).");
}

void EnsureWalletIsUnlocked(CWallet * const pwallet)
{
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

void WalletTxToJSON(const CWalletTx& wtx, Object& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms));
    if (wtx.IsCoinBase() || wtx.IsCoinStake())
        entry.push_back(Pair("generated", true));
    if (confirms > 0)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime()));
    } else {
        entry.push_back(Pair("trusted", wtx.IsTrusted()));
    }

    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));
    for (const std::pair<std::string, std::string>& item : wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

void LockTimeRedeemScriptToJSON(const CScript& redeemScript, txnouttype type, Object& out)
{
    std::vector<CTxDestination> addresses;
    uint32_t nLockTime = 0;
    std::string addressType = "";
    std::string lockCondition = "";
    bool isTimeBasedLock = false;
    std::string redeemScriptFormat = redeemScript.ToString();

    out.push_back(Pair("RedeemScriptHex", HexStr(redeemScript.begin(), redeemScript.end())));
    out.push_back(Pair("RedeemScriptFormat", redeemScriptFormat));

    // Get locktime and public key
    std::string delimiter = " ";
    std::string data;
    size_t pos = 0;
    bool firstPos = true;
    while ((pos = redeemScriptFormat.find(delimiter)) != std::string::npos)
    {
        data = redeemScriptFormat.substr(0, pos);
        if (firstPos)
        {
            nLockTime = atoi(data.c_str());
            firstPos = false;
        }
        redeemScriptFormat.erase(0, pos + delimiter.length());
    }
    out.push_back(Pair("PublicKey", data));

    // Convert to address
    CScriptID redeemScriptID(redeemScript);
    if (type == TX_CLTV_P2SH)
    {
        addressType += "CltvAddress";
        if (nLockTime < LOCKTIME_THRESHOLD)
        {
            std::stringstream ss;
            ss << nLockTime;
            lockCondition += "locked until block height " + ss.str();
            isTimeBasedLock = false;
        }
        else
        {
            lockCondition += "locked until " + DateTimeStrFormat(nLockTime);
            isTimeBasedLock = true;
        }
    }
    else // TX_CSV_P2SH
    {
        addressType += "CsvAddress";
        if (nLockTime & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            std::stringstream ss;
            ss << ((nLockTime & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY);
            lockCondition += "locked for a period of " + ss.str() + " seconds";
            isTimeBasedLock = true;
        }
        else
        {
            std::stringstream ss;
            ss << nLockTime;
            lockCondition += "locked within " + ss.str() + " blocks";
            isTimeBasedLock = false;
        }
    }
    out.push_back(Pair("LockType", isTimeBasedLock ? "Time-based lock" : "Block-based lock"));
    out.push_back(Pair(addressType, CBitcoinAddress(redeemScriptID).ToString()));
    out.push_back(Pair("Description", "This is a redeemscript of " + addressType + "."
                                    + " Any coins sent to this " + addressType + " will be " + lockCondition + "."
                                    + " After the lock time, if anyone has a signature signed by private key matching"
                                      " with public key then they can spend coins from this address"));
}

string AccountFromValue(const Value& value)
{
    std::string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

static void ConvertUpTimeToNiceString(::int64_t nUpTimeSeconds,
                                      string& sUpTime)
{
  ::int64_t nUpCopy = nUpTimeSeconds;

  if (nUpTimeSeconds >= nSecondsPerDay) {
    int nDaysUp = nUpTimeSeconds / nSecondsPerDay;
    nUpTimeSeconds -= (nDaysUp * nSecondsPerDay);
    sUpTime += strprintf("%d day%s ", nDaysUp, 1 == nDaysUp ? "" : "s");
  }

  if (nUpTimeSeconds >= nSecondsPerHour)  // & less than 1 day
  {
    sUpTime += strprintf(
        "%s (%" PRId64 " sec)",
        DateTimeStrFormat("%H hrs %M mins %S sec", nUpTimeSeconds).c_str(),
        nUpCopy);
  }
  else if (nUpTimeSeconds >= nSecondsperMinute)  // & less than 1 hour
  {
    sUpTime += strprintf(
        "%s (%" PRId64 " sec)",
        DateTimeStrFormat("%M mins %S sec", nUpTimeSeconds).c_str(), nUpCopy);
  }
  else  // < one minute
  {
    sUpTime = strprintf("%" PRId64 " sec", nUpCopy);
  }
}

Value getinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    CWallet * const pwallet = GetWalletForJSONRPCRequest();
    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    Object obj, diff;
    obj.push_back(Pair("version",       FormatFullVersion()));
    obj.push_back(Pair("protocolversion",(int)PROTOCOL_VERSION));
    obj.push_back(Pair("walletversion", pwallet->GetVersion()));
    obj.push_back(Pair("balance",       ValueFromAmount(pwallet->GetBalance())));
    obj.push_back(Pair("unspendable",   ValueFromAmount(pwallet->GetWatchOnlyBalance())));
    obj.push_back(Pair("stake",         ValueFromAmount(pwallet->GetStake())));
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("timeoffset",    (boost::int64_t)GetTimeOffset()));

    ::int64_t nUpTimeSeconds = GetTime() - nUpTimeStart;
    string sUpTime = "";
    ConvertUpTimeToNiceString( nUpTimeSeconds, sUpTime );

    obj.push_back(Pair("up-time",       sUpTime));

    obj.push_back(Pair("moneysupply",   ValueFromAmount(chainActive.Tip()->nMoneySupply)));
    if(g_connman)
        obj.push_back(Pair("connections",   (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL)));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string())));
    for (const std::pair<CNetAddr, LocalServiceInfo> &item : mapLocalHost)
    {
        obj.push_back(Pair("ip", item.first.ToString()));
        obj.push_back(Pair("port", item.second.nPort));
        obj.push_back(Pair("score", item.second.nScore));
    }

    diff.push_back(Pair("proof-of-work",  GetDifficulty()));
    diff.push_back(Pair("proof-of-stake", GetDifficulty(GetLastBlockIndex(chainActive.Tip(), true))));
    obj.push_back(Pair("difficulty",    diff));

    obj.push_back(Pair("testnet",       fTestNet));
    obj.push_back(Pair("keypoololdest", (boost::int64_t)pwallet->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize",   (int)pwallet->GetKeyPoolSize()));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(nTransactionFee)));
    if (pwallet->IsCrypted())
        obj.push_back(Pair("unlocked_until", (boost::int64_t)nWalletUnlockTime / 1000));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

Value getnewaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "getnewaddress ( \"account\" )\n"
            "\nReturns a new Yacoin address for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "\nResult:\n"
            "\"address\"    (string) The new yacoin address\n"
            "\nExamples:\n"
            + HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
        );

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwallet->SetAddressBook(keyID, strAccount, "receive");

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(CWallet* const pwallet, std::string strAccount, bool bForceNew=false)
{
    CPubKey pubKey;
    if (!pwallet->GetAccountPubkey(pubKey, strAccount, bForceNew)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }

    return CBitcoinAddress(pubKey.GetID());
}

Value getaccountaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current Yacoin address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"address\"          (string) The account yacoin address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccountaddress", "")
            + HelpExampleCli("getaccountaddress", "\"\"")
            + HelpExampleCli("getaccountaddress", "\"myaccount\"")
            + HelpExampleRpc("getaccountaddress", "\"myaccount\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    Value ret;

    ret = GetAccountAddress(pwallet, strAccount).ToString();
    return ret;
}

Value getrawchangeaddress(const Array& params, bool fHelp)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 0)
        throw std::runtime_error(
            "getrawchangeaddress\n"
            "\nReturns a new Yacoin address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
       );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    CReserveKey reservekey(pwallet);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey, true))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey();

    CKeyID keyID = vchPubKey.GetID();

    return CBitcoinAddress(keyID).ToString();
}

Value setaccount(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setaccount <yacoinaddress> <account>\n"
            "Sets the account associated with the given address.");

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");


    std::string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwallet, address.Get())) {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwallet->mapAddressBook.count(address.Get())) {
            std::string strOldAccount = pwallet->mapAddressBook[address.Get()].name;
            if (address == GetAccountAddress(pwallet, strOldAccount)) {
                GetAccountAddress(pwallet, strOldAccount, true);
            }
        }
        pwallet->SetAddressBook(address.Get(), strAccount, "receive");
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return Value::null;
}

Value getaccount(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getaccount \"address\"\n"
            "\nDEPRECATED. Returns the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The yacoin address for account lookup.\n"
            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"")
            + HelpExampleRpc("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");

    std::string strAccount;
    std::map<CTxDestination, CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(address.Get());
    if (mi != pwallet->mapAddressBook.end() && !(*mi).second.name.empty()) {
        strAccount = (*mi).second.name;
    }
    return strAccount;
}


Value getaddressesbyaccount(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getaddressesbyaccount \"account\"\n"
            "\nDEPRECATED. Returns the list of addresses for the given account.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, required) The account name.\n"
            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"address\"         (string) a yacoin address associated with the given account\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressesbyaccount", "\"tabby\"")
            + HelpExampleRpc("getaddressesbyaccount", "\"tabby\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    Array ret;
    for (const std::pair<CBitcoinAddress, CAddressBookData>& item : pwallet->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

static void SendMoney(CWallet* const pwallet, const CTxDestination& address,
                      CAmount nValue, bool fSubtractFeeFromAmount,
                      CWalletTx& wtxNew, const CCoinControl& coin_control,
                      const CScript* fromScriptPubKey,
                      bool useExpiredTimelockUTXO)
{
  CAmount curBalance = pwallet->GetBalance();

  // Check amount
  if (nValue <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

  if (nValue > curBalance)
    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

  if (pwallet->GetBroadcastTransactions() && !g_connman) {
    throw JSONRPCError(RPC_CLIENT_P2P_DISABLED,
                       "Error: Peer-to-peer functionality missing or disabled");
  }

  // Parse Bitcoin address
  CScript scriptPubKey = GetScriptForDestination(address);

  // Create and send the transaction
  CReserveKey reservekey(pwallet);
  CAmount nFeeRequired;

  std::string strError;
  std::vector<CRecipient> vecSend;
  int nChangePosRet = -1;
  CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};
  vecSend.push_back(recipient);
  if (!pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError, coin_control, fromScriptPubKey, useExpiredTimelockUTXO)) {
    if (!fSubtractFeeFromAmount && nValue + nFeeRequired > curBalance)
      strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
    LogPrintf("SendMoney() : %s\n", strError);
    throw JSONRPCError(RPC_WALLET_ERROR, strError);
  }
  CValidationState state;
  if (!pwallet->CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
    strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
    throw JSONRPCError(RPC_WALLET_ERROR, strError);
  }
}

Value sendtoaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "sendtoaddress <yacoinaddress> <amount> [useExpiredTimelockUTXO] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + FormatMoney(MIN_TXOUT_AMOUNT)
            + HelpRequiringPassphrase(pwallet));

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");

    // Amount
    int64_t nAmount = AmountFromValue(params[1]);

    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Send amount too small");

    // Allow to use locktime UTXO
    bool useExpiredTimelockUTXO = true;
    if (params.size() > 2 && params[2].type() == bool_type)
        useExpiredTimelockUTXO = params[2].get_bool();

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["to"]      = params[4].get_str();

    EnsureWalletIsUnlocked(pwallet);

    CCoinControl coinControl;
    SendMoney(pwallet, address.Get(), nAmount, false /* fSubtractFeeFromAmount */, wtx, coinControl, NULL /* fromScriptPubKey */, useExpiredTimelockUTXO);

    return wtx.GetHash().GetHex();
}

Value listaddressgroupings(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp)
        throw std::runtime_error(
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"address\",            (string) The yacoin address\n"
            "      amount,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"account\"             (string, optional) DEPRECATED. The account\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    Array jsonGroupings;
    std::map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (std::set<CTxDestination> grouping : pwallet->GetAddressGroupings())
    {
        Array jsonGrouping;
        for(CTxDestination address : grouping)
        {
            Array addressInfo;
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (pwallet->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwallet->mapAddressBook.end()) {
                    addressInfo.push_back(pwallet->mapAddressBook.find(CBitcoinAddress(address).Get())->second.name);
                }
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

Value signmessage(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage <yacoinaddress> <message>\n"
            "Sign a message with the private key of an address");

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwallet->GetKey(keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

Value verifymessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage <yacoinaddress> <signature> <message>\n"
            "Verify a signed message");

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}

Value getreceivedbyaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getreceivedbyaddress \"address\" ( minconf )\n"
            "\nReturns the total amount received by the given address in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The yacoin address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", 6")
       );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");
    // build standard output script via GetScriptForDestination()
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwallet,scriptPubKey))
        return (double)0.0;

    CTxDestination dest = address.Get();

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !CheckFinalTx(wtx))
            continue;

        for (const auto& txout : wtx.tx->vout)
        {
            CTxDestination addressRet;
            if (ExtractDestination(txout.scriptPubKey, addressRet) && addressRet == dest)
            {
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
            }
        }
    }

    return  ValueFromAmount(nAmount);
}

Value getreceivedbyaccount(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getreceivedbyaccount \"account\" ( minconf )\n"
            "\nDEPRECATED. Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 6")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys assigned to account
    std::string strAccount = AccountFromValue(params[0]);
    std::set<CTxDestination> setAddress = pwallet->GetAccountAddresses(strAccount);

    // Tally
    int64_t nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !CheckFinalTx(wtx))
            continue;

        for(const CTxOut& txout : wtx.tx->vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwallet, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return ValueFromAmount(nAmount);
}

Value getbalance(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "getbalance ( \"account\" minconf include_watchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"         (string, optional) DEPRECATED. The account string may be given as a\n"
            "                     specific account name to find the balance associated with wallet keys in\n"
            "                     a named account, or as the empty string (\"\") to find the balance\n"
            "                     associated with wallet keys not in any named account, or as \"*\" to find\n"
            "                     the balance associated with all wallet keys regardless of account.\n"
            "                     When this option is specified, it calculates the balance in a different\n"
            "                     way than when it is not specified, and which can count spends twice when\n"
            "                     there are conflicting pending transactions (such as those created by\n"
            "                     the bumpfee command), temporarily resulting in low or even negative\n"
            "                     balances. In general, account balance calculation is not considered\n"
            "                     reliable and has resulted in confusing outcomes, so it is recommended to\n"
            "                     avoid passing this argument.\n"
            "2. minconf           (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. include_watchonly (bool, optional, default=false) Also include balance in watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet with 1 or more confirmations\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet at least 6 blocks confirmed\n"
            + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getbalance", "\"*\", 6")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (params.size() == 0)
        return  ValueFromAmount(pwallet->GetBalance());

    const std::string& account_param = params[0].get_str();
    const std::string* account = account_param != "*" ? &account_param : nullptr;

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    return ValueFromAmount(pwallet->GetLegacyBalance(filter, nMinDepth, account));
}

Value getavailablebalance(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "getavailablebalance ( \"account\" minconf include_watchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"         (string, optional) DEPRECATED. The account string may be given as a\n"
            "                     specific account name to find the balance associated with wallet keys in\n"
            "                     a named account, or as the empty string (\"\") to find the balance\n"
            "                     associated with wallet keys not in any named account, or as \"*\" to find\n"
            "                     the balance associated with all wallet keys regardless of account.\n"
            "                     When this option is specified, it calculates the balance in a different\n"
            "                     way than when it is not specified, and which can count spends twice when\n"
            "                     there are conflicting pending transactions (such as those created by\n"
            "                     the bumpfee command), temporarily resulting in low or even negative\n"
            "                     balances. In general, account balance calculation is not considered\n"
            "                     reliable and has resulted in confusing outcomes, so it is recommended to\n"
            "                     avoid passing this argument.\n"
            "2. minconf           (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. include_watchonly (bool, optional, default=false) Also include balance in watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet with 1 or more confirmations\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet at least 6 blocks confirmed\n"
            + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getbalance", "\"*\", 6")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    bool fExcludeNotExpiredTimelock = true;
    if (params.size() == 0)
        return  ValueFromAmount(pwallet->GetBalance(fExcludeNotExpiredTimelock));

    const std::string& account_param = params[0].get_str();
    const std::string* account = account_param != "*" ? &account_param : nullptr;

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    return ValueFromAmount(pwallet->GetLegacyBalance(filter, nMinDepth, account, fExcludeNotExpiredTimelock));
}

Value getunconfirmedbalance(const Array& params, bool fHelp)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 0)
        throw std::runtime_error(
                "getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    LOCK2(cs_main, pwallet->cs_wallet);

    return ValueFromAmount(pwallet->GetUnconfirmedBalance());
}

Value movecmd(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 3 || params.size() > 5)
        throw std::runtime_error(
            "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nDEPRECATED. Move a specified amount from one account in your wallet to another.\n"
            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. amount            (numeric) Quantity of " + CURRENCY_UNIT + " to move between accounts.\n"
            "4. (dummy)           (numeric, optional) Ignored. Remains for backward compatibility.\n"
            "5. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"
            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"
            "\nExamples:\n"
            "\nMove 0.01 " + CURRENCY_UNIT + " from the default account to the account named tabby\n"
            + HelpExampleCli("move", "\"\" \"tabby\" 0.01") +
            "\nMove 0.01 " + CURRENCY_UNIT + " timotei to akiko with a comment and funds have 6 confirmations\n"
            + HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    CAmount nAmount = AmountFromValue(params[2]);

    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Send amount too small");

    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    if (!pwallet->AccountMove(strFrom, strTo, nAmount, strComment)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");
    }

    return true;
}

Value sendfrom(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 3 || params.size() > 7)
        throw runtime_error(
            "sendfrom <fromaccount> <toyacoinaddress> <amount> [useExpiredTimelockUTXO] [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + FormatMoney(MIN_TXOUT_AMOUNT)
            + HelpRequiringPassphrase(pwallet));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(params[0]);
    CBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");
    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Send amount too small");

    // Allow to use locktime UTXO
    bool useExpiredTimelockUTXO = true;
    if (params.size() > 3 && params[3].type() == bool_type)
        useExpiredTimelockUTXO = params[3].get_bool();

    int nMinDepth = 1;
    if (params.size() > 4)
        nMinDepth = params[4].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
        wtx.mapValue["comment"] = params[5].get_str();
    if (params.size() > 6 && params[6].type() != null_type && !params[6].get_str().empty())
        wtx.mapValue["to"]      = params[6].get_str();

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth, &strAccount);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CCoinControl no_coin_control; // This is a deprecated API
    SendMoney(pwallet, address.Get(), nAmount, false /* fSubtractFeeFromAmount */, wtx, no_coin_control, NULL /* fromScriptPubKey */, useExpiredTimelockUTXO);

    return wtx.GetHash().GetHex();
}

Value sendmany(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [useExpiredTimelockUTXO] [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers"
            + HelpRequiringPassphrase(pwallet));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    std::string strAccount = AccountFromValue(params[0]);
    Object sendTo = params[1].get_obj();

    // Allow to use locktime UTXO
    bool useExpiredTimelockUTXO = true;
    if (params.size() > 2 && params[2].type() == bool_type)
        useExpiredTimelockUTXO = params[2].get_bool();

    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();

    std::set<CBitcoinAddress> setAddress;
    std::vector<CRecipient> vecSend;

    int64_t totalAmount = 0;
    for(const Pair& s : sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Yacoin address: ")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        // build standard output script via GetScriptForDestination()
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        int64_t nAmount = AmountFromValue(s.value_);

        if (nAmount < MIN_TXOUT_AMOUNT)
            throw JSONRPCError(-101, "Send amount too small");

        totalAmount += nAmount;

        CRecipient recipient = {scriptPubKey, nAmount, false};
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth, &strAccount);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwallet);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    std::string strFailReason;
    CCoinControl coinControl;
    bool fCreated = pwallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason, coinControl, NULL, useExpiredTimelockUTXO);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, keyChange, g_connman.get(), state)) {
        strFailReason = strprintf("Transaction commit failed:: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    return wtx.GetHash().GetHex();
}

Value addmultisigaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        std::string msg = "addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet. Requires a new wallet backup.\n"
            "Each key is a Yacoin address or hex-encoded public key.\n"
            "If 'account' is specified (DEPRECATED), assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired        (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"         (string, required) A json array of yacoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"  (string) yacoin address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. \"account\"      (string, optional) DEPRECATED. An account to assign the addresses to.\n"

            "\nResult:\n"
            "\"address\"         (string) A yacoin address associated with the keys.\n"

            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    int nRequired = params[0].get_int();
    const Array& keys = params[1].get_array();
    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %" PRIszu " keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();

        // Case 1: Bitcoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks.c_str()));
            CPubKey vchPubKey;
            if (!pwallet->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks.c_str()));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner = GetScriptForMultisig(nRequired, pubkeys);

    if (inner.size() > MAX_SCRIPT_ELEMENT_SIZE)
    throw runtime_error(
        strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), MAX_SCRIPT_ELEMENT_SIZE));

    CScriptID innerID(inner);
    pwallet->AddCScript(inner);

    pwallet->SetAddressBook(innerID, strAccount, "send");
    return CBitcoinAddress(innerID).ToString();
}

Value describeredeemscript(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
    {
        string msg = "describeredeemscript <redeemScript>\n"
            "Parse redeem script and give more information\n";
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    vector<unsigned char> innerData = ParseHexV(params[0], "redeemScript");
    CScript redeemScript(innerData.begin(), innerData.end());

    // Check if it is CLTV/CSV redeemscript
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(redeemScript, whichType, vSolutions))
    {
        string msg = "This is non-standard redeemscript\n";
        throw runtime_error(msg);
    }

    if (whichType != TX_CLTV_P2SH && whichType != TX_CSV_P2SH)
    {
        string msg = "This is not CLTV/CSV redeemscript\n";
        throw runtime_error(msg);
    }

    // Parse redeemscript
    Object output;
    LockTimeRedeemScriptToJSON(redeemScript, whichType, output);

    return output;
}

Value spendcltv(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 3 || params.size() > 5)
    {
	    string msg = "spendcltv <cltv_address> <destination_address> <amount> [comment] [comment-to]\n"
            "send coin from cltv address to another address\n";
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Check if cltv address exist in the wallet
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid cltv address");
    // build standard output script via GetScriptForDestination()
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwallet,scriptPubKey))
    	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wallet doesn't manage coins in this address");

    // Get redeemscript
    CTxDestination tmpAddr;
    CScript redeemScript;
    if (ExtractDestination(scriptPubKey, tmpAddr))
    {
        const CScriptID& hash = boost::get<CScriptID>(tmpAddr);
        if (!pwallet->GetCScript(hash, redeemScript))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wallet doesn't manage redeemscript of this address");
    }

    // Scan information from redeemscript to get lock time
    CScript::const_iterator pc = redeemScript.begin();
    opcodetype opcode;
    vector<unsigned char> vch;
    if (!redeemScript.GetOp(pc, opcode, vch))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wallet can't get lock time from redeemscript");
    const CScriptNum nLockTime(vch, false);

    // Check if destination address is valid
    CBitcoinAddress destAddress(params[1].get_str());
    if (!destAddress.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");

    // Check if number coins in cltv address is enough to spend
    int64_t nAmount = AmountFromValue(params[2]);
    int64_t nTotalValue = 0;
    for (map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !CheckFinalTx(wtx))
            continue;

        for(const CTxOut& txout : wtx.tx->vout)
            if (txout.scriptPubKey == scriptPubKey)
            	nTotalValue += txout.nValue;
    }

    if (nTotalValue < nAmount)
    	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not enough coin in the wallet to spend");

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["to"]      = params[4].get_str();

    if (pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = pwallet->SendMoneyToDestination(destAddress.Get(), nAmount, wtx, false, &scriptPubKey);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

Value spendcsv(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 3 || params.size() > 5)
    {
        string msg = "spendcsv <cltv_address> <destination_address> <amount> [comment] [comment-to]\n"
            "send coin from csv address to another address\n"
            "<csv_address>: required param. csv address containing locked coins. This address is created by \"createcsvaddress\" rpc command\n"
            "<destination_address>: required param. Coins will be sent to this address\n"
            "<amount>: required param. Number coins will be sent to <destination_address>. It excludes the transaction fee, so that it must be smaller"
                    " than number of locked coins in csv address. The remaining coins (= locked coins - <amount> - transaction fee) will be sent to a newly"
                    " generated address which manages by wallet (same behaviour as \"sendtoaddress\" rpc command)\n"
            "[comment], [comment-to]: optional param. Wallet comments\n";
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Check if csv address exist in the wallet
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    if (!address.IsValid())
        throw runtime_error("Invalid csv address");
    // build standard output script via GetScriptForDestination()
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwallet,scriptPubKey))
        throw runtime_error("Wallet doesn't manage coins in this address");

    // Check if destination address is valid
    CBitcoinAddress destAddress(params[1].get_str());
    if (!destAddress.IsValid())
        throw runtime_error("Invalid destination address");

    // Check if number coins in csv address is enough to spend
    int64_t nAmount = AmountFromValue(params[2]);
    int64_t nTotalValue = 0;
    for (map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !CheckFinalTx(wtx))
            continue;

        for(const CTxOut& txout : wtx.tx->vout)
            if (txout.scriptPubKey == scriptPubKey)
                nTotalValue += txout.nValue;
    }

    if (nTotalValue < nAmount)
        throw runtime_error("Not enough coin in the wallet to spend");

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["to"]      = params[4].get_str();

    if (pwallet->IsLocked())
        throw runtime_error("Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = pwallet->SendMoneyToDestination(destAddress.Get(), nAmount, wtx, false, &scriptPubKey);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

Value createcltvaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        string msg = "createcltvaddress <lock_time> [account]\n"
            "Create a P2SH address which lock coins until lock_time\n";
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Generate a new key that is added to wallet
    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    CPubKey pubkey;
    if (!pwallet->GetKeyFromPool(pubkey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    // Get lock time
    uint32_t nLockTime = params[0].get_int64();

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Construct using pay-to-script-hash:
    CScript inner = GetScriptForCltvP2SH(nLockTime, pubkey);

    if (inner.size() > MAX_SCRIPT_ELEMENT_SIZE)
    throw runtime_error(
        strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), MAX_SCRIPT_ELEMENT_SIZE));

    CScriptID innerID(inner);
    pwallet->AddCScript(inner);

    CBitcoinAddress address(innerID);

    std::string warnMsg = "Any coins sent to this cltv address will be locked until ";
    if (nLockTime < LOCKTIME_THRESHOLD)
    {
        std::stringstream ss;
        ss << nLockTime;
        warnMsg += "block height " + ss.str();
    }
    else
        warnMsg += DateTimeStrFormat(nLockTime);
    Object result;
    result.push_back(Pair("cltv address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));
    result.push_back(Pair("Warning", warnMsg));

    pwallet->SetAddressBook(innerID, strAccount, "receive");
    return result;
}

Value createcsvaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        string msg = "createcsvaddress <lock_time> [isBlockHeightLock] [account]\n"
            "Create a P2SH address which lock coins within a number of blocks/seconds\n"
            "<lock_time>: required param. Specify time in seconds or number of blocks which coins will be locked within. Valid range 1->1073741823\n"
            "[isBlockHeightLock]: optional true/false param. Determine <lock_time> is number of blocks or seconds. By default isBlockHeightLock=false\n"
            "[account]: optional param. Account name corresponds to csv address\n";
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Generate a new key that is added to wallet
    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    CPubKey pubkey;
    if (!pwallet->GetKeyFromPool(pubkey))
        throw runtime_error("Error: Keypool ran out, please call keypoolrefill first");

    // Get lock time
    ::uint32_t nLockTime = params[0].get_int64();
    if (nLockTime < 1 || nLockTime > CTxIn::SEQUENCE_LOCKTIME_MASK)
        throw runtime_error("<lock_time> must be between 1 and 1073741823");

    bool fBlockHeightLock = false;
    if (params.size() > 1)
        fBlockHeightLock = params[1].get_bool();

    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Construct using pay-to-script-hash:
    ::uint32_t nSequence = fBlockHeightLock? nLockTime: (nLockTime | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG);
    CScript inner = GetScriptForCsvP2SH(nSequence, pubkey);

    if (inner.size() > MAX_SCRIPT_ELEMENT_SIZE)
    throw runtime_error(
        strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), MAX_SCRIPT_ELEMENT_SIZE));

    CScriptID innerID(inner);
    pwallet->AddCScript(inner);

    CBitcoinAddress address(innerID);

    std::string warnMsg = "Any coins sent to this csv address will be locked ";
    if (fBlockHeightLock)
    {
        std::stringstream ss;
        ss << nLockTime;
        warnMsg += "within " + ss.str() + " blocks";
    }
    else
    {
        std::stringstream ss;
        ss << (nLockTime * (1 << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY));
        warnMsg += "for a period of " + ss.str() + " seconds";
    }
    Object result;
    result.push_back(Pair("csv address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));
    result.push_back(Pair("Warning", warnMsg));

    pwallet->SetAddressBook(innerID, strAccount, "receive");
    return result;
}

Value timelockcoins(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 2 || params.size() > 5)
    {
        throw runtime_error(
            "timelockcoins <amount> <lock_time> [isRelativeTimelock] [isBlockHeightLock] [to_address]\n"
            "\nTimelocks an amount of coins within a number of blocks/seconds (relative timelock) or until a specific block/time (absolute timelock)\n"

            "\nArguments:\n"
            "1. \"amount\"                (numeric, required) Number of YAC you want to timelock\n"
            "2. \"lock_time\"             (integer, required) The meaning of lock_time depends on isRelativeTimelock, isBlockHeightLock and the value itself\n"
            "                                                 If isRelativeTimelock = true: Specify time in seconds (isBlockHeightLock = false) or number of blocks (isBlockHeightLock = true) which coins will be locked within. Valid range 1->1073741823\n"
            "                                                 If isRelativeTimelock = false: Specify specific time (lock_time >= 500000000) or a specific block number (lock_time < 500000000) which coins will be locked until. Valid range 1->4294967295\n"
            "3. \"isRelativeTimelock\"    (boolean, optional, default=true), Whether it is relative or absolute timelock\n"
            "4. \"isBlockHeightLock\"     (boolean, optional, default=true), Whether <lock_time> is in units of block or time (in seconds)\n"
            "                                                                This argument is only used in case isRelativeTimelock = true\n"
            "5. \"to_address\"            (string), optional, default=\"\"), Address contains the timelocked coins, if it is empty, address will be generated for you\n"

            "\nResult:\n"
            "\"txid\"                     (string) The transaction id\n"

            "\nExamples:\n"
            "Lock 1000 YAC within 21000 blocks: timelockcoins 1000 21000\n"
            "Lock 1000 YAC within 600 seconds: timelockcoins 1000 600 true false\n"
            "Lock 1000 YAC until block height = 1990000: timelockcoins 1000 1990000 false\n"
            "Lock 1000 YAC until Tuesday, March 4, 2025 12:00:00 AM UTC: 1000 1741046400 false false\n"
            "Lock 1000 YAC within 21000 blocks at address YCk26dUcaXu8vu6zG3E2PrbBeECAV8RNFp: timelockcoins 1000 21000 true true YCk26dUcaXu8vu6zG3E2PrbBeECAV8RNFp\n"
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Amount
    CAmount nAmount = AmountFromValue(params[0]);
    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(RPC_TYPE_ERROR, "Lock amount too small");

    // isRelativeTimelock
    bool isRelativeTimelock = true;
    if (params.size() > 2)
        isRelativeTimelock = params[2].get_bool();

    // isBlockHeightLock
    bool isBlockHeightLock = true;
    if (params.size() > 3)
        isBlockHeightLock = params[3].get_bool();

    // Get lock time
    int64_t nLockTime = params[1].get_int64();
    if (isRelativeTimelock && (nLockTime < 1 || nLockTime > CTxIn::SEQUENCE_LOCKTIME_MASK))
        throw JSONRPCError(RPC_INVALID_PARAMS, std::string("For relative timelock, <lock_time> must be in range of 1->1073741823"));
    else if (!isRelativeTimelock && (nLockTime < 1 || nLockTime > std::numeric_limits<uint32_t>::max()))
        throw JSONRPCError(RPC_INVALID_PARAMS, std::string("For absolute timelock, <lock_time> must be in range of 1->4294967295"));

    // to_address
    std::string address = "";
    if (params.size() > 4)
        address = params[4].get_str();
    CKeyID keyID;

    if (!address.empty()) {
        CTxDestination destination = DecodeDestination(address);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Yacoin address: ") + address);
        }
        keyID = boost::get<CKeyID>(destination);
    } else {
        // Create a new address
        std::string strAccount;

        if (!pwallet->IsLocked()) {
            pwallet->TopUpKeyPool();
        }

        // Generate a new key that is added to wallet
        CPubKey newKey;
        if (!pwallet->GetKeyFromPool(newKey)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
        }
        keyID = newKey.GetID();

        pwallet->SetAddressBook(keyID, strAccount, "receive");

        address = EncodeDestination(keyID);
    }

    // Create timelock script
    CScript timeLockScriptPubKey;
    if (isRelativeTimelock)
    {
        ::uint32_t nSequence = isBlockHeightLock? nLockTime: (nLockTime | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG);
        timeLockScriptPubKey = GetScriptForCsvP2PKH(nSequence, keyID);
    }
    else
    {
        timeLockScriptPubKey = GetScriptForCltvP2PKH(::uint32_t(nLockTime), keyID);
    }

    if (timeLockScriptPubKey.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw runtime_error(
            strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", timeLockScriptPubKey.size(), MAX_SCRIPT_ELEMENT_SIZE));

    Object result;

    // Create transaction
    CWalletTx wtx;
    string strError = pwallet->SendMoney(timeLockScriptPubKey, nAmount, wtx, false, NULL, true);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    // Output the message
    std::stringstream ss;
    if (isRelativeTimelock)
    {
        ss << ValueFromAmountStr(nAmount) << " YAC are now locked. These coins will be locked ";
        if (isBlockHeightLock)
        {
            ss << "within " << nLockTime << " blocks";
        }
        else
        {
            ss << "for a period of " << (nLockTime * (1 << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY)) << " seconds";
        }
    }
    else
    {
        ss << ValueFromAmountStr(nAmount) << " YAC are now locked. These coins will be locked until ";
        if (nLockTime < LOCKTIME_THRESHOLD)
        {
            ss << "block height " << nLockTime;
        }
        else
        {
            ss << DateTimeStrFormat(nLockTime);
        }
    }
    result.push_back(Pair("message", ss.str()));
    result.push_back(Pair("address_containing_timelocked_coins", address));
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));

    return result;
}

Value addredeemscript(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        string msg = "addredeemscript <redeemScript> [account]\n"
            "Add a P2SH address with a specified redeemScript to the wallet.\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Construct using pay-to-script-hash:
    vector<unsigned char> innerData = ParseHexV(params[0], "redeemScript");
    CScript inner(innerData.begin(), innerData.end());
    CScriptID innerID(inner);
    pwallet->AddCScript(inner);

    pwallet->SetAddressBook(innerID, strAccount, "receive");
    return CBitcoinAddress(innerID).ToString();
}

struct tallyitem
{
    CAmount nAmount;
    int nConf;
    std::vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

Value ListReceived(CWallet * const pwallet, const Array& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    // Tally
    std::map<CBitcoinAddress, tallyitem> mapTally;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;

        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !CheckFinalTx(*wtx.tx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        for(const CTxOut& txout : wtx.tx->vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = IsMine(*pwallet, address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    Array ret;
    std::map<std::string, tallyitem> mapAccountTally;
    for (const std::pair<CBitcoinAddress, CAddressBookData>& item : pwallet->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const std::string& strAccount = item.second.name;
        std::map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (fByAccounts)
        {
            tallyitem& _item = mapAccountTally[strAccount];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        }
        else
        {
            Object obj;
            if(fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("address",       address.ToString()));
            obj.push_back(Pair("account",       strAccount));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            if (!fByAccounts)
                obj.push_back(Pair("label", strAccount));
            Array transactions;
            if (it != mapTally.end())
            {
                for (const uint256& _item : (*it).second.txids)
                {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.push_back(Pair("txids", transactions));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (std::map<std::string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            CAmount nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            Object obj;
            if((*it).second.fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("account",       (*it).first));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

Value listreceivedbyaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 3)
        throw std::runtime_error(
            "listreceivedbyaddress ( minconf include_empty include_watchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,        (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) DEPRECATED. The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
            "    \"confirmations\" : n,               (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\",               (string) A comment for the address/transaction, if any\n"
            "    \"txids\": [\n"
            "       n,                                (numeric) The ids of transactions received with the address \n"
            "       ...\n"
            "    ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, params, false);
}

Value listreceivedbyaccount(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "listreceivedbyaccount ( minconf include_empty include_watchonly)\n"
            "\nDEPRECATED. List balances by account.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,   (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
            "    \"confirmations\" : n,          (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"           (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaccount", "")
            + HelpExampleCli("listreceivedbyaccount", "6 true")
            + HelpExampleRpc("listreceivedbyaccount", "6, true, true")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, params, true);
}

static void MaybePushAddress(Object & entry, const CTxDestination &dest)
{
    CBitcoinAddress addr;
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(CWallet* const pwallet, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret, Array& retTokens, const isminefilter& filter)
{
    CAmount nFee;
    std::string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    std::list<CTokenOutputEntry> listTokensReceived;
    std::list<CTokenOutputEntry> listTokensSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter, listTokensReceived, listTokensSent);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        for (const COutputEntry& s : listSent)
        {
            Object entry;
            if(involvesWatchonly || (::IsMine(*pwallet, s.destination) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.destination);
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            if (pwallet->mapAddressBook.count(s.destination)) {
                entry.push_back(Pair("label", pwallet->mapAddressBook[s.destination].name));
            }
            entry.push_back(Pair("vout", s.vout));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            entry.push_back(Pair("abandoned", wtx.isAbandoned()));
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        for (const COutputEntry& r : listReceived)
        {
            string account;
            if (pwallet->mapAddressBook.count(r.destination)) {
                account = pwallet->mapAddressBook[r.destination].name;
            }
            if (fAllAccounts || (account == strAccount))
            {
                Object entry;
                if(involvesWatchonly || (::IsMine(*pwallet, r.destination) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.destination);
                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                }
                else
                    entry.push_back(Pair("category", "receive"));
                entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
                if (pwallet->mapAddressBook.count(r.destination)) {
                    entry.push_back(Pair("label", account));
                }
                entry.push_back(Pair("vout", r.vout));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }

    /** YAC_TOKEN START */
    if (AreTokensDeployed()) {
        if (listTokensReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth) {
            for (const CTokenOutputEntry &data : listTokensReceived){
                Object entry;

                if (involvesWatchonly || (::IsMine(*pwallet, data.destination) & ISMINE_WATCH_ONLY)) {
                    entry.push_back(Pair("involvesWatchonly", true));
                }

                ETokenType tokenType;
                std::string tokenError = "";
                if (!IsTokenNameValid(data.tokenName, tokenType, tokenError)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid token name: ") + data.tokenName + std::string("\nError: ") + tokenError);
                }

                entry.push_back(Pair("token_operation", GetTxnOutputType(data.type)));
                entry.push_back(Pair("token_name", data.tokenName));
                entry.push_back(Pair("token_type", ETokenTypeToString(tokenType)));
                entry.push_back(Pair("amount", TokenValueFromAmount(data.nAmount, data.tokenName)));
                MaybePushAddress(entry, data.destination);
                entry.push_back(Pair("vout", data.vout));
                entry.push_back(Pair("category", "receive"));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                entry.push_back(Pair("abandoned", wtx.isAbandoned()));
                retTokens.push_back(entry);
            }
        }

        if ((!listTokensSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount)) {
            for (const CTokenOutputEntry &data : listTokensSent) {
                Object entry;

                if (involvesWatchonly || (::IsMine(*pwallet, data.destination) & ISMINE_WATCH_ONLY)) {
                    entry.push_back(Pair("involvesWatchonly", true));
                }

                entry.push_back(Pair("token_type", GetTxnOutputType(data.type)));
                entry.push_back(Pair("token_name", data.tokenName));
                entry.push_back(Pair("amount", TokenValueFromAmount(data.nAmount, data.tokenName)));
                MaybePushAddress(entry, data.destination);
                entry.push_back(Pair("vout", data.vout));
                entry.push_back(Pair("category", "send"));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                entry.push_back(Pair("abandoned", wtx.isAbandoned()));
                retTokens.push_back(entry);
            }
        }
    }
    /** YAC_TOKEN END */
}

void ListTransactions(CWallet* const pwallet, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret, const isminefilter& filter)
{
    Array tokenDetails;
    ListTransactions(pwallet, wtx, strAccount, nMinDepth, fLong, ret, tokenDetails, filter);
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        Object entry;
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

Value listtransactions(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 4)
        throw std::runtime_error(
            "listtransactions ( \"account\" count skip include_watchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. skip           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. include_watchonly (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"address\",    (string) The yacoin address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"label\": \"label\",       (string) A comment for the address/transaction, if any\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx,           (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"otheraccount\": \"accountname\",  (string) DEPRECATED. For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
            "                                         'send' category of transactions.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();

    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 3)
        if(params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    Array ret;

    const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(pwallet, *pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount+nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;
    Array::iterator first = ret.begin();
    std::advance(first, nFrom);
    Array::iterator last = ret.begin();
    std::advance(last, nFrom+nCount);

    if (last != ret.end()) ret.erase(last, ret.end());
    if (first != ret.begin()) ret.erase(ret.begin(), first);

    std::reverse(ret.begin(), ret.end()); // Return oldest to newest

    return ret;
}

Value listaccounts(const Array& params, bool fHelp)
{
  CWallet* const pwallet = GetWalletForJSONRPCRequest();
  if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
    return Value::null;
  }

  if (fHelp || params.size() > 2)
      throw std::runtime_error(
          "listaccounts ( minconf include_watchonly)\n"
          "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"
          "\nArguments:\n"
          "1. minconf             (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
          "2. include_watchonly   (bool, optional, default=false) Include balances in watch-only addresses (see 'importaddress')\n"
          "\nResult:\n"
          "{                      (json object where keys are account names, and values are numeric balances\n"
          "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
          "  ...\n"
          "}\n"
          "\nExamples:\n"
          "\nList account balances where there at least 1 confirmation\n"
          + HelpExampleCli("listaccounts", "") +
          "\nList account balances including zero confirmation transactions\n"
          + HelpExampleCli("listaccounts", "0") +
          "\nList account balances for 6 or more confirmations\n"
          + HelpExampleCli("listaccounts", "6") +
          "\nAs json rpc call\n"
          + HelpExampleRpc("listaccounts", "6")
      );

  LOCK2(cs_main, pwallet->cs_wallet);

  int nMinDepth = 1;
  if (params.size() > 0) nMinDepth = params[0].get_int();

  isminefilter includeWatchonly = ISMINE_SPENDABLE;

  if (params.size() > 1)
      if (params[1].get_bool())
          includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

  std::map<std::string, CAmount> mapAccountBalances;
  for (const std::pair<CTxDestination, CAddressBookData>& entry :
       pwallet->mapAddressBook) {
    if (IsMine(*pwallet, entry.first) & includeWatchonly) {  // This address belongs to me
      mapAccountBalances[entry.second.name] = 0;
    }
  }

  for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
    const CWalletTx& wtx = pairWtx.second;
    CAmount nFee;
    string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    int nDepth = wtx.GetDepthInMainChain();
    if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0) continue;
    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
    mapAccountBalances[strSentAccount] -= nFee;
    for (const COutputEntry& s : listSent)
      mapAccountBalances[strSentAccount] -= s.amount;

    if (nDepth >= nMinDepth)
    {
        for (const COutputEntry& r : listReceived)
            if (pwallet->mapAddressBook.count(r.destination)) {
                mapAccountBalances[pwallet->mapAddressBook[r.destination].name] += r.amount;
            }
            else
                mapAccountBalances[""] += r.amount;
    }
  }

  const std::list<CAccountingEntry>& acentries = pwallet->laccentries;
  for (const CAccountingEntry& entry : acentries)
    mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

  Object ret;

  for (const std::pair<std::string, CAmount>& accountBalance : mapAccountBalances) {
    ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
  }
  return ret;
}

Value listsinceblock(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() > 4)
        throw std::runtime_error(
            "listsinceblock ( \"blockhash\" target_confirmations include_watchonly include_removed )\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
            "If \"blockhash\" is no longer a part of the main chain, transactions from the fork point onward are included.\n"
            "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n"
            "\nArguments:\n"
            "1. \"blockhash\"            (string, optional) The block hash to list transactions since\n"
            "2. target_confirmations:    (numeric, optional, default=1) Return the nth block hash from the main chain. e.g. 1 would mean the best block hash. Note: this is not used as a filter, but only affects [lastblock] in the return value\n"
            "3. include_watchonly:       (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')\n"
            "4. include_removed:         (bool, optional, default=true) Show transactions that were removed due to a reorg in the \"removed\" array\n"
            "                                                           (not guaranteed to work on pruned nodes)\n"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"address\",    (string) The yacoin address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "                                          When it's < 0, it means the transaction conflicted that many blocks ago.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "    \"abandoned\": xxx,         (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the 'send' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
            "  ],\n"
            "  \"removed\": [\n"
            "    <structure is the same as \"transactions\" above, only present if include_removed=true>\n"
            "    Note: transactions that were readded in the active chain will appear as-is in this array, and may thus have a positive confirmation count.\n"
            "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the block (target_confirmations-1) from the best block on the main chain. This is typically used to feed back into listsinceblock the next time you call it. So you would generally use a target_confirmations of say 6, so you will be continually re-notified of transactions until they've reached 6 confirmations plus any new ones\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    const CBlockIndex* pindex = nullptr;    // Block index of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    const CBlockIndex* paltindex = nullptr; // Block index of the specified block, even if it's in a deactivated chain.
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (params.size() > 0)
    {
        uint256 blockId = 0;
        blockId.SetHex(params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it == mapBlockIndex.end()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        paltindex = pindex = it->second;
        if (chainActive[pindex->nHeight] != pindex) {
            // the block being asked for is a part of a deactivated chain;
            // we don't want to depend on its perceived height in the block
            // chain, we want to instead use the last common ancestor
            pindex = chainActive.FindFork(pindex);
        }
    }

    if (params.size() > 1)
    {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    bool include_removed = false;
    if(params.size() > 3)
        include_removed = params[3].get_bool();

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    Array transactions;

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        CWalletTx tx = pairWtx.second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth) {
            ListTransactions(pwallet, tx, "*", 0, true, transactions, filter);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    Array removed;
    while (include_removed && paltindex && paltindex != pindex) {
        CBlock block;
        if (!ReadBlockFromDisk(block, paltindex, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }
        for (const CTransaction& tx : block.vtx) {
            if (pwallet->mapWallet.count(tx.GetHash()) > 0) {
                // We want all transactions regardless of confirmation count to appear here,
                // even negative confirmation ones, hence the big negative.
                ListTransactions(pwallet, pwallet->mapWallet[tx.GetHash()], "*", -100000000, true, removed, filter);
            }
        }
        paltindex = paltindex->pprev;
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    Object ret;
    ret.push_back(Pair("transactions", transactions));
    if (include_removed) ret.push_back(Pair("removed", removed));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));
    return ret;
}

Value gettransaction(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || (params.size() < 1) || (params.size() > 2))
      throw runtime_error(
          "gettransaction <txid>\n"
          "Get detailed information about <txid>");

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE;

    if(params.size() > 1)
        if(params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    Object entry;
    if (pwallet->mapWallet.count(hash))
    {
        const CWalletTx& wtx = pwallet->mapWallet[hash];

        CAmount nCredit = wtx.GetCredit(filter);
        CAmount nDebit = wtx.GetDebit(filter);
        CAmount nNet = nCredit - nDebit;
        CAmount nFee = (wtx.IsFromMe(filter) ? wtx.tx->GetValueOut() - nDebit : 0);

        entry.push_back(Pair("Credit", ValueFromAmount(nCredit)));
        entry.push_back(Pair("Debit", ValueFromAmount(nDebit)));
        entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
        if (wtx.IsFromMe(filter))
            entry.push_back(Pair("fee", ValueFromAmount(nFee)));
        TxToJSON(wtx, 0, entry);
        WalletTxToJSON(wtx, entry);

        Array details;
        Array tokenDetails;
        ListTransactions(pwallet, wtx, "*", 0, false, details, tokenDetails, filter);
        entry.push_back(Pair("details", details));
        entry.push_back(Pair("token_details", tokenDetails));
    }
    else
    {
        CTransaction tx;
        uint256 hashBlock = 0;
        if (GetTransaction(hash, tx, hashBlock))
        {
            TxToJSON(tx, 0, entry);
            if (hashBlock == 0)
                entry.push_back(Pair("confirmations", 0));
            else
            {
                entry.push_back(Pair("blockhash", hashBlock.GetHex()));
                BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
                if (mi != mapBlockIndex.end() && (*mi).second)
                {
                    CBlockIndex* pindex = (*mi).second;
                    if (pindex->IsInMainChain())
                        entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                    else
                        entry.push_back(Pair("confirmations", 0));
                }
            }
        }
        else
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    }

    return entry;
}

Value abandontransaction(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "abandontransaction \"txid\"\n"
            "\nMark in-wallet transaction <txid> as abandoned\n"
            "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
            "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
            "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
            "It has no effect on transactions which are already conflicted or abandoned.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());

    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return Value::null;
}

Value backupwallet(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "backupwallet \"destination\"\n"
            "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"
            "\nExamples:\n"
            + HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    string strDest = params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return Value::null;
}

Value keypoolrefill(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool.\n"
            "IMPORTANT: Any previous backups you have made of your wallet file "
            "should be replaced with the newly generated one."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    unsigned int nSize = max<unsigned int>(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), 0);
    if (params.size() > 0) {
        if (params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size");
        nSize = (unsigned int) params[0].get_int();
    }

    EnsureWalletIsUnlocked(pwallet);

    pwallet->TopUpKeyPool(nSize);

    if (pwallet->GetKeyPoolSize() < nSize)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return Value::null;
}

struct WalletUnlockParams {
    int64_t timeoutSeconds;
    CWallet* wallet;  // Example of passing another parameter
};

void ThreadCleanWalletPassphrase(void* parg)
{
    // Make this thread recognisable as the wallet relocking thread
    RenameThread("yacoin-lock-wa");

    std::unique_ptr<WalletUnlockParams> params(reinterpret_cast<WalletUnlockParams*>(parg));
    int64_t nMyWakeTime = GetTimeMillis() + params->timeoutSeconds * 1000;
    CWallet* pWallet = params->wallet;
    ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

    if (nWalletUnlockTime == 0)
    {
        nWalletUnlockTime = nMyWakeTime;

        do
        {
            if (nWalletUnlockTime==0)
                break;
            int64_t nToSleep = nWalletUnlockTime - GetTimeMillis();
            if (nToSleep <= 0)
                break;

            LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
            Sleep(nToSleep);
            ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

        } while( true );

        if (nWalletUnlockTime)
        {
            nWalletUnlockTime = 0;
            LOCK(pWallet->cs_wallet);
            pWallet->nRelockTime = 0;
            pWallet->Lock();
        }
    }
    else
    {
        if (nWalletUnlockTime < nMyWakeTime)
            nWalletUnlockTime = nMyWakeTime;
    }

    LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);

    delete (int64_t*)parg;
}

Value walletpassphrase(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() != 2)
      throw runtime_error(
          "walletpassphrase <passphrase> <timeout>\n"
          "Stores the wallet decryption key in memory for <timeout> seconds.\n"
          "mintonly is optional true/false allowing only block minting.");

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
    }

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwallet->Unlock(strWalletPass))
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw std::runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    pwallet->TopUpKeyPool();
    int64_t nSleepTime = int64_t(params[1].get_int64());
    pwallet->nRelockTime = GetTime() + nSleepTime;

    WalletUnlockParams* walletParams = new WalletUnlockParams();
    walletParams->timeoutSeconds = nSleepTime;
    walletParams->wallet = pwallet;

    NewThread(ThreadCleanWalletPassphrase, walletParams);

    return Value::null;
}

Value walletpassphrasechange(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() != 2)
      throw runtime_error(
          "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
          "Changes the wallet passphrase from <oldpassphrase> to "
          "<newpassphrase>.");

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    }

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }

    return Value::null;
}

Value walletlock(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() != 0)
      throw runtime_error(
          "walletlock\n"
          "Removes the wallet encryption key from memory, locking the wallet.\n"
          "After calling this method, you will need to call walletpassphrase "
          "again\n"
          "before being able to call any methods which require the wallet to "
          "be unlocked.");

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    }

    {
        LOCK(cs_nWalletUnlockTime);
        nWalletUnlockTime = 0;
        pwallet->Lock();
        pwallet->nRelockTime = 0;
    }

    return Value::null;
}

Value encryptwallet(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "encryptwallet \"passphrase\"\n"
            "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with private keys such as sending or signing \n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the walletpassphrase call for this, and then walletlock call.\n"
            "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
            "Note that this will shutdown the server.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"
            "\nExamples:\n"
            "\nEncrypt your wallet\n"
            + HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending yacoin\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can do something like sign\n"
            + HelpExampleCli("signmessage", "\"address\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
    }

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwallet->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; Yacoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";
}

class DescribeAddressVisitor : public boost::static_visitor<Object>
{
public:
    CWallet * const pwallet;

    DescribeAddressVisitor(CWallet *_pwallet) : pwallet(_pwallet) {}

    Object operator()(const CNoDestination &dest) const { return Object(); }
    Object operator()(const CKeyID &keyID) const {
        Object obj;
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    Object operator()(const CScriptID &scriptID) const {
        Object obj;
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(Pair("script", GetTxnOutputType(whichType)));
            obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
            Array a;
            for(const CTxDestination& addr : addresses)
                a.push_back(CBitcoinAddress(addr).ToString());
            obj.push_back(Pair("addresses", a));
            if (whichType == TX_MULTISIG)
                obj.push_back(Pair("sigsrequired", nRequired));
        }
        return obj;
    }
};

Value validateaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress <yacoinaddress>\n"
            "Return information about <yacoinaddress>.");

    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);

    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        std::string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

        isminetype mine = pwallet ? IsMine(*pwallet, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", bool(mine & ISMINE_SPENDABLE)));
        ret.push_back(Pair("iswatchonly", bool(mine & ISMINE_WATCH_ONLY)));
        Object detail = boost::apply_visitor(DescribeAddressVisitor(pwallet), dest);
        ret.insert(ret.end(), detail.begin(), detail.end());

        if (pwallet && pwallet->mapAddressBook.count(dest)) {
            ret.push_back(Pair("account", pwallet->mapAddressBook[dest].name));
        }
        CKeyID keyID;
        if (pwallet) {
            const auto& meta = pwallet->mapKeyMetadata;
            auto it = address.GetKeyID(keyID) ? meta.find(keyID) : meta.end();
            if (it == meta.end()) {
                it = meta.find(CScriptID(scriptPubKey));
            }
            if (it != meta.end()) {
                ret.push_back(Pair("timestamp", it->second.nCreateTime));
                if (!it->second.hdKeypath.empty()) {
                    ret.push_back(Pair("hdkeypath", it->second.hdKeypath));
                    ret.push_back(Pair("hdmasterkeyid", it->second.hdMasterKeyID.GetHex()));
                }
            }
        }
    }
    return ret;
}

Value getwalletinfo(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp)
        throw std::runtime_error(
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"walletname\": xxxxx,             (string) the wallet name\n"
            "  \"walletversion\": xxxxx,          (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,              (numeric) the total confirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"unconfirmed_balance\": xxx,      (numeric) the total unconfirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"immature_balance\": xxxxxx,      (numeric) the total immature balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"txcount\": xxxxxxx,              (numeric) the total number of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,         (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,             (numeric) how many new keys are pre-generated (only counts external keys)\n"
            "  \"keypoolsize_hd_internal\": xxxx, (numeric) how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)\n"
            "  \"unlocked_until\": ttt,           (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,              (numeric) the transaction fee configuration, set in " + CURRENCY_UNIT + "/kB\n"
            "  \"hdmasterkeyid\": \"<hash160>\"     (string) the Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    if(pwallet==NULL){
        throw runtime_error("getwalletinfo: wallet = Null\n");
    }

    Object obj;
    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    obj.push_back(Pair("walletname", pwallet->GetName()));
    obj.push_back(Pair("walletversion", pwallet->GetVersion()));
    obj.push_back(Pair("balance",       ValueFromAmount(pwallet->GetBalance())));
    obj.push_back(Pair("unconfirmed_balance", ValueFromAmount(pwallet->GetUnconfirmedBalance())));
    obj.push_back(Pair("immature_balance",    ValueFromAmount(pwallet->GetImmatureBalance())));
    obj.push_back(Pair("txcount",       (int)pwallet->mapWallet.size()));
    obj.push_back(Pair("keypoololdest", pwallet->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize", (int64_t)kpExternalSize));
    CKeyID masterKeyID = pwallet->GetHDChain().masterKeyID;
    if (!masterKeyID.IsNull() && pwallet->CanSupportFeature(FEATURE_HD_SPLIT)) {
        obj.push_back(Pair("keypoolsize_hd_internal",   (int64_t)(pwallet->GetKeyPoolSize() - kpExternalSize)));
    }
    if (pwallet->IsCrypted()) {
        obj.push_back(Pair("unlocked_until", pwallet->nRelockTime));
    }
    if (!masterKeyID.IsNull())
         obj.push_back(Pair("hdmasterkeyid", masterKeyID.GetHex()));

    return obj;
}

Value listwallets(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "listwallets\n"
            "Returns a list of currently loaded wallets.\n"
            "For full information on the wallet, use \"getwalletinfo\"\n"
            "\nResult:\n"
            "[                         (json array of strings)\n"
            "  \"walletname\"            (string) the wallet name\n"
            "   ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listwallets", "")
            + HelpExampleRpc("listwallets", "")
        );

    Array obj;
    for (CWalletRef pwallet : vpwallets) {

        if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
            return Value::null;
        }

        LOCK(pwallet->cs_wallet);

        obj.push_back(pwallet->GetName());
    }

    return obj;
}

// Yacoin: resend unconfirmed wallet transactions
Value resendwallettransactions(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
      return Value::null;
    }

    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns an RPC error if -walletbroadcast is set to false.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    if (!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->GetBroadcastTransactions()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet transaction broadcasting is disabled with -walletbroadcast");
    }

    std::vector<uint256> txids = pwallet->ResendWalletTransactionsBefore(GetTime(), g_connman.get());
    Array result;
    for (const uint256& txid : txids)
    {
        result.push_back(txid.ToString());
    }
    return result;
}
