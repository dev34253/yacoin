// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "bitcoinrpc.h"
#include "chain.h"
//#include "rpc/server.h"
#include "init.h"
#include "validation.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet.h"
#include "merkleblock.h"
//#include "core_io.h"

#include "rpcwallet.h"

#include <fstream>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

//#include <univalue.h>

// TACA: OLD LOGIC BEGIN
using namespace json_spirit;

using std::runtime_error;
using std::string;
// TACA: OLD LOGIC END

Value importprivkey(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "importprivkey \"privkey\" ( \"label\" ) ( rescan )\n"
            "\nAdds a private key (as returned by dumpprivkey) to your wallet. Requires a new wallet backup.\n"
            "\nArguments:\n"
            "1. \"privkey\"          (string, required) The private key (see dumpprivkey)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key with rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\"") +
            "\nImport using a label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"testing\" false") +
            "\nImport using default blank label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CKey key = vchSecret.GetKey();
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));
    CKeyID vchAddress = pubkey.GetID();
    {
        pwallet->MarkDirty();
        pwallet->SetAddressBook(vchAddress, strLabel, "receive");

        // Don't throw error in case a key is already there
        if (pwallet->HaveKey(vchAddress)) {
            return Value::null;
        }

        pwallet->mapKeyMetadata[vchAddress].nCreateTime = 1;

        if (!pwallet->AddKeyPubKey(key, pubkey)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
        }

        // whenever a key is imported, we need to scan the whole chain
        pwallet->UpdateTimeFirstKey(1);

        if (fRescan) {
            pwallet->RescanFromTime(TIMESTAMP_MIN, true /* update */);
        }
    }

    return Value::null;
}

void ImportAddress(CWallet*, const CBitcoinAddress& address, const std::string& strLabel);
void ImportScript(CWallet* const pwallet, const CScript& script, const std::string& strLabel, bool isRedeemScript)
{
    if (!isRedeemScript && ::IsMine(*pwallet, script) == ISMINE_SPENDABLE) {
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");
    }

    pwallet->MarkDirty();

    if (!pwallet->HaveWatchOnly(script) && !pwallet->AddWatchOnly(script, 0 /* nCreateTime */)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
    }

    if (isRedeemScript) {
        if (!pwallet->HaveCScript(script) && !pwallet->AddCScript(script)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
        }
        ImportAddress(pwallet, CBitcoinAddress(CScriptID(script)), strLabel);
    } else {
        CTxDestination destination;
        if (ExtractDestination(script, destination)) {
            pwallet->SetAddressBook(destination, strLabel, "receive");
        }
    }
}

void ImportAddress(CWallet* const pwallet, const CBitcoinAddress& address, const std::string& strLabel)
{
    CScript script = GetScriptForDestination(address.Get());
    ImportScript(pwallet, script, strLabel, false);
    // add to address book or update label
    if (address.IsValid())
        pwallet->SetAddressBook(address.Get(), strLabel, "receive");
}

Value importaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "importaddress \"address\" ( \"label\" rescan p2sh )\n"
            "\nAdds a script (in hex) or address that can be watched as if it were in your wallet but cannot be used to spend. Requires a new wallet backup.\n"
            "\nArguments:\n"
            "1. \"script\"           (string, required) The hex-encoded script (or address)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "4. p2sh                 (boolean, optional, default=false) Add the P2SH version of the script as well\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "If you have the full public key, you should call importpubkey instead of this.\n"
            "\nNote: If you import a non-standard raw script in hex form, outputs sending to it will be treated\n"
            "as change, and not show up in many RPCs.\n"
            "\nExamples:\n"
            "\nImport a script with rescan\n"
            + HelpExampleCli("importaddress", "\"myscript\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importaddress", "\"myscript\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importaddress", "\"myscript\", \"testing\", false")
        );

    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    // Whether to import a p2sh version, too
    bool fP2SH = false;
    if (params.size() > 3)
        fP2SH = params[3].get_bool();

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        if (fP2SH)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead");
        ImportAddress(pwallet, address, strLabel);
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        ImportScript(pwallet, CScript(data.begin(), data.end()), strLabel, fP2SH);
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address or script");
    }

    if (fRescan)
    {
        pwallet->RescanFromTime(TIMESTAMP_MIN, true /* update */);
        pwallet->ReacceptWalletTransactions();
    }

    return Value::null;
}

Value removeaddress(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "removeaddress 'address'\n"
            "\nRemoves watch-only address or script (in hex) added by importaddress.\n"
            "\nArguments:\n"
            "1. 'address' (string, required) The address\n"
            "\nExamples:\n"
            "\nremoveaddress 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n"
            "\nRemove watch-only address 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n");

    LOCK2(cs_main, pwallet->cs_wallet);

    CScript script;
    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        script = GetScriptForDestination(address.Get());
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address or script");
    }

    if (::IsMine(*pwallet, script) == ISMINE_SPENDABLE)
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet contains the private key for this address or script - can't remove it");

    if (!pwallet->HaveWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet does not contain this address or script");

    pwallet->MarkDirty();

    if (!pwallet->RemoveWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error removing address from wallet");

    return Value::null;
}

Value importpubkey(const Array& params, bool fHelp)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw std::runtime_error(
            "importpubkey \"pubkey\" ( \"label\" rescan )\n"
            "\nAdds a public key (in hex) that can be watched as if it were in your wallet but cannot be used to spend. Requires a new wallet backup.\n"
            "\nArguments:\n"
            "1. \"pubkey\"           (string, required) The hex-encoded public key\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nImport a public key with rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importpubkey", "\"mypubkey\", \"testing\", false")
        );


    std::string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    if (!IsHex(params[0].get_str()))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string");
    std::vector<unsigned char> data(ParseHex(params[0].get_str()));
    CPubKey pubKey(data.begin(), data.end());
    if (!pubKey.IsFullyValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey is not a valid public key");

    LOCK2(cs_main, pwallet->cs_wallet);

    ImportAddress(pwallet, CBitcoinAddress(pubKey.GetID()), strLabel);
    ImportScript(pwallet, GetScriptForRawPubKey(pubKey), strLabel, false);

    if (fRescan)
    {
        pwallet->RescanFromTime(TIMESTAMP_MIN, true /* update */);
        pwallet->ReacceptWalletTransactions();
    }

    return Value::null;
}

Value importwallet(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "importwallet \"filename\"\n"
            "\nImports keys from a wallet dump file (see dumpwallet). Requires a new wallet backup to include imported keys.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("dumpwallet", "\"test\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("importwallet", "\"test\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("importwallet", "\"test\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Open wallet file
    std::ifstream file;
    file.open(params[0].get_str().c_str(), std::ios::in | std::ios::ate);
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64_t nTimeBegin = chainActive.Tip()->GetBlockTime();

    bool fGood = true;

    // read through input file checking and importing keys into wallet.
    enum ReadState {
        begin = 0,
        readP2PKH = 1,
        readP2SH = 2,
        finish = 3
    };
    ::uint32_t readState = begin;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
    file.seekg(0, file.beg);

    pwallet->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI

    while (file.good()) {
        pwallet->ShowProgress("", std::max(1, std::min(99, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line);
        if (line.empty() || line[0] == '#')
            continue;

        if (line[0] == '@') {
            readState++;
            continue;
        }

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" "));
        if (vstr.size() < 2)
            continue;
        CBitcoinSecret vchSecret;
        if (!vchSecret.SetString(vstr[0]))
            continue;

        CKey key = vchSecret.GetKey();
        CPubKey pubkey = key.GetPubKey();
        assert(key.VerifyPubKey(pubkey));
        CKeyID keyid = pubkey.GetID();
        int64_t nTime = DecodeDumpTime(vstr[1]);
        CScript scriptP2SH; // for P2SH redeemscript
        std::string strLabel;
        bool fLabel = true;
        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) {
            if (boost::algorithm::starts_with(vstr[nStr], "#"))
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = DecodeDumpString(vstr[nStr].substr(6));
                fLabel = true;
            }
            if (boost::algorithm::starts_with(vstr[nStr], "redeemscript=")) {
                std::vector<unsigned char> innerData = ParseHex(vstr[nStr].substr(13));
                scriptP2SH.assign(innerData.begin(), innerData.end());
            }
        }

        if (pwallet->HaveKey(keyid)) {
            if (readState == readP2SH && !pwallet->GetCScript(CScriptID(scriptP2SH), scriptP2SH))
            {
                pwallet->AddCScript(scriptP2SH);
                if (fLabel)
                    pwallet->SetAddressBook(CScriptID(scriptP2SH), strLabel, "receive");
            }
            LogPrintf("Skipping import of %s (key already present)\n", CBitcoinAddress(keyid).ToString());
            continue;
        }

        LogPrintf("Importing %s...\n", CBitcoinAddress(keyid).ToString());
        if (!pwallet->AddKeyPubKey(key, pubkey)) {
            fGood = false;
            continue;
        }

        if (readState == readP2PKH)
        {
            ::int64_t nTime = DecodeDumpTime(vstr[1]);
            pwallet->mapKeyMetadata[keyid].nCreateTime = nTime;
            nTimeBegin = std::min(nTimeBegin, nTime);
            if (fLabel)
                pwallet->SetAddressBook(keyid, strLabel, "receive");
        }
        else if (readState == readP2SH)
        {
            pwallet->AddCScript(scriptP2SH);
            if (fLabel)
                pwallet->SetAddressBook(CScriptID(scriptP2SH), strLabel, "receive");
        }
    }
    file.close();

    pwallet->ShowProgress("", 100); // hide progress dialog in GUI
    // rescan block chain looking for coins from new keys
    CBlockIndex *pindex = chainActive.Tip();
    while (pindex && pindex->pprev && pindex->nTime > nTimeBegin - 7200)
        pindex = pindex->pprev;

    LogPrintf("Rescanning last %i blocks\n", chainActive.Tip()->nHeight - pindex->nHeight + 1);
    pwallet->UpdateTimeFirstKey(nTimeBegin);
    pwallet->RescanFromTime(nTimeBegin, false /* update */);
    pwallet->MarkDirty();

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "dumpprivkey \"address\"\n"
            "\nReveals the private key corresponding to 'address'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"address\"   (string, required) The bitcoin address for the private key\n"
            "\nResult:\n"
            "\"key\"                (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");

    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwallet,scriptPubKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet doesn't manage coins in this address");

    CKeyingMaterial vchSecret;
    txnouttype whichTypeRet;
    bool fCompressed;
    CScript subscript;
    if (!pwallet->GetSecret(scriptPubKey, vchSecret, fCompressed, whichTypeRet, subscript))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    CKey key;
    key.Set(vchSecret.begin(), vchSecret.end(), fCompressed);

    Object result;
    if (whichTypeRet == TX_CLTV_P2SH || whichTypeRet == TX_CSV_P2SH)
    {
        result.push_back(Pair("address_type", "P2SH address"));
        result.push_back(Pair("private_key", CBitcoinSecret(key).ToString()));
        result.push_back(Pair("redeem_script", HexStr(subscript.begin(), subscript.end())));
    }
    else
    {
        result.push_back(Pair("address_type", "P2PKH address"));
        result.push_back(Pair("private_key", CBitcoinSecret(key).ToString()));
    }
    return result;
}

Value dumpwallet(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "dumpwallet \"filename\"\n"
            "\nDumps all wallet keys in a human-readable format to a server-side file. This does not allow overwriting existing files.\n"
            "Imported scripts are not currently included in wallet dumps, these must be backed up separately.\n"
            "Note that if your wallet contains keys which are not derived from your HD seed (e.g. imported keys), these are not covered by\n"
            "only backing up the seed itself, and must be backed up too (e.g. ensure you back up the whole dumpfile).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename with path (either absolute or relative to bitcoind)\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"filename\" : {        (string) The filename with full absolute path\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    if(!DumpWallet(pwallet, params[0].get_str().c_str() ))
      throw JSONRPCError(RPC_WALLET_ERROR, "Error dumping wallet keys to file");

    return Value::null;
}

Value abortrescan(const Array& params, bool fHelp)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest();
    if (!EnsureWalletIsAvailable(pwallet, fHelp)) {
        return Value::null;
    }

    if (fHelp || params.size() > 0)
        throw std::runtime_error(
            "abortrescan\n"
            "\nStops current wallet rescan triggered e.g. by an importprivkey call.\n"
            "\nExamples:\n"
            "\nImport a private key\n"
            + HelpExampleCli("importprivkey", "\"mykey\"") +
            "\nAbort the running wallet rescan\n"
            + HelpExampleCli("abortrescan", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("abortrescan", "")
        );

    if (!pwallet->IsScanning() || pwallet->IsAbortingRescan()) return false;
    pwallet->AbortRescan();
    return true;
}
