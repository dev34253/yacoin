// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/standard.h"

#include "pubkey.h"
#include "script/script.h"
#include "script/sign.h"
#include "util.h"
#include "utilstrencodings.h"
#include "tokens/tokens.h"
#include "keystore.h"

#include <map>

CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

const char* GetTxnOutputType(txnouttype t)
{
    switch (t)
    {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_NULL_DATA: return "nulldata";
    case TX_CLTV_P2SH: return "CLTV_P2SH_timelock";
    case TX_CSV_P2SH: return "CSV_P2SH_timelock";
    case TX_CLTV_P2PKH: return "CLTV_P2PKH_timelock";
    case TX_CSV_P2PKH: return "CSV_P2PKH_timelock";
    /** YAC START */
    case TX_NEW_TOKEN: return TOKEN_NEW_STRING;
    case TX_TRANSFER_TOKEN: return TOKEN_TRANSFER_STRING;
    case TX_REISSUE_TOKEN: return TOKEN_REISSUE_STRING;
    /** YAC END */
    }
    return NULL;
}

/**
 * Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
 */
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet)
{
    // Templates
    static std::map<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(std::make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(std::make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(std::make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

        // CLTV-P2SH transaction, sender provides pubkey, receiver provides redeemscript and signature
        mTemplates.insert(std::make_pair(TX_CLTV_P2SH, CScript() << OP_SMALLDATA << OP_NOP2 << OP_DROP << OP_PUBKEYS << OP_CHECKSIG));

        // CSV-P2SH transaction, sender provides pubkey, receiver provides redeemscript and signature
        mTemplates.insert(std::make_pair(TX_CSV_P2SH, CScript() << OP_SMALLDATA << OP_NOP3 << OP_DROP << OP_PUBKEYS << OP_CHECKSIG));

        // CLTV-P2PKH transaction, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(std::make_pair(TX_CLTV_P2PKH, CScript() << OP_SMALLDATA << OP_NOP2 << OP_DROP << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // CSV-P2PKH transaction, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(std::make_pair(TX_CSV_P2PKH, CScript() << OP_SMALLDATA << OP_NOP3 << OP_DROP << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));
    }

    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    /** YAC_TOKEN START */
    int nType = 0;
    bool fIsOwner = false;
    if (scriptPubKey.IsTokenScript(nType, fIsOwner)) {
        // It is  OP_DUP OP_HASH160 20 <Hash160_public_key> OP_EQUALVERIFY OP_CHECKSIG OP_YAC_TOKEN <token_data> OP_DROP
        typeRet = (txnouttype)nType;
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+3, scriptPubKey.begin()+23);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }
    /** YAC_TOKEN END */

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_NULL_DATA;
        return true;
    }

    // Scan templates
    const CScript& script1 = scriptPubKey;
    for (const std::pair<txnouttype, CScript>& tplate : mTemplates)
    {
        const CScript& script2 = tplate.second;
        vSolutionsRet.clear();

        opcodetype opcode1, opcode2;
        std::vector<unsigned char> vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        while (true)
        {
            if (pc1 == script1.end() && pc2 == script2.end())
            {
                // Found a match
                typeRet = tplate.first;
                if (typeRet == TX_MULTISIG)
                {
                    // Additional checks for TX_MULTISIG:
                    unsigned char m = vSolutionsRet.front()[0];
                    unsigned char n = vSolutionsRet.back()[0];
                    if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                        return false;
                }
                return true;
            }
            if (!script1.GetOp(pc1, opcode1, vch1))
                break;
            if (!script2.GetOp(pc2, opcode2, vch2))
                break;

            // Template matching opcodes:
            if (opcode2 == OP_PUBKEYS)
            {
                while (vch1.size() >= 33 && vch1.size() <= 120)
                {
                    vSolutionsRet.push_back(vch1);
                    if (!script1.GetOp(pc1, opcode1, vch1))
                        break;
                }
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;
                // Normal situation is to fall through
                // to other if/else statements
            }

            if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() < 33 || vch1.size() > 120)
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_SMALLINTEGER)
            {   // Single-byte small integer pushed onto vSolutions
                if (opcode1 == OP_0 ||
                    (opcode1 >= OP_1 && opcode1 <= OP_16))
                {
                    char n = (char)CScript::DecodeOP_N(opcode1);
                    vSolutionsRet.push_back(valtype(1, n));
                }
                else
                    break;
            }
            else if (opcode2 == OP_SMALLDATA)   // this is different from 0.4.4
            {
                // Nothing
            }
            else if ((opcode1 != opcode2) || (vch1 != vch2))
            {   // Others must match exactly
                break;
            }
        }
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

//
// Sign scriptPubKey with private keys stored in keystore, given transaction hash and hash type.
// Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
// unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
// Returns false if scriptPubKey could not be completely satisfied.
//
bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey, uint256 hash, int nHashType, CScript& scriptSigRet, txnouttype& whichTypeRet)
{
    scriptSigRet.clear();

    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:  // this is not in 0.4.4 code
        return false;
    case TX_PUBKEY:
    case TX_CLTV_P2SH:
    case TX_CSV_P2SH:
        keyID = CPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, keystore, hash, nHashType, scriptSigRet);
    case TX_NEW_TOKEN:
    case TX_REISSUE_TOKEN:
    case TX_TRANSFER_TOKEN:
    case TX_CLTV_P2PKH:
    case TX_CSV_P2PKH:
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
            return false;
        else
        {
            CPubKey vch;
            keystore.GetPubKey(keyID, vch);
            scriptSigRet << ToByteVector(vch);
        }
        return true;
    case TX_SCRIPTHASH:
        return keystore.GetCScript(uint160(vSolutions[0]), scriptSigRet);

    case TX_MULTISIG:
        scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
        return (SignN(vSolutions, keystore, hash, nHashType, scriptSigRet));
    }
    return false;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY || whichType == TX_CLTV_P2SH || whichType == TX_CSV_P2SH)
    {
        addressRet = CPubKey(vSolutions[0]).GetID();
        return true;
    }
    else if (whichType == TX_PUBKEYHASH || whichType == TX_CLTV_P2PKH || whichType == TX_CSV_P2PKH)
    {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_SCRIPTHASH)
    {
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    /** YAC_TOKEN START */
    } else if (whichType == TX_NEW_TOKEN || whichType == TX_REISSUE_TOKEN || whichType == TX_TRANSFER_TOKEN) {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
     /** YAC_TOKEN END */
    // Multisig txns have more than one address...
    return false;
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, typeRet, vSolutions))
        return false;
    if (typeRet == TX_NULL_DATA)
        return true;

    if (typeRet == TX_MULTISIG)
    {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
            CPubKey pubKey(vSolutions[i]);
            if (!pubKey.IsValid())
                continue;

            CTxDestination address = pubKey.GetID();
            addressRet.push_back(address);
        }

        if (addressRet.empty())
            return false;
    }
    else
    {
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestination(scriptPubKey, address))
           return false;
        addressRet.push_back(address);
    }

    return true;
}

namespace
{
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }
};
} // namespace
CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;

    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForRawPubKey(const CPubKey& pubKey)
{
    return CScript() << std::vector<unsigned char>(pubKey.begin(), pubKey.end()) << OP_CHECKSIG;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;
    script << CScript::EncodeOP_N(nRequired);
    for (const CPubKey& key : keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
    return script;
}

CScript GetScriptForCltvP2SH(uint32_t nLockTime, const CPubKey& pubKey)
{
    CScript script;
    script << (CScriptNum)nLockTime;
    script << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    script << ToByteVector(pubKey) << OP_CHECKSIG;
    return script;
}

CScript GetScriptForCltvP2PKH(uint32_t nLockTime, const CKeyID &keyID)
{
    CScript script;
    script << (CScriptNum)nLockTime;
    script << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    script  << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
    return script;
}

CScript GetScriptForCsvP2SH(::uint32_t nSequence, const CPubKey& pubKey)
{
    CScript script;
    script << (CScriptNum)nSequence;
    script << OP_CHECKSEQUENCEVERIFY << OP_DROP;
    script << ToByteVector(pubKey) << OP_CHECKSIG;
    return script;
}

CScript GetScriptForCsvP2PKH(::uint32_t nSequence, const CKeyID &keyID)
{
    CScript script;
    script << (CScriptNum)nSequence;
    script << OP_CHECKSEQUENCEVERIFY << OP_DROP;
    script  << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
    return script;
}

int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char> >& vSolutions)
{
    switch (t)
    {
    case TX_NONSTANDARD:
        return -1;
    case TX_NULL_DATA:
        return 1;
    case TX_CLTV_P2SH:
    case TX_CSV_P2SH:
    case TX_PUBKEY:
        return 1;
    case TX_NEW_TOKEN:
    case TX_REISSUE_TOKEN:
    case TX_TRANSFER_TOKEN:
    case TX_CLTV_P2PKH:
    case TX_CSV_P2PKH:
    case TX_PUBKEYHASH:
        return 2;
    case TX_MULTISIG:
        if (vSolutions.size() < 1 || vSolutions[0].size() < 1)
            return -1;
        return vSolutions[0][0] + 1;
    case TX_SCRIPTHASH:
        return 1; // doesn't include args needed by the script
    }
    return -1;
}

bool IsSpendableTimelockUTXO(const CKeyStore &keystore,
        const CScript &scriptPubKey, txnouttype& retType, uint32_t& retLockDur)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions)) {
        return false;
    }

    switch (whichType)
    {
    case TX_SCRIPTHASH:
    {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript))
        {
            return IsSpendableTimelockUTXO(keystore, subscript, retType, retLockDur);
        }
        break;
    }
    case TX_CLTV_P2SH:
    case TX_CSV_P2SH:
    {
        CKeyID keyID = CPubKey(vSolutions[0]).GetID();
        retType = whichType;
        if (!ExtractLockDuration(scriptPubKey, retLockDur))
        {
            LogPrintf("IsSpendableTimelockUTXO(), Can't get lock duration from scriptPubKey\n");
        }
        if (keystore.HaveKey(keyID))
        {
            return true;
        }
        break;
    }
    case TX_CLTV_P2PKH:
    case TX_CSV_P2PKH:
    {
        CKeyID keyID = CKeyID(uint160(vSolutions[0]));
        retType = whichType;
        if (!ExtractLockDuration(scriptPubKey, retLockDur))
        {
            LogPrintf("IsSpendableTimelockUTXO(), Can't get lock duration from scriptPubKey\n");
        }
        if (keystore.HaveKey(keyID))
        {
            return true;
        }
        break;
    }
    }

    return false;
}

bool IsValidDestination(const CTxDestination& dest) {
    return dest.which() != 0;
}

