// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "script/script.h"
#include "script/standard.h"
#include "main.h"
#include "tokens/tokens.h"
#include "streams.h"
#include "policy/policy.h"
#include "validation.h"

#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>

#include <openssl/ripemd.h>
#include <openssl/sha.h>

using namespace boost;

using std::vector;
using std::runtime_error;
using std::map;
using std::set;

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expanson
    case OP_NOP1                   : return "OP_NOP1";
    case OP_CHECKLOCKTIMEVERIFY    : return "OP_CHECKLOCKTIMEVERIFY";
    case OP_CHECKSEQUENCEVERIFY    : return "OP_CHECKSEQUENCEVERIFY";
    case OP_YAC_TOKEN              : return "OP_YAC_TOKEN";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";



    // template matching params
    case OP_PUBKEYHASH             : return "OP_PUBKEYHASH";
    case OP_PUBKEY                 : return "OP_PUBKEY";
    case OP_SMALLDATA              : return "OP_SMALLDATA";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";
    default:
        return "OP_UNKNOWN";
    }
}

bool ExtractLockDuration(const CScript& scriptPubKey, uint32_t& lockDuration)
{
    // Scan information from scriptPubKey to get lock duration
    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;
    vector<unsigned char> vch;
    if (!scriptPubKey.GetOp(pc, opcode, vch))
    {
        return false;
    }

    lockDuration = CScriptNum(vch).getuint();
    return true;
}

class CAffectedKeysVisitor : public boost::static_visitor<void> {
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript &script) {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            for(const CTxDestination &dest : vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId) {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const CNoDestination &none) {}
};


void ExtractAffectedKeys(const CKeyStore &keystore, const CScript& scriptPubKey, std::vector<CKeyID> &vKeys) {
    CAffectedKeysVisitor(keystore, vKeys).Process(scriptPubKey);
}

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += MAX_PUBKEYS_PER_MULTISIG;
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, data))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToPublicKey() const
{
    // Test for pay-to-pubkey CScript with both
    // compressed or uncompressed pubkey
    if (this->size() == 35) {
        return ((*this)[1] == 0x02 || (*this)[1] == 0x03) &&
                (*this)[34] == OP_CHECKSIG;
    }
    if (this->size() == 67) {
        return (*this)[1] == 0x04 &&
                (*this)[66] == OP_CHECKSIG;

    }
    return false;
}

bool CScript::IsPayToPublicKeyHash() const
{
    // Extra-fast test for pay-to-pubkey-hash CScripts:
    return (this->size() == 25 &&
        (*this)[0] == OP_DUP &&
        (*this)[1] == OP_HASH160 &&
        (*this)[2] == 0x14 &&
        (*this)[23] == OP_EQUALVERIFY &&
        (*this)[24] == OP_CHECKSIG);
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            this->at(0) == OP_HASH160 &&
            this->at(1) == 0x14 &&
            this->at(22) == OP_EQUAL);
}

bool CScript::IsP2PKHTimelock(std::vector<unsigned char>& addressRet) const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(*this, whichType, vSolutions))
        return false;

    if (whichType == TX_CLTV_P2PKH || whichType == TX_CSV_P2PKH)
    {
        addressRet = vSolutions[0];
        return true;
    }
    return false;
}

/** YAC_TOKEN START */
bool CScript::IsTokenScript() const
{
    int nType = 0;
    bool isOwner = false;
    int start = 0;
    return IsTokenScript(nType, isOwner, start);
}

bool CScript::IsTokenScript(int& nType, bool& isOwner) const
{
    int start = 0;
    return IsTokenScript(nType, isOwner, start);
}

bool CScript::IsTokenScript(int& nType, bool& fIsOwner, int& nStartingIndex) const
{
    if (this->size() > 31) {
        if ((*this)[25] == OP_YAC_TOKEN) { // OP_YAC_TOKEN is always in the 25 index of the script if it exists
            int index = -1;
            if ((*this)[27] == YAC_Y) { // Check to see if YAC starts at 27 ( this->size() < 105)
                if ((*this)[28] == YAC_A)
                    if ((*this)[29] == YAC_C)
                        index = 30;
            } else {
                if ((*this)[28] == YAC_Y) // Check to see if YAC starts at 28 ( this->size() >= 105)
                    if ((*this)[29] == YAC_A)
                        if ((*this)[30] == YAC_C)
                            index = 31;
            }

            if (index > 0) {
                nStartingIndex = index + 1; // Set the index where the token data begins. Use to serialize the token data into token objects
                if ((*this)[index] == YAC_T) { // Transfer first anticipating more transfers than other tokens operations
                    nType = TX_TRANSFER_TOKEN;
                    return true;
                } else if ((*this)[index] == YAC_Q && this->size() > 39) {
                    nType = TX_NEW_TOKEN;
                    fIsOwner = false;
                    return true;
                } else if ((*this)[index] == YAC_O) {
                    nType = TX_NEW_TOKEN;
                    fIsOwner = true;
                    return true;
                } else if ((*this)[index] == YAC_R) {
                    nType = TX_REISSUE_TOKEN;
                    return true;
                }
            }
        }
    }
    return false;
}


bool CScript::IsNewToken() const
{

    int nType = 0;
    bool fIsOwner = false;
    if (IsTokenScript(nType, fIsOwner))
        return !fIsOwner && nType == TX_NEW_TOKEN;

    return false;
}

bool CScript::IsOwnerToken() const
{
    int nType = 0;
    bool fIsOwner = false;
    if (IsTokenScript(nType, fIsOwner))
        return fIsOwner && nType == TX_NEW_TOKEN;

    return false;
}

bool CScript::IsReissueToken() const
{
    int nType = 0;
    bool fIsOwner = false;
    if (IsTokenScript(nType, fIsOwner))
        return nType == TX_REISSUE_TOKEN;

    return false;
}

bool CScript::IsTransferToken() const
{
    int nType = 0;
    bool fIsOwner = false;
    if (IsTokenScript(nType, fIsOwner))
        return nType == TX_TRANSFER_TOKEN;

    return false;
}
/** YAC_TOKEN END */

bool CScript::HasCanonicalPushes() const
{
    const_iterator pc = begin();
    while (pc < end())
    {
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!GetOp(pc, opcode, data))
            return false;
        if (opcode > OP_16)
            continue;
        if (opcode < OP_PUSHDATA1 && opcode > OP_0 && (data.size() == 1 && data[0] <= 16))
            // Could have used an OP_n code, rather than a 1-byte push.
            return false;
        if (opcode == OP_PUSHDATA1 && data.size() < OP_PUSHDATA1)
            // Could have used a normal n-byte push, rather than OP_PUSHDATA1.
            return false;
        if (opcode == OP_PUSHDATA2 && data.size() <= 0xFF)
            // Could have used an OP_PUSHDATA1.
            return false;
        if (opcode == OP_PUSHDATA4 && data.size() <= 0xFFFF)
            // Could have used an OP_PUSHDATA2.
            return false;
    }
    return true;
}

void CScript::SetDestination(const CTxDestination& dest)
{
    boost::apply_visitor(CScriptVisitor(this), dest);
}

void CScript::SetMultisig(int nRequired, const std::vector<CKey>& keys)
{
    this->clear();

    *this << EncodeOP_N(nRequired);
    BOOST_FOREACH(const CKey& key, keys)
        *this << key.GetPubKey();
    *this << EncodeOP_N((int)(keys.size())) << OP_CHECKMULTISIG;
}

void CScript::SetCltvP2SH(uint32_t nLockTime, const CPubKey& pubKey)
{
    this->clear();

    *this << (CScriptNum)nLockTime;
    *this << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
	*this << pubKey << OP_CHECKSIG;
}

void CScript::SetCltvP2PKH(uint32_t nLockTime, const CKeyID &keyID)
{
    this->clear();

    *this << (CScriptNum)nLockTime;
    *this << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    *this  << OP_DUP << OP_HASH160 << keyID << OP_EQUALVERIFY << OP_CHECKSIG;
}

void CScript::SetCsvP2SH(::uint32_t nSequence, const CPubKey& pubKey)
{
    this->clear();

    *this << (CScriptNum)nSequence;
    *this << OP_CHECKSEQUENCEVERIFY << OP_DROP;
    *this << pubKey << OP_CHECKSIG;
}

void CScript::SetCsvP2PKH(::uint32_t nSequence, const CKeyID &keyID)
{
    this->clear();

    *this << (CScriptNum)nSequence;
    *this << OP_CHECKSEQUENCEVERIFY << OP_DROP;
    *this  << OP_DUP << OP_HASH160 << keyID << OP_EQUALVERIFY << OP_CHECKSIG;
}

bool CScript::IsUnspendable() const
{
    CAmount nAmount;
    return (size() > 0 && *begin() == OP_RETURN) || (size() > 0 && *begin() == OP_YAC_TOKEN) || (size() > MAX_SCRIPT_SIZE) || (GetTokenAmountFromScript(*this, nAmount) && nAmount == 0);
}

CScriptID CScript::GetID() const
{
    return CScriptID(Hash160(*this));
}
//!--------------------------------------------------------------------------------------------------------------------------!//
//! These are needed because script.h and script.cpp do not have access to tokens.h and tokens.cpp functions. This is
//! because the make file compiles them at different times. The script files are compiled with other
//! consensus files, and token files are compiled with core files.

//! Used to check if a token script contains zero tokens. Is so, it should be unspendable
bool GetTokenAmountFromScript(const CScript& script, CAmount& nAmount)
{
    // Placeholder strings that will get set if you successfully get the transfer or token from the script
    std::string address = "";
    std::string tokenName = "";

    int nType = 0;
    bool fIsOwner = false;
    if (!script.IsTokenScript(nType, fIsOwner)) {
        return false;
    }

    txnouttype type = txnouttype(nType);

    // Get the New Token or Transfer Token from the scriptPubKey
    if (type == TX_NEW_TOKEN && !fIsOwner) {
        if (AmountFromNewTokenScript(script, nAmount)) {
            return true;
        }
    } else if (type == TX_TRANSFER_TOKEN) {
        if (AmountFromTransferScript(script, nAmount)) {
            return true;
        }
    } else if (type == TX_NEW_TOKEN && fIsOwner) {
            nAmount = OWNER_TOKEN_AMOUNT;
            return true;
    } else if (type == TX_REISSUE_TOKEN) {
        if (AmountFromReissueScript(script, nAmount)) {
            return true;
        }
    }

    return false;
}

bool ScriptNewToken(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner =false;
    if (scriptPubKey.IsTokenScript(nType, fIsOwner, nStartingIndex)) {
        return nType == TX_NEW_TOKEN && !fIsOwner;
    }

    return false;
}

bool ScriptTransferToken(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner =false;
    if (scriptPubKey.IsTokenScript(nType, fIsOwner, nStartingIndex)) {
        return nType == TX_TRANSFER_TOKEN;
    }

    return false;
}

bool ScriptReissueToken(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner =false;
    if (scriptPubKey.IsTokenScript(nType, fIsOwner, nStartingIndex)) {
        return nType == TX_REISSUE_TOKEN;
    }

    return false;
}


bool AmountFromNewTokenScript(const CScript& scriptPubKey, CAmount& nAmount)
{
    int nStartingIndex = 0;
    if (!ScriptNewToken(scriptPubKey, nStartingIndex))
        return false;

    std::vector<unsigned char> vchNewToken;
    vchNewToken.insert(vchNewToken.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssToken(vchNewToken, SER_NETWORK, PROTOCOL_VERSION);

    CNewToken tokenNew;
    try {
        ssToken >> tokenNew;
    } catch(std::exception& e) {
        std::cout << "Failed to get the token from the stream: " << e.what() << std::endl;
        return false;
    }

    nAmount = tokenNew.nAmount;
    return true;
}

bool AmountFromTransferScript(const CScript& scriptPubKey, CAmount& nAmount)
{
    int nStartingIndex = 0;
    if (!ScriptTransferToken(scriptPubKey, nStartingIndex))
        return false;

    std::vector<unsigned char> vchToken;
    vchToken.insert(vchToken.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssToken(vchToken, SER_NETWORK, PROTOCOL_VERSION);

    CTokenTransfer token;
    try {
        ssToken >> token;
    } catch(std::exception& e) {
        std::cout << "Failed to get the token from the stream: " << e.what() << std::endl;
        return false;
    }

    nAmount = token.nAmount;
    return true;
}

bool AmountFromReissueScript(const CScript& scriptPubKey, CAmount& nAmount)
{
    int nStartingIndex = 0;
    if (!ScriptReissueToken(scriptPubKey, nStartingIndex))
        return false;

    std::vector<unsigned char> vchNewToken;
    vchNewToken.insert(vchNewToken.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssToken(vchNewToken, SER_NETWORK, PROTOCOL_VERSION);

    CReissueToken token;
    try {
        ssToken >> token;
    } catch(std::exception& e) {
        std::cout << "Failed to get the token from the stream: " << e.what() << std::endl;
        return false;
    }

    nAmount = token.nAmount;
    return true;
}
//!--------------------------------------------------------------------------------------------------------------------------!//

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
