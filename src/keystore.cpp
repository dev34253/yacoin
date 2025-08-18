// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "keystore.h"

#include "base58.h"
#include "script/standard.h"

extern bool fWalletUnlockMintOnly;
using std::vector;

bool CKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key))
        return false;
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CBasicKeyStore::GetSecret(const CScript& scriptPubKey, CKeyingMaterial& vchSecret, bool &fCompressed, txnouttype& whichTypeRet, CScript& subscript) const
{
    vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
#ifdef _MSC_VER
    bool
        fTest = false;
    if( vSolutions.empty() )
        {       // one can't technically access vSolutions[ 0 ]
        fTest = true;
        return false;
        }
#endif
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:  // this is not in 0.4.4 code
        return false;
    case TX_PUBKEY:
    case TX_CLTV_P2SH:
    case TX_CSV_P2SH:
        keyID = CPubKey(vSolutions[0]).GetID();
        break;
    case TX_NEW_TOKEN:
    case TX_REISSUE_TOKEN:
    case TX_TRANSFER_TOKEN:
    case TX_CLTV_P2PKH:
    case TX_CSV_P2PKH:
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        break;
    case TX_SCRIPTHASH:
    {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript tempScript;
        if (GetCScript(scriptID, subscript)) {
            if (GetSecret(subscript, vchSecret, fCompressed, whichTypeRet, tempScript)) {
                return true;
            }
        }
        return false;
    }
    case TX_MULTISIG:
        return false;
    }

    CKey key;
    if (!GetKey(keyID, key))
        return false;
    CKeyingMaterial keySecret(key.begin(), key.end());
    vchSecret = keySecret;
    return true;
}

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}


bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);

    CTxDestination address;
    if (ExtractDestination(dest, address)) {
        CKeyID keyID;
        CBitcoinAddress(address).GetKeyID(keyID);
        if (HaveKey(keyID))
            return false;
    }

    setWatchOnly.insert(dest);
    return true;
}


bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}
