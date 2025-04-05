// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/sign.h"

#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "uint256.h"

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for(const valtype& v: values)
        result << v;
    return result;
}

bool Sign1(const CKeyID& address, const CKeyStore& keystore, uint256 hash, int nHashType, CScript& scriptSigRet)
{
    CKey key;
    if (!keystore.GetKey(address, key))
        return false;

    std::vector<unsigned char> vchSig;
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;

    return true;
}

bool SignN(const std::vector<valtype>& multisigdata, const CKeyStore& keystore,
           uint256 hash, int nHashType, CScript& scriptSigRet) {
  int nSigned = 0;
#ifdef _MSC_VER
    bool
        fTest = false;
    if( multisigdata.empty() )  //trouble
        {
        fTest = true;   // need a fix here!!!
        return false;   //???
        }
#endif
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; ++i)
    {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
            ++nSigned;
    }
    return nSigned==nRequired;
}

bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CTransaction& txTo, unsigned int nIn, int nHashType)
{
    Yassert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];

    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    uint256 hash = SignatureHash(fromPubKey, txTo, nIn, nHashType);

    txnouttype whichType;
    if (!Solver(keystore, fromPubKey, hash, nHashType, txin.scriptSig, whichType))
        return false;

    if (whichType == TX_SCRIPTHASH)
    {
        // Solver returns the subscript that need to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        // Important note: Until this step, we only have the redeemscript stored in txin.scriptSig. We still need signature for the public key
        // specified in the redeemscript. Below steps do that for us.
        CScript subscript = txin.scriptSig;

        // Recompute txn hash using subscript in place of scriptPubKey:
        uint256 hash2 = SignatureHash(subscript, txTo, nIn, nHashType);

        txnouttype subType;
        bool fSolved =
            Solver(keystore, subscript, hash2, nHashType, txin.scriptSig, subType) && subType != TX_SCRIPTHASH; // IMPORTANT HERE
        // Append serialized subscript whether or not it is completely signed:
        txin.scriptSig << static_cast<valtype>(subscript); // append redeemscript to scriptSig
        if (!fSolved) return false;
    }

    // Test solution
    ScriptError serror = SCRIPT_ERR_OK;
    return VerifyScript(txin.scriptSig, fromPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txTo, nIn), &serror);
}

bool SignSignature(const CKeyStore &keystore, const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType)
{
    Yassert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    Yassert(txin.prevout.COutPointGet_n() < txFrom.vout.size());
    Yassert(txin.prevout.COutPointGetHash() == txFrom.GetHash());
    const CTxOut& txout = txFrom.vout[txin.prevout.COutPointGet_n()]; // Get UTXO

    return SignSignature(keystore, txout.scriptPubKey, txTo, nIn, nHashType);
}

bool SignSignature(const CKeyStore &keystore, const CTxOut& txOutFrom, CTransaction& txTo, unsigned int nIn, int nHashType)
{
    return SignSignature(keystore, txOutFrom.scriptPubKey, txTo, nIn, nHashType);
}

static CScript CombineMultisig(CScript scriptPubKey, const BaseSignatureChecker& checker,
                               const std::vector<valtype>& vSolutions,
                               std::vector<valtype>& sigs1, std::vector<valtype>& sigs2)
{
    // Combine all the signatures we've got:
    std::set<valtype> allsigs;
    for(const valtype& v : sigs1)
    {
        if (!v.empty())
            allsigs.insert(v);
    }
    for(const valtype& v : sigs2)
    {
        if (!v.empty())
            allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    Yassert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = (unsigned int)(vSolutions.size()-2);
    std::map<valtype, valtype> sigs;
    for(const valtype& sig : allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype& pubkey = vSolutions[i+1];
            if (sigs.count(pubkey))
                continue; // Already got a sig for this pubkey

            if (checker.CheckSig(sig, pubkey, scriptPubKey))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
    CScript result; result << OP_0; // pop-one-too-many workaround
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i+1]))
        {
            result << sigs[vSolutions[i+1]];
            ++nSigsHave;
        }
    }
    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
        result << OP_0;

    return result;
}

static CScript CombineSignatures(CScript scriptPubKey, const BaseSignatureChecker& checker,
                                 const txnouttype txType, const std::vector<valtype>& vSolutions,
                                 std::vector<valtype>& sigs1, std::vector<valtype>& sigs2)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.size() >= sigs2.size())
            return PushAll(sigs1);
        return PushAll(sigs2);
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.empty() || sigs1[0].empty())
            return PushAll(sigs2);
        return PushAll(sigs1);
    case TX_SCRIPTHASH:
        if (sigs1.empty() || sigs1.back().empty())
            return PushAll(sigs2);
        else if (sigs2.empty() || sigs2.back().empty())
            return PushAll(sigs1);
        else
        {
            // Recur to combine:
            valtype spk = sigs1.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            std::vector<std::vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.pop_back();
            sigs2.pop_back();
            CScript result = CombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2);
            result << spk;
            return result;
        }
    case TX_MULTISIG:
        return CombineMultisig(scriptPubKey, checker, vSolutions, sigs1, sigs2);
    }

    return CScript();
}

CScript CombineSignatures(CScript scriptPubKey, const BaseSignatureChecker& checker,
                          const CScript& scriptSig1, const CScript& scriptSig2)
{
    txnouttype txType;
    std::vector<std::vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

    std::vector<valtype> stack1;
    EvalScript(stack1, scriptSig1, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker());
    std::vector<valtype> stack2;
    EvalScript(stack2, scriptSig2, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker());

    return CombineSignatures(scriptPubKey, checker, txType, vSolutions, stack1, stack2);
}
