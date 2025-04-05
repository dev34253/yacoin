// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include "script_error.h"
#include "primitives/transaction.h"

#include <vector>
#include <stdint.h>
#include <string>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE      = 0,
    SCRIPT_VERIFY_P2SH      = (1U << 0), // evaluate P2SH (BIP16) subscripts
    SCRIPT_VERIFY_STRICTENC = (1U << 1), // enforce strict conformance to DER and SEC2 for signatures and pubkeys
    SCRIPT_VERIFY_LOW_S     = (1U << 2), // enforce low S values in signatures (depends on STRICTENC)
    SCRIPT_VERIFY_NOCACHE   = (1U << 3), // do not store results in signature cache (but do query it)
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4), // verify dummy stack item consumed by CHECKMULTISIG is of zero-length

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),
};

uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);

bool CheckSig(std::vector<unsigned char> vchSig, const std::vector<unsigned char> &vchPubKey, const CScript &scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, int flags);
bool CheckLockTime(const CTransaction& txTo, unsigned int nIn, const CScriptNum& nLockTime);
bool CheckSequence(const CTransaction& txTo, unsigned int nIn, const CScriptNum& nSequence);

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType);

bool IsCanonicalPubKey(const std::vector<unsigned char> &vchPubKey, unsigned int flags);
bool IsCanonicalSignature(const std::vector<unsigned char> &vchSig, unsigned int flags);

#endif // BITCOIN_SCRIPT_INTERPRETER_H
