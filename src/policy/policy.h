// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_POLICY_POLICY_H
#define YACOIN_POLICY_POLICY_H

#include "consensus/consensus.h"
#include "feerate.h"
#include "script/script.h"

#include <string>

class CCoinsViewCache;
class CTxOut;

/** Default for -maxmempool, maximum megabytes of mempool memory usage */
static const unsigned int DEFAULT_MAX_MEMPOOL_SIZE = 300;
/** Maximum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 21;

// Strict verification:
//
// * force DER encoding;
// * force low S;
// * ensure that CHECKMULTISIG dummy argument is null.
static const unsigned int STRICT_FORMAT_FLAGS = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLDUMMY;

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
static const unsigned int MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH;

/**
 * Standard script verification flags that standard transactions will comply
 * with. However scripts violating these flags may still be present in valid
 * blocks and we must accept those blocks.
 */
static const unsigned int STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                         STRICT_FORMAT_FLAGS |
                                                         SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                         SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;

/** For convenience, standard but not mandatory verify flags. */
static const unsigned int STANDARD_NOT_MANDATORY_VERIFY_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS;

// Soft verifications, no extended signature format checkings
static const unsigned int SOFT_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS & ~STRICT_FORMAT_FLAGS;

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
// TODO: Support LOCKTIME_MEDIAN_TIME_PAST in future (affect consensus rule)
static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE;

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType);
/**
 * Check for standard transaction types
 * @return True if all outputs (scriptPubKeys) use only standard transaction forms
 */
bool IsStandardTx(const CTransaction& tx, std::string& reason);
/**
 * Check for standard transaction types
 * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
 * @return True if all inputs (scriptSigs) use only standard transaction forms
 */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
#endif // YACOIN_POLICY_POLICY_H
