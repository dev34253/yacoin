// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_SCRIPT_ISMINE_H
#define YACOIN_SCRIPT_ISMINE_H

#include "script/standard.h"

#include <stdint.h>

class CKeyStore;
class CScript;

/** IsMine() return codes */
enum isminetype
{
    MINE_NO = 0,
    MINE_WATCH_ONLY = 1,
    MINE_SPENDABLE = 2,
    MINE_ALL = MINE_WATCH_ONLY | MINE_SPENDABLE
};

/** used for bitflags of isminetype */
typedef uint8_t isminefilter;

/* isInvalid becomes true when the script is found invalid by consensus or policy. This will terminate the recursion
 * and return a ISMINE_NO immediately, as an invalid script should never be considered as "mine". This is needed as
 * different SIGVERSION may have different network rules. Currently the only use of isInvalid is indicate uncompressed
 * keys in SIGVERSION_WITNESS_V0 script, but could also be used in similar cases in the future
 */
isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey);
isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest);

#endif // YACOIN_SCRIPT_ISMINE_H
