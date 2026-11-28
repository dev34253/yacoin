// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SENDCOINSRECIPIENTRECORD_H
#define BITCOIN_QT_SENDCOINSRECIPIENTRECORD_H

#include "amount.h"
#include "serialize.h"

#include <string>

/**
 * The stored form of a SendCoinsRecipient (in saved receive requests), with
 * the fields in their stored order and without Qt types.
 * SendCoinsRecipient serialises through this struct.
 */
struct SendCoinsRecipientRecord
{
    int nVersion;
    std::string address;
    std::string label;
    CAmount amount;
    std::string message;

    SendCoinsRecipientRecord() : nVersion(0), amount(0) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // The two trailing strings are part of the stored layout; written
        // empty and not used when read.
        std::string reserved1;
        std::string reserved2;

        READWRITE(nVersion);
        READWRITE(address);
        READWRITE(label);
        READWRITE(amount);
        READWRITE(message);
        READWRITE(reserved1);
        READWRITE(reserved2);
    }
};

#endif // BITCOIN_QT_SENDCOINSRECIPIENTRECORD_H
