// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include "compressor.h" 
#include "consensus/consensus.h"
#include "primitives/transaction.h"
#include "serialize.h"

/** Undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is be compatible with older versions which expect to see
 *  the transaction version there.
 */
class TxInUndoSerializer
{
    const Coin* txout;

public:
    template<typename Stream>
    void Serialize(Stream &s) const {
        ::Serialize(s, VARINT(txout->nHeight * 2 + (txout->fCoinBase ? 1 : 0)));
        ::Serialize(s, VARINT(txout->nTime));
        if (txout->nHeight < Params().GetConsensus().HeliopolisHardforkHeight) {
            // ppcoin flags
            unsigned int nFlag = txout->fCoinStake? 1 : 0;
            ::Serialize(s, VARINT(nFlag));
        }
        if (txout->nHeight > 0) {
            // Required to maintain compatibility with older undo format.
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, CTxOutCompressor(REF(txout->out)));
    }

    TxInUndoSerializer(const Coin* coin) : txout(coin) {}
};

class TxInUndoDeserializer
{
    Coin* txout;

public:
    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout->nHeight = nCode / 2;
        txout->fCoinBase = nCode & 1;
        ::Unserialize(s, VARINT(txout->nTime));
        if (txout->nHeight < Params().GetConsensus().HeliopolisHardforkHeight) {
            // ppcoin flags
            unsigned int nFlag = 0;
            ::Unserialize(s, VARINT(nFlag));
            txout->fCoinStake = nFlag & 1;
        }
        if (txout->nHeight > 0) {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, REF(CTxOutCompressor(REF(txout->out))));
    }

    TxInUndoDeserializer(Coin* coin) : txout(coin) {}
};

static const size_t MIN_TRANSACTION_INPUT_WEIGHT = ::GetSerializeSize(CTxIn(), SER_NETWORK, PROTOCOL_VERSION);

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    template <typename Stream>
    void Serialize(Stream& s) const {
        // TODO: avoid reimplementing vector serializer
        uint64_t count = vprevout.size();
        ::Serialize(s, COMPACTSIZE(REF(count)));
        for (const auto& prevout : vprevout) {
            ::Serialize(s, REF(TxInUndoSerializer(&prevout)));
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        // TODO: avoid reimplementing vector deserializer
        uint64_t count = 0;
        ::Unserialize(s, COMPACTSIZE(count));

        // Temporary variable to hold the first deserialized Coin
        Coin firstCoin;

        if (count > 0) {
            // Read the first Coin object to determine the block height
            ::Unserialize(s, REF(TxInUndoDeserializer(&firstCoin)));
            uint32_t blockHeight = firstCoin.nHeight;  // Extract block height

            // Dynamically compute MAX_INPUTS_PER_BLOCK based on the extracted height
            size_t maxInputsPerBlock = GetMaxSize(MAX_BLOCK_SIZE, blockHeight) / MIN_TRANSACTION_INPUT_WEIGHT;

            // Validate the number of undo records
            if (count > maxInputsPerBlock) {
                throw std::ios_base::failure("Too many input undo records for block height " + std::to_string(blockHeight));
            }

            // Reserve space and add the first coin
            vprevout.resize(count);
            vprevout[0] = std::move(firstCoin);
        } else {
            vprevout.resize(count);
        }

        // Deserialize the remaining undo records
        for (size_t i = 1; i < count; i++) {
            ::Unserialize(s, REF(TxInUndoDeserializer(&vprevout[i])));
        }
    }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vtxundo);
    }
};

#endif // BITCOIN_UNDO_H
