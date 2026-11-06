// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// One address index record of the block tree database (txdb.cpp): the input
// is the record's key followed by its value, read as CDBWrapper reads them
// (disk serialisation, the client version). The key's first byte chooses the
// record: 'a' (address index: CAddressIndexKey, the amount) or 'u' (unspent
// outputs: CAddressUnspentKey, CAddressUnspentValue). The key bytes are also
// read as each of the keys the index lookups seek to (the iterator keys of
// addressindex.h). An input that starts with another byte is ignored, and a
// read past the end of the input ends the read.

#include "test/fuzz/fuzz.h"
#include "test/fuzz/fuzz_util.h"

#include "addressindex.h"
#include "amount.h"
#include "clientversion.h"
#include "serialize.h"
#include "streams.h"

#include <ios>
#include <utility>

namespace {
/** Reads one T from a stream of the whole input */
template <typename T>
void ReadKey(const FuzzBufferType& buffer)
{
    CDataStream ds(buffer, SER_DISK, CLIENT_VERSION);
    try {
        std::pair<char, T> key;
        ds >> key;
    } catch (const std::ios_base::failure&) {
    }
}
} // namespace

FUZZ_TARGET(addressindex_deserialize)
{
    if (buffer.empty() || buffer.size() > MAX_FUZZ_INPUT_SIZE) return;
    if (buffer[0] != 'a' && buffer[0] != 'u') return;
    CDataStream ds(buffer, SER_DISK, CLIENT_VERSION);
    try {
        if (buffer[0] == 'a') {
            std::pair<char, CAddressIndexKey> key;
            CAmount nValue;
            ds >> key >> nValue;
        } else {
            std::pair<char, CAddressUnspentKey> key;
            CAddressUnspentValue value;
            ds >> key >> value;
        }
    } catch (const std::ios_base::failure&) {
    }
    ReadKey<CAddressIndexIteratorKey>(buffer);
    ReadKey<CAddressIndexIteratorTokenKey>(buffer);
    ReadKey<CAddressIndexIteratorHeightKey>(buffer);
}
