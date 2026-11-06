// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// One record of the token database (CTokensDB, tokens/tokendb.cpp): the input
// is the record's key followed by its value, read as CDBWrapper reads them
// (disk serialisation, the client version). The key's first byte, the record
// kind of tokendb.cpp's key layout, chooses the types; an input that starts
// with another byte is ignored, and a read past the end of the input ends the
// run.

#include "test/fuzz/fuzz.h"
#include "test/fuzz/fuzz_util.h"

#include "amount.h"
#include "clientversion.h"
#include "serialize.h"
#include "streams.h"
#include "tokens/tokendb.h"
#include "tokens/tokentypes.h"
#include "uint256.h"

#include <ios>
#include <map>
#include <string>
#include <utility>
#include <vector>

FUZZ_TARGET(tokendb_record_deserialize)
{
    if (buffer.empty() || buffer.size() > MAX_FUZZ_INPUT_SIZE) return;
    CDataStream ds(buffer, SER_DISK, CLIENT_VERSION);
    try {
        switch (buffer[0]) {
        case 'A': { // token name -> token data, height and block hash
            std::pair<char, std::string> key;
            CDatabasedTokenData data;
            ds >> key >> data;
            break;
        }
        case 'B':   // token name and address -> quantity
        case 'C': { // address and token name -> quantity
            std::pair<char, std::pair<std::string, std::string> > key;
            CAmount nQuantity;
            ds >> key >> nQuantity;
            break;
        }
        case 'U': { // block hash -> the block's token undo data
            std::pair<char, uint256> key;
            std::vector<std::pair<std::string, CBlockTokenUndo> > undo;
            ds >> key >> undo;
            break;
        }
        case 'Z': { // the reissues in the mempool
            char key;
            std::map<std::string, uint256> reissues;
            ds >> key >> reissues;
            break;
        }
        default:
            break;
        }
    } catch (const std::ios_base::failure&) {
    }
}
