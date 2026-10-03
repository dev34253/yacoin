// Copyright (c) 2026 The Yacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Reader for the per-block consensus value dump (task P0-08).
//
// Parses the CSV written by the hidden RPC `dumpconsensusvalues`
// (src/consensusdump.h) back into ConsensusDumpRow, strictly: every field
// is checked for syntax and range. Test-only. Format: src/test/README.md,
// "Consensus value dump".
#ifndef YACOIN_TEST_CONSENSUS_DUMP_READER_H
#define YACOIN_TEST_CONSENSUS_DUMP_READER_H

#include "consensusdump.h"

#include <istream>
#include <map>
#include <string>
#include <vector>

namespace consensus_dump {

struct ConsensusDump {
    /** key=value pairs of the comment lines before the header (format,
     *  version, client, fork_height, ...). */
    std::map<std::string, std::string> meta;
    std::vector<ConsensusDumpRow> rows;
    /** True when the "# end rows=N end_hash=H" trailer was present (and
     *  matched the rows read). Excerpts cut from a dump have no trailer. */
    bool fComplete = false;
};

/**
 * Read a dump. Requires the format line ("# format=yacoin-consensus-dump
 * version=1") as the first non-empty line, then optional "# key=value ..."
 * lines, the header line naming every column of format version 1 (in any
 * order; unknown columns are ignored), then rows with strictly ascending
 * heights. Blank lines and CR line ends are accepted. A trailer, if
 * present, must match the rows read and be the last line. Throws
 * std::runtime_error("<name>:<line>: <reason>") on any error.
 */
ConsensusDump ReadConsensusDump(std::istream& in, const std::string& name = "<stream>");

/** ReadConsensusDump on a file (uncompressed; decompress zstd dumps first). */
ConsensusDump ReadConsensusDumpFile(const std::string& path);

} // namespace consensus_dump

#endif // YACOIN_TEST_CONSENSUS_DUMP_READER_H
