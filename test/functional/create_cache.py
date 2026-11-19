#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Create the blockchain cache of each chain.

Creating a cache of the blockchain speeds up test execution when running
multiple functional tests. This helper script is executed by test_runner when multiple
tests are being run in parallel. It builds the cache of every chain a script
can choose (<cachedir>/main/ and <cachedir>/regtest/), so that no script
builds one while others run; with --cachechain=<chain> only the cache of that
chain.
"""

from test_framework.test_framework import CHAINS, BitcoinTestFramework

class CreateCache(BitcoinTestFramework):
    # Test network and test nodes are not required:

    def set_test_params(self):
        self.num_nodes = 0

    def add_options(self, parser):
        parser.add_argument("--cachechain", choices=CHAINS,
                            help="build the cache of this chain only (default: of every chain)")

    def setup_chain(self):
        for chain in [self.options.cachechain] if self.options.cachechain else CHAINS:
            self.log.info("Creating the cache of %s", chain)
            self.chain = chain
            self._initialize_chain()

    def setup_network(self):
        pass

    def run_test(self):
        pass

if __name__ == '__main__':
    CreateCache().main()
