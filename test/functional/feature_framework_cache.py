#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Self-checks of the framework's block cache, one per chain.

- A regtest script without setup_clean_chain starts its nodes from the
  regtest cache in <cachedir>/regtest/: 40 blocks, 41 after the set-up, on
  chain regtest, with the chain's files in <datadir>/regtest.
- create_cache.py builds the cache of each chain, <cachedir>/main/ and
  <cachedir>/regtest/, both with epochinterval=20; a main node started on a
  copy of the main cache has its 40 blocks on chain main.
"""

import os
import shutil
import subprocess
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    get_datadir_path,
    initialize_datadir,
)


def read_lines(path):
    with open(path, encoding='utf8') as f:
        return f.read().splitlines()


class FrameworkCacheTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def run_test(self):
        self.test_regtest_cache()
        self.test_create_cache()

    def test_regtest_cache(self):
        self.log.info("The nodes start from the regtest cache: 40 blocks, 41 after the set-up")
        for node in self.nodes:
            info = node.gettimechaininfo()
            assert_equal((info['chain'], info['blocks']), ('regtest', 41))
            assert os.path.isdir(os.path.join(node.datadir, 'regtest', 'blocks'))
            assert not os.path.exists(os.path.join(node.datadir, 'blocks'))
            assert_equal(read_lines(os.path.join(node.datadir, 'yacoin.conf'))[0], 'regtest=1')

        self.log.info("The regtest cache is in <cachedir>/regtest/")
        self.check_cache(self.options.cachedir, 'regtest')

    def check_cache(self, cachedir, chain):
        """The cache node of chain in cachedir holds its chain's blocks and was
        set up with epochinterval=20."""
        cache_node = get_datadir_path(os.path.join(cachedir, chain), 0)
        conf = read_lines(os.path.join(cache_node, 'yacoin.conf'))
        assert 'epochinterval=20' in conf, conf
        if chain == 'main':
            assert os.path.isdir(os.path.join(cache_node, 'blocks'))
            assert 'regtest=1' not in conf, conf
        else:
            assert os.path.isdir(os.path.join(cache_node, chain, 'blocks'))
            assert not os.path.exists(os.path.join(cache_node, 'blocks'))
            assert_equal(conf[0], '%s=1' % chain)

    def test_create_cache(self):
        self.log.info("create_cache.py builds the cache of each chain")
        # The cache node uses the ports of node 0.
        self.stop_nodes()
        cachedir = os.path.join(self.options.tmpdir, 'cache')
        script = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'create_cache.py')
        subprocess.run([sys.executable, script,
                        '--cachedir=' + cachedir,
                        '--tmpdir=' + os.path.join(self.options.tmpdir, 'create_cache'),
                        '--portseed=%d' % self.options.port_seed,
                        '--configfile=' + self.options.configfile],
                       stdout=subprocess.DEVNULL, check=True)
        assert_equal(sorted(os.listdir(cachedir)), ['main', 'regtest'])
        for chain in ('main', 'regtest'):
            self.check_cache(cachedir, chain)

        self.log.info("A main node on a copy of the main cache has its 40 blocks on chain main")
        main_dir = os.path.join(self.options.tmpdir, 'main')
        shutil.copytree(get_datadir_path(os.path.join(cachedir, 'main'), 0), get_datadir_path(main_dir, 0))
        initialize_datadir(main_dir, 0, 'main')
        self.nodes.append(TestNode(0, get_datadir_path(main_dir, 0), chain='main', rpchost=None,
                                   timewait=self.rpc_timeout, bitcoind=self.options.bitcoind,
                                   bitcoin_cli=self.options.bitcoincli, coverage_dir=None,
                                   cwd=self.options.tmpdir, extra_conf=["bind=127.0.0.1"], extra_args=[]))
        main_node = self.nodes[-1]
        main_node.start()
        main_node.wait_for_rpc_connection()
        info = main_node.gettimechaininfo()
        assert_equal((info['chain'], info['blocks']), ('main', 40))
        assert os.path.isfile(main_node.debug_log_path)
        assert_equal(main_node.debug_log_path, os.path.join(main_node.datadir, 'debug.log'))


if __name__ == '__main__':
    FrameworkCacheTest().main()
