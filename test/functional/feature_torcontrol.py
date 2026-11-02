#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Tor control thread's start, reconnect and stop.

- A node with the framework's yacoin.conf starts no Tor control: the
  framework writes listenonion=0 there.
- With that line removed (the node's default -listenonion) and -torcontrol
  pointing at a local port that refuses connections: the connection error,
  the reconnect timer, a second connection error after the timer, then a
  clean stop (exit code 0, "tor: Thread interrupt").
- With that line removed and -listen=0: -listenonion is set to 0 by the
  parameter interaction and no Tor control starts.
- An unparsable -torcontrol: the address error and the failed connection
  attempt are logged; the node still serves RPC and stops cleanly.

The framework's nodes run without Tor control because a node stopped before
its Tor control thread has entered its event loop can hang in shutdown. This
test removes the listenonion=0 line to test the node's default, and stops a
node whose thread runs an event loop only after the thread has logged a line
from inside that loop.
"""

import os
import re
import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    wait_until,
)

BIND = "-bind=127.0.0.1"
NO_ONION_LINE = "listenonion=0\n"
CONNECT_ERROR = "tor: Error connecting to Tor control socket"


class TorControlTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # The framework's bind=127.0.0.1 line is an init error with -listen=0;
        # the other starts get -bind=127.0.0.1 as an argument.
        self.bind_to_localhost_only = False
        self.extra_args = [[BIND]]

    def run_test(self):
        node = self.nodes[0]
        conf = os.path.join(node.datadir, 'yacoin.conf')

        self.log.info("Framework node: no Tor control")
        with open(conf, encoding='utf8') as f:
            assert NO_ONION_LINE in f.readlines()
        self.stop_node(0)
        assert_equal(self.tor_lines(self.debug_log()), [])

        with open(conf, encoding='utf8') as f:
            lines = f.readlines()
        with open(conf, 'w', encoding='utf8') as f:
            f.writelines(l for l in lines if l != NO_ONION_LINE)

        self.log.info("Default -listenonion, Tor control port refuses connections")
        # A TCP socket that is bound but not listening: connections to its
        # port are refused, and no other process can take the port meanwhile.
        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.bind(("127.0.0.1", 0))
        target = "127.0.0.1:%d" % closed.getsockname()[1]
        try:
            start = self.log_size()
            self.start_node(0, [BIND, "-torcontrol=" + target])
            # Both errors and the reconnect line are logged from inside the
            # thread's event loop; the second one after the reconnect timer
            # (1 s) fired.
            wait_until(lambda: self.debug_log(start).count(CONNECT_ERROR) >= 2, timeout=30)
            log = self.debug_log(start)
            first = log.index(CONNECT_ERROR)
            reconnect = log.index("tor: Not connected to Tor control port %s, trying to reconnect" % target)
            second = log.index(CONNECT_ERROR, first + 1)
            assert first < reconnect < second
            assert "tor: Re-initiating connection" not in log
            assert "tor: Initiating connection" not in log
            node.getblockcount()
            self.stop_node(0)
            assert "tor: Thread interrupt" in self.debug_log(start)
        finally:
            closed.close()

        self.log.info("-listen=0 turns Tor control off")
        start = self.log_size()
        self.start_node(0, ["-listen=0"])
        self.stop_node(0)
        log = self.debug_log(start)
        assert "parameter interaction: -listen=0 -> setting -listenonion=0" in log
        assert_equal(self.tor_lines(log), [])

        self.log.info("Unparsable -torcontrol")
        start = self.log_size()
        bad = "127.0.0.1:notaport"
        self.start_node(0, [BIND, "-torcontrol=" + bad])
        # Logged by the thread before its event loop, which then has no event
        # and returns at once: the stop below cannot be lost.
        wait_until(lambda: "tor: Initiating connection to Tor control port %s failed" % bad in self.debug_log(start), timeout=30)
        log = self.debug_log(start)
        assert "tor: Error parsing socket address %s" % bad in log
        assert CONNECT_ERROR not in log
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        assert "tor: Thread interrupt" in self.debug_log(start)

    def debug_log(self, start=0):
        """debug.log from byte offset start on."""
        with open(os.path.join(self.nodes[0].datadir, 'debug.log'), 'rb') as f:
            f.seek(start)
            return f.read().decode('utf-8')

    def log_size(self):
        return os.path.getsize(os.path.join(self.nodes[0].datadir, 'debug.log'))

    def tor_lines(self, log):
        """The Tor control lines: its own and its thread's start and exit."""
        return [l for l in log.splitlines() if re.search(r"(^| )tor: |torcontrol thread", l)]


if __name__ == '__main__':
    TorControlTest().main()
