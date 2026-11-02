#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the stop RPC.

- stop while another connection waits in waitfornewblock: the waiting call
  returns the current tip and the node exits with code 0;
- stop accepts one (ignored) argument and rejects two;
- stop while the Tor control thread has not yet entered its event loop: the
  node does not exit today (MG-075), as the interrupt sent before the loop
  runs is lost and shutdown waits for the thread for ever. The thread reads
  <datadir>/onion_private_key before its loop; made a FIFO, that file holds
  the thread there until the test opens it for writing, which the test does
  only after the node has logged that shutdown is in progress.

The node can shut down before it writes the reply to stop; such a stop counts
as sent (TestNode.send_stop) and the node must still exit. The reply text is
checked whenever it arrives.
"""

import errno
import os
from threading import Thread

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    get_rpc_proxy,
    wait_until,
)


class ShutdownTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        genesis = node.getbestblockhash()

        self.log.info("stop during waitfornewblock")
        rpc = get_rpc_proxy(node.url, 1, timeout=600, coveragedir=node.coverage_dir)
        rpc.getblockcount()  # open the connection
        result = {}

        def wait_for_block():
            try:
                result['block'] = rpc.waitfornewblock()
            except Exception as e:
                result['error'] = e
        waiter = Thread(target=wait_for_block)
        waiter.start()
        wait_until(lambda: len(node.getrpcinfo()['active_commands']) == 2)
        reply = self.stop_checked(node)
        node.wait_until_stopped()
        waiter.join(10)
        assert not waiter.is_alive()
        if reply is None:
            # The HTTP server stopped before it wrote the reply to stop; the
            # waiting call's reply comes later and is lost the same way.
            self.log.warning("Waiting call not checked: %r", result)
        else:
            assert_equal(result.get('block'), {'hash': genesis, 'height': 0})

        self.log.info("stop with one argument")
        self.start_node(0)
        self.stop_checked(node, 1)
        node.wait_until_stopped()

        self.log.info("stop with two arguments")
        self.start_node(0)
        assert_raises_rpc_error(-1, "stop\n\nStop Yacoin server.", node.stop, 1, 2)

        self.log.info("stop while the Tor control thread is still starting")
        self.stop_node(0)
        key_file = os.path.join(node.datadir, 'onion_private_key')
        os.mkfifo(key_file)
        self.start_node(0)
        log_start = len(self.debug_log(node))
        self.stop_checked(node)
        # Logged after the Tor control thread has been interrupted.
        wait_until(lambda: "Shutdown: In progress..." in self.debug_log(node)[log_start:])
        writer = []

        def open_writer():
            try:
                writer.append(os.open(key_file, os.O_WRONLY | os.O_NONBLOCK))
                return True
            except OSError as e:
                if e.errno != errno.ENXIO:  # ENXIO: the thread has not opened the file yet
                    raise
                return False
        wait_until(open_writer)
        os.close(writer[0])  # the thread reads an empty key and enters its event loop
        self.known_failure("MG-075", lambda: node.wait_until_stopped(timeout=10), "not true after")
        node.process.kill()
        node.wait_for_exit()
        os.remove(key_file)

    def stop_checked(self, node, *args):
        """Send stop; check its reply if it arrives (see TestNode.send_stop).

        Returns the reply, or None if it was lost."""
        reply = node.send_stop(*args)
        if reply is not None:
            assert_equal(reply, "Yacoin server stopping")
        return reply

    def debug_log(self, node):
        with open(os.path.join(node.datadir, 'debug.log'), encoding='utf-8') as f:
            return f.read()


if __name__ == '__main__':
    ShutdownTest().main()
