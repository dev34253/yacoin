Description
------------

This directory contains data-driven tests for various aspects of Bitcoin.

`stake_modifier_blocks.raw` holds the hash and time of the YaCoin mainnet blocks 0 to 15000,
read from a mainnet node over RPC (`getblockhash`, `getblock`). Each block is 36 bytes: the hash in
its internal byte order (the reverse of the hex that RPC shows), then the time as a 4-byte
little-endian number. `kernel_tests` computes the stake modifiers of these blocks.

License
--------

The data files in this directory are distributed under the MIT software
license, see the accompanying file COPYING or
http://www.opensource.org/licenses/mit-license.php.

