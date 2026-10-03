Description
------------

This directory contains data-driven tests for various aspects of Bitcoin.

`*.json` files are embedded into `test_bitcoin` as byte arrays
(`*.json.h`); `*.json.xz` files are unpacked with `xz` at build time and
embedded as strings (`*.json.xz.h`), see `src/Makefile.test.include`.
`bignum_vectors.json.xz` holds the `CBigNum` golden vectors (task P0-13;
format and regeneration in `src/test/README.md`); never edit it by hand.
`reward_vectors.json` is the reward and block-size golden table (task
P0-46), written by `contrib/testing/reward_vectors.py`; never edit it by
hand either. `header_hash_vectors.json` holds the block-header hash
known answers (task P0-19), written by
`contrib/testing/header_hash_vectors.py`; never edit it by hand.
`*.csv` files are embedded as strings (`*.csv.h`).
`consensus_dump_mainnet_{early,pos,fork}.csv` are three ranges of the
mainnet consensus value dump (task P0-08; heights 1–60, 500,040–500,099 and
1,889,990–1,890,010), written by the RPC `dumpconsensusvalues` on the
P0-08 snapshot (the `client=` line names a `-dirty` build of the P0-08
branch); format in `src/test/README.md`. Regenerate them only with the RPC,
never by hand.

License
--------

The data files in this directory are distributed under the MIT software
license, see the accompanying file COPYING or
http://www.opensource.org/licenses/mit-license.php.

