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
hand either.

License
--------

The data files in this directory are distributed under the MIT software
license, see the accompanying file COPYING or
http://www.opensource.org/licenses/mit-license.php.

