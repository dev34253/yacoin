<img src="src/qt/res/icons/yacoin-128.png" alt="YACoin logo" width="128">

# YACoin

[![Yacoin multi platform build](https://github.com/dev34253/yacoin/actions/workflows/yacoinbuildmultiplatform.yml/badge.svg?branch=master)](https://github.com/dev34253/yacoin/actions/workflows/yacoinbuildmultiplatform.yml)

YACoin (YAC) is a proof-of-work cryptocurrency. It started in 2013 as a rename of NovaCoin ([`COPYING`](COPYING)). This repository holds
the YACoin node: the daemon `yacoind`, the RPC client `yacoin-cli` and the GUI wallet `yacoin-qt` ([`src/Makefile.am`](src/Makefile.am),
[`src/Makefile.qt.include`](src/Makefile.qt.include)). The code base is C++11 ([`configure.ac`](configure.ac)) from the Bitcoin Core 0.15
era, built with autotools, with YACoin's own consensus rules.

## The chain

Since the Heliopolis hard fork at block 1890000 every block is a proof-of-work block ([`src/init.cpp`](src/init.cpp),
[`src/chainparams.cpp`](src/chainparams.cpp)). Proof of stake is historical: the node still validates the older proof-of-stake blocks below
that height ([`src/kernel.cpp`](src/kernel.cpp)), and it has no staking code.

| Item | Value | Defined in |
|---|---|---|
| Proof of work | scrypt-jane with Keccak-512 and ChaCha20/8; the scrypt hash of the block header is the block hash | [`src/Makefile.am`](src/Makefile.am), [`src/scrypt.cpp`](src/scrypt.cpp), [`src/primitives/block.h`](src/primitives/block.h) |
| N-factor | fixed at 21 for block version 7 and later, which every block from 1890000 must use: N = 2^22, 512 MiB of memory per hash | [`src/init.cpp`](src/init.cpp), [`src/primitives/block.h`](src/primitives/block.h), [`src/validation.cpp`](src/validation.cpp), [`src/scrypt-jane/scrypt-jane.c`](src/scrypt-jane/scrypt-jane.c) |
| Block target | 60 seconds | [`src/chainparams.cpp`](src/chainparams.cpp) |
| Block reward | about 2 % of the money supply a year: money supply before the epoch × 0.02 / 525960, the same for all 21000 blocks of an epoch | [`src/validation.cpp`](src/validation.cpp), [`src/validation.h`](src/validation.h), [`src/init.cpp`](src/init.cpp) |
| Difficulty | retargets once per 21000-block epoch | [`src/pow.cpp`](src/pow.cpp) |
| Tokens | token rules apply from block 1911211 | [`src/init.cpp`](src/init.cpp), [`src/validation.cpp`](src/validation.cpp), [`src/tokens/`](src/tokens/) |
| Networks | mainnet and regtest (`-regtest`); `-testnet` is not available | [`src/chainparams.cpp`](src/chainparams.cpp) |
| Ports | P2P 7688; RPC 7687 on mainnet, 17687 on regtest | [`src/protocol.h`](src/protocol.h), [`src/chainparamsbase.cpp`](src/chainparamsbase.cpp) |
| Version | 1.11.0 | [`configure.ac`](configure.ac) |

## Build

[`dev.sh`](dev.sh) builds against the pinned libraries in `depends/`, never against system libraries. `depends/` does not build with gcc 14
or newer (Boost 1.64, [`depends/packages/boost.mk`](depends/packages/boost.mk); see [`doc/developer-build.md`](doc/developer-build.md)). On such a
host, build in the CI images.

### In the CI images (needs only Docker)

`./dev.sh container` builds an image from [`ci/containers/`](ci/containers/) and runs one of its modes on this checkout. The images are
`ubuntu.22.04` (default), `ubuntu.16.04`, `windows` and `macos`.

```sh
./dev.sh container unit-tests                # build test_bitcoin and run all unit test suites
./dev.sh container functional-tests          # low-difficulty build, then the functional tests
./dev.sh container ubuntu.16.04 unit-tests   # the same in another image
```

The build modes (`build`, `build-low-difficulty`, `windows`, `macos`) configure the source tree in place
([`ci/containers/entrypoint.sh`](ci/containers/entrypoint.sh), [`entrypoint.windows.sh`](ci/containers/entrypoint.windows.sh),
[`entrypoint.macos.sh`](ci/containers/entrypoint.macos.sh)). Host builds and the test modes refuse such a tree; `make distclean` clears it. Run the release builds in separate clones, one per platform:

```sh
git clone . ../yacoin-linux && ../yacoin-linux/dev.sh container build         # yacoind, yacoin-cli, yacoin-qt in ../yacoin-linux/release-root/bin/
git clone . ../yacoin-windows && ../yacoin-windows/dev.sh container windows   # likewise macos
```

`ci/containers/run.sh --help` lists the options.

### On the host (gcc 13 or older)

Install the host tools listed in [`doc/developer-build.md`](doc/developer-build.md), then:

```sh
./dev.sh depends          # build the pinned dependencies once (without Qt)
./dev.sh build release    # yacoind and yacoin-cli in build/release/src/
./dev.sh build dev        # development build: mainnet consensus, -O1 -g
```

The host builds have no GUI; `yacoin-qt` comes from `./dev.sh container build`. `./dev.sh` without arguments lists all commands and build
variants.

## Test

```sh
./dev.sh unit                       # unit tests (test_bitcoin, build/dev), all suites in parallel
./dev.sh unit pow_tests             # selected suites
./dev.sh ftest                      # functional tests (test/functional/, low-difficulty build build/func), 4 in parallel
./dev.sh ftest feature_tokens.py    # selected functional tests
./dev.sh asan                       # unit tests under AddressSanitizer and UndefinedBehaviorSanitizer
./dev.sh all                        # build dev, unit, ftest and build release, with a summary
```

Without a suitable host compiler, `./dev.sh container unit-tests` and `./dev.sh container functional-tests` run the unit and functional tests.

## Documentation

- [`doc/developer-build.md`](doc/developer-build.md): `dev.sh`, build variants, tests, coverage and the CI images.
- [`doc/cross-compilation-with-depends-system.md`](doc/cross-compilation-with-depends-system.md): release binaries for Linux, Windows and
  macOS with `depends/`.
- [`ci/containers/README.md`](ci/containers/README.md): the CI build images and how CI uses them.
- [`depends/README.md`](depends/README.md): the depends system.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): how to contribute.
- [`SECURITY.md`](SECURITY.md): how to report a vulnerability.
- [`CLAUDE.md`](CLAUDE.md): the workflow and the rules of this repository.

## License

YACoin is released under the MIT license, see [`COPYING`](COPYING). Third-party code in `src/` keeps its own license, for example
[`src/leveldb/LICENSE`](src/leveldb/LICENSE), [`src/secp256k1/COPYING`](src/secp256k1/COPYING) and [`src/LibBoolEE.cpp`](src/LibBoolEE.cpp)
(LGPL version 3 or later, compiled into `libyacoin_consensus.a`, [`src/Makefile.am`](src/Makefile.am)). Attributions for the icons and
some third-party code are in [`doc/assets-attribution.txt`](doc/assets-attribution.txt).
