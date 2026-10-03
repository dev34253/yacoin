# Dependencies

These are the versions that the `depends` system builds (`depends/packages/*.mk`).
The supported build uses them (see `CLAUDE.md`, *Building*, and
[build-unix.md](build-unix.md)). System packages of other versions are
not supported. On Ubuntu 24.04 in particular, OpenSSL 3, Boost 1.83 and
BDB 5.3 do not work today; see
[`project/plans/overview.md`](../project/plans/overview.md).

| Dependency | Version in `depends` | Needed by | Notes |
|---|---|---|---|
| Boost | 1.64.0 | all | system, filesystem, program_options, thread, chrono; unit_test_framework for tests |
| OpenSSL | 1.0.1k | `yacoind`, `yacoin-cli`, Qt | `CBigNum` (consensus), RNG seeding, `getwork` midstate; must be 1.0.x until Phase 4/5 |
| libevent | 2.1.8-stable | all | HTTP/RPC server; patched for glibc ≥ 2.36 (`arc4random`) |
| Berkeley DB | 4.8.30 | wallet | `--disable-wallet` drops it; other versions need `--with-incompatible-bdb` and produce non-portable wallets |
| miniupnpc | 2.0.20170509 | optional (UPnP) | |
| ZeroMQ | 4.1.5 | – | built by `depends` but not used (ZMQ notifications are not compiled in) |
| Qt | 5.7.1 | GUI only (deferred) | does not build with GCC 13 |
| protobuf | 2.6.1 | GUI only | payment requests (BIP70) |
| qrencode | 3.4.4 | GUI only | |
| zlib, expat, dbus, freetype, fontconfig, libxcb, libX11 and X11 protocol packages | see `depends/packages/` | GUI only (Linux) | |

Bundled in the source tree (`src/`): LevelDB, libsecp256k1, UniValue,
scrypt-jane.

Package groups (`depends/packages/packages.mk`): base = boost, openssl,
libevent, zeromq; wallet = bdb; upnp = miniupnpc; qt = qt, qrencode,
protobuf, zlib (plus X11 libraries on Linux). `NO_QT=1`, `NO_WALLET=1` and
`NO_UPNP=1` skip groups.

Compiler: GCC 11 in the build image `dev34253/yacoin-build:ubuntu.24.04-gcc11-1`
(C++11). GCC 13 is Phase 1 of the modernisation plan.
