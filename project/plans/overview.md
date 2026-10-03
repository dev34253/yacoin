# Dependency modernisation – overview

## Scope and priorities

The goal of this work is a stable, reproducible build on Ubuntu 24.04 with
current, maintained library versions – or no dependency at all where it can
be removed. OpenSSL is the main one (Phase 4 replaces `CBigNum`). Bugs and
oddities found on the way are not fixed as part of this work unless they
block that goal: they are recorded in
[`../known-issues.md`](../known-issues.md) for later (owner, 2026-10-03).

## Why

Yacoin only builds against library versions from around 2016–2018. On a
stock Ubuntu 24.04 system the build fails:

| Library | Code expects | Ubuntu 24.04 | Failure |
|---|---|---|---|
| OpenSSL | 1.0.x | 3.0 | `BIGNUM` is opaque and `BN_init` is gone since 1.1; `src/bignum.h` inherits from `BIGNUM`. `configure` mistakes OpenSSL 3 for LibreSSL (`RAND_egd` check). |
| Boost | 1.58–1.64 | 1.83 | `boost::bind` placeholders `_1`/`_2` no longer global (16 files use `boost::bind`, ~9 use the placeholders – re-measure from compiler errors). Deprecated `filesystem` APIs. |
| GCC | 5–9 | 13 | Missing transitive includes, e.g. `httpserver.cpp` uses `std::deque` without `<deque>`. |
| Berkeley DB | 4.8 | 5.3 | Works with `--with-incompatible-bdb`; wallet portability concern. |

Today the only working build is the `depends` system, which compiles
OpenSSL 1.0.1k (2015), Boost 1.64 (2017) and BDB 4.8 (2009) from source.
These versions no longer receive security fixes.

## Inventory (corrected after the [Phase 0 review](phase0-review.md), checked against the source in P0-50)

Code that can never run is listed separately in
[`dead-code.md`](dead-code.md) and marked "dead" below.

### `CBigNum` (OpenSSL `BIGNUM`)

59 production lines in 12 files mention `CBigNum` (60 in 13 counting a
comment in dead `scrypt.cpp` code), plus 113 lines (158 occurrences) inside
`bignum.h` itself and 4 lines in tests (`test/pow_tests.cpp`):

| Where | What | Consensus? |
|---|---|---|
| `pow.cpp` | difficulty retarget, `CheckProofOfWork`, PoS hard limit (`bnProofOfStakeHardLimit`) | yes |
| `pow.cpp:231-234,255-287` | `GetProofOfStakeLimit`, `ComputeMaxBits`, `ComputeMinWork`, `ComputeMinStake` | dead (no callers) |
| `kernel.cpp` | stake kernel (`bnCoinDayWeight * bnTargetPerCoinDay` can exceed 2^256, ≈2^263 worst case) | yes (below height 1,890,000) |
| `validation.cpp:918-979` | **pre-fork PoW block reward**: bisection with ~400-bit products (`mid^6·powLimit`, `limit^6·target`) | yes |
| `validation.cpp:3760` | `bnChainTrust` sum when loading the block index (`LoadBlockIndexDB`) | yes (fork choice) |
| `validation.cpp:3703-3706,3727` | minimum-difficulty value in `LoadBlockRewardAndHighestDiff` | log output only |
| `chain.cpp`/`chain.h` | `GetBlockTrust` (several branches, see below), `bnChainTrust`, `GetBlockProofEquivalentTime` | yes (fork choice) |
| `consensus/params.h:62,64` | `powLimit` is a `CBigNum` | yes |
| `chainparams.cpp:78-83,237-238` | `powLimit`, `initialHashTarget` | yes |
| `main.cpp:74-75` | `bnProofOfStakeLegacyLimit`, `bnProofOfStakeLimit` | dead (never referenced) |
| `net_processing.cpp` | `bnChainTrust` comparisons drive header sync and peer protection | P2P behaviour |
| `rpc/mining.cpp:145,420,860`, `rpc/blockchain.cpp:358`, `miner.cpp:642,801`, `qt/explorer.cpp:1302` | `getsubsidy`, `getwork`, `getblocktemplate`, `getdifficulty`, `CheckWork`, `YacoinMiner`, explorer | output only |

Block trust rules (`chain.cpp:75-115`): genesis = 1; PoW before
`CONSECUTIVE_STAKE_SWITCH_TIME` = 1; PoW after = `powLimit / target` (×2 if
the previous block was PoS); PoS after PoW = `pprev->GetBlockTrust() + 1`;
PoS after PoS = 0; legacy PoS = `(1<<256)/(target+1)`. `bnChainTrust` is
computed in memory and not serialised, but `nStakeModifier` and
`hashProofOfStake` (computed with this code) are stored in the block index.

### Other OpenSSL use

| Where | What | Notes |
|---|---|---|
| `random.cpp:47-48,135,166,276,450-451` | RNG: `RAND_add`, `RAND_bytes` | Phase 3 |
| `util.cpp:84-86,120-163` | locking callbacks, `OPENSSL_no_config`, `RAND_screen` (WIN32, removed in 1.1+), `RAND_cleanup` | Phase 3 |
| `support/cleanse.cpp:13` | `OPENSSL_cleanse` behind `memory_cleanse` | Phase 3 |
| `miner.cpp:16,93-106` | `SHA256Transform` writing into `SHA256_CTX` internals, used by `getwork` midstate (`miner.cpp:597,634`) | Phase 3 |
| `init.cpp:66,972` | `SSLeay_version(SSLEAY_VERSION)` in the start-up log line (OpenSSL 1.0 name) | Phase 3/5 |
| `pbkdf2.cpp` | OpenSSL `SHA256_*`; only used by dead `scrypt.cpp` functions | dead, delete ([P0-59](../todo/P0-59-dead-code-removal.md)) |
| `wallet/test/crypto_tests.cpp:17-84,143` | OpenSSL EVP as a test oracle, `SSLeay()` | replace with fixed vectors |
| Qt (`paymentserver`, `paymentrequestplus`: X509; `winshutdownmonitor`: `RAND_event`; Qt tests `paymentservertests`, `test_main`) | BIP70 TLS etc. | Phase 5 decision |
| `wallet/wallet.cpp:48`, `test/crypto_tests.cpp:20-21`, `qt/rpcconsole.cpp:23`, `qt/explorer.cpp:19` | stale includes (no OpenSSL call) | delete (P0-59; Qt ones in the Qt phase) |
| Build | `SSL_LIBS` linked into `yacoind`, `yacoin-cli`, `test_bitcoin`, `test_bitcoin_fuzzy`, `yacoin-qt` and the Qt tests (`Makefile.am:407,425`, `Makefile.test.include:100,124`, `Makefile.qt.include:463`, `Makefile.qttest.include:59`); configure requires libssl (`configure.ac:922,937-941`); `RAND_egd` LibreSSL check twice (`configure.ac:958-964,973-985`) | Phase 5 |

Not OpenSSL any more: **wallet encryption** (`wallet/crypter.cpp` already
uses `crypto/aes.h`, `crypto/sha512.h` and its own `BytesToKeySHA512AES`;
v1.0.0/v1.1.0 still used `EVP_BytesToKey`), **signatures** (bundled
libsecp256k1), `random_nonce.cpp` (`rand()`/`srand(time)`; dead code, see
[`dead-code.md`](dead-code.md)).

### Other consensus code that is sensitive to compiler/library changes

- **Block PoW hash**: `CBlockHeader::CalculateHash` → `scrypt_hash(...,
  Nfactor)` in `scrypt.cpp:108-139` → scrypt-jane
  (`primitives/block.h:126-218`) with its own N-factor table; algorithms and
  SIMD path chosen at compile time (`DEFS+=` at `Makefile.am:191`; the other
  lines in `Makefile.am:186-195` are an unused rule); packed headers hashed
  raw. (`GetNfactor` in `main.cpp` is display-only; every other function in
  `scrypt.cpp` is dead, see [`dead-code.md`](dead-code.md).)
- **Post-fork reward and max block size** use `double`
  (`validation.cpp:932`, `consensus/consensus.cpp:26-27`).
- **Token names** validated with `std::regex` (`tokens/tokens.cpp:67-74`).

## Phases

| Phase | Content | Main risk |
|---|---|---|
| **0 – Safety net** | Characterisation tests, mainnet replay, oracle, fuzzing, benchmarks. See [`phase0-test-safety-net.md`](phase0-test-safety-net.md). | Mainnet data logistics; kernel/reward coverage. |
| 1 – Newer compilers | Switch the Ubuntu 24.04 build image (P0-57) from GCC 11 to GCC 13; fix missing includes and other GCC 13 errors. | `std::regex`, floating point and scrypt-jane code-path changes (covered by Phase 0 tests). |
| 2 – Boost upgrade | Placeholders, `filesystem`, `signals2`, `assign`; possibly C++14; bump Boost in `depends`. | Thread shutdown/interruption hangs; path handling. |
| 3 – OpenSSL out of non-consensus code | RNG (port Bitcoin Core's), `cleanse`, `util.cpp` init, `SSLeay_version` log line, `getwork` SHA256 midstate, test oracles → fixed vectors; delete dead `pbkdf2.cpp`/`scrypt.cpp` functions (P0-59 may do this earlier). | Weaker randomness (review against Bitcoin Core); `getwork` output. |
| 4 – Replace `CBigNum` | Migrate to `arith_uint256` one function at a time; 512-bit intermediates (or rearranged comparisons) for the stake kernel **and the pre-fork reward**; every trust branch preserved. | Chain split. |
| 5 – Drop OpenSSL | Remove `SSL_LIBS` from non-Qt targets and the libssl requirement; decide Qt BIP70; remove `--with-libressl` and both `RAND_egd` checks; plain `apt install` build docs for 24.04. | Low once 3–4 are done. |
| 6 – Berkeley DB (separate decision) | Keep 4.8 or plan a wallet migration. | Wallet compatibility. |
| Later – Qt GUI (deferred, P0-00) | Qt 5.7.1 in `depends` won't build with GCC 13; BIP70 TLS; `qt/explorer.cpp` uses `CBigNum`. Phase 0 builds with `NO_QT=1`. | GUI-only code paths. |

Each phase is its own set of pull requests, keeps the build green, and is
checked against the previous phase's behaviour using the Phase 0 tests.

## Baseline (2026-10-02, tree identical to yacoin/yacoin master)

Ubuntu 22.04 + `depends`, built with `--enable-low-difficulty-for-development`
and coverage instrumentation:

- Functional tests: 45/45 passed (≈6.5 min with 4 jobs).
- Unit tests: 238/239 passed. `pow_tests/get_next_work_pow_limit` fails
  (expected `0x1e0fffff`, got `0x1e1a19f8`). Cause confirmed by arithmetic:
  the low-difficulty `powLimit` (2^253) does not clamp the retarget, the
  mainnet one (2^236) does (task P0-02).
- Line coverage: 56.7% unit only, 75.7% unit + functional (functions 74.0%).

| File | Lines covered (unit + functional) | Note |
|---|---|---|
| `kernel.cpp` | 17.9% | much of the rest is debug logging |
| `scrypt.cpp` | 7.3% | all dead except `scrypt_hash` ([list](dead-code.md)) |
| `random_nonce.cpp` | 0% | dead code ([list](dead-code.md)) |
| `bignum.h` | 73.7% | |
| `pow.cpp` | 76.9% (50% of functions) | |
| `chain.cpp` | 76.2% | |
| `validation.cpp` | 71.5% | |
| `wallet/crypter.cpp` | 73.4% | |
| `random.cpp` | 85.8% | |
