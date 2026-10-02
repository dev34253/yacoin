# Dependency modernisation – overview

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

## Inventory (corrected after the [Phase 0 review](phase0-review.md))

### `CBigNum` (OpenSSL `BIGNUM`)

About 60 production call sites in 13 files (plus 113 occurrences inside
`bignum.h` itself and 4 in tests):

| Where | What | Consensus? |
|---|---|---|
| `pow.cpp` | difficulty retarget, `CheckProofOfWork`, PoS limit, min work/stake | yes |
| `kernel.cpp` | stake kernel (`bnCoinDayWeight * bnTargetPerCoinDay` can exceed 2^256, ≈2^263 worst case) | yes (below height 1,890,000) |
| `validation.cpp:918-979` | **pre-fork PoW block reward**: bisection with ~400-bit products (`mid^6·powLimit`, `limit^6·target`) | yes |
| `chain.cpp`/`chain.h` | `GetBlockTrust` (several branches, see below), `bnChainTrust`, `GetBlockProofEquivalentTime` | yes (fork choice) |
| `consensus/params.h:62,64` | `powLimit` is a `CBigNum` | yes |
| `chainparams.cpp`, `main.cpp:74-75` | limits | yes |
| `net_processing.cpp` | `bnChainTrust` comparisons drive header sync and peer protection | P2P behaviour |
| `rpc/mining.cpp`, `rpc/blockchain.cpp`, `miner.cpp`, `qt/explorer.cpp` | `getsubsidy`, `getwork`, difficulty target, miner | output only |

Block trust rules (`chain.cpp:75-115`): genesis = 1; PoW before
`CONSECUTIVE_STAKE_SWITCH_TIME` = 1; PoW after = `powLimit / target` (×2 if
the previous block was PoS); PoS after PoW = `pprev->GetBlockTrust() + 1`;
PoS after PoS = 0; legacy PoS = `(1<<256)/(target+1)`. `bnChainTrust` is
computed in memory and not serialised, but `nStakeModifier` and
`hashProofOfStake` (computed with this code) are stored in the block index.

### Other OpenSSL use

| Where | What | Notes |
|---|---|---|
| `random.cpp`, `util.cpp:120-163` | RNG, locking callbacks, `OPENSSL_no_config`, `RAND_screen` (WIN32, removed in 1.1+) | Phase 3 |
| `support/cleanse.cpp:13` | `OPENSSL_cleanse` behind `memory_cleanse` | Phase 3 |
| `miner.cpp:93-105` | `SHA256Transform` writing into `SHA256_CTX` internals, used by `getwork` midstate | Phase 3 |
| `pbkdf2.cpp` | OpenSSL `SHA256_*`; only used by dead `scrypt.cpp` functions | delete |
| `wallet/test/crypto_tests.cpp`, `test/crypto_tests.cpp` | OpenSSL EVP as a test oracle | replace with fixed vectors |
| Qt (`paymentserver`, `paymentrequestplus`, `rpcconsole`, `winshutdownmonitor`) | BIP70 TLS etc. | Phase 5 decision |
| `wallet/wallet.cpp:48`, `init.cpp:66` | stale includes | delete |
| Build | `SSL_LIBS` linked into `yacoind`/`yacoin-cli`; configure requires libssl | Phase 5 |

Not OpenSSL any more: **wallet encryption** (`wallet/crypter.cpp` already
uses `crypto/aes.h`, `crypto/sha512.h` and its own `BytesToKeySHA512AES`;
v1.0.0/v1.1.0 still used `EVP_BytesToKey`), **signatures** (bundled
libsecp256k1), `random_nonce.cpp` (`rand()`, dead code).

### Other consensus code that is sensitive to compiler/library changes

- **Block PoW hash**: `CBlockHeader::CalculateHash` → scrypt-jane
  (`primitives/block.h:126-218`) with its own N-factor table; SIMD path chosen
  at compile time (`Makefile.am:186-195`); packed headers hashed raw.
  (`GetNfactor` in `main.cpp` is display-only; most of `scrypt.cpp` is dead.)
- **Post-fork reward and max block size** use `double`
  (`validation.cpp:932`, `consensus/consensus.cpp:26-27`).
- **Token names** validated with `std::regex` (`tokens/tokens.cpp:67-74`).

## Phases

| Phase | Content | Main risk |
|---|---|---|
| **0 – Safety net** | Characterisation tests, mainnet replay, oracle, fuzzing, benchmarks. See [`phase0-test-safety-net.md`](phase0-test-safety-net.md). | Mainnet data logistics; kernel/reward coverage. |
| 1 – Newer compilers | Missing includes and other GCC 13 errors; build on 24.04 with `depends`; 24.04 CI job. | `std::regex`, floating point and scrypt-jane code-path changes (covered by Phase 0 tests). |
| 2 – Boost upgrade | Placeholders, `filesystem`, `signals2`, `assign`; possibly C++14; bump Boost in `depends`. | Thread shutdown/interruption hangs; path handling. |
| 3 – OpenSSL out of non-consensus code | RNG (port Bitcoin Core's), `cleanse`, `util.cpp` init, `getwork` SHA256 midstate, test oracles → fixed vectors; delete dead `pbkdf2.cpp`/`scrypt.cpp` functions. | Weaker randomness (review against Bitcoin Core); `getwork` output. |
| 4 – Replace `CBigNum` | Migrate to `arith_uint256` one function at a time; 512-bit intermediates (or rearranged comparisons) for the stake kernel **and the pre-fork reward**; every trust branch preserved. | Chain split. |
| 5 – Drop OpenSSL | Remove `SSL_LIBS` from non-Qt targets and the libssl requirement; decide Qt BIP70; remove `--with-libressl`/`RAND_egd`; plain `apt install` build docs for 24.04. | Low once 3–4 are done. |
| 6 – Berkeley DB (separate decision) | Keep 4.8 or plan a wallet migration. | Wallet compatibility. |

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
| `scrypt.cpp` | 7.3% | mostly dead code |
| `random_nonce.cpp` | 0% | dead code |
| `bignum.h` | 73.7% | |
| `pow.cpp` | 76.9% (50% of functions) | |
| `chain.cpp` | 76.2% | |
| `validation.cpp` | 71.5% | |
| `wallet/crypter.cpp` | 73.4% | |
| `random.cpp` | 85.8% | |
