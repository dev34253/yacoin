# Dependency modernisation – overview

## Why

Yacoin only builds against library versions from around 2016–2018. On a
stock Ubuntu 24.04 system the build fails:

| Library | Code expects | Ubuntu 24.04 | Failure |
|---|---|---|---|
| OpenSSL | 1.0.x | 3.0 | `BIGNUM` is opaque and `BN_init` is gone since 1.1; `src/bignum.h` inherits from `BIGNUM`. `configure` mistakes OpenSSL 3 for LibreSSL (`RAND_egd` check). |
| Boost | 1.58–1.64 | 1.83 | `boost::bind` placeholders `_1`/`_2` no longer global (19 files). |
| GCC | 5–9 | 13 | Missing transitive includes, e.g. `httpserver.cpp` uses `std::deque` without `<deque>`. |
| Berkeley DB | 4.8 | 5.3 | Works with `--with-incompatible-bdb`; wallet portability concern. |

Today the only working build is the `depends` system, which compiles
OpenSSL 1.0.1k (2015), Boost 1.64 (2017) and BDB 4.8 (2009) from source.
These versions no longer receive security fixes.

What OpenSSL is used for in `yacoind`:

- `CBigNum` (`bignum.h`) – arithmetic in consensus code: `pow.cpp`
  (difficulty), `kernel.cpp` (proof-of-stake), `chain.cpp`/`chain.h`
  (block trust), `validation.cpp`, `chainparams.cpp`. 177 uses.
- Randomness – `random.cpp`, `random_nonce.cpp`, `util.cpp`.
- Wallet encryption – `wallet/crypter.cpp` (`EVP_aes_*`, `EVP_BytesToKey`).
- TLS only in the Qt GUI (BIP70 payment requests). Signatures use the bundled
  libsecp256k1, not OpenSSL.

## Phases

| Phase | Content | Main risk |
|---|---|---|
| **0 – Safety net** | Characterisation tests, mainnet replay, fuzzing, benchmarks. See [`phase0-test-safety-net.md`](phase0-test-safety-net.md). | Getting mainnet data and enough coverage of `kernel.cpp`. |
| 1 – Newer compilers | Missing includes and other GCC 13 errors; build on 24.04 with `depends`; 24.04 CI job. | Low. |
| 2 – Boost upgrade | Placeholders, `filesystem`, `signals2`; bump Boost in `depends`. | Thread shutdown/interruption hangs. |
| 3 – OpenSSL out of non-consensus code | Port Bitcoin Core's AES and `BytesToKeySHA512AES` for the wallet and its RNG. | Existing encrypted wallets failing to unlock; weaker randomness. |
| 4 – Replace `CBigNum` | Migrate to `arith_uint256` one function at a time. A 512-bit intermediate (or rearranged comparison) for the stake kernel; Bitcoin's `(~target / (target+1)) + 1` for block trust. | Chain split. |
| 5 – Drop OpenSSL | Remove from `yacoind`; decide on Qt BIP70; remove `--with-libressl`/`RAND_egd`; plain `apt install` build docs for 24.04. | Low once 3–4 are done. |
| 6 – Berkeley DB (separate decision) | Keep 4.8 or plan a wallet migration. | Wallet compatibility. |

Each phase is its own set of pull requests, keeps the build green, and is
checked against the previous phase's behaviour using the Phase 0 tests.

## Baseline (2026-10-02, tree identical to yacoin/yacoin master)

Ubuntu 22.04 + `depends`, built with `--enable-low-difficulty-for-development`
and coverage instrumentation:

- Functional tests: 45/45 passed (≈6.5 min with 4 jobs).
- Unit tests: 238/239 passed. `pow_tests/get_next_work_pow_limit` fails
  (expected `0x1e0fffff`, got `0x1e1a19f8`); probably caused by the
  low-difficulty flag, not yet confirmed (task P0-02).
- Line coverage: 56.7% unit only, 75.7% unit + functional (functions 74.0%).

| File | Lines covered (unit + functional) |
|---|---|
| `kernel.cpp` | 17.9% |
| `scrypt.cpp` | 7.3% |
| `random_nonce.cpp` | 0% |
| `bignum.h` | 73.7% |
| `pow.cpp` | 76.9% (50% of functions) |
| `chain.cpp` | 76.2% |
| `validation.cpp` | 71.5% |
| `wallet/crypter.cpp` | 73.4% |
| `random.cpp` | 85.8% |
