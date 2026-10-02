# Phase 0 – Test safety net

Phase 0 builds a safety net that records exactly how the current code
behaves, so every later change (Boost, OpenSSL, `CBigNum`) can be proven to
behave the same. Tasks for this phase are in `../todo/` (`P0-*`).

## Guiding rules

1. **Record behaviour; don't fix it.** These tests capture what the code does
   today, bugs included. In consensus code, behaving the same as the rest of
   the network counts for more than being "correct". A suspected bug is
   written down and its current behaviour pinned by a test; any fix is a
   separate, deliberate change.
2. **Use real data where possible.** No code in this tree creates
   proof-of-stake blocks (no `CreateCoinStake` or stake miner), so the
   stake-checking code can only be exercised with historical mainnet blocks.
   That is why `kernel.cpp` sits at 17.9% coverage. Mainnet data is the
   backbone of this phase.
3. **Every test must also run against the new code later.** Tests go through
   stable interfaces (functions, RPC, files on disk), not through `CBigNum`
   internals, so they keep working once `CBigNum` is gone.

## 0.1 Infrastructure

| Item | Detail |
|---|---|
| Two build configurations | **Mainnet parameters** (no `--enable-low-difficulty-for-development`) for unit tests and mainnet replay. **Low difficulty** for functional tests. Each suite runs in the right one. This also decides whether the `pow_tests/get_next_work_pow_limit` failure is the flag or a real bug. |
| Pinned toolchain | Ubuntu 22.04 + `depends` image (`dev34253/yacoin-build:ubuntu.22.04-1`). Ubuntu 16.04 kept only as reference. |
| Coverage in CI | lcov after unit and after unit+functional, HTML reports as CI artifacts, per-file minimums (0.10). |
| Fixture storage | Small fixtures in the repo under `src/test/data/`. Large ones (full-chain dumps, block files) versioned and stored outside the repo with checksums, downloaded by test scripts. |
| Baseline binary | Archive `yacoind`/`yacoin-cli`/`test_bitcoin` built from the Phase 0 starting commit; later phases test against it (0.6). |
| Mainnet data dump tool | RPC or standalone tool run against a fully synced node built from the current code. Per block: height, hash, `nTime`, `nBits`, PoW/PoS, next required target, `GetBlockTrust`, total chain trust, stake modifier and checksum, `hashProofOfStake`, kernel check result. This is the "golden" record (0.3). |

## 0.2 Unit tests (C++, `test_bitcoin`)

### a) `CBigNum` full contract (`bignum.h`, 73.7% → ≥95%)

| Area | Cases |
|---|---|
| Constructors | Each integer width at 0, 1, -1, min, max; from `uint256`/`uint160`. |
| Conversions | `setuint64`/`getuint64`, `setint64`, `setuint256`/`getuint256` round-trips; values over 256 bits; negative values. |
| Compact form | `SetCompact`/`GetCompact`: every exponent 0–34, sign bit, mantissa overflow, `0x00800000`, zero. Port Bitcoin's `arith_uint256` compact tests and record where Yacoin differs. |
| Text and bytes | `SetHex` (prefix, whitespace, odd length, invalid chars), `ToString(base)`, `GetHex`, `getvch`/`setvch`, MPI format, `Serialize`/`Unserialize`. |
| Arithmetic | `+ - * / %`, shifts (incl. ≥256 and negative values), `++`/`--`, comparisons; division by zero (record behaviour). |
| Results over 256 bits | Products and shifts past 2^256 – the cases `arith_uint256` cannot represent (`kernel.cpp`, `chain.cpp`). |
| Rarely used methods | `pow`, `mul_mod`, `pow_mod`, `inverse`, `gcd`, `isPrime`: find out whether anything uses them. Unused → delete in Phase 4; used → test. |
| Golden vectors | Generator runs ~100k random and adversarial operations through today's `CBigNum` and writes inputs/outputs to JSON. The replacement must reproduce every line. |

### b) Difficulty (`pow.cpp`, 76.9% lines / 50% functions → 100% functions, ≥95% lines)

Functions: `GetLastBlockIndex`, `CalculateNextWorkRequired`,
`GetNextTargetRequired044`, `GetNextTargetRequired`, `CheckProofOfWork`,
`GetProofOfStakeLimit`, `ComputeMaxBits`, `ComputeMinWork`, `ComputeMinStake`.

- Synthetic block-index chains: timespans extremely fast, extremely slow,
  exactly on target; clamping at limits; genesis and first blocks; PoW and
  PoS paths; epoch and hardfork boundaries.
- Real mainnet windows from the 0.3 dump around every retarget, epoch change
  and hardfork height.
- `CheckProofOfWork`: hash equal to target, one above, one below; negative,
  overflowing and zero `nBits`.

### c) Chain trust (`chain.cpp`, `chain.h`)

- `GetBlockTrust` for PoW and PoS, zero target, maximum target, before/after
  hardfork – including the `(1<<256)/(target+1)` case.
- Accumulated trust over a synthetic chain; fork comparison
  (`CBlockIndexWorkComparator`, `validation.cpp:116`).
- RPC `chaintrust` hex output (`rpc/blockchain.cpp:96`).
- Note: `bnChainTrust` is computed in memory and never serialised, so no
  on-disk format is involved.

### d) Proof-of-stake (`kernel.cpp`, 17.9% → ≥90%)

- `GetWeight`, `IsFixedModifierInterval`, stake-modifier selection intervals,
  `SelectBlockFromCandidates`, `ComputeNextStakeModifier` – using real
  mainnet block-index sequences.
- `CheckStakeKernelHash` / `CheckProofOfStake` against real PoS blocks (must
  accept), then hash, time, amount or `nBits` mutated by one (must reject).
- **Overflow cases**: inputs where `bnCoinDayWeight * bnTargetPerCoinDay`
  exceeds 2^256, recording current behaviour.
- `GetStakeModifierChecksum` against every stake-modifier checkpoint.

### e) Hashing and N-factor schedule (`scrypt.cpp`, 7.3% → ≥90%)

- Known-answer tests for `scrypt_hash`, salted, multi-round,
  `scrypt_blockhash` at each N-factor in use.
- N-factor by timestamp (`main.cpp:92` ff.) incl. min/max and the 1.0
  hardfork limit (`maxNfactorYc1dot0`).
- `scrypt_blockhash` of real mainnet headers equals the stored hash.

### f) Chain parameters snapshot (`chainparams.cpp`)

- Pin `powLimit`, genesis, checkpoints, ports, etc. for mainnet, regtest and
  the low-difficulty build so an accidental change fails loudly.

### g) Randomness (`random.cpp` 85.8%, `random_nonce.cpp` 0%)

- API contracts: ranges of `GetRand`/`GetRandInt`; `GetStrongRandBytes`
  never repeats across 1M calls; seeded `FastRandomContext` deterministic;
  `Random_SanityCheck`.
- Loose chi-square on byte counts (catches broken generators, not weak ones).
- `random_nonce.cpp`: determine whether it is dead code; test or remove.

### h) Wallet encryption (`wallet/crypter.cpp`, 73.4% → ≥95%)

- Known-answer vectors for key derivation (`EVP_BytesToKey`, SHA-512, N
  rounds) and AES-256-CBC with 0, 15, 16, 17 bytes of padding.
- Wrong passphrase, damaged ciphertext, empty input.
- Master-key round-trip and decryption of a stored encrypted key created by
  the current binary.

## 0.3 Mainnet replay (the most important test)

| Test | How | Pass condition |
|---|---|---|
| Offline function replay | Feed dump records through difficulty, trust and kernel functions in a unit test; no network. | Every computed value matches, every block. |
| Sampled fixture in repo | A few thousand records around retargets, epochs, hardforks, PoS blocks, checkpoints. | Runs in normal CI in seconds. |
| Full reindex | `-reindex -checkblocks=0 -checklevel=4` on a mainnet block copy. | Same tip hash, `chaintrust`, UTXO hash (`gettxoutsetinfo` `hash_serialized`), identical at every checkpoint. |
| `-reindex-chainstate` | Same, rebuilding only the UTXO set. | Same results. |
| Rejection | Mutated real blocks (`nBits`±1, shifted timestamp, tampered kernel, wrong stake modifier). | Rejected with the same reason as the baseline binary. |

Needs a fully synced mainnet node: initial sync time and storage are the main
logistics question. Probably a self-hosted runner, run weekly.

## 0.4 Differential testing, fuzzing, sanitizers

- **Reference copy**: freeze today's `CBigNum` as a test-only class still
  linked against OpenSSL in test builds; Phase 4 checks each replacement
  function against it.
- **Property tests**: `(a*b)/b == a`, `(a<<n)>>n`, compact round-trips, on
  random inputs including >256-bit values.
- **New fuzz targets** in `test_bitcoin_fuzzy`: compact decode, `CBigNum`
  ops, `CheckProofOfWork`, difficulty on fuzzed block-index sequences, stake
  kernel. Seeded with mainnet values; corpus kept for regression.
- **ASan + UBSan builds** running unit and functional tests. UBSan matters
  because `pow.cpp`/`kernel.cpp` use `int64` timespans where signed overflow
  is undefined behaviour.

## 0.5 Functional tests (Python, regtest)

| New test | Purpose |
|---|---|
| `wallet_encryption_compat.py` | Encrypted wallet from the baseline binary (and from `v1.0.0`/`v1.1.0` releases): unlock, change passphrase, keypool top-up, `dumpprivkey`, sign. |
| `feature_difficulty_epochs.py` | Several retargets via `-epochinterval`; `getdifficulty`/`nBits` vs stored expected values. |
| `feature_chaintrust_reorg.py` | Competing forks with different trust; node picks higher trust; `getchaintips`, `invalidateblock`/`reconsiderblock`, `chaintrust` vs stored values. |
| `rpc_output_snapshots.py` | Stored expected JSON for `getblock`, `getblockheader`, `getdifficulty`, `getmininginfo`, `getblocktemplate`, `getblockchaininfo`, volatile fields masked. |
| `feature_shutdown.py` | Repeated start/stop; stop during sync, reindex and mining; `SIGTERM`; shutdown-time limits (catches Phase 2 thread regressions). |
| `p2p_fixture_sync.py` | One node serves a stored chain, another syncs headers-first; identical end state. |
| Flakiness baseline | Full suite 10×; per-test failure rates recorded. |

## 0.6 Cross-version compatibility

- Mixed-version regtest network (baseline + candidate binary) mining
  alternately: same tip, mutual relay and acceptance.
- Data directory compatibility both ways (block index, chainstate, wallet).

## 0.7 Performance

Microbenchmarks (port `bench_bitcoin` from Bitcoin Core 0.16 – there is no
`src/bench` in this tree):

- `CBigNum` arithmetic, `SetCompact`/`GetCompact`, `GetBlockTrust`
- `CheckProofOfWork`, `GetNextTargetRequired`, `CheckStakeKernelHash`,
  `ComputeNextStakeModifier`
- `scrypt_blockhash` at each N-factor
- AES encrypt/decrypt, key derivation, `GetStrongRandBytes`
- Block/transaction deserialisation, `ConnectBlock` on a stored block

System level: full reindex time and peak memory; sync time from a local peer;
startup and shutdown time; RPC latency (`getblocktemplate`, `getblock`) under
load.

Method: dedicated runner, median of 5 runs, stored history; >10% change is
flagged for review, not failed automatically.

## 0.8 Long-running tests

- Candidate node against live mainnet peers for 24–72 h: forks, stalls,
  memory growth, log errors.
- Nightly fuzzing; inputs that find new paths are kept.

## 0.9 CI layout

| Trigger | Jobs |
|---|---|
| Every push | Both build configurations; unit; functional; sampled mainnet replay; coverage + minimums |
| Nightly | Sanitizer builds; fuzzers; benchmarks; functional 3× |
| Weekly / manual | Full mainnet reindex and replay; cross-version network; long-running test |

## 0.10 Exit criteria

| File | Today | Target |
|---|---|---|
| `kernel.cpp` | 17.9% | ≥ 90% lines |
| `pow.cpp` | 76.9% (50% functions) | 100% functions, ≥ 95% lines |
| `bignum.h` | 73.7% | ≥ 95% |
| `chain.cpp` | 76.2% | ≥ 95% |
| `wallet/crypter.cpp` | 73.4% | ≥ 95% |
| `scrypt.cpp` | 7.3% | ≥ 90% |
| `random.cpp` | 85.8% | ≥ 90% (`random_nonce.cpp` resolved) |
| Overall | 75.7% | ≥ 80% |

Plus: full mainnet replay matches; golden vectors and reference `CBigNum` in
place; benchmark baseline recorded; flakiness baseline recorded; every
suspected bug written down with current behaviour pinned by a test.

## Suggested order

1. Infrastructure: build configurations, CI coverage, `pow_tests` triage,
   baseline binary.
2. Mainnet data: sync a node, dump tool, full dump and sampled fixture
   (longest lead time – start early).
3. Unit tests for consensus code (0.2 a–f).
4. Unit tests for randomness and wallet encryption (0.2 g–h) + wallet fixtures.
5. Functional tests (0.5) and cross-version testing (0.6).
6. Differential testing, fuzzing, sanitizers (0.4).
7. Performance (0.7).
8. Full mainnet replay in CI, long-running test, exit review.

Steps 3–7 can largely run in parallel once step 2 has produced the fixture.

## Open decisions (task P0-00)

- Where to sync the mainnet node and keep block data.
- Whether fixtures and the benchmark framework go into the fork first or
  straight upstream to `yacoin/yacoin`.
- Whether old release wallets (`v1.0.0`/`v1.1.0`) must stay readable.
