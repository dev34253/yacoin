# Phase 0 – Test safety net

Phase 0 builds a safety net that records exactly how the current code
behaves, so every later change (compiler, Boost, OpenSSL, `CBigNum`) can be
proven to behave the same. Tasks are in `../todo/` (`P0-00` … `P0-59`).
This version incorporates the [review](phase0-review.md).

## Guiding rules

1. **Record behaviour; don't fix it.** Tests capture what the code does
   today, bugs included. In consensus code, behaving the same as the rest of
   the network counts for more than being "correct". A suspected bug is
   written down and its current behaviour pinned; any fix is a separate,
   deliberate change.
2. **Use real data, and synthetic data where real data can't reach.** No code
   in this tree creates proof-of-stake blocks today, and the stake kernel only
   runs below height 1,890,000, so historical mainnet blocks are the primary
   source. A test-only synthetic PoS generator (P0-55) covers branches and
   overflow cases the real chain never hits.
3. **Durable artefacts outlive the code they test.** Golden vectors, mainnet
   dumps and RPC snapshots are implementation-neutral (hex in, hex out) and
   are what Phase 4 is judged against. Tests that call the `CBigNum` API
   directly are accepted as temporary and are retired in Phase 4.
4. **Know which parameters a test runs with.** There are three different
   parameter sets today (see 0.1); every test states which one it uses.

## 0.1 Infrastructure and test environment

### Parameter sets in use today

| Context | Chain params | Globals | Consequence |
|---|---|---|---|
| Unit tests (`test_bitcoin`) | main (or low-diff main) | `nMainnetNewLogicBlockNumber = 0`, `nFactorAtHardfork = 0` (only set in `AppInit`) | Everything is "post-fork from height 0" with Nf 0; stake-modifier code returns early; old retarget branch unreachable. |
| Functional tests | **main params with the low-difficulty genesis** (never `-regtest`) | `epochinterval=10`, `nFactorAtHardfork=4`, fork height set per test | Fast mining; PoW-only chains. |
| Mainnet node | main | fork at 1,890,000, Nf 21 | The real thing. |

A shared harness (P0-47, `src/test/consensus_harness.h`, usage in
`src/test/README.md`) lets unit tests set these globals explicitly, so
consensus functions can be tested in pre-fork and post-fork mode with real
mainnet values.

### Infrastructure items

| Item | Detail | Task |
|---|---|---|
| Build image | Ubuntu 24.04 with GCC 11 pinned (same compiler as the 22.04 baseline); Dockerfile in dev34253/yacoin-build-ubuntu (`Dockerfile.ubuntu.24.04-gcc11`); published to Docker Hub as `dev34253/yacoin-build:ubuntu.24.04-gcc11-1`. | P0-57 |
| Build configurations | Mainnet and low-difficulty builds via one script, coverage (`CFLAGS` **and** `CXXFLAGS`) and sanitizer options; out-of-tree. Measure unit-test runtime in the mainnet config before deciding where unit tests run. | P0-01 |
| `pow_tests` failure | Caused by the low-difficulty `powLimit`; add the mainnet-config run and document. Done: the test pins the result per configuration, unit tests 239/239 in both. | P0-02 |
| CI | Unit, functional, coverage on push; a CI skeleton with schedules, runner, artifact storage and image mirroring. Each later job task adds its own job. P0-03: `.github/workflows/tests.yml` – unit tests in both configurations, functional in lowdiff, coverage of both configurations merged as a union (`contrib/testing/README.md`). | P0-03, P0-44 |
| Coverage gates | Re-baselined after CI merges both configurations; **branch** coverage for consensus math; dead code and dead `fTestNet` branches excluded from denominators. | P0-04 |
| Fixture storage | Small in repo, large external with manifest and checksums; also pre-fetched `depends` sources. | P0-05 |
| Baseline binaries | Built from the **end of Phase 0 infrastructure** (includes the dump tool and `gettxoutsetinfo`), mainnet and low-diff builds, recorded by commit and image digest. | P0-06 |
| Old release builds | v1.0.0/v1.1.0 rebuilt with the low-difficulty flag (release binaries can't join the functional-test network). | P0-54 |
| UTXO hash RPC | Port `gettxoutsetinfo` / `GetUTXOStats` from Bitcoin Core 0.16 – it does not exist in this tree. | P0-48 |
| Inventory correction | Overview facts checked against the source; dead-code list in [`dead-code.md`](dead-code.md); Phase 3/5 scope. | P0-50 |
| Dead-code removal | Removes the [`dead-code.md`](dead-code.md) list in three gated PRs (no consensus file / `scrypt.cpp` after P0-19 / consensus files after their tests and the replay). **Not** a Phase 0 exit criterion. | P0-59 |

## 0.2 Unit tests (C++, `test_bitcoin`)

All consensus unit tests use the shared harness (P0-47): block-index /
`chainActive` builder, explicit globals, mocktime, temporary block files.

### a) `CBigNum` contract (`bignum.h`) – P0-10 … P0-13

- Constructors, conversions, text/bytes, arithmetic, comparisons.
- Edge semantics the replacement must match: `%` is non-negative
  (`BN_nnmod`); `>>` of a negative value gives 0; `getuint256`/`getuint64`
  return the magnitude mod 2^n; `BN_div` truncates toward zero; compact values
  ≥ 2^256 are representable.
- Compact form (`SetCompact`/`GetCompact`): every exponent 0–34, sign bit,
  overflow, zero; Bitcoin's `arith_uint256` compact tests ported, differences
  listed. Done in P0-11: `src/test/bignum_compact_tests.cpp`; the
  differences (negative results, negative zero from a sign-bit `nBits`,
  exact values ≥ 2^256, exponent wrap at 2^2039) are listed in
  `project/done/P0-11-compact-encoding-tests.md` as Phase 4 special cases.
- Values over 256 bits: the kernel product, the trust shift, the reward
  bisection products.
- Method audit: which methods are used at all (`pow`, `mul_mod`, `pow_mod`,
  `inverse`, `gcd`, `isPrime`, `randBignum`, `RandKBitBigum`,
  `generatePrime`, `bitSize`, `isOne`, `getint32`, `setuint160`, …). Unused
  methods are excluded from the coverage target and deleted in Phase 4. The
  audited list (compile-time audit, P0-12) is in [`dead-code.md`](dead-code.md)
  c), with the `bignum.h` line ranges of the used methods; only those count
  for the "`bignum.h` (used methods only)" target in 0.10, because
  `bignum_tests` (P0-10) instantiates most unused methods in coverage builds.
  Large-value expressions: `src/test/bignum_consensus_tests.cpp` (P0-12).
- Golden vectors (~100k operations, hex in/out) – the durable artefact.

### b) Difficulty (`pow.cpp`) – P0-14, P0-15

- All functions with synthetic chains, in pre-fork and post-fork mode.
- `CalculateNextWorkRequired` scans **all** post-fork blocks for `nMinEase`
  and reads the genesis block from disk; tests and fixtures must provide that.
- Real mainnet windows, with all post-fork index entries available.

### c) Chain trust and fork choice (`chain.cpp`, `chain.h`, `net_processing.cpp`) – P0-16

- Every `GetBlockTrust` branch (see overview), the `fTestNet` switch,
  accumulated `bnChainTrust`, `CBlockIndexWorkComparator`,
  `GetBlockProofEquivalentTime` (mixes Yacoin trust with `GetBlockProof`;
  pin, don't fix), the `net_processing.cpp` comparisons, RPC `chaintrust`.

### d) Proof-of-stake (`kernel.cpp`) – P0-17, P0-18

- Stake modifier computation and checkpoints on contiguous mainnet index
  segments, with mainnet globals set and mocktime.
- Kernel accept/reject on real PoS blocks and one-field mutations; overflow
  inputs; negative coin-day weight; truncated `targetProofOfStake` vs
  full-precision comparison.
- Primary criterion: every historical PoS block and stake modifier
  reproduced (P0-23). Line coverage is secondary (much of `kernel.cpp` is
  debug logging).

### e) Block PoW hash (scrypt-jane, `primitives/block.h`) – P0-19

- `CBlockHeader::GetHash()` known answers for v<7 headers at every N-factor
  step in the `block.h` table (4…25) and v≥7 at Nf 21 (mainnet), 4
  (functional tests) and 0 (unit tests).
- `static_assert` on packed header sizes (88 and 80 bytes).
- Dead `scrypt.cpp` functions are not tested; they are on the
  [deletion list](dead-code.md). The only live one is
  `scrypt_hash(..., Nfactor)`, which `CalculateHash` calls; these known
  answers are the gate for removing the rest (P0-59 part B).

### f) Rewards and block size – P0-46

- `GetProofOfWorkReward` pre-fork (`CBigNum` bisection) and post-fork
  (`double` inflation), `GetMaxSize`, `GetProofOfStakeReward`/`GetCoinAge`,
  `LoadBlockRewardAndHighestDiff`, `getsubsidy`.
- Golden table for every pre-fork `nBits` seen on mainnet plus boundaries;
  reward and max size per epoch.

### g) Token-name validation – P0-49

- `std::regex`-based `IsTokenNameValid` and tag validators: golden
  accept/reject set over generated names (all short strings over the relevant
  alphabet) and adversarial cases. Runs on every build target.

### h) Chain parameters snapshot – P0-20

- All three parameter sets (mainnet, low-diff functional, unit-test
  globals), including fork heights, N-factor at fork, epoch interval,
  checkpoints, stake-modifier checkpoints.

### i) Randomness – P0-21

- API contracts and a loose statistical check for `random.cpp`.
- `random_nonce.cpp` recorded as dead code ([`dead-code.md`](dead-code.md)).

### j) Wallet encryption – P0-22

- The OpenSSL → internal AES/KDF switch has already landed. Known-answer
  vectors for `BytesToKeySHA512AES` and AES-256-CBC replace the OpenSSL test
  oracle; master-key round trip; wrong passphrase, damaged ciphertext.

## 0.3 Mainnet data and replay (the most important test)

| Step | Detail | Task |
|---|---|---|
| Sync | Self-hosted machine; `addnode` peers (no DNS seeds); record time, disk, memory; `-stopatheight` snapshots at chosen heights for P0-25. | P0-07 |
| Dump tool | Per block: height, hash, header hash and its N-factor, `nTime`, `nBits`, PoW/PoS, next required target, running min `nBits` since fork, `GetBlockTrust`, chain trust, stake modifier and checksum, `hashProofOfStake`, all kernel inputs (blockFrom time, `txPrev.nTime`, tx offset, prevout n, `nValueIn`, coinstake `nTime`, entropy bit/`nFlags`, `prevoutStake`), kernel result, block reward and coinbase value, PoS reward/coin age, max block size, `nMoneySupply`. | P0-08 |
| Fixtures | Full dump externally; in-repo fixture = several contiguous segments (≥ 50k blocks each, enough for 30-day stake age and selection intervals) plus all post-fork blocks; size re-estimated. | P0-09 |
| Offline replay | Recompute every dumped value; sampled replay in CI. **Primary exit criterion for kernel, reward and difficulty.** | P0-23 |
| Full reindex | `-reindex -checkblocks=0 -checklevel=4`; compare tip, chain trust, `gettxoutsetinfo` hash, checkpoint states, and `debug.log` free of "Failed stake modifier checkpoint". Takes 24–48 h; `-reindex-fast` is not a substitute. | P0-24 |
| Script checks | The reindex skips script verification below the last checkpoint (≈99% of history); add a test-only switch to force it, or document the gap. | P0-52 |
| Rejection | Mutated real blocks near prepared snapshots, or at unit level with on-disk block files. | P0-25 |

## 0.4 Oracle, differential testing, fuzzing, mutation testing, sanitizers

- **Reference oracle** (P0-51, P0-26): an OpenSSL-backed copy of `CBigNum`
  cannot compile against OpenSSL ≥ 1.1 and won't exist after Phase 5. Decide
  between (a) a pimpl reference using `BIGNUM*` with libcrypto as a
  test-only dependency until Phase 4 is verified, or (b, preferred)
  `boost::multiprecision::cpp_int` as an independent header-only oracle
  (check its C++ standard requirement first). Either way it is validated
  against the golden vectors.
- **Property tests** (P0-27): algebraic identities on random inputs.
- **Fuzzing** (P0-28): libFuzzer entry point (the current harness is
  AFL-stdin only); targets for compact decode, big-number ops,
  `CheckProofOfWork`, difficulty, kernel, reward, token names.
- **Mutation testing** (P0-56) over `pow.cpp`, trust, kernel and reward:
  every surviving mutant gets a test or a written justification.
- **ASan + UBSan** (P0-29) on unit and functional suites.
- **Static analysis** (P0-58): clang-tidy (curated checks), Clang Static
  Analyzer, cppcheck and CodeQL; today's findings recorded as a baseline and
  CI fails on new findings only. Consensus-code findings are pinned by tests,
  not fixed, in Phase 0.

## 0.5 Functional tests (Python, low-difficulty main params)

| Test | Purpose | Task |
|---|---|---|
| `wallet_encryption_compat.py` | Wallets created by v1.0.0/v1.1.0 (OpenSSL `EVP_BytesToKey`) and the baseline open, unlock, re-encrypt, sign. | P0-30 |
| `feature_difficulty_epochs.py` | Retargets across epochs vs stored values. | P0-31 |
| `feature_chaintrust_reorg.py` | Fork choice by trust (PoW; PoS branches via P0-55). | P0-32 |
| `rpc_output_snapshots.py` | `getblock`, `getblockheader`, `getdifficulty` (incl. target), `getmininginfo`, `getblocktemplate`, `getsubsidy`, `getwork` (midstate/data), `gettimechaininfo`, `calculatescrypthash`. | P0-33 |
| `feature_shutdown.py` | Start/stop, `SIGTERM`, shutdown during sync/reindex/mining; Boost filesystem cases (`backupwallet` overwrite, relative/trailing-slash paths). | P0-34 |
| `p2p_fixture_sync.py` | Sync from a stored chain; compare tip, trust, UTXO hash. | P0-35 |
| Synthetic PoS | Test-only coinstake grinding on a pre-fork test chain. | P0-55 |
| Flakiness baseline | Full suite 10×, repeated at exit. | P0-36, P0-45 |

## 0.6 Cross-version and cross-target

- Mixed-version network (P0-37) and datadir compatibility (P0-38), using
  low-difficulty builds of the baseline and old releases (P0-54).
- Tests on Windows (wine) and macOS builds (P0-53): `test_bitcoin` and the
  known-answer suites for header hash, reward/max size, token regex and
  compact encoding.

## 0.7 Performance

- Benchmark framework (P0-39, port of Bitcoin Core 0.16 `src/bench`).
- Microbenchmarks (P0-40): big-number ops, compact, trust, PoW check,
  retarget, kernel, modifier, reward, header hash per N-factor, AES/KDF,
  `GetStrongRandBytes`, (de)serialisation, `ConnectBlock`.
- System level (P0-41): reindex time and memory, sync from local peer,
  startup/shutdown, RPC latency. Median of 5 on a fixed machine; >10% change
  flagged.

## 0.8 Long-running

- Mainnet soak 24–72 h (P0-42); nightly fuzzing with corpus retention (P0-43).

## 0.9 CI layout (P0-44 skeleton; jobs added by their tasks)

| Trigger | Jobs |
|---|---|
| Every push | Both builds; unit (both configs if affordable); functional; sampled replay; coverage gates. Done by P0-03 (`tests.yml`): unit in both configs and functional on every push; coverage per config and merged on master and by hand |
| Nightly | Sanitizers; fuzzers; benchmarks; functional 3×; Windows/macOS test runs |
| Weekly / manual | Full replay and reindex (self-hosted, 24–48 h); cross-version network; soak |

## 0.10 Exit criteria

Primary (behavioural):

- Offline replay reproduces every dumped value for every mainnet block,
  including every historical PoS block and stake modifier (P0-23).
- Full reindex matches the baseline; no stake-modifier checkpoint failures
  (P0-24); script-check gap closed or documented (P0-52).
- Golden vectors, reward table, header-hash and token-name known answers
  pass on every build target (P0-13, P0-46, P0-19, P0-49, P0-53).
- Reference oracle chosen and validated (P0-51, P0-26).
- No surviving mutants in consensus math without justification (P0-56).

Secondary (coverage, branch coverage for consensus math, dead code excluded):

| File | Today (lines) | Target |
|---|---|---|
| `pow.cpp` | 76.9% (50% of functions) | 100% functions, ≥ 95% branches |
| `chain.cpp` trust code | 76.2% | 100% of `GetBlockTrust` branches |
| `kernel.cpp` (excluding debug logging) | 17.9% | ≥ 90% lines |
| reward functions in `validation.cpp` | – | 100% branches |
| `bignum.h` (used methods only) | 73.7% | ≥ 95% |
| `wallet/crypter.cpp` | 73.4% | ≥ 95% |
| `random.cpp` | 85.8% | ≥ 90% |
| Overall | 75.7% | ≥ 80% |

Plus: benchmark and flakiness baselines recorded; every suspected bug written
down with its behaviour pinned; accepted residual risks listed (mempool and
token consensus rely on existing tests and replay).

## Suggested order

1. Decisions and infrastructure: P0-00, P0-01, P0-02, P0-03, P0-05, P0-44,
   P0-47, P0-48, P0-50.
2. Mainnet data (longest lead time): P0-07, P0-08, P0-09; then baseline
   binaries P0-06 and old builds P0-54.
3. Consensus unit tests that need no mainnet data: P0-10–14, P0-16, P0-19,
   P0-20, P0-46 (synthetic part), P0-49.
4. Mainnet-driven tests: P0-15, P0-17, P0-18, P0-23, P0-25.
5. Oracle and robustness: P0-51, P0-26, P0-27, P0-28, P0-29, P0-56.
6. Functional and cross-version/target: P0-30–38, P0-53, P0-55.
7. Performance and long-running: P0-39–43; full reindex P0-24, P0-52.
8. Exit review P0-45.

## Decisions (P0-00, settled 2026-10-02)

| Topic | Decision |
|---|---|
| Mainnet node host | Your own machine/server as a self-hosted GitHub Actions runner (cloud sessions can't reach P2P port 7688). |
| Sync peers | 7 fixed seeds + known reliable peers via `addnode`, listed in the P0-07 runbook. |
| Where work lands | Fork first (dev34253/yacoin), upstream later in reviewed batches. |
| Old release wallets | v1.0.0/v1.1.0 encrypted wallets must stay readable; tested in P0-30. |
| Qt | Deferred to its own later phase; Phase 0 builds with `NO_QT=1`. |
| Build OS | Ubuntu 24.04 image with GCC 11 pinned (P0-57); GCC 13 in Phase 1. |
| CI and images | GitHub Actions (hosted for per-push, self-hosted for long jobs); build images published to Docker Hub from dev34253/yacoin-build-ubuntu and pinned by digest; a GHCR mirror against Docker Hub rate limits is optional (P0-44). |
