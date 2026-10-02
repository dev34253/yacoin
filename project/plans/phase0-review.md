# Phase 0 plan review (2026-10-02)

An independent, read-only review of the first version of the plans and the
46 Phase 0 tasks, checked against the source. The key claims (wallet crypter
already free of OpenSSL, functional tests not on regtest, `gettxoutsetinfo`
missing, `CBigNum` in `GetProofOfWorkReward`, `GetNfactor` display-only,
`std::regex` in token validation) were spot-checked and confirmed.

All findings below have been applied to `overview.md`,
`phase0-test-safety-net.md` and the task files. Task IDs in the "Applied in"
column refer to the revised task list.

## Summary verdict

The Phase 0 structure (pin behaviour → mainnet replay → differential/fuzz) is
sound. The first version pointed at the wrong code in several places: it
missed the most arithmetic-heavy `CBigNum` consensus function (pre-fork PoW
reward, ~400-bit intermediates), targeted dead `scrypt.cpp` code and the
display-only `GetNfactor` instead of the real block-hash path (scrypt-jane in
`primitives/block.h`), planned a wallet AES/KDF port that has already
happened, assumed functional tests run on regtest and unit tests with
mainnet settings (neither is true), and relied on two RPCs
(`gettxoutsetinfo`, `getblockchaininfo`) that don't exist. Several task
dependencies were missing or circular, and the baseline binary was built too
early to contain the tooling later tasks compare against.

## (A) Factual errors

| # | Sev | Finding | Evidence | Applied in |
|---|---|---|---|---|
| A1 | High | Wallet crypter already uses internal `crypto/aes.h`, `crypto/sha512.h` and its own `BytesToKeySHA512AES`; OpenSSL EVP only as a test oracle. v1.0.0/v1.1.0 still used `EVP_BytesToKey`. | `wallet/crypter.cpp:8-9,17-41`; `wallet/test/crypto_tests.cpp:24-84` | overview, P0-22, P0-30 |
| A2 | High | Block PoW hash is `CBlockHeader::CalculateHash` → scrypt-jane with the consensus N-factor table in `block.h`; `GetNfactor` is display-only; `scrypt_blockhash`, salted, multiround, `scanhash_scrypt` are dead. | `primitives/block.h:126-218`; `main.cpp:100`; `rpc/mining.cpp:313`; `qt/clientmodel.cpp:210` | P0-19 rescoped, P0-50 |
| A3 | High | Functional tests never pass `-regtest`; they run `CMainParams` with the low-difficulty genesis, `epochinterval=10`, `nFactorAtHardfork=4`, per-test fork height. `CRegTestParams` shares magic and port with main. | `test_framework/util.py:337-338`; `test_node.py:92-101`; `chainparams.cpp:82-84,133,233` | plan 0.5, P0-20 |
| A4 | High | In `test_bitcoin` the globals `nMainnetNewLogicBlockNumber` and `nFactorAtHardfork` are 0 (only set in `AppInit`), so unit tests run "post-fork from height 0" with Nf=0; `ComputeNextStakeModifier` and `CheckStakeModifierCheckpoints` return early; the old retarget branch is never reached. | `util.cpp:576-578`; `init.cpp:858-860,1144`; `kernel.cpp:189,651`; `pow.cpp:184-203` | plan 0.1, P0-47 |
| A5 | High | `CBigNum` inventory incomplete: also `consensus/params.h:62,64` (`powLimit`), `main.cpp:74-75`, `rpc/mining.cpp:145,420,860`, `rpc/blockchain.cpp:358`, `miner.cpp:642,801`, `qt/explorer.cpp:1302`; `bnChainTrust` drives P2P logic in `net_processing.cpp:438-456,536,1481,1507,1583,3113-3119`. | grep | overview, P0-16, P0-32 |
| A6 | Med | "177 uses" = 113 inside `bignum.h` + ~60 production call sites in 13 files + 4 in tests. | grep | overview |
| A7 | Med | Bitcoin's `(~t/(t+1))+1` only matches the legacy PoS branch. Live trust rules: PoW = `powLimit/target` (×2 after PoS), PoS-after-PoW = `pprev->GetBlockTrust()+1`, PoS-after-PoS = 0, genesis = 1, pre-switch PoW = 1. `GetBlockProofEquivalentTime` mixes Yacoin trust with Bitcoin `GetBlockProof`. | `chain.cpp:75-115,188-205`; `timestamps.h:29`; `net_processing.cpp:1119` | overview, P0-16 |
| A8 | Med | `random_nonce.cpp` uses `rand()`/`srand(time)`, not OpenSSL; only caller is dead `scanhash_scrypt`. | `random_nonce.cpp:9,27,71`; `scrypt.cpp:266` | P0-21, P0-50 |
| A9 | Med | "PoS can only be exercised with mainnet data" is too strong: synthetic coinstakes can be ground on a pre-fork test chain with `setmocktime`. | `rpc/misc.cpp:1278`; `pow.cpp:21`; `feature_hardfork_1_0.py` | P0-55 |
| A10 | Low | libssl still linked into `yacoind`/`yacoin-cli`; configure requires libssl. | `Makefile.am:407,425`; `configure.ac:922-941` | overview Phase 5 |
| A11 | Low | 16 files use `boost::bind`, ~9 use `_1`/`_2`. | grep | overview |
| A12 | Low | `bnChainTrust` is not serialised (correct), but `nStakeModifier` and `hashProofOfStake` are; a stake-modifier checkpoint mismatch at load only logs. | `chain.h:521-526`; `validation.cpp:3763-3764` | P0-24, P0-38 |

Confirmed correct: `pow_tests/get_next_work_pow_limit` failure is the
low-difficulty flag (`0x0fffff·2055491/1260000` gives exactly `0x1e1a19f8`,
clamped by the mainnet `powLimit` 2^236 but not by the low-diff 2^253);
kernel product can exceed 2^256 (≈2^263 worst case); `CScriptNum` does not
use `CBigNum`.

## (B) Missing risks

| # | Sev | Risk | Evidence | Applied in |
|---|---|---|---|---|
| B1 | High | Pre-fork PoW reward uses `CBigNum` bisection with ~400-bit products. | `validation.cpp:918-979`; callers `validation.cpp:2021`, `miner.cpp:526`, `rpc/mining.cpp:153,301` | P0-46 |
| B2 | High | Post-fork reward and max block size (`GetMaxSize`) use `double`; consensus. | `validation.h:235`; `validation.cpp:932,3714-3717`; `consensus/consensus.cpp:26-27` | P0-46, P0-53 |
| B3 | High | Consensus `std::regex` in token-name validation, no unit tests; implementation differs across GCC versions and targets. | `tokens/tokens.cpp:67-74`; `consensus/tx_verify.cpp:227,328,587` | P0-49 |
| B4 | High | scrypt-jane SIMD path chosen at compile time; packed headers hashed raw. | `Makefile.am:186-195`; `block.h:22-44` | P0-19, P0-53 |
| B5 | Med | OpenSSL inventory gaps: `pbkdf2.cpp`, `miner.cpp:93-105` (`SHA256_CTX` internals for `getwork`), `support/cleanse.cpp:13`, `util.cpp:120-163` (locking callbacks; `RAND_screen` on WIN32), Qt files, stale includes. | as listed | overview, P0-50, P0-33 |
| B6 | Med | Reindex skips script verification below the last checkpoint (≈99% of history). | `validation.cpp:1725` | P0-52 |
| B7 | Med | Global/wall-clock state: `chainActive`, `mapBlockIndex`, `GetAdjustedTime`, `ReadBlockFromDisk(genesis)`; retarget scans all post-fork blocks for `nMinEase`. | `pow.cpp:40-68,174-176`; `kernel.cpp:139,339-370` | P0-08, P0-09, P0-15, P0-47 |
| B8 | Med | Boost behaviour: `copy_option::overwrite_if_exists`, `basename`/`extension`, `is_complete`, `thread_interrupted`, `assign::map_list_of`; C++11 pinned while some Boost 1.8x libs need C++14. | `wallet/db.cpp:270,715`; `util.cpp:771,831`; `rpc/protocol.cpp:77`; `kernel.cpp:33-71`; `configure.ac:65` | P0-34, P0-51 |
| B9 | Med | Qt out of scope but shipped; depends Qt 5.7.1 won't build with GCC 13; `qt/explorer.cpp` uses `CBigNum`. | `depends/packages/qt.mk:2`; CI workflow | P0-00 |
| B10 | Low | `CBigNum` edge semantics to match: `%` non-negative, `>>` of negative gives 0, `getuint256`/`getuint64` magnitude mod 2^n, truncated `targetProofOfStake`, possible negative coin-day weight, `BN_div` truncates toward zero. | `bignum.h:268-288,396-409,728-733,831`; `kernel.cpp:447-461,526,568` | P0-10, P0-12, P0-18 |
| B11 | Low | `fTestNet` branches are dead (no testnet params). | `chainparams.cpp:323-330`; `chain.cpp:83`; `kernel.cpp:76,656` | P0-04, P0-16 |

## (C) Test-plan gaps

| # | Sev | Gap | Applied in |
|---|---|---|---|
| C1 | High | Dump lacks kernel inputs, rewards, max size, money supply, header hash/Nf, running min `nBits`. | P0-08 |
| C2 | High | "Few thousand records" cannot drive kernel/modifier tests; needs contiguous segments and all post-fork blocks. | P0-09 |
| C3 | High | Kernel code only runs below height 1,890,000; full replay of every historical PoS block should be the primary exit criterion. | plan 0.10, P0-23 |
| C4 | Med | Line coverage weak for consensus math; `scrypt.cpp` target meaningless; C sources need `CFLAGS` coverage. | P0-01, P0-04, P0-56 |
| C5 | Med | Thresholds from one low-diff build; merging two configurations' `.info` files undefined. | P0-03, P0-04 |
| C6 | Med | RPC snapshot list wrong/incomplete. | P0-33 |
| C7 | Med | Windows/macOS builds never run tests. | P0-53 |
| C8 | Med | PoS trust branches in fork choice untested. | P0-16, P0-55 |
| C9 | Low | Direct `CBigNum` API tests will not survive Phase 4. | plan rule 3, P0-13 |
| C10 | Low | Mempool/token consensus only covered by existing tests and replay. | plan (accepted residual risk) |

## (D) Task and dependency issues

| # | Sev | Issue | Applied in |
|---|---|---|---|
| D1 | High | `gettxoutsetinfo` doesn't exist. | P0-48; deps of P0-06, P0-24, P0-35 |
| D2 | High | Baseline binary built too early. | P0-06 redefined |
| D3 | High | P0-43 ↔ P0-44 practical cycle. | P0-44 = CI skeleton; job tasks add their own jobs |
| D4 | High | Exit review deps incomplete. | P0-45 depends on all |
| D5 | Med | Missing deps (P0-06/07→05, P0-13→12, P0-28→29, P0-25→07, P0-24→06, P0-41→06, P0-08→07). | all applied |
| D6 | Med | Conditional acceptance criteria (P0-16, P0-19). | split/moved to P0-23 |
| D7 | Med | No shared consensus test harness. | P0-47; P0-17/18 sized L |
| D8 | Med | Mutated-block submission needs datadirs near the target heights. | P0-07 (`-stopatheight` snapshots), P0-25 |
| D9 | Low | P0-12 method audit list incomplete. | P0-12 |
| D10 | Low | P0-02 effectively solved. | P0-02 shrunk |
| D11 | Low | Flakiness measured before new tests exist. | P0-45 re-run |

## (E) Feasibility

| # | Sev | Issue | Applied in |
|---|---|---|---|
| E1 | High | Frozen OpenSSL-backed `CBigNum` can't compile against OpenSSL ≥1.1 or survive Phase 5. | P0-51 (oracle decision), P0-26 |
| E2 | High | Release binaries are mainnet builds and can't join the low-diff functional-test network. | P0-54 |
| E3 | Med | Mainnet sync/reindex 24–48 h, scrypt-jane memory-heavy, 6 h hosted-runner limit, no DNS seeds; `-reindex-fast` is not a substitute. | P0-00, P0-07, P0-24 |
| E4 | Med | Unit tests with mainnet `powLimit` may be slow (`TestChain100Setup` brute-forces blocks). | P0-01 |
| E5 | Low | Docker Hub rate limits; images pinned by tag. | P0-44 |
| E6 | Low | Old tags need old depends sources that may have disappeared. | P0-05 |
