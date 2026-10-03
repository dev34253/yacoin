# Yacoin Core – software architecture

This document describes how Yacoin Core is built and how it is organised:
the build products and libraries, the source tree, the processes and
threads at run time, persistent storage, the network and RPC layers, the
validation pipeline, and the build and test infrastructure. It also shows
where the dependency modernisation (see `project/`) will change things.

- What the software does: [functional specification](functional-specification.md).
- Why it is built this way: [design decisions](design-decisions.md).
- State: tree at version 1.11.0, identical to yacoin/yacoin `master` plus
  the dev34253 project and testing files (October 2026).

## 1. Context

```
            miners (ccminer, cpuminer,       wallets, explorers,
            pools)                           YASwap atomic-swap agents
                 │ getwork / getblocktemplate       │ JSON-RPC
                 ▼                                  ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ yacoind                                                      │
 │  P2P (7688) ◄──► other yacoind nodes                          │
 │  RPC (7687) ◄──  yacoin-cli                                   │
 │  datadir: blocks/, chainstate/, tokens/, wallet.dat, …        │
 └──────────────────────────────────────────────────────────────┘
```

- Yacoin Core is a single daemon (`yacoind`) plus an RPC client
  (`yacoin-cli`). A Qt GUI (`yacoin-qt`) exists in the tree but is not
  built in the supported configuration.
- External programs in the wider Yacoin ecosystem (ccminer forks, the
  YASwap wallet and atomic agent, the block explorer) talk to it only over
  RPC. They live in other repositories and are out of scope here.
- Pre-fork 0.4.x nodes cannot follow the chain after block 1,890,000; they
  are on a different chain.
- There are no DNS seeds; nodes find each other through 7 fixed seeds,
  `addnode` and address relay.

## 2. Heritage

The code is a layered result of three code bases:

| Layer | Origin | Where it shows |
|---|---|---|
| Infrastructure | Bitcoin Core 0.15/0.16 (ported 2021–2026) | `init`, `net`, `net_processing`, `validation` structure, `txdb`, mempool, wallet, RPC server, `arith_uint256`, `gArgs`, tests |
| Consensus core | PPCoin / NovaCoin / Yacoin 0.4.x (2013–2018) | `kernel.cpp`, `bignum.h` (`CBigNum`), block trust, pre-fork difficulty and reward, block signatures, `nTime` in transactions |
| Yacoin 1.x additions | Yacoin developers (2020–2026) | Heliopolis fork rules, scrypt-jane at fixed N-factor, 64-bit time, epoch reward/difficulty, timelock RPCs, tokens (from Ravencoin), multithreaded hash calculation |

The structure is that of Bitcoin Core 0.15 with some 0.16 parts (free functions in
`validation.cpp`, no `CChainState` class), with `PROTOCOL_VERSION`
70015. The PPCoin consensus code was kept as is and wrapped, not
rewritten (see [D-01](design-decisions.md#d-01-keep-the-ppcoin-consensus-code)).

## 3. Build products and libraries

Defined in `src/Makefile.am`, `src/Makefile.test.include`,
`src/Makefile.qt.include`.

| Product | Built | Contents |
|---|---|---|
| `yacoind` | yes | the node |
| `yacoin-cli` | yes | RPC client |
| `test/test_bitcoin` | yes (in `bin_PROGRAMS`; run by `make check`) | Boost.Test unit tests |
| `test/test_bitcoin_fuzzy` | yes | AFL-style fuzz entry point (stdin) |
| `qt/yacoin-qt` | only with Qt (deferred) | GUI |
| `yacoin-tx`, `bench_bitcoin`, `libyacoinconsensus` | **no** | not present / commented out |

Internal static libraries (link order as in `yacoind_LDADD`):

```
yacoind ─┬─ libyacoin_server   node logic: init, net, net_processing, validation,
         │                     txdb, txmempool, miner, pow, kernel, checkpoints,
         │                     rpc/*, tokens/*, scrypt*.cpp/.S, scrypt-jane,
         │                     main.cpp (leftovers), pbkdf2, random_nonce
         ├─ libyacoin_common   chainparams, coins, keys, base58, script/sign,
         │                     script/standard, netbase, protocol, scheduler
         ├─ libunivalue        JSON
         ├─ libyacoin_util     util, args, fs, random, sync, time, clientversion
         ├─ libyacoin_wallet   wallet, walletdb, db (BDB), crypter, rpcwallet,
         │                     rpcdump                       (if wallet enabled)
         ├─ libyacoin_consensus primitives, script interpreter, hash,
         │                     arith_uint256, pubkey, LibBoolEE
         ├─ libyacoin_crypto   sha1/256/512, ripemd160, hmac, aes, chacha20,
         │                     siphash
         ├─ leveldb (+sse42, memenv)   bundled
         ├─ libsecp256k1               bundled
         └─ external: Boost, BDB 4.8, OpenSSL (libssl+libcrypto), libevent,
                      miniupnpc
yacoin-cli ── libyacoin_cli (rpc/client) + univalue + util + crypto
              + Boost, OpenSSL, libevent
```

Notes:

- `libyacoin_consensus` is not self-contained: consensus logic also lives
  in `libyacoin_server` (`pow.cpp`, `kernel.cpp`, `chain.cpp`,
  `consensus/consensus.cpp`, `consensus/tx_verify.cpp`, `validation.cpp`,
  `tokens/`) and depends on globals and `chainActive`.
- scrypt-jane (`src/scrypt-jane/scrypt-jane.c`) is compiled into
  `libyacoin_server` with `-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA
  -DSCRYPT_CHOOSE_COMPILETIME`, so the SIMD code path is chosen at compile
  time. The separate `-O3 -DUSE_ASM` rule in `Makefile.am` is unused.
- ZMQ is not built (no `src/zmq/`; `ENABLE_ZMQ` code in `init.cpp` is
  dead), REST is not built (no `rest.cpp`).
- OpenSSL is still linked into `yacoind` and `yacoin-cli`. Inside the node
  it provides `CBigNum` (`BIGNUM`); the RNG (`GetRandBytes` is
  `RAND_bytes`, mixed into `GetStrongRandBytes`, so key and wallet master-key
  generation depend on it) and its locking callbacks; `OPENSSL_cleanse`; and
  the SHA-256 midstate for `getwork`. The wallet cipher and signatures do
  **not** use it (in-tree AES, libsecp256k1).

## 4. Source tree

| Path | Purpose |
|---|---|
| `src/init.cpp`, `src/yacoind.cpp` | Start-up and shutdown; argument handling; sets the fork globals. |
| `src/validation.cpp/.h` | Block and transaction validation, chain activation, block files, reward function, global chain state. |
| `src/consensus/` | `params.h` (consensus parameters incl. `HeliopolisHardforkHeight`, `powLimit` as `CBigNum`), `consensus.cpp` (`GetMaxSize`, coinbase maturity), `tx_verify.cpp` (input, sequence-lock and token checks). |
| `src/pow.cpp` | Difficulty (pre- and post-fork), `CheckProofOfWork`, PoS limits and stake reward. |
| `src/kernel.cpp` | PPCoin stake kernel, stake modifier and its checkpoints. (`kernelrecord.cpp/.h` is an unbuilt minting-view class – dead code, P0-50.) |
| `src/chain.cpp/.h` | `CBlockIndex`, `CChain`, block trust, `bnChainTrust`. |
| `src/primitives/` | `CBlockHeader`/`CBlock` (scrypt-jane hash, header versions, PoS classification, block signature), `CTransaction` (`nTime`, normalized txid). |
| `src/scrypt.cpp`, `scrypt-*.S`, `scrypt-generic.cpp`, `src/scrypt-jane/` | Hash functions. Only `scrypt_hash` + scrypt-jane are live; the rest is dead code (P0-50). |
| `src/bignum.h` | `CBigNum`, a C++ wrapper that **inherits** from OpenSSL `BIGNUM` (needs OpenSSL 1.0.x). |
| `src/main.cpp/.h` | Leftovers from the 0.4.x `main.cpp`: PoS limits, display `GetNfactor`, `MAX_MINT_PROOF_OF_WORK`. |
| `src/timestamps.h` | Historic switch-over times (e.g. `CONSECUTIVE_STAKE_SWITCH_TIME`). |
| `src/checkpoints.cpp` | Hard-coded checkpoints. |
| `src/net.cpp`, `net_processing.cpp`, `addrman`, `protocol`, `netbase` | P2P (Bitcoin Core 0.15 design). |
| `src/txdb.cpp`, `dbwrapper` | LevelDB: block index, coins, block-hash cache, address index. |
| `src/txmempool.cpp`, `policy/` | Mempool and relay policy (`fees.h`: `MIN_TX_FEE`). |
| `src/miner.cpp` | Block assembly, internal PoW miner, `getwork` helpers. |
| `src/rpc/` | RPC server and command tables (blockchain, mining, misc, net, rawtransaction, tokens). |
| `src/httpserver.cpp`, `httprpc.cpp` | libevent HTTP server, JSON-RPC endpoint, auth. |
| `src/tokens/`, `LibBoolEE.*` | Token rules, token DB and caches, verifier-string evaluator (from Ravencoin). |
| `src/wallet/` | Wallet, BDB storage, encryption, wallet RPCs, wallet unit tests. |
| `src/script/` | Script interpreter (CLTV, CSV, `OP_YAC_TOKEN`), standard templates (incl. CLTV/CSV P2PKH), signing. |
| `src/crypto/`, `support/`, `compat/` | Hash/cipher primitives, secure allocators, platform shims. |
| `src/leveldb/`, `secp256k1/`, `univalue/` | Bundled third-party libraries. |
| `src/qt/` | GUI (deferred), incl. Yacoin `explorer.cpp`, which uses `CBigNum`. |
| `src/test/` | Unit tests. |
| `test/functional/` | Python functional tests and framework. |
| `depends/` | Reproducible dependency builds (Bitcoin Core system). |
| `contrib/testing/` | `build.sh`: scripted builds and test runs in the pinned image. |
| `project/` | Modernisation plans, task board, runbooks. |

### 4.1 Global state and fork switches

Consensus decisions read **process-wide globals** in addition to
`Params()`:

| Global | Set in | Used by |
|---|---|---|
| `cs_main`, `mapBlockIndex`, `chainActive`, `pindexBestHeader`, `setBlockIndexCandidates`, `mempool` | `validation.cpp` (static) | everything |
| `pcoinsTip`, `pblocktree`, `ptokensdb`, `ptokens` | `init.cpp` (Step 7) | validation, RPC, miner |
| `nMainnetNewLogicBlockNumber`, `nEpochInterval`, `nDifficultyInterval`, `nFactorAtHardfork`, `nTokenSupportBlockNumber` | `init.cpp` from arguments (epoch and N-factor in Step 3, fork and token heights at the start of Step 7) | pow, reward, size, maturity, header hash, tokens |
| `fTestNet` | `init.cpp` | dead branches (no testnet params) |

Consequences: consensus functions are not pure (they read `chainActive`,
the block index, block files and `GetAdjustedTime`), and the unit-test
binary runs them with the globals at 0. The Phase 0 harness (P0-47) makes
these inputs explicit for tests.

## 5. Persistent storage

Default data directory `~/.yacoin` (`%APPDATA%\Yacoin` on Windows).

| Path | Format | Content |
|---|---|---|
| `yacoin.conf`, `yacoind.pid`, `.lock`, `debug.log` | text | configuration, process files, log |
| `blocks/blk*.dat`, `blocks/rev*.dat` | raw | blocks and undo data, 128 MiB files |
| `blocks/index/` | LevelDB | block index (`b`), file info (`f`), last file (`l`), reindex flag (`R`), flags (`F`), tx index (`t`, on by default), block-hash cache, address index (`a`/`u`, only with `-addressindex`, which needs a reindex) |
| `chainstate/` | LevelDB | UTXO set, per output (`C`), best block (`B`), head blocks during a flush (`H`), Bitcoin Core 0.15 format |
| `tokens/` | LevelDB | token metadata and balances (`-tokenindex` adds lookups; needs a reindex) |
| `wallet.dat`, `database/` | Berkeley DB 4.8 | wallet(s) and BDB logs |
| `peers.dat`, `banlist.dat`, `mempool.dat` | Bitcoin serialisation | address manager, bans, mempool snapshot |
| `bootstrap.dat` | raw blocks | imported at start-up if present |

Not serialised: `bnChainTrust` (recomputed at load). Serialised and
computed with legacy code: `nStakeModifier`, `hashProofOfStake`,
`nMoneySupply` in the block index; coin and undo records change format at
the Heliopolis height.

## 6. Run-time architecture

### 6.1 Start-up (`AppInit` → `init.cpp`)

The step numbers are those of the `Step N` comments in `init.cpp`.

1. Steps 1–2: basic setup, parameter interaction.
2. Step 3: flags; `nEpochInterval`/`nFactorAtHardfork` from arguments; RPC
   tables registered.
3. Step 4: sanity checks, data-directory lock. Step 4a (`AppInitMain`):
   threads for script check, **hash calculation** and the scheduler;
   HTTP/RPC server in warm-up mode.
4. Steps 5–6: wallet verification, network set-up.
5. Step 7: fork and token heights from arguments; load the chain: migrate
   pre-1.5.0 data directories, open block-tree, coins and token databases,
   `LoadBlockIndex` (recompute trust, load reward and highest difficulty),
   `VerifyDB`.
6. Step 8: load wallets.
7. Step 10: import blocks **synchronously** (reindex, `bootstrap.dat`,
   `-loadblock`), `ActivateBestChain`, load mempool. (Bitcoin Core does
   this in a background `ThreadImport`; here start-up waits for it.)
8. Steps 11–12: start P2P (`connman.Start`), the optional internal miner,
   finish RPC warm-up.

Shutdown is the reverse (`Interrupt`, `Shutdown`), triggered by `stop`,
SIGTERM or SIGINT.

### 6.2 Threads

| Thread | Purpose |
|---|---|
| main | start-up, then waits for shutdown (renamed `yacoin-shutoff` during shutdown) |
| `yacoin-scheduler` | periodic tasks (wallet DB compaction every 500 ms, …) |
| `yacoin-scriptch` × n | parallel script verification (`CCheckQueue`) |
| `yacoin-hashcalc` × n | parallel scrypt-jane header hashing during sync (Yacoin-specific `CCheckQueue`) |
| `yacoin-net` | socket I/O |
| `yacoin-msghand` | P2P message processing (takes `cs_main`) |
| `yacoin-opencon`, `yacoin-addcon`, `yacoin-dnsseed` | outbound connections (`dnsseed` starts although there are no DNS seeds, unless `-dnsseed=0`) |
| `yacoin-upnp`, `yacoin-torcontrol` | optional |
| `bitcoin-http`, `bitcoin-httpworker` × n | HTTP server and RPC workers |
| `yacoin-miner` × n | internal PoW miner (`-gen`) |

`TraceThread` adds the `yacoin-` prefix. There is no staking thread. Most state is protected by `cs_main`; the
wallet adds `cs_wallet`; the mempool has its own `cs`.

### 6.3 P2P layer

- Bitcoin Core 0.15 message set, `PROTOCOL_VERSION` 70015; no
  Yacoin-specific messages; compact-block relay disabled (`sendcmpct` is
  still sent, but `cmpctblock`/`getblocktxn` handling is commented out).
- **Headers-first** download (`getheaders`/`headers`, `sendheaders`),
  with a Yacoin fallback: if headers are more than 10,000 ahead of blocks
  during initial download, send legacy `getblocks` once a minute.
- Scrypt-jane hashing of received headers is the main cost of sync; it is
  parallelised and cached.
- Peer and fork-choice decisions compare `bnChainTrust`, not chain work.

### 6.4 RPC

`httpserver.cpp` (libevent) → `httprpc.cpp` (auth, `/` and
`/wallet/<name>`) → `CRPCTable` (`rpc/server.cpp`). Command tables are
registered from `rpc/register.h` (core and tokens) and the wallet. RPC
handlers take `cs_main`/`cs_wallet` as needed.

### 6.5 Wallet

- `CWallet` instances (one per `-wallet=`), stored in BDB 4.8
  (`wallet/db.cpp`, `walletdb.cpp`), reached over RPC at `/wallet/<name>`.
- Keys: HD (BIP32) by default; keypool; encryption with in-tree AES and
  `BytesToKeySHA512AES`.
- Bitcoin Core 0.15 coin selection, plus Yacoin timelocks: CLTV/CSV P2PKH
  and P2SH templates in `script/standard.cpp`, spendable-balance rules for
  locked outputs (`getavailablebalance`, `useexpiredtimelockutxo`).
- The legacy accounts API is still present.
- Signs `getwork` and internally mined blocks (block signatures).

### 6.6 Validation pipeline

```
P2P block / submitblock / miner
  └─ ProcessNewBlock
       ├─ CheckBlock                 size, merkle, coinbase/coinstake shape,
       │    │                        block signature (after last checkpoint time)
       │    └─ CheckBlockHeader      PoW (PoW blocks), nNonce == 0 (PoS blocks)
       ├─ AcceptBlock  (cs_main)
       │    ├─ AcceptBlockHeader → ContextualCheckBlockHeader
       │    │      nBits == GetNextTargetRequired, checkpoints, time,
       │    │      version ≥ 7 after the fork
       │    ├─ ContextualCheckBlock  tx versions, finality (block time),
       │    │                        coinbase height, max size
       │    ├─ PoSContextualBlockChecks   only below the fork height
       │    └─ write block to disk; ReceivedBlockTransactions
       │           (stake modifier + checkpoints below the fork)
       └─ ActivateBestChain → ConnectTip → ConnectBlock
              inputs, scripts (CheckInputs), sequence locks, tokens,
              reward limit, nMoneySupply, UTXO and token cache flush

Transaction (P2P / RPC / wallet)
  └─ AcceptToMemoryPool → CheckTransaction, finality, sequence locks,
       CheckTxInputs, CheckTxTokens (if active), fee, scripts
```

## 7. Build infrastructure

| Element | Detail |
|---|---|
| Build system | autotools (`autogen.sh`, `configure.ac`, `Makefile.am`) |
| Dependencies | `depends/` builds pinned sources: OpenSSL 1.0.1k, Boost 1.64.0, BDB 4.8.30, libevent 2.1.8, miniupnpc 2.0, zeromq 4.1.5 (unused), Qt 5.7.1 + protobuf, qrencode, X11 libs (GUI only). See [dependencies](dependencies.md). |
| Configurations | *mainnet* (default) and *low difficulty* (`--enable-low-difficulty-for-development`) |
| Build image | `dev34253/yacoin-build:ubuntu.24.04-gcc11-1` (Ubuntu 24.04, GCC 11), pinned by digest; Dockerfiles in dev34253/yacoin-build-ubuntu |
| Scripted build | `contrib/testing/build.sh` – out-of-tree build from a copy, in the pinned image; options for configuration, coverage, sanitizers, unit and functional tests |
| CI | `.github/workflows/yacoinbuildmultiplatform.yml`: depends builds for Ubuntu 16.04–22.04, Windows and macOS (cross), a low-difficulty build and a functional-test job; no unit-test job yet (P0-03, P0-44) |
| Legacy | `build-windows-in-docker.sh` (qmake/makefile.mingw, files no longer exist), `doc/README_ubuntu.txt`, `doc/release-process.txt` |

## 8. Test architecture

| Level | Where | Notes |
|---|---|---|
| Unit | `src/test/*_tests.cpp`, `src/wallet/test/` → `test_bitcoin` (239 cases) | Boost.Test; fixtures `BasicTestingSetup`, `TestingSetup`, `TestChain100Setup`, `WalletTestingSetup`. Run in the **mainnet** build; fork globals are 0. |
| Functional | `test/functional/` (45 tests in `test_runner.py`) | Python framework from Bitcoin Core. Run in the **low-difficulty** build on main params (never `-regtest`), with `epochinterval=10`, `nFactorAtHardfork=4` and a per-test fork height. Yacoin-specific: `feature_hardfork_1_0`, `feature_epoch`, `feature_tokens`, `feature_token_overflow`, `feature_timelock`, `feature_op_cltv`, `feature_op_csv`, `feature_tx_malleability`, `feature_set_min_fee`, `feature_uptime`. |
| Fuzz | `test_bitcoin_fuzzy` | AFL/stdin only. |
| Planned (Phase 0) | `project/plans/phase0-test-safety-net.md` | mainnet replay, golden vectors, consensus harness, oracle, fuzzing, sanitizers, static analysis, benchmarks. |

## 9. Planned architectural changes

From [`project/plans/overview.md`](../project/plans/overview.md):

| Phase | Architectural effect |
|---|---|
| 0 | Test harness and fixtures; `gettxoutsetinfo`; dead-code inventory. No production behaviour change. |
| 1 | Compiler GCC 11 → 13. |
| 2 | Boost 1.64 → current; possibly C++14. |
| 3 | OpenSSL removed from non-consensus code (RNG, cleanse, `getwork` midstate); dead scrypt/pbkdf2 code deleted. |
| 4 | `CBigNum` replaced by `arith_uint256` with wider intermediates; `powLimit` type changes. |
| 5 | OpenSSL dropped from the build. |
| 6 | Berkeley DB decision (keep 4.8 or migrate wallets). |
| later | Qt GUI. |
