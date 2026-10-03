# Yacoin Core – design and implementation decisions

A log of the significant design and implementation decisions, in the style
of architecture decision records (ADRs): context, decision, consequences
and evidence. It covers the decisions inherited from the history of the
code (D-01 … D-14) and those of the current modernisation work
(D-15 … D-22), plus D-23, which is historical and was added after the
review.

- What the software does: [functional specification](functional-specification.md).
- How it is organised: [architecture](architecture.md).
- Sources: the code, the git history, `project/` (plans, task logs,
  review) and the Trello board "YACoin Development". The local clone is
  shallow, so commit dates before 2025 are approximate. Where the rationale
  was not written down and is inferred, the entry says so.

**How to add a decision.** Add an entry with the next free number, status
*Accepted* (or *Proposed* until the owner agrees), date, and the four
sections. Do not edit the substance of an accepted entry; supersede it with
a new one and set the old one's status to *Superseded by D-nn*. Task files
in `project/` that make a decision link to the entry.

## Index

| # | Decision | Status | Date |
|---|---|---|---|
| D-01 | [Keep the PPCoin consensus code](#d-01-keep-the-ppcoin-consensus-code) | Accepted | 2013–today |
| D-02 | [scrypt-jane PoW; N-factor frozen at the fork](#d-02-scrypt-jane-pow-n-factor-frozen-at-the-fork) | Accepted | 2013 / 2020 |
| D-03 | [Heliopolis hard fork: PoW only](#d-03-heliopolis-hard-fork-pow-only) | Accepted | 2021-04 |
| D-04 | [Epoch difficulty with a minimum-difficulty floor](#d-04-epoch-difficulty-with-a-minimum-difficulty-floor) | Accepted | 2021-04 |
| D-05 | [Supply-based reward; block size from reward and fee](#d-05-supply-based-reward-block-size-from-reward-and-fee) | Accepted | 2021-04 |
| D-06 | [Hard-coded checkpoints only](#d-06-hard-coded-checkpoints-only) | Accepted | 2021-03 |
| D-07 | [64-bit timestamps](#d-07-64-bit-timestamps) | Accepted | 2021-04 |
| D-08 | [Malleability fix by normalized txid](#d-08-malleability-fix-by-normalized-txid) | Accepted | 2021-04 |
| D-09 | [CLTV/CSV activated by height; lock times use block time](#d-09-cltvcsv-activated-by-height-lock-times-use-block-time) | Accepted | 2021-04 |
| D-10 | [Fork switches as start-up globals](#d-10-fork-switches-as-start-up-globals) | Accepted (to be revisited) | 2020–2021 |
| D-11 | [Port Bitcoin Core 0.15 infrastructure step by step](#d-11-port-bitcoin-core-015-infrastructure-step-by-step) | Accepted | 2021–2026 |
| D-12 | [Header-only PoS classification; parallel, cached block hashing](#d-12-header-only-pos-classification-parallel-cached-block-hashing) | Accepted | 2021–2022 |
| D-13 | [Tokens ported from Ravencoin; issuance fee as a timelock](#d-13-tokens-ported-from-ravencoin-issuance-fee-as-a-timelock) | Accepted | 2023 |
| D-14 | [LevelDB for chain data, Berkeley DB 4.8 for wallets](#d-14-leveldb-for-chain-data-berkeley-db-48-for-wallets) | Accepted | 2017–2025 |
| D-15 | [Qt GUI deferred](#d-15-qt-gui-deferred) | Accepted | 2026-10-02 |
| D-16 | [`depends` build and the yacoind / yacoin-cli split](#d-16-depends-build-and-the-yacoind--yacoin-cli-split) | Accepted | 2025 |
| D-17 | [Functional tests on low-difficulty main params, not regtest](#d-17-functional-tests-on-low-difficulty-main-params-not-regtest) | Accepted | 2020 |
| D-18 | [Modernise in phases behind a test safety net](#d-18-modernise-in-phases-behind-a-test-safety-net) | Accepted | 2026-10-02 |
| D-19 | [Build image: Ubuntu 24.04 with GCC 11, on Docker Hub](#d-19-build-image-ubuntu-2404-with-gcc-11-on-docker-hub) | Accepted | 2026-10-02 |
| D-20 | [Project logistics: fork first, own mainnet node, old wallets stay readable](#d-20-project-logistics-fork-first-own-mainnet-node-old-wallets-stay-readable) | Accepted | 2026-10-02 |
| D-21 | [Scripted out-of-tree builds in two configurations](#d-21-scripted-out-of-tree-builds-in-two-configurations) | Accepted | 2026-10-02 |
| D-22 | [Documentation set and process](#d-22-documentation-set-and-process) | Accepted | 2026-10-03 |
| D-23 | [Keep `getwork` next to `getblocktemplate`](#d-23-keep-getwork-next-to-getblocktemplate) | Accepted | 2020–2026 |

---

## D-01: Keep the PPCoin consensus code

- **Status:** Accepted. Its replacement is planned in Phase 4 (D-18).
- **Date:** 2013 (launch), kept through every port since.

**Context.** Yacoin started in 2013 as a PPCoin/NovaCoin derivative. Every
node must validate the whole chain from 2013, including about 1.9 million
blocks with PoS blocks, the NovaCoin reward curve and PPCoin block trust.

**Decision.** The legacy consensus code was kept as it is and the Bitcoin
Core infrastructure was built around it:

- `CBigNum` (`bignum.h`, a class that inherits from OpenSSL `BIGNUM`)
- the stake kernel and modifier (`kernel.cpp`)
- block trust (`chain.cpp`)
- the pre-fork difficulty (`pow.cpp`) and reward (`GetProofOfWorkReward`)
- block signatures
- `nTime` in transactions

`consensus.powLimit` is itself a `CBigNum`.

**Consequences.**

- The node only builds against OpenSSL 1.0.x, because `BIGNUM` became
  opaque in 1.1. This is the main reason for the modernisation programme.
- `arith_uint256` (Bitcoin) and `CBigNum` sit side by side.
- Several values exceed 256 bits: the kernel product, the trust of legacy
  PoS blocks, and the ~400-bit reward bisection. A replacement must
  reproduce them exactly, or the chain splits.

**Evidence.** `src/bignum.h`; `src/kernel.cpp`; `src/chain.cpp`
(`GetBlockTrust`); `src/validation.cpp` (`GetProofOfWorkReward`);
`src/consensus/params.h`; `project/plans/overview.md` (Inventory).

## D-02: scrypt-jane PoW; N-factor frozen at the fork

- **Status:** Accepted.
- **Date:** 2013 (launch); frozen in the 2020 work for 1.0.0, commit 37148d4.

**Context.** Yacoin's goal was CPU-friendly mining. It uses scrypt-jane
(Keccak-512 + ChaCha20/8), whose memory cost N = 2^(Nf+1) rose with time
through a timestamp table. A 32-bit time would also have run out in 2106.

**Decision.**

- The block hash is the scrypt-jane hash of the packed header.
- Before the fork, the N-factor comes from the timestamp table, capped at 25.
- From block version 7 on, the N-factor is fixed by `nFactorAtHardfork`
  (default 21) "and kept forever".

**Consequences.**

- Hashing one header at Nf 21 costs about 256 MiB and noticeable CPU time.
  This makes sync slow, and led to D-12.
- The SIMD path of scrypt-jane is chosen at compile time, so the hash has
  to be checked on every build target (P0-19, P0-53).
- `GetNfactor()` in `main.cpp` is display-only, and most of `scrypt.cpp`
  is dead code.

**Evidence.** `src/primitives/block.h` (`CalculateHash`); `src/init.cpp`
(`-nFactorAtHardfork`); `src/Makefile.am` (scrypt defines).

## D-03: Heliopolis hard fork: PoW only

- **Status:** Accepted.
- **Date:** v1.0.0 tagged 2021-03-05; active at height 1,890,000 (about
  2021-04-25).

**Context.** The 1.0.0 roadmap aimed to simplify the coin and make it
safer to hold and trade.

The merge message of upstream PR #89 sums up the release as:

- PoW only
- nFactor 21
- 2 % annualised maximum inflation
- block size based on supply
- CLTV and CSV opcodes

The Trello card "Test smooth transition of hard fork from 0.4.9 to 1.0.0"
records the requirements: keep the history, leave the UTXO set unchanged,
and add replay protection.

**Decision.**

- One fork height (1,890,000) switches on all new rules (D-04 … D-09).
- Proof-of-stake blocks are no longer accepted after the fork. PoS checks
  run only below the fork height.
- The PoS minting code was removed later, in 1.4.0.
- Coinbase maturity drops from 500 to 6 blocks.
- Replay protection comes from the new block and transaction versions.

**Consequences.**

- The PoS code (kernel, modifier, trust branches) is still consensus code,
  but only for history. Its line coverage is low (17.9 % for `kernel.cpp`),
  and the main way to test it is replaying mainnet (P0-23).
- No code in the tree can create PoS blocks any more. Tests need a
  synthetic generator (P0-55).

**Evidence.** `src/init.cpp` (`mainnetNewLogicBlockNumber`);
`src/validation.cpp` (`AcceptBlock` → `PoSContextualBlockChecks` guarded
by the fork height); `src/chainparams.cpp` (`HeliopolisHardforkHeight`,
checkpoint 1,890,005); `src/consensus/consensus.h` (maturity).

## D-04: Epoch difficulty with a minimum-difficulty floor

- **Status:** Accepted.
- **Date:** 2021-04 (Heliopolis).

**Context.** The PPCoin per-block retarget reacts quickly. The Trello card
"Implement minimum difficulty (max ease)" gives the reason: "to avoid an
attack that makes reorgs easier by mining new blocks within seconds" (a
mitigation, not a complete solution). The rule it asks for: target
1 minute over the previous epoch of 21,000 blocks, "OR 1/3rd of the highest difficulty in
ANY of the previous epochs – whichever is greater".

**Decision.**

- After the fork, difficulty changes only once per epoch of
  `nEpochInterval` blocks (21,000, about 14.6 days).
- Each change is clamped to ¼ … 4× of the previous difficulty.
- The target may never be easier than 3× the target of the hardest
  post-fork block, nor easier than `powLimit`.
- The fork block starts at `powLimit`, "same as 0.4.9" (commit 08be1ab).

**Consequences.**

- A long-range attacker cannot drop the difficulty quickly. The flip side
  is that honest hashrate leaving is also followed slowly: up to 14.6 days
  per step, and never below one third of the record difficulty.
- The floor is found by walking every post-fork block (O(chain) per
  retarget), and the walk reads both `chainActive` and the block index
  (review B7).
- The implementation uses `CBigNum`.

**Evidence.** `src/pow.cpp` (`GetNextTargetRequired`,
`CalculateNextWorkRequired`); `test/functional/feature_epoch.py`.

## D-05: Supply-based reward; block size from reward and fee

- **Status:** Accepted.
- **Date:** 2021-04 (Heliopolis). Epoch reward from upstream PR #74
  (2020).

**Context.** The NovaCoin curve (100 YAC / difficulty^(1/6)) ties
inflation to difficulty. The 1.0 roadmap wanted a bounded inflation rate.
It also wanted a block-size limit that grows with the supply instead of a
fixed 1 MB.

Trello cards on this:

- "Set block reward for the duration of an epoch"
- "Set min relay fee to 0.01 YAC/kB. Calculate and implement max block size
  from block reward and relay fee"

**Decision.**

- **Reward:** the money supply before the epoch start × 2 % / 525,960
  blocks per year. It is fixed for the whole epoch, with no fees added.
- **Minimum fee:** `MIN_TX_FEE` = `MIN_RELAY_TX_FEE` = 0.01 YAC/kB.
- **Max block size:** reward × 1000 / `MIN_TX_FEE`, so a full block of
  minimum-fee transactions pays as much in fees as the subsidy.
- **Sigops limit:** max(size, 1 MB) / 50.

**Consequences.**

- Inflation is at most about 2 % a year, and the block size grows with the
  supply.
- The reward is computed in `double`, and the block size inherits it
  (integer arithmetic on the reward). Floating point in consensus has to
  be reproduced exactly on every compiler and target (review B2, P0-46,
  P0-53).
- `GetMaxSize` without a height uses the tip, which is a latent pitfall
  (TODO in the code).

**Evidence.** `src/validation.cpp`, `src/validation.h` (`nInflation`,
`nNumberOfBlocksPerYear`); `src/consensus/consensus.cpp`;
`src/policy/fees.h`; `test/functional/feature_set_min_fee.py`.

## D-06: Hard-coded checkpoints only

- **Status:** Accepted.
- **Date:** 2021-03 (upstream PR #93); remnants removed in #98 and #101
  (2021–2022).

**Context.** PPCoin-style *sync checkpoints* are broadcast and signed
centrally. Commit 5a3c808 says only "Not use sync-checkpoint for yacoin
1.0.0 … Not allow to reorg back to blocks which before last checkpoint".
Inferred rationale: a central signing key is a trust and maintenance
burden.

**Decision.**

- Sync checkpoints were removed.
- Only checkpoints compiled into `checkpoints.cpp` and `chainparams.cpp`
  remain (up to height 1,911,210).
- A branch that reaches a checkpoint height with a different hash is
  rejected (`CheckHardened`). Despite the commit message, there is no
  general check that refuses reorganisations below the last checkpoint.
- Signature checks are skipped for blocks before the last checkpoint time.
- Stake-modifier checkpoints stay as they are.

**Consequences.**

- No central key is needed.
- Initial sync is faster.
- A reindex does not verify scripts for about 99 % of history (review B6,
  P0-52).
- New checkpoints need a release.

**Evidence.** `src/checkpoints.cpp`; `src/validation.cpp`
(`ContextualCheckBlockHeader`, `ProcessNewBlock`).

## D-07: 64-bit timestamps

- **Status:** Accepted.
- **Date:** 2021-04 (Heliopolis).

**Context.** Unsigned 32-bit Unix times end in 2106. Trello: "Fix UTC
timebug".

**Decision.**

- Block version 7 serialises and hashes a 64-bit `nTime`.
- Transaction version 2 serialises a 64-bit `nTime`.
- In memory, `nTime` is already `int64`.
- `getwork` got a 64-bit layout, and the ccminer fork was adapted to it.

**Consequences.**

- There are two header and two transaction layouts, chosen by version.
- Coin and undo serialisation switches at the fork height.
- External miners had to be updated.

**Evidence.** `src/primitives/block.h`;
`src/primitives/transaction.h`; `src/miner.cpp`
(`FormatHashBuffers_64bit_nTime`).

## D-08: Malleability fix by normalized txid

- **Status:** Accepted.
- **Date:** 2021-04 (Heliopolis).

**Context.** Third parties could change a txid by re-encoding signatures.
That breaks chains of unconfirmed transactions, such as atomic-swap refunds.
Trello: "Implement and test TXID Malleability Fix" ("a variation of
SegWit… since we are enacting a hard fork").

**Decision.**

- For transaction version ≥ 2, the txid is the hash of the transaction
  with every `scriptSig` blanked (`GetNormalizedHash`); coinbase
  transactions are hashed in full.
- Signatures stay in the transaction. There is no witness structure.
- `OP_CHECKTEMPLATEVERIFY` was considered and dropped.

**Consequences.**

- Txids are stable without a SegWit-style redesign.
- The txid no longer commits to the signatures. The block's merkle root
  is built from these txids (`CBlock::BuildMerkleTree`), so for v2
  transactions the `scriptSig`s are not committed to by the block header.
  There is no separate witness commitment as in SegWit. Recorded as an
  observation for Phase 0, not as a change to make.

**Evidence.** `src/primitives/transaction.h`;
`test/functional/feature_tx_malleability.py`.

## D-09: CLTV/CSV activated by height; lock times use block time

- **Status:** Accepted.
- **Date:** 2021-04 (Heliopolis). Opcodes from upstream PR #78.

**Context.** Timelocked coins and atomic swaps (YASwap) need
`OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY`.

**Decision.**

- BIP65 and BIP68/112 are active from the fork height (`BIP65Height`,
  `BIP68Height`), not through BIP9 signalling.
- BIP113 (median time past) is **not** adopted. `nLockTime` and relative
  time locks compare with block times.
- Wallet RPCs create and spend CLTV/CSV P2PKH and P2SH outputs, and
  `timelockcoins` locks coins.

**Consequences.**

- A time lock expires as soon as one block's timestamp passes it.
- The swap agent waits exactly the lock duration on Yacoin, but about one
  hour longer on Bitcoin/Litecoin (Trello "Yacoind improvement points +
  important notes").
- Miners have slightly more influence over lock expiry than in Bitcoin.

**Evidence.** `src/chainparams.cpp`; `src/validation.cpp`
(`GetBlockScriptFlags`, `ContextualCheckBlock`);
`src/consensus/tx_verify.cpp`; `src/wallet/rpcwallet.cpp`.

## D-10: Fork switches as start-up globals

- **Status:** Accepted. To be revisited (Trello To Do "Release: Hardcode
  fork block number, nFactor, epoch").
- **Date:** 2020–2021.

**Context.** The fork had to be tested on a fast test chain at a low
height, with short epochs and a small N-factor. A working testnet did not
exist.

**Decision.**

- The fork height, epoch length, N-factor, and later the token activation
  height are process-wide globals set from command-line options
  (`-testnetNewLogicBlockNumber`, `-epochinterval`, `-nFactorAtHardfork`,
  `-tokenSupportBlockNumber`).
- Mainnet defaults are compiled in.
- `HeliopolisHardforkHeight` in the chain parameters is used only for the
  block-version rule and serialisation.

**Consequences.**

- Tests can move the fork freely (D-17).
- A mis-set option on mainnet makes the node follow different rules.
- Consensus functions read hidden global state. In `test_bitcoin` the
  globals are 0, so unit tests run "post-fork from height 0" (review A4).
- The consensus test harness (`src/test/consensus_harness.h`, P0-47) sets
  these globals explicitly and restores them after each test.

**Evidence.** `src/init.cpp`; `src/util.cpp` (definitions);
`test/functional/test_framework/util.py`, `test_node.py`.

## D-11: Port Bitcoin Core 0.15 infrastructure step by step

- **Status:** Accepted.
- **Date:** 2021–2026 (upstream PRs #100, #101, #104, #108, #109, #111,
  #112).

**Context.** The 0.4.x code base (Bitcoin 0.6/PPCoin era) suffered from:

- slow and stalling sync
- an old mempool
- duplicated maintenance

Trello "Review" cards ask to align P2P, mempool, wallet, RPC, script
validation and the UTXO set with Bitcoin Core v0.15.2.

**Decision.** Port Bitcoin Core 0.15/0.16 subsystems one at a time, in
place, and do not rebase onto Bitcoin Core:

| PR | What was ported |
|---|---|
| #100 | `chainActive`, block status, `CValidationState`, headers-first sync |
| #101 | multithreaded block-hash calculation, sync-stall fixes (see D-12) |
| #104 | tokens and the `primitives/`/`script/` split (see D-13) |
| #108 | mempool and block assembly |
| #109 | net/addrman, `gArgs`, serialize, `arith_uint256`; BDB txdb and alerts removed |
| #111 | UTXO set (`chainstate/`), `txdb.cpp` |
| #112 | `getblocktemplate`/`submitblock`, unit and functional test suites |

**Consequences.**

- The code is structurally close to Bitcoin Core 0.15, so Bitcoin knowledge
  and fixes transfer.
- Some 0.4.x leftovers remain (`main.cpp`, `fTestNet`, dead scrypt code,
  the accounts API, synchronous block import at start-up).
- `PROTOCOL_VERSION` is 70015.
- `getblockchaininfo` does not exist; Yacoin has its own reduced
  equivalent, `gettimechaininfo` (added in #100).

**Evidence.** git history; `src/version.h`; `src/rpc/blockchain.cpp`.

## D-12: Header-only PoS classification; parallel, cached block hashing

- **Status:** Accepted.
- **Date:** 1.0.x–1.1.0 (2021–2022, upstream PRs #98, #100, #101).

**Context.** Headers-first sync must decide PoW or PoS before the block
body is known. The original rule ("`vtx[1]` is a coinstake") needs the
body. Hashing millions of headers at a high N-factor made sync very slow.
Trello: "Investigate slow startup time", "Block sync problems".

**Decision.**

- **PoS classification.** `IsProofOfStake()` uses header fields only. A
  block is PoS when its time is before the fork, `nNonce == 0` and `nBits`
  is under a limit, plus three hash exceptions. This is valid because the
  set of PoS blocks is now fixed.
- **Hash cache.** Block hashes are stored in LevelDB (`-blockhashindex`,
  default on).
- **Parallel hashing.** Hashes are computed in parallel by a dedicated
  `CCheckQueue` (`yacoin-hashcalc` threads).
- **`-reindex-fast`.** Reindex reuses the stored hashes.

**Consequences.**

- Sync is faster.
- The classification rule is a hard-coded description of history.
- `-reindex-fast` does not recompute hashes, so it is not a substitute for a
  full verification (P0-24).

**Evidence.** `src/primitives/block.h`; `src/net_processing.cpp`;
`src/init.cpp`; `src/txdb.cpp`.

## D-13: Tokens ported from Ravencoin; issuance fee as a timelock

- **Status:** Accepted.
- **Date:** 2023 (upstream PR #104, v1.2.0). CIDv1 and `timelockcoins` came
  in v1.3.0.

**Context.** Trello "Implement an Asset Management System" asked for assets
like Ravencoin's or BCH SLP. The card also asked whether a soft fork would
be enough.

**Decision.**

- **Origin.** Port Ravencoin's asset layer as "tokens": root, sub, unique,
  owner, vote and reissue. It uses a NOP opcode (`OP_YAC_TOKEN`), a token
  LevelDB and RPCs.
- **Activation.** By height (1,911,210).
- **Issuance fee.** Instead of Ravencoin's burn addresses, issuing locks
  2100 YAC in a CSV output to the issuer for 21,000 blocks. Inferred
  rationale: the fee is a deposit rather than destroyed supply.
- **IPFS.** Both CIDv0 and CIDv1 hashes are accepted.

**Consequences.**

- The token rules are consensus code, including `std::regex` name
  validation, whose behaviour can differ between C++ standard libraries
  (review B3, P0-49).
- A token overflow bug was fixed in v1.11.0 (`feature_token_overflow`).

**Evidence.** `src/tokens/`; `src/rpc/tokens.cpp`;
`src/consensus/tx_verify.cpp`; `test/functional/feature_tokens.py`.

## D-14: LevelDB for chain data, Berkeley DB 4.8 for wallets

- **Status:** Accepted. The BDB choice is reopened in Phase 6.
- **Date:**
  - LevelDB block index since 2017.
  - BDB transaction database removed in 2025 (#109).
  - UTXO set in 2025 (#111).
  - Data-directory migration in v1.5.0.

**Context.** The PPCoin code stored transactions and the block index in
BDB. Bitcoin Core moved chain data to LevelDB and kept BDB 4.8 for wallets,
for file compatibility.

**Decision.**

- The block index, the UTXO set (`chainstate/`), block-hash cache, tx index,
  address index and token database live in LevelDB.
- Wallets stay in BDB 4.8.
- `-txindex` is on by default, because historical PoS blocks need the
  previous transaction to validate.
- Old data directories are migrated on first start: block files are
  hard-linked into `blocks/`, followed by a fast reindex.

**Consequences.**

- Chain storage is like Bitcoin Core's.
- Wallet files are tied to BDB 4.8. Distributions ship 5.3, and builds need
  `depends` or `--with-incompatible-bdb`.
- v1.0.0/v1.1.0 wallets must remain readable (D-20).

**Evidence.** `src/txdb.cpp`; `src/init.cpp` (migration);
`src/wallet/db.cpp`; `depends/packages/bdb.mk`.

---

## D-15: Qt GUI deferred

- **Status:** Accepted.
- **Date:** 2026-10-02 (P0-00, decision 5).

**Context.**

- The Qt 5.7.1 in `depends` does not build with GCC 13.
- The GUI uses BIP70/TLS through OpenSSL.
- `qt/explorer.cpp` uses `CBigNum`.
- CI ships `yacoin-qt`.

**Decision.**

- Phase 0 and the dependency phases build with `NO_QT=1` and
  `--with-gui=no`.
- The GUI becomes its own later phase.

**Consequences.**

- GUI code paths are not tested or modernised for now.
- Release packaging of `yacoin-qt` has to be decided before the next release.

**Evidence.** `project/done/P0-00-phase0-decisions.md`;
`project/plans/overview.md`.

## D-16: `depends` build and the yacoind / yacoin-cli split

- **Status:** Accepted.
- **Date:** 2025 (upstream PRs #43 (fork) and #111, v1.9.0).

**Context.** Earlier builds used qmake and hand-written makefiles, with
Docker for Windows. They needed system libraries of specific old versions.
Binaries did not run on newer distributions.

Trello cards on this:

- "Enhance the build process"
- "Run on Ubuntu 20.04 (or later)"
- "Improve RPC Command-Line Interface"

**Decision.**

- **depends.** Adopt Bitcoin Core's `depends` system: pinned dependency
  sources, built from source, cross-compilation for Windows and macOS.
- **Portable binaries.** Build release binaries on the oldest supported
  glibc (Ubuntu 16.04), so they run on newer systems.
- **Split.** Separate `yacoind` (the node) from `yacoin-cli` (the RPC
  client).
- **CI.** GitHub Actions builds in `dev34253/yacoin-build` Docker images.

**Consequences.**

- Builds are reproducible across hosts.
- The pinned dependencies (OpenSSL 1.0.1k, Boost 1.64, BDB 4.8.30,
  Qt 5.7.1) are old and get no security fixes. That is the motivation for
  D-18.
- `build-windows-in-docker.sh` and the old Ubuntu notes are now obsolete.

**Evidence.** `depends/`; `doc/cross-compilation-with-depends-system.md`;
`.github/workflows/yacoinbuildmultiplatform.yml`; `src/Makefile.am`.

## D-17: Functional tests on low-difficulty main params, not regtest

- **Status:** Accepted.
- **Date:** 2020 (test framework, "adding functional tests like in
  bitcoin"). Test suites extended in v1.11.0.

**Context.** The fork logic depends on the D-10 globals and on mainnet
parameters. Regtest parameters were never adapted: they share magic and
port with main, and all fork heights are 0. Mining at the mainnet
`powLimit` is too slow for tests.

**Decision.**

- **Build flag.** A build flag, `--enable-low-difficulty-for-development`,
  gives main a low-difficulty `powLimit` (2^253), its own genesis, seeds
  and checkpoints, and a small token fee lock.
- **Test settings.** Functional tests run that build on main params with
  `epochinterval=10`, `nFactorAtHardfork=4` and a per-test fork height.
- **Unit tests.** Unit tests run in the normal (mainnet) build.

**Consequences.**

- Pre- and post-fork behaviour, including the transition, can be tested in
  minutes.
- Two build configurations are needed.
- Unit-test results that depend on `powLimit` differ between the two
  builds. Since P0-02 the tests pin the expected value per build with
  `#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT` (e.g.
  `pow_tests/get_next_work_pow_limit`); a test is never skipped in one
  build.
- Release (mainnet) binaries cannot join the test network. Old releases
  must be rebuilt with the flag for cross-version tests (P0-54).

**Evidence.** `configure.ac`; `src/chainparams.cpp`;
`test/functional/test_framework/util.py`, `test_node.py`.

## D-18: Modernise in phases behind a test safety net

- **Status:** Accepted.
- **Date:** 2026-10-02 (dev34253 fork; plan reviewed the same day).

**Context.** The code does not build on current Linux. On Ubuntu 24.04:

- OpenSSL 3 breaks `CBigNum`.
- Boost 1.83 breaks `boost::bind` placeholders and `filesystem`.
- GCC 13 exposes missing includes.
- BDB is version 5.3.

The riskiest change, replacing `CBigNum` in consensus code, can split the
chain if a single value differs.

**Decision.**

- **Phases.** Phase 0 is the safety net, followed by GCC 13, Boost,
  OpenSSL out of non-consensus code, `CBigNum` → `arith_uint256`, dropping
  OpenSSL, a BDB decision, and Qt later.
- **Phase 0 rule.** Phase 0 records current behaviour, bugs included:
  "pin it, don't fix it".
- **Primary evidence.** Replaying every mainnet block (P0-23) and a full
  reindex (P0-24), backed by golden vectors, an independent big-number
  oracle (P0-51), fuzzing, mutation testing and sanitizers.
- **Working rules (`CLAUDE.md`).**
  - Never change consensus behaviour unless the plan calls for it.
  - Run the tests before every commit.
  - Review every diff.
  - Log new behaviour.
  - Document changes in the same pull request.
- **Process.** Tasks follow the `implement-task` skill.

**Consequences.**

- Phase 0 is large: 59 tasks (P0-00 … P0-58).
- Long-running jobs need a self-hosted machine (D-20).
- Suspected bugs are written down, not fixed.

**Evidence.** `project/plans/overview.md`,
`project/plans/phase0-test-safety-net.md`,
`project/plans/phase0-review.md`; `CLAUDE.md`;
`.claude/skills/implement-task/SKILL.md`.

## D-19: Build image: Ubuntu 24.04 with GCC 11, on Docker Hub

- **Status:** Accepted.
- **Date:** 2026-10-02 (P0-00 decision 7, P0-57 done).

**Context.** The baseline was measured with GCC 11 on Ubuntu 22.04. The
target is a current distribution. Changing the OS and the compiler at the
same time would mix two sources of behaviour change.

**Decision.**

- **Image.** Build in `dev34253/yacoin-build:ubuntu.24.04-gcc11-1`: Ubuntu
  24.04 with GCC 11 pinned. GCC 13 comes in Phase 1.
- **Publication.** The image is pinned by digest. Its Dockerfile lives in
  dev34253/yacoin-build-ubuntu and is published to Docker Hub (owner
  decision). A GHCR mirror is optional.
- **Fixes.** Only build-host fixes were allowed:
  - libevent `arc4random` patch for glibc ≥ 2.36
  - `strlcpy` include for glibc ≥ 2.38
  - Python 3.12 test fixes

**Consequences.**

- Results match the 22.04 baseline: low-difficulty unit tests 238/239 (the
  same known failure) and functional tests 45/45. The mainnet build passes
  239/239 unit tests (a new measurement; the baseline had no mainnet run).
- Binaries need glibc ≥ 2.38, so this image is for dev and CI only, not for
  releases.

**Evidence.** `project/done/P0-57-ubuntu-2404-build-image.md`;
`CLAUDE.md` (Building).

## D-20: Project logistics: fork first, own mainnet node, old wallets stay readable

- **Status:** Accepted.
- **Date:** 2026-10-02 (P0-00, decisions 1–4 and 6).

**Context.** Phase 0 could not start without answers to some practical
questions:

- where a fully synced mainnet node runs, given 24–48 h reindexes and no
  P2P access from cloud sessions;
- how to find peers without DNS seeds;
- whether work goes to the fork or straight upstream;
- whether old encrypted wallets must stay readable;
- which CI system runs the long jobs.

**Decision.**

- **Mainnet node.** A fully synced node runs on the owner's machine as a
  self-hosted runner. Cloud sessions cannot reach P2P port 7688, and hosted
  runners stop jobs after 6 hours.
- **Peers.** There are no DNS seeds, so sync uses the 7 fixed seeds plus
  `addnode` peers.
- **Where work lands.** Work goes into dev34253/yacoin first and upstream to
  yacoin/yacoin later, in reviewed batches.
- **Old wallets.** Encrypted wallets from v1.0.0/v1.1.0 must stay readable.
- **CI.** GitHub Actions, hosted runners for per-push jobs and the
  self-hosted runner for long jobs.

**Consequences.** P0-07 (node sync), P0-30 and P0-54 (old wallets) and
P0-44 (CI skeleton) carry these out.

**Evidence.** `project/done/P0-00-phase0-decisions.md`;
`project/runbooks/mainnet-node-setup.md`.

## D-21: Scripted out-of-tree builds in two configurations

- **Status:** Accepted.
- **Date:** 2026-10-02 (P0-01, dev34253/yacoin#50).

**Context.** The manual build modifies the checkout: `autogen.sh` rewrites
tracked files and `depends` writes into the tree. Tests need two
configurations (D-17), plus coverage and sanitizer variants.

**Decision.**

- `contrib/testing/build.sh` builds out of tree from a mirrored copy of
  the source, inside the pinned image (D-19).
- It takes `--config mainnet|lowdiff`, `--coverage`, `--sanitizers`,
  `--unit` and `--functional`.
- Recommendation for CI: unit tests in mainnet, functional tests in lowdiff.

**Consequences.**

- Builds are reproducible and the checkout stays clean.
- Until P0-02, `--config lowdiff --unit` exited 1 because of the one
  known failure; since P0-02 both configurations exit 0.

**Evidence.** `contrib/testing/README.md`;
`project/done/P0-01-build-configurations.md`.

## D-22: Documentation set and process

- **Status:** Accepted.
- **Date:** 2026-10-03.

**Context.** The `doc/` folder held build notes (some for Ubuntu 12.04 or
qmake) and NovaCoin/PPCoin-era text. There was no description of the
consensus rules, the architecture or the reasons behind them. Knowledge was
spread over code comments, commit messages, `project/` and the Trello board.

**Decision.** Keep three living documents in `doc/`, updated in the same
pull request as the change they describe (`CLAUDE.md` rule 6):

- [`functional-specification.md`](functional-specification.md)
- [`architecture.md`](architecture.md)
- `design-decisions.md` (this file)

Build dependency versions are listed in [`dependencies.md`](dependencies.md).
The documentation review and the follow-ups it found are recorded in
`project/plans/documentation-review.md`.

**Consequences.** Consensus changes in later phases must update the
functional specification. New decisions get an entry here.

**Evidence.** this file; `CLAUDE.md`.

## D-23: Keep `getwork` next to `getblocktemplate`

- **Status:** Accepted. Affected by Phase 3 (the `getwork` midstate uses
  OpenSSL `SHA256_CTX` internals).
- **Date:** 2020 (64-bit layout, commit c805d1a) to 2026 (v1.11.0: race
  fix, `getblocktemplate`/`submitblock` aligned with Bitcoin Core 0.15.2).

**Context.** Yacoin's GPU and CPU miners (ccminer and cpuminer forks) and
pools speak the legacy `getwork` protocol. Bitcoin Core removed `getwork`
in 0.10. Trello: "Fix getwork rpc command issue", "ccminer fork: handle
case nTime 64bit after hard fork", "Integrate scrypt-chacha algorithm to
xmrig" (which asks for getwork, getblocktemplate and Stratum).

**Decision.**

- Keep `getwork`, with both the 32-bit and the 64-bit (`nTime`) header
  layouts. Blocks found through it are signed by the node's wallet.
- Offer `getblocktemplate`/`submitblock` (BIP22/23) as well, and
  `calculatescrypthash` as a helper for miner developers.

**Consequences.**

- External miners keep working, but `getwork` needs a wallet, peers and a
  synced node.
- The `getwork` midstate code (`miner.cpp`) writes into OpenSSL
  `SHA256_CTX` internals. Phase 3 has to replace it without changing the
  output, which RPC snapshots will pin (P0-33).

**Evidence.** `src/rpc/mining.cpp` (`getwork`, `getblocktemplate`);
`src/miner.cpp` (`FormatHashBuffers_64bit_nTime`, `SHA256Transform`).
