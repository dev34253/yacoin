# Yacoin Core – functional specification

This document describes **what the software does today**: the network, the
consensus rules before and after the 1.0 ("Heliopolis") hard fork, mining,
the wallet, tokens and timelocks, the RPC interface and the configuration
options that are specific to Yacoin.

- Scope: `yacoind` and `yacoin-cli` built from this tree (version 1.11.0,
  `configure.ac`). The Qt GUI is deferred (see
  [design decision D-15](design-decisions.md#d-15-qt-gui-deferred)).
- Companion documents: [architecture](architecture.md) (how the code is
  organised) and [design decisions](design-decisions.md) (why it looks like
  this).
- References name the source file and function. Line numbers are left out
  where possible because they change often.
- **Describing is not endorsing.** Where today's behaviour looks wrong, it is
  marked *Known quirk*. Consensus quirks must be **kept** – see
  `CLAUDE.md` rule 1 and the
  [Phase 0 plan](../project/plans/phase0-test-safety-net.md).

## 1. Overview

Yacoin (YAC) is a cryptocurrency launched in May 2013 as a PPCoin/NovaCoin
derivative with hybrid proof-of-work and proof-of-stake. Its PoW hash is
scrypt-jane (Keccak-512 + ChaCha20/8) with a large, configurable memory
cost (the *N-factor*), designed to be mined on CPUs.

The chain has two eras:

| | Before the fork (height < 1,890,000) | From the fork on (height ≥ 1,890,000, 2021-04-25) |
|---|---|---|
| Block types | PoW and PoS | PoW only |
| Block version | 3 (0.4.4) / 6 (0.4.9) | 7 (blocks below 7 are rejected) |
| Header/tx `nTime` | 32-bit on the wire | 64-bit on the wire (header v7, tx v2) |
| N-factor | from a timestamp table (4 … 25) | fixed, default 21 |
| Difficulty | per-block, PPCoin-style | once per epoch (21,000 blocks) with a floor |
| PoW reward | NovaCoin curve, ≤ 100 YAC, + fees | 2 %/year of money supply, fixed per epoch |
| Max block size | 1,000,000 bytes | derived from the reward and the minimum fee |
| Coinbase maturity | 500 blocks | 6 blocks |
| Txid | hash of the full transaction | v2: hash with `scriptSig`s blanked (malleability fix) |
| Timelocks | – | `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`, BIP68 |
| Tokens | – | from height 1,911,210 |

## 2. Networks and chain parameters

Source: `src/chainparams.cpp`, `src/chainparamsbase.cpp`,
`src/chainparamsseeds.h`.

### 2.1 Networks

| Network | Usable? | Notes |
|---|---|---|
| **main** | yes | The production network. |
| **regtest** | starts, but not isolated | Same magic bytes, P2P port, address prefixes and fixed seeds as main. All fork heights are 0. Not used by the tests. |
| testnet | **no** | `-testnet` is accepted by the argument parser, but `CreateChainParams` has no testnet class and throws "Unknown chain", so `yacoind` exits. The legacy global `fTestNet` still switches some code paths (N-factor 4, trust rules, coinstake fee); these paths are dead. |
| *low-difficulty main* | build-time variant | Main params from a binary built with `--enable-low-difficulty-for-development`: different `powLimit` (2^253 instead of 2^236), genesis block, money supply, seeds and checkpoints, token fee lock of 10 YAC for 10 blocks. Used by the functional tests and for development mining. The version string ends in `-low-difficulty`. |

### 2.2 Main network parameters

| Parameter | Value |
|---|---|
| Message start (magic) | `d9 e6 e7 e5` |
| P2P port | 7688 |
| RPC port | 7687 |
| DNS seeds | none (commented out) |
| Fixed seeds | 7 IPv4 nodes on port 7688 (`chainparamsseeds.h`) |
| Address prefixes | pubkey 77 (`Y…`), script 139, secret key 205; BIP32 `xpub`/`xprv` as Bitcoin |
| Genesis | hash `0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5`, chain start time 1367991200 (2013-05-08) |
| `powLimit` | `~uint256(0) >> 20` (2^236) |
| PoS limit | `~uint256(0) >> 30` |
| Target spacing | 60 s for PoW |
| Stake min/max age | 30 days / 90 days; stake-modifier interval 6 h |
| Checkpoints | hard-coded, heights 0 … 1,911,210 (includes 1,890,005 "Heliopolis hardfork") |
| Unit | 1 YAC = 1,000,000 base units (6 decimals); `CENT` = 0.01 YAC; `MAX_MONEY` = 2·10^9 YAC |

There are no centrally signed (PPCoin "sync") checkpoints; they were
removed in 1.0 (see [D-06](design-decisions.md#d-06-hard-coded-checkpoints-only)).

## 3. Consensus rules

### 3.1 Fork switches

The fork is not driven by the chain parameters but by **global variables
set at start-up** in `AppInitParameterInteraction`/`AppInitMain`
(`src/init.cpp`):

| Global | Default | Option | Meaning |
|---|---|---|---|
| `nMainnetNewLogicBlockNumber` | 1,890,000 | `-testnetNewLogicBlockNumber` | Heliopolis fork height for almost every rule below. |
| `nEpochInterval`, `nDifficultyInterval` | 21,000 | `-epochinterval` | Epoch length for reward and difficulty. |
| `nFactorAtHardfork` | 21 | `-nFactorAtHardfork` | N-factor for version-7 headers. |
| `nTokenSupportBlockNumber` | 1,911,210 | `-tokenSupportBlockNumber` | Token activation height. |
| `Consensus::Params::HeliopolisHardforkHeight` | 1,890,000 | – | Only the block-version rule and coin/undo serialisation. |
| `BIP65Height`, `BIP68Height` | 1,890,000 | – | CLTV and CSV/sequence locks (height-based, not BIP9). |

Changing these options on mainnet makes a node follow different rules – they
exist for tests. In `test_bitcoin` the first three globals are **0** (they
are only set in `AppInit`), so unit tests run "post-fork from height 0" with
N-factor 0.

### 3.2 Block header and PoW hash

Source: `src/primitives/block.h` (`CBlockHeader::CalculateHash`),
`src/scrypt.cpp`, `src/scrypt-jane/`.

- The block hash **is** the scrypt-jane hash (there is no separate
  SHA-256d block id). `scrypt(header, header, Nfactor, 0, 0, out, 32)`
  with Keccak-512 and ChaCha20/8.
- Version ≥ 7 headers are hashed in a packed 88-byte layout with a 64-bit
  `nTime`, using `nFactorAtHardfork` (21 on mainnet; 4 in the functional
  tests; 0 in unit tests).
- Older headers are hashed in the packed 80-byte layout with a 32-bit
  `nTime`; the N-factor comes from a table indexed by the block timestamp
  (4 … 25, `MAXIMUM_N_FACTOR` 25).
- `GetNfactor()` in `src/main.cpp` is used for display only
  (`getmininginfo`).
- `GetSHA256Hash()` gives a SHA-256d hash of the header; RPC
  `getbestblockhashsha256` exposes it. It is not used by consensus.
- The block hash is cached in LevelDB (`-blockhashindex`, default on)
  because hashing at N-factor 21 is slow; on start-up and during header
  sync hashes are computed in parallel by the `yacoin-hashcalc` threads.

### 3.3 Block classification (PoW or PoS)

`CBlockHeader::IsProofOfStake()` decides from the header alone (so that
headers-first sync works): a block is PoS if `nTime ≤ nYac10HardforkTime`
(1619048730), `nNonce == 0` and `nBits ≤ 486801407`, with three hard-coded
exceptions by hash. No block after April 2021 can be PoS.

### 3.4 Difficulty

Source: `src/pow.cpp` (`GetNextTargetRequired`,
`CalculateNextWorkRequired`).

**Before the fork** – PPCoin-style per-block exponential retarget towards
the target spacing (PoW spacing min(12 min, 60 s × gap since last PoW
block), one-week timespan), separately for PoW and PoS.

**From the fork on:**

1. The fork block itself requires `powLimit`.
2. The target stays the same for a whole epoch; it changes only when
   `(height + 1) % nDifficultyInterval == 0`.
3. At an epoch boundary: `new = prev × actual / nominal`, where *actual* is
   the time taken by the last epoch, clamped to ¼ … 4 × *nominal*
   (21,000 × 60 s).
4. **Floor ("minimum difficulty / max ease")**: the new target may not be
   easier than 3 × the target of the hardest block since the fork, and not
   easier than `powLimit`. The hardest block is the smallest compact `nBits`
   found by walking all post-fork blocks of `chainActive` and of the block
   index. (Trello: "Implement minimum difficulty (max ease)".)
5. A header with the wrong `nBits` is rejected (`bad-diffbits`, DoS 10).

### 3.5 Block reward and money supply

Source: `src/validation.cpp` (`GetProofOfWorkReward`, `ConnectBlock`),
`src/validation.h`.

**Before the fork** (NovaCoin curve): subsidy = 100 YAC / difficulty^(1/6),
computed by a `CBigNum` bisection, capped at `MAX_MINT_PROOF_OF_WORK`
(100 YAC), rounded down to whole cents, **plus the block's fees**.

**From the fork on:** for a block at height *h*:

```
epochStart = (h / nEpochInterval) * nEpochInterval      (fork height if 0)
reward     = nMoneySupply(block epochStart − 1) * 0.02 / 525,960
```

- 525,960 = blocks per year at 1 block/minute (365.25 days).
- The reward is constant within an epoch and recomputed each epoch
  (Trello: "Set block reward for the duration of an epoch").
- Fees are **not** added; the coinbase may not exceed the reward.
- The arithmetic uses `double` (`nInflation = 0.02`). *Known quirk*:
  floating point in consensus (review B2); it must be preserved bit for bit.
- `nMoneySupply` is stored in every block index entry.

**Proof-of-stake reward** (pre-fork blocks only): coin age × 5 % ×
33 / (365 × 33 + 8) per coin-year, checked in `Consensus::CheckTxInputs`.

### 3.6 Block size and sigops

Source: `src/consensus/consensus.cpp` (`GetMaxSize`).

| Limit | Before the fork | From the fork on |
|---|---|---|
| `MAX_BLOCK_SIZE` | 1,000,000 bytes | `reward × 1000 / MIN_TX_FEE` |
| `MAX_BLOCK_SIZE_GEN` (miner) | half of the above | half of the above |
| `MAX_BLOCK_SIGOPS` | max(size, 1 MB) / 50 | same formula |

With `MIN_TX_FEE` = 0.01 YAC the post-fork block can hold "one reward's
worth" of minimum-fee kilobytes. (Trello: "Set min relay fee to 0.01
YAC/kB. Calculate and implement max block size from block reward and relay
fee".) *Known quirk*: when called without a height, `GetMaxSize` uses the
current tip + 1.

### 3.7 Proof-of-stake (historical blocks only)

Source: `src/kernel.cpp`, `src/validation.cpp`
(`PoSContextualBlockChecks`).

The node still **validates** the PoS blocks of the first 1,890,000
heights; it can no longer **create** them (minting code removed in 1.4.0).

- Kernel: `Hash(stakeModifier, blockFrom.nTime, txOffset, txPrev.nTime,
  prevout.n, nTimeTx) ≤ target × coin-day weight`; weight =
  min(age, 90 days) − 30 days.
- Stake modifier computed per block (PPCoin v0.3 rules) and checked
  against hard-coded stake-modifier checkpoints up to height 712,177.
- PoS block rules: empty coinbase, coinstake time equal to block time, a
  valid block signature, `nNonce == 0`.
- All of this is skipped for heights ≥ the fork height.
- The kernel arithmetic uses `CBigNum` and can exceed 256 bits.

### 3.8 Chain selection (block trust)

Source: `src/chain.cpp` (`CBlockIndex::GetBlockTrust`),
`src/validation.cpp` (`CBlockIndexWorkComparator`).

The best chain is the one with the highest accumulated **chain trust**
(`bnChainTrust`, a `CBigNum`), not Bitcoin's `nChainWork`. Ties are broken
by arrival order (`nSequenceId`).

| Block | Trust |
|---|---|
| Genesis | 1 |
| PoW before `CONSECUTIVE_STAKE_SWITCH_TIME` (1392241857, Feb 2014) | 1 |
| PoS before that time | 2^256 / (target + 1) |
| PoW after that time | `powLimit / target`, doubled if the previous block was PoS |
| PoS after PoW | trust of the previous block + 1 |
| PoS after PoS | 0 |

Since the fork every block is PoW, so trust grows with `powLimit / target`.
Reorganisations below the last hard-coded checkpoint are refused.

### 3.9 Transactions

- **Versions.** v1 has a 32-bit `nTime`; v2 has a 64-bit `nTime`. From the
  fork on, blocks containing a v1 transaction are rejected
  (`bad-txns-version`), and the wallet creates v2.
- **Malleability fix.** For v2+ the txid is `GetNormalizedHash()`: the hash
  of the transaction with every `scriptSig` blanked (coinbase excluded). A
  third party can no longer change the txid by re-encoding a signature. This
  is not SegWit; signatures stay in the transaction.
- **Coinbase.** Must start with the serialised block height (BIP34-style,
  every block). Maturity 500 blocks before the fork, 6 after. *Known
  quirk*: maturity is chosen from the current tip height, not the spending
  height; the wallet adds an extra 20 blocks before the fork.
- **Coinstake** outputs follow the same maturity; coinstake transactions are
  not accepted into the mempool.
- **Lock time.** `nLockTime` is compared with the **block time**, not the
  median time past (BIP113 is not active). Relative time locks (BIP68) also
  use block times. Consequence for atomic swaps: a CLTV refund becomes
  spendable as soon as one block has a timestamp past the lock time
  (Trello "Yacoind improvement points + important notes").
- **Script flags.** P2SH (since 2012 timestamp), CLTV from `BIP65Height`,
  CSV from `BIP68Height`. Strict DER (BIP66) is not enforced.
- **Opcodes.** `OP_CHECKLOCKTIMEVERIFY` (NOP2), `OP_CHECKSEQUENCEVERIFY`
  (NOP3), `OP_YAC_TOKEN` (NOP4, token payloads).

### 3.10 Fees and relay policy

Source: `src/policy/fees.h`, `src/policy/fees.cpp`, `src/validation.h`.

| Constant | Value |
|---|---|
| `MIN_TX_FEE` = `MIN_RELAY_TX_FEE` | 0.01 YAC per 1000 bytes |
| `GetMinFee(tx)` | size in bytes × `MIN_TX_FEE` / 1000 |
| Default max fee | 0.1 YAC |
| P2SH | relaxed standardness, `MAX_P2SH_SIGOPS` 21 |

The mempool is Bitcoin Core 0.15-style (ancestor/descendant limits,
`mempool.dat` persistence, re-validation on reorg).

## 4. Tokens

Source: `src/tokens/`, `src/rpc/tokens.cpp`,
`src/consensus/tx_verify.cpp` (`CheckTxTokens`). Ported from Ravencoin's
asset layer and renamed "tokens".

- **Activation:** chain height ≥ 1,911,210. Before that, token scripts are
  only logged.
- **Types:** `YATOKEN` (root), `SUB` (`ROOT/SUB`), `UNIQUE` (`ROOT#tag`),
  `OWNER` (`ROOT!`), `VOTE` (`ROOT^…`), `REISSUE`. Units 0–6 decimals.
- **Names:** `^[A-Z0-9._]{3,}$`, at most 30 characters for root and
  sub-token names (31 with the owner `!`), no leading, trailing or double
  `.`/`_`; `YAC`, `YACOIN`, `#YAC`, `#YACOIN` are reserved. Unique tags
  allow `A–Z a–z 0–9 @$%&*()[]{}_.?:-`. Validation uses `std::regex`,
  which makes it consensus code that depends on the C++ library
  (review B3).
- **Issuance cost:** not a burn. Issuing a root, sub or unique token, or
  reissuing, **locks 2100 YAC** (per unique unit) in a CSV-P2PKH output to
  the issuer for 21,000 blocks (low-difficulty build: 10 YAC, 10 blocks).
  Owner and vote tokens cost nothing extra.
- **IPFS data:** an optional 34-byte hash; the RPC accepts CIDv0 (`Qm…`) and
  CIDv1 (`b…`) strings.
- **Indexes:** `-tokenindex` and `-addressindex` (both off by default) add
  lookups by token and by address.

## 5. Mining

| Interface | Behaviour |
|---|---|
| `getwork` | Legacy work protocol used by external GPU/CPU miners (ccminer). Needs a wallet, peers and a synced node. Handles 32- and 64-bit-time header layouts. Found blocks are signed by the wallet. |
| `getblocktemplate` / `submitblock` | BIP22/23, aligned with Bitcoin Core 0.15.2. |
| `generatetoaddress nblocks address [maxtries]` | Mines blocks in-process (tests, development). |
| Internal miner | `-gen`, `-genproclimit` (−1 = all cores) or `setgenerate`; threads `yacoin-miner`; PoW only. |
| `getmininginfo`, `getsubsidy`, `gethashespersec`, `calculatescrypthash` | Information and helpers. |

Proof-of-stake minting does not exist any more.

## 6. Wallet

Source: `src/wallet/`.

- Berkeley DB 4.8 file `wallet.dat`; several wallets with `-wallet=`
  (`listwallets`, RPC endpoint `/wallet/<name>`).
- HD key derivation (BIP32) on by default for new wallets (`-usehd`).
- Encryption: AES-256-CBC with a key from `BytesToKeySHA512AES`, using the
  in-tree `crypto/` code (not OpenSSL). Wallets created by v1.0.0/v1.1.0
  must remain readable (project decision P0-00 #4).
- Accounts API (`move`, `listaccounts`, …) still present. *Known quirk*
  (Trello Bugs): `listaccounts` can show a different total from
  `getbalance`.
- Timelocks: `createcltvaddress`, `createcsvaddress`, `spendcltv`,
  `spendcsv`, `timelockcoins`, `describeredeemscript`,
  `addredeemscript`, `getavailablebalance` (excludes locked coins), and a
  `useexpiredtimelockutxo` flag on `sendtoaddress`, `sendfrom`, `sendmany`.

## 7. RPC interface

JSON-RPC over HTTP on port 7687 (`yacoin-cli` or any HTTP client), with
`rpcuser`/`rpcpassword` or cookie authentication. REST and ZMQ are not
built.

| Group (file) | Commands | Yacoin-specific |
|---|---|---|
| Blockchain (`rpc/blockchain.cpp`) | 23 | `gettimechaininfo` (renamed from `getblockchaininfo`), `getblockbynumber`, `getbestblockhashsha256`, `calculatescrypthash` |
| Mining (`rpc/mining.cpp`) | 9 | `getwork`, `getsubsidy`, `gethashespersec`, `getgenerate`, `setgenerate` |
| Misc (`rpc/misc.cpp`) | 15 | `calculateblockhash`, `getaddressutxos`, `getaddressdeltas`, `getaddresstxids`, `getaddressbalance` |
| Network (`rpc/net.cpp`) | 13 | `getaddrmaninfo` |
| Raw transactions (`rpc/rawtransaction.cpp`) | 6 | – |
| Server (`rpc/server.cpp`) | 4 | – |
| Tokens (`rpc/tokens.cpp`) | 9 | `issue`, `reissue`, `transfer`, `transferfromaddress`, `listmytokens`, `listtokens`, `gettokendata`, `listaddressesbytoken`, `listtokenbalancesbyaddress` |
| Wallet (`wallet/rpcwallet.cpp`, `rpcdump.cpp`) | 53 | timelock commands (section 6), `removeaddress` |

Not available: `getblockchaininfo` (use `getinfo` / `gettimechaininfo`),
`gettxoutsetinfo` (planned, P0-48), REST, ZMQ notifications.

## 8. Configuration options specific to Yacoin

Standard Bitcoin Core 0.15 options are not repeated here.

| Option | Default | Effect |
|---|---|---|
| `-testnetNewLogicBlockNumber` | 1890000 | Fork height (tests only). Help text spells it `-testnetnewlogicblocknumber`. |
| `-epochinterval` | 21000 | Epoch length (tests only; no help entry). |
| `-nFactorAtHardfork` | 21 | N-factor of v7 headers (tests only; no help entry). |
| `-tokenSupportBlockNumber` | 1911210 | Token activation height (tests only; no help entry). |
| `-reindex-fast` | off | Reindex without recomputing block hashes. Not a substitute for `-reindex` when verifying the chain. |
| `-blockhashindex` | on | Store scrypt block hashes in LevelDB. |
| `-txindex` | **on** | Transaction index (needed to validate historical PoS blocks). |
| `-tokenindex`, `-addressindex` | off | Extra indexes (section 4). |
| `-initSyncDownloadTimeout`, `-initSyncMaximumBlocksInDownloadPerPeer`, `-initSyncBlockDownloadWindow`, `-initSyncTriggerGetBlocks` | – | Tuning of initial block download. If headers are more than 10,000 ahead of blocks, the node falls back to legacy `getblocks` once a minute. |
| `-gen`, `-genproclimit` | off, −1 | Internal miner. |
| `-memorylog`, `-detachdb`, `-btcyacprovider`, `-rpcssl*` | – | Legacy options. |

## 9. Data directory

`~/.yacoin` on Linux, `%APPDATA%\Yacoin` on Windows: `yacoin.conf`,
`debug.log`, `blocks/` (block files and `blocks/index` LevelDB),
`chainstate/` (UTXO set), `tokens/` (token database), `wallet.dat` and
`database/`, `peers.dat`, `banlist.dat`, `mempool.dat`. Details:
[architecture §5](architecture.md#5-persistent-storage). A data directory
from before 1.5.0 (`blkNNNN.dat` files in the top level, `txleveldb/`) is
migrated on first start: the block files are hard-linked into `blocks/` and
a fast reindex runs.

## 10. Known issues and open functional topics

From the code and the Trello board "YACoin Development" (Bugs, To Do and
Review lists, read 2026-10-03). Listed here so they are not mistaken for
intended behaviour; none is being fixed in Phase 0.

| Topic | Status |
|---|---|
| Consensus floating point (post-fork reward, max size) and `std::regex` token names | Pinned by Phase 0 tasks P0-46, P0-49. |
| `-testnet` unusable; regtest not isolated from main | Tests use low-difficulty main instead. |
| Fork switches are globals overridable from the command line | Trello To Do "Release: Hardcode fork block number, nFactor, epoch". |
| BIP113 (median time past) not enforced | Documented above; affects swap refund timing. |
| Mempool does not evict transactions that become invalid | Trello "Yacoind mempool improvement". |
| Peer keep-alive / reconnect, block broadcast delay | Trello "Improvements to Yacoind's P2P connection and block syncing". |
| `listaccounts` vs `getbalance` totals | Trello Bugs. |
| Slow shutdown, slow RPC under sync load | Trello Bugs/Review. |
