# P0-08: Per-block consensus value dump tool

- Plan section: 0.1, 0.3
- Depends on: P0-01, P0-07
- Size: M
- Owner: Claude (subagent of the local Remote Control session on artman-X) for dev34253
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Write the tool that records, for every block, everything later phases must reproduce, including the inputs needed to recompute it offline.

## Steps

1. Implement as a hidden RPC or a standalone binary linked against libyacoin_server.
2. Fields: height, hash, header hash and its N-factor, nTime, nBits, PoW/PoS, next required target, running min nBits since the fork, GetBlockTrust, accumulated chaintrust, stake modifier, modifier checksum, hashProofOfStake, kernel result.
3. Kernel inputs: blockFrom hash/time, txPrev.nTime, tx offset, prevout n, nValueIn, coinstake nTime, entropy bit / nFlags, prevoutStake.
4. Money: block reward, coinbase value, PoS reward and coin age, max block size, nMoneySupply.
5. Stable, line-oriented, compressible format (CSV or JSON lines) with a C++ reader for tests.

## Acceptance criteria

- [x] Tool produces a complete dump from the P0-07 node (snapshot of it; see Log).
- [x] Format documented (`src/test/README.md`, "Consensus value dump"); C++ reader exists (`src/test/consensus_dump_reader.h`).

## Notes

Review: B7, C1.

- P0-47 defines the index-chain CSV format and loader used by the unit tests (`src/test/README.md`, *Index-chain CSV*: `height,hash,prev_hash,time,bits,version,nonce,merkle_root,flags,stake_modifier,hash_proof_of_stake,prevout_stake,stake_time`). Emit these column names (extra columns are ignored by the loader) or extend the loader.

## Detailed description

### Facts checked in the code (step 1)

- The block id is the scrypt-jane header hash (`CBlockHeader::CalculateHash`,
  `primitives/block.h:126`): the "header hash" of the task *is* the block
  hash. Its N-factor is chosen inline: v ≥ 7 headers use the global
  `nFactorAtHardfork` (21 on mainnet), older headers a table of `nTime`
  steps (Nf 4 … 25). No function returns the N-factor.
- `CalculateNextWorkRequired` (`pow.cpp:37`) starts its `nMinEase` scan at
  `chainActive.Tip()`, not at `pindexLast` (review B7). On a fully synced
  chain, `GetNextTargetRequired(pprev)` at a post-fork epoch boundary sees
  the minimum over **all** post-fork blocks up to the tip, not only those
  before the block. `nMinEase` compares compact values as plain unsigned
  integers, starting from `powLimit.GetCompact()`.
- `CheckStakeModifierCheckpoints` *does* run for every entry while the
  index is loaded, because `chainActive` is still empty then
  (`validation.cpp:3762-3764`, before `LoadChainTip`): a wrong stored
  modifier at a checkpoint height logs "Failed stake modifier checkpoint".
- `ComputeNextStakeModifier` and `CheckStakeModifierCheckpoints`
  (`kernel.cpp:187`, `kernel.cpp:650`) return early when `chainActive.Tip()`
  is at or past the fork, so on a synced node the stake modifier cannot be
  recomputed by calling them; the stored `nStakeModifier` and the flags are
  what can be dumped (the early return of the checkpoint check does not
  apply at load time, see above). `nStakeModifierChecksum` is not stored: it is
  recomputed for every entry when the index is loaded
  (`validation.cpp:3762`).
- `CBlockIndex::prevoutStake` and `nStakeTime` are serialised in the block
  index but never assigned by the current code (only `txdb.cpp:487-488`
  reads them). On a node synced with this code they are null/0 for every
  block (if the datadir was synced from scratch by this code; older
  versions may have filled them). The stored values are dumped as they are;
  the kernel's prevout and time come from the coinstake transaction.
- `CheckStakeKernelHash` (`kernel.cpp:436`) is public and can be called on
  the active chain. It returns the kernel hash (left null when it fails
  before hashing), the target (only when it passes) and the result. The
  stake modifier it uses comes from the file-static `GetKernelStakeModifier`
  (`kernel.cpp:335`) and is not returned, but that function is a short walk
  along `chainActive.Next` that the tool can repeat; the repeated walk is
  checked by re-hashing with the (external, undeclared)
  `GetProofOfStakeHash` and comparing with `CheckStakeKernelHash`'s hash.
  On a synced chain the walk may go past `pprev` where at validation time
  it would have stopped; for accepted blocks it cannot (they passed), and
  rows where it does are counted.
- `GetCoinAge` (`validation.cpp:4809`) needs a coins view in which the
  coinstake inputs are unspent. On a synced node they are spent, so the
  chainstate cannot be used. The block's undo data (`rev*.dat`) holds every
  coin the block spent with value, height, flags and `nTime`
  (`undo.h:28-63`) – exactly the view `ConnectBlock` had – so the tool
  builds the view from the undo data. `UndoReadFromDisk` is file-local
  (`validation.cpp:1160`, anonymous namespace), so the tool repeats its few
  steps (open `rev?????.dat` via the public `GetBlockPosFilename`, read
  through `CHashVerifier`, check the checksum). For coins created at or
  above `HeliopolisHardforkHeight` the undo record does not store the
  coinstake flag (`undo.h:31-35`); `GetCoinAge` and the fees do not use it. `GetCoinAge` reads only `coin.nTime` and existence
  from the view (`Coin.nTime` = creating tx's `nTime`, `coins.cpp:176`).
  The same view gives an **independent** fee sum.
- `ConnectBlock` (`validation.cpp:1772-1806, 2042-2043`): `nMint = nValueOut
  - nValueIn + nFees`, `nMoneySupply = prev + nValueOut - nValueIn`, where
  `nFees` counts non-coinbase, non-coinstake transactions only. So the fees
  of a block are also `nMint - (nMoneySupply - prev.nMoneySupply)`, and for
  a PoW block `nMint` equals the coinbase output. The dump takes the fees
  from the undo data and counts rows where the index-derived value differs.
- The coinstake limit in `CheckTxInputs` (`consensus/tx_verify.cpp:417-419`)
  is `GetProofOfStakeReward(...) - GetMinFee(nTxSize) + CENT`, with
  `nTxSize = 0` unless `tx.nTime > VALIDATION_SWITCH_TIME` (far future) or
  testnet.
- After the fork `GetProofOfWorkReward` ignores `nFees` and reads the money
  supply of the block before the epoch start through `chainActive`
  (`validation.cpp:923-932`); `GetMaxSize` uses it too. On the synced chain
  that block is the same one validation saw.
- `GetMaxSize(mode, 0)` uses `chainActive.Tip()->nHeight + 1`, so height 0
  cannot be asked for (`consensus/consensus.cpp:22`).
- `ReadBlockFromDisk` checks the PoW and recomputes the scrypt hash unless
  `-blockhashindex` (default on) has the hash. `CBlockHeader::GetHash()`
  only uses the cached hash when the header was deserialised
  (`previousBlockHeader`, `block.h:105-110, 220-245`), so the kernel's
  `blockFrom` header must be read from the file and get its hash from
  `ReadBlockHash`, as `CheckProofOfStake` does – otherwise every PoS row
  costs a scrypt hash.
- `GetSHA256Hash()` hashes the packed 84-byte `block_header` struct (64-bit
  time) for every version (`block.h:247-260`): it is the `mapHash` key, not
  the SHA-256 of the serialised header.
- The library is `libyacoin_server.a` (task text: "libyacoin_server").
- `-txindex` defaults to on (`validation.h:150`); the kernel and coin age
  need it.

### Scope

A **hidden RPC `dumpconsensusvalues`** in `yacoind` that writes one CSV row
per block of the active chain, a format description, a C++ reader for
tests, unit and functional tests, and one complete dump of the mainnet
snapshot (stored outside git). No consensus code changes: the new code only
calls existing public functions and reads the block index, block files and
transaction index.

*Why an RPC and not a standalone binary:* the RPC runs inside a node that
`AppInit` has set up exactly as for validation (chain params, fork globals,
`nFactorAtHardfork`, `-epochinterval`, `fTxIndex`, `mapBlockIndex` with
chain trust and modifier checksums, `chainActive`, `pblocktree`). A
standalone binary would have to repeat that start-up sequence and could get
it subtly wrong. The RPC can also be covered by a functional test on a real
(low-difficulty) chain. Bitcoin Core later took the same route
(`dumptxoutset`). The cost: the node must be started on a copy of the
datadir, and the RPC holds `cs_main` for the whole dump.

Files: `src/consensusdump.{h,cpp}` (new: row struct, columns, formatting,
row computation, N-factor table), `src/rpc/blockchain.cpp` (RPC),
`src/Makefile.am`, `src/test/consensus_dump_reader.{h,cpp}` and
`src/test/consensus_dump_tests.cpp` (new), small sample CSVs in
`src/test/data/`, `src/Makefile.test.include` (rule to embed CSV),
`test/functional/rpc_dumpconsensusvalues.py` (new) and the test runner,
docs (`src/test/README.md`, `doc/functional-specification.md`,
`doc/architecture.md`, `doc/design-decisions.md`, plan 0.3, known issues).

Not in scope: recomputing the stake modifier chain, scrypt hashes of every block, replaying the chain (P0-23), fixture
selection (P0-09).

### Behaviour

`dumpconsensusvalues "filename" ( start_height end_height )` – hidden
category, so it does not appear in `help` but `help dumpconsensusvalues`
works.

- Defaults: heights 0 … tip of `chainActive`. Errors (`RPC_INVALID_PARAMETER`):
  start < 0, end > tip, start > end, file already exists. A relative
  filename is taken relative to the datadir.
- Requires `-txindex` (error otherwise). Holds `cs_main` while it runs;
  stops cleanly (incomplete file removed) when shutdown is requested.
- Writes `<filename>.incomplete` (a stale one from an aborted run is
  refused with an error; remove it by hand) and renames it when done, so a file with the final name is
  always complete.
- Returns `{filename, rows, start_height, end_height, end_hash, pos_blocks,
  kernel_failed, kernel_hash_mismatch, kernel_rehash_mismatch,
  kernel_modifier_after_prev, required_bits_mismatch, fees_mismatch,
  coinbase_over_reward, coinstake_over_limit, pos_without_coinstake,
  coinstake_in_pow_block, nfactor_checked, nfactor_mismatch, seconds}`.
- `LogPrintf` at start, every 100,000 rows (progress) and at the end with
  the summary. Any read error throws and is logged.
- Output is deterministic for a given binary and chain (no wall-clock time
  in the file).

**File format** (version 1): comment lines start with `#` (the P0-47 loader
skips them):

```
# format=yacoin-consensus-dump version=1 doc=src/test/README.md
# client=<version string> chain=main lowdiff=0 fork_height=1890000 heliopolis_hardfork_height=1890000 nfactor_at_hardfork=21 epoch_interval=21000 difficulty_interval=21000 yac10_hardfork_time=1619048730 start_height=0 end_height=N
height,hash,prev_hash,time,bits,version,nonce,merkle_root,flags,stake_modifier,hash_proof_of_stake,prevout_stake,stake_time,header_sha256,nfactor,is_pos,median_time_past,required_bits,min_bits_since_fork,block_trust,chain_trust,stake_modifier_checksum,kernel_prevout,kernel_block_from_hash,kernel_block_from_time,kernel_tx_prev_time,kernel_tx_prev_offset,kernel_value_in,kernel_tx_time,kernel_stake_modifier,kernel_modifier_height,kernel_hash,kernel_target,kernel_ok,tx_count,block_size,sigops,max_sigops,coinbase_value,fees,pow_reward,coinstake_value_in,coinstake_value_out,coin_age,pos_reward,pos_reward_limit,max_block_size,mint,money_supply
<one row per block>
# end rows=<n> end_hash=<hash>
```

The first 13 columns are exactly the P0-47 index-chain columns with the same
meaning and encoding (index values as stored), so
`LoadIndexChainCsv` reads a dump directly – with two limits of the loader:
a range that starts at height 0 cannot be loaded in a `TestingSetup`
(its genesis is already in `mapBlockIndex`), and a loaded segment's
`bnChainTrust` restarts at 0, so compare trust differences. An empty field means "not
applicable". Hashes are 64 hex digits in RPC byte order; `bits`,
`required_bits`, `min_bits_since_fork` 0x + 8 hex digits; `stake_modifier`
0x + 16, `stake_modifier_checksum` 0x + 8; trust and `kernel_target` 0x +
lowercase hex without leading zeros (`0x0` for zero); amounts are signed
decimal integers in the smallest unit (1 YAC = 1,000,000).

| Column | Value | Source |
|---|---|---|
| P0-47 columns | index fields; `prev_hash` empty at genesis; `hash_proof_of_stake`, `prevout_stake`, `stake_time` empty when null/0 | `CBlockIndex` |
| `header_sha256` | `GetSHA256Hash()`, the `mapHash` key (double SHA-256 of the packed 84-byte struct) | `CBlockIndex` |
| `nfactor` | N-factor of the scrypt header hash | tool copy of the `CalculateHash` table; checked against the stored hash once per distinct value (see below) |
| `is_pos` | 1/0 | `IsProofOfStake()` |
| `median_time_past` | `GetMedianTimePast()` of this block (block h+1 must be later) | `CBlockIndex` |
| `required_bits` | target required for this block, computed **now** | `GetNextTargetRequired(pprev, is_pos)`; empty at genesis |
| `min_bits_since_fork` | `min(powLimit.GetCompact(), nBits of heights fork…h−1)` as unsigned integers – the `nMinEase` a node validating block h with tip h−1 uses | running minimum; empty below the fork |
| `block_trust`, `chain_trust` | | `GetBlockTrust()`, `bnChainTrust` |
| `stake_modifier_checksum` | | `nStakeModifierChecksum` (from index load) |
| `kernel_*` (PoS only) | coinstake `vin[0].prevout`; hash and time of the block holding txPrev; `txPrev.nTime`; offset `nTxOffset + header size`; `nValue` of the prevout; coinstake `nTime`; stake modifier used and the height that generated it (repeated walk); kernel hash (empty if the check fails before hashing); target (only if it passes); result 1/0 | transaction index + `CheckStakeKernelHash` with the block hash from the block-hash index |
| `tx_count`, `block_size` | `vtx.size()`, network serialised size | block from disk |
| `sigops`, `max_sigops` | Σ `GetLegacySigOpCount`, `GetMaxSize(MAX_BLOCK_SIGOPS, h)` (as `ContextualCheckBlock`) | block; empty `max_sigops` at genesis |
| `coinbase_value` | `vtx[0].GetValueOut()` | block |
| `fees` | Σ (in − out) of the non-coinbase, non-coinstake transactions; empty at genesis | undo data (rows where `mint - Δmoney_supply` differs are counted) |
| `pow_reward` (PoW only) | maximum coinbase value (after the fork without fees) | `GetProofOfWorkReward(nBits, fees, h)`; empty at genesis |
| `coinstake_value_in/out`, `coin_age`, `pos_reward`, `pos_reward_limit` (PoS only) | inputs/outputs of `vtx[1]`; coin age in coin-days; `GetProofOfStakeReward(coin_age, nBits, tx.nTime)`; that `- GetMinFee(nTxSize) + CENT` as in `CheckTxInputs` | undo-data coins view + `GetCoinAge` |
| `max_block_size` | `GetMaxSize(MAX_BLOCK_SIZE, h)`; empty at genesis | |
| `mint`, `money_supply` | | index |

**N-factor check:** for the first row of each distinct (v ≥ 7, N-factor)
combination the RPC hashes the header with `scrypt_hash` at the dumped
N-factor and compares with the stored hash (18 hashes on mainnet,
up to 512 MiB of memory each at Nf 21). Mismatches are counted and logged.

### Fields of the task that are *not* dumped, and why

- **Recomputed stake modifier**: `ComputeNextStakeModifier` returns early on
  a post-fork tip (facts above); the stored value is dumped, the
  checkpoints are checked at index load ("Failed stake modifier checkpoint"
  must not appear in the node's `debug.log`). P0-17/P0-23 recompute it.
- **Historical "next required target" at post-fork epoch boundaries**:
  `required_bits` is what the function returns on today's tip (B7). The
  value the network enforced is `bits` itself (`ContextualCheckBlockHeader`
  requires equality); `min_bits_since_fork` gives the history-independent
  minimum. Rows where `required_bits != bits` are counted and explained in
  the Log.
- **Recomputed scrypt hash of every block**: about 1 s per hash at Nf 20–21;
  only the per-N-factor check above.
- **Coin-day weight** of the kernel: internal; follows from
  `kernel_value_in`, the times and `GetWeight` (P0-23). It does not enter
  the kernel hash (`GetProofOfStakeHash` ignores it).
- **`max_block_size`/`pow_reward` as seen during header-first sync**: they
  are computed on the synced chain (see facts); the epoch-start block they
  read is the same, so they equal the validated values.

### Edge cases

- Genesis: no `prev_hash`, `required_bits`, `fees`, `pow_reward`,
  `max_block_size`, `max_sigops` (`GetMaxSize(…, 0)` means "tip + 1"); no
  undo data; `ConnectBlock` skips it – the index values are dumped as
  stored.
- `vtx[1]` is a coinstake but the index says PoW (the PoS flag comes from a
  header heuristic, `block.h:265-279`): counted in
  `coinstake_in_pow_block`, logged (should be 0).
- PoS flag set but no coinstake at `vtx[1]`: kernel/coinstake columns empty,
  counted in `pos_without_coinstake`, logged (should be 0).
- Kernel fails (`CheckStakeKernelHash` false): `kernel_ok=0`, empty
  target (and empty hash if it failed before hashing), counted; the row is
  still written. Expected 0 on mainnet.
- Missing block data, txindex entry or txid mismatch: the RPC throws, the
  incomplete file is removed (a dump must be complete).
- Low-difficulty build / functional tests: PoW-only chain, fork height per
  test, epoch 10, Nf 4; all PoS columns empty. Unit tests: fork 0, Nf 0.
- Big values: trust up to 256 bits (error if a value does not fit),
  `stake_modifier` full 64 bits, negative amounts allowed in the format.
- Two calls on the same chain give identical files; an existing file is
  never overwritten.
- Long run (≈1.96 M blocks): progress in `debug.log`; client needs
  `-rpcclienttimeout=86400` (0 does not mean "no timeout" here, see the Log). `GetNextTargetRequired` logs one line per post-fork
  block (`PoW constant target …`), about 75,000 lines.

### How to test

| Criterion | Test | Expected |
|---|---|---|
| Format and reader | unit `consensus_dump_tests/format_round_trip`: rows (PoW, PoS, extremes, empty fields) → `FormatConsensusDumpRow` → reader | identical fields; header = column list |
| Reader rejects bad input | unit `consensus_dump_tests/reader_errors` | `std::runtime_error` with `name:line` for each case |
| N-factor table | unit `consensus_dump_tests/nfactor_table`: boundaries Nf 4–12 vs `CalculateHash`, v7 uses `nFactorAtHardfork` | equal |
| Real data readable by both loaders | unit `consensus_dump_tests/mainnet_samples`: reader + `LoadIndexChainCsv` on the committed mainnet samples (all starting above height 0), internal consistency (trust differences, fees = mint − Δsupply, kernel hash = stored proof hash, kernel ok, coinstake reward ≤ limit, `required_bits == bits` outside epoch boundaries, N-factor table) | pass in both builds |
| RPC on a real chain | functional `rpc_dumpconsensusvalues.py` (lowdiff): mine across the fork and epoch boundaries; compare every row with `getblock`/`getblockheader` (hash, prev, time, bits, version, nonce, merkle root, flags, modifier, checksum, trust, mint, money supply, size, tx count, coinbase value); `required_bits == bits`; running min; ranges; errors; determinism; trailer | pass |
| Complete mainnet dump | manual run on the snapshot copy | rows = 1,964,618, end hash = snapshot tip, all counters 0 or explained, no "Failed stake modifier checkpoint" in `debug.log`; stats in the Log |
| No regressions | `build.sh` mainnet unit, lowdiff unit + functional | 348/348, 348/348, 47/47 (341 + 7 unit cases, 46 + 1 functional) |

### Risks

- Consensus: none intended – read-only calls only. The RPC calls functions
  with side effects only on logs (`GetNextTargetRequired` logs). It holds
  `cs_main`; run it only on an offline node.
- Running yacoind on the snapshot writes to that datadir (debug.log,
  peers.dat, missing block-hash index entries, LevelDB compaction). It is
  run on a **working copy** of the snapshot so the snapshot stays as taken,
  with `-listen=0 -connect=0 -dnsseed=0 -disablewallet -persistmempool=0`,
  non-default ports, `-rpcservertimeout` raised and the client's
  `-rpcclienttimeout=86400`.
- The N-factor table and the kernel modifier walk are copies; a wrong copy
  would give a wrong column. The per-N-factor scrypt check, the per-row
  re-hash of the kernel and the unit test guard them.
- The PoS path is not covered by the functional test (PoW-only chains); it
  is checked by the self-checks on every mainnet PoS row and by the
  committed mainnet sample; no synthetic PoS unit test was added (open
  point, see Log step 7).
- Memory: Nf 21 scrypt needs 512 MiB per hash, one at a time.

## Implementation plan

1. **`src/consensusdump.{h,cpp}`** (new, in `libyacoin_server`; added to
   `src/Makefile.am`):
   - `struct ConsensusDumpRow` – one field per column, `boost::optional`
     for the columns that may be empty; trust and kernel target as
     `arith_uint256`.
   - `ConsensusDumpColumns()` (the column list, used by writer, reader and
     tests), `FormatConsensusDumpRow(row)`, `ConsensusDumpNFactor(nVersion,
     nTime)` (copy of the `CalculateHash` table, `fTestNet` → 4, v ≥ 7 →
     `nFactorAtHardfork`).
   - `class CCoinsViewUndo : public CCoinsView` – a map from each input's
     prevout to the `Coin` in the block's undo data (local reader, see
     facts); `GetCoin` returns it, unknown outpoints throw.
     One view per block.
   - Copy of `GetStakeModifierSelectionInterval` and of the
     `GetKernelStakeModifier` walk (active chain only) → modifier, its
     generating height, the last visited height.
   - `FillRow(CBlockIndex*, nMinEase, row, result)`:
     index fields; block read with `CAutoFile` (no PoW recheck; header
     compared with the index, merkle root recomputed); undo read and the
     view; fees from the view; sigops; `GetNextTargetRequired`; trust;
     kernel via txindex + `CheckStakeKernelHash` (header read from the
     file, `blockHash` from `ReadBlockHash`, as `CheckProofOfStake` does),
     the modifier walk and the re-hash with `GetProofOfStakeHash`; coin age
     via `CCoinsViewCache(&undoView)` + `GetCoinAge`; rewards and the
     coinstake limit; max size; counters.
   - `DumpConsensusValues(path, nStart, nEnd)` → result struct: checks,
     metadata lines, `.incomplete` + rename, running `nMinEase` over
     fork…h−1 (primed up to `nStart - 1`), N-factor check with `scrypt_hash`,
     progress `LogPrintf`, shutdown check, trailer. Throws
     `std::runtime_error` on errors (file removed).
   *Verify:* compiles in the mainnet build.
2. **RPC** `dumpconsensusvalues` in `src/rpc/blockchain.cpp`, hidden
   category; help text with the format pointer; argument checks; relative
   path → datadir; `LOCK(cs_main)`; result object. *Verify:* `help
   dumpconsensusvalues` in the functional test.
3. **Reader** `src/test/consensus_dump_reader.{h,cpp}`:
   `ReadConsensusDump(istream, name)` / `ReadConsensusDumpFile(path)` →
   `{meta map, rows, fComplete}`; checks format line, required columns
   (unknown ones ignored), field count, every field's syntax, ascending
   heights, trailer row count; errors as `<name>:<line>: <reason>`.
4. **Unit tests** `src/test/consensus_dump_tests.cpp`: `format_round_trip`,
   `reader_errors`, `nfactor_table` (Nf 4–12 boundaries vs `CalculateHash`;
   v7 with `ScopedConsensusGlobals::SetNFactorAtHardfork`). Add sources to
   `src/Makefile.test.include`. *Verify:* `build.sh --config mainnet --unit`.
5. **Functional test** `test/functional/rpc_dumpconsensusvalues.py`
   (lowdiff, clean chain, mocktime, fork at block 15, epoch 10, ~45
   blocks): rows vs `getblock`/`getblockheader`; `required_bits == bits`;
   running minimum; fees and `pow_reward ≥ coinbase_value`; empty PoS
   columns; metadata and trailer; ranges; errors (exists, bad range);
   relative path; identical bytes on a second dump; parse in Python with
   the same column list; spend a coinbase after the fork so one block has
   fees; assert `pos_blocks == 0`, `nfactor_checked == 2`. Register in
   `test_runner.py` (`BASE_SCRIPTS`). *Verify:* `build.sh
   --config lowdiff --unit --functional` (47/47).
6. **Mainnet dump**: copy the mainnet `yacoind`/`yacoin-cli` to
   `/srv/yacoin/dumps/p0-08/`, `cp -a` the snapshot to a working copy
   there, write a minimal `yacoin.conf` (local RPC user/password, needed
   for the RPC), start yacoind on the copy (`-listen=0 -connect=0
   -dnsseed=0 -disablewallet -persistmempool=0 -port=17688 -rpcport=17687
   -rpcservertimeout=86400 -checkblocks=1 -server`), first a short range
   (timing, PoS-heavy) to confirm no scrypt per row, then the RPC for
   the whole chain with a long `-rpcclienttimeout`, record runtime and summary,
   produce the sample ranges, check `debug.log` for "Failed stake modifier
   checkpoint", stop the node. Compress with zstd, SHA256,
   append to `/srv/yacoin/dumps/SHA256SUMS`. Check rows and end hash.
7. **Mainnet samples**: commit 2–3 small ranges produced by the RPC
   (early chain from height 1, a PoS segment, the fork boundary) to
   `src/test/data/` (listed in `src/test/data/README.md`), embedded with
   a new `%.csv.h` rule (in `GENERATED_TEST_FILES` and the test sources); unit test
   `mainnet_samples` (reader + `LoadIndexChainCsv` + consistency).
   *Verify:* both builds.
8. **Docs**: `src/test/README.md` (format, reader, how to run),
   `doc/functional-specification.md` (RPC), `doc/architecture.md`,
   `doc/design-decisions.md` (RPC vs standalone), plan 0.3 row,
   `known-issues.md` (findings), `CLAUDE.md` test counts,
   `contrib/testing/README.md` expected counts.

## Log

- 2026-10-03 – step 0: picked up on branch `task/P0-08-mainnet-dump-tool`
  (from master 6859321). Dependencies: P0-01 is done; P0-07 is still in
  `inprogress/` (snapshots and checksums not finished), but the owner's
  answer to Q9 says P0-08 can start, and the parent session prepared a
  consistent tip snapshot of the node (height 1,964,617, tip
  `00000384e8e155597aad553e8609b27aec6321086fe6aeb029869f47dcce17bf`,
  taken with the node stopped, `/srv/yacoin/snapshots/p0-08-datadir/`),
  which is all this task needs from P0-07. Proceeding on that basis.
- 2026-10-03 – step 1: read the task, plan 0.1/0.3, review B7/C1 and the
  code. Corrections to the task text are in "Facts checked in the code"
  (the header hash is the block hash; "next required target" depends on
  the tip at epoch boundaries; `prevoutStake`/`nStakeTime` are never set;
  the library is `libyacoin_server`).
- 2026-10-03 – step 2: detailed description written (hidden RPC chosen).
- 2026-10-03 – step 3: description reviewed by a subagent (12 findings).
  Applied: dump ranges from height 0 cannot go through `LoadIndexChainCsv`
  in a `TestingSetup`, trust differences instead of absolute values (1);
  kernel header read from the file with the hash from `ReadBlockHash` (2 –
  already so in the draft); `min_bits_since_fork` over fork…h−1 (3);
  checkpoint check at index load as acceptance item (4); kernel stake
  modifier and its height via a copied walk, self-checked by re-hashing (5);
  `pos_reward_limit` (6); undo-data coins view and independent fees (7);
  "computed now" notes for `pow_reward`/`max_block_size` (9); kernel hash
  empty when the check fails before hashing, walk past `pprev` counted
  (10); `median_time_past`, `sigops`, `max_sigops`, the
  coinstake-in-PoW counter, `pow_reward` empty at genesis, both fork
  heights in the header, stale `.incomplete` (11); `header_sha256`
  wording (12); start-up flags and `-rpcservertimeout` (operational).
  Not decided yet: a synthetic PoS unit test with blocks on disk (8) – see
  step 6; the PoS path is otherwise checked on every mainnet PoS row.
- 2026-10-03 – step 4: implementation plan written.
- 2026-10-03 – step 5: plan reviewed by a subagent (12 findings). Applied:
  `UndoReadFromDisk` is file-local, so a local reader (1 – the draft would
  not have linked); `GetProofOfStakeHash` declared at global scope,
  missing includes (2); functional test: `required_bits` may differ only at
  post-fork epoch boundaries, asserted with the exact count (3); a block
  with fees (4); undo quirk (coinstake flag not stored after the fork) in
  the format notes (5); kernel target truncation note (6); build and doc
  steps: test sources, CSV embedding, `src/test/data/README.md`, help text
  in sync (8); functional-test pitfalls and the assertions `pos_blocks ==
  0`, `nfactor_checked == 2` (9); runtime "hours, not half an hour", a
  timed short run first (12; actual run: 449 s, see below). Not applied: a local `--coverage-report` run
  (8) – the new file is outside the consensus gates and CI runs the merged
  coverage gate on `master`; skipped to stay in the turn budget.
- 2026-10-03 – step 6: implemented as planned (`src/consensusdump.{h,cpp}`,
  RPC in `rpc/blockchain.cpp` + `rpc/client.cpp` conversions, reader,
  unit tests, functional test, `%.csv.h` rule, runbook
  `project/runbooks/mainnet-dump.md`), as planned.
- 2026-10-03 – **mainnet dump.** Binary: mainnet build of this branch
  (`YAC-v1.11.0.0-f2eab1892bb4-dirty`, yacoind SHA-256
  `c24c38998e0624766193d35c6311914d9a11ce1240bdce87ffaaffcd87f2d28b`),
  copied to `/srv/yacoin/dumps/p0-08/`. Data: working copy
  (`/srv/yacoin/dumps/p0-08/datadir`, `cp -a`) of the snapshot
  `/srv/yacoin/snapshots/p0-08-datadir`, so the snapshot itself was not
  opened; minimal `yacoin.conf` there with a random local RPC password
  (the RPC needs it), `-listen=0 -connect=0 -dnsseed=0 -disablewallet`,
  ports 17687/17688. The live node and `/srv/yacoin/datadir` were not
  touched. Start-up: index loaded, tip 1,964,617
  `00000384e8e155597aad553e8609b27aec6321086fe6aeb029869f47dcce17bf`,
  no "Failed stake modifier checkpoint" in `debug.log`.
  - Timed trial: heights 500,000–504,999 (478 PoS) in 1.6 s, all
    counters 0 – no scrypt per row.
  - Full run, heights 0–1,964,617: **449.3 s** (RPC time; started
    11:49:43, done 11:57:12 UTC), **1,964,618 rows**, end hash = snapshot
    tip (`00000384…17bf`, matches; trailer and header line checked).
    Counters: pos_blocks 223,809; kernel_failed, kernel_hash_mismatch,
    kernel_rehash_mismatch, kernel_modifier_after_prev,
    required_bits_mismatch, fees_mismatch, coinbase_over_reward,
    coinstake_over_limit, pos_without_coinstake, coinstake_in_pow_block,
    nfactor_mismatch all **0**; nfactor_checked 18 (N-factor 4–20 for
    version < 7 headers at their first block, 21 for version 7 at
    1,890,000 – every hash reproduced).
  - `yacoin-cli -rpcclienttimeout=0` gave up after 50 s ("timeout
    reached"): 0 means libevent's default here, not "no timeout"
    (known issue added). The dump finished in the node; the summary was
    taken from `debug.log`. Runbook and help text now say to use a long
    timeout.
  - Output: 1,004,613,966 bytes uncompressed (SHA-256
    `2e2f4379608d6793d325427a3e578663a46f0b1c5532f74f1baa6b7e794f4509`),
    stored as **`/srv/yacoin/dumps/consensus-dump-1964617.csv.zst`**
    (`zstd -19 -T4`, 7 min 15 s, `zstd -t` ok): **289,287,475 bytes**,
    SHA-256 **`b29fcb8941726fb2952f697ac1d32c6f9187e62b6159207f099d1fc365ac2836`**,
    line added to `/srv/yacoin/dumps/SHA256SUMS`. Uncompressed file
    removed. Not in git.
  - Checks over the full dump (Python/awk on the zst, not committed): no
    row has `prevout_stake`/`stake_time` (index fields never set); the last
    PoS block is 1,889,995; all 74,618 post-fork blocks have `nBits`
    0x1e0fffff (powLimit), which is why `required_bits` equals `bits` at the
    epoch boundaries 1,911,000/1,932,000/1,953,000 despite B7; an
    independent model (Python integers, `SetCompact`, weight =
    min(Δt − 30 d, 90 d)) reproduces `kernel_target` for all 223,809 PoS
    rows, and no product reaches 2^256 (so the `getuint256` truncation
    never happened); `kernel_hash <= kernel_target` on every PoS row.
  - Samples for the unit test written by the RPC: heights 1–60,
    500,040–500,099 (3 PoS), 1,889,990–1,890,010 (3 PoS) – 70 KB together.
  - The review fixes made after the run (stale `.incomplete` refused, a log
    category, help text, reader `bad()` check) do not change the rows.
- 2026-10-03 – step 7: code review by a subagent on the staged diff (no
  high findings). Applied: stage docs with the code (1, at commit); test of
  the run-time error path and cleanup, plus the genesis dumped and read
  back (3); a stale `.incomplete` is refused instead of overwritten and
  deleted (5); reader fails on `in.bad()` (6); warning when
  `-blockhashindex` is off, per-row recompute message under
  `BCLog::RPC`, log volume in the runbook (7); `const_cast` removed,
  Makefile order, header comment, `-dirty` note for the samples (8);
  sigop-cost note (9). Item 4 (kernel target truncation) checked on the
  full dump instead of changed: no truncation on mainnet (above),
  documented. Not applied: item 2, a synthetic PoS unit test with blocks,
  undo data and a transaction index on disk – sizeable test
  infrastructure; the PoS path is checked on all 223,809 mainnet PoS rows
  by the self-check counters and the independent target model, and by the
  committed PoS sample. Recorded as an open point (and in
  `src/test/README.md`).
- 2026-10-03 – step 8: first lowdiff functional run failed in the new
  test: (a) genesis has 0 sigops – assertion moved past the genesis;
  (b) with fork 15 (not a multiple of the interval 10) the fork block
  takes the "constant target" branch, not the powLimit one – the extra
  assertion was wrong and is removed (the general `required_bits == bits`
  check covers it). A new unit assertion passed nMinEase 0 for the genesis
  instead of the powLimit compact – test fixed.
- 2026-10-03 – step 9: docs: `src/test/README.md` ("Consensus value
  dump"), `src/test/data/README.md`, `doc/functional-specification.md`
  §7, `doc/architecture.md` §6.4/§8, `doc/design-decisions.md` D-25,
  plan 0.3 row, runbook `mainnet-dump.md`, `known-issues.md` (B7 retarget
  tip dependency, `prevoutStake`/`nStakeTime` never set,
  `-rpcclienttimeout=0`, `GetMaxSize(…, 0)`), test counts in `CLAUDE.md`
  and `contrib/testing/README.md`.
- 2026-10-03 – step 8 (final): after the review fixes, `build.sh --config
  mainnet --unit`: exit 0, **348/348** unit tests; `build.sh --config
  lowdiff --unit --functional`: exit 0, **348/348** unit tests, functional
  **ALL Passed, 47/47** (223 s).
- 2026-10-03 – step 10: documentation reviewed by a subagent (18 findings,
  all medium/low wording or consistency). Applied: task description
  brought in line with the final code (stale `.incomplete` refused, kernel
  modifier is dumped, final counts, no synthetic PoS test, 18 N-factor
  hashes); D-25 wording on how the copies are checked; README wording
  (`txPrev.nTime`, offset, `min_bits_since_fork` at the genesis only on
  mainnet, full dump vs committed samples); runbook: `-txindex`/
  `-blockhashindex` assumptions, commands for the samples, removing the
  working copy; known-issues line reference; functional spec counter
  wording; architecture test list. Not applied: adding the stale
  `.incomplete` note to the RPC help text (14) – it would change compiled
  code after the final test run; README and runbook say it.
