# P0-48: Port gettxoutsetinfo (UTXO set hash)

- Plan section: 0.1
- Depends on: P0-01
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Provide a UTXO-set hash to compare chainstates; the RPC does not exist in this tree.

## Steps

1. Port GetUTXOStats and gettxoutsetinfo from Bitcoin Core 0.16, adapted to Yacoin's coins/token data.
2. Unit test on a small chain; functional test calling it.

## Acceptance criteria

- [x] RPC returns a stable hash_serialized for identical chainstates (unit `utxostats_tests`, functional `rpc_gettxoutsetinfo`).
- [ ] Included in the baseline binary (P0-06). – Closed by P0-06, which builds from a master that contains this change (P0-48 is one of its dependencies).

## Notes

Adds an RPC but no consensus change. Review: D1.

## Detailed description

### Facts checked (step 1)

- No `gettxoutsetinfo`, `GetUTXOStats` or `CCoinsStats` anywhere in `src/`
  (grep); `CLAUDE.md` and `doc/functional-specification.md` §7 list it as
  missing/planned.
- Coins: `CCoinsViewDB` (`src/txdb.h`) stores one record per output under key
  `'C' + COutPoint` (`txdb.cpp` `DB_COIN`), iterated in key order by
  `CCoinsViewDBCursor` (`txdb.cpp` `Cursor()`; LevelDB iterators read an
  implicit snapshot). Yacoin's `Coin` (`src/coins.h`) has two fields Bitcoin's
  lacks: `nTime` (ppcoin tx timestamp) and `fCoinStake`; `fCoinStake` is only
  stored for heights below `HeliopolisHardforkHeight` and reads back as false
  above it (`Coin::Unserialize`).
- Tokens: token outputs are ordinary coins (the token payload is in the
  `scriptPubKey`). Token metadata lives in a second LevelDB, `ptokensdb`
  (`src/tokens/tokendb.cpp`, `<datadir>/tokens`): records `'A'+name` →
  `CDatabasedTokenData` (name, amount, units, reissuable, IPFS, issue height,
  issue block hash) are written for every token whatever the options;
  `'B'`/`'C'` address-quantity records only with `-tokenindex`
  (`tokens.cpp` `DumpCacheToDatabase`, `fTokenIndex` checks), `'U'` block undo
  data, `'Z'` the mempool reissue state, `'M'` unused.
- `FlushStateToDisk()` (`validation.cpp`, `FLUSH_STATE_ALWAYS`) flushes
  `pcoinsTip` and then dumps the token cache to `ptokensdb`, both under
  `cs_main`.
- `TestingSetup` (P0-62) creates in-memory `pcoinsdbview` and `ptokensdb`;
  `TestChain100Setup` mines `COINBASE_MATURITY_AFTER_HARDFORK` (6) blocks.

### Scope

- New `CCoinsStats` + `GetUTXOStats()` (Bitcoin Core 0.16 port, adapted) in
  `src/rpc/blockchain.cpp`, declared in `src/rpc/blockchain.h` so unit tests
  can call it.
- New method `CTokensDB::GetTokenDataStats()` (hash + count of the `'A'`
  token-metadata records) in `src/tokens/tokendb.{h,cpp}`.
- New **visible** RPC `gettxoutsetinfo` (category `blockchain`, no
  arguments) with help text and `LogPrint(BCLog::RPC, …)` logging.
- Unit tests `src/test/utxostats_tests.cpp`; functional test
  `test/functional/rpc_gettxoutsetinfo.py` (added to `test_runner.py`).
- Docs: `doc/functional-specification.md` §7, `doc/architecture.md`,
  `CLAUDE.md`, test counts (`CLAUDE.md`, `contrib/testing/README.md`, the
  implement-task skill, `doc/architecture.md`).
- Not done: Bitcoin Core's later `hash_type`/MuHash/`coinstatsindex`
  variants, `dumptxoutset`, REST `/rest/...`; no change to how coins or tokens
  are stored, flushed or validated.

### Behaviour

`gettxoutsetinfo` flushes the chainstate (`FlushStateToDisk()`), then reads
the on-disk UTXO set and token database and returns:

```
{ "height": n, "bestblock": "hash", "transactions": n, "txouts": n,
  "bogosize": n, "hash_serialized": "hex", "disk_size": n,
  "total_amount": x.xxxxxx, "tokens": n, "hash_tokens": "hex" }
```

- `hash_serialized`: SHA-256d (`CHashWriter`, `SER_GETHASH`) over
  `bestblock`, then for each txid in key order: `txid`, and for each unspent
  output of it in index order `VARINT(n+1)`, `scriptPubKey`,
  `VARINT(nValue)`, `VARINT(nHeight*2+fCoinBase)`, `VARINT(nTime)`,
  `fCoinStake` (1 byte), then `VARINT(0)` per txid. Difference from Bitcoin
  Core's `hash_serialized_2`: height/coinbase are hashed per output instead
  of once per txid, and Yacoin's `nTime`/`fCoinStake` are added, so every
  field of a stored `Coin` is covered. The key is called `hash_serialized`
  (task wording); it is not comparable with Bitcoin Core's values.
- `hash_tokens`: SHA-256d over `bestblock` and then every `'A'` record of the
  token database in key order (`name`, then the `CDatabasedTokenData` record
  serialized as stored (`SER_DISK`) and hashed as a length-prefixed string –
  `CNewToken`'s serializer needs a stream with `size()`, which `CHashWriter`
  lacks);
  `tokens` is the number of records.
- **Why tokens are a separate hash:** token balances are already in
  `hash_serialized` (token outputs are coins with the token in the script),
  but token metadata (units, reissuable flag, IPFS hash, total amount after
  reissues) is chainstate that the UTXO set alone does not determine, so it
  must be covered too. It is kept as its own hash so a mismatch tells which
  database differs, and `hash_serialized` keeps Bitcoin's meaning (the UTXO
  set). Address-quantity records are excluded because they exist only with
  `-tokenindex` (two nodes with identical chainstate but different options
  must return identical hashes); undo data and the mempool reissue state are
  excluded because they are not part of the state at the tip.
- `transactions`/`txouts`/`total_amount`: txids with unspent outputs, unspent
  outputs, their total value (token outputs count with their YAC value,
  normally 0). `bogosize`: Bitcoin's formula (comparison metric only).
  `disk_size`: `CCoinsViewDB::EstimateSize()` (varies between nodes; not
  part of any comparison).
- Consistency: after the flush, the coins cursor and the token iterator are
  created together while holding `cs_main` (coins and tokens are only written
  together, by a full flush under `cs_main`, so both snapshots belong to the
  reported `bestblock`, even if a block arrives between flush and scan); the scan itself runs without `cs_main` (snapshots), so a
  long scan does not stall block processing.
- Logging: `LogPrint(BCLog::RPC, "gettxoutsetinfo: height=… bestblock=…
  txouts=… hash_serialized=… tokens=… hash_tokens=… (…s)")`;
  `LogPrintf` on a read failure. Error: `RPC_INTERNAL_ERROR "Unable to read
  UTXO set"`.

### Edge cases

- Empty UTXO set / empty token DB (fresh node, unit test before any
  block): valid result, counts 0, deterministic hashes (hash of
  `bestblock` + nothing).
- `bestblock` not in `mapBlockIndex` (unit test view with an arbitrary best
  block): height reported as -1 instead of Bitcoin's null dereference.
- `ptokensdb == nullptr` (fixtures without it): `tokens` 0, `hash_tokens`
  over `bestblock` only.
- Heights ≥ `HeliopolisHardforkHeight`: `fCoinStake` reads back false; the
  hash uses the value read from disk, so it is the same on every node.
- Same chain, different `-tokenindex`, `-txindex`, `-dbcache`: same hashes
  (only on-disk chainstate is read, after a full flush).
- Restart and `-reindex`: same hashes (rebuilt from the same blocks).
- Reorg/`invalidateblock` back to an earlier tip: hash returns to the
  earlier value (if not, that is a real chainstate difference – recorded as a
  finding, not fixed).
- Both builds: the RPC does not depend on chain parameters; unit tests
  compare hashes with each other (no hard-coded hash values), so they pass in
  mainnet and low-difficulty builds alike.
- Mainnet size: the scan holds no lock; `yacoin-cli` default timeout may be
  too short on slow disks – documented in the help text.

### How to test

| Acceptance / behaviour | Test | Expected |
|---|---|---|
| stable hash for identical chainstate | unit `utxostats_tests/identical_sets_same_hash`: two in-memory `CCoinsViewDB`s filled with the same coins in different write order/batches | same `hash_serialized`, counts, total |
| every coin field is covered | unit `utxostats_tests/each_field_changes_hash`: change value, script, height, coinbase, nTime, fCoinStake, txid, index, best block | hash differs each time |
| counts and totals | unit `utxostats_tests/counts_and_totals` (incl. empty set) | exact numbers |
| hash format is frozen | unit `utxostats_tests/known_answer`: fixed coins (heights below the Heliopolis height, main params) and best block | pinned `hash_serialized` and `hash_tokens` values, same in both builds |
| token metadata hash | unit `utxostats_tests/token_data_hash`: write/modify/erase token records in the in-memory token DB | tokens count, hash changes, returns to earlier value after erase |
| small chain | unit `utxostats_tests/small_chain_hash` (`TestChain100Setup`): mine a block with a spend → hash changes; `InvalidateBlock` back → hash equals the earlier one | as stated |
| RPC end to end | functional `rpc_gettxoutsetinfo.py`: two nodes synced → identical results (except `disk_size`); new block → hash changes, both nodes agree again; restart → unchanged; `-tokenindex` on one node only → same hashes; token issue → `tokens`/`hash_tokens` change; `invalidateblock` of the tip on one node → its result equals the one recorded at the previous height (there is no `reconsiderblock` here, so this runs last); `txouts`/`total_amount` checked against the coinbases mined | all pass |
| no regressions | `build.sh --config mainnet --unit`, `--config lowdiff --unit --functional` | 371+N unit in both, 48/48 functional |
| baseline binary (P0-06) | P0-06 builds from master after this merge | criterion closed by P0-06 |

### Risks

- No consensus code changes; the only call into validation is
  `FlushStateToDisk()` (already called by other RPCs, e.g. token RPCs).
- Flushing on every call costs time on a busy node; acceptable for a
  diagnostic RPC (same as Bitcoin Core).
- A hash definition that later needs to change would break comparison with
  P0-06 baselines; the format is documented here and in the help text.

## Implementation plan

1. **Token stats** – `src/tokens/tokendb.{h,cpp}`: add the static member
   `CTokensDB::HashTokenData(CDBIterator& cursor, CHashWriter& ss, uint64_t& nTokens)`
   (it needs the file-local `TOKEN_FLAG`): seeks `('A', "")`, hashes `name`
   and `CDatabasedTokenData` of each `'A'` record, stops at the first other
   key, returns false if a value cannot be read. The iterator is created by
   the caller (so it can be created under `cs_main`). Verify: compiles; unit
   test `token_data_hash`.
2. **`CCoinsStats` / `GetUTXOStats`** – `src/rpc/blockchain.{h,cpp}`: struct
   with the fields of the RPC result; `ApplyStats()` (per-txid group, fields
   as in the description); `bool GetUTXOStats(CCoinsView* view, CTokensDB*
   tokensdb, CCoinsStats& stats)`: under `cs_main` create the coins cursor and
   the token iterator, read `bestblock`, look up the height (-1 if unknown),
   `EstimateSize()`; then without the lock iterate coins
   (`boost::this_thread::interruption_point()`), then tokens; return false
   (with `error()` → debug.log) when a value cannot be read. Verify: unit tests.
3. **RPC** `gettxoutsetinfo` – help text (result fields, hash definitions,
   what is excluded and why, flush, runtime note, examples), `FlushStateToDisk()`,
   `GetUTXOStats(pcoinsdbview, ptokensdb, stats)`, result object,
   `LogPrint(BCLog::RPC, …)` with height, best block, counts, hashes and run
   time; register in `commands[]` as `blockchain` (visible).
   Verify: `yacoin-cli help gettxoutsetinfo`, functional test.
4. **Unit tests** `src/test/utxostats_tests.cpp` (+ `Makefile.test.include`):
   `counts_and_totals`, `identical_sets_same_hash`, `each_field_changes_hash`,
   `known_answer` (pin after first run, check identical in both builds),
   `token_data_hash`, `small_chain_hash` (`TestChain100Setup`, spend a
   coinbase, `InvalidateBlock`). Coins are written through a
   `CCoinsViewCache` on an in-memory `CCoinsViewDB` + `Flush()`.
5. **Functional test** `test/functional/rpc_gettxoutsetinfo.py` (2 nodes,
   node1 with `-tokenindex=1`, both `-tokenSupportBlockNumber=10`), add to
   `BASE_SCRIPTS`. Checks listed in "How to test".
6. **Build and test** both configurations (step 8 of the skill).
7. **Docs** – `doc/functional-specification.md` §7 (RPC listed, hash
   definition), `doc/architecture.md` (RPC section near
   `dumpconsensusvalues`, test counts and functional list), `CLAUDE.md`
   (remove "does not exist", counts), `contrib/testing/README.md`, skill counts,
   `project/plans/phase0-test-safety-net.md` unaffected (already names P0-48).

## Log

- 2026-10-03: step 0 – picked up (dependency P0-01 done), branch `task/P0-48-gettxoutsetinfo-rpc`.
- 2026-10-03: steps 1–2 – facts verified against the code (see "Facts checked"); detailed description written.
- 2026-10-03: step 3 – self-review (no Agent tool) of the description against task, D1, P0-06/P0-24/P0-35 uses and code. Findings applied: (1) unit tests only compared hashes with each other, so an accidental format change would go unnoticed although P0-06/P0-24 compare against stored baselines → added `known_answer` test with pinned hashes; (2) `reconsiderblock` does not exist in this tree → functional invalidate check runs last and compares with the value recorded at the earlier height; (3) `fCoinStake` is only stored below `HeliopolisHardforkHeight` (1,890,000 main, 0 regtest) → field tests use main params (`TestingSetup`) and low heights. Not applied: hashing tokens into `hash_serialized` (kept separate, reason in Behaviour).
- 2026-10-03: step 4 – implementation plan written.
- 2026-10-03: step 5 – self-review (no Agent tool) of the plan. Findings applied: (1) step 1 had an undecided signature → fixed to a static `CTokensDB::HashTokenData` taking a caller-created iterator; (2) flush and cursor creation are not in one `cs_main` section (flush in the RPC, cursors in `GetUTXOStats`) → checked that coins and tokens are only written by a full flush under `cs_main`, so the snapshots stay consistent with the reported `bestblock`; description reworded; (3) unit chain test must call `FlushStateToDisk()` before reading `pcoinsdbview`. No `rpc/client.cpp` entry is needed (no arguments). No consensus impact: only reads, plus the existing `FlushStateToDisk()`.
- 2026-10-03: step 6 – implemented as planned. Change during implementation: `CNewToken`'s serializer needs a stream with `size()`/`empty()` (`ReadWriteTokenHash`, tokentypes.h), which `CHashWriter` lacks → token records are serialized to a `CDataStream` (`SER_DISK`, as stored) and hashed as a length-prefixed string; description and docs updated. Unit test fix: `CCoinsViewDB::BatchWrite` asserts a non-null best block → the "other best block" case uses `0xb2`.
- 2026-10-03: step 7 – `code-review` skill (medium) on the staged diff: no correctness findings. Minor points: (a) `HashTokenData` stops silently on an undecodable key – left as is, a corrupt DB still yields a different `hash_tokens`; (b) the RPC ignores a failed `FlushStateToDisk()` – left as is, a failed flush aborts the node and the result still names the block actually scanned; (c) test list order in `Makefile.test.include` – fixed. Own pass: cast `nHeight` to `uint32_t` before `*2`, `assert(pcursor)` moved before first use, help text "height of bestblock".
- 2026-10-03: known-answer values (`utxostats_tests/known_answer`) reproduced independently: a 30-line Python implementation of the documented format gives the same `hash_serialized` (6e65f680…07d4) and empty-token `hash_tokens` (35374abb…d384).
- 2026-10-03: step 8 – first lowdiff run: `rpc_gettxoutsetinfo` failed on `disk_size > 0` (LevelDB's estimate covers table files only, a small chainstate still in the log reports 0) → check relaxed to an integer ≥ 0. Merged origin/master (P0-61) as requested. Final runs on the merged tree: lowdiff `build.sh --unit --functional` exit 0, 377/377 unit, ALL 48/48 functional; mainnet `build.sh --unit` exit 0, 377/377 unit, vector checkers ok.
- 2026-10-03: step 9/10 – docs updated (functional-specification §7, architecture §6.4 and test table, CLAUDE.md, contrib/testing/README.md, skill counts); self-review (no Agent tool) against code and results: claim "independent of -tokenindex, -txindex, -dbcache" reworded to say only `-tokenindex` is tested; token-hash wording aligned with the as-stored serialization; blockchain RPC count corrected to 25 (5 hidden) – the old 23 was already out of date before P0-08.
