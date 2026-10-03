# P0-16: Block trust, chain trust and fork-choice tests

- Plan section: 0.2c
- Depends on: P0-10, P0-47
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Pin every trust branch and its uses in fork choice and P2P.

## Steps

1. GetBlockTrust branches: genesis = 1; PoW before CONSECUTIVE_STAKE_SWITCH_TIME = 1; PoW after = powLimit/target (×2 after PoS); PoS after PoW = pprev->GetBlockTrust()+1; PoS after PoS = 0; legacy PoS = (1<<256)/(target+1); fTestNet switch (chain.cpp:83).
2. Accumulated bnChainTrust; CBlockIndexWorkComparator (validation.cpp:116).
3. GetBlockProofEquivalentTime (chain.cpp:188-205) – pin, don't fix.
4. net_processing.cpp comparisons (438-456, 536, 1481, 1507, 1583, 3113-3119) via unit-level scenarios where practical.
5. chaintrust hex in getblock/getblockheader and gettimechaininfo's getuint64 truncation (rpc/blockchain.cpp:945).

## Acceptance criteria

- [x] 100% of GetBlockTrust branches covered (all reachable ones; mapping
  in the Log, 2026-10-03 step 8).
- [x] Mainnet trust values are checked by P0-23 (not here) – nothing to do
  here; recorded in the test file header.

## Notes

Review: A5, A7, C8, D6.

- `src/test/chain_trust_tests.cpp` exists (P0-47) with the first trust-branch tests on harness chains; extend it.

## Detailed description

### Findings from reading the task (step 1)

All line references were checked against master 45eae1a.

- `GetBlockTrust` is `chain.cpp:75-115`; the `fTestNet` switch is
  `chain.cpp:83`, `GetBlockProofEquivalentTime` `chain.cpp:188-205`,
  `CBlockIndexWorkComparator` `validation.cpp:112-131` (compares at 116),
  `gettimechaininfo` `rpc/blockchain.cpp:945`, `chaintrust`
  `rpc/blockchain.cpp:96` (header) and `126-127` (block). The
  `net_processing.cpp` lines 438-456, 536, 1481, 1507, 1583, 3113-3119 are
  correct.
- Step 1 says "genesis = 1". The rule is "no `pprev`" (any first entry,
  PoW or PoS) under the new rules. The real genesis (2013) is before
  `CONSECUTIVE_STAKE_SWITCH_TIME` and gets 1 through the *legacy* PoW rule.
- Missing from step 1: target <= 0 gives 0 in every mode (`chain.cpp:79-80`),
  and the final `return CBigNum(0)` (`chain.cpp:112`) is unreachable (a block
  is either PoS or PoW, `chain.h:429-437`), so "100% of branches" means all
  reachable ones.
- `CBlockIndexWorkComparator` is in an anonymous namespace and
  `setBlockIndexCandidates` is not reachable from tests; there is no
  `reconsiderblock`/`ResetBlockFailureFlags`/`PreciousBlock` in this code.
  The comparator can only be exercised through `ProcessNewBlock` with real
  blocks. Regtest (`chainparams.cpp:237`, powLimit 2^255-1) makes mining in
  unit tests cheap (`TestChain100Setup` does it already).
- `UpdateBlockAvailability`, `ProcessBlockAvailability`,
  `FindNextBlocksToDownload` are file-internal in `net_processing.cpp`; they
  are reachable through `ProcessMessages` (an `inv` message) and
  `SendMessages`, and observable through `GetNodeStateStats` (`nSyncHeight`,
  `vHeightInFlight`). `ConsiderEviction` is public.
- 1481, 1507, 1583 are in `ProcessHeadersMessage` and only reached with
  headers that pass `ProcessNewBlockHeaders`; their effects
  (`m_last_block_announcement`, direct fetch, `m_protect`) need a full
  header-sync scenario. P0-32 (`feature_chaintrust_reorg.py`, "header sync
  and peer behaviour") covers them end to end.
- `gettimechaininfo` returns `bnChainTrust` as a JSON **number**
  (`getuint64()`, low 64 bits) although its help says "string ...
  hexadecimal".
- `chaintrust`/`blocktrust` use `leftTrim(GetHex(), '0')`: a value of 0
  becomes the empty string.

### Scope

Test-only. Extend `src/test/chain_trust_tests.cpp`; no production code
changes (CLAUDE.md rule 1, Phase 0 pins). Changes: the test file,
`src/test/README.md` (what the suite pins), task board, P0-32 note, test
counts in `CLAUDE.md`, `contrib/testing/README.md` and the
`implement-task` skill.

Not done here: mainnet trust values (P0-23), the `LoadBlockIndexDB` trust
recomputation `validation.cpp:3760` (same formula as AddToBlockIndex; full
reload is P0-24/P0-38), PoS blocks in real fork choice (P0-55/P0-32), the
header-sync comparisons 1481/1507/1583 (P0-32), the pointer tie-break of the
comparator (only for blocks loaded from disk, `nSequenceId` 0).

### Behaviour to pin (tests)

All on the mainnet params of the build unless noted; values that depend on
`powLimit` are pinned per build (`#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT`).
Synthetic entries come from the P0-47 `TestChain`.

1. `trust_target_not_positive`: nBits 0, negative compact (`0x04923456`),
   zero mantissa (`0x05000000`) give 0 for PoW/PoS, first block or not, new
   and legacy rules.
2. `trust_first_block_new_rules`: no `pprev` → 1 for PoW and PoS, any
   positive target (also > powLimit).
3. `trust_pow_new_rules`: `powLimit / target` (integer division):
   `0x1d00ffff` → 4096 (low-diff 536879104); target = compact powLimit → 1
   (low-diff 131072 for mainnet's `0x1e0fffff`); target > powLimit → 0
   (`0x1f00ffff` mainnet; low-diff 8192); doubled after PoS, also when that
   PoS block has trust 0; not doubled after PoW.
4. `trust_pos_new_rules`: PoS after PoW = `pprev->GetBlockTrust() + 1`
   (recursive: after a doubled PoW = 2T + 1; after a first block = 2; after
   a PoW with target 0 = 1); own nBits irrelevant if > 0; PoS after PoS = 0.
5. `trust_switch_time_boundary`: `nTime = switch - 1` legacy, `= switch` new;
   PoS after the switch on a PoW before it gets 1 + 1 = 2 (pprev's trust uses
   pprev's own time); PoW after the switch on a legacy PoS is doubled.
6. `trust_legacy_rules`: PoW 1 for any positive target (also > powLimit);
   PoS `2^256 / (target + 1)`, equal to Bitcoin `GetBlockProof` for targets
   < 2^256 (A7); no `pprev` uses the legacy rule (not 1); PoS after PoS is
   not 0; target 2^256 (compact `0x21010000`) → 0 while `GetBlockProof`
   gives 0 for it too (overflow).
7. `trust_testnet_switch`: (existing case, extended) first block and PoS
   after PoS under `fTestNet` with pre-switch times.
8. `chain_trust_real_blocks` (regtest, real blocks via `ProcessNewBlock`):
   genesis `bnChainTrust` = 1; each block's `bnChainTrust` = pprev's +
   `GetBlockTrust()` (AddToBlockIndex, `validation.cpp:2934`); also the
   mainnet genesis in `TestingSetup` = 1.
9. `fork_choice_by_trust` (regtest, real blocks): two forks from one parent;
   more trust → reorg; equal trust → the block received first stays tip (no
   reorg); a later block on the other fork making it heavier → reorg back.
   Exercises `CBlockIndexWorkComparator` (trust, then `nSequenceId`).
10. `fork_trust_with_pos` (synthetic): fork-choice consequence of the PoS
    rules (C8): PoW→PoS beats PoW→PoW by exactly 1; PoW→PoS→PoW beats
    PoW→PoW→PoW by T + 1; PoS→PoS adds nothing, so a fork with consecutive
    PoS loses to a PoW fork of equal length.
11. `proof_equivalent_time` (pin, don't fix): result =
    `sign * (|Δ chain trust| mod 2^256) * nPowTargetSpacing / GetBlockProof(tip)`;
    0 for equal trust; sign from the order; saturates at ±INT64_MAX (not
    INT64_MIN) when > 63 bits; a trust difference of exactly 2^256 gives 0;
    a tip whose nBits gives `GetBlockProof == 0` throws `uint_error`
    (division by zero); with mainnet PoW blocks (trust 4096,
    `GetBlockProof(0x1d00ffff)` = 4295032833) a month of blocks (43200) is
    worth 2 seconds – so the "older than a month in work" check at
    `net_processing.cpp:1119` does not trigger for new-rules blocks (A7).
12. `rpc_chaintrust`: `getblockheader` and `blockToJSON`: lower-case hex
    without leading zeros, 0 → `""` (`blocktrust` of PoS after PoS);
    `gettimechaininfo.bnChainTrust` is a number = trust mod 2^64 (2^64 + 5 →
    5).
13. `p2p_block_availability_by_trust` (438-456): `inv` for a known block
    with trust > 0 sets the peer's best known block (`nSyncHeight`); a later
    block with less trust is ignored, one with equal trust replaces it
    (`>=`); a known entry with trust 0 and an unknown hash are kept as
    "last unknown" and adopted by the next `inv` once known with trust > 0
    (`ProcessBlockAvailability`), not adopted while their trust is lower.
14. `p2p_download_by_trust` (536): `SendMessages` requests blocks
    (`vHeightInFlight`) from a peer whose best known block has trust >= our
    tip (equal included) and nothing when it is lower.
15. `p2p_eviction_by_trust` (3113-3119): `ConsiderEviction` on an outbound
    peer: best known trust >= tip → no timeout (no getheaders, no
    disconnect after the timeout); lower → getheaders after
    `CHAIN_SYNC_TIMEOUT`, disconnect after the response time.

### Edge cases

- Both builds: every value depending on powLimit is pinned per build;
  legacy and PoS-after-PoW values do not depend on it.
- Unit-test globals (fork height 0): trust does not read them; `fTestNet`
  is restored by `ScopedConsensusGlobals`.
- Regtest cases: no synthetic entries in `mapBlockIndex` (CheckBlockIndex
  walks it); forks need distinct coinbase scripts so equal-height blocks
  differ.
- P2P cases: peers are finalised before the `TestChain` is destroyed
  (dangling `pindexBestKnownBlock`, `mapBlocksInFlight`); mock time reset.
- Values > 256 bits (2^256 trust) are representable in `CBigNum`.

### How to test

- Both configurations: `build.sh --config mainnet --unit` and
  `--config lowdiff --unit --functional` all pass; expected 277 + new cases.
- Acceptance "100% of GetBlockTrust branches": mapping branch → test case in
  the Log (lines 79, 83 both ways, 86, 92, 96, 100 with/without ×2 (107), 112
  unreachable, 114 both ways).

### Risks

- No consensus code is touched. Risk is only in test correctness and test
  side effects on global state (net_processing node state, chainActive,
  mapBlockIndex, mock time, fTestNet).
- Regtest mining cost (scrypt hashes) – a few dozen blocks, as in
  `TestChain100Setup`.

## Implementation plan

1. **Trust branches (synthetic, mainnet params)** – in
   `chain_trust_tests.cpp` add cases 1-7 of the description; existing two
   cases stay. Expected powLimit-dependent values are literal per build
   (`#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT`), the others are computed from
   `CBigNum` and also checked against literals where small. Verify: build
   and run `--run_test=chain_trust_tests` in both builds.
2. **Fork trust with PoS (case 10)** – two `TestChain` forks from one entry
   (`Append(prev, spec)`); compare tips' `bnChainTrust`.
3. **GetBlockProofEquivalentTime (case 11)** – synthetic entries; tips with
   chosen nBits (`0x1d00ffff`, `0x21008000` → `GetBlockProof` 1, `0`);
   expected values computed by hand/Python and written as literals with
   the derivation in a comment; `BOOST_CHECK_THROW(..., uint_error)`.
4. **RPC (case 12)** – `blockToJSON(CBlock(), pindex)` for
   `blocktrust`/`chaintrust`, `tableRPC.execute` of `getblockheader <hash>`
   for a synthetic entry, and `gettimechaininfo` with `chain.SetActiveTip`
   on a tip whose `bnChainTrust` is set to 2^64 + 5 (test-owned entry).
5. **Regtest real blocks (cases 8, 9)** – fixture
   `RegtestConsensusSetup : ConsensusTestingSetup(REGTEST)`; helper
   `MineBlock(parent, scriptPubKey)`: `BlockAssembler().CreateNewBlock`
   (template on the active tip), then `hashPrevBlock = parent`,
   `nBits = GetNextTargetRequired(parent, false)`, `nTime` >= parent's
   median time past + 1, `IncrementExtraNonce(&block, parent, n)` (coinbase
   height and merkle root; the coinbase value is reset to
   `GetProofOfWorkReward(nBits, 0, parent height + 1)` because the template
   uses the active height, `miner.cpp:525`), grind `nNonce` until `CheckProofOfWork`.
   Submit with `ProcessNewBlock(…, fForceProcessing, …)` and check
   `chainActive.Tip()`. Also pin `AcceptBlock`'s `fHasMoreOrSameWork`
   (`validation.cpp:3457`): an unrequested block with less trust is not
   stored (`BLOCK_HAVE_DATA` unset), one with equal trust is.
6. **P2P (cases 13-15)** – helpers in the test file: `MakeOutboundPeer()`
   (as in `DoS_tests`), `ReceiveMessage(node, command, payload)` building a
   `CNetMessage` (`readHeader`/`readData` with `::pchMessageStart` and the
   checksum) and calling `peerLogic->ProcessMessages`, `CountSent(node,
   command)` parsing the 24-byte headers in `vSendMsg`, `SyncHeight(node)`
   via `GetNodeStateStats`. A small RAII guard calls `FinalizeNode` and
   `CConnmanTest::ClearNodes` before the `TestChain` is destroyed; mock
   time via `globals.SetMockTime` (restored automatically).
7. **Tests** – both builds via `build.sh` (functional with the flock).
8. **Docs** – `src/test/README.md` (suite list and what P0-16 pins,
   including the behaviours found: empty-string zero trust,
   `gettimechaininfo` number, PoW trust 0 above powLimit,
   `GetBlockProofEquivalentTime` quirks); P0-32 task note for 1481/1507/1583;
   test counts in `CLAUDE.md`, `contrib/testing/README.md`, the skill; task
   Log with the branch → test mapping.

Logging (rule 5): no daemon code changes, so no new log lines; tests report
values with `BOOST_TEST_MESSAGE`.

## Log

- 2026-10-03: step 0 – dependencies P0-10, P0-47 done; moved to inprogress on branch `task/P0-16-chain-trust-tests`.
- 2026-10-03: step 1 – read task, plan 0.2c, review A5/A7/C8/D6, code.
  Corrections and gaps recorded under "Findings" (genesis rule, target <= 0,
  unreachable line 108, comparator not reachable directly, 1481/1507/1583).
- 2026-10-03: step 3 – description review, self-review (no Agent tool):
  re-read against the code. Changes: saturation case needs a trust
  difference whose product with the spacing stays < 2^256 (arith_uint256
  multiplication wraps) – added the wrap (2^255 · 60 ≡ 0) as its own pinned
  value; added `AcceptBlock` `fHasMoreOrSameWork` (`validation.cpp:3457`) to
  case 9; equal-trust fork cases must check the trust equality first
  (regtest nBits may differ) – done with `BOOST_REQUIRE`; added the 3119
  "peer caught up to the work header" branch to case 15. Not applied: the
  header-sync comparisons stay with P0-32 (needs a header-sync scenario;
  the effects are only visible through the eviction logic).
- 2026-10-03: step 5 – plan review, self-review (no Agent tool): template
  coinbase value is for the active height (`miner.cpp:525`), fixed in
  step 5; regtest cases must not create `TestChain` entries
  (`CheckBlockIndex` walks `mapBlockIndex`); P2P peers must be finalised
  before the chain is destroyed – RAII guard. No consensus impact (tests
  only).
- 2026-10-03: step 6 – implemented `src/test/chain_trust_tests.cpp` (2 → 18
  cases in 3 suites: `chain_trust_tests` 13, `chain_trust_fork_choice_tests`
  2, `chain_trust_p2p_tests` 3). Plan deviations: (a) a reorg in
  `test_bitcoin` crashed (null `ptokensdb` in `DisconnectBlock`,
  `validation.cpp:1322`; `TestingSetup` creates no token DB) – the regtest
  fixture installs an in-memory `CTokensDB`; (b) `ProcessMessages` skipped
  the injected messages because the unstarted test `CConnman` has a
  send-buffer limit of 0 and every queued message sets `fPauseSend` – the
  test peer clears it; (c) `trust_genesis` added (real genesis, legacy
  rule). Both are test-environment issues, no production change.
- 2026-10-03: step 7 – `code-review` skill (high) on the staged diff, 9
  findings. Applied: wrong `chain.cpp` line numbers (75-115, 112
  unreachable, 114 legacy, 99-111 PoW, 92-97 PoS, 173 GetBlockProof) in the
  test comments, README and this file; test counts updated (CLAUDE.md,
  `contrib/testing/README.md`, skill: 293); pass counts in this Log;
  `Add`/`AddWithHash` merged; the "one TestPeer at a time" limit
  documented. Not applied: (1) the 43,200-entry month in
  `proof_equivalent_time` stays – it is the realistic case the A7 finding
  is about and costs ~80 ms; (2) the two P0-47 `harness_*` cases stay as
  they are (P0-47's harness examples, not worth churning); (3) a shared
  P2P message helper in `test_bitcoin.{h,cpp}` and a non-zero send-buffer
  limit for the test `CConnman` – out of scope (changes shared test setup);
  noted in `src/test/README.md` for whoever needs it next (P0-32 is
  functional).
- 2026-10-03: step 8 – tests (`build.sh`, image pinned by digest):
  mainnet unit 293/293, exit 0; lowdiff unit 293/293 and functional 45/45,
  exit 0. Branch → test mapping for `GetBlockTrust` (`chain.cpp:75-115`):
  79-80 target <= 0 → `trust_target_not_positive`; 83 new rules by time →
  `trust_switch_time_boundary`, by `fTestNet` → `trust_testnet_switch`,
  `harness_trust_legacy_rules_and_testnet_switch`, legacy (false) →
  `trust_legacy_rules`; 86-87 no pprev → `trust_first_block_new_rules`;
  92-93 PoS after PoS → `trust_pos_new_rules`, `trust_pow_new_rules`;
  96-97 PoS after PoW → `trust_pos_new_rules`, `trust_switch_time_boundary`;
  100-110 PoW with/without doubling (107-108) → `trust_pow_new_rules`;
  112 unreachable (a block is PoS or PoW, `chain.h:429-437`); 114 legacy
  PoS/PoW → `trust_legacy_rules`, `trust_genesis`.
- 2026-10-03: step 9 – docs: `src/test/README.md` (suites, pinned
  behaviour, test-setup pitfalls), P0-32 note for 1481/1507/1583, test
  counts in `CLAUDE.md`, `contrib/testing/README.md`, the skill.
- 2026-10-03: step 10 – documentation review, self-review (no Agent tool):
  README section, description, P0-32 note and counts re-read against the
  code and the test logs. Fixed: "the one-month check never triggers" was
  too strong (legacy PoS trust is large enough) – reworded in README and
  description; line numbers corrected in step 7. Nothing left open.
- 2026-10-03: step 11 – merged origin/master (P0-12, 4b3d2e0; merge
  commit, count conflicts resolved to 284 + 16 = 300) and re-ran on the
  merged tree: mainnet unit 300/300, exit 0; lowdiff unit 300/300 and
  functional 45/45, exit 0. Moved to done; branch pushed, PR
  https://github.com/dev34253/yacoin/pull/58.
