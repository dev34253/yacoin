# P0-50: Inventory correction and dead-code list

- Plan section: 0.1
- Depends on: none
- Size: S
- Owner: Claude (subagent of the owner's Claude Code session)
- Started: 2026-10-02
- Finished: 2026-10-02

## Goal

Keep the plans factually right and list dead code for removal.

## Steps

1. Verify the corrected OpenSSL/CBigNum inventory in plans/overview.md against the source (review A1, A2, A5, A8, A10, B5).
2. Dead-code list: unused scrypt.cpp functions (scrypt_blockhash, salted, multiround, scanhash_scrypt), pbkdf2.cpp, random_nonce.cpp, unused CBigNum methods (from P0-12), dead fTestNet branches.
3. Propose removal as a separate PR (outside Phase 0 consensus freeze rules, since none of it is reachable).

## Acceptance criteria

- [x] Inventory confirmed; dead-code list committed to plans/; removal PR proposed.
  (Inventory corrected in `plans/overview.md`; list in
  [`plans/dead-code.md`](../plans/dead-code.md); removal proposed as task
  [P0-59](../todo/P0-59-dead-code-removal.md) with three gated PRs. No
  code-removal PR opened, see Detailed description – Risks.)

## Notes

Feeds P0-04 coverage exclusions. Review: A1, A2, A5, A8, B5.

## Detailed description

Checked against `master` at 651e82e. Line numbers below are from that tree.

### Scope

Will do:

1. **Inventory check.** Check every row of the `CBigNum` and "Other
   OpenSSL use" tables and the "Other consensus code" list in
   `project/plans/overview.md` against the source, and correct
   `overview.md` where it is wrong. Review findings A1, A2, A5, A8, A10
   and B5 are re-checked one by one.
2. **Dead-code list.** Write a new plan page,
   `project/plans/dead-code.md`. For every item it gives the location
   (file:line), the evidence that the item is unreachable (callers, build
   flags, start-up path), whether the file is consensus code, what it
   means for P0-04 coverage exclusions, and how and when to remove it.
   Groups:
   - **a) unreferenced functions and files:** in `scrypt.cpp` everything
     except `bool scrypt_hash(..., Nfactor)`; `pbkdf2.cpp/.h`;
     `random_nonce.cpp/.h`; the `scrypt_core` implementations
     (`scrypt-generic.cpp`, `scrypt-x86.S`, `scrypt-x86_64.S`), and
     `scrypt-arm.S`, which no Makefile lists at all;
     `ComputeMinWork`, `ComputeMinStake`, `ComputeMaxBits` and
     `GetProofOfStakeLimit` in `pow.cpp`; the globals at `main.cpp:74-75`.
   - **b) dead `fTestNet` branches:** every use of `fTestNet`, with the
     start-up path that proves it is always `false`.
   - **c) unused `CBigNum` methods:** a first list found with grep. It is
     marked "preliminary"; P0-12 confirms it.
   - **d) leftovers:** OpenSSL includes that nothing uses, unused includes
     of the dead files, the orphan `yacoind-scrypt-jane.o` make rule and
     the flags only it uses, and the `-rpcssl*` help text for options the
     node refuses.
3. **Removal proposal.** A new task file,
   `project/todo/P0-59-dead-code-removal.md`, describes the removal PRs:
   what each one deletes, the order, the gates (which Phase 0 tests must be
   in place first), and how to check that nothing changed (unit and
   functional tests, header-hash known answers, and identical object code
   for the consensus files where possible). The task does **not** open a
   code-removal PR (see Risks).
4. Cross-references: plan 0.1 and 0.2e in `phase0-test-safety-net.md`, a
   follow-up note in `phase0-review.md` (corrections to A2, A5, B5 and
   B11), and the task list range in the plan header.

Will not do: change any C++ source, build file, test or `.github/`
workflow; the `CBigNum` large-value tests and the full method audit
(P0-12); the coverage exclusion config (P0-04).

### Behaviour (what the documents will say)

Results of step 1, each checked in the source:

| Claim (overview / review) | Result | Evidence |
|---|---|---|
| A1: wallet crypter uses `crypto/aes.h`, `crypto/sha512.h`, own `BytesToKeySHA512AES`; EVP only as a test oracle | confirmed | `wallet/crypter.cpp:8-9,17-41`; `wallet/test/crypto_tests.cpp:17-84` (EVP), `:143` (`SSLeay()`) |
| A2: block hash = `CalculateHash` → scrypt-jane; `GetNfactor` display-only; `scrypt_blockhash`, salted, multiround, `scanhash_scrypt` dead | confirmed, and more is dead: in `scrypt.cpp` only `bool scrypt_hash(..., Nfactor)` (`:108-139`) is called (from `primitives/block.h:139,212`). `uint256 scrypt_hash(input,len)`, `scrypt_nosalt`, `scrypt_SHA256`, `scrypt_buffer_alloc/free` have no callers either, so the `scrypt_core` implementations and `pbkdf2.cpp` are dead too | grep of every symbol; `GetNfactor` callers `rpc/mining.cpp:313`, `qt/clientmodel.cpp:210` only |
| A5/A6: "about 60 production call sites in 13 files, 113 in `bignum.h`, 4 in tests" | counts are **lines**: 60 lines in 13 files, of which 1 is a comment in dead code (`scrypt.cpp:235`), so 59 lines in 12 files; `bignum.h` has 113 lines (158 occurrences); tests 4 lines (`test/pow_tests.cpp`) | `grep -c CBigNum` per file |
| A5 table rows (`consensus/params.h:62,64`, `rpc/mining.cpp:145,420,860`, `rpc/blockchain.cpp:358`, `miner.cpp:642,801`, `qt/explorer.cpp:1302`, `net_processing.cpp` lines) | confirmed (`getsubsidy`, `getwork`, `getblocktemplate`, `getdifficulty`, `CheckWork`, `YacoinMiner`) | file:line |
| `main.cpp:74-75` "limits, consensus" | **wrong**: `bnProofOfStakeLegacyLimit` and `bnProofOfStakeLimit` are never referenced | grep |
| `pow.cpp` "min work/stake" | **wrong**: `ComputeMinWork`/`ComputeMinStake` (`pow.cpp:275-287`, declared `pow.h:29-30`) have no callers; so `ComputeMaxBits` and `GetProofOfStakeLimit` are dead too. `bnProofOfStakeHardLimit` stays (used at `pow.cpp:112`) | grep |
| `validation.cpp` | missing rows: `:3703-3706,3727` (`LoadBlockRewardAndHighestDiff`, `CBigNum` only for a log line) and `:3760` (`bnChainTrust` sum in `LoadBlockIndexDB`, fork choice) | file:line |
| A8: `random_nonce.cpp` uses `rand()`/`srand(time)`; only caller is `scanhash_scrypt` | confirmed, more precisely: `scanhash_scrypt` calls `get_a_nonce` (a plain increment); `randomize_the_nonce` (the `rand()` user) has no caller at all | `random_nonce.cpp:9,27,53-77`; `scrypt.cpp:266` |
| A10: libssl linked into `yacoind`/`yacoin-cli`, configure requires libssl | confirmed (`Makefile.am:407,425`; `configure.ac:922,937-941`); also linked into `test_bitcoin`, `test_bitcoin_fuzzy`, `yacoin-qt` (`Makefile.test.include:100,124`, `Makefile.qt.include:463`); the `RAND_egd` LibreSSL check appears twice (`configure.ac:958-964`, `973-985`) | |
| B5: `util.cpp:120-163`, `support/cleanse.cpp:13`, `miner.cpp:93-105`, `pbkdf2.cpp`, Qt files | confirmed (`SHA256Transform` ends at `:106`) (`SHA256Transform` is used by `getwork` at `miner.cpp:597,634`) | |
| B5: `init.cpp:66` stale include | **wrong**: `init.cpp:972` calls `SSLeay_version(SSLEAY_VERSION)` (OpenSSL 1.0 name) | |
| B5: `wallet/wallet.cpp:48` stale include | confirmed (no OpenSSL call in the file) | |
| overview: `test/crypto_tests.cpp` uses EVP as an oracle | **wrong**: includes `openssl/aes.h`/`evp.h` (`:20-21`) but calls no OpenSSL function (`AES_BLOCKSIZE` is from `crypto/aes.h`) – stale includes | |
| overview Qt list | `qt/rpcconsole.cpp:23` and `qt/explorer.cpp:19` include `openssl/crypto.h` without any OpenSSL call (stale); real Qt uses: `paymentserver`, `paymentrequestplus` (X509), `winshutdownmonitor` (`RAND_event`) | |
| overview: SIMD path chosen at `Makefile.am:186-195` | partly: only `DEFS+=` at `:191` reaches the real compile (`SCRYPT_CHOOSE_COMPILETIME` etc.). `SCRYPTDEFS`, `xCXXFLAGS`, `xCXXFLAGS_SCRYPT_JANE` and the rule `yacoind-scrypt-jane.o` (`:186-188,190,193-195`) are used by nothing, so `USE_ASM` is never defined and the `.S` files assemble to empty objects | `Makefile*.am/include`; checked on the build output (see How to test) |
| B11: `fTestNet` branches dead | confirmed: `-testnet` makes `CreateChainParams` throw (`chainparams.cpp:323-330`), caught at `yacoind.cpp:119-124` / `qt/bitcoin.cpp:645-650`, which exit before `init.cpp:849` sets `fTestNet`; `test_bitcoin` never sets it. `testnet=1` in `yacoin.conf` takes the same path (`ReadConfigFile` runs first, `yacoind.cpp:113`). Uses: `chain.cpp:83`, `kernel.cpp:76,656`, `primitives/block.h:173,200-203`, `consensus/tx_verify.cpp:417`, `miner.cpp:854`, `protocol.h:19-21`, `init.cpp:849`; definition/declarations `util.cpp:586`, `util.h:455`, `protocol.h:18`; commented-out `miner.cpp:159,168`; dead data `mapStakeModifierCheckpointsTestNet` (`kernel.cpp:68-71`) and `nModifierTestSwitchTime` (`timestamps.h:60`). **Not** the global: `chainparamsbase.cpp:93` is a live local variable of the same name | |
| other OpenSSL use not in the overview | `miner.cpp:16` (`openssl/sha.h`, behind `SHA256Transform`); `random.cpp:135,166,276,450-451` (`RAND_add`, `RAND_bytes`); Qt tests `qt/test/paymentservertests.cpp:17-18` (X509 calls), `qt/test/test_main.cpp:24,77`; `Makefile.qttest.include:59` links `SSL_LIBS` | grep |
| Qt testnet code (outside B11) | `qt/paymentserver.cpp:230,232,249` calls `CreateChainParams`/`SelectParams(TESTNET)`, which throw because no testnet params exist: reachable from a payment URI or file, so a latent Qt bug, not dead code (Qt, grep only) | `chainparams.cpp:323-330` |

Not dead although they look like it (the list says so explicitly, so nobody
removes them): `bool scrypt_hash(..., Nfactor)` (consensus block hash);
`DEFS+=` at `Makefile.am:191`; `bnProofOfStakeHardLimit`;
`-testnetNewLogicBlockNumber` (a mainnet option used by the functional
tests, `init.cpp:1144`); the local `fTestNet` in `ChainNameFromCommandLine`
(`chainparamsbase.cpp:93`); `CBaseTestNetParams` (`yacoin-cli -testnet` still
selects port 17687); `CRegTestParams` (selectable with `-regtest`, only
unused by the tests); `getinfo`'s `"testnet"` field (always `false`, but
an output); `SHA256Transform` (`getwork`).

### Edge cases

- **Inline header code and coverage:** unused inline `CBigNum` methods are
  never emitted, so gcov records no lines for them; excluding them in
  P0-04 changes nothing. The non-inline dead functions (`scrypt.cpp`,
  `pbkdf2.cpp`, `random_nonce.cpp`, `scrypt-generic.cpp`, `pow.cpp`) do
  count. The list says which is which.
- **Static initialisers:** `main.cpp:74-75` construct two `CBigNum`
  globals and `random_nonce.cpp:19` constructs `Big` at start-up; removing
  them changes start-up slightly (harmless), so "identical object code" can
  only be required for the functions that stay, not for whole files or the
  binary.
- **Wallet:** the wallet only supports key derivation method 0
  (`wallet/crypter.cpp:50`) and uses none of the salted scrypt functions;
  the list says so, so nobody keeps them "for old wallets".
- **Static library linking:** `scrypt.cpp` is linked because
  `scrypt_hash` is live, so its dead functions and their dependencies
  (`pbkdf2.o`, `scrypt-generic.o`, `random_nonce.o`) are linked as well.
  Removing them changes the binary but not the live function.
- **Two build configurations:** `scanhash_scrypt` has
  `LOW_DIFFICULTY_FOR_DEVELOPMENT` branches; it is dead in both.
- **Other targets:** the `.S` files are guarded by `USE_ASM` and
  `__i386__`/`__x86_64__`; Windows/macOS cross builds (P0-53) use the same
  `Makefile.am`, so the same reasoning holds; recorded as "not verified on
  those targets".
- **Qt:** deferred (P0-00), not built here; Qt-only facts come from grep
  only and are marked so.
- **grep limits:** generic method names (`ToString`, `GetHex`, `SetHex`,
  `getvch`, `++`/`--`) cannot be attributed to `CBigNum` by grep; they are
  left to P0-12.

### How to test

| Acceptance criterion | Check | Expected |
|---|---|---|
| Inventory confirmed | every claim in the table above re-run with the `grep`/`sed` commands recorded in `dead-code.md` | same results |
| "Dead" is really unreferenced | `git grep -nw <symbol>` over the whole repository (sources, `.S`, Makefiles, `configure.ac`, `contrib/`, `test/`, `depends/`), plus the underscore-prefixed asm names (`_scrypt_core`) | only the definition, declaration and other dead callers |
| `USE_ASM` not defined in the real build | after the mainnet build, `nm` on the `scrypt-x86_64` object in the build work dir | no symbols (empty object) |
| Dead `scrypt.cpp` functions are linked but never run | `nm -C` on `yacoind` lists `scrypt_blockhash` etc. (holds because the build uses neither `--gc-sections` nor LTO); no run-time check possible | present (explains the coverage denominator) |
| Dead-code list committed to `plans/` | `project/plans/dead-code.md` exists, linked from `overview.md` and plan 0.1 | – |
| Removal PR proposed | `project/todo/P0-59-dead-code-removal.md` exists with steps, gates and checks | – |
| No regression (skill step 8; docs-only change) | `build.sh --config mainnet --unit`; `build.sh --config lowdiff --unit --functional` | mainnet 239/239; lowdiff 238/239 (known `pow_tests/get_next_work_pow_limit`), functional 45/45 |

Test levels: no new tests (documentation only); the full existing suites in
both configurations.

### Risks

- **Consensus:** none from this task; no source changes. The removal itself
  touches consensus files (`scrypt.cpp` holds the live block-hash wrapper;
  `pow.cpp`, `chain.cpp`, `kernel.cpp`, `primitives/block.h`,
  `consensus/tx_verify.cpp` hold the `fTestNet` operands and dead
  functions). Even a behaviour-preserving edit there is against CLAUDE.md
  rule 1 until the matching Phase 0 tests exist. That is why the removal is
  proposed as a gated task rather than opened as a PR now. `pbkdf2.cpp`,
  `random_nonce.cpp`, `scrypt-generic.cpp` and the `.S` files cannot go
  without editing `scrypt.cpp`, which references them. P0-59 therefore
  has an ungated part A that touches no consensus file (stale non-Qt
  includes, `-rpcssl*` help text, orphan make rule and flags,
  `scrypt-arm.S`) and gated parts for the rest. (The `RAND_egd` check was
  dropped from part A after the plan review, see step 5 in the Log.)
- **Wrong "dead" verdict:** a symbol called through a macro, a function
  pointer, or from code outside `src/`. Mitigated by greps over the whole
  tree (including `qt/`, `test/`, `contrib/`, `.S`), and the removal task
  requires the build to fail loudly (undefined reference) if anything was
  still used.
- **Line numbers go stale:** the list names functions as well as lines, and
  records the commit it was checked at.

## Implementation plan

Documentation only; no file under `src/`, `configure.ac`, `Makefile*`,
`depends/` or `.github/` changes.

1. **`project/plans/dead-code.md` (new).** Header: purpose, the commit it
   was checked at, consensus-file marker legend, how to re-check (the
   `git grep` commands). Sections:
   - a) unreferenced functions and files: one row each with location,
     evidence, consensus file yes/no, counted in coverage yes/no, removal
     part in P0-59;
   - b) dead `fTestNet` uses with the start-up argument, including the
     `yacoin.conf` path, and the live local in `chainparamsbase.cpp:93`;
   - c) unused `CBigNum` methods, marked preliminary (P0-12 confirms; Phase 4
     deletes, plan 0.2a);
   - d) leftovers: stale includes, orphan make rule and flags,
     `-rpcssl*` and testnet help text; notes on things that are not dead
     (`RAND_egd` checks, Qt payment-server testnet code). `scrypt-arm.S`
     went to a) while writing;
   - "Looks dead but is not" list;
   - notes for P0-04 (which items are in the gcov denominator) and the
     removal proposal summary pointing to P0-59.
   *Verify:* re-run each `git grep` while writing; every row's file:line
   opened.
2. **`project/plans/overview.md`.** Correct the inventory: `CBigNum`
   counts (lines, 59/12 after removing the dead comment), `main.cpp:74-75`
   and the `pow.cpp` min-work/stake row, missing `validation.cpp` rows;
   OpenSSL table: `init.cpp` (`SSLeay_version`), `miner.cpp:16`,
   `random.cpp` lines, test rows (wallet test is the only EVP oracle;
   `test/crypto_tests.cpp` stale), Qt rows (real vs stale), build row
   (all link lines, `RAND_egd` twice); `random_nonce.cpp` sentence;
   block-hash bullet (`scrypt.cpp` has one live function; only
   `Makefile.am:191` is live); Phase 3 and Phase 5 rows (dead code to
   P0-59; `RAND_egd` twice; Qt stale vs real includes); coverage table rows
   for `scrypt.cpp`/`random_nonce.cpp` link the list; link to
   `dead-code.md`. *Verify:* diff read against the step-1 table.
3. **`project/plans/phase0-test-safety-net.md`.** Task range in the intro
   (`P0-00` … `P0-59`); 0.1 "Inventory correction" row links
   `dead-code.md`, plus a new row for P0-59 saying it is not an exit
   criterion; 0.2a
   method audit mentions the preliminary list; 0.2e dead-function bullet
   links the list. *Verify:* links resolve (relative paths).
4. **`project/plans/phase0-review.md`.** Short "Follow-up (P0-50)" note
   listing which findings were refined (A2 scope, A5/A6 counts, B5
   `init.cpp:66`, B11 list) – the review tables stay as the historical
   record.
5. **`project/todo/P0-59-dead-code-removal.md` (new).** Task format of
   `project/README.md`. Each part is one PR:
   - Part A (no consensus file; depends on P0-50 only): stale non-Qt
     includes, `-rpcssl*` help text, orphan make rule and flags
     (`Makefile.am:186-188,190,193-195`, keeping the live `DEFS+=` at
     `:191`), `scrypt-arm.S`. Check: `make V=1` compile line of
     `scrypt-jane.c` identical and its object byte-identical before/after.
     Not in part A: the `RAND_egd` checks (the first one has side effects:
     it adds `-lcrypto` to `LIBS` and defines `HAVE_LIBCRYPTO`; Phase 5
     removes both) and the Qt includes (Qt is deferred, P0-00).
   - Part B (`scrypt.cpp` dead functions, `pbkdf2.*`, `random_nonce.*`,
     `scrypt-generic.cpp`, `scrypt-x86*.S`, `Makefile.am:123,130,220,224,236-238`
     entries, `miner.cpp:49` include): gated on P0-19. Checks: P0-19 known
     answers, `objdump -dr` of `scrypt_hash` in the `.o` before/after
     (relocations symbolic), the part-A `make V=1` check.
   - Part C (`pow.cpp` dead functions, `main.cpp:74-75`, every `fTestNet`
     use incl. `protocol.h` `GetDefaultPort` used by `net.cpp`): gated on
     P0-14, P0-16, P0-17, P0-18, P0-19, P0-23 and P0-46. Object code can
     only be compared for functions that are not edited; the edited ones
     (`GetBlockTrust`, `IsFixedModifierInterval`,
     `CheckStakeModifierCheckpoints`, `CalculateHash`, `CheckTxInputs`) rely
     on the gating tests plus the P0-23 replay or a P0-24-style reindex.
     (The code review added more functions whose object code changes; the
     final list is in P0-59.)
   - All parts: both test configurations.
   Not added to P0-45's dependencies and not a Phase 0 exit criterion
   (the plan says so); timing is an owner decision (Open points). Record
   the interaction with P0-04: if parts B/C land first, P0-04's exclusion
   list shrinks.
6. **Related task files.** P0-04 step 3 and P0-12 point to
   `plans/dead-code.md`; P0-21 step 3 notes it is already recorded.
7. **Checks on the build output** (after the builds in step 8):
   `nm` on the `scrypt-x86_64` object (expect empty) and `nm -C yacoind`
   (expect the dead `scrypt.cpp` symbols present). Record in the Log and
   `dead-code.md`.
8. Tests (skill step 8): mainnet unit, lowdiff unit + functional. Since no
   source changes, a run on any commit of this branch is valid for the
   final tree; the Log records which commit and that only `project/`
   differed.

Logging (CLAUDE.md rule 5): not applicable, no behaviour changes.

## Log

- 2026-10-02 – Step 0: dependencies none; branch
  `task/P0-50-inventory-and-dead-code` from `origin/master` 651e82e; moved to
  `inprogress/` (commit 95235c59) and pushed.
- 2026-10-02 – Step 1: read plan 0.1/0.2a/0.2e, `overview.md`,
  `phase0-review.md` (A1–A12, B5, B11), P0-04, P0-12, P0-19, P0-21 and the
  named sources. Every claim checked in the source; results are in the
  table in "Detailed description". Wrong or incomplete in the task/plans:
  `init.cpp:66` is not stale; `test/crypto_tests.cpp` is not an EVP oracle;
  `main.cpp:74-75` and the `pow.cpp` min-work/stake functions are dead,
  not consensus; much more of `scrypt.cpp` is dead than the task lists
  (all but one function), which makes `scrypt-generic.cpp` and the `.S`
  files dead too; `USE_ASM` never reaches the real compile. The task's
  "unused CBigNum methods (from P0-12)" depends on P0-12, which is not done;
  a preliminary grep list is given instead. Step 3 says "propose removal as
  a separate PR … none of it is reachable": true, but some of it sits in
  consensus files, so the proposal is a gated task file, not an open PR.
- 2026-10-02 – Step 2: detailed description written.
- 2026-10-02 – Step 3: description reviewed by a reviewer subagent, which
  re-ran the greps and confirmed every verdict (A1, A2, A5 counts, A8, A10,
  B5, `USE_ASM`, `fTestNet` incl. the `yacoin.conf` path). Applied: complete
  `fTestNet` list and the live local `chainparamsbase.cpp:93`; whole-repo
  grep incl. `_scrypt_core`; `scrypt-arm.S`; missing OpenSSL rows
  (`miner.cpp:16`, `random.cpp` lines, Qt tests, `Makefile.qttest.include`);
  Qt payment-server testnet code (recorded as a latent Qt bug, not dead);
  static-initialiser side effects; `nm` assumption (no `--gc-sections`/LTO);
  ungated part A in P0-59. Not applied: the claim that
  `scrypt_salted_multiround_hash` was once used for wallet key derivation
  (reviewer marked it unconfirmed; `git log -S` finds no such use in the
  crypter); only the confirmed fact (wallet supports method 0 only) is
  recorded.
- 2026-10-02 – Step 4: implementation plan written. Started the two test
  builds in the background on 95235c59 (no source changes in this task).
- 2026-10-02 – Step 5: plan reviewed by a reviewer subagent (10
  findings). Applied all: `RAND_egd` removed from part A (the first check
  has side effects: `-lcrypto` in `LIBS`, `HAVE_LIBCRYPTO`) and left to
  Phase 5; part A gets a `make V=1`/byte-identical check for
  `scrypt-jane.c` because the live `DEFS+=` line sits between the dead
  ones; P0-46 added to the part C gate (`tx_verify.cpp:417` is reward
  logic); object-code comparison limited to functions that are not edited,
  `objdump -dr` on `.o` files; mainnet check is the P0-23 replay or a
  reindex, not just a start; Qt includes out of part A; Phase 5 rows,
  coverage table, plan task list and intro range added; P0-59 explicitly
  not an exit criterion, P0-04 interaction recorded; `GetDefaultPort`
  callers in `net.cpp` named; `getinfo` "testnet" source named.
- 2026-10-02 – Step 6: wrote `plans/dead-code.md` and
  `todo/P0-59-dead-code-removal.md`; corrected `plans/overview.md`; updated
  `plans/phase0-test-safety-net.md` (task range, 0.1 rows, 0.2a, 0.2e,
  0.2i), `plans/phase0-review.md` (follow-up note), P0-04, P0-12, P0-21.
- 2026-10-02 – Step 7: `code-review` skill (medium) on the staged diff;
  about 100 file:line claims checked, 5 findings, all applied: `block.h`
  dead `else` is at `:200-203` (not `173-182`); P0-59 part C must also
  exempt functions changed by inlining `GetDefaultPort` (`net.cpp`
  callers), `AppInitParameterInteraction` and the `kernel.o`/`main.o`
  static initialisers from the object-code comparison; `kernel.cpp:68-71`
  (not `67-70`); `SHA256Transform` is `miner.cpp:93-106`; `rand()`/`srand`
  still have live users in `util.cpp:762,809`. The fixes were small
  corrections, so no second review round; the documentation review
  (step 10) covers the final text. `phase0-review.md` keeps its original
  `miner.cpp:93-105` (historical table). No static analysis: P0-58 is not
  done.
- 2026-10-02 – Step 8: tests with `contrib/testing/build.sh --jobs 2`
  (pinned P0-57 image, GCC 11.5, `-O2 -g`). They ran on 95235c59-dirty:
  `src/` is identical to 651e82e, and the uncommitted changes were all under
  `project/`. Results:

  | Configuration | Unit | Functional |
  |---|---|---|
  | mainnet | 239/239 (exit 0) | – |
  | lowdiff | 238/239; only `pow_tests/get_next_work_pow_limit` failed (known, P0-02), so the script exits 1 as expected | 45/45 (`ALL … Passed`, 228 s) |

  Build-output checks (mainnet build dir):
  - `nm` on `libyacoin_server_a-scrypt-x86_64.o` and `-x86.o` prints "no
    symbols".
  - `nm -C yacoind` shows `scrypt_core(unsigned int*, unsigned int*)` with
    C++ linkage, which is the `scrypt-generic.cpp` version, so `USE_ASM` is
    not defined.
  - `nm -C yacoind` also lists `scrypt_blockhash`,
    `scrypt_salted_multiround_hash`, `scanhash_scrypt`, `PBKDF2_SHA256`,
    `CRandomNonce::get_a_nonce`, `Big`, `ComputeMinWork` and
    `ComputeMinStake`, so the dead code is linked.
  - The scrypt-jane object is `src/scrypt-jane/libyacoin_server_a-scrypt-jane.o`;
    P0-59 was corrected to use that path.
- 2026-10-02 – Step 9: documentation is the deliverable, see step 6. The
  "Checked on the build" section in `dead-code.md` now has the real output.
  No `doc/`, RPC help or `CLAUDE.md` change is needed.
- 2026-10-02 – Step 10: a reviewer subagent checked the documentation. It
  spot-checked about 70 file:line claims, all accurate, and found all links
  resolve. It reported 8 findings, applied as follows:
  - The task file's Risks section still had `RAND_egd` in part A: fixed.
  - The plan's edited-functions list was stale: note added pointing to
    P0-59.
  - "Refuse" was too strong for three `-rpcssl*` options: reworded.
  - New d) items: unused `init.cpp:73` and the `yacoind` testnet help text
    (both in part A), plus the `-testnetnewlogicblocknumber` help spelling.
    The spelling issue is a help/option bug on Linux and on Windows
    (case-sensitive lookup, lowercased argv on WIN32,
    `util.cpp:415-419`); found by reading the code and not run.
  - `miner.cpp` range noted.
  - P0-59 part B now says to re-check the other `scrypt.cpp` includes.

  Not applied:
  - The extra "## Checks" section in P0-59 stays. It is clearer than
    folding the checks into Acceptance criteria, and `project/README.md`
    lists the sections only as a minimum.
  - Cosmetic wording in the overview's CBigNum and wallet-test rows: the
    prose already explains it.
- 2026-10-02 – Step 11: moved to `done/`; committed (5708a4da), pushed,
  PR https://github.com/dev34253/yacoin/pull/54.
- Open points for the owner:
  - When to do P0-59. Part A could start now. Parts B and C wait for their
    gates. P0-59 is not a Phase 0 exit criterion and is not in P0-45's
    dependencies.
  - P0-12 should confirm the preliminary unused-`CBigNum` list.
  - Latent bugs found while reading the code, recorded rather than fixed
    (Phase 0 rule 1), all in `dead-code.md` d):
    - the `-testnetnewlogicblocknumber` help spelling and its Windows
      behaviour;
    - Qt `paymentserver.cpp` selecting the nonexistent testnet params.
