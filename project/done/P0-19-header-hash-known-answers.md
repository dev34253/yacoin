# P0-19: Block-header hash known-answer tests (scrypt-jane)

- Plan section: 0.2e
- Depends on: P0-01
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Pin the real proof-of-work hash path.

## Steps

1. CBlockHeader::GetHash() known answers for v<7 headers at every N-factor step in the primitives/block.h table (4…25), using timestamps at each step boundary.
2. v≥7 headers at nFactorAtHardfork 21 (mainnet), 4 (functional tests), 0 (unit tests).
3. Real mainnet headers from the fixture (after P0-09, via P0-23).
4. static_assert on packed header sizes (84 and 80 bytes; only the 84-byte v7 layout is `#pragma pack`ed).

## Acceptance criteria

- [x] All known answers pass in both build configurations.
- [x] Vectors stored hex in/out so P0-53 can run them on Windows/macOS.

## Notes

Replaces the original scrypt.cpp task: most of scrypt.cpp is dead code (P0-50). Review: A2, B4.

## Detailed description

### Findings from reading the task (step 1)

Line references checked against master 520b6ef.

- The PoW hash is `CBlockHeader::GetHash()` → `CalculateHash()`
  (`primitives/block.h:126-219`, cache in `GetHash` 235-248). It hashes the
  **raw memory** of a struct, not the serialisation: v≥7 uses the
  `#pragma pack(1)` `block_header` (block.h:22-33, 84 bytes, 64-bit
  `timestamp`), v<7 the unpacked `old_block_header` (block.h:35-44, 80
  bytes without padding because every field is 4-byte aligned). On a
  little-endian target both equal the serialised header (`SerializationOp`,
  block.h:92-116) – this is what P0-53 has to check on other targets (B4).
- `scrypt_hash(input, len, res, Nfactor)` (`scrypt.cpp:108-140`) calls
  scrypt-jane `scrypt(input, len, input, len, Nfactor, 0, 0, res, 32)`:
  password = salt = header bytes, **N = 2^(Nf+1)**, r = 2^0 = 1,
  p = 2^0 = 1, 32 bytes out (`scrypt-jane.c:196-198`). Hash and mix are
  fixed by `-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA -DSCRYPT_CHOOSE_COMPILETIME`
  (`Makefile.am:190-191`): HMAC/PBKDF2 over **Keccak-512 with the original
  Keccak padding 0x01** (not SHA3-512, `scrypt-jane-hash_keccak.h`, rate 72),
  BlockMix with **ChaCha20/8** (`scrypt-jane-chacha.h`). So Python's
  `hashlib.scrypt` (SHA-256/Salsa20/8) is **not** an oracle; an independent
  model has to implement Keccak-512 + ChaCha20/8 scrypt-jane. Memory is
  N·128 bytes: Nf 21 = 512 MiB, Nf 25 = 8 GiB.
- N-factor table (block.h:148-198) ✓ 4…25: `nTime < 1368515488` → 4, each
  next bound +1, `nTime < 3515474848` → 25, otherwise
  `MAXIMUM_N_FACTOR` = 25 (block.h:53). The `nSpanOf25` comment says
  "(Nf) 26", but the cap gives 25 – both sides of 3515474848 hash with 25.
  `fTestNet` (always false, B11) would select 4; not tested (dead).
- v≥7 uses the global `nFactorAtHardfork` (util.cpp:577, zero-initialised;
  `init.cpp:860` default 21; functional framework writes 4,
  `test_framework/util.py:353`; harness constants in
  `consensus_harness.h`) ✓. The timestamp table is ignored for v≥7.
- `GetNfactor(t, false)` (`main.cpp:100-129`, display only per A2) uses a
  bit-count formula; computed independently in Python it gives exactly the
  table's N-factor on both sides of every bound – an independent
  derivation of the table constants. `GetNfactor(t, true)` returns
  `nFactorAtHardfork`.
- `GetHash()` caches on the header fields only: after a change of
  `nFactorAtHardfork` it returns the stale hash while `CalculateHash()`
  returns the new one; its `blockHeight` argument is unused. Pinned, not
  fixed (rule 1).
- If scrypt-jane fails to allocate, `CalculateHash` returns 0 (block.h:143,
  215); with Linux overcommit `scrypt_alloc` usually succeeds or the
  process is killed; not testable reliably – not tested.
- Step 3 needs the P0-09 mainnet dump (node still syncing): left for P0-23
  as P0-46 did. The genesis headers are real headers and are included.
- Measured (x86-64, -O3): Nf 18 0.27 s, Nf 21 2.1 s, Nf 25 ≈ 34 s / 8 GiB
  per hash; pure Python ≈ 0.8 s at Nf 12, doubling per step (≈ 7 min at
  Nf 21, ≈ 2 h at Nf 25).

### Scope

Test-only (rule 1): no change in `src/` outside `src/test/`.

- `contrib/testing/header_hash_vectors.py`: independent model
  (Keccak-f[1600] from FIPS 202, Keccak-512 pad 0x01, HMAC, PBKDF2,
  ChaCha20/8 BlockMix, ROMix as in the scrypt paper), self-tests, the case
  list and `--write`/`--check` of the vector file.
- `contrib/testing/scrypt_jane_refhash.c`: tiny driver for the **upstream**
  scrypt-jane (floodyberry, commit 0ab6125), used as second reference for
  N-factors too slow for Python.
- `src/test/data/header_hash_vectors.json` (hex in/out), embedded like
  `reward_vectors.json`.
- `src/test/header_hash_tests.cpp` (suite `header_hash_tests`).
- Docs: `src/test/README.md`, `src/test/data/README.md`,
  `contrib/testing/README.md`, test counts in `CLAUDE.md` and the skill,
  task file; open question Q13 if needed.
- Not done: real mainnet headers (P0-23), big-endian/other targets (P0-53),
  the dead scrypt functions (P0-50), changing any behaviour.

### Behaviour (cases)

Header fields fixed and non-trivial (prev/merkle from SHA-256 of a label,
bits 0x1e0fffff, nonce 0x9e3779b9) so a swapped or truncated field changes
the hash.

1. **v6 table boundaries:** for each of the 22 bounds B (1368515488 …
   3515474848): `nTime = B-1` and `nTime = B`, expected N-factor from the
   table (4→5 … 24→25, 25→25 at the cap). Plus `nTime = 0` (4).
2. **Versions** at Nf 4: v1, v3, v6 and `nVersion = -1` (negative is < 7)
   with the same fields – different hashes, same table path.
3. **Real headers:** mainnet genesis (hash 0000060f…) and low-difficulty
   genesis (1ddf335e…) – their hashes are consensus constants from
   `chainparams.cpp`, so they are known answers not produced by this code.
4. **v7:** `nFactorAtHardfork` 0, 4 and 21 on one header; at 0 and 4 also a
   64-bit `nTime` (0x1_2345_6789, all 8 bytes hashed), a `nTime` in the
   Nf-4 era (table ignored) and `nVersion = 0x7fffffff`.
5. Each vector stores `header_hex` (the 80/84 hashed bytes), the
   N-factor, `GetNfactor(t,false)` for v<7, and `hash` (`GetHex()`
   order). The C++ test builds the header from the fields and checks:
   serialisation == `header_hex`; the raw struct bytes `CalculateHash`
   hashes == `header_hex`; `scrypt_hash(header_hex, nfactor)` == hash
   (pins which N-factor is used); `CalculateHash()` and `GetHash()` == hash;
   `GetNfactor` value.
6. **Layout:** `static_assert` sizeof 84/80 and field offsets in the test
   file (block.h is not touched).
7. **Cache quirk:** `GetHash()` stale after `nFactorAtHardfork` changes;
   `GetHash(h)` ignores `h`.

### Edge cases

- Runtime/memory: vectors with N-factor above
  `YACOIN_HEADER_HASH_MAX_NFACTOR` (default **21**, the highest N-factor
  real mainnet blocks used) are skipped with a test message; `=25` runs all
  (≈ 8 GiB RAM, ≈ 3 min). Default run ≈ 10 s at -O2 (Nf 18-21 dominate);
  more under the -O0 coverage build.
- Unit-test globals (Nf 0) and both build configurations: vectors do not
  depend on chain params (genesis hashes are data); v7 cases set
  `nFactorAtHardfork` with `ScopedConsensusGlobals`, restored afterwards.
- 32-bit `nTime` truncation for v<7: only values < 2^32 are used (the
  serialisation also truncates).
- Python 3.11/3.12 with standard library only; `hashlib.sha3_512` is used
  only to self-test the Keccak permutation.

### How to test

| Criterion | Test / command | Expected |
|---|---|---|
| Known answers, both builds | `test_bitcoin --run_test=header_hash_tests` via `build.sh --config mainnet --unit` and `--config lowdiff --unit --functional` | all pass, exit 0; total 341 + new cases |
| All N-factors | `YACOIN_HEADER_HASH_MAX_NFACTOR=25 test_bitcoin --run_test=header_hash_tests` (once, logged) | pass |
| Independence | `header_hash_vectors.py --check --max-nfactor 21` (Python) and `--reference refhash` for 22-25 | exit 0 |
| Hex in/out | JSON file with `header_hex`/`hash` | readable without node code |

### Risks

None for consensus (test-only). Risk of a slow or memory-hungry default
unit run – bounded by the default cap of 21 and documented.

## Implementation plan

1. `contrib/testing/header_hash_vectors.py`: model functions, self-tests
   (Keccak permutation vs `hashlib.sha3_512`, Keccak-512("") prefix
   0eab42de…, upstream POST vector `scrypt("", "", Nf 3, r 0, p 0)` for
   Keccak-512/ChaCha, both genesis hashes), the case list, `--write`,
   `--check`, `--max-nfactor`, `--jobs`, `--reference BIN`. Verify:
   self-tests pass; the Python hash equals the upstream C driver on every
   case with Nf ≤ 21.
2. `contrib/testing/scrypt_jane_refhash.c` + build instructions in its
   header comment. Verify: builds with plain `gcc` against upstream
   0ab6125, matches Python.
3. Generate `src/test/data/header_hash_vectors.json`: Python for
   Nf ≤ 21, reference for 22-25 (each vector records `"source"`).
4. `src/test/header_hash_tests.cpp`: JSON loader (format/version check),
   per-vector checks of the description item 5, layout `static_assert`s,
   `GetNfactor` checks, cache quirk; env var
   `YACOIN_HEADER_HASH_MAX_NFACTOR` (default 21; invalid → error). Add the
   JSON to `JSON_TEST_FILES` and the .cpp to `BITCOIN_TESTS` in
   `src/Makefile.test.include`. Logging: test messages only (rule 5 needs
   no daemon logging; `scrypt_hash` already logs each call).
5. Build and run both configurations; run once with the env var at 25;
   time the suite.
6. Docs: `src/test/README.md` section "Block-header hash (P0-19)" (format,
   regeneration, env var, runtime), `src/test/data/README.md`,
   `contrib/testing/README.md` section + files table, test counts in
   `CLAUDE.md`, `contrib/testing/README.md` and the skill; task file.
7. Code review, doc review (self-review passes), commit, push, PR, CI.

## Log

- 2026-10-03 step 0: moved to inprogress (19dbb24).
- 2026-10-03 step 1: claims checked (findings above). Independent model
  built in Python and checked against hashlib SHA3-512 (permutation),
  upstream scrypt-jane POST vector and both genesis hashes.
- 2026-10-03 step 3, self-review (no Agent tool) of the description:
  added invalid env-var handling; noted that Nf 22-25 rely on the upstream
  C reference unless the slow Python run is done; dropped an extra
  `nTime = 0xFFFFFFFF` case (same branch as `nTime = 3515474848`).
- 2026-10-03 step 5, self-review (no Agent tool) of the plan: order is
  model → reference → data → test so expected values never come from the
  code under test; no step touches `src/` outside `src/test/`; each step
  has a check. No changes.
- 2026-10-03 step 6: implemented as planned. `header_hash_vectors.py`
  (model + self-tests + 59 cases), `scrypt_jane_refhash.c` (upstream
  scrypt-jane 0ab6125), `src/test/data/header_hash_vectors.json`,
  `header_hash_tests.cpp` (3 cases: `known_answers`,
  `nfactor_table_coverage`, `gethash_cache_quirks`). Python model agrees
  with the upstream build on all 50 vectors with N-factor ≤ 21 (Python
  run: 15.5 min with 3 jobs); N-factor 22-25 (9 vectors) come from the
  upstream build. `--check --reference refhash`: 59/59 agree (4 min).
  Plan change: the first run hashed every vector three times
  (`scrypt_hash`, `CalculateHash`, `GetHash`; 38 s under load); now
  `GetHash()` once per vector, the direct `CalculateHash`/`scrypt_hash`
  checks only up to N-factor 12 → 9.5 s. Also `run()` hashes
  N-factor ≥ 22 one at a time (three parallel N-factor-25 runs were
  OOM-killed on 15 GiB).
- 2026-10-03 step 7, code review, self-review (no Agent tool) of the
  staged diff: removed an unused include, fixed a timing comment, made the
  checker executable. No consensus/production code touched (only
  `src/test/`, `src/Makefile.test.include`, `contrib/testing/`, docs).
  Not applied: the per-vector direct `scrypt_hash` check above N-factor 12
  (runtime; `GetHash` equality with a hash computed at the vector's
  N-factor already pins the N-factor).
- 2026-10-03 step 8, tests (build.sh, `--jobs 3`): mainnet 344/344 unit,
  exit 0 (suite 44 s, `header_hash_tests` 9.5 s); lowdiff 344/344 unit
  (`header_hash_tests` 10.2 s) and 46/46 functional, exit 0.
  `YACOIN_HEADER_HASH_MAX_NFACTOR=25`: 59 vectors hashed, 0 skipped, no
  errors, 206 s. Invalid value (`abc`) fails the case with a message.
- 2026-10-03: merged origin/master (known-issues.md, PR #69); the two
  findings (stale `GetHash()` cache after serialisation, `nSpanOf25`
  comment) went to `project/known-issues.md`, not open questions. Added the
  new checker to P0-61 step 6 (vector checkers in `build.sh --unit`).
- 2026-10-03 step 9/10: docs in `src/test/README.md`,
  `src/test/data/README.md`, `contrib/testing/README.md`, test counts in
  `CLAUDE.md`, `contrib/testing/README.md`, the skill. Doc review
  self-review (no Agent tool): checked every number and command against
  the runs above; fixed the P0-23 note (the checker compares the file with
  its case list, so P0-23 extends the list).
