# P0-13: Implementation-neutral golden vectors

- Plan section: 0.2a
- Depends on: P0-12
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Produce vectors from today's CBigNum that any replacement or oracle must reproduce.

## Steps

1. Generator (test-only) running ~100k random and adversarial operations limited to the methods/expressions found in P0-12, plus compact encoding.
2. Hex in / hex out JSON (compressed) under src/test/data/; fixed seed.
3. Replay test.

## Acceptance criteria

- [x] Vectors committed; replay test passes in < 30 s (`src/test/data/bignum_vectors.json.xz`, 100,000 vectors; replay about 0.3 s, see Log).
- [x] Format independent of CBigNum (usable by the oracle in P0-51/P0-26): signed-hex text format (`src/test/README.md`); `contrib/testing/bignum_vectors_check.py` reproduces all 100,000 vectors with Python integers, without `CBigNum` or OpenSSL.

## Notes

Review: C9.

## Detailed description

### Findings from reading the task and the code (step 1)

Checked against master `a108fdd`:

- The production `CBigNum` surface is the P0-12 "used" list
  (`project/plans/dead-code.md` c): integer constructors (`int32_t`,
  `int64_t`), `CBigNum(uint256)`/`setuint256`, `getuint256`, `getuint64`,
  `SetCompact`, `GetCompact`, `ToString`, `GetHex`, binary `+ - * /`,
  `*=`, `/=`, `<< unsigned`, `< <= > >=`. Re-checked at the call sites:
  `chain.cpp:77-114` (trust: `powLimit / target`, `*= 2`, `+ 1`,
  `(CBigNum(1) << 256) / (target + 1)`), `kernel.cpp:451-461,526`
  (`CBigNum(nValueIn) * weight / COIN / 86400`, `hash > weight * target`),
  `pow.cpp:78-103,189-202,215-222,255-263` (`SetCompact(..).getuint256()`,
  `setuint256`, `*=`/`/=` by `int64_t`, compare with `powLimit`,
  `GetCompact`), `validation.cpp:935-977` (reward bisection: `(lower +
  upper) / 2`, `mid^6 * limit > limit^6 * target`, `getuint64`).
- Values outside 256 bits and signs: products up to ~432 bits (P0-12),
  negative values from `SetCompact` with the sign bit and from negative
  `int64_t` factors (`pow.cpp:197` multiplies by an expression of
  `nActualSpacing`, which can be negative), and the negative zero from
  `SetCompact` (P0-11).
- Undefined behaviour that must stay out of any vector (P0-10/P0-11):
  `GetCompact`, `getuint256` and `getuint64` of a negative zero (one-byte
  heap overflow in `BN_bn2mpi`). OpenSSL 1.0.1k source (`depends`) read
  for the semantics the vectors will contain: `BN_mpi2bn`
  (`bn_mpi.c:91-127`) keeps the sign of a zero magnitude; `BN_cmp`
  (`bn_lib.c:668`) compares the sign flag first, so `-0 < 0` and `-0 > -1`;
  `BN_mul` returns an ordinary 0 when an operand is zero (`bn_mul.c:967`);
  `BN_lshift` keeps the sign (`bn_shift.c:144`); `BN_div` fails on a zero
  divisor, so `operator/` throws `bignum_error`.
- Test data is embedded in `test_bitcoin` today: `src/Makefile.test.include`
  turns `test/data/*.json` into `*.json.h` (a `hexdump` byte array, about
  6 bytes of header per byte of data). `depends` has no zlib without Qt
  (`depends/packages/packages.mk:5`), so the test binary cannot decompress
  anything itself; `xz`, `gzip`, `sed` and `python3` are in the pinned build
  image (checked with `docker run`).
- Size: a Python estimate of 100k records with fully random 64–1100-bit
  operands gives 14 MB of JSON and 6 MB compressed (gzip -9) – too large.
  Operands shaped like the production values (compact-derived targets,
  `int64_t` amounts and times, powers of two, products of those) plus a
  bounded pool of operands that records reuse give about 12 MB of JSON and
  about 1.3 MB with `xz -9` (gzip -9: about 1.9 MB, its 32 KiB window
  cannot see repeated operands). Hence xz.
- The task's "Generator (test-only)" must use the real `CBigNum` (the
  vectors record today's behaviour), so it is C++ linked into `test_bitcoin`;
  "format independent of CBigNum" is shown by a reader that does not use
  `CBigNum` at all (a Python model, below).

### Scope

- **New:** `src/test/bignum_vectors_tests.cpp` (suite
  `bignum_vectors_tests`, `BasicTestingSetup`) with the generator and two
  test cases; `src/test/data/bignum_vectors.json.xz` (the vectors);
  `contrib/testing/bignum_vectors_check.py` (independent Python model that
  checks every vector without `CBigNum`); a make rule that turns
  `*.json.xz` into a header (`xz -dc` → C string literal); `configure.ac`
  looks for `xz` (required with tests, like `hexdump`).
- **Changed docs:** `src/test/README.md` (format, regeneration),
  `src/test/data/README.md`, `contrib/testing/README.md` (checker, counts),
  plan 0.2a (done note), CLAUDE.md and the skill (test counts), this task
  file.
- **Not changed:** `bignum.h`, any production code (CLAUDE.md rule 1).
  No oracle (P0-51/P0-26), no property tests (P0-27), no function-level
  consensus tests (P0-14 … P0-18, P0-46). Unused `CBigNum` methods (`%`,
  `>>`, `==`, `SetHex`, …) get no vectors – they have no production caller
  and are deleted in Phase 4.

### Behaviour

**File format** (`bignum_vectors.json`, compressed as `.json.xz`): one JSON
object, written with one vector per line so diffs stay readable:

```
{"format":"yacoin-bignum-vectors","version":"1",
 "generator":"src/test/bignum_vectors_tests.cpp","seed":"<hex>",
 "count":"<n>",
 "vectors":[
["add","1d00ffff","-5","1d00fffa"],
...
]}
```

Every field is a JSON string. Encodings:

- **V (value):** `0`, or an optional `-` followed by lowercase hex digits
  without leading zeros. `-0` is the negative zero (sign flag set on a zero
  magnitude); it appears only where listed below.
- **U (unsigned):** like V, never negative.
- **I (integer):** like V, the operand of an integer constructor; its range
  is that of the C type.

| op | inputs | output | `CBigNum` code replayed |
|---|---|---|---|
| `int32` | I (int32) | V | `CBigNum(int32_t)` |
| `int64` | I (int64) | V | `CBigNum(int64_t)` |
| `uint256` | U (< 2^256) | V | `CBigNum(uint256)` and `setuint256` |
| `get_uint256` | V (not `-0`) | U: \|v\| mod 2^256 | `getuint256()` |
| `get_uint64` | V (not `-0`) | U: \|v\| mod 2^64 | `getuint64()` |
| `set_compact` | U (32 bit) | V (may be `-0`) | `SetCompact` |
| `get_compact` | V (not `-0`) | U (32 bit) | `GetCompact` |
| `to_string` | V (may be `-0`) | decimal text as returned | `ToString()` |
| `get_hex` | V (may be `-0`) | text as returned | `GetHex()` |
| `add`, `sub` | V, V (not `-0`) | V | `a + b`, `a - b` |
| `mul` | V, V (either may be `-0`) | V | `a * b` and `a *= b` |
| `div` | V, V (not `-0`) | V, or `error` when `b` is 0 | `a / b` and `a /= b` (`bignum_error`) |
| `shl` | V (not `-0`), U (≤ 2048) | V | `a << n` |
| `cmp` | V, V (either may be `-0`) | `-1`, `0` or `1` | `<`, `<=`, `>`, `>=` all consistent with the result |

**Content** (about 100,000 vectors, fixed seed, deterministic):

1. Adversarial (35,498 vectors as built): 33 special magnitudes (1, 2,
   0x7f, 0x80, 0xff, 0x100, 0xffff, 0x7fffff, 0x800000, `CENT`, `COIN`,
   100 `COIN`, `MAX_MONEY`, 86400, 2^k − 1 and 2^k for k = 31, 32, 63, 64,
   256, 2^128, 2^255, the PoS hard limit, both `powLimit` values, the
   compacts `0x1d00ffff` and `0x1e0fffff`, 2^256 + 1, 2^264), giving 67
   values with both signs and 0, crossed with themselves for `add`, `sub`,
   `mul`, `div`, `cmp`, and shifted by 16 amounts up to 2048; `-0` against
   all 67 for `cmp` and `mul` (both orders); `uint256`, the getters and the
   text methods on each; integer-constructor limits; `set_compact` for
   every exponent 0–255 with mantissas 0, 1, 0x7f, 0x80, 0xff, 0x7fff,
   0x8000, 0xffff, 0x7fffff, 0x800000, 0x800001, 0xffffff; `get_compact` on
   ±2^k, ±(2^k − 1) for k up to 2056 (MPI length boundaries and the
   exponent wrap at 2^2039).
2. Production-shaped chains (34,091 vectors as built), each step a separate vector whose inputs are
   the previous step's recorded outputs: stake kernel (amount × weight /
   `COIN` / 86400, × target, compare with a hash, `getuint256`, also with
   negative weights), legacy PoS trust (`1 << 256`, target + 1, divide), PoW
   trust (`powLimit / target`, × 2), retarget (`SetCompact` → `getuint256`
   → `uint256` → × timespan / timespan, compare with `powLimit`,
   `GetCompact`), reward bisection (the 14-step loop with `mid^6 * limit`
   and `limit^6 * target` for a range of `nBits`, `getuint64`).
3. Random (the remaining 30,411): the rest, each op with production-shaped operands (`int64_t`
   amounts/times, compact-derived targets, 256-bit hashes, products of
   these, ±2^k ± 1) and a few fully random values up to 600 bits; operands
   are drawn from a bounded pool so the file compresses.

The generator uses its own PRNG (splitmix64, documented constant seed) and
only integer arithmetic, so the same build always produces the same bytes.

**Tests** (suite `bignum_vectors_tests`):

- `replay` – decompressed vectors embedded at build time; checks the header
  (format, version, count = number of vectors), then for every vector runs
  the `CBigNum` code in the table and compares; inputs are built and
  outputs formatted with raw OpenSSL calls (`BN_bin2bn`, `BN_mpi2bn` for
  `-0`, `BN_bn2bin`, `BN_is_negative`), not with the methods under test. A
  mismatch reports the vector index, op, inputs, expected and actual (the
  first 20 in full, then a count). Unknown ops or malformed fields fail.
- `generator_reproduces_vectors` – runs the generator and requires the text
  to equal the embedded file byte for byte (so the committed file is
  exactly what the committed generator and seed produce). With
  `YACOIN_BIGNUM_VECTORS_OUT=<path>` it also writes the text to `<path>`
  (regeneration; then `xz -9e` and rebuild).

**Independent check:** `contrib/testing/bignum_vectors_check.py <file>`
(Python 3 standard library, reads `.json` or `.json.xz`) models each op
with Python integers plus the documented OpenSSL quirks (sign-and-magnitude,
negative zero, MPI compact encoding with the exponent byte wrap,
truncating division) and reports every disagreement; expected: 0.

### Edge cases

- Negative zero: only via `set_compact` output and as `cmp`/`mul`/`to_string`/`get_hex` input;
  never fed to `GetCompact`/`getuint256`/`getuint64` (UB). Created in the
  replay with `BN_mpi2bn`, as `SetCompact` does.
- Division by zero: `error`; the OpenSSL error queue entry is cleared.
- Very large values: `set_compact` outputs up to 2^2039 (510 hex digits);
  `get_compact` inputs up to 2^2056; shifts ≤ 2048 (`BN_lshift` takes an
  `int`).
- `ToString` of a negative zero is `"0"`; `GetHex` likewise.
- Build configurations: `CBigNum` does not depend on chain parameters; the
  `powLimit` special values are literals (mainnet and low-difficulty), so
  the vectors and both tests are identical in both builds. Unit-test globals
  are irrelevant.
- C++11 string literal: the JSON contains no `\`, no `"` inside strings
  other than delimiters, no `??` (trigraphs with `-std=c++11`); the make
  rule escapes `\` and `"` anyway.
- Truncated or corrupt data: `xz -t` in the make rule; `count` in the header
  checked against the number of vectors.
- `uint256` inputs are built with `uint256S` (the `uint256` class, not
  `CBigNum`).
- Build system: the generated header is added to `GENERATED_TEST_FILES`
  (so it is built before the tests and removed by `make clean`) and the
  `.json.xz` to the test sources (so `make dist` ships it).
- Logging (CLAUDE.md rule 5): test-only change, nothing runs in the daemon;
  the tests report through Boost (`BOOST_TEST_MESSAGE` with counts and
  timing at `--log_level=message`).

### How to test

| Criterion | Test / command | Expected |
|---|---|---|
| Vectors committed, replay passes | `bignum_vectors_tests/replay`, both builds | pass |
| Replay < 30 s | `--log_level=test_suite` timing in `unit.log` (mainnet and lowdiff; also note a coverage `-O0` timing if one is run) | well below 30 s |
| Committed file = generator output | `bignum_vectors_tests/generator_reproduces_vectors` | pass |
| Format independent of `CBigNum` | `contrib/testing/bignum_vectors_check.py src/test/data/bignum_vectors.json.xz` | 0 mismatches over all vectors |
| No regressions | `build.sh --config mainnet --unit`, `build.sh --config lowdiff --unit --functional` | 316/316 unit both, 46/46 functional |
| Build cost | time and peak memory of compiling the generated header; `make` output | a few seconds, no warnings |

### Risks

- No production code changes; consensus risk none. The risk is a vector set
  that pins something other than production behaviour (e.g. a helper bug
  in the replay). Mitigated by the independent Python model: a value both
  `CBigNum` and Python agree on is right by two independent routes; any
  disagreement is investigated and documented as a quirk.
- Repository size: 0.97 MB compressed (12.9 MB of JSON) per version of the file;
  regenerate only when the format changes.
- Build: a new tool requirement (`xz`) for test builds.

## Implementation plan

1. **Build rule** – `configure.ac`: `AC_PATH_PROG(XZ, xz)` next to
   `HEXDUMP`, and "xz is required for tests" next to the hexdump error.
   `src/Makefile.test.include`: `JSON_XZ_TEST_FILES =
   test/data/bignum_vectors.json.xz`; add `$(JSON_XZ_TEST_FILES:.json.xz=.json.xz.h)`
   to `GENERATED_TEST_FILES` and the `.xz` to `test_test_bitcoin_SOURCES`;
   pattern rule `%.json.xz.h: %.json.xz` → `$(XZ) -t`, then
   `namespace json_tests{ static const char <name>[] = "<line>\n" ... ; }`
   via `$(XZ) -dc | $(SED)` (escape `\` and `"`). Verify: header compiles,
   compile time/memory measured.
2. **Test file skeleton** – `src/test/bignum_vectors_tests.cpp`, registered
   in `BITCOIN_TESTS`: value helpers on raw OpenSSL (`ParseValue` with `-0`
   via `BN_mpi2bn`, `FormatValue` via `BN_bn2bin`/`BN_is_negative`, integer
   and `uint256` parsing), the op executor `Execute(op, inputs) ->
   output` shared by generator and replay (so the generator records exactly
   what the replay checks), plus the compound/variant checks (`*=`, `/=`,
   `setuint256`, the four comparison operators) inside the executor.
3. **Generator** – splitmix64 PRNG; special-value list; sections 1–3 of the
   description; JSON writer (deterministic, one vector per line). Tune the
   mix to about 100,000 vectors and ~1–1.5 MB `xz -9e`.
4. **Bootstrap** – the make rule needs the `.xz` to exist: start with a
   valid file with no vectors (`"count":"0"`, empty `vectors`), build, run
   `test_bitcoin --run_test=bignum_vectors_tests/generator_reproduces_vectors`
   with `YACOIN_BIGNUM_VECTORS_OUT` (it writes the file and fails the
   comparison, as expected), compress with `xz -9e`, copy into
   `src/test/data/`, rebuild, run the suite. The test compares the
   decompressed text, so the compressed bytes need not be reproducible.
5. **Python checker** – `contrib/testing/bignum_vectors_check.py`: read
   `.json`/`.json.xz`, validate format, model every op, print per-op counts
   and mismatches, exit 1 on any mismatch or format error. Run it on the
   file; investigate any disagreement (fix the model only if the C++ side is
   the real behaviour; never edit vectors by hand).
6. **Tests** – mainnet `--unit`, lowdiff `--unit --functional`; record
   replay and generator timings; also run the replay in a coverage build if
   time allows (timing only).
7. **Docs** – `src/test/README.md` section (format table, ops, quirks,
   regeneration commands), `src/test/data/README.md` line,
   `contrib/testing/README.md` (checker, counts 316), CLAUDE.md and skill
   counts (316), plan 0.2a done note, P0-51/P0-26 pointers (format and
   checker), task Log.

Because generator and replay share `Execute`, a bug in it would be
recorded and replayed consistently; the Python model (step 5) is the
independent check that catches that.

Verification of each step: steps 1–3 by building `test_bitcoin` in the
mainnet work dir; step 4/5 by the checker and the two test cases; step 6 by
`build.sh`. Code review (skill step 7) after step 5 on the staged diff.

## Log

- 2026-10-03 step 0: task moved to inprogress (commit 4cef6b1), branch `task/P0-13-cbignum-golden-vectors`.
- 2026-10-03 step 1: task, plan 0.2a/0.4, C9, P0-51/P0-26, P0-10/11/12 results and the production call sites checked (see Findings). Size estimate with a Python prototype (scratch): fully random operands 6 MB compressed → production-shaped operands from a bounded pool, xz.
- 2026-10-03 step 2: detailed description written.
- 2026-10-03 step 3: self-review (no Agent tool) of the description. Applied: `uint256` inputs via `uint256S`; build-system details (`GENERATED_TEST_FILES`, dist); logging note (rule 5 – test only). Considered and kept: two test cases instead of a disabled generator case (a disabled Boost case would show up as "skipped" in the counts and is never exercised; the reproduce check also proves the committed file is the generator's output).
- 2026-10-03 step 4: implementation plan written.
- 2026-10-03 step 5: self-review (no Agent tool) of the plan. Applied: bootstrap with an empty but valid vector file instead of the unclear placeholder wording; note that a shared `Execute` bug would be self-consistent and is caught only by the independent model; `count` is a string like every other field. No consensus impact (test and build files only). Nothing left out.
- 2026-10-03 step 6: implemented `src/test/bignum_vectors_tests.cpp` (helpers on raw OpenSSL, shared `Execute()`, generator, `replay`, `generator_reproduces_vectors`), the `%.json.xz.h` make rule and the `xz` configure check, `contrib/testing/bignum_vectors_check.py`. Bootstrap as planned (empty vector file, generate, `xz -9e -T1`). Result: 100,000 vectors (35,498 adversarial, 34,091 chains, 30,411 random; add 11,345, cmp 13,035, div 14,445, get_compact 10,468, get_hex 1,347, get_uint256 3,440, get_uint64 2,668, int32 167, int64 4,259, mul 16,891, set_compact 8,590, shl 2,281, sub 8,844, to_string 383, uint256 1,837), 12.9 MB of JSON, **0.97 MB** xz. Generation 0.18 s. The Python model agreed with all 100,000 vectors on the first run (no quirk beyond those documented by P0-10/P0-11). Negative checks: two edited vectors in a scratch copy are reported by both the checker and the replay (and the generator check), malformed vectors (`[]`, `5`, `"1\n"`, unknown op) are reported by the checker. Build cost: the generated header is 14 MB, header + object + link of the incremental rebuild took 17 s (`-j3`); the object is 45 MB (debug info), `test_bitcoin` was already 274 MB. No compiler warnings from the new file (only the existing `util.h`/`timestamps.h` header warnings every test file shows).
- 2026-10-03 step 7: code review with the `code-review` skill (medium) on the staged diff. Findings: (1) README docs referenced but not yet written – done in step 9; (2) checker crashed with a traceback on an empty or non-list vector – fixed, reported as format error; (3) checker regex `$` accepted a trailing newline, looser than the C++ parser – fixed with `fullmatch`. The fixes are checker-only; re-checked by hand and with the malformed-vector run above. Also changed after the first build: the generator case used `BOOST_ERROR` only, so Boost warned "did not check any assertions" – now `BOOST_CHECK_MESSAGE`. Nothing left as is.
- 2026-10-03 step 8: `build.sh --config lowdiff --unit --functional`: exit 0, **316/316** unit, **46/46** functional. `build.sh --config mainnet --unit`: exit 0, **316/316** unit. `replay` 0.29 s (both builds), `generator_reproduces_vectors` 0.19 s; whole unit run 31–32 s as before. `bignum_vectors_check.py`: 100,000 vectors, 0 disagree, 0.5 s. Coverage (`-O0`) timing not measured (not needed for < 30 s: 0.3 s at `-O2` leaves two orders of magnitude).
- 2026-10-03 step 9: docs – `src/test/README.md` (section "CBigNum golden vectors": format, ops table, quirks, content, regeneration), `src/test/data/README.md`, `contrib/testing/README.md` (checker, counts 316), `doc/build-unix.md` (`xz` requirement), plan 0.2a done note, P0-51/P0-26 notes (pointer to format and checker), CLAUDE.md and skill counts (316), `project/open-questions.md` Q10, this file (description aligned with what was built: `-0` also allowed for `to_string`/`get_hex`, the actual special-value list and section sizes).
- 2026-10-03 step 10: documentation review – self-review (no Agent tool) against the code and the generated file. Every example re-checked in the file (`["div","-ff","2","-7f"]`, `["set_compact","1800000","-0"]`, `["cmp","-0","0","-1"]`, `["get_compact","8"+511 zeros,"1008000"]`, `["get_uint64","-10000000000000000","0"]`). Applied: the special-value list in the README said ±2^k for k including 2^128 (garbled) and listed compact forms of both `powLimit`s (only `0x1d00ffff` and `0x1e0fffff` are in the list) – rewritten; "`-0` against all of them" now says for `cmp` and `mul`; the regeneration commands say which paths are relative to the build dir. Nothing left out.
- 2026-10-03 step 11: commit 2ea5c4c pushed; PR https://github.com/dev34253/yacoin/pull/62.
