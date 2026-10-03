# P0-10: CBigNum contract tests incl. edge semantics

- Plan section: 0.2a
- Depends on: P0-01
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Pin the CBigNum API behaviour used by the code (temporary tests, retired in Phase 4).

## Steps

1. Constructors for each integer width at 0, 1, -1, min, max; from uint256/uint160.
2. setuint64/getuint64, setint64, setuint256/getuint256 round-trips; getuint256/getuint64 return magnitude mod 2^n for large and negative values.
3. SetHex (0x prefix, whitespace, odd length, invalid characters), ToString(base), GetHex, getvch/setvch, MPI format, Serialize/Unserialize.
4. + - * / % (non-negative BN_nnmod), shifts (>> of negative gives 0), ++/--, comparisons; division truncates toward zero; division by zero behaviour recorded.

## Acceptance criteria

- [x] src/test/bignum_tests.cpp passes (19 cases, mainnet and lowdiff builds).
- [x] bignum.h (used methods) ≥ 90% line coverage from unit tests (93.3 %, measured with a scratch gcov build of the suite, see Log).

## Notes

Review: B10, C9.

## Detailed description

### Findings from reading the task and the code (step 1)

Verified against `src/bignum.h` (862 lines, OpenSSL 1.0.1k from `depends`):

- B10's line references are correct: `getuint64` 268–288, `getuint256`
  396–409, the `>>=` "less than 2^shift gives 0" shortcut 728–733, `%` via
  `BN_nnmod` 831.
- Step 1 says "from uint256/uint160": there is a `CBigNum(uint256)`
  constructor (explicit) but **no `CBigNum(uint160)` constructor**; uint160 is
  only reachable through `setuint160`/`getuint160`. Tested that way.
- Step 3 "MPI format": the MPI form is internal (`BN_bn2mpi`/`BN_mpi2bn`);
  it is observable through `getvch`/`setvch` (MPI without the 4-byte length,
  byte-reversed, i.e. little-endian with the sign in the top bit of the last
  byte) and `Serialize` (compact-size length + `getvch`). Tested there.
- Behaviour found with a probe program (scratchpad only, same image and
  `depends` OpenSSL) that the tests must pin, bugs included:
  - `>>` returns 0 for **every** negative value and every shift, including
    `-1 >> 0` (the shortcut compares `1 << shift` with the signed value).
  - `/` truncates toward zero (`-7/2 = -3`), `%` is always non-negative
    (`-7 % 2 = 1`, `7 % -2 = 1`, `-7 % -2 = 1`), so
    `(a/b)*b + a%b != a` for negative `a`.
  - `/` and `%` by zero throw `bignum_error`; `ToString(0)` throws too.
  - `getuint64`/`getuint256` return the magnitude mod 2^64 / 2^256
    (`-1 → 1`, `2^64+5 → 5`, `INT64_MIN → 2^63`, `2^256 → 0`).
  - `getuint32` is `BN_get_word` truncated: `2^32+5 → 5`, but any value
    ≥ 2^64 gives `0xffffffff` (`BN_get_word` returns all ones when the value
    does not fit a word). `getint32` saturates at `INT32_MAX`/`INT32_MIN`.
  - `setvch({0x80})` (and `{0x00,0x80}`) creates a **negative zero**: it
    prints as `0`, `!x` is true, `getvch()` is empty, but `x == 0` is false
    and `x < 0` is true (OpenSSL 1.0.1 `BN_cmp` compares the sign flag first).
    Arithmetic results (`x + 0`, `-x`, `x * 5`) are normal zeros again.
  - `SetHex` skips leading whitespace, accepts one `-` before the optional
    `0x`/`0X`, skips whitespace after it (so `"- 5"` and `"  -0x  1fF"` parse),
    stops at the first non-hex character (`"1 2" → 1`, `"g1" → 0`,
    `"0x-5" → 0`), and `"-0"` gives a normal (non-negative) zero.
  - `ToString(base)` prints the sign and digits without leading zeros
    (`GetHex(-255) = "-ff"`, `GetHex(0) = "0"`); bases 2–16 work; base 1
    never terminates and bases > 16 read past the digit table (both
    undefined, not tested, documented here).
  - `getuint64()` is not `const` (all other getters are).
- Used methods (callers outside `src/test` and `src/qt`, grep over `src/`):
  integer constructors (`int`, `int64_t`, `uint64_t` incl. implicit
  conversions such as `CBigNum x = MAX_MINT_PROOF_OF_WORK`), `CBigNum(uint256)`,
  copy/assign, `SetCompact`, `GetCompact`, `setuint256`, `getuint256`,
  `getuint64`, `ToString()`, `GetHex()`, `+ - * /`, `<<`, `> < <= ==`,
  `std::min` (via `<`). `operator>>`, `%`, `++/--`, `SetHex`, `getvch/setvch`,
  `Serialize`, `setuint160`, `getint32`, `setBytes/getBytes` and the math
  helpers (`pow`, `mul_mod`, `pow_mod`, `inverse`, `gcd`, `isPrime`,
  `generatePrime`, `randBignum`, `RandKBitBigum`, `bitSize`, `isOne`) have no
  caller today (preliminary; the binding audit is P0-12). Callers:
  `chain.cpp` (`GetBlockTrust`, `GetBlockProofEquivalentTime`), `pow.cpp`,
  `kernel.cpp` (`CheckStakeKernelHash`), `validation.cpp`
  (`GetProofOfWorkReward` bisection, chain trust), `chainparams.cpp`,
  `main.cpp`, `miner.cpp`, `rpc/blockchain.cpp`, `rpc/mining.cpp`.

### Scope

- **New:** `src/test/bignum_tests.cpp` (Boost suite `bignum_tests`,
  `BasicTestingSetup` fixture), registered in `src/Makefile.test.include`.
- **Changed:** this task file only (description, plan, log). No change to
  `src/bignum.h` or any non-test code (CLAUDE.md rule 1).
- **Not in scope:** exhaustive compact encoding (P0-11; only a smoke test
  here so `SetCompact`/`GetCompact` are not untested), the specific > 256-bit
  consensus expressions and the binding method audit (P0-12), golden vectors
  (P0-13), `generatePrime`/`randBignum`/`RandKBitBigum` (random, unused –
  P0-12 decides), Phase 4 replacement.
- Test-count lines in `CLAUDE.md`, `contrib/testing/README.md` and the skill
  are **not** edited here (PRs #51/#52 change the same lines); the new counts
  go into the Log and the PR, and the lines are updated after those merge.

### Behaviour (test cases)

All expected values are literal constants (decimal, hex or byte strings),
not computed with `CBigNum` itself, so a replacement can be checked against
the same table.

1. `constructors_integer_widths` – every constructor (`int8/16/32/64`,
   `uint8/16/32/64`) at 0, 1, -1 (signed), min and max; checked through
   `ToString()` and `getvch()`; e.g. `CBigNum(INT64_MIN)` →
   `"-9223372036854775808"`, `getvch = 00 00 00 00 00 00 00 80 80`.
2. `constructor_uint256_and_uint160` – `CBigNum(uint256)` for 0, 1,
   `~uint256(0) >> 20` (mainnet powLimit), top bit set
   (`8000…0001`), all ones; `setuint160`/`getuint160` round-trip including a
   top-bit-set value.
3. `set_get_roundtrips` – `setuint32`, `setuint64`, `setint64`,
   `setuint256` round-trips; each setter overwrites a previous negative value
   (sign cleared); `setint64` at 0, ±127, ±128, ±255, INT64_MIN/MAX.
4. `getters_magnitude_mod_2n` – `getuint64`, `getuint256`, `getuint32`,
   `getint32` for negative, ≥ 2^64, ≥ 2^256 and 300-bit values (results as
   listed in the findings).
5. `sethex_parsing` – the `SetHex` cases above plus odd length (`"abc"`),
   leading zeros, upper/lower case, empty string, `"0x"` alone, a
   non-ASCII byte stops parsing; previous value is replaced.
6. `tostring_and_gethex` – bases 2, 8, 10, 16, negative values, zero,
   2^256, `operator<<(ostream)`; `ToString(0)` throws `bignum_error`.
7. `vch_mpi_format` – `getvch`/`setvch` for 0, ±1, ±127, ±128, ±255, 2^63,
   2^64-1; `setvch` with redundant leading zero bytes, empty vector, and the
   negative-zero cases.
8. `bytes_big_endian` – `setBytes`/`getBytes` (big-endian magnitude, sign
   dropped, leading zero bytes dropped).
9. `serialize_roundtrip` – `CDataStream` bytes of `-300`
   (`02 2c 81`) and `0` (`00`), `GetSerializeSize`, unserialize back.
10. `add_sub_mul` – sign combinations, results crossing zero, values above
    2^256, unary minus (including of zero), compound `+=`, `-=`, `*=`.
11. `division_truncates_toward_zero` – all four sign combinations, exact
    division, `|a| < |b|`, large values (`-(2^256+1)/2`).
12. `modulo_non_negative` – all four sign combinations, the
    `(a/b)*b + a%b != a` consequence, `%=`.
13. `division_by_zero_throws` – `/`, `%`, `/=`, `%=` by 0 throw
    `bignum_error`; the left operand of the compound forms is unchanged.
14. `shifts` – `<<` / `<<=` (incl. negative values, shift 0, 300);
    `>>` / `>>=`: positive values like a real shift (`9>>3 = 1`,
    `8>>3 = 1`, `5>>3 = 0`, `x>>0 = x`, shift past the length gives 0),
    every negative value gives 0 (`-256>>1`, `-1>>0`, `-(2^300)>>1`).
15. `increment_decrement` – prefix/postfix `++`/`--` return values, crossing
    zero.
16. `comparisons` – all six operators on mixed signs and sizes, `!`,
    negative zero vs zero.
17. `copy_and_assign` – copy constructor, assignment, self-assignment, copy
    independence.
18. `compact_smoke` – `SetCompact`/`GetCompact` for a handful of real
    `nBits` values (mainnet powLimit, `0x1d00ffff`, zero); exhaustive cases
    are P0-11.
19. `unused_math_helpers` – one or two known answers each for `pow`,
    `mul_mod`, `pow_mod` (incl. negative exponent), `inverse` (and that a
    non-invertible value throws), `gcd`, `isPrime`, `isOne`, `bitSize`
    (preliminary: these are unused; P0-12 decides whether they stay).

### Edge cases

- Both build configurations: `bignum.h` has no `#ifdef` on the
  low-difficulty flag; the suite must pass in mainnet and lowdiff builds.
- Unit-test globals at 0: irrelevant here (no chain state is used);
  `BasicTestingSetup` is used only for consistency with other suites.
- 64-bit `BN_ULONG`: `setuint64` takes the `BN_set_word` branch; the
  MPI-building branch (lines 300–322) is dead on x86_64 and is excluded from
  the coverage denominator (documented, not forced).
- Undefined behaviour is not exercised: `ToString(1)` (endless loop),
  `ToString(>16)` (out-of-bounds read), `setBytes` with an empty vector
  (`&v[0]` on an empty vector). `SetHex` passes a plain `char` to
  `isxdigit`/`isspace`, which is undefined for negative values other than
  `EOF`; the non-ASCII case therefore uses byte `0xff` only (it becomes
  `-1 == EOF` on x86_64, where `char` is signed, and stops parsing).
- Found in code review: `getuint64`/`getuint160`/`getuint256`/`GetCompact`
  of a **negative zero** write one byte past their heap buffer
  (`BN_bn2mpi` reports 4 bytes for a zero but still sets the sign bit in
  `d[4]`), and `getBytes()` of zero / `setBytes()` of an empty vector take
  `&v[0]` of an empty vector. Undefined behaviour – not tested, documented in
  the test file. Negative zero only arises from `setvch`/`Unserialize`,
  which have no production caller.
- Overload resolution: the integer constructors are for the fixed-width
  types only, so e.g. `CBigNum(1LL)` (`long long`, not `int64_t` on
  x86_64 Linux) is ambiguous and does not compile. Tests use fixed-width
  types; this is noted for Phase 4 but not a test (it is a compile error).
- No test depends on locale, time, randomness or files.

### How to test

| Acceptance criterion | Test / command | Expected |
|---|---|---|
| `src/test/bignum_tests.cpp` passes | `test_bitcoin --run_test=bignum_tests` in both builds; full `contrib/testing/build.sh --config mainnet --unit` and `--config lowdiff --unit --functional` | all `bignum_tests` cases pass; mainnet 239 + N new, lowdiff only the known `pow_tests/get_next_work_pow_limit` failure, functional 45/45 |
| `bignum.h` (used methods) ≥ 90 % line coverage from unit tests | `gcov` on `bignum.h` from a scratch-only instrumented build of `bignum_tests.cpp` alone (stub fixture, same image and `depends`), see plan; full project coverage builds are not possible in this session (disk) and belong to P0-03/P0-04 | ≥ 90 % of the lines of the used methods (list above) executed; actual numbers in the Log |

Test levels: unit only. Functional tests are run because the skill requires
it (no node code changes, so no change is expected).

### Risks

- None for consensus: no production code changes. The only risk is a test
  pinning OpenSSL-version-specific behaviour (negative zero via `BN_cmp`,
  `BN_get_word` saturation); that is intended – it is exactly what Phase 4
  must notice – and each such check carries a comment saying so.
- Merge conflicts with #51/#52: avoided by not touching the count lines and
  by inserting the Makefile entry away from #52's hunk.

## Implementation plan

1. **Test file skeleton.** Create `src/test/bignum_tests.cpp`: MIT header,
   file comment (what it pins, that it is temporary per plan rule 3 / C9,
   pointers to P0-11/12/13), includes (`bignum.h`, `streams.h`,
   `utilstrencodings.h`, `version.h`, `test/test_bitcoin.h`, Boost.Test),
   `BOOST_FIXTURE_TEST_SUITE(bignum_tests, BasicTestingSetup)`. Small local
   helpers: `Vch("hex")` (bytes from hex via `ParseHex`), `HexOf(vch)`
   (`HexStr`). Expected values are written as decimal/hex string literals
   and compared with `ToString()`/`GetHex()`, never computed with `CBigNum`.
   *Verify:* compiles.
2. **Register** the file in `src/Makefile.test.include` (`BITCOIN_TESTS`,
   after `test/base64_tests.cpp`, keeping #52's hunk untouched).
3. **Cases 1–4** (constructors, uint256/uint160, setters, getters).
4. **Cases 5–9** (SetHex, ToString/GetHex, vch/MPI, bytes, serialization).
5. **Cases 10–17** (arithmetic, division, modulo, division by zero, shifts,
   ++/--, comparisons, copy/assign).
6. **Cases 18–19** (compact smoke, unused math helpers).
   Every check that pins a known oddity (negative `>>`, non-negative `%`,
   negative zero, `getuint32`/`getint32` saturation, magnitude mod 2^n)
   carries a one-line comment "pinned: …" so Phase 4 sees it is deliberate.
7. **Coverage measurement (scratch only, not committed).** In the build
   image: compile `bignum_tests.cpp` with `-O0 --coverage`, a stub
   `test/test_bitcoin.h` (`struct BasicTestingSetup {};`) placed first on
   the include path, `support/cleanse.cpp`, `utilstrencodings.cpp` (plus
   whatever else the linker asks for, scratch only) and the
   Boost.Test `unit_test_framework` library from `depends` plus a
   `BOOST_TEST_MODULE` main; run it, then `gcov` and count executed lines of
   `bignum.h` per method; compute the percentage over the used-method lines
   (list in the description, excluding the dead 32-bit branch of
   `setuint64`). Output stays in the scratchpad. *Verify:* ≥ 90 %, numbers
   into the Log.
8. **Code review** (`code-review` skill on the staged diff), fix findings.
9. **Full test runs:** `contrib/testing/build.sh --config mainnet --unit
   --jobs 2 --work-dir /root/.cache/yacoin-build-P0-10` and
   `--config lowdiff --unit --functional` (same options); additionally
   `--run_test=bignum_tests` output from both `unit.log`s.
10. **Documentation:** this task file (acceptance criteria, Log); the test
    file's header comment is the user documentation of the contract. No
    `doc/` or RPC change (no user-facing behaviour). `src/test/README.md` is
    not edited (#52 appends to it; nothing bignum-specific is needed there).
    Logging (CLAUDE.md rule 5): not applicable, no daemon code changes.
11. **Doc review**, finish task file, `git mv` to `done/`, commit, push, PR.

## Log

- 2026-10-03 step 0: picked up; dependency P0-01 is in done/; branch task/P0-10-cbignum-contract-tests.
- 2026-10-03 step 1–2: task verified against the code (findings in the description: no `CBigNum(uint160)` constructor, negative zero from `setvch`, `getuint32`/`getint32` saturation, `-1 >> 0 = 0`); behaviour confirmed with a scratch probe program in the build image. Detailed description written.
- 2026-10-03 step 3: description review – self-review (no Agent tool). Applied: compound `+=`/`-=`/`*=` added to case 10; `isxdigit` UB on negative `char` – non-ASCII case restricted to `0xff` (== `EOF`); `long long` constructor ambiguity noted. Not applied: none.
- 2026-10-03 step 4–5: implementation plan written; plan review – self-review (no Agent tool). Checked feasibility (Boost.Test static lib and `ParseHex`/`HexStr` available), ordering, consensus impact (none). Applied: expected values stated as literals, never computed with `CBigNum`; link list of the scratch coverage build left open. Not applied: none.
- 2026-10-03 step 6: `src/test/bignum_tests.cpp` (19 test cases, suite `bignum_tests`) added and registered in `src/Makefile.test.include` (after `base64_tests.cpp`, outside #52's hunk). No production code changed.
- 2026-10-03 step 7: code review with the `code-review` skill (medium) on the staged diff. Two findings, both applied: (1) `getuint64`/`getuint256` of a negative zero write one byte past their buffer (`BN_bn2mpi` sets the sign bit in `d[4]` of a 4-byte buffer) – those checks removed, UB documented in the test and the description; (2) `getBytes()` of zero takes `&v[0]` of an empty vector – check removed, documented. The rest of the expected values were confirmed by the reviewer. Second pass after the fixes (removals and comments only): self-review, no further findings.
- 2026-10-03 extra check: the suite built standalone (scratch, stub fixture) with `-fsanitize=address,undefined -D_GLIBCXX_ASSERTIONS` runs clean (OpenSSL itself is not instrumented). No compiler warnings from the test file with `-Wall -Wextra`.
- 2026-10-03 coverage: scratch-only gcov build of `bignum_tests.cpp` alone (same image and `depends`, stub `BasicTestingSetup`; no project coverage build – disk). `bignum.h`: 449/483 instantiated lines = 93.0 %; used methods (ranges listed in the description) 252/270 = **93.3 %**. Missed lines are all OpenSSL failure `throw`s (allocation failure, not reachable without fault injection) and the dead `nSize < 4` returns of `getuint64`/`getuint160`/`getuint256`. gcov does not count inline functions that are never called (`randBignum`, `RandKBitBigum`, `generatePrime`) and the `setuint64` MPI branch for 32-bit `BN_ULONG` is compiled out on x86_64. The project-wide figure belongs to P0-03/P0-04.
- 2026-10-03 step 8 tests (`contrib/testing/build.sh … --jobs 2`): mainnet `--unit` exit 0, **258/258** (239 + 19 new). lowdiff `--unit --functional` exit 1 as expected: unit **257/258**, the only failure is the known `pow_tests/get_next_work_pow_limit` (P0-02); functional **45/45**, `ALL … Passed`. `bignum_tests` 19/19 in both builds.
- 2026-10-03 step 9: documentation = this task file (findings, description, plan, Log, acceptance criteria) and the header comment of `src/test/bignum_tests.cpp`. No `doc/`, RPC help or runbook change (no user-facing behaviour). Not edited on purpose: the test-count lines in `CLAUDE.md`, `contrib/testing/README.md` and the implement-task skill (PRs #51/#52 change the same lines; update to +19 after they merge) and `src/test/README.md` (#52 appends to it).
- 2026-10-03 step 10: documentation review – self-review (no Agent tool), checked against the code and the test logs. Applied: test header said all inputs above 64 bits come from `SetHex` – corrected (a few use `CBigNum(uint256)` or `<<`). Verified: "mainnet powLimit" claim (`chainparams.cpp:78`, non-lowdiff branch), counts 258/257/45, coverage figures, case list matches the 19 cases. Not applied: none.
- 2026-10-03 step 11: moved to done/; PR https://github.com/dev34253/yacoin/pull/55
