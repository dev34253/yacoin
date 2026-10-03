# P0-11: Compact (nBits) encoding tests

- Plan section: 0.2a
- Depends on: P0-10
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Pin SetCompact/GetCompact exactly.

## Steps

1. Every exponent 0–34, sign bit, mantissa overflow, 0x00800000, zero, values ≥ 2^256.
2. Port Bitcoin Core's arith_uint256 compact tests; list every difference from Yacoin's behaviour.

## Acceptance criteria

- [ ] All cases pass against current code.
- [ ] Differences from arith_uint256 listed in Log (Phase 4 special cases).

## Notes

- Expected values were generated with this independent Python 3 model of
  both implementations (not with `CBigNum`). It was cross-checked against a
  scratch probe of the real `bignum.h`/`arith_uint256.cpp` with OpenSSL
  1.0.1k from `depends` in the build image (exponents 0–36 × 15 mantissas
  plus large values: 555 compacts, 0 mismatches), and independently
  re-derived by the code reviewer.

```python
# Independent model of CBigNum::SetCompact/GetCompact (bignum.h, OpenSSL MPI
# format) and of arith_uint256::SetCompact/GetCompact; generates the P0-11
# expected values.
def cb_set(c):
    e = c >> 24
    if e == 0:
        return 0, False
    b = [(c >> 16) & 0xff, (c >> 8) & 0xff, c & 0xff][:e] + [0] * max(e - 3, 0)
    neg = bool(b[0] & 0x80)
    b[0] &= 0x7f
    return int.from_bytes(bytes(b), 'big'), neg   # neg may be set with value 0 (negative zero)

def cb_get(v, neg):
    assert not (neg and v == 0)                 # GetCompact of a negative zero is UB
    if v == 0:
        return 0
    b = list(v.to_bytes((v.bit_length() + 7) // 8, 'big'))
    if b[0] & 0x80:
        b = [0] + b
    if neg:
        b[0] |= 0x80
    n = len(b)
    c = (n << 24) & 0xffffffff
    for i in range(min(n, 3)):
        c |= b[i] << (16 - 8 * i)
    return c

def ar_set(c):
    e = c >> 24; w = c & 0x7fffff
    if e <= 3:
        w >>= 8 * (3 - e); v = w
    else:
        v = (w << (8 * (e - 3))) % (1 << 256) if 8 * (e - 3) < 256 else 0
    neg = w != 0 and bool(c & 0x800000)
    ovf = w != 0 and (e > 34 or (w > 0xff and e > 33) or (w > 0xffff and e > 32))
    return v, neg, ovf

def ar_get(v, neg):
    n = (v.bit_length() + 7) // 8
    c = v << 8 * (3 - n) if n <= 3 else v >> 8 * (n - 3)
    if c & 0x800000:
        c >>= 8; n += 1
    c |= n << 24
    if neg and (c & 0x7fffff):
        c |= 0x800000
    return c

def cb_hex(v, neg):
    return ('-' if neg and v else '') + format(v, 'x')

# case 1 table (setcompact_every_exponent)
import sys
M = [0x123456, 0x7fffff, 0x00ffff, 0x000080, 0x923456]
for e in range(0, 35):
    row = []
    for m in M:
        c = (e << 24) | m
        v, neg = cb_set(c)
        z = max(e - 3, 0) if v else 0
        digits = cb_hex(v >> (8 * z), neg)
        assert not (neg and v == 0)
        row.append('{0x%08x, "%s", %d, 0x%08x}' % (c, digits, z, cb_get(v, neg)))
    print('    ' + ', '.join(row[:3]) + ',\n    ' + ', '.join(row[3:]) + ',')

# case 6 sweep (differences_from_arith_uint256): relations and counts
M=[0x000000,0x000001,0x000080,0x0000ff,0x008000,0x00ffff,0x010000,0x123456,0x7fffff,0x800000,0x800001,0x8000ff,0x808000,0x923456,0xffffff]
cnt=dict(negzero=0,zero=0,negative=0,overflow=0,overflow_neg=0,agree=0)
for e in range(256):
  for m in M:
    c=(e<<24)|m; v,neg=cb_set(c); av,an,ao=ar_set(c)
    # relations
    if neg and v==0:
        assert e>=1 and (c&0x800000) and av==0 and not an
        cnt['negzero']+=1; continue
    assert neg==an, hex(c)
    assert v % (1<<256) == av
    assert ao == (v >= 1<<256), hex(c)
    assert cb_set(cb_get(v,neg))==(v,neg)
    if v==0: cnt['zero']+=1
    if neg: cnt['negative']+=1
    if ao:
        cnt['overflow']+=1
        if neg: cnt['overflow_neg']+=1
    else:
        assert cb_get(v,neg)==ar_get(av,an); cnt['agree']+=1
print(cnt, 256*len(M))
```

## Detailed description

### Verified against the code (step 1)

- `CBigNum::SetCompact`/`GetCompact` are `src/bignum.h:457-480`. They go
  through OpenSSL's MPI format (`BN_mpi2bn`/`BN_bn2mpi`, OpenSSL 1.0.1k from
  `depends`), i.e. the pre-0.10 Bitcoin implementation, not the shift-based
  `arith_uint256::SetCompact`/`GetCompact` (`src/arith_uint256.cpp:206-247`).
- Production callers (grep, matches the P0-12 audit): `SetCompact` in
  `pow.cpp:78,85,137,189,216,258`, `chain.cpp:78` (`GetBlockTrust`),
  `kernel.cpp:452`, `validation.cpp:938,940,3703`, `rpc/blockchain.cpp:358`,
  `rpc/mining.cpp:420,860`, `miner.cpp:642,801`, `qt/explorer.cpp:1304`;
  `GetCompact` in `pow.cpp:41,103,116,123,129,154,162,202,268`,
  `validation.cpp:940,3683`, `chainparams.cpp:126,275`, `rpc/mining.cpp:146`.
  `chain.cpp:178` (`GetBlockProof`) already uses
  `arith_uint256::SetCompact` with the negative/overflow flags.
- Task text: "every exponent 0–34, sign bit, mantissa overflow, 0x00800000,
  zero, values ≥ 2^256" – all apply. "Mantissa overflow" is read as the
  `0x00800000` normalisation in `GetCompact` (a top byte ≥ 0x80 needs an
  extra zero byte and exponent + 1) and as the bytes `SetCompact` drops for
  exponents 1–2.
- Bitcoin Core's compact tests are present in this tree:
  `src/test/arith_uint256_tests.cpp:412-538` (`bignum_SetCompact`).
- Finding (corrects P0-10): the P0-10 task file says a **negative zero**
  "only arises from `setvch`/`Unserialize`". `SetCompact` also creates one:
  any `nBits` with exponent ≥ 1, the sign bit `0x00800000` set and all bytes
  that are kept zero (e.g. `0x01800000`, `0x04800000`, `0x01800001`,
  `0x028000ff`) goes through the same `BN_mpi2bn` path. `nBits` comes from
  block headers, so this is reachable from the network. Every current
  production path is safe: `CheckProofOfWork` (`pow.cpp:219`) and
  `GetBlockTrust` (`chain.cpp:79`) test `bnTarget <= 0` first (true for a
  negative zero, so the block is rejected / gets zero trust, as an ordinary
  zero would); the stake kernel (`kernel.cpp:526,568`) only multiplies it,
  which gives an ordinary zero; the other callers use `nBits` of accepted
  blocks or chain parameters. `GetCompact`/`getuint256` of a negative zero
  remain undefined behaviour (one-byte heap overflow, P0-10) and are not
  called by the tests.

### Scope

- New unit-test file `src/test/bignum_compact_tests.cpp` (suite
  `bignum_compact_tests`, `BasicTestingSetup`), registered in
  `src/Makefile.test.include`. Six test cases (below). Expected values are
  literals generated with an independent Python model (script in the Notes
  section), never computed with `CBigNum`; the model was cross-checked
  against a scratch probe of the real code in the build image (555 compacts,
  0 mismatches).
- No production code change (`bignum.h`, `arith_uint256.*` and all callers
  unchanged; CLAUDE.md rule 1). No logging change (tests only).
- Documentation: this task file (Log with the list of differences from
  `arith_uint256` = Phase 4 special cases), a correction note in the P0-10
  task file and the P0-10 test comment, `project/plans/phase0-test-safety-net.md`
  0.2a pointer, test counts in `CLAUDE.md`, `contrib/testing/README.md` and
  the `implement-task` skill.
- Not in scope: golden vectors (P0-13), `GetNextTargetRequired` (P0-14/15),
  fixing the negative zero or the exponent wrap (Phase 4).

### Behaviour pinned (test cases)

1. `setcompact_every_exponent` – every exponent 0–34 with the mantissas
   `0x123456`, `0x7fffff`, `0x00ffff`, `0x000080` and the negative
   `0x923456`: value (`GetHex`), and `GetCompact` of the result (canonical
   re-encoding, e.g. `0x04000080` → `0x03008000`, `0x0100ffff` → 0).
   Exponents 1–2 keep only the top 1–2 mantissa bytes (`0x01123456` = 0x12).
2. `setcompact_sign_and_zero` – exponent 0 is always an ordinary zero (also
   `0x00800000`, `0x00ffffff`); zero mantissa with every exponent 1–255 is
   an ordinary zero; sign bit with zero kept bytes for every exponent 1–255
   (and `0x01800001`, `0x018000ff`, `0x01808000`, `0x02800001`,
   `0x028000ff`) is a negative
   zero (sign flag, prints "0", `!bn`, `bn < 0`, `bn <= 0`, `bn != 0`), and
   multiplying it gives an ordinary zero; `0x03800001` is -1;
   `SetCompact` replaces a previous (negative) value and returns `*this`.
3. `setcompact_large_values` – values ≥ 2^256 are exact: `0x21010000`,
   `0x22000100`, `0x23000001` all = 2^256 (canonical `0x21010000`);
   `0x2100ffff` < 2^256; every exponent 35–255 with mantissa `0x010000`
   (= 2^(8(e-1))) and round trip; `0xff7fffff` (largest, 2039 bits);
   `0xff800001` negative; `getuint256()` of these is the magnitude mod 2^256
   (`0x21123456` → `3456` followed by 60 zero digits, 2^256 → 0); comparison
   with `~uint256(0)` (as in `CheckProofOfWork`).
4. `getcompact_encoding` – small values 0, 1, 0x7f, 0x80, 0xff, 0x100,
   0x7fff, 0x8000, 0x7fffff, 0x800000; truncation (not rounding)
   0x123456ff → `0x04123456`, 0x123456789 → `0x05012345`; negatives -1,
   -0x7f, -0x80, -0x12345600; 2^255, 2^256-1, 2^256, -2^256, 2^263, 2^264;
   the chain-parameter targets `~uint256(0) >> 20, >> 3, >> 8, >> 30`
   and `0x7fff…ff` (from literals, not from `Params()`); and the exponent
   wrap (bug, pinned): the MPI length is shifted into 8 bits, so
   |v| ≥ 2^2039 wraps: 2^2031 → `0xff008000`, 2^2032 → `0xff010000`,
   2^2039-1 → `0xff7fffff`, 2^2039 → `0x00008000`, 2^2040 → `0x00010000`
   (decodes to 0), -2^2040 → `0x00810000`, 2^2048 → `0x01010000`.
5. `arith_uint256_tests_ported` – every case of Core's `bignum_SetCompact`
   on `CBigNum` with the `CBigNum` result as literal; where `CBigNum`
   differs the comment says how.
6. `differences_from_arith_uint256` – sweep of every exponent 0–255 × 15
   mantissas (3840 compacts) comparing `CBigNum` with `arith_uint256` and
   checking the documented relations: negative zero exactly when exponent
   ≥ 1, sign bit set and `arith_uint256` reports no `fNegative` (it then
   gives 0); otherwise sign flag ==
   `fNegative`, `getuint256()` == arith value, `fOverflow` == (|v| ≥ 2^256),
   `GetCompact()` == arith `GetCompact(fNegative)` when not overflowing, and
   `SetCompact(GetCompact(v)) == v` (no wrap below 2^2039). Category counts
   are checked as literals so the sweep cannot silently skip a category.

### Edge cases

- Both build configurations: nothing here reads chain parameters, so the
  expected values are identical (chain-parameter targets are built from
  literals). Unit-test globals at 0 are irrelevant.
- Negative zero: never passed to `GetCompact`/`getuint256` (UB). The sweep
  skips those calls for that category.
- OpenSSL version: behaviour is that of 1.0.1k (`BN_mpi2bn` keeps the sign
  flag on a zero result). If a later OpenSSL upgrade normalises the sign of
  a zero, case 2 (and P0-10's `vch_mpi_format`) fail – intended: that is a
  behaviour change (`bn < 0` would become false) to be looked at.
- Exponents 1–2 with the sign bit and a non-zero dropped byte
  (`0x01800001`, `0x028000ff`): `CBigNum` gives a negative zero,
  `arith_uint256` an ordinary zero with `fNegative` false – listed as a
  difference.
- Large strings: `GetHex` of 2039-bit values (510 digits) is fine.

### How to test

- Acceptance "all cases pass against current code": `build.sh --config
  mainnet --unit` and `--config lowdiff --unit --functional` → 306/306 unit
  each (300 + 6), 45/45 functional, exit 0.
- Acceptance "differences listed": section "Differences from
  `arith_uint256`" (referenced from the Log), each item backed by checks in
  cases 2–6.
- Extra: scratch probe of the real code vs the Python model (done, 0
  mismatches); the new file built standalone with ASan/UBSan (scratch) to
  show no UB is exercised.

### Risks

- Tests only; no consensus code changes. Risk is limited to wrong expected
  values (mitigated by the independent model and the probe) and to touching
  UB (mitigated by never calling `GetCompact`/`getuint256` on a negative
  zero and the ASan run).

## Implementation plan

1. Python model + generator (scratch, copied into Notes): `cb_set`, `cb_get`,
   `ar_set`, `ar_get`; generate the case-1 table, the case-6 category
   counts and the remaining literals. Verify: model vs scratch probe of the
   real code (done: 555 compacts, 0 mismatches).
2. Create `src/test/bignum_compact_tests.cpp`: header comment (purpose,
   pin-not-fix, literals from the model, UB note, retirement in Phase 4 like
   `bignum_tests.cpp`), helpers `SignFlag`, `Hex`, `Pow2`, `Zeros`; cases
   1–6 as in the description. Verify: compiles without warnings in the
   build image.
3. Register the file in `src/Makefile.test.include` (alphabetical: before
   `bignum_consensus_tests.cpp`).
4. Scratch: build the file standalone with `-fsanitize=address,undefined`
   (stub `BasicTestingSetup`, depends Boost/OpenSSL) and run it – no
   sanitizer report, all checks pass.
5. Code review (step 7) of the staged diff; then the two `build.sh` runs
   (mainnet unit; lowdiff unit + functional under the lock). Expected
   306/306, 306/306, 45/45.
6. Docs: correct the P0-10 negative-zero statement (task file + the
   comment at `bignum_tests.cpp:404`), add a P0-11 pointer to plan 0.2a,
   update the test counts (CLAUDE.md, `contrib/testing/README.md`, skill),
   Log with the differences list. Docs review (step 10).
7. Move the task to `done/`, commit, push, PR, CI check.

No logging change: tests only, no daemon behaviour changes (rule 5 n/a).

## Differences from `arith_uint256` (Phase 4 special cases)

Each item is checked in `src/test/bignum_compact_tests.cpp` (case in
brackets). `arith_uint256` = `arith_uint256::SetCompact(c, &fNegative,
&fOverflow)` / `GetCompact(fNegative)` (`arith_uint256.cpp:206-247`).

1. **Signed result.** A compact with the sign bit and a non-zero kept
   mantissa gives a negative `CBigNum` (`0x04923456` = -0x12345600);
   `arith_uint256` gives the magnitude and `fNegative = true`. Callers test
   `bnTarget <= 0` (`pow.cpp:219`, `chain.cpp:79`) where Core tests
   `fNegative`. The sign flag equals `fNegative` for every compact that is
   not a negative zero. [cases 5, 6]
2. **Negative zero.** Exponent ≥ 1, sign bit set and all kept mantissa
   bytes zero (`0xNN800000` for every NN ≥ 1; for exponents 1–2 also with
   non-zero dropped bytes: `0x01800001`, `0x018000ff`, `0x01808000`,
   `0x02800001`, `0x028000ff`): `CBigNum` has the sign flag set on a zero –
   `< 0`, `<= 0` and `!= 0` are true, it prints "0"; `GetCompact`/`getuint256`
   on it are undefined behaviour (one-byte heap overflow). `arith_uint256`
   gives an ordinary 0 with `fNegative = false`. Both reject it in
   `CheckProofOfWork`/give zero trust; a replacement must keep "`<= 0` is
   true" and must not crash. Exponent 0 (`0x00800000`) is an ordinary zero in
   both. Reachable from the network (`nBits` in headers). [cases 2, 5, 6]
3. **No overflow – values ≥ 2^256 are exact.** `CBigNum` holds the full
   value up to `0xff7fffff` = 2^2039 − 2^2016; `arith_uint256` truncates mod
   2^256 (for exponents ≥ 35 to 0) and sets `fOverflow`. `fOverflow` is
   exactly |value| ≥ 2^256, and `getuint256()` of the `CBigNum` (magnitude
   mod 2^256) equals the `arith_uint256` value for every compact. So
   `CBigNum().SetCompact(n).getuint256()` (`pow.cpp:78,85,137`,
   `rpc/*.cpp`, `miner.cpp`) silently truncates where Core would flag
   overflow; `CheckProofOfWork` compares the full `CBigNum` with `powLimit`
   first and rejects it. [cases 3, 5, 6]
4. **`GetCompact` takes no sign argument.** `CBigNum::GetCompact()` uses the
   value's own sign; it equals `arith_uint256::GetCompact(fNegative)` for
   every value below 2^256 (694 compacts in the sweep). [cases 4, 5, 6]
5. **`GetCompact` of values ≥ 2^256** gives exponents 0x21–0xff
   (2^256 → `0x21010000`, -2^256 → `0x21810000`); `arith_uint256` cannot
   hold such values. [cases 3, 4]
6. **Exponent wrap (bug).** `GetCompact` shifts the MPI byte length into 8
   bits, so for |v| ≥ 2^2039 it wraps mod 256: 2^2039 → `0x00008000`,
   2^2040 → `0x00010000` (decodes to 0), -2^2040 → `0x00810000`,
   2^2048 and 2^4096 → `0x01010000` (decodes to 1). `arith_uint256` asserts
   `nSize < 256`, unreachable for 256-bit values. Not reachable from
   `SetCompact` output (max 2^2039 − 2^2016) and no production caller
   encodes such values, but a replacement must not be used on them blindly.
   [case 4]
7. **Same results elsewhere** (no special case needed): exponent 0 gives 0;
   exponents 1–2 drop the low mantissa bytes; `GetCompact` truncates (no
   rounding) and adds a zero byte when the top byte is ≥ 0x80 (`0x80` →
   `0x02008000`); all of Core's other `bignum_SetCompact` cases give the
   same value and compact. [cases 1, 4, 5, 6]

## Log

- 2026-10-03 step 0: moved to inprogress (ce14f16), branch `task/P0-11-compact-encoding-tests`.
- 2026-10-03 step 1: task verified against `bignum.h:457-480`, `arith_uint256.cpp:206-247`, `arith_uint256_tests.cpp:412-538` and all production callers. Finding: `SetCompact` creates a negative zero for sign-bit compacts with zero kept bytes (network-reachable via `nBits`); P0-10's statement that negative zero only arises from `setvch`/`Unserialize` is wrong. All current production paths are safe (see description). Scratch probe (real `bignum.h` + depends OpenSSL 1.0.1k in the build image) for exponents 0–36 × 15 mantissas plus large values.
- 2026-10-03 step 2: detailed description written; Python model cross-checked with the probe (555 compacts, 0 mismatches).
- 2026-10-03 step 3: self-review (no Agent tool) of the description against the code: cited lines re-checked (`pow.cpp:219`, `chain.cpp:79`, `kernel.cpp:526,568`); two changes applied: the OpenSSL-upgrade note no longer claims which version normalises a zero's sign (not verified), and the exponent-1/2 dropped-byte negative zero was added as an explicit edge case. Nothing left out.
- 2026-10-03 step 5: self-review (no Agent tool) of the plan: feasible, every step has a check, no consensus code touched, ordering fine (tests before docs, docs before the final commit). One fix: the Makefile position was wrong (`bignum_compact` sorts before `bignum_consensus`).
- 2026-10-03 step 6: implemented `src/test/bignum_compact_tests.cpp` (6 cases) and registered it in `src/Makefile.test.include`. Scratch standalone build of the file (stub fixture, depends Boost/OpenSSL, `-Wall -Wextra -fsanitize=address,undefined -D_GLIBCXX_ASSERTIONS`): no warnings from the file, no sanitizer report, all checks pass. First run found a wrong relation in my sweep (I had characterised a negative zero by `a == 0`, but overflowing negatives also truncate to 0 in arith_uint256); corrected to "sign bit set and no `fNegative`" – the code under test was right, the test's statement was wrong.
- 2026-10-03 step 7: `code-review` skill (medium) on the staged diff. The reviewer re-derived every literal with its own Python model (175 table rows, 20 GetCompact rows, all sweep counts) – all match. One finding (docs, low), applied: the file comment and description gave 2^2040 as the exactness/no-wrap bound; it is 2^2039 (largest SetCompact value 2^2039 - 2^2016, GetCompact wraps at 2^2039). Static analysis (rule 3): P0-58 not done, n/a.
- 2026-10-03 step 8 (mainnet): `build.sh --config mainnet --unit` exit 0, **306/306** test cases, 4239925 assertions passed.
