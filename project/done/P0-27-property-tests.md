# P0-27: Property-based tests for big-number and compact encoding

- Plan section: 0.4
- Depends on: P0-10
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Catch classes of arithmetic errors with identities on random inputs.

## Steps

1. (a*b)/b == a, (a<<n)>>n == a, a+b-b == a, compact round-trips, ordering consistency; inputs include >256-bit and negative values; fixed seed with a randomise option.

## Acceptance criteria

- [x] Tests pass in < 10 s (`bignum_property_tests`, 11 cases, 1000 samples each: 0.4 s in the lowdiff build, 0.3 s mainnet; 20,000 samples per case: 6.5 s).

## Notes

-

## Detailed description

### Findings from reading the task and the code (step 1)

Checked against master `0affd2e`:

- The task names the identities `(a*b)/b == a`, `(a<<n)>>n == a`,
  `a+b-b == a`, compact round trips and ordering consistency, on inputs
  that include values above 256 bits and negative values, with a fixed seed
  and an option to randomise. Plan 0.4 only says "algebraic identities on
  random inputs". The only acceptance criterion is "< 10 s".
- Production uses (`project/plans/dead-code.md` c, P0-12): integer
  constructors, `CBigNum(uint256)`/`setuint256`, `getuint256`, `getuint64`,
  `SetCompact`/`GetCompact`, `ToString`/`GetHex`, binary `+ - * /`, `*=`,
  `/=`, `<<`, `< <= > >=`. The properties focus on these; `>>`, `==`, `!=`,
  unary `-`, `%`, `+=`, `-=` (tests only) appear where an identity needs
  them or where the identity documents their pinned behaviour.
- Identities that do **not** hold for `CBigNum` (`bignum.h`, OpenSSL 1.0.1k
  in `depends`, sources read in `crypto/bn/`):
  - `(a<<n)>>n == a` holds only for `a >= 0`: `operator>>=`
    (`bignum.h:724-737`) returns an ordinary 0 whenever `2^n > a`, i.e. for
    **every** negative `a` and every `n` including 0 (pinned in P0-10
    `bignum_tests/shifts`).
  - Division truncates toward zero (`BN_div`), so `a/b` is not floor
    division; `(a*b)/b == a` still holds for all signs. `%` (`BN_nnmod`) is
    always in `[0, |b|)`, so `(a/b)*b + a%b != a` for negative `a` with a
    non-zero remainder (P0-10 `modulo_non_negative`).
  - Negative zero (sign flag set, magnitude 0) comes from `SetCompact` of a
    sign-bit compact with zero kept mantissa bytes (`0x01800000`, P0-11) and
    from `setvch("80")`. It compares `< 0` and `> -1` (`BN_cmp` checks the
    sign first). Reading OpenSSL: `BN_add`/`BN_sub` set the result sign from
    the operand signs, so `-0 - 0` and `-0 + -0` stay negative zeros while
    `-0 + 0`, `0 - -0`, `-0 - -0` are ordinary zeros; `BN_lshift` keeps the
    sign; `BN_mul` and the `BN_div` quotient give ordinary zeros;
    `BN_div` copies the negative zero into the remainder, so `BN_nnmod`
    adds `|b|` and **`-0 % b == |b|`** (outside `[0, |b|)`).
    `GetCompact`, `getuint256` and `getuint64` of a negative zero write one
    byte past their buffer (UB, open question Q2) and are never called.
  - `GetCompact` of a value whose MPI needs >= 256 bytes (`|v| >= 2^2039`)
    wraps the exponent byte (P0-11, pinned).
- Repo random conventions: `insecure_rand_ctx`/`SeedInsecureRand` in
  `test_bitcoin.h` is seeded from `GetRandHash()` at start-up (not
  deterministic); `FastRandomContext(const uint256&)` gives a deterministic
  stream. P0-13 uses an environment variable (`YACOIN_BIGNUM_VECTORS_OUT`)
  for an optional mode; the same pattern is used here.

### Scope

- New `src/test/bignum_property_tests.cpp` (Boost suite
  `bignum_property_tests`, `BasicTestingSetup`), added to
  `src/Makefile.test.include`.
- No change to `bignum.h`, consensus code or any other production file;
  no change to existing tests.
- Documentation: `src/test/README.md` (how to run, seed and iteration
  variables, how to reproduce a failure), test counts in `CLAUDE.md`,
  `contrib/testing/README.md`, the `implement-task` skill; task file.
- Not in scope: an independent oracle (P0-51/P0-26), fuzzing (P0-28),
  fixing any pinned bug.

### Behaviour

**Random source.** Each test case gets its own `FastRandomContext` seeded
with `SHA256(base seed || case name)`, so cases are independent of order
and of `--run_test` filtering. The base seed is a fixed constant by default
(the default run is deterministic). Environment variables:

- `YACOIN_PROPERTY_SEED`: `random` (fresh `GetRandHash()` seed) or 64 hex
  digits (replay a given seed). Anything else fails the case with a clear
  message.
- `YACOIN_PROPERTY_ITERATIONS`: positive integer, samples per case
  (default 1000). Invalid values fail with a message.

The seed actually used is printed with `BOOST_TEST_MESSAGE` and is part of
every failure message, together with the iteration and the operands (hex),
so any failure can be replayed with `YACOIN_PROPERTY_SEED=<seed>`.

**Value generator.** Random sign (about half negative) and a magnitude
class: zero; 1-64 bits; 65-256 bits; 257-520 bits; 521-1100 bits; a special
form `2^k`, `2^k - 1`, `2^k + 1` (k up to 520); a "runs" form (random runs of
0x00/0xff bytes, to hit carries and borrows). Values are built with
`SetHex` (pinned in P0-10). The generator never makes a negative zero
(`SetHex("-0")` gives an ordinary 0); negative zeros are made explicitly
with `SetCompact`.

**Test cases (one per property group):**

1. `add_sub_identities`: `a+b-b == a`, `a-b+b == a`, `a+b == b+a`,
   `(a+b)+c == a+(b+c)`, `a-b == -(b-a)`, `a-b == a+(-b)`, `a+0 == a`,
   `a-a == 0`, `+=`/`-=` agree with `+`/`-`.
2. `mul_div_identities`: `(a*b)/b == a` (b != 0, all signs), `a*b == b*a`,
   `(a*b)*c == a*(b*c)`, `a*(b+c) == a*b + a*c`, `a*1 == a`,
   `a*(-1) == -a`, `a*0 == 0`; `*=`/`/=` agree with `*`/`/`; multiplying
   and dividing by a random `int64_t` (as `pow.cpp` does) agrees with the
   `CBigNum` operand.
3. `division_truncates`: for `q = a/b`, `r = a - q*b`: `|r| < |b|`,
   `r == 0` or `sign(r) == sign(a)`, `(-a)/b == -(a/b) == a/(-b)`,
   `|a| < |b|` gives 0; `%` result in `[0, |b|)` and equals `r` or
   `r + |b|` (pinned: not `r` for negative `a`); division and `%` by zero
   throw `bignum_error` and `/=` leaves the operand unchanged.
4. `shift_identities` with `n` in 0..600 (biased to 0, 1, 7, 8, 63, 64,
   65, 255, 256, 257): `a<<n == a*2^n` (all signs; `2^n` from a table built
   by repeated `*2`, not with `<<`); for `a >= 0`: `(a<<n)>>n == a`,
   `a>>n == a/2^n`, `(a>>n)<<n == a - a%2^n`, `(a>>n)>>m == a>>(n+m)`;
   `(a<<n)<<m == a<<(n+m)`. Pinned for `a < 0`: `a>>n == 0` and
   `(a<<n)>>n == 0` for every `n`, result an ordinary zero.
5. `ordering_consistency`: exactly one of `<`, `==`, `>`; `<=`, `>=`, `!=`
   consistent with them; antisymmetry; `a < b` iff `a-b < 0` iff `b-a > 0`;
   transitivity on sorted triples; `a < b` implies `a+c < b+c` and
   `a*c < b*c` for `c > 0`, `a*c > b*c` for `c < 0`; `std::min`/`std::max`
   (as used in `pow.cpp`) return one of the operands with the right order.
6. `no_negative_zero_from_ordinary_inputs`: none of `+ - * / % << >>`,
   unary `-`, `SetCompact(GetCompact(x))` applied to generator values
   produces a negative zero (sign flag set with value 0). This is what makes
   the UB getters safe on the results of the other cases.
7. `compact_roundtrip_values`: for generator values with MPI size
   `n <= 255` bytes: `GetCompact(x)` has exponent `n` and the sign bit iff
   `x < 0`; `SetCompact(GetCompact(x))` equals `x` truncated toward zero to
   its top three MPI bytes (expected value computed with `/` and `*` by
   `256^(n-3)`, not with `GetCompact`), so it equals `x` for `n <= 3`;
   `GetCompact` is idempotent on the result; truncation is monotonic
   (`a <= b` implies `T(a) <= T(b)`). Pinned: for `n` in 256..300 the
   exponent byte is `n mod 256` and the mantissa is still the top three MPI
   bytes.
8. `compact_roundtrip_encodings`: for random 32-bit compacts (any exponent,
   biased to 0-4 and 0x18-0x21, and to the sign-bit mantissas): the decoded
   value equals `sign * mantissa' * 256^(e-3)` computed independently
   (mantissa' drops the bytes beyond the exponent for `e < 3`);
   `SetCompact(GetCompact(v)) == v` and `GetCompact(SetCompact(c2)) == c2`
   for `c2 = GetCompact(v)`. Compacts that decode to a negative zero are
   counted and pinned (sign flag, `!v`, `v < 0`, `v > -1`,
   `ToString() == "0"`); `GetCompact` is not called on them.
9. `uint_getters`: for `0 <= x < 2^256`: `CBigNum(x.getuint256()) == x`,
   `setuint256` round trip; for every generator value:
   `getuint256` is `|x| mod 2^256` and `getuint64` is `|x| mod 2^64`
   (P0-10 pinned semantics, now on random inputs including > 256 bits and
   negatives); `CBigNum(int64_t)`/`CBigNum(uint256)` agree with `SetHex`.
10. `arith_uint256_agreement`: for `0 <= a, b < 2^256` (the range Phase 4's
   `arith_uint256` covers): ordering, `+`, `-` (a >= b), `*` (mod 2^256),
   `/` (b != 0), `<<` (mod 2^256), `>>` and `GetCompact` agree with
   `arith_uint256`.
11. `negative_zero_operands`: `nz` from `SetCompact((e << 24) | 0x800000)`
   (random `e` in 1-255) against random ordinary `x`: values (compared via
   `ToString` and sign flag, never `GetCompact`) and sign flags of
   `nz+x`, `x+nz`, `nz-x`, `x-nz`, `nz*x`, `x*nz`, `nz/x`, `x/nz` (throws),
   `nz%x` (pinned `|x|`), `x%nz` (throws), `nz<<n`, `nz>>n`, `-nz`, and comparisons with `x`
   and with 0 — pinned as observed and explained from the OpenSSL source.

### Edge cases

- Zero divisors are excluded from identities that need `b != 0` but
  tested on their own (throw).
- Shift amounts 0 and multiples of the 64-bit word size; values that are
  exactly powers of two (`>>=` compares with `2^n`).
- MPI sign-padding boundary (`x` with the top bit of its top byte set) for
  compact sizes.
- Values above 2^256 and up to 1100 bits (products up to ~2200 bits; the
  compact cases stay below 2^2039 except the pinned wrap samples).
- Both build configurations: nothing here depends on chain parameters, so
  the expected results are the same for mainnet and lowdiff.
- Unit-test globals at 0: not used.
- Time: CBigNum operations on <= 2200-bit values are microseconds; budget
  is well under 10 s even for coverage builds (measured and logged).

### How to test

| Criterion | Test / command | Expected |
|---|---|---|
| Identities hold / pinned deviations hold | `test_bitcoin --run_test=bignum_property_tests` | 11 cases pass |
| Deterministic default | run twice, compare the printed seed and the value-class counts (`--log_level=message`) | identical |
| Randomise option works | `YACOIN_PROPERTY_SEED=random` and an explicit seed, `YACOIN_PROPERTY_ITERATIONS=20000` | pass; seed printed |
| Bad option values | `YACOIN_PROPERTY_SEED=xyz` | case fails with message |
| A failure is reproducible | temporarily break an identity locally (not committed), check the message names seed, iteration and operands | message complete |
| < 10 s | elapsed per case printed; total from `unit.log` timing | well under 10 s |
| Full suites | `build.sh --config mainnet --unit`, `flock ... build.sh --config lowdiff --unit --functional` | 327/327 unit both, 46/46 functional |

### Risks

- None for consensus: test-only file, no production change.
- Flakiness: excluded by the fixed default seed; with `random` a failure is
  a real finding and is reproducible from the printed seed.
- A pinned observation could be platform-dependent (OpenSSL version,
  32-bit `BN_ULONG`); the file comment states the platform, like P0-10.

## Implementation plan

1. **Skeleton and random source** – create `src/test/bignum_property_tests.cpp`
   with the file comment (purpose, pinned deviations, platform, how to
   replay), helpers `SignFlag`, `Hex`, `Compact`, `IsNegativeZero`, the
   option parsing (`PropertyOptions`: base seed from `YACOIN_PROPERTY_SEED`,
   iterations from `YACOIN_PROPERTY_ITERATIONS`, both validated) and a
   `PropertyRng` per case (`FastRandomContext` seeded with
   `CSHA256(base seed || case name)`), a `Describe()` helper that formats
   seed, case, iteration and operands for failure messages, and a timer that
   prints elapsed time and the class counts per case. Add the file to
   `src/Makefile.test.include`. Verify: builds, empty suite runs.
2. **Value generator** – `RandomValue(rng)` with the classes of the
   description (zero, 1-64, 65-256, 257-520, 521-1100 bits, `2^k` and
   `2^k +- 1`, byte runs), random sign, built from a random hex string
   with `SetHex`; `RandomNonZero`, `RandomShift`, `Pow2` table built with
   `*2` (up to 1200 bits), `Abs`. Counts per class recorded.
3. **Cases 1-5** (add/sub, mul/div, truncation and `%`, shifts, ordering) –
   identities as in the description; every check uses `BOOST_CHECK_MESSAGE`
   with `Describe()`. To keep the log readable, a failing case stops after
   the first 20 failures (`BOOST_REQUIRE` on a failure counter).
4. **Case 6** (no negative zero from ordinary inputs).
5. **Cases 7-8** (compact round trips from values and from encodings,
   including the pinned exponent wrap and the negative-zero encodings).
   Expected values computed with `/`, `*` and the power table, never with
   `GetCompact`/`SetCompact` of the same value.
6. **Cases 9-10** (`getuint256`/`getuint64`/`setuint256`/`CBigNum(int64_t)`
   and `arith_uint256` agreement).
7. **Case 11** (negative-zero operands): write the expectations from the
   OpenSSL reading; if a run disagrees, re-read the OpenSSL source, and pin
   what the code does with the explanation (Phase 0 rule) – never adjust
   without an explanation.
8. **Run** `test_bitcoin --run_test=bignum_property_tests --log_level=message`
   in both build dirs (via `build.sh --unit`), with the default seed, with
   `YACOIN_PROPERTY_SEED=random` a few times and with
   `YACOIN_PROPERTY_ITERATIONS=20000`; check a bad seed value fails cleanly;
   temporarily break one identity in a scratch copy to see the failure
   message (not committed). Record times.
9. **Code review** (self-review, no Agent tool) of the staged diff; fix.
10. **Full test runs**: mainnet unit, lowdiff unit + functional (with the
    functional lock). Expected 327/327 and 46/46.
11. **Documentation**: `src/test/README.md` section "Property tests
    (P0-27)"; test counts 316 -> 327 in `CLAUDE.md`, `contrib/testing/README.md`
    (expected-results table and heading), the `implement-task` skill; task
    file (criteria, Log). Doc self-review.
12. **Commit, push, PR**; move the task to `done/`.

Logging: test-only code; `test_bitcoin` does not write `debug.log` (see
`src/test/README.md`), so observability is `BOOST_TEST_MESSAGE` (seed,
iterations, counts, elapsed) and the failure messages. No `LogPrintf`
changes.

## Log

- 2026-10-03 – step 0: moved to `inprogress/` (commit 623a393).
- 2026-10-03 – steps 1-2: read the task, plan 0.4, P0-10/11/12/13 tests,
  `bignum.h` and the OpenSSL 1.0.1k `crypto/bn` sources from the `depends`
  cache; detailed description written.
- 2026-10-03 – step 3, self-review (no Agent tool) of the description:
  re-checked every identity against `bignum.h` and OpenSSL. Added
  `x % nz` (throws) to case 11. Decided not to assert the 10 s limit inside
  the test (a timing assertion would be flaky on loaded CI and coverage
  builds); the time is printed and recorded here instead. Checked that the
  decoded value for `e < 3` is `(c & 0x7fffff) >> 8*(3-e)` with the sign
  bit still taken from bit 23 (`bignum.h:457-467`), and that values decoded
  from any compact have an MPI of at most 255 bytes, so their round trip
  never hits the exponent wrap.
- 2026-10-03 – step 5, self-review (no Agent tool) of the plan: the wrap
  samples of case 7 need values up to ~2400 bits, so the power table goes
  to 2400 bits (built by doubling, < 1 ms). Seeding per case from the case
  name keeps `--run_test` filters reproducible. No consensus impact
  (test-only). Nothing left out.
- 2026-10-03 – step 6: implemented `src/test/bignum_property_tests.cpp`
  (11 cases) as planned. The first build passed all 11 cases; every
  negative-zero expectation derived from the OpenSSL source held
  (`nz - 0`, `nz + nz`, `nz << n` negative zeros; `nz % x == |x|`;
  products, quotients, `nz >> n`, `-nz` ordinary zeros; `x / nz` and
  `x % nz` throw). The compact wrap samples also hit a decoded negative
  zero (exponent 1 or 2 after the wrap with a sign-bit mantissa); this is
  pinned. Then renamed the case-level counters of `shift_identities` and
  `compact_roundtrip_encodings`, which reused the generator's names.
- 2026-10-03 – checks of the options (mainnet build): default run
  deterministic (same seed and class counts on repeated runs), 0.3 s for
  all 11 cases (largest 0.05 s); `YACOIN_PROPERTY_SEED=random` 3 runs, an
  explicit seed and `YACOIN_PROPERTY_SEED=random
  YACOIN_PROPERTY_ITERATIONS=20000` (6.5 s in total) all pass;
  `YACOIN_PROPERTY_SEED=xyz` and `YACOIN_PROPERTY_ITERATIONS=0` fail the
  case with a clear message. A deliberately broken identity (scratch build,
  not committed) gave: `bignum_property_tests.cpp:426: a + b - b == a +
  CBigNum(i == 5 ? 1 : 0) failed; case add_sub_identities, iteration 5,
  a=… b=… c=-1 (replay with YACOIN_PROPERTY_SEED=50302d…00000000)`.
- 2026-10-03 – step 7, code review (`code-review` skill, medium, on the
  staged diff): no findings. It checked `DecodeCompact` against
  `SetCompact`, `MpiSize`, the exponent wrap, the random helpers' edge
  cases, member initialisation order, `INT64_MIN` and `std::min`/`max`
  with equal operands. Its note that the file header points to
  `project/done/` holds once the task file is moved at the end. In my own
  pass I found that with `random` each case draws its own base seed, and
  documented that in `src/test/README.md`. Left as is: `a / n == a /
  CBigNum(n)` in `mul_div_identities` goes through the same implicit
  conversion on both sides. It stays as documentation of the `pow.cpp`
  usage, and the `r *= n; r /= n` round trip next to it is the real check.
- 2026-10-03 – step 8, full runs (`build.sh`, pinned image): mainnet
  `--unit` exit 0, 327/327 unit (3,759,852 assertions); lowdiff `--unit
  --functional` exit 0, 327/327 unit, 46/46 functional. Property suite in
  the lowdiff unit log: 0.40 s (cases 13-55 ms).
- 2026-10-03 – steps 9-10: documentation in `src/test/README.md` ("CBigNum
  property tests (P0-27)"), test counts 316 -> 327 in `CLAUDE.md`,
  `contrib/testing/README.md` and the `implement-task` skill.
  Self-review (no Agent tool) against the code and the runs: every pinned
  behaviour listed in the README is asserted in the file, the option names
  and the failure-message format match the observed output, and the counts
  match `unit.log`. No owner questions came up: the new pinned oddity
  (`nz % x == |x|`) is in a method with no production caller and falls
  under the negative-zero entry of open question Q2.
- 2026-10-03 – step 11: moved to `done/`, committed and pushed.
