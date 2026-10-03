# P0-12: CBigNum >256-bit behaviour and method audit

- Plan section: 0.2a
- Depends on: P0-10
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Cover the values arith_uint256 cannot represent and decide which methods need replacing.

## Steps

1. Tests for the exact large-value expressions: kernel bnCoinDayWeight * bnTargetPerCoinDay (up to ≈2^263), chain.cpp (CBigNum(1)<<256)/(bnTarget+1), reward bisection products mid^6·powLimit and limit^6·target (~400 bits).
2. Negative intermediates (e.g. negative coin-day weight when txPrev.nTime > nTimeBlockFrom).
3. Audit callers of pow, mul_mod, pow_mod, inverse, gcd, isPrime, randBignum, RandKBitBigum, generatePrime, bitSize, isOne, getint32, setuint160/getuint160, setBytes/getBytes, ToString/GetHex. Start from the preliminary grep list in [plans/dead-code.md](../plans/dead-code.md) c), confirm or correct it there, and settle the names grep could not attribute (ToString, GetHex, SetHex, getvch/setvch, ++/--).

## Acceptance criteria

- [x] Large-value tests pass and document current results (`bignum_consensus_tests`, 7 cases, both builds).
- [x] Used/unused method list in Log (full table in [plans/dead-code.md](../plans/dead-code.md) c)); unused ones excluded from coverage targets (plan 0.2a, P0-04 Notes).

## Notes

Review: B1, B10, D9.

## Detailed description

### Findings from reading the task and the code (step 1)

Verified against the code at master `45eae1a`:

- **Kernel product** (`kernel.cpp:457-461,526,568`):
  `bnCoinDayWeight = CBigNum(nValueIn) * GetWeight(txPrev.nTime, nTimeTx) / COIN / (24 * 60 * 60)`,
  evaluated left to right with two truncating divisions; `GetWeight`
  (`kernel.cpp:80-90`) is `min(nTimeTx - txPrev.nTime - nStakeMinAge, nStakeMaxAge)`
  (`int64_t`). The intermediate `nValueIn * weight` reaches 74 bits
  (`MAX_MONEY` × 90 days), so it would overflow `int64_t`. Maximum weight is
  `MAX_MONEY / COIN * 90 = 180000000000` coin-days (38 bits). Times the PoS
  hard-limit target (`nBits 0x1d03ffff`, `pow.cpp:21`, 226 bits) the product
  has **264 bits** (the task's "≈2^263"); at the mainnet `powLimit` compact
  `0x1e0fffff` (236 bits) it has 274 bits. The full product is compared with
  the hash at `kernel.cpp:526`; `targetProofOfStake` at `kernel.cpp:568` is
  `getuint256()` of it, i.e. the product **mod 2^256** (B10 "truncated
  targetProofOfStake").
- **Negative coin-day weight:** the min-age check (`kernel.cpp:448`) uses
  `nTimeBlockFrom`, `GetWeight` uses `txPrev.nTime`, so the weight is
  negative iff `txPrev.nTime > nTimeTx - nStakeMinAge ≥ nTimeBlockFrom`; the
  range is `[-nStakeMinAge, 0)` (`nTimeTx ≥ txPrev.nTime` is checked at
  `kernel.cpp:444`). On a valid chain this does not happen, because
  `CheckBlock` rejects a block whose timestamp is earlier than any of its
  transactions (`validation.cpp:3205`), so `txPrev.nTime ≤ nTimeBlockFrom`.
  `CheckStakeKernelHash` itself does not reject it: the hash input then
  uses `getuint64()` = the **magnitude** of the weight, and the product is
  negative (or zero), so `hash > product` rejects every hash except that a
  weight truncated to 0 accepts a hash of exactly 0. Division truncates
  toward zero, so e.g. a weight of −1 s on 1 coin gives 0, not −1.
- **Trust shift** (`chain.cpp:114`): `(CBigNum(1) << 256) / (bnTarget + 1)`
  for PoS blocks before `CONSECUTIVE_STAKE_SWITCH_TIME`. `2^256` has 257
  bits; the quotient is at most `2^255` (target 1), because targets ≤ 0 return
  0 earlier (`chain.cpp:79-80`). Compact targets ≥ 2^256 (`nBits ≥
  0x21010000`) give 0. Accumulated `bnChainTrust` can exceed 256 bits (two
  blocks of trust 2^255); `GetBlockProofEquivalentTime` then truncates with
  `getuint256()` (`chain.cpp:193-197`), RPC `chaintrust` prints the full
  `GetHex()` (`rpc/blockchain.cpp:96,127`), `gettimechaininfo` prints
  `getuint64()` (`rpc/blockchain.cpp:945`).
- **Reward bisection** (`validation.cpp:935-977`, pre-fork branch): compares
  `mid^6 * bnTargetLimit > limit^6 * bnTarget` with `limit = 100 COIN`
  (`main.h:50`) and `bnTargetLimit = SetCompact(powLimit.GetCompact())`
  (mainnet `0x1e0fffff`, lowdiff `0x201fffff`). `limit^6` alone is 160 bits;
  the products have **396 bits** (mainnet, `nBits` = powLimit), 407–413 bits
  in the low-difficulty build, up to 432 bits for `nBits 0x2300ffff`. 14
  bisection steps; `mid = (lower + upper) / 2` truncates.
  In unit tests `nMainnetNewLogicBlockNumber` is 0, so
  `GetProofOfWorkReward(nBits, 0, 0)` (height 0) takes the pre-fork branch
  without any chain state.
- **Method audit:** `bignum.h` also defines `typedef CBigNum Bignum`
  (`bignum.h:860`); grep for `CBigNum` alone misses method calls on
  variables (`bnChainTrust`, `powLimit`, …). A grep cannot attribute generic
  names (`ToString`, `GetHex`, `SetHex`, `getvch`, `++`) either. The audit
  is therefore done by the compiler (see *How to test*).
- `bignum.h` line numbers in `dead-code.md` c) are those of master and still
  correct (`randBignum` 160 … `isOne` 674).
- Qt (`qt/explorer.cpp`) uses `CBigNum` but is not built (P0-00); it is
  audited by reading the file.

### Scope

- **New:** `src/test/bignum_consensus_tests.cpp` (suite
  `bignum_consensus_tests`, `BasicTestingSetup`), registered in
  `src/Makefile.test.include`. It pins the three large-value expressions and
  the negative intermediates at the CBigNum level, with the expressions
  copied verbatim from the production code into small helpers, plus
  `GetProofOfWorkReward` anchors that tie the bisection helper to the
  production function.
- **Changed docs:** `project/plans/dead-code.md` c) (confirmed and corrected
  used/unused list, the generic names settled), the plan 0.2a/coverage note
  (which `bignum.h` lines count), `project/todo/P0-04-coverage-gates.md`
  (pointer to the exclusion list), this task file, `src/test/README.md` if it
  lists suites.
- **Not changed:** `bignum.h` and all production code (CLAUDE.md rule 1).
  No function-level tests of `CheckStakeKernelHash` (P0-18),
  `GetBlockTrust`/chain trust (P0-16, in progress in parallel, its file
  `chain_trust_tests.cpp` is not touched) or the reward golden table and
  branch coverage (P0-46). No golden vectors (P0-13).

### Behaviour (test cases)

Expected values are literals computed independently (Python big integers
with truncating division; script in the Log), never with `CBigNum`.

0. `consensus_constants` – `COIN`, `CENT`, `MAX_MONEY`,
   `MAX_MINT_PROOF_OF_WORK` and `Params()` stake min/max age equal the
   literals the helpers use.
1. `kernel_coin_day_weight` – helper `CoinDayWeight(nValueIn, nTimeWeight)`
   = the `kernel.cpp:458-461` expression. Max: `MAX_MONEY`, 90 days →
   `180000000000` (`0x29e8d60800`), `getuint64()` the same. Truncation:
   1 unit × 90 days → 0. Negative: 5 COIN × −3 days → −15, `getuint64()` 15;
   1 COIN × −1 s → 0 (floor would be −1); 1 COIN × −1 day → −1;
   `MAX_MONEY` × −30 days (−`nStakeMinAge`, the lower bound) →
   −60000000000, `getuint64()` 60000000000.
2. `kernel_target_product_over_256_bits` – max weight × `SetCompact(0x1d03ffff)`
   (264 bits) and × `SetCompact(0x1e0fffff)` (274 bits): exact hex;
   `getuint256()` = low 256 bits; the full-precision check (`:526`) passes
   even the all-ones hash, while the truncated `targetProofOfStake` (`:568`)
   is smaller than that hash (pinned discrepancy).
3. `kernel_negative_weight_product` – weight −15 × `0x1d03ffff` target:
   negative product, hash 0 and all-ones hash both rejected (`>` true),
   `getuint256()` = magnitude; weight 0: product 0, hash 0 passes, hash 1
   rejected.
4. `trust_shift_over_256_bits` – `CBigNum(1) << 256` (257 bits, `getuint256()`
   0); quotient table for `nBits` `0x01010000` (2^255), `0x1d03ffff`
   (`0x40001000`), `0x1e0fffff` (`0x100001`), `0x201fffff` (8), `0x207fffff`
   (2), `0x2100ffff` (1), `0x21010000` (target 2^256 → 0); sum of two
   2^255 trusts = 2^256: `GetHex()` full, `getuint256()` 0, `getuint64()` 0.
5. `reward_bisection_products` – `limit^6 * target` for `0x1e0fffff` (396
   bits) and `0x2300ffff` (432 bits), `mid^6 * targetLimit` for mid 50 and 99
   COIN with both target limits (`0x1e0fffff`: 390/396 bits, `0x201fffff`:
   407/413 bits); comparison results; the `powLimit` compact round trip of
   the current build (`#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT`, as `pow_tests`).
6. `reward_bisection_results` – helper = the `validation.cpp:949-966` loop
   plus rounding to `CENT` and the `min` with the limit; for `nBits`
   `0x1e0fffff, 0x1d00ffff, 0x1c00ffff, 0x1b00ffff, 0x1a00ffff, 0x201fffff,
   0x21010000, 0x2300ffff, 0x01010000` with both target limits (literal
   table, e.g. `0x1d00ffff`: 25.00 coins mainnet, 3.51 lowdiff); and
   `GetProofOfWorkReward(nBits, 0, 0)` equals the column of the current build
   for every row (`nFees` 0, height 0 → pre-fork branch).

### Expected-value model

The literals in `bignum_consensus_tests.cpp` were computed with this Python
3 model (plain integers; `tdiv` is `BN_div`'s truncation toward zero;
`compact` is `SetCompact` for inputs without the sign bit), not with
`CBigNum`:

```python
def tdiv(a, b):
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q

def compact(n):
    size = n >> 24
    m = [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
    b = (m + [0] * max(0, size - 3))[:size]
    return int.from_bytes(bytes(b), 'big') if size else 0

COIN, CENT, MAX_MONEY, DAY = 10**6, 10**4, 2 * 10**15, 86400
weight = lambda value, w: tdiv(tdiv(value * w, COIN), DAY)   # kernel.cpp:458-461
trust = lambda nbits: tdiv(1 << 256, compact(nbits) + 1)     # chain.cpp:114

def reward(nbits, limit_compact):                            # validation.cpp:935-977
    L, T, TL = 100 * COIN, compact(nbits), compact(limit_compact)
    lo, up = CENT, L
    while lo + CENT <= up:
        mid = tdiv(lo + up, 2)
        if mid**6 * TL > L**6 * T: up = mid
        else: lo = mid
    return min(up // CENT * CENT, L)

# e.g. format(weight(MAX_MONEY, 90 * DAY) * compact(0x1d03ffff), 'x')
#      == 'a7a32e3729f8' + '0' * 54;  reward(0x1d00ffff, 0x1e0fffff) == 25000000
```

### Edge cases

- Both builds: cases 1–4 do not depend on chain parameters; 5–6 pin both
  target limits in both builds and the production call per build with
  `#ifdef`, nothing skipped.
- Unit-test globals at 0 make height 0 pre-fork; `fDebug` logging in the
  bisection is off (`-printcreation` not set).
- `CBigNum(1LL)`-style ambiguity: helpers take `int64_t` explicitly.
- No undefined behaviour (no negative zero, no `ToString(1)`, no empty
  `getBytes`) is exercised.
- Expression copies can drift from production: each helper cites the source
  line; the reward helper is cross-checked against the production function;
  the kernel and trust expressions are checked at function level by P0-18 and
  P0-16.

### Method audit (step 3)

Compile-time audit: in a scratch copy of the tree (never committed), every
`CBigNum` member and free operator in `bignum.h` gets
`__attribute__((deprecated("CBIGNUM_AUDIT")))`; the whole tree (daemon,
CLI, wallet, `test_bitcoin`, `test_bitcoin_fuzzy`; bench and zmq are not
configured) is built with `make -k` in the
build image for mainnet and lowdiff. Each warning names the method and the
calling file:line, so every use — including those through variables,
implicit conversions, templates and generic names — is attributed.
Calls inside `bignum.h` are mapped by reading. Code not compiled here (Qt,
`WIN32`, other `#ifdef`s) is checked by grep/reading. Result: a table
method → production callers / test-only / internal-only / none in
`dead-code.md` c) and the Log.

### How to test

| Acceptance criterion | Test / command | Expected |
|---|---|---|
| Large-value tests pass and document current results | `bignum_consensus_tests` in `contrib/testing/build.sh --config mainnet --unit` and `--config lowdiff --unit --functional` | 7/7 cases in both builds; totals 284/284 unit both builds, 45/45 functional |
| Used/unused list in Log; unused excluded from coverage targets | compile-time audit logs (scratch), counts per method in the Log; `dead-code.md` c) and plan/P0-04 note updated | every method classified; preliminary list confirmed or corrected |

Test levels: unit; functional run per the skill (no node code changes).

### Risks

- No consensus risk: no production code changes.
- Pinning OpenSSL behaviour is intended; the values are plain integer
  arithmetic, so any correct big-integer library must reproduce them.
- Merge conflicts: `Makefile.test.include` line next to `bignum_tests.cpp`;
  test-count lines in CLAUDE.md, `contrib/testing/README.md` and the skill
  change (+7) – mentioned in the PR.

## Implementation plan

1. **Expected values.** Python script (scratchpad, quoted in the Log) that
   models the expressions with Python integers and truncating division and
   prints every literal used by the tests. *Verify:* the model reproduces
   known values (mainnet `powLimit` compact `0x1e0fffff`, P0-10's
   `bnPowTrust == 4096` at `0x1d00ffff`).
2. **Test file.** `src/test/bignum_consensus_tests.cpp`: header comment
   (what is pinned, why temporary, related tasks P0-16/P0-18/P0-46/P0-13),
   helpers `Target(nBits)`, `CoinDayWeight`, `TrustShift`, `RewardBisection`
   – each a verbatim copy of the production expression with its
   file:line – and cases 1–6 from the description. Register it in
   `src/Makefile.test.include` after `test/bignum_tests.cpp`. Checks that
   pin an oddity carry "pinned:". *Verify:* builds without warnings; the
   suite passes in both builds (`--run_test=bignum_consensus_tests` from
   `unit.log`).
3. **Method audit.** Scratch compile-time audit (already running, see
   description), mainnet and lowdiff; summarise warnings per method and
   per calling file (production / `src/test` / `bignum.h` internal); read
   `qt/explorer.cpp`; grep `#ifdef`-guarded code that is not compiled here
   (`WIN32`, `ENABLE_ZMQ`, bench). *Verify:* every `bignum.h` method appears
   in the table; the counts are reproducible from the logs.
4. **Code review** of the staged diff (code-review skill or self-review),
   fixes.
5. **Tests:** `contrib/testing/build.sh --config mainnet --unit --jobs 2
   --work-dir /root/.cache/yacoin-build-P0-12`, then (with the functional
   lock) `--config lowdiff --unit --functional`. Expected 284/284, 284/284,
   45/45.
6. **Documentation:** `dead-code.md` c) rewritten from "preliminary" to the
   audited table (with line ranges of the used methods for the coverage
   target); plan 0.2a coverage line points to it; P0-04 Notes get the
   pointer; `src/test/README.md` suite list if applicable; test-count lines
   in `CLAUDE.md`, `contrib/testing/README.md`, the skill (277 → 284); task
   file (criteria, Log). Logging (CLAUDE.md rule 5): not applicable, no
   daemon code.
7. **Doc review**, task to `done/`, commit, push, PR, CI check.

## Log

- 2026-10-03 step 0: picked up; dependency P0-10 is in done/; branch task/P0-12-cbignum-overflow-and-method-audit (commit 0137686).
- 2026-10-03 step 1–2: task verified against the code (findings in the description: products reach 264/274 bits in the kernel and 396–432 bits in the reward; negative weight is not reachable on a valid chain because of `validation.cpp:3205` but is not rejected by `CheckStakeKernelHash` itself; `typedef CBigNum Bignum` and calls through variables make a grep audit incomplete → compile-time audit). Expected values from a Python model (truncating division), scratchpad only.
- 2026-10-03 step 3: description review – self-review (no Agent tool). Applied: kernel line references corrected (`:444`, `:448`); lower bound of the negative weight is `-nStakeMinAge` (not `-MAX_FUTURE_BLOCK_TIME` as first drafted, because `nTimeTx ≥ txPrev.nTime` is checked); added a `consensus_constants` case so the helpers' literal ages/limits are tied to `Params()`/`amount.h`; the reward helper is cross-checked against `GetProofOfWorkReward` to catch drift of the copied expression. Not applied: function-level kernel/trust tests (P0-18/P0-16 own them; P0-16 is in progress in parallel).
- 2026-10-03 step 4–5: implementation plan written; plan review – self-review (no Agent tool). Checked: `GetProofOfWorkReward` is declared in `consensus/consensus.h` (not `validation.h`), callable at height 0 without chain state; zmq and bench are not configured, so their (CBigNum-free, by grep) sources are not compiled by the audit; consensus impact none. Applied: test count is 277 + 7 = 284 (the constants case added in step 3).
- 2026-10-03 step 6: `src/test/bignum_consensus_tests.cpp` (7 cases, suite `bignum_consensus_tests`) added and registered in `src/Makefile.test.include`. No production code changed. Method audit: scratch compile-time audit (every `CBigNum` method marked deprecated, `make -k`, mainnet and lowdiff, about 22,800 log lines with the marker per build), summarised per method and caller; logs kept in the work dir only.
- 2026-10-03 audit result (full table with line ranges in `plans/dead-code.md` c)):
  - **Used by production code:** default/copy constructor, `operator=`, destructor; `CBigNum(int32_t)`, `CBigNum(int64_t)`, `CBigNum(uint256)`; `SetCompact`, `GetCompact`, `setuint256`, `getuint256`, `getuint64`, `ToString` (log text only), `GetHex` (RPC only); `*=`, `/=`; binary `+ - * /`; `<<` (only `chain.cpp:114`); `< <= > >=`.
  - **Used only inside `bignum.h` by those:** `setuint32`, `setint64`, `setuint64`, `getuint32`, `CAutoBN_CTX`.
  - **Unused by production code** (tests only, or nothing): `CBigNum(int8_t/int16_t/uint8_t/uint16_t/uint32_t/uint64_t)`, vector constructor (no caller at all), `randBignum`, `RandKBitBigum`, `generatePrime` (no caller at all), `bitSize`, `getint32`, `setuint160`/`getuint160`, `setBytes`/`getBytes`, `setvch`/`getvch`, `SetHex`, `GetSerializeSize`/`Serialize`/`Unserialize`, `pow` ×2, `mul_mod`, `pow_mod`, `inverse`, `gcd`, `isPrime`, `isOne`, `operator!`, `+=`, `-=`, `%=`, `<<=`, `>>=`, `++`/`--` (prefix and postfix), unary `-`, `%`, `>>`, `==`, `!=`, `operator<<(ostream)`.
  - Corrections to the preliminary lists (P0-50 c), P0-10 description): `operator==`, `operator!`, `+=` and `CBigNum(uint64_t)` have no production caller; `ToString`/`GetHex`/`SetHex`/`getvch`/`setvch`/`++`/`--` settled as above. Qt (`qt/explorer.cpp`, not built) uses only default constructor, `SetCompact`, `getuint256`.
- 2026-10-03 step 7: code review with the `code-review` skill (medium) on the staged diff: all helpers match the production expressions, every literal recomputed independently and correct, `dead-code.md` c) line ranges checked against `bignum.h`. One finding (comment `// floor: -1` misleading) – applied. Not applied: none. No static analysis yet (P0-58 not done).
- 2026-10-03 step 8 tests (`contrib/testing/build.sh … --jobs 2`): mainnet `--unit` exit 0, **284/284** (277 + 7 new); lowdiff `--unit --functional` exit 0, unit **284/284**, functional **45/45** (`ALL … Passed`). `bignum_consensus_tests` passes in both builds; no compiler warning from the new file. (Docker daemon was not running at the start and was started with `dockerd`.)
- 2026-10-03 step 9: documentation: `plans/dead-code.md` c) rewritten from the preliminary grep list to the audited table; plan 0.2a method-audit bullet; `todo/P0-04-coverage-gates.md` Notes (which `bignum.h` lines count); test counts 277 → 284 in `CLAUDE.md`, `contrib/testing/README.md`, the implement-task skill; this task file (findings, expected-value model, Log). Logging (CLAUDE.md rule 5): not applicable, no daemon code. No `doc/` or RPC change.
- 2026-10-03 step 10: documentation review – self-review (no Agent tool), re-read against the code, the audit logs and the test logs. Applied: `dead-code.md` listed `yacoin-tx` as built (it is not; `test_bitcoin_fuzzy` is) – corrected here and in the description; added the missing call sites `validation.cpp:3683,3703`; the test header promised the Python script "in the task file" – added as *Expected-value model* and re-run (reproduces the literals). Not applied: P0-10's done task file still lists `==`/`CBigNum(uint64_t)` as used – a finished task's record is left as is, the correction is in `dead-code.md` c) and here.
