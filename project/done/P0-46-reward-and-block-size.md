# P0-46: Reward and block-size characterisation

- Plan section: 0.2f
- Depends on: P0-01, P0-47
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Pin the reward functions and the reward-derived block size limit.

## Steps

1. GetProofOfWorkReward pre-fork (CBigNum bisection, validation.cpp:918-979) and post-fork (double nInflation, validation.cpp:932).
2. GetMaxSize (consensus/consensus.cpp:26-27), GetProofOfStakeReward/GetCoinAge (consensus/tx_verify.cpp:415-422), LoadBlockRewardAndHighestDiff (validation.cpp:3714-3717, different evaluation order), getsubsidy.
3. Golden table: reward for every pre-fork nBits seen on mainnet (from the dump once P0-09 exists) plus boundary nBits; reward and max size per epoch.
4. Store vectors hex/decimal so P0-53 can run them on other targets.

## Acceptance criteria

- [x] Reward functions 100% branch coverage – every source-level branch; see "Coverage" for the gcov numbers and the compiler branches that remain.
- [x] Golden table committed (`src/test/data/reward_vectors.json`); replay of per-block rewards, mainnet `nBits` and real per-epoch supplies left to P0-23 (note added there).

## Notes

Second place where Phase 4 needs >256-bit arithmetic. Review: B1, B2.

## Detailed description

### Findings from reading the task (step 1)

Line references checked against master f7e81bc.

- `GetProofOfWorkReward` is `validation.cpp:918-980` (post-fork `double` at
  932, pre-fork bisection 935-977) ✓. `GetMaxSize` is
  `consensus/consensus.cpp:20-47` (fork switch 26-27) ✓.
  `LoadBlockRewardAndHighestDiff` is `validation.cpp:3677-3729` (reward
  3714-3717) ✓; it only writes three `LogPrintf` lines, nothing else
  uses its values. `getsubsidy` is `rpc/mining.cpp:134-154`.
- Step 2's `consensus/tx_verify.cpp:415-422` is the **caller**
  (coinstake check in `Consensus::CheckTxInputs`, 410-423).
  `GetProofOfStakeReward` is `pow.cpp:237-250`, `GetCoinAge`
  `validation.cpp:4809-4866`.
- `GetProofOfStakeReward` ignores `nBits` and `nTime`:
  `nCoinAge * 5 * CENT * 33 / (365 * 33 + 8)` (int64, truncating; signed
  overflow – UB – above nCoinAge 5,589,922,446,578).
- Post-fork the reward **ignores `nFees`** (`validation.cpp:932`, no
  `+ nFees`); pre-fork adds them after the `min` with 100 YAC.
- `nHeight == 0` always takes the pre-fork branch, also when the fork
  height is 0 (unit tests): `GetMaxSize(mode, 0)` on an empty
  `chainActive` therefore calls `GetProofOfWorkReward(0, 0, 0)` = target 0
  → `CENT` → max size 1000 bytes.
- First post-fork epoch: `startEpochBlockHeight == 0` → fork height; the
  supply is read with `FindBlockByHeight`, which returns the **tip** for
  any height ≥ tip height and genesis for heights ≤ 0 (`chain.cpp:226-236`).
- `LoadBlockRewardAndHighestDiff` divides first (integer
  `nMoneySupply / nNumberOfBlocksPerYear`) and multiplies by 0.02 after,
  `GetProofOfWorkReward` multiplies first in `double`. It also finds no
  epoch block when the fork height is not a multiple of `nEpochInterval`
  and the tip is still in the first epoch, then logs "something wrong" and
  reward 0, while `GetProofOfWorkReward` uses the supply at fork − 1.
- Arithmetic check (scratch C program, x86-64/SSE2 `double`): both forms
  equal the exact integer `floor(nMoneySupply / 26,298,000)` for every
  supply 0 … `MAX_MONEY` (2·10^15). Both are monotone in the supply, so it
  suffices to check each step point k·26,298,000 and the value below it
  (k ≤ 76,051,411), and for the second form n·50 and n·50 − 1. So on this
  target the "different evaluation order" gives the same values; B2's
  risk is other targets (x87, P0-53) – the check becomes a unit test that
  P0-53 runs there.
- `getsubsidy`: the client converts `ntarget` as JSON (`rpc/client.cpp:81`),
  so `yacoin-cli getsubsidy <hex>` must quote the hex as a JSON string; the
  server reads it with `get_str()`. Post-fork the target is ignored.
- `nNumberOfBlocksPerYear` = 525,960 (`validation.h:236-242`); `COIN` 10^6,
  `CENT` 10^4, `MIN_TX_FEE` = `CENT`; so max size = reward / 10 bytes.
- Mainnet dump (P0-09) does not exist yet: "every pre-fork nBits seen on
  mainnet" and real per-epoch supplies cannot be added now (see Scope).

### Scope

Test-only (CLAUDE.md rule 1: nothing in `src/` outside `src/test/`
changes).

- New `src/test/reward_tests.cpp` (suite `reward_tests`, harness fixture
  `ConsensusTestingSetup`) covering `GetProofOfWorkReward` (both branches,
  fees, debug logging), `GetMaxSize` (3 modes, both sides of the fork,
  `nHeight == 0`), `GetProofOfStakeReward`, `GetCoinAge` (all paths),
  the coinstake reward limit in `Consensus::CheckTxInputs`,
  `LoadBlockRewardAndHighestDiff` (log output captured) and `getsubsidy`.
- Golden table `src/test/data/reward_vectors.json` (embedded like the other
  `*.json`): pre-fork rows `nBits` → reward for both target limits
  (mainnet 0x1e0fffff, low-difficulty 0x201fffff); post-fork rows money
  supply → reward, `LoadBlockReward` value, max size in the 3 modes; PoS rows
  coin age → reward; a per-epoch model table. All values are decimal
  strings, `nBits` 8-digit hex. Each row has a `source` tag
  (`boundary`, `sweep`, `model`, later `mainnet`).
- `contrib/testing/reward_vectors.py`: generates the table with Python
  integers/floats (no `CBigNum`) and `--check`s a file; `--mainnet-nbits FILE`
  adds rows for a list of nBits later (P0-23 / after P0-09).
- The pre-fork bisection helper of `bignum_consensus_tests.cpp`
  (`RewardBisection`) is reused for the column of the other build (made
  non-static, declared in the new file), not duplicated.
- Callers are not re-tested here: the coinbase check in `ConnectBlock`
  (`validation.cpp:2021`, height `chainActive.Height() + 1`), the miner
  (`miner.cpp:526`) and `getmininginfo`'s `blockvalue`
  (`rpc/mining.cpp:301`, passes `chainActive.Height()` – the current, not
  the next, height; noted for the RPC snapshots of P0-33).
- Not done here: per-block replay (P0-23), mainnet nBits and real per-epoch
  supplies (need P0-09; added as a step to P0-23), other targets (P0-53).

### Behaviour (examples, pinned)

- Pre-fork, mainnet limit: `0x1e0fffff` → 100,000,000; `0x1d00ffff` →
  25,000,000; target 0 / negative target → 10,000 (`CENT`); target above
  the limit → 100,000,000; `nFees` added after the cap.
- Post-fork: supply 10^14 → 3,802,570; max size 380,257 bytes (reward /
  10), GEN 190,128, SIGOPS max(size, 10^6)/50 = 20,000; supply 0 →
  reward 0, size 0, GEN 0, SIGOPS 20,000. Fees ignored.
- Pre-fork `GetMaxSize`: 1,000,000 / 500,000 / 20,000.
- PoS: coin age 365 coin-days → 49,966 (365·50,000·33 / 12,053, i.e. 5 %
  a year); `nBits`/`nTime` have no effect; negative coin age truncates
  toward zero (coin age −1 → −136, not −137).
- Epoch selection (mainnet globals, fork 1,890,000, epoch 21,000):
  heights 1,890,000 … 1,910,999 use the supply of 1,889,999; 1,911,000 …
  1,931,999 that of 1,910,999; a height beyond the tip uses the tip.

### Edge cases

Target 0, negative compact, exponent overflow (target ≥ 2^256), target
exactly the limit and one above; supply 0, step points k·26,298,000 and
k·26,298,000 − 1, `MAX_MONEY`; unit-test globals (fork 0) vs mainnet vs
functional (epoch 10) globals; fork height not a multiple of the epoch;
epoch block at a segment start or genesis (`pprev == nullptr`); empty
`chainActive` (`GetMaxSize` height 0); both build configurations (the
pre-fork column and `initialMoneySupply` differ: `#ifdef
LOW_DIFFICULTY_FOR_DEVELOPMENT`); coin age: coinbase, missing coin,
timestamp violation, no tx index, index miss, corrupt offset, txid
mismatch, younger than `nStakeMinAge`, several inputs, per-input
truncation; debug-logging switches (`fDebug`, `-printcreation`,
`-printcoinage`) restored afterwards.

### How to test

| Acceptance | Test | Expected |
|---|---|---|
| 100 % branch coverage of the reward functions | coverage builds (mainnet + lowdiff), `--coverage-report`, branch count per function (exception branches not counted, as in the gate) | 100 % or every missing branch explained |
| Golden table committed | `reward_tests/golden_*` replay the JSON in both builds; `reward_vectors.py --check` | all rows match |
| Docs/test counts | CLAUDE.md, `contrib/testing/README.md`, skill updated to the new count; coverage gate minimums ratcheted with `coverage_gate.py --suggest` | – |
| Regression | `build.sh --config mainnet --unit`, `--config lowdiff --unit --functional` | 327 + new unit tests, 46/46 functional |

### Risks

None for consensus (no production change). Test risks: global state
(`fDebug`, `gArgs`, `fTxIndex`, stdout capture) must be restored even on
failure (RAII); the critical-point scan must stay fast in the `-O0`
coverage build.

## Implementation plan

1. **Generator** `contrib/testing/reward_vectors.py` (Python 3, stdlib
   only): integer bisection (copy of `validation.cpp:949-977`, truncating
   division), post-fork `int(float(s) * 0.02 / 525960)` and
   `int(float(s // 525960) * 0.02)`, max sizes, PoS
   `trunc(a * 1650000 / 12053)`. Writes `src/test/data/reward_vectors.json`
   (`--write`), compares with the file (`--check`, default), adds rows from
   `--mainnet-nbits FILE` (one hex nBits per line, `source: mainnet`).
   Rows: boundary nBits (0, negative, limits ±1, exponent overflow, target
   1, 2^256), sweep exponents 0x03-0x22 × mantissas, a denser sweep over
   exponents 0x1a-0x1e (mainnet pre-fork range); supplies (0, 1, step
   points ±1, 10^14, `MAX_MONEY`, …); per-epoch model (start at 10^14,
   +21,000 blocks · reward per epoch, 60 epochs); coin ages.
   Verify: `--check` passes; spot values equal the P0-12 literals.
2. **Embed** the JSON: `JSON_TEST_FILES` in `src/Makefile.test.include`,
   `reward_tests.cpp` in `BITCOIN_TESTS`. Verify: builds.
3. **`RewardBisection`** in `bignum_consensus_tests.cpp` out of the
   anonymous namespace (declaration comment points to reward_tests).
4. **`src/test/reward_tests.cpp`** (`ConsensusTestingSetup`), cases:
   - `golden_prefork_pow` – every pre-fork row: `GetProofOfWorkReward(nBits,
     0, 0)` = column of this build, `RewardBisection` = both columns.
   - `golden_postfork_pow_and_max_size` – functional globals (epoch 10,
     fork 10), chain genesis … 10 (10 is an epoch block); for every supply
     row set height 9's `nMoneySupply`, then `GetProofOfWorkReward(0, 0,
     11)`, `GetMaxSize(mode, 11)` (3 modes) and the "Current block reward"
     line of `LoadBlockRewardAndHighestDiff` (captured) match the row.
   - `golden_per_epoch` – same globals, chain of all model epochs (10
     blocks each, supply of the last block of each epoch from the table):
     reward and max size of every height in every epoch.
   - `golden_pos` – `GetProofOfStakeReward` for every row, several
     nBits/nTime.
   - `postfork_double_equals_integer` – critical-point scan (both forms).
   - `pow_reward_fees_and_branches` – fees pre/post-fork, `nHeight == 0`
     with fork 0, debug logging branches (`fDebug`, `-printcreation`,
     captured log lines).
   - `epoch_selection_mainnet` – mainnet globals, segment
     1,889,990 … 1,932,001 with distinct supplies, heights at each
     boundary, height beyond tip.
   - `max_size_prefork_and_empty_chain` – pre-fork sizes; `nHeight = 0`
     uses tip + 1; fork 0 with empty `chainActive` → 1000/500/20000.
   - `coin_age_paths` – all `GetCoinAge` paths, `-printcoinage` log.
   - `coinstake_reward_limit` – `Consensus::CheckTxInputs` accepts reward
     = calculated, rejects +1 with `bad-txns-coinstake-too-large`, rejects
     when coin age fails.
   - `load_block_reward_log` – log lines for: chain below fork (reward 0,
     no epoch), epoch block found (pprev and pprev == nullptr), epoch block
     missing ("something wrong"), min-ease/`nMinEase` update.
   - `getsubsidy_rpc` – with/without target, pre/post-fork, JSON quoting,
     help/too many params.
   Helpers (anonymous namespace): `LogCapture` (RAII: `fPrintToConsole`,
   stdout fd redirected to a temp file with `dup`/`dup2`), `ScopedArg`
   (`gArgs.ForceSetArg` + restore), `ScopedFlag<T>` for `fDebug`/`fTxIndex`.
   Verify: build + run suite in both configurations.
5. **Coverage**: coverage builds both configs, `--coverage-report`,
   per-function branch numbers (script in log); explain any gap; ratchet
   `coverage-gates.toml` (`validation.cpp rewards` + add functions
   `GetCoinAge`; new gates for `GetMaxSize`, `GetProofOfStakeReward` if
   useful) with `--suggest`.
6. **Docs**: `src/test/README.md` section "Rewards and block size (P0-46)"
   (format, generator, findings), `src/test/data/README.md`,
   `contrib/testing/README.md` (generator + counts), CLAUDE.md and skill
   counts, plan 0.2f note, P0-23 step for mainnet nBits/supplies, open
   questions.
7. Code review, tests (both configs + functional), doc review, commit, PR.

Logging: no production change, so no new log lines; the tests check the
existing `LogPrintf` lines of `LoadBlockRewardAndHighestDiff` and the
`-printcreation`/`-printcoinage` output.

## Coverage

Local coverage runs of this branch (`build.sh --config mainnet --coverage
--unit`, `--config lowdiff --coverage --unit --functional`,
`--coverage-report`), merged; gcov branches without exception branches
(as the gate counts them):

| Function | Lines | Branches |
|---|---|---|
| `GetProofOfWorkReward` | 33/33 | 73/101 |
| `LoadBlockRewardAndHighestDiff` | 30/30 | 39/76 |
| `GetCoinAge` | 40/40 | 63/82 |
| `GetMaxSize` | 16/16 | 10/10 |
| `GetProofOfStakeReward` | 7/7 | 15/28 |
| `getsubsidy` | 11/11 | 14/14 |

Before (P0-04 report): 31/33 – 61/160 (with exception branches), 28/30,
0/40, 16/16, 0/7, 0/11. Every source-level decision runs both ways
(fork switch, `nHeight == 0`, epoch-start fallback, bisection
comparison, `fDebug` / `-printcreation` / `-printcoinage`, every
`GetCoinAge` return, the `LoadBlockRewardAndHighestDiff` loop, epoch,
min-ease, found/not-found and `pprev` branches, the `getsubsidy` help and
target paths, all `GetMaxSize` modes). The branches that stay at 0 are
compiler branches without a source decision:

- inside the `LogPrintf` macro (`util.h:167-176`) on lines 955, 972, 3722,
  3726-3728, 4856, 4864 and `pow.cpp:246`: the
  `catch (tinyformat::format_error&)` handler and the string building in
  it – reachable only with a malformed format string;
- `validation.cpp:954`, `pow.cpp:245` branches 14-17: the cleanup of the
  `std::string` temporary of `gArgs.GetBoolArg("-printcreation")` when it
  throws (all other outcomes of the line ran);
- `validation.cpp:4843` branch 0: the `catch (std::exception&)` type test
  for an exception that is not a `std::exception` – nothing in the `try`
  throws one.

Gates (`contrib/testing/coverage-gates.toml`) ratcheted with `--suggest`
from this run: overall lines 69→70, functions 76→77; `pow.cpp` 88/82/62 →
95/100/69; "validation.cpp rewards" now also selects `GetCoinAge`, 93/54 →
100/67; new gate `GetMaxSize` 100/100. The `fTestNet` exclusion on
`tx_verify.cpp:417` was `verified = false`; the coinstake test now runs the
line, the gate stopped (exit 2) as designed, the outcome id 0,2 was checked
on the data (0,0 and 0,3 ran) and the entry is now verified.

## Log

- 2026-10-03 step 0: task moved to inprogress (a3e87d6).
- 2026-10-03 step 1: references checked, findings in "Detailed
  description". GetProofOfStakeReward/GetCoinAge are in pow.cpp and
  validation.cpp; tx_verify.cpp:415-422 is their caller.
- 2026-10-03 step 3, self-review (no Agent tool) of the description:
  fixed two wrong examples (max size, PoS 365 coin-days); added the
  callers that stay out of scope (ConnectBlock, miner, getmininginfo's
  `blockvalue` at the current height → P0-33) and the doc/test-count and
  coverage-ratchet rows to "How to test".
- 2026-10-03 step 5, self-review (no Agent tool) of the plan: the
  post-fork golden case first used a fork-height-2 chain on which
  `LoadBlockRewardAndHighestDiff` finds no epoch block; changed to epoch
  10 / fork 10 so every row is checked through the real function instead
  of an expression copy. getsubsidy without target is compared with
  `GetProofOfWorkReward(GetNextTargetRequired(..))` rather than a literal
  (the retarget is P0-14/P0-15's subject). Stdout capture flushes
  `std::cout` and `stdout` before and after redirecting; no BOOST checks
  inside the capture window.
- 2026-10-03 step 6: implemented (generator + golden table, 13 cases in
  `reward_tests.cpp`, `RewardBisection` shared). First mainnet run: 2
  failures in `epoch_selection_mainnet` – `GetMaxSize(mode)` without a
  height on a chain *segment* returns the pre-fork size because
  `chainActive.Genesis()` is null (`consensus.cpp:23`), not tip + 1. The
  expectation was wrong; pinned as such and "tip + 1" checked on a chain
  with a height-0 entry instead. Then mainnet 340/340.
- 2026-10-03 step 7: `code-review` skill (medium) on the staged diff, 4
  low findings, all fixed: a `BOOST_CHECK` inside a log capture (moved
  after `Stop()`); README described the `epochs` columns wrongly;
  `--mainnet-nbits` replaced instead of adding to the existing mainnet rows
  (now merged; a value that is already a boundary/sweep row is re-tagged
  `mainnet`); values wider than 32 bits in the list were silently cut (now
  an error). The generator changes were checked by hand (two incremental
  lists, an overlapping value, a 33-bit value).
- 2026-10-03 step 8: mainnet 340/340 (exit 0); lowdiff 340/340 and
  functional 46/46 (exit 0). Coverage runs (above) found two source
  branches still open (`GetProofOfStakeReward` logging, `getsubsidy` help);
  added `pos_reward_logging` and an `fHelp` check, the coverage gate's
  `verified = false` stop on `tx_verify.cpp:417` was resolved. Final:
  mainnet coverage build 341/341, lowdiff (-O2) 341/341, coverage gate
  all 22 checks passed, `test_coverage_gate.py` OK,
  `reward_vectors.py --check` OK. 14 new test cases (327 → 341).
- 2026-10-03 step 7 (second pass), self-review (no Agent tool) of the
  delta after the review (new PoS logging case, fHelp check, gate
  config): no `BOOST_CHECK` inside a capture, globals restored by RAII,
  `nBits` printed with `%d` pinned as decimal; no findings.
- 2026-10-03 step 10, self-review (no Agent tool) of the documentation
  against the code and the runs: fixed the `getmininginfo` wording in Q12
  (old reward shows when the *next* block starts an epoch) and the scan
  run time (0.3 s measured in the -O2 build, not "about a second");
  test counts in CLAUDE.md, contrib/testing/README.md and the skill set
  to 341.
- Open: mainnet `nBits` rows and real per-epoch supplies (P0-23, needs
  P0-09); other targets (P0-53); owner questions in open-questions Q12.
