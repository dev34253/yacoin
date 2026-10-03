# P0-21: Randomness API tests

- Plan section: 0.2i
- Depends on: P0-01
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Pin RNG API contracts before OpenSSL is removed from it.

## Steps

1. GetRand/GetRandInt ranges; GetStrongRandBytes no repeats across 1M calls; seeded FastRandomContext deterministic; Random_SanityCheck.
2. Loose chi-square on byte distribution.
3. Record random_nonce.cpp as dead code (uses rand(), only caller is dead scanhash_scrypt) on the P0-50 list. Done by P0-50: [plans/dead-code.md](../plans/dead-code.md) a).

## Acceptance criteria

- [x] random.cpp ≥ 90% lines (92.6 %, 150/162; functions 21/22).

## Notes

Catches broken generators, not weak ones – Phase 3 RNG changes also need review against Bitcoin Core. Review: A8.

## Detailed description

Verified against the code (master 5183b3a):

- `src/random.cpp` uses OpenSSL in `RandAddSeed` (`RAND_add`, :135),
  `RandAddSeedPerfmon` (Windows only, :166), `GetRandBytes` (`RAND_bytes`,
  :276) and `Random_SanityCheck` (`RAND_add`, :450-451) – the lines
  `overview.md` lists. `GetRand`, `GetRandInt`, `GetRandHash`,
  `FastRandomContext::RandomSeed` and the first source of
  `GetStrongRandBytes` all go through `GetRandBytes`, i.e. OpenSSL.
- Existing `random_tests` (3 cases): `Random_SanityCheck`, deterministic
  `FastRandomContext(true)` pairs agree, `randbits`/`randrange` ranges.
- Coverage at P0-04 (merged report): 139/162 lines (85.8 %), 20/22
  functions. Uncovered: `RandFailure` (:50-53), `GetHWRand`'s `return
  false` (:128, the CI/host CPUs have RDRAND), all of `GetDevURandom`
  (:183-199, only the ENOSYS fallback calls it), the failure branches
  :224/229/231/277, `GetRand(0)` (:356) and the `len == 0` exit of
  `randbytes` (:405).
- Step 3 (`random_nonce.cpp` dead) is done: `dead-code.md` a) (P0-50); the
  file is excluded from the coverage gate.

**Scope.** Test code only: extend `src/test/random_tests.cpp`; ratchet the
`random.cpp` gate in `contrib/testing/coverage-gates.toml`; update test
counts and docs. No change to `random.{h,cpp}` or any node code.

**Behaviour – new test cases (pinned contracts):**

1. `getrand_ranges`: `GetRand(0) == 0`, `GetRand(1) == 0`; `GetRand(n) < n`
   for n in {2, 3, 7, 1000, 2^32, 2^63+1, UINT64_MAX} (100 draws each);
   every value of `GetRand(10)` appears in 1000 draws (miss probability
   10·0.9^1000 < 1e-44); same for `GetRandInt` (0, 1, 10, INT_MAX).
   Negative `GetRandInt` arguments are outside the contract and not tested
   (only `DoS_tests.cpp:96` passes one, `0xffffffff`; known issue recorded).
2. `getrandbytes_and_hash`: `GetRandBytes` overwrites a zeroed 64-byte
   buffer (some byte non-zero; P(all zero)=2^-512) and leaves a canary
   after `num` untouched; two `GetRandHash()` differ and are non-null.
3. `strongrandbytes_no_repeats`: 1,000,000 calls of
   `GetStrongRandBytes(buf, 32)`; the first 16 bytes of every output are
   collected, sorted, and must be pairwise distinct (birthday bound
   n²/2^129 ≈ 1.5e-27). Also checks that no output is all-zero.
4. `strongrandbytes_lengths_and_threads`: `num` = 0, 1, 16, 31, 32 writes
   exactly `num` bytes (canary after them unchanged); 4 threads × 10,000
   calls give 40,000 distinct outputs (the state update is under
   `cs_rng_state`).
5. `fastrandom_known_answers`: `FastRandomContext(true)` is ChaCha20 with a
   zero key: the first `rand64()` is `0x903df1a0ade0b876` (RFC 7539 A.1 test vector #1:
   keystream `76b8e0ad…`), then `rand32()`, `randbits(3)`,
   `rand256()`, `randbytes(17)` (which starts a new ChaCha20 block – a
   partial `Output` discards the rest of its block) and `rand64()` have
   fixed values; a context seeded with bytes 0x00..0x1f has a fixed first
   `rand64()` and `randbytes(32)`. Expected values computed with an
   independent Python ChaCha20 model (log). This pins the stream that the
   deterministic test helpers (`SeedInsecureRand(true)`) rely on.
6. `fastrandom_seeded`: two contexts with the same `uint256` seed produce the
   same mixed sequence; different seeds and seeded vs. `fDeterministic`
   differ; `FastRandomContext(uint256())` equals `FastRandomContext(true)`
   (`SeedInsecureRand(true)` relies on it); `randbits(0) == 0`, `randrange(1) == 0`, `randbits(64)` works,
   `randbytes(0)` is empty, `randbool()` produces both values.
7. `osrand_and_devurandom`: `GetOSRand` and the `/dev/urandom` fallback
   `GetDevURandom` (non-static in `random.cpp`, declared `extern` in the
   test; not in `random.h`) fill all 32 bytes (each byte seen non-zero within
   64 calls, as `Random_SanityCheck` does) and two calls differ.
8. `seed_functions`: `RandAddSeed`, `RandAddSeedPerfmon`, `RandAddSeedSleep`
   run, and `GetRandBytes`/`GetStrongRandBytes` still produce differing
   output afterwards (smoke: they must not break the generator).
9. `byte_distribution_chisquare`: for `GetRandBytes`, `GetStrongRandBytes`,
   `GetOSRand` and a randomly seeded `FastRandomContext`, 262,144 bytes each
   (1024 expected per value), chi-square over 256 bins (df 255) must lie in
   [124, 450]. For a correct generator the asymptotic chi-square
   distribution gives P(X > 450) = 5.8e-13 and P(X < 124) = 2.3e-13
   (regularized incomplete gamma, computed in Python; see Log), so the
   whole case fails falsely with probability ≈ 3.2e-12 – three orders of
   magnitude below 1e-9, which leaves room for the error of the asymptotic
   approximation at 1024 expected counts per bin. The lower bound catches
   "too uniform" output such as a byte counter.

**Edge cases.** Both builds (no chain-parameter dependence; same results);
`-O0 --coverage` builds (slower – runtime measured); CPUs without RDRAND
(`GetHWRand` false: tests do not depend on it); kernels without
`getrandom` (the fallback is tested directly); Boost 1.58 (only
`BOOST_CHECK`, `BOOST_CHECK_EQUAL`, `BOOST_REQUIRE`); `GetStrongRandBytes`
with `num > 32` asserts and with `num < 0` would `memcpy` a negative size –
not tested (abort/UB), noted as known issue; `RandFailure` (abort) is not
testable in-process and stays uncovered.

**How to test.**

| Criterion | Test / command | Expected |
|---|---|---|
| contracts pinned | `test_bitcoin --run_test=random_tests` | 12/12 cases pass, < ~10 s |
| random.cpp ≥ 90 % lines | `build.sh --coverage` mainnet + lowdiff + `--coverage-report` | ≈ 151/162 = 93 % lines, 21/22 functions |
| no regressions | `build.sh --config mainnet --unit`; `--config lowdiff --unit --functional` | 390/390; 390/390 + 48/48 |
| gate | CI coverage job on the branch | green with the ratcheted minimums |

**Risks.** None for consensus (test code only). Flakiness: every
probabilistic check has a documented bound < 1e-9 per run. Runtime: 1M
`GetStrongRandBytes` (getrandom syscall + `RAND_bytes` + SHA-512 each) is
measured; reduced with a documented justification if it is too slow.

## Implementation plan

1. Write cases 1-9 (in threads, collect results and check them in the main
   thread – Boost.Test assertions are not thread-safe) in `src/test/random_tests.cpp` (keep the 3 existing
   cases unchanged); helper `ChiSquare256(const std::vector<unsigned
   char>&)`. Verify: builds in the mainnet build; `--run_test=random_tests`
   passes; per-case time with `--report_level=detailed`/`--log_level=
   test_suite`.
2. Measure runtime of `strongrandbytes_no_repeats` in the normal and the
   coverage build; adjust if it exceeds a few seconds (with a comment).
3. Code review (self-review, no Agent tool) of the diff.
4. Full runs: `build.sh --config mainnet --unit`, `--config lowdiff --unit
   --functional`.
5. Coverage: `build.sh --config mainnet --coverage --unit`, `--config
   lowdiff --coverage --unit`, `--coverage-report`; ratchet the `random.cpp`
   gate with the `--suggest` values.
6. Docs: test counts (CLAUDE.md, contrib/testing/README.md, the skill,
   doc/architecture.md); plan 0.2i / 0.10 note on what is pinned and the
   measured coverage; known issues (negative `GetRandInt`/
   `GetStrongRandBytes` arguments). No logging change: tests only, no new
   node behaviour (CLAUDE.md rule 5 n/a).
7. Doc review, task to done, commit, push, PR, CI.

## Log

- 2026-10-03 step 0: picked up; dependency P0-01 done; branch `task/P0-21-randomness-tests`.
- 2026-10-03 steps 1-2: task verified against the code (see Detailed
  description); detailed description written. ChaCha20 model checked
  against RFC 7539 (zero key block 0 = `76b8e0ada0f13d90…`).
- 2026-10-03 step 3, self-review (no Agent tool) of the description:
  (a) seeded-with-zero equals `fDeterministic` – added as a pinned
  contract instead of "seeded vs deterministic differ"; (b) chi-square
  bounds at 1e-10 per tail rely on the asymptotic distribution at the
  extreme tail – tightened to [124, 450] (≈ 3e-12 total) for margin;
  (c) Boost.Test checks from worker threads are not thread-safe – collect
  and check in the main thread. All applied.
- 2026-10-03 step 4-5: implementation plan written; self-review (no Agent
  tool): order is fine (measure runtime before the full runs, coverage
  last so the gate uses the final tests); no consensus impact; no logging
  needed (test code only). Nothing left out.
- 2026-10-03 step 6: 9 new cases in `src/test/random_tests.cpp` (12 in the
  suite). Runtime of `random_tests`: 3.2 s in the normal build (1M
  `GetStrongRandBytes` 2.7 s), 28 s in the `-O0 --coverage` build (1M calls
  25.7 s). Kept at 1M as the task asks; the coverage job takes ~15 min, so
  this adds ~3 %. 200 repeated runs of the probabilistic cases: 0 failures.
- 2026-10-03 step 7, code review: the forked `code-review` skill reviewed the
  wrong checkout (`/home/user/yacoin`, P0-01 commits) and gave nothing for
  this diff; its two findings (`build.sh` `--sanitizers` rejects hyphens,
  relative `YACOIN_CA_BUNDLE`) concern `build.sh`, not this task – not
  applied here. Self-review (no Agent tool) of the diff: thread results are
  checked in the main thread; every probabilistic check has a stated bound;
  Boost 1.58 compatible (only `BOOST_CHECK`, `BOOST_CHECK_EQUAL`,
  `BOOST_CHECK_MESSAGE`, `BOOST_REQUIRE`); no warnings from the file in
  the build log. Nothing left open.
- 2026-10-03 step 8: `build.sh --config mainnet --unit` exit 0, 390/390;
  `--config lowdiff --unit --functional` exit 0, 390/390 and 48/48.
  Coverage (`--coverage --unit` both configs, `--coverage-report`):
  `random.cpp` 150/162 lines (92.59 %), 21/22 functions (95.45 %; only
  `RandFailure` – abort – is not run). Still uncovered: `RandFailure`,
  `GetHWRand` `return false` (:128, the CPU has RDRAND), the failure
  branches :187/193-194/224/229/231/277 and :405 (gcov attributes the
  closing brace of `randbytes` oddly; `randbytes(0)` is called). Gate
  ratcheted with `--suggest`: lines 85 → 92, functions 90 → 94. (The local
  report had no lowdiff functional coverage, so other gates were low there;
  CI runs the full set.)
- 2026-10-03 step 9-10: docs updated (test counts 381 → 390 in CLAUDE.md,
  contrib/testing/README.md, the skill, doc/architecture.md; plan 0.2i;
  known issue "RNG: no argument checks for negative sizes"). Self-review (no
  Agent tool) of the docs against code and results: found that
  `DoS_tests.cpp:96` does pass `GetRandInt(0xffffffff)` (= -1) – the
  known-issue text and the description were corrected.
- 2026-10-03 step 11: committed f0669cc, merged origin/master (9d742d4), PR https://github.com/dev34253/yacoin/pull/83.
- 2026-10-03: merged origin/master again (P0-22: 388 unit tests; P0-64);
  counts resolved to 397 (388 + 9). Re-run after the merge: mainnet
  `--unit` exit 0, 397/397; lowdiff `--unit --functional` exit 0, 397/397
  and 48/48; all 4 vector checks ok.
