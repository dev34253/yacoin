# P0-58: Static analysis baseline and "no new findings" gate

- Plan section: 0.4
- Depends on: P0-01, P0-44
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Run modern static analysis on the C/C++ code, record today's findings as a baseline, and fail CI on any **new** finding in changed code (decision by the owner, 2026-10-02).

## Steps

1. **clang-tidy** with a curated check set in `.clang-tidy`: `bugprone-*`, `cert-*`, `performance-*`, `concurrency-*`, `misc-*`, `clang-analyzer-*` (exclude `modernize-*`, `readability-*`, `fuchsia-*`, `llvmlibc-*` for now). Generate `compile_commands.json` from the P0-01 build (e.g. `bear -- make`).
2. **Clang Static Analyzer** via `scan-build make` on the same configuration.
3. **cppcheck** (`--enable=warning,performance,portability --inline-suppr`, using `compile_commands.json`).
4. **CodeQL** (GitHub `codeql-action`, C/C++ `security-and-quality` suite) as a workflow in the P0-44 CI skeleton.
5. Exclude third-party code: `src/leveldb`, `src/secp256k1`, `src/univalue`, `src/crypto/ctaes`, `src/scryptjane`, `depends/`.
6. Record the baseline per tool (finding id, file, line-independent fingerprint) under `contrib/static-analysis/baseline/`, with a script that compares a new run to the baseline and fails on new findings only.
7. Triage the baseline: findings in consensus code (pow, kernel, chain, validation, bignum, tokens, script) get a note and, where relevant, a Phase 0 test that pins the current behaviour – no fixes in Phase 0. Obvious non-consensus bugs get follow-up tasks.
8. Add a local command (e.g. `contrib/static-analysis/run.sh --changed`) and reference it in CLAUDE.md ("run static analysis on changed files before commit").

## Acceptance criteria

- [ ] All four tools run in CI (clang-tidy, scan-build, cppcheck on push for changed files or nightly in full; CodeQL on push).
- [ ] Baseline committed; CI fails on new findings and passes on the baseline.
- [ ] Local script works in the build image and is documented in CLAUDE.md and `contrib/static-analysis/README.md`.
- [ ] Baseline triage summary in Log (counts per tool and severity; consensus-code findings listed).

## Notes

GCC `-fanalyzer` is optional (strong for C, limited for C++). Sanitizers are P0-29; ThreadSanitizer is worth adding there before the Phase 2 Boost/thread changes.

## Log

-
