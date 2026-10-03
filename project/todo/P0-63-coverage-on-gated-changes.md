# P0-63: Coverage gate on changes to gated files; two more logging exclusions

- Plan section: 0.1, 0.9
- Depends on: P0-04
- Size: S
- Owner:
- Started:
- Finished:

## Goal

A push that changes consensus code covered by the coverage gate is checked
before it is merged, without slowing down other pushes (open question Q11,
answered by the owner on 2026-10-03).

## Steps

1. `.github/workflows/tests.yml`: run the coverage jobs and "coverage report
   (merged)" (with the gate) also on pushes whose changes touch a gated file
   or the gate itself: the `paths` of the `[[gate]]` entries in
   `contrib/testing/coverage-gates.toml` (today `src/pow.cpp`, `src/chain.cpp`,
   `src/kernel.cpp`, `src/validation.cpp`, `src/consensus/tx_verify.cpp`,
   `src/consensus/consensus.cpp`, `src/bignum.h`, `src/wallet/crypter.cpp`,
   `src/random.cpp` – check the config), `contrib/testing/coverage-gates.toml`,
   `contrib/testing/coverage_gate.py` and `contrib/testing/build.sh`. Keep
   master and *Run workflow* as today. Choose a mechanism that sees the
   changed files of the push (e.g. a small job computing the matrix with
   `git diff` against the merge base with `master`, or `dorny/paths-filter`
   pinned by SHA) and document it.
2. `contrib/testing/coverage-gates.toml`: exclude the `if (fPrintProofOfStake)`
   logging in `kernel.cpp` (around line 485) and the `-printcreation`
   logging in `GetProofOfWorkReward` (validation.cpp), like the existing
   `fDebug` blocks; re-run the gate and ratchet the affected minimums with
   `--suggest`.
3. Docs: `contrib/testing/README.md` (CI table: when the coverage jobs run),
   `CLAUDE.md` CI bullet.

## Acceptance criteria

- [ ] A push that changes a gated file runs the coverage jobs and the gate; a
      docs-only push does not (show both runs).
- [ ] The two logging blocks are excluded; the gate passes; actionlint clean.

## Notes

Touches `.github/workflows/`: implement from a session whose token has the
`workflow` scope.

## Log

-
