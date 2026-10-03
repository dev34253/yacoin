# P0-61: build.sh: per-work-dir port range, unit summary check, vector checkers

- Plan section: 0.1
- Depends on: P0-01
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Two `contrib/testing/build.sh --functional` runs on one machine must not collide
on ports (open question Q4, answered by the owner on 2026-10-03: per-work-dir
port range).

## Steps

1. Reproduce: with `HTTPS_PROXY` set, `build.sh` runs Docker with
   `--network host`; two concurrent functional runs in different work dirs
   fail with "Unable to start HTTP server" (seen while merging #52).
2. Give each work dir its own port range, e.g. derive the test framework's
   `--portseed` (see `test/functional/test_framework/util.py` `PortSeed`,
   `p2p_port`/`rpc_port`) from a hash of the work dir, passed through
   `test_runner.py`; make sure the ranges of `-j4` workers in one run still do
   not overlap and stay below 65535.
3. Remove the `flock /root/.cache/yacoin-functional.lock` workaround from the
   docs/instructions once concurrent runs work; document the behaviour in
   `contrib/testing/README.md`.

4. (Q8, owner 2026-10-03) `build.sh --unit` fails when `unit.log` has no
   Boost "N test cases out of N passed" summary (e.g. `test_bitcoin` exited
   early with status 0); the `Shutdown(void*)` stub in
   `src/test/test_bitcoin_main.cpp` exits with failure like the
   `StartShutdown()` stub (P0-20).
5. (Q8) Fix the functional framework docstring about the cache chain
   (`test/functional/test_framework/test_framework.py`): 40 blocks mined with
   `-epochinterval=20`, not 199. Do not change the cache chain itself.

6. (Q10, owner 2026-10-03) `build.sh --unit` also runs the independent
   vector checkers `contrib/testing/bignum_vectors_check.py` (P0-13) and
   `contrib/testing/reward_vectors.py` (P0-46, check mode), and
   `contrib/testing/header_hash_vectors.py` (P0-19, default check: model
   self-test plus N-factor ≤ 12 in Python, about 4 s); a mismatch fails
   the run. They then run in CI through the existing unit jobs.

## Acceptance criteria

- [ ] Two concurrent `build.sh --config lowdiff --functional` runs in different
      work dirs both pass (46/46 each).
- [ ] A single run behaves as before.
- [ ] A unit run without a Boost summary makes `build.sh` exit non-zero.
- [ ] `build.sh --unit` runs the three vector checkers; a modified vector file fails it.

## Detailed description

**Checked against the code (step 1).** `util.py:266-306`: p2p port =
`PORT_MIN + n + (12*seed) % 4987`, rpc port = the same `+ 5000`;
`PORT_MIN` comes from `TEST_RUNNER_PORT_MIN` (default 11000).
`test_runner.py:569` gives each test `--portseed=len(remaining tests)`, so
the N tests of one run use seeds 0..N-1 and ports `PORT_MIN + [0, 12N]` and
`PORT_MIN + 5000 + [0, 12N]` (N = 46 today: offsets <= 552). Every run
uses the same seeds, so two runs collide whenever both use 11000. The
container side of `build.sh` always sees `WORK_DIR=/work`, so anything
derived from the work dir has to be computed on the host side.
`feature_getrpcinfo.py:25` hardcodes `16000` (= default `PORT_MIN` + 5000):
it would fail with any other `PORT_MIN`. The flock workaround of Q4 is in
no repository document (only in agent prompts, Q4 itself and old task logs,
which stay as history). `test_bitcoin_main.cpp:16`: `Shutdown(void*)` exits
`EXIT_SUCCESS`. `test_framework.py:530` says "199-block-long chain"; the
code mines 4 x 10 = 40 blocks with `initialize_datadir(..., 20)`
(`-epochinterval=20`), the test nodes then get 10. Checkers:
`bignum_vectors_check.py` (no args, 0.5 s), `reward_vectors.py --check`
(0.04 s), `header_hash_vectors.py --check` (3.9 s, 31 vectors in Python,
28 above N-factor 12 reported as not checked, not a failure); all exit 1 on
a mismatch, standard library only.

**Scope.** `contrib/testing/build.sh`, `contrib/testing/README.md`,
`test/functional/feature_getrpcinfo.py` (use `rpc_port(0)`),
`test/functional/test_framework/test_framework.py` (docstring only),
`src/test/test_bitcoin_main.cpp` (`Shutdown` stub). Not changed: the port
formula in `util.py`, `test_runner.py`, the cache chain, CI workflows, node
code. Deviation from step 2: instead of deriving `--portseed` (which
`test_runner.py` assigns per test, and whose `% 4987` wrap leaves only ~415
non-overlapping seed positions) `build.sh` sets the existing
`TEST_RUNNER_PORT_MIN`; no `test_runner.py` change is needed.

**Behaviour.**
1. *Port slots.* With `--functional`, the host side of `build.sh` claims
   one of 10 port slots. Slot k (block b = k / 5, position p = k % 5) has
   `PORT_MIN = 11000 + 10000*b + 1000*p`: p2p ports `[PORT_MIN,
   PORT_MIN+1000)`, rpc ports `[PORT_MIN+5000, PORT_MIN+6000)`. Blocks are
   11000-20999 and 21000-30999, so all slots are disjoint (a slot's p2p
   window never meets another slot's rpc window) and below the Linux
   ephemeral range (32768). The preferred slot is `cksum(work dir) % 10`;
   the slot is held with `flock` on `/tmp/yacoin-build-ports/slot-<k>.lock`
   (`YACOIN_PORT_LOCK_DIR` overrides the directory) for the whole run
   (inherited by `exec docker`, like the work dir lock); if it is taken,
   the next free slot is used; if all 10 are taken, the run waits for its
   preferred slot. The value goes to the container side as the internal
   option `--port-min N`, which exports `TEST_RUNNER_PORT_MIN`. The log
   shows slot, p2p and rpc ranges. Example: work dir A -> slot 3 ->
   p2p 14000-14999, rpc 19000-19999.
2. *Override.* If `TEST_RUNNER_PORT_MIN` is set in the caller's
   environment, it is used as is (no slot, no lock), validated as an
   integer 1024..55535.
3. *Unit summary.* After `test_bitcoin`, `build.sh` requires a line
   `N test cases out of N passed` (or `1 test case out of 1 passed`) in
   `unit.log`; otherwise it prints "unit tests: no '... out of ... passed'
   summary for all test cases in unit.log" and the run exits 1, even if
   `test_bitcoin` exited 0. The stub `Shutdown(void*)` prints a message to
   stderr and exits `EXIT_FAILURE`, like `StartShutdown()`.
4. *Vector checkers.* With `--unit`, after `test_bitcoin`, `build.sh` runs
   `bignum_vectors_check.py`, `reward_vectors.py --check` and
   `header_hash_vectors.py --check` from the source copy, output to
   `<builddir>/vectors.log`, prints each checker's result line and exit
   code; any non-zero exit makes the run exit 1. Both configurations run
   them (~4.5 s; they do not depend on the configuration), so CI runs them
   in the existing unit jobs.
5. *Docstring.* `_initialize_chain` says 40 blocks mined with
   `-epochinterval=20` (test nodes then run with 10).

**Edge cases.** One run alone: gets its preferred slot; with the
default `PORT_MIN` no longer 11000 for most work dirs, so a manual
`test_runner.py` run (11000) and a `build.sh` run only collide if the
work dir hashes to slot 0 and slot 0 is free (documented). Slot width 1000
holds runs of up to 83 tests (12N < 1000); more tests (e.g. `--extended`
in the future) would spill into the next slot – documented. Stale lock
files are harmless (flock is released when the process exits; the file
stays). Lock dir created by another user: dir is made mode 1777, files
are opened read-only for `flock` (works on Linux), a slot whose file cannot
be opened is skipped; if none can be opened, the run fails with a message.
`--no-docker` (CI): the lock is held by the exec'd inner script. A
`TEST_RUNNER_PORT_MIN` value outside 1024..55535 or non-numeric: error.
Functional run without `--functional`: no slot. `--coverage-report`: no
slot, no checkers. `unit.log` with failures (`344 test cases out of 345
passed`) already fails through the exit code; the summary check also
catches it. Python 3.12 in the image: checkers use only the standard
library.

**How to test.**
- Concurrent runs: two `build.sh --config lowdiff --functional` in two
  work dirs at the same time (under the shared functional lock so other
  agents wait): both exit 0, `ALL ... Passed` 46/46, logs show different
  slots. Before the change (reproduction): the same pair with
  `TEST_RUNNER_PORT_MIN` both 11000 shows the collision.
- Single run: `build.sh --config mainnet --unit` and `build.sh --config
  lowdiff --unit --functional`: 345/345, 345/345, 46/46, checkers OK.
- Summary check: temporarily (not committed) make one unit test call
  `exit(0)`; `build.sh --config mainnet --unit` exits 1 with the message.
- Checkers: temporarily modify one value in `reward_vectors.json` (and
  separately check the other two by running the checker on a modified
  copy); `build.sh --unit` exits 1 naming the checker.
- `bash -n`, `shellcheck` if available, on `build.sh`.

**Risks.** No node/consensus code; the only C++ change is the test stub.
Port slots in 21000-30999 could meet other local services (rare; override
with `TEST_RUNNER_PORT_MIN`).

## Implementation plan

1. `src/test/test_bitcoin_main.cpp`: `Shutdown` prints to stderr and exits
   `EXIT_FAILURE`. Verify: builds, 345/345.
2. `test_framework.py` docstring; `feature_getrpcinfo.py`: `expected =
   rpc_port(0)` (import `rpc_port`), assert node 1 = `rpc_port(1)`.
   Verify: functional run with non-default `PORT_MIN` passes the test.
3. `build.sh` host side: `claim_port_slot` (only with `--functional`),
   internal `--port-min`, log line; usage text. Verify: `bash -n`; two
   runs pick different slots; a run waits/moves when its slot is held
   (manual `flock` on a slot file).
4. `build.sh` container side: export `TEST_RUNNER_PORT_MIN` for
   `test_runner.py`; log it.
5. `build.sh` unit block: summary check; `run_vector_checkers` writing
   `vectors.log`. Verify with the temporary modifications above.
6. README: "What it does" (port slot, summary check, checkers),
   "Concurrent runs" paragraph replacing the need for an external lock,
   checker sections say they run in `--unit`; options/env table
   (`TEST_RUNNER_PORT_MIN`, `YACOIN_PORT_LOCK_DIR`).
7. Tests (step 8), docs review, merge `origin/master`, PR.

## Notes

-

## Log

- 2026-10-03 step 0-1: task picked up (P0-01 done); claims checked against
  the code (see "Detailed description"); found `feature_getrpcinfo.py`
  hardcoding the default port base, and that the flock workaround is in no
  repository doc (only Q4 and old task logs, left as history).
- 2026-10-03 step 3 (self-review, no Agent tool): description re-read
  against `util.py`, `test_runner.py`, `test_framework.py` and the Boost
  output in `unit.log`. Added: slot width vs. test count limit (83), the
  `TEST_RUNNER_PORT_MIN` override, lock dir permissions, ephemeral range;
  checked that no other functional test uses literal local ports
  (`feature_defaultport.py` only connects to remote addresses).
- 2026-10-03 step 5 (self-review, no Agent tool): plan checked for
  ordering (stub first so the build starts early) and testability (fake
  `docker` on `PATH` to test slot claiming without building). Deviation
  from step 2 kept: `TEST_RUNNER_PORT_MIN` instead of a derived
  `--portseed` (reason in the description).
- 2026-10-03 step 6: slot claiming tested with a fake `docker`: work dir
  lock still rejects a second run in the same dir; a held preferred slot
  (8) moves the run to slot 9; with all 10 held the run waits for its
  slot (3 s) and then takes it; `TEST_RUNNER_PORT_MIN=12345` is passed as
  is, `99999` is rejected; `--unit` alone claims no slot.
- 2026-10-03 step 7 (`code-review` skill, medium): (1) `create_cache.py`
  ran without `--portseed`, so with `-j4` the cache node used the process
  id as seed and could bind ports anywhere in `PORT_MIN + 0..9998`, i.e.
  in another slot – fixed: `test_runner.py` passes `--portseed=N` (N =
  number of tests; the tests use 0..N-1). (2) README not updated yet –
  done in step 9 (planned). `shellcheck`: no new findings (the
  pre-existing SC2015 infos only).
- 2026-10-03 step 8 (base 086a431 + this change; logs in
  `/root/.cache/yacoin-build-P0-61/p061-*.out`): `build.sh --config
  mainnet --unit` exit 0, **345/345**, the three checkers ok (bignum 100000
  vectors 0 disagree; reward 226/79/60/18 rows agree; header hash 31
  vectors in Python, 28 above N-factor 12 not checked); `--config lowdiff
  --unit` exit 0, **345/345**, checkers ok.
- 2026-10-03 negative test (temporary, not committed): a unit test calling
  `exit(0)` plus one changed value in `reward_vectors.json`:
  `test_bitcoin` exit 0 without a summary -> "unit tests: no 'N test
  cases out of N passed' summary"; `reward_vectors.py --check: FAILED`
  (line 7 differs); `build.sh` exit 1. The other two checkers exit 1 on a
  modified copy (`bignum_vectors_check.py`: 1 disagree; `header_hash_vectors.py
  --check`: FAIL).
- 2026-10-03 concurrent functional runs (held
  `/root/.cache/yacoin-functional.lock` around the pair so other agents
  waited; work dirs `/root/.cache/yacoin-build-P0-61` and `…-P0-61-b`,
  `--network host` through the proxy). Reproduction (step 1) with both at
  `TEST_RUNNER_PORT_MIN=11000`: both exit 1, 14 and 19 tests failed.
  With port slots: slot 5 (p2p 21000-21999, rpc 26000-26999) and slot 7
  (23000-23999 / 28000-28999), both exit 0, **46/46** each
  (`feature_getrpcinfo.py` passes with the non-default port base).
- 2026-10-03 step 10 (documentation self-review, no Agent tool): README
  re-read against `build.sh` and the runs above; fixed "runs on the host,
  not in the build image" for the bignum checker and the header-hash note
  that only the checks above N-factor 12 stay manual.
