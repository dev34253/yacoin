# P0-61: build.sh: per-work-dir port range, unit summary check, vector checkers

- Plan section: 0.1
- Depends on: P0-01
- Size: S
- Owner:
- Started:
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
   `contrib/testing/reward_vectors.py` (P0-46, check mode); a mismatch fails
   the run. They then run in CI through the existing unit jobs.

## Acceptance criteria

- [ ] Two concurrent `build.sh --config lowdiff --functional` runs in different
      work dirs both pass (46/46 each).
- [ ] A single run behaves as before.
- [ ] A unit run without a Boost summary makes `build.sh` exit non-zero.
- [ ] `build.sh --unit` runs both vector checkers; a modified vector file fails it.

## Notes

-

## Log

-
