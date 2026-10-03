# P0-61: Per-work-dir port range for functional tests in build.sh

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

## Acceptance criteria

- [ ] Two concurrent `build.sh --config lowdiff --functional` runs in different
      work dirs both pass (46/46 each).
- [ ] A single run behaves as before.

## Notes

-

## Log

-
