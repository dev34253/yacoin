# P0-34: Functional test: shutdown and filesystem behaviour

- Plan section: 0.5
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Catch Boost thread and filesystem regressions (Phase 2 risk).

## Steps

1. Repeated start/stop; stop during sync, reindex and mining; SIGTERM; clean exit within time limits.
2. backupwallet onto an existing file (fs::copy_option::overwrite_if_exists, wallet/db.cpp:715).
3. Relative and trailing-slash paths for -datadir, -conf, -pid, -walletdir (path::is_complete, util.cpp:771,831; rpc/protocol.cpp:77).

## Acceptance criteria

- [ ] test/functional/feature_shutdown.py (and a paths test) pass reliably, 10/10 runs.

## Notes

Review: B8.

## Log

-
