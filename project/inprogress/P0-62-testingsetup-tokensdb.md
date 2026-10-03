# P0-62: TestingSetup creates the token database (and a usable test CConnman)

- Plan section: 0.2
- Depends on: P0-16
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Unit tests that reorganise the chain or inject P2P messages work with the
shared test setup, without per-test workarounds (open question Q7, answered
by the owner on 2026-10-03).

## Steps

1. `src/test/test_bitcoin.cpp` `TestingSetup`: create an in-memory token
   database, `ptokensdb = new CTokensDB(<cache>, true /* fMemory */)`, next to
   `pblocktree`/`pcoinsdbview`, and delete it (and reset the pointer) in the
   destructor in the right order. Today `ptokensdb` stays `nullptr`, so any
   reorg in a unit test crashes in `DisconnectBlock`
   (`validation.cpp:1322`, `ptokensdb->ReadBlockUndoTokenData`).
2. The test `CConnman` is never started, so its send-buffer limit is 0, every
   queued message sets the peer's `fPauseSend` and `ProcessMessages` skips the
   receive queue. Give the test connman a usable limit (or an equivalent
   fix in the shared test setup) so injected messages are processed.
3. Remove the workarounds in `src/test/chain_trust_tests.cpp` (P0-16: its own
   in-memory `CTokensDB` in the regtest fixture, clearing `fPauseSend` in the
   test peer) and update `src/test/README.md`.
4. Test code only – no node code changes.

## Acceptance criteria

- [ ] A unit test that reorganises the chain passes without its own token DB.
- [ ] P0-16's tests pass without the workarounds; all unit and functional tests pass.

## Notes

Needed by later tests with reorgs or P2P messages (e.g. P0-17, P0-18, P0-25).

## Log

-
