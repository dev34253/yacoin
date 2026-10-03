# P0-62: TestingSetup creates the token database (and a usable test CConnman)

- Plan section: 0.2
- Depends on: P0-16
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

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

- [x] A unit test that reorganises the chain passes without its own token DB.
- [x] P0-16's tests pass without the workarounds; all unit and functional tests pass.

## Notes

Needed by later tests with reorgs or P2P messages (e.g. P0-17, P0-18, P0-25).

## Detailed description

Verified against the code (master 6859321):

- `TestingSetup` (`src/test/test_bitcoin.cpp:73-112`) creates `pblocktree`,
  `pcoinsdbview`, `pcoinsTip` and `ptokens`, but not `ptokensdb`
  (`validation.cpp:92`, null by default). `DisconnectBlock` dereferences it
  unconditionally (`validation.cpp:1322`), and so do `ConnectBlock` when a
  block has token undo data (`validation.cpp:2062`) and
  `CTokensCache::DumpCacheToDatabase` (`tokens/tokens.cpp:1408ff`).
- The test `CConnman` is constructed but never `Init`/`Start`ed, so
  `nSendBufferMaxSize` stays 0 (`net.cpp:2234`); `PushMessage` sets
  `fPauseSend` as soon as anything is queued (`net.cpp:2868-2869`), and
  `ProcessMessages` returns without processing while `fPauseSend` is set.
  `nReceiveFloodSize` is 0 as well (used for `fPauseRecv`).
- P0-16 works around both in `src/test/chain_trust_tests.cpp`:
  `RegtestConsensusSetup` installs its own in-memory `CTokensDB`
  (lines 545-562) and `TestPeer::Receive` clears `fPauseSend` (lines
  744-748). `src/test/README.md` ("Two pitfalls of `TestingSetup`")
  documents them.
- The task file's facts are correct. `CConnmanTest` is a friend of
  `CConnman` (`net.h:444`), so the test setup can set the buffer limits
  without a node code change.

**Scope.** Test code and docs only (no node code change, no consensus
change):

- `src/test/test_bitcoin.{h,cpp}`: `TestingSetup` creates
  `ptokensdb = new CTokensDB(1 << 20, true /* fMemory */)` right after
  `pcoinsTip` (before `LoadGenesisBlock`/`ActivateBestChain`, which may
  connect blocks) and, in the destructor, deletes it after
  `UnloadBlockIndex()` next to `pblocktree` and sets `ptokensdb = nullptr`
  so a later fixture (or a `BasicTestingSetup` test) never sees a dangling
  pointer. New `CConnmanTest::SetBufferSizes(nSendBufferMaxSize,
  nReceiveFloodSize)`; `TestingSetup` calls it with the node defaults
  `1000 * DEFAULT_MAXSENDBUFFER` / `1000 * DEFAULT_MAXRECEIVEBUFFER`
  (the values `init.cpp:1530-1531` passes without `-maxsendbuffer`/
  `-maxreceivebuffer`).
- `src/test/chain_trust_tests.cpp`: remove both workarounds; the regtest
  fixture only requires that `ptokensdb` is set; `TestPeer::Receive`
  requires `!fPauseSend` instead of clearing it (this pins the fix).
  `TestPeer::ClearSent` keeps resetting `fPauseSend` together with
  `nSendSize`: it emulates the socket having sent the queue, which is what
  `net.cpp:865` does – not a workaround.
- One new unit test case pinning the contract (see "How to test").
- Docs: `src/test/README.md` (replace the pitfalls paragraph with a
  description of what `TestingSetup` provides), test-count lines (341 ->
  342) in `CLAUDE.md`, `contrib/testing/README.md`, the implement-task
  skill; `doc/architecture.md` if it mentions test setup (it does not).
- Not in scope: `ptokensCache` (still null in tests; the code paths using
  it check it), the other globals the destructor deletes without resetting
  (`pcoinsTip`, `pblocktree`, `ptokens` – recorded in
  `project/known-issues.md`), starting the connman threads.

**Behaviour.** Every test using `TestingSetup` (and `TestChain100Setup`,
`ConsensusTestingSetup`) has an empty in-memory token DB; a reorg works
without per-test setup; a message delivered to a test peer with
`ProcessMessages` is processed as long as the peer's send queue is below
1 MB. `BasicTestingSetup` tests are unchanged (`ptokensdb` stays null).

**Edge cases.**
- Side effects on existing tests now that `ptokensdb` is non-null:
  `FlushStateToDisk` writes the (empty) reissued-mempool state
  (`validation.cpp:2236`) into the memory DB; `rpc/tokens.cpp` RPCs no
  longer throw "token db unavailable" (no unit test calls them);
  `tokens.cpp:2057/2142` also need `ptokensCache`, still null – unchanged.
- Each `CTokensDB` with `fMemory` has its own LevelDB `MemEnv`
  (`dbwrapper.cpp:103-105`), so no state leaks between fixtures and nothing
  is written to `pathTemp`; the path is still built from `-datadir`, so it
  must be created after `ForceSetArg("-datadir")` (it is).
- `DoS_tests/stale_tip_peer_management` calls `connman->Init(options)`,
  which sets both buffer sizes back to 0 for the rest of that case; it does
  not call `ProcessMessages`, so this is harmless (documented).
- A send queue above 1 MB still pauses the peer, as in the node.
- Both builds (mainnet, low difficulty): the change is parameter-independent;
  regtest and main fixtures both get the DB.
- Destructor order: threads stopped, background callbacks flushed, connman
  and peer logic gone and block index unloaded before the token DB is
  deleted; nothing touches `ptokensdb` after that.

**How to test.**
- AC1 (reorg without own token DB): `chain_trust_fork_choice_tests/
  fork_choice_by_trust` reorganises twice (A -> B -> A) with the fixture's
  own DB removed; must pass in both builds.
- AC2: `chain_trust_p2p_tests/*` pass with `Receive` requiring
  `!fPauseSend`; all unit tests 342/342 in both builds (`build.sh --config
  mainnet --unit`, `--config lowdiff --unit --functional`), functional
  46/46, `build.sh` exit 0.
- New case `chain_trust_fork_choice_tests/testingsetup_token_db_and_buffers`
  (no fixture): construct a `TestingSetup(REGTEST)`, check `ptokensdb` is
  set, write and read back token undo data, check a test peer's
  `fPauseSend` stays false after a message is queued (send buffer > 0) and
  is set beyond 1 MB; destroy it and check `ptokensdb == nullptr` and
  `g_connman == nullptr`; construct a second one and check the DB is empty
  (the data written by the first is gone).

**Risks.** None for consensus (no node code touched). Risk of changing other
tests' behaviour through the now non-null `ptokensdb`: covered by running
the full unit suite in both builds.

## Implementation plan

1. `src/test/test_bitcoin.h`: declare `CConnmanTest::SetBufferSizes(unsigned
   int nSendBufferMaxSize, unsigned int nReceiveFloodSize)` with a comment.
2. `src/test/test_bitcoin.cpp`: implement it (on `g_connman`); include
   `net.h`, `tokens/tokendb.h`; create `ptokensdb` after `pcoinsTip`; call
   `SetBufferSizes(1000 * DEFAULT_MAXSENDBUFFER, 1000 *
   DEFAULT_MAXRECEIVEBUFFER)` after creating `g_connman`; destructor:
   `delete ptokensdb; ptokensdb = nullptr;` after `delete pblocktree`.
   Comments explain why (reorgs, `fPauseSend`).
3. `src/test/chain_trust_tests.cpp`: drop `tokensdb` member, ctor/dtor
   workaround, `tokens/tokendb.h` include if unused; `BOOST_REQUIRE(ptokensdb
   != nullptr)` in the fixture; `Receive`: replace clearing with
   `BOOST_REQUIRE(!node.fPauseSend)`; update comments; add the new test case.
   Verify: build + unit tests both configs.
4. Docs: `src/test/README.md`, counts 341 -> 342 (`CLAUDE.md`,
   `contrib/testing/README.md`, skill), `project/known-issues.md` entry,
   task log. Logging: none – test fixture code, `fPrintToDebugLog` is off in
   unit tests (CLAUDE.md rule 5 applies to daemon behaviour; unchanged).
5. Code review (self-review, no Agent tool), tests both configs, doc review,
   commit, push, PR.

## Log

- 2026-10-03 step 0: P0-16 in done; branch `task/P0-62-testingsetup-tokensdb`
  (from master 6859321); task moved to inprogress (f360b8b).
- 2026-10-03 step 1: task claims verified (see Detailed description); all
  correct. Extra uses of `ptokensdb` checked: `validation.cpp:2062`
  (`ConnectBlock`), `:2236` (`FlushStateToDisk`), `tokens/tokens.cpp`
  (`DumpCacheToDatabase`, lookups that also need `ptokensCache`),
  `rpc/tokens.cpp:821/1017` (no unit test calls them).
- 2026-10-03 step 3 (self-review, no Agent tool) of the description: added
  the side-effect analysis for tests that now see a non-null `ptokensdb`,
  the `DoS_tests` `Init(options)` interaction, the per-fixture memory
  environment, and a test of the exact buffer boundary. Kept
  `TestPeer::ClearSent` resetting `fPauseSend` (it emulates a socket send,
  as `net.cpp:865` does) – not a workaround.
- 2026-10-03 step 5 (self-review, no Agent tool) of the plan: the new test
  case goes into `chain_trust_tests.cpp` (the suites that rely on the
  contract) rather than a new file, to keep `src/Makefile.test.include`
  unchanged (P0-19 edits it in parallel). Buffer limits are set through the
  `CConnmanTest` friend instead of `CConnman::Init(options)`, which would
  also zero `nMaxConnections`/`nMaxOutbound` etc. Logging: none needed (test
  fixture only, `fPrintToDebugLog` is off; no daemon behaviour changes).
- 2026-10-03 step 6: implemented as planned.
- 2026-10-03 step 7 (self-review, no Agent tool) of the staged diff:
  fixed a wrong comment ("one byte more" – the next message adds at least a
  24-byte header) and merged two lock blocks in the new test. Not changed:
  if `LoadGenesisBlock`/`ActivateBestChain` throws in the constructor, the
  globals (including the new `ptokensdb`) leak – pre-existing for all
  globals and the test run fails anyway. Dangling `pcoinsTip`/`pblocktree`/
  `ptokens` after a fixture: out of scope, recorded in
  `project/known-issues.md`.
- 2026-10-03 step 8: `build.sh --config mainnet --unit`: exit 0, 342/342
  unit; `build.sh --config lowdiff --unit --functional`: exit 0, 342/342
  unit, 46/46 functional (on master 6859321 + this change).
- 2026-10-03 step 10 (self-review, no Agent tool) of the docs: checked
  `src/test/README.md` against the code; added that the P2P test peer now
  requires a clear `fPauseSend`. Counts updated to the measured 342.
- 2026-10-03: merged origin/master (P0-19, +3 unit tests) into the branch;
  count lines resolved to 344 + 1 = 345. Re-run after the merge:
  `build.sh --config mainnet --unit` exit 0, 345/345 unit;
  `build.sh --config lowdiff --unit --functional` exit 0, 345/345 unit,
  46/46 functional.
- 2026-10-03 step 11: task moved to done; PR https://github.com/dev34253/yacoin/pull/72.
