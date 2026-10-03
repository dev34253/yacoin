# Open questions for the owner

Collected while tasks were implemented without the owner present. Findings
that are recorded but not fixed are listed in [`known-issues.md`](known-issues.md).

Each entry: where it came from, the question, and what was done for now. Answer inline
(or in a PR comment) and move answered entries to "Answered" with the
decision.

## Open

(none)

## Answered

### Q6 – Behaviour pinned by P0-16 that looks wrong (from P0-16)
- `gettimechaininfo` returns `bnChainTrust` as a number holding only the low
  64 bits, while its help text says hex string; a trust of 0 is shown as an
  empty string in RPC output.
- `GetBlockProofEquivalentTime` for new-rules PoW blocks: a month of mainnet
  blocks counts as ~2 seconds, so the one-month check at
  `net_processing.cpp:1119` never fires; it also wraps at 2^256, caps at
  ±INT64_MAX and throws `uint_error` when the tip's proof is 0.
- A PoW block with a target above powLimit gets trust 0 under the new rules;
  `chain.cpp:112` is unreachable.
*For now:* pinned in `src/test/chain_trust_tests.cpp`, not changed (rule 1).
Fix candidates for after Phase 0?
**Answer (owner, 2026-10-03):** (1) RPC output (`gettimechaininfo` chain trust as a
number with only the low 64 bits; trust 0 as empty string): fix later, after
Phase 0, as a small RPC task. (2) `GetBlockProofEquivalentTime` / the
one-month check: leave as is. (3) trust 0 above powLimit and the unreachable
`chain.cpp:112`: leave as is.

### Q7 – Unit-test setup gaps (from P0-16)
`TestingSetup` creates no `ptokensdb`, so any unit test that reorganises the
chain crashes in `DisconnectBlock`; the test `CConnman` is never started, so
injected P2P messages are ignored (`fPauseSend`). P0-16 works around both in
its own test file. *For now:* documented in `src/test/README.md`. Should a
small task fix `TestingSetup` (shared test setup) so later tests do not need
the workarounds?
**Answer (owner, 2026-10-03):** yes – `TestingSetup` creates the in-memory token
database itself (`ptokensdb`, like `pblocktree`/`pcoinsdbview`); task
`todo/P0-62-testingsetup-tokensdb.md` (also covers the test `CConnman`
send-buffer gap and removes P0-16's workarounds).

### Q8 – Test tooling gaps found by P0-20 (from P0-20)
- `build.sh` does not fail when `unit.log` has no Boost "test cases" summary
  (e.g. `test_bitcoin` exits early). P0-20 fixed the known hole (the
  `StartShutdown()` stub exited 0); the `Shutdown(void*)` stub still exits 0
  (no test calls it). Add the summary check to `build.sh`?
- The functional-test cache chain is mined with `-epochinterval=20` (40
  blocks, `test_framework.py:540`) while the tests run with 10, and the
  framework docstring says 199 blocks. Recorded only.
- `-testnet` has base params but no chain params (`CreateChainParams("test")`
  throws "Unknown chain test"); checkpoint 1,750,000 has no leading zeros.
  Recorded only.
**Answer (owner, 2026-10-03):** (1) yes – `build.sh` fails when `unit.log` has no
"test cases … passed" summary, and the `Shutdown(void*)` stub exits 1; added to
P0-61. (2) record only; fix the framework docstring (40 blocks, epoch
interval 20) – also in P0-61. (3) leave as is (testnet remnants go with
P0-59 at the end of Phase 0).

### Q10 – CBigNum golden vectors: CI check, `xz`, size (from P0-13)
- `contrib/testing/bignum_vectors_check.py` (independent Python model of
  all 100,000 vectors, < 1 s) is not run in CI; the task may not edit
  `.github/workflows/`. The `test_bitcoin` replay runs in CI as part of the
  unit tests. Add the checker as a CI step (or to `build.sh --unit`)?
- Test builds now need `xz` (`configure` errors without it, like
  `hexdump`). It is in the build image and on practically every system;
  documented in `doc/build-unix.md`. Acceptable, or embed differently?
- The vector file is 0.97 MB (xz; 12.9 MB of JSON embedded in
  `test_bitcoin`). Each regeneration adds another blob of that size to git
  history, so regenerate only on format changes.
*For now:* checker manual (documented in `contrib/testing/README.md`),
`xz` required, file committed as is.
**Answer (owner, 2026-10-03):** (1) yes – `build.sh --unit` runs
`bignum_vectors_check.py` and P0-46's `reward_vectors.py` (so locally and in
CI, no workflow change); added to P0-61. (2) `xz` as a test-build requirement
is accepted. (3) the size is accepted; regenerate the vectors only when the
format changes.

### Q11 – Coverage gate: where it runs, threshold rule (from P0-04)
- The gate runs only where the coverage jobs run: on `master` and when the
  Tests workflow is started by hand (owner decision in P0-03: coverage
  jobs not on every push). A task branch that lowers coverage is
  therefore caught only after the merge, unless its author starts the
  workflow by hand. Run coverage (and the gate) on PRs that touch gated
  files (`pow.cpp`, `chain.cpp`, `kernel.cpp`, `validation.cpp`,
  `bignum.h`, `wallet/crypter.cpp`, `random.cpp`), e.g. with a
  `pull_request` path filter?
- Threshold rule: minimum = `floor(measured − 0.5)` %, a measured 100 %
  stays 100; minimums are only raised (lowering needs a reason in the PR).
  Tighter (e.g. exact counts for the consensus files) or looser?
- Exclusions: only what the task names. `if (fPrintProofOfStake)`
  logging in `kernel.cpp` (line 485) and the `fDebug`/`-printcreation`
  logging in `GetProofOfWorkReward` are counted. Exclude them too?
*For now:* master/by hand, the rule above, exclusions as listed in
`contrib/testing/coverage-gates.toml`.
**Answer (owner, 2026-10-03):** (1) yes – coverage and the gate also run on
pushes that change a gated file or the gate config (path filter); other
pushes stay fast. (2) keep the rule floor(measured − 0.5), only raised.
(3) exclude the `fPrintProofOfStake` and `-printcreation` logging blocks too.
(1) and (3): task `todo/P0-63-coverage-on-gated-changes.md`.

### Q12 – Reward quirks found while pinning them (from P0-46)
- Post-fork, `GetProofOfWorkReward` ignores `nFees` (`validation.cpp:932`
  has no `+ nFees`), so a post-fork PoW coinbase cannot claim the fees of
  its transactions; pre-fork it can. Pinned as consensus behaviour. Is
  this intended (fees burned), and should it be documented for miners?
- `getsubsidy`: `yacoin-cli` converts `ntarget` as JSON
  (`rpc/client.cpp:81`), so the hex target only works quoted
  (`'"0000…"'`); the server then reads it with `get_str()`. After the
  fork the target is ignored. Fix the client conversion (RPC only, not
  consensus) in a later phase, or leave it?
- `getmininginfo`'s `blockvalue` passes `chainActive.Height()` (the tip,
  not the next block) to `GetProofOfWorkReward` (`rpc/mining.cpp:301`);
  when the next block starts a new epoch it still shows the current
  epoch's reward. Leave as is?
- `LoadBlockRewardAndHighestDiff` logs reward 0 and "something wrong" when
  the fork height is not a multiple of `-epochinterval` and the tip is in
  the first epoch (functional tests with such a fork height). Log only.
*For now:* all pinned as they are by `reward_tests`; nothing changed.
**Answer (owner, 2026-10-03):** the current tasks are about a stable build with
current libraries on Ubuntu 24.04 (OpenSSL first), not about fixing every
finding. All four are recorded in [`known-issues.md`](known-issues.md); the
fees one is consensus and stays as is; `getsubsidy` is left for now.

### Q1 – When to schedule P0-59 (dead-code removal)? (from P0-50)
P0-50 proposed removing dead code in three gated PRs: A (no consensus files,
could start now), B (`scrypt.cpp`, after P0-19), C (consensus files, after
P0-14/16/17/18/19/23/46). P0-59 is not in P0-45's dependencies or the Phase 0
exit criteria.
*For now:* not scheduled; it stays in `todo/`. Should part A be done during
Phase 0, and should P0-59 become a Phase 0 exit criterion?
**Answer (owner, 2026-10-03):** do the dead-code removal (all three parts) at the very end of Phase 0, once all other Phase 0 tasks are done, for the largest safety net. P0-59 now depends on every other Phase 0 task; P0-45 (exit review) depends on P0-59 (and on the new P0-60/P0-61).

### Q5 – P0-03 was verified in CI, not locally
The local lowdiff/coverage runs were blocked by the session's permission
classifier; with your OK the task was finished on the CI results (all five
jobs green). Nothing open unless you want the local runs repeated.
**Answer (owner, 2026-10-03):** fine – verifying P0-03 through the CI runs is accepted; no local re-run needed.

### Q2 – Latent bugs found while reading code: fix later or record only?
- `-testnetnewlogicblocknumber` is documented, but the code reads
  `-testnetNewLogicBlockNumber`; on Windows the command line is lowercased,
  so the option never matches (`util.cpp:415-419`, `init.cpp:1144`). (P0-50)
- `qt/paymentserver.cpp:230,232,249` select testnet params that do not
  exist (Qt is deferred). (P0-50)
- `bignum.h`: `getuint64`/`getuint256` on a negative zero write one byte past
  their buffer; `getBytes()` of zero takes `&v[0]` of an empty vector. A
  negative zero comes from `setvch`/`Unserialize` (no production caller)
  and, as P0-11 found, from `SetCompact` of a sign-bit `nBits` with zero
  kept bytes (e.g. `0x01800000`, reachable from block headers); every
  current production caller tests `<= 0` or multiplies first, so the
  overflow is not reached. (P0-10, P0-11)
- `CheckStakeKernelHash` does not reject a negative coin-day weight; on a valid
  chain it cannot occur because `validation.cpp:3205` requires tx time ≤ block
  time. (P0-12)
- `BuildSkip()` asserts on index chains that start above height 0 (only
  reachable in tests; the P0-47 harness computes skip pointers itself).
*For now:* recorded only (Phase 0 pins behaviour). The CBigNum ones go away
with the arith_uint256 replacement in Phase 4. Do you want separate fix tasks
for the first two?
**Answer (owner, 2026-10-03):** record only for now; fixes can be done once Phase 0 is complete.

### Q3 – macOS CI build depends on an unreachable download (from #52)
`build-macos` (release workflow) downloads clang+llvm 3.7.1 from llvm.org;
when llvm.org is unreachable, the bitcoincore.org fallback answers 404 and the
job fails. *For now:* nothing changed; the release workflow now runs only on
master, tags and by hand, so it no longer blocks task branches. Should a task
add a working mirror (e.g. our own copy of the tarball) in
`depends/packages/native_cctools.mk`?
**Answer (owner, 2026-10-03):** yes – task `todo/P0-60-macos-depends-mirror.md`.

### Q4 – Parallel functional test runs on one machine (from merging #52)
Two `build.sh --functional` runs on one machine collide on ports when Docker
uses `--network host` (always the case when a proxy is set). *For now:*
parallel agents serialise functional runs with
`flock /root/.cache/yacoin-functional.lock`. Should `build.sh` get a per-work-
dir port range (the test framework's `PortSeed`) so this is not needed?
**Answer (owner, 2026-10-03):** yes, per-work-dir port range – task `todo/P0-61-build-sh-port-range.md`.

### Q9 – Mainnet sync speed (P0-07)
On 2026-10-03 04:00 UTC the laptop node was at block 122,727 (headers ~97 %,
N-factor 21), about 8,200 blocks/hour: the full sync (~1.96 M blocks) needs
roughly 9–10 more days at this rate. P0-08/P0-09 (mainnet dump and fixture)
and everything after them wait for it. *For now:* waiting. Options if this is
too slow: more CPU for the node, or a second node.
**Answer (owner, 2026-10-03):** not a problem any more – once the headers were synced, the blocks synced quickly as well. (The owner's note was numbered Q8; it is about the sync, so it is recorded here. Q8 itself is still open.) Confirmed 2026-10-03 10:26 UTC: the node is at the tip, height 1,964,616, best block `00000d6beaa6c3d7107e96247edfe953a45a4250b495498b4e725e915afdbecf`, datadir 3.3 GB, yacoind RSS 1.45 GiB, 1 peer (P0-07 records the details; P0-08/P0-09 can start).
