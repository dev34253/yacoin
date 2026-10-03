# Known issues

Findings that were recorded but deliberately **not fixed**. The current work
(Phases 0–5 of [`plans/overview.md`](plans/overview.md)) has one goal: a
stable build on Ubuntu 24.04 with current libraries, OpenSSL removed first.
Phase 0 pins today's behaviour, bugs included (CLAUDE.md rule 1). Everything
below is for later, after the modernisation, unless it blocks that goal.

Each entry: what, where, impact, found by. Consensus-relevant entries need a
hard fork or at least a careful, separately reviewed change.

## Consensus behaviour (pinned by tests; changing it needs a fork)

- **Post-fork PoW reward ignores fees.** `GetProofOfWorkReward` after the
  fork has no `+ nFees` (`validation.cpp:932`), so a post-fork PoW coinbase
  cannot claim the fees of its transactions – the fees are destroyed (as in
  Peercoin, from which Yacoin derives; probably intended). Pre-fork the fees
  are included. To document for miners; confirm with the yacoin/yacoin
  developers. Pinned by `reward_tests`. (P0-46, Q12)
- **`CheckStakeKernelHash` accepts a negative coin-day weight.** Cannot occur
  on a valid chain because `validation.cpp:3205` requires tx time ≤ block
  time. (P0-12, Q2)
- **PoW trust 0 above powLimit; unreachable `chain.cpp:112`.** Such blocks
  are rejected by `CheckProofOfWork` anyway; leave. (P0-16, Q6)
- **`GetHash()` cache can return a stale PoW hash.** `CBlockHeader::GetHash()`
  (`primitives/block.h:235-248`) recomputes only when a header field differs
  from `previousBlockHeader`. `SerializationOp` (block.h:110-115) also
  writes `previousBlockHeader`, so changing a field and then serialising the
  header before `GetHash()` leaves the old hash in the cache; a change of
  `nFactorAtHardfork` is not part of the key either (a node does not change
  it after `AppInit`). Impact: only if a code path changes `nNonce`/`nTime`
  and serialises before hashing (not investigated); fixing it changes hashing
  code. Pinned by `header_hash_tests/gethash_cache_quirks`. (P0-19)
- **N-factor table comment.** `block.h:170` says "(Nf) 26" for `nSpanOf25`,
  but the cap `MAXIMUM_N_FACTOR` gives 25 from 3515474848 on; comment only.
  Pinned by `header_hash_tests`. (P0-19)

- **Retarget minimum depends on the tip** (review B7). `CalculateNextWorkRequired`
  starts its `nMinEase` scan at `chainActive.Tip()` (`pow.cpp:40-51`), and
  `nMinEase` compares compact `nBits` as plain integers. A node that checks
  an epoch-boundary block while its tip is elsewhere (header-first sync,
  reorg) can compute a different target. On mainnet so far harmless: all
  74,618 post-fork blocks up to 1,964,617 have `nBits` 0x1e0fffff (powLimit),
  so the minimum never moved; the P0-08 dump found no difference. (P0-08)
- **`CBlockIndex::prevoutStake` and `nStakeTime` are never set.** They are
  serialised in the block index (`chain.h:522-527`) but only read
  (`txdb.cpp:487-488`); none of the 1,964,618 mainnet entries has them.
  Harmless (nothing reads them), but anyone expecting the ppcoin values must
  take them from the coinstake (`CBlock::GetProofOfStake()`). (P0-08)
- **Post-fork next target depends on `chainActive`.** `CalculateNextWorkRequired`
  takes nMinEase (the cap 3 · target of the lowest nBits) from *both* the
  active chain and pindexLast's own chain (`pow.cpp:40-68`), so the target
  required for a side-chain block changes with the active tip; the comment at
  `validation.cpp:3234` acknowledges it (DoS score lowered to 10). It also
  scans every post-fork block on each retarget (review B7). Pinned by
  `pow_chain_tests/calc_min_ease_scans`. (P0-14)
- **nMinEase includes PoS blocks and compares compact values.** The scan
  (`pow.cpp:46,62`) takes PoS blocks' nBits like PoW ones and compares the
  compact numbers, not the targets; a non-normalised nBits (e.g. 0x1e000001,
  target 2^216) is not seen as harder than 0x1d00ffff. Unreachable for the
  compact part (a block's nBits must equal `GetNextTargetRequired`, which
  always normalises, `validation.cpp:3236`); the PoS part matters only if
  there are post-fork PoS blocks (P0-15 will show). Post-fork PoS requests
  also use the PoW epoch rule and pindexLast's nBits (`pow.cpp:141-155`).
  Pinned by `pow_chain_tests/calc_min_ease_quirks`, `post_fork_pos_requests`.
  (P0-14)
- **Retarget window off by one at the first epoch.** At a boundary with
  `pindexLast->nHeight <= nDifficultyInterval + 1` the window starts at the
  genesis (interval − 1 blocks at the first boundary; with interval ≤ 2 the
  second boundary measures from the genesis too, e.g. 3 blocks for interval
  2), later boundaries go back interval blocks (`pow.cpp:167-178`). Unreachable on mainnet (fork at 1,890,000); only
  functional-test chains (interval 10) take the genesis branch. Pinned by
  `pow_chain_tests/post_fork_window_off_by_one`. (P0-14)
- **Pre-fork retarget can produce a negative target.** With an actual
  spacing below −(nInterval − 1) · spacing / 2 (−302,370 s for PoW at 60 s)
  the multiplier at `pow.cpp:197` is negative, the result is not clamped and
  its compact form has the sign bit set (`CheckProofOfWork` rejects it).
  Needs a block 3.5 days before its parent, which the median-time and
  future-time rules prevent; pre-fork history only. Pinned by
  `pow_chain_tests/pre_fork_negative_spacing`. (P0-14)
- **Crashes instead of errors in the retarget.** A pindexLast whose
  `phashBlock` is not in mapBlockIndex dereferences `end()`
  (`pow.cpp:57-58`); the first-epoch retarget with no genesis in
  `chainActive` passes null to `ReadBlockFromDisk` (`pow.cpp:174-176`, whose
  result is ignored anyway); a window longer than the chain hits `Yassert`,
  which in a release build only logs and calls `StartShutdown()`
  (`main.cpp:138-160`), then dereferences null (`pow.cpp:179-181`). All
  callers pass index entries of a full chain, so not reachable in a node;
  not testable. (P0-14)

## CBigNum / OpenSSL (go away with the arith_uint256 replacement, Phase 4)

- **Negative zero.** `getuint64`/`getuint256` on a negative zero write one
  byte past their buffer; `getBytes()` of zero takes `&v[0]` of an empty
  vector. A negative zero comes from `setvch`/`Unserialize` (no production
  caller) and from `SetCompact` of a sign-bit `nBits` with zero kept bytes
  (e.g. `0x01800000`, reachable from block headers); every current production
  caller tests `<= 0` or multiplies first. (P0-10, P0-11, Q2)
- **`GetCompact` exponent wraps** at 256 or more MPI bytes (|v| ≥ 2^2039).
  Pinned. (P0-11, P0-27)
- The full list of CBigNum semantics the replacement must match or special-case
  is in the P0-10, P0-11, P0-12 and P0-27 task files.

## RPC and command line (not consensus)

- **`gettimechaininfo` chain trust**: returned as a JSON number holding only
  the low 64 bits, although the help says hex string; trust 0 is shown as an
  empty string in `chaintrust`/`blocktrust`. Owner: fix later. (P0-16, Q6)
- **`-rpcclienttimeout=0` does not disable the timeout.** `yacoin-cli` passes
  the value straight to `evhttp_connection_set_timeout` (`rpc/client.cpp:474`);
  libevent then uses its 50-second default, although the help says "0 for no
  timeout". Long calls (e.g. `dumpconsensusvalues`) need a large value; the
  server side finishes regardless. Bitcoin Core fixed this later. (P0-08)
- **`getsubsidy`**: `yacoin-cli` converts `ntarget` as JSON
  (`rpc/client.cpp:81`), so the hex target must be quoted (`'"0000…"'`).
  Owner: leave for now. (P0-46, Q12)
- **`getmininginfo` `blockvalue`** uses the tip height, not the next block's,
  so at an epoch boundary it shows the previous epoch's reward. (P0-46, Q12)
- **`-testnetnewlogicblocknumber`** is documented, but the code reads
  `-testnetNewLogicBlockNumber`; on Windows the command line is lowercased,
  so the option never matches (`util.cpp:415-419`, `init.cpp:1144`). (P0-50, Q2)
- **`-testnet`** has base params but no chain params; `CreateChainParams("test")`
  throws "Unknown chain test". Testnet remnants are removed with P0-59. (P0-20, Q8)

## P2P (not consensus)

- **`GetBlockProofEquivalentTime`** divides a Yacoin trust difference by
  Bitcoin's `GetBlockProof`: a month of mainnet PoW blocks counts as ~2
  seconds, so the one-month check at `net_processing.cpp:1119` never fires for
  new-rules blocks; it also wraps at 2^256, caps at ±INT64_MAX and throws when
  the tip's proof is 0. Owner: leave. (P0-16, Q6)

## Logging

- **`LoadBlockRewardAndHighestDiff`** logs reward 0 and "something wrong" when
  the fork height is not a multiple of `-epochinterval` and the tip is in the
  first epoch (only in functional tests). Leave. (P0-46, Q12)
- **"PoW constant target … to go" plural.** `pow.cpp:150-153` formats
  `"(%d block %s to go)"` with `nDifficultyInterval - nBlocksToGo` but
  chooses the "s" by `nBlocksToGo != 1`, and the "s" is a separate word:
  the output reads "(9 block  to go)" or "(1 block s to go)". Cosmetic.
  (P0-14)

## Qt (deferred)

- **`qt/paymentserver.cpp:230,232,249`** select testnet params that do not
  exist. (P0-50, Q2)

## Tests and tooling

- **`GetMaxSize(mode, 0)` means "tip + 1"** (`consensus/consensus.cpp:22`), so
  the size limit of height 0 cannot be asked for; callers that pass a real
  height of 0 get the next block's limit. Only reachable for the genesis.
  (P0-08)

- **`BuildSkip()`** asserts on index chains that start above height 0 (only
  reachable in tests; the P0-47 harness computes skip pointers itself). (P0-47, Q2)
- **Functional cache chain** is mined with `-epochinterval=20` (40 blocks)
  while the tests run with 10. Recorded; docstring fix in P0-61. (P0-20, Q8)
- **Checkpoint 1,750,000** is written without leading zeros (harmless). (P0-20, Q8)
- **`TestingSetup` leaves dangling globals.** Its destructor deletes
  `pcoinsTip`, `pcoinsdbview`, `pblocktree` and `ptokens` without resetting
  the globals (`src/test/test_bitcoin.cpp`), so a `BasicTestingSetup` test
  that ran after a `TestingSetup` one and used them would see freed memory.
  No test does today; `ptokensdb` is reset since P0-62. `ptokensCache` is
  never created in unit tests (the code using it checks for null). (P0-62)
- **`DoS_tests/stale_tip_peer_management`** calls `connman->Init(options)`,
  which sets the test `CConnman`'s send/receive buffer limits back to 0 for
  the rest of that case (harmless: it calls no `ProcessMessages`). (P0-62)
- **`build.sh` exits 141 on a failed build.** In P0-14 a compile error
  made `build.sh` exit 141 (SIGPIPE) after printing 30 lines of Boost
  "required from" notes, without the "build failed" message; the real
  errors were only in `<builddir>/make.log`. Probably `grep … | head -n 30`
  under `set -o pipefail` (`contrib/testing/build.sh:377-378`). Use
  `grep ' error:' <builddir>/make.log` meanwhile. (P0-14)
