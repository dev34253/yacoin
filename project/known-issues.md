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
