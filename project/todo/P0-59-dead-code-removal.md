# P0-59: Dead-code removal

- Plan section: 0.1
- Depends on: P0-50 (part A); P0-19 (part B); P0-14, P0-16, P0-17, P0-18, P0-19, P0-23, P0-46 (part C)
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Delete the code that [`plans/dead-code.md`](../plans/dead-code.md) lists as
unreachable, without changing what any binary does.

## Steps

Each part is its own pull request. A part may start once its own
dependencies are done; it need not wait for the other parts. Re-check every
item with the `git grep` commands in `dead-code.md` before deleting it,
because the line numbers are from 651e82e.

1. **Part A – no consensus file (depends on P0-50 only).**
   - Delete `src/scrypt-arm.S`; no Makefile lists it.
   - Delete the orphan make rule and flags in `src/Makefile.am:186-188,190,193-195`
     (`SCRYPTDEFS`, `SCRYPTHARDENING`, `xCXXFLAGS`,
     `xCXXFLAGS_SCRYPT_JANE`, the rule `yacoind-scrypt-jane.o`). **Keep line
     191** (`DEFS+=-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA
     -DSCRYPT_CHOOSE_COMPILETIME`): it selects the scrypt-jane algorithms and
     SIMD path, which is consensus.
   - Delete the unused OpenSSL includes `src/wallet/wallet.cpp:48` and
     `src/test/crypto_tests.cpp:20-21`.
   - Delete the `-rpcssl*` help text at `src/init.cpp:425-428`. The node
     refuses `-rpcssl` (`httpserver.cpp:383-385`, `rpc/client.cpp:382-384`)
     and reads none of the other three.
   - Delete the `yacoind` testnet help text (`src/init.cpp:381,422`
     "or testnet: …", `:439` `-testnet`) and the unused constant
     `testnetNewLogicBlockNumber` (`init.cpp:73`). Keep the shared
     `-testnet` text in `chainparamsbase.cpp:20` (used by `yacoin-cli`).
     Optionally fix the `-testnetnewlogicblocknumber` help spelling (see
     `dead-code.md` d).
   - Not in this task: the duplicate `RAND_egd` check in `configure.ac`
     (the first one adds `-lcrypto` to `LIBS` and defines `HAVE_LIBCRYPTO`;
     Phase 5) and the Qt includes (Qt is deferred, P0-00).
2. **Part B – `scrypt.cpp` and the files only it uses (gate: P0-19).**
   - In `src/scrypt.cpp`, delete every function except
     `bool scrypt_hash(const void*, size_t, uint32_t*, unsigned char Nfactor)`.
     Also delete `SCRYPT_BUFFER_SIZE`, the `scrypt_core` declaration and the
     `pbkdf2.h`/`random_nonce.h` includes. Remove the matching
     declarations from `src/scrypt.h`. Check whether the other includes
     (`validation.h`, `main.h`, `primitives/block.h`, `scrypt.cpp:44-46`)
     were needed only by `scanhash_scrypt`.
   - Delete `src/pbkdf2.cpp`, `src/pbkdf2.h`, `src/random_nonce.cpp`,
     `src/random_nonce.h`, `src/scrypt-generic.cpp`, `src/scrypt-x86.S` and
     `src/scrypt-x86_64.S`, with their `Makefile.am` entries
     (`:123,130,220,224,236-238`). Delete the include at `src/miner.cpp:49`.
3. **Part C – consensus files (gate: P0-14, P0-16, P0-17, P0-18, P0-19,
   P0-23, P0-46).**
   - Delete `ComputeMinWork`, `ComputeMinStake`, `ComputeMaxBits` and
     `GetProofOfStakeLimit` (`pow.cpp`, `pow.h`) and the globals at
     `main.cpp:74-75`.
   - Remove every `fTestNet` use listed in `dead-code.md` b): replace each
     expression with its value for `fTestNet == false`. Delete the dead data
     (`mapStakeModifierCheckpointsTestNet`, `nModifierTestSwitchTime`), the
     assignment at `init.cpp:849`, and the global and its declarations.
     `GetDefaultPort()` in `protocol.h` returns 7688 and is used by
     `net.cpp`.
   - Do **not** touch the local `fTestNet` in `chainparamsbase.cpp:93`.
4. Update `plans/dead-code.md` (mark the parts as removed), the overview
   inventory, and the P0-04 exclusion list if P0-04 is already done.

## Checks (every part)

- `contrib/testing/build.sh --config mainnet --unit` and
  `--config lowdiff --unit --functional`: same pass counts as before.
- The build fails with an undefined reference if anything removed was still
  used. Do not paper over such an error; put the item back and correct
  `dead-code.md`.
- **Part A:** the `make V=1` compile command for `scrypt-jane.c` is
  identical before and after, and
  `src/scrypt-jane/libyacoin_server_a-scrypt-jane.o` is byte-identical.
- **Part B:** the P0-19 header-hash known answers pass in both
  configurations. `objdump -dr` of `scrypt_hash` in `scrypt.o` is identical
  before and after; compare per function with relocations shown
  symbolically, not linked-binary addresses. The part-A `scrypt-jane.c`
  check also passes.
- **Part C:** functions whose object code changes cannot be compared:
  those edited directly (`GetBlockTrust`, `IsFixedModifierInterval`,
  `CheckStakeModifierCheckpoints`, `CalculateHash`, `CheckTxInputs`,
  `YacoinMiner`, `AppInitParameterInteraction`), those that inline
  `GetDefaultPort()` (the `net.cpp` callers: `GetListenPort`,
  `CConnman::ConnectNode`, `ThreadDNSAddressSeed`,
  `ThreadOpenConnections`, `GetAddedNodeInfo`,
  `ThreadOpenAddedConnections`), and the static initialisers of `kernel.o`
  and `main.o`. They rely on the gating tests and the P0-23 offline replay,
  or a P0-24-style reindex on the owner's machine. The other functions in
  the edited `.o` files are compared with `objdump -dr` as in part B.

## Acceptance criteria

- [ ] Part A merged; `scrypt-jane.c` compile line and object unchanged.
- [ ] Part B merged; header-hash known answers pass; `scrypt_hash` object code unchanged.
- [ ] Part C merged; gating tests and replay pass.
- [ ] `plans/dead-code.md` and the overview updated.

## Notes

- Not a Phase 0 exit criterion and not in P0-45's dependencies. Phase 3 of
  the overview also plans to delete the dead `pbkdf2.cpp`/`scrypt.cpp`
  code; this task is that work, pulled forward where its gates allow. When
  to do it is the owner's decision.
- Unused `CBigNum` methods (`dead-code.md` c) are not part of this task:
  they are deleted in Phase 4 after the P0-12 audit (plan 0.2a).
- Created by P0-50.

## Log

-
