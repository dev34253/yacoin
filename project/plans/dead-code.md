# Dead-code list

Code in this tree that can never run in `yacoind`, `yacoin-cli` or
`test_bitcoin`, plus leftovers (unused includes, build rules, help text).
Written by task P0-50, checked against `master` at 651e82e (2026-10-02);
line numbers are from that tree, and every entry names the function too.

What the list is for:

- **Coverage (P0-04):** dead code is excluded from the coverage
  denominators. The column "gcov" says whether the item is counted at all:
  code that is compiled and linked counts, unused inline header functions do
  not (the compiler never emits them).
- **Removal:** proposed in task
  [P0-59](../todo/P0-59-dead-code-removal.md), in three parts with
  different gates (see [Removal proposal](#removal-proposal)).
- **Scope of later phases:** what Phase 3–5 do not need to port.

"Consensus file" marks files that hold consensus code (CLAUDE.md rule 1):
even a change that keeps behaviour there waits for the Phase 0 tests that
cover the file.

## How to re-check

Each "no callers" verdict is a whole-repository search, excluding the
vendored `src/leveldb`, `src/secp256k1` and `src/univalue`:

```bash
git grep -nw <symbol> -- ':!src/leveldb' ':!src/secp256k1' ':!src/univalue'
git grep -n '_scrypt_core'      # assembler names have a leading underscore
```

An entry is dead when the only hits are its definition, its declaration,
and other entries on this list. The two build-output checks in
[Checked on the build](#checked-on-the-build) back up the build-system
claims.

## a) Unreferenced functions and files

| Item | Location | Why it is dead | Consensus file | gcov | P0-59 part |
|---|---|---|---|---|---|
| `scrypt_nosalt` | `scrypt.cpp:62-74` | only caller is `uint256 scrypt_hash(input, len)` (below) | yes (`scrypt.cpp`) | yes | B |
| `scrypt_SHA256` (static) | `scrypt.cpp:77-99` | only caller is `scrypt_salted_hash` | yes | yes | B |
| `uint256 scrypt_hash(const void*, size_t)` | `scrypt.cpp:101-105`, `scrypt.h:19` | no callers (the live overload is the `bool` one) | yes | yes | B |
| `scrypt_salted_hash` | `scrypt.cpp:141-145`, `scrypt.h:18` | only caller is `scrypt_salted_multiround_hash` | yes | yes | B |
| `scrypt_salted_multiround_hash` | `scrypt.cpp:147-159`, `scrypt.h:17` | no callers | yes | yes | B |
| `scrypt_blockhash` | `scrypt.cpp:161-174`, `scrypt.h:20` | no callers; the block hash is `CBlockHeader::CalculateHash` (`primitives/block.h:126-218`) | yes | yes | B |
| `scrypt_buffer_alloc`, `scrypt_buffer_free` | `scrypt.cpp:176-183`, `scrypt.h:21-22` | no callers | yes | yes | B |
| `scanhash_scrypt` | `scrypt.cpp:186-308`, `scrypt.h:23-30` | no callers (the built-in miner `YacoinMiner` in `miner.cpp` does not use it); dead in both build configurations | yes | yes | B |
| `SCRYPT_BUFFER_SIZE`, `scrypt_core` declaration, includes of `pbkdf2.h` and `random_nonce.h` | `scrypt.cpp:42-55` | only used by the functions above | yes | – | B |
| `pbkdf2.cpp`, `pbkdf2.h` (`PBKDF2_SHA256`, `HMAC_SHA256_*`; OpenSSL `SHA256_*`) | whole files; `Makefile.am:123,220` | only callers are `scrypt_nosalt`, `scrypt_SHA256`, `scrypt_blockhash` | no | yes | B |
| `random_nonce.cpp`, `random_nonce.h` (`CRandomNonce`, global `Big`) | whole files; `Makefile.am:130,224` | `get_a_nonce` (a plain increment) is only called by `scanhash_scrypt` (`scrypt.cpp:266`); `randomize_the_nonce`, the `rand()`/`srand(time)` user in this file (`random_nonce.cpp:27-30,71`), has no caller at all. (`rand()`/`srand` are still used live elsewhere: `util.cpp:762` in `randomStrGen`, `util.cpp:809` in `createConf`.) | no | yes | B |
| `scrypt_core` (C++), `scrypt-generic.cpp` | whole file (body under `#ifndef USE_ASM`, `:29-135`); `Makefile.am:238` | only callers are `scrypt_nosalt`, `scrypt_SHA256`, `scrypt_blockhash` | no | yes | B |
| `scrypt-x86.S`, `scrypt-x86_64.S` (`scrypt_core`, `_scrypt_core`) | whole files; `Makefile.am:236-237` | whole body under `#ifdef USE_ASM`, which no real compile defines (see d), so they assemble to empty objects; would only be called by the dead functions above anyway | no | no (empty) | B |
| `scrypt-arm.S` | whole file | not listed in any Makefile; also under `#ifdef USE_ASM` | no | no | A |
| `ComputeMinWork`, `ComputeMinStake` | `pow.cpp:275-278,284-287`, `pow.h:29-30` | no callers | yes (`pow.cpp`) | yes | C |
| `ComputeMaxBits` | `pow.cpp:255-269` | only callers are `ComputeMinWork`/`ComputeMinStake` | yes | yes | C |
| `GetProofOfStakeLimit` | `pow.cpp:231-234` | only caller is `ComputeMinStake` | yes | yes | C |
| `bnProofOfStakeLegacyLimit`, `bnProofOfStakeLimit` (globals) | `main.cpp:74-75` | never referenced; they only run their `CBigNum` constructors at start-up | no | yes (2 lines) | C |

Only one function in `scrypt.cpp` is live:
`bool scrypt_hash(const void*, size_t, uint32_t*, unsigned char Nfactor)`
(`scrypt.cpp:108-139`). It calls scrypt-jane's `scrypt()` and is the
consensus block hash, called from `primitives/block.h:139,212`. It must stay
and does not use `scrypt_core`, `pbkdf2.cpp` or `random_nonce.cpp`.

Because `scrypt.cpp` is linked for that one function, its dead functions and
everything they reference (`pbkdf2.o`, `scrypt-generic.o`, `random_nonce.o`)
are linked into `yacoind` and `test_bitcoin` as well. They count in the
coverage denominators but never run.

The wallet does not use the salted scrypt functions: it only supports key
derivation method 0 (`wallet/crypter.cpp:50`, `BytesToKeySHA512AES`).
Removing them does not affect existing wallets.

## b) Dead `fTestNet` branches

**Why `fTestNet` is always `false`.**

- There are no testnet chain parameters: `CreateChainParams` knows only
  main and regtest (`chainparams.cpp:323-330`) and throws for `-testnet`.
- `yacoind` calls `SelectParams(ChainNameFromCommandLine())` and exits on
  that exception (`yacoind.cpp:119-124`). The Qt client does the same
  (`qt/bitcoin.cpp:645-650`). Both happen before `init.cpp:849` sets
  `fTestNet = gArgs.GetBoolArg("-testnet")`.
- `testnet=1` in `yacoin.conf` takes the same path, because
  `ReadConfigFile` runs first (`yacoind.cpp:113`).
- `test_bitcoin` never sets `fTestNet`; it keeps the default `false` from
  `util.cpp:586`.

| Use | Location | Effect today | Consensus file |
|---|---|---|---|
| `fTestNet \|\| (GetBlockTime() >= CONSECUTIVE_STAKE_SWITCH_TIME)` in `GetBlockTrust` | `chain.cpp:83` | the left operand is always false | yes |
| `fTestNet ? nModifierTestSwitchTime : nModifierSwitchTime` in `IsFixedModifierInterval` | `kernel.cpp:76` | always `nModifierSwitchTime` | yes |
| `fTestNet ? mapStakeModifierCheckpointsTestNet : …` in `CheckStakeModifierCheckpoints` | `kernel.cpp:656` | always the mainnet map | yes |
| `mapStakeModifierCheckpointsTestNet` (data) | `kernel.cpp:68-71` | only used by the dead branch | yes |
| `nModifierTestSwitchTime` (constant) | `timestamps.h:60` | only used by the dead branch | yes |
| `if (!fTestNet) … else nfactor = 4;` in `CalculateHash` (v<7 headers) | `primitives/block.h:173,200-203` | the `else` is never taken | yes |
| `tx.nTime > VALIDATION_SWITCH_TIME \|\| fTestNet` (coinstake fee size) | `consensus/tx_verify.cpp:417` | the right operand is always false | yes |
| `… && !fTestNet` in `YacoinMiner` | `miner.cpp:854` | always true | no |
| commented-out `!fTestNet` | `miner.cpp:159,168` | comments | no |
| `GetDefaultPort(const bool testnet = fTestNet)` → `testnet ? 17688 : 7688` | `protocol.h:19-21`; used by `net.cpp:108,392,1627,1850,1909,1954` | always 7688 | no (P2P) |
| assignment `fTestNet = gArgs.GetBoolArg("-testnet")` | `init.cpp:849` | always assigns `false` (reached only without `-testnet`) | no |
| definition and declarations | `util.cpp:586`, `util.h:455`, `protocol.h:18` | – | no |

Not the global, and live: the local `fTestNet` in
`ChainNameFromCommandLine` (`chainparamsbase.cpp:93`).

For coverage, the dead branches are single operands or `else` arms, so they
show up in **branch** coverage (P0-04 step 2), not as whole uncovered
functions.

## c) `CBigNum` methods: used and unused (audited, P0-12)

**Method.** Compile-time audit (P0-12, scratch only): in a copy of the tree
every member and free operator of `CBigNum` in `bignum.h` was marked
`__attribute__((deprecated))` and the whole tree as configured by
`contrib/testing/build.sh` (`yacoind`, `yacoin-cli`, wallet, `test_bitcoin`,
`test_bitcoin_fuzzy`) was built with `make -k` in the pinned build image,
once for mainnet and once for `--enable-low-difficulty-for-development`.
Every resulting warning names the method and the calling file:line, so
calls through variables (`bnChainTrust`, `powLimit`, …), implicit
conversions (`CBigNum x = CENT`, `bnTarget <= 0`), templates and generic
names (`ToString`, `GetHex`, `++`) are all attributed. Both builds give the
same production call sites (only the `chainparams.cpp` lines of the
`#ifdef`ed `powLimit` differ). Not compiled here and checked by reading:
Qt (`qt/explorer.cpp:1302-1306`: default constructor, `SetCompact`,
`getuint256` – all used anyway); zmq and bench are not configured and do
not mention `CBigNum`. Every other grep hit for `CBigNum`-like names outside
`bignum.h` and `src/test` was matched to a warning or is `arith_uint256`
(`chain.cpp:178`, `validation.cpp:4835-4865`). The destructor and
`CAutoBN_CTX` were not marked (used by everything). Per plan 0.2a nothing
is deleted before Phase 4.

**Used by production code** (callers outside `bignum.h`, `src/test`,
`src/qt`; line ranges in `bignum.h` at master `45eae1a`):

| Method | `bignum.h` lines | Production callers |
|---|---|---|
| `CBigNum()`, copy constructor, `operator=`, destructor | 56-81 | everywhere (`chain.cpp`, `kernel.cpp`, `pow.cpp`, `validation.cpp`, `miner.cpp`, `rpc/*`, `chain.h`, `consensus/params.h`) |
| `CBigNum(int32_t)` | 101-108 | int literals: `chain.cpp:79-114`, `kernel.cpp:461`, `net_processing.cpp:438,454`, `chain.h:264`, … |
| `CBigNum(int64_t)` | 110-117 | `kernel.cpp:458,461`, `pow.cpp:81-82,197-198`, `validation.cpp:935,949,951` |
| `CBigNum(uint256)` | 143-147 | `chainparams.cpp:78-83,237-238`, `kernel.cpp:526`, `main.cpp:74-75`, `pow.cpp:21`, `rpc/mining.cpp:145` |
| `SetCompact`, `GetCompact` | 457-480 | `chain.cpp:78`, `kernel.cpp:452`, `pow.cpp`, `validation.cpp:938-940,3683,3703`, `chainparams.cpp:126,275`, `miner.cpp:642,801`, `rpc/blockchain.cpp:358`, `rpc/mining.cpp:146,420,860` |
| `setuint256`, `getuint256` | 368-409 | `pow.cpp`, `validation.cpp:3703,3705,3727`, `chain.cpp:194,197`, `kernel.cpp:568`, `miner.cpp`, `rpc/*` |
| `getuint64` | 268-288 | `kernel.cpp:482` (hash input), `validation.cpp:957-958,968`, `rpc/blockchain.cpp:945` |
| `ToString` | 512-536 | log lines only: `validation.cpp:989,997,2331,3882` |
| `GetHex` | 538-541 | RPC `chaintrust`/`blocktrust`: `rpc/blockchain.cpp:96,126,127` |
| `operator*=`, `operator/=` | 697-709 | `chain.cpp:108`, `pow.cpp:81-82,88,197-198,259,263`, `validation.cpp:3706` |
| binary `+`, `-`, `*`, `/` | 786-800, 809-825 | `chain.cpp:97,103,114,193,196`, `kernel.cpp:461,526,568`, `validation.cpp:951-962,2934,3760` |
| `operator<<(CBigNum, unsigned)` | 836-842 | `chain.cpp:114` only |
| `<`, `<=`, `>`, `>=` | 853-856 | `chain.cpp`, `kernel.cpp:526`, `pow.cpp`, `net_processing.cpp`, `validation.cpp` (fork choice) |

**Used only inside `bignum.h` by the methods above** (count as used):
`setuint32` (189-193, integer constructors), `setint64` (215-266, negative
integer constructors), `setuint64` (290-323, `CBigNum(int64_t)` for n ≥ 0;
its MPI branch 300-322 is compiled out with 64-bit `BN_ULONG`), `getuint32`
(195-198, `ToString`), `CAutoBN_CTX` (24-49).

**Unused by production code** (only `src/test`, mostly P0-10's
`bignum_tests.cpp`, or nothing; no `arith_uint256` replacement needed):

| Method | `bignum.h` line | Callers outside `bignum.h` |
|---|---|---|
| `CBigNum(int8_t)`, `(int16_t)`, `(uint8_t)`, `(uint16_t)`, `(uint32_t)`, `(uint64_t)` | 83-99, 119-141 | tests only |
| `CBigNum(const std::vector<uint8_t>&)` | 149 | none |
| `randBignum`, `RandKBitBigum` | 160, 172 | none |
| `bitSize` | 184 | tests only |
| `getint32` | 200 | tests only |
| `setuint160`, `getuint160` | 325, 353 | tests only |
| `setBytes`, `getBytes` | 411, 416 | tests only |
| `setvch`, `getvch` | 430, 445 | tests only; inside `bignum.h` only from the unused vector constructor, `Serialize`, `Unserialize`, `GetSerializeSize` |
| `SetHex` | 482 | tests only |
| `GetSerializeSize`, `Serialize`, `Unserialize` | 543-560 | tests only (`bnChainTrust` is memory-only, never serialized) |
| `pow(int)`, `pow(const CBigNum&)` | 567, 576 | tests only (`pow(int)` → `pow(CBigNum)`) |
| `mul_mod`, `pow_mod`, `inverse` | 589, 603, 625 | tests only (`pow_mod` → `inverse`) |
| `generatePrime` | 639 | none |
| `gcd`, `isPrime`, `isOne` | 651, 665, 674 | tests only |
| `operator!` | 679 | tests only |
| `+=`, `-=`, `%=` | 684, 691, 711 | tests only (`+=` also used by `SetHex`) |
| `<<=`, `>>=` | 717, 724 | tests only; inside `bignum.h` only from `SetHex` and `>>` |
| prefix and postfix `++`, `--` | 742-774 | tests only |
| unary `-` | 802 | tests only |
| `%` | 827 | tests only |
| `>>` | 844 | tests only |
| `==`, `!=` | 851-852 | tests only |
| `operator<<(std::ostream&, CBigNum)` | 858 | tests only |

Corrections to the preliminary list (from P0-50 and the P0-10 task):
`operator==`, `operator!`, `+=`, `CBigNum(uint64_t)` were thought to be
used but have no production caller (the reward code's
`CBigNum x = MAX_MINT_PROOF_OF_WORK` is `CBigNum(int64_t)`); the vector
constructor, `getvch`/`setvch`, `SetHex`, serialization, `%`, `>>`,
`++`/`--`, unary `-` and the narrow integer constructors are unused as
well. `ToString` and `GetHex` are used, but only for log and RPC text.

**Coverage.** Unused inline methods that nothing calls are not emitted, so
gcov records no lines for them; but `test_bitcoin` now calls most of the
unused methods (P0-10), so in a coverage build they do appear in
`bignum.h`'s counts. The plan 0.10 target "`bignum.h` (used methods only)"
therefore counts only the line ranges of the two "used" lists above
(P0-04 applies it).

## d) Leftovers

| Item | Location | Notes | P0-59 part |
|---|---|---|---|
| unused `#include <openssl/rand.h>` | `wallet/wallet.cpp:48` | no OpenSSL call in the file | A |
| unused `#include <openssl/aes.h>`, `<openssl/evp.h>` | `test/crypto_tests.cpp:20-21` | no OpenSSL call; `AES_BLOCKSIZE` comes from `crypto/aes.h` | A |
| unused `#include "random_nonce.h"` | `miner.cpp:49` | `miner.cpp` does not use `Big` | B (goes with `random_nonce.h`) |
| unused `#include <openssl/crypto.h>` (Qt) | `qt/rpcconsole.cpp:23`, `qt/explorer.cpp:19` | no OpenSSL call; Qt is deferred (P0-00), so this cannot be compiled here | Qt phase |
| orphan make rule and flags | `Makefile.am:186-188,190,193-195` (`SCRYPTDEFS`, `SCRYPTHARDENING`, `xCXXFLAGS`, `xCXXFLAGS_SCRYPT_JANE`, rule `yacoind-scrypt-jane.o`) | nothing depends on `yacoind-scrypt-jane.o`; automake builds `scrypt-jane.c` as `scrypt-jane/libyacoin_server_a-scrypt-jane.o` with the normal flags. This is the only place `USE_ASM` is set, so `USE_ASM` is never defined. **Line 191 (`DEFS+=-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA -DSCRYPT_CHOOSE_COMPILETIME`) is live and consensus-relevant** (scrypt-jane algorithm and SIMD selection) and must stay | A |
| `-rpcssl`, `-rpcsslcertificatechainfile`, `-rpcsslprivatekeyfile`, `-rpcsslciphers` help text | `init.cpp:425-428` | advertises `-rpcssl`, which `httpserver.cpp:383-385` and `rpc/client.cpp:382-384` refuse ("no longer supported"), and three options that nothing reads | A |
| testnet help text of `yacoind` | `init.cpp:381,422` ("or testnet: …"), `init.cpp:439` (`-testnet`) | `yacoind -testnet` always exits (see b). The `-testnet` text in `chainparamsbase.cpp:20` is shared with `yacoin-cli` and stays | A |
| `testnetNewLogicBlockNumber` constant | `init.cpp:73` | never used (`init.cpp:1144` only uses the option name) | A |

Not dead code, recorded here so nobody removes it as such:

- The `RAND_egd` LibreSSL check appears twice in `configure.ac`
  (`958-964` and `973-985`). The first one is an `AC_CHECK_LIB` with an empty
  action, so autoconf's default action runs: it adds `-lcrypto` to `LIBS`
  and defines `HAVE_LIBCRYPTO`. Removing it changes link lines. Both checks
  go in Phase 5.
- The help text documents `-testnetnewlogicblocknumber` (`init.cpp:440`),
  but the code reads `-testnetNewLogicBlockNumber` (`init.cpp:1144`; the
  functional tests pass that spelling, `test_node.py:100`). Option names are
  case-sensitive except on Windows, where the command line is lowercased
  (`util.cpp:415-419`). On Linux the documented spelling is therefore
  ignored. On Windows the camel-case lookup would never match, so the option
  would never work there. This was found by reading the code and not run.
  It is a help-text/option bug, not dead code; fix it together with part A
  or separately.
- In the Qt payment server, `qt/paymentserver.cpp:230,232,249` call
  `CreateChainParams`/`SelectParams` with `TESTNET`. These throw, because no
  testnet params exist. The code is reachable from a payment URI or a
  payment-request file, so this is a latent Qt bug, not dead code. Qt
  phase; from grep only, not run.

## Looks dead but is not

| Item | Why it stays |
|---|---|
| `bool scrypt_hash(..., Nfactor)` (`scrypt.cpp:108-139`) | consensus block hash |
| `DEFS+=…` (`Makefile.am:191`) | scrypt-jane compile-time selection |
| `bnProofOfStakeHardLimit` (`pow.cpp:21`) | used by `GetNextTargetRequired044` (`pow.cpp:112`) |
| `GetNfactor` (`main.cpp:100`) | display only (`rpc/mining.cpp:313`, `qt/clientmodel.cpp:210`), but used |
| `SHA256Transform` (`miner.cpp:93-106`) | `getwork` midstate (`miner.cpp:597,634`) |
| `-testnetNewLogicBlockNumber` (`init.cpp:1144`) | despite the name, sets the mainnet fork height; the functional tests use it |
| `CBaseTestNetParams` (`chainparamsbase.cpp`) | `yacoin-cli -testnet` still selects RPC port 17687 |
| `CRegTestParams` | selectable with `-regtest`; only unused by the tests |
| `getinfo` `"testnet"` field (`rpc/misc.cpp:695`) | always `false`, but it is RPC output; it comes from `Params().NetworkIDString()`, not `fTestNet` |
| local `fTestNet` (`chainparamsbase.cpp:93`) | live, see b) |

## Checked on the build

From the P0-50 mainnet test build (`contrib/testing/build.sh --config
mainnet`, pinned P0-57 image, GCC 11.5, `-O2 -g`), in
`<work-dir>/build-mainnet/src`:

- `nm libyacoin_server_a-scrypt-x86_64.o` and `nm
  libyacoin_server_a-scrypt-x86.o` both report "no symbols": `USE_ASM` is
  not defined, and the `.S` files assemble to empty objects.
- `nm -C yacoind` shows `scrypt_core(unsigned int*, unsigned int*)` with
  C++ linkage. That is the `scrypt-generic.cpp` version, which is compiled
  only without `USE_ASM`.
- `nm -C yacoind` also lists `scrypt_blockhash`,
  `scrypt_salted_multiround_hash`, `scanhash_scrypt`, `PBKDF2_SHA256`,
  `CRandomNonce::get_a_nonce`, `Big`, `ComputeMinWork` and
  `ComputeMinStake`. They are linked but never run; the build uses neither
  `--gc-sections` nor LTO.

## Removal proposal

Task [P0-59](../todo/P0-59-dead-code-removal.md) removes the list in three
PRs. It is not a Phase 0 exit criterion and is not in P0-45's dependencies:

| Part | Content | Gate | Main check |
|---|---|---|---|
| A | `scrypt-arm.S`; orphan make rule and flags (keep `:191`); `wallet/wallet.cpp:48` and `test/crypto_tests.cpp:20-21` includes; `-rpcssl*` and `yacoind` testnet help text; `init.cpp:73` | P0-50 | `make V=1` compile line of `scrypt-jane.c` identical, object byte-identical |
| B | dead `scrypt.cpp` functions, `pbkdf2.*`, `random_nonce.*`, `scrypt-generic.cpp`, `scrypt-x86*.S`, their Makefile entries, `miner.cpp:49` | P0-19 (header-hash known answers) | known answers; `objdump -dr` of `scrypt_hash` unchanged |
| C | `pow.cpp` dead functions, `main.cpp:74-75`, every `fTestNet` use | P0-14, P0-16, P0-17, P0-18, P0-19, P0-23, P0-46 | gating tests and the P0-23 replay (edited functions, and functions whose code changes through inlining such as the `net.cpp` callers of `GetDefaultPort`, cannot be compared as object code) |

Part C makes the `fTestNet` branches disappear from the branch-coverage
denominators. If it lands before P0-04, P0-04's exclusion list gets
shorter.
