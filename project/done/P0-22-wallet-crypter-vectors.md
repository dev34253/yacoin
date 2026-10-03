# P0-22: Wallet encryption known-answer vectors

- Plan section: 0.2j
- Depends on: P0-01
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Replace the OpenSSL test oracle with fixed vectors and pin the already-internal AES/KDF.

## Steps

1. Known-answer vectors for BytesToKeySHA512AES (several round counts) and AES-256-CBC with 0/15/16/17 bytes of padding, generated once against the OpenSSL oracle in wallet/test/crypto_tests.cpp and stored as fixed data.
2. Wrong passphrase, damaged ciphertext, empty input; master-key round trip.

## Acceptance criteria

- [x] wallet/crypter.cpp ≥ 95% lines (96.62 %, 200/207; functions 100 %).
- [x] Fixed vectors committed; OpenSSL oracle can later be removed without losing coverage (the seven new cases use no OpenSSL).

## Notes

wallet/crypter.cpp already uses crypto/aes.h and crypto/sha512.h. Review: A1.

## Detailed description

### Verified facts (step 1)

- `wallet/crypter.cpp:8-9` includes `crypto/aes.h` and `crypto/sha512.h`;
  `BytesToKeySHA512AES` (`:17-42`) is the node's own EVP_BytesToKey
  (SHA-512, one D_0 block, `count` rounds); Encrypt/Decrypt use
  `AES256CBCEncrypt/Decrypt` with padding (`:75-111`). No OpenSSL in the
  crypter (review A1 confirmed).
- `wallet/test/crypto_tests.cpp` **is** a real OpenSSL oracle:
  `OldSetKeyFromPassphrase` calls `EVP_BytesToKey`, `OldEncrypt/OldDecrypt`
  call `EVP_*crypt*`, `TestDecrypt` calls `SSLeay()` (`:17-84,143`). The P0-50
  note about stale OpenSSL includes is about `src/test/crypto_tests.cpp`, a
  different file. Only one fixed known answer exists today (key/IV for
  "test"/`0000deadbeef0000`/25000, `:194-196`); everything else is
  random input compared against OpenSSL.
- `CCryptoKeyStore` (`crypter.cpp:139-329`) has no unit test; its coverage
  (73.4 % lines for the file, plan 0.10) comes only from the functional
  wallet-encryption tests.
- Behaviour that differs from OpenSSL (recorded, not changed):
  `CCrypter::Encrypt` of an **empty** plaintext returns `true` with an
  **empty** ciphertext (`CBCEncrypt` returns 0 for size 0, `crypto/aes.cpp:83`;
  OpenSSL gives one padding block), and `Decrypt` of a block that is all
  padding (plaintext would be empty) returns `false` (`CBCDecrypt` returns
  `written * !fail` = 0, `crypter.cpp:106`). Both use `&v[0]` on an empty
  vector. No wallet path encrypts empty data (secrets and the master key
  are 32 bytes), so there is no user impact → `project/known-issues.md`.

### Scope

Test code and test data only; no change to `wallet/crypter.{h,cpp}`,
`crypto/` or any other node code. Changes:
- `contrib/testing/crypter_vectors.py` (new): independent Python 3
  standard-library model (hashlib SHA-512/SHA-256, AES-256 from FIPS-197,
  CBC + PKCS#7, the CCrypter decrypt rules, secp256k1 public keys, the
  `CMasterKey` serialisation) that writes and checks
  `src/test/data/crypter_vectors.json`; self-tests against FIPS-197 and
  SP 800-38A known answers; `--cross-check` additionally compares every AES
  vector with the OpenSSL CLI and, if installed, the `cryptography` package.
- `src/test/data/crypter_vectors.json` (new, embedded like the other JSON
  test data via `JSON_TEST_FILES`).
- `src/wallet/test/crypto_tests.cpp`: new test cases in the existing suite
  `wallet_crypto` (needed for the `friend` access to `CCrypter`'s key/IV and
  `BytesToKeySHA512AES` without touching `crypter.h`); the new cases do not
  use OpenSSL, so the oracle cases (`passphrase`, `encrypt`, `decrypt`) and
  the `Old*` helpers can later be deleted without losing coverage. The
  oracle stays for now.
- `contrib/testing/build.sh`: run `crypter_vectors.py --check` with the
  other vector checkers in `--unit`.
- `contrib/testing/coverage-gates.toml`: ratchet the `wallet/crypter.cpp`
  gate to the measured values.
- Docs: `contrib/testing/README.md`, `src/test/README.md` (format),
  test counts (CLAUDE.md, README, skill, `doc/architecture.md`), plan 0.2j
  status, known issues.
Not done: removing the oracle (Phase 5), end-to-end v1.0.0/v1.1.0 wallet
files (P0-30), any fix of the empty-input behaviour.

### Behaviour (new test cases)

1. `kdf_vectors`: for each KDF vector, `BytesToKeySHA512AES` (direct,
   friend access) gives the expected key and IV; for 8-byte salts
   `SetKeyFromPassphrase(…, 0)` sets the same key/IV and returns true.
   Vectors: rounds 1, 2, 3, 1000, 25000 (incl. the existing
   fc7aba…/cf2f26… answer), 123457; passphrases empty, ASCII, UTF-8,
   one with an embedded NUL byte, 100 bytes; salt empty (direct call only)
   and 8 bytes.
2. `kdf_invalid_arguments`: `BytesToKeySHA512AES` returns 0 for count 0,
   null key, null IV; `SetKeyFromPassphrase` returns false for 0 rounds,
   salt of 0/7/9 bytes, derivation method 1, and leaves the crypter
   unkeyed (Encrypt/Decrypt return false); a crypter that was keyed and then
   fails with 0 rounds or a bad salt keeps its old key, and with method 1
   has its key/IV cleansed (zero) while fKeySet stays true – pins current
   behaviour (see edge cases); CleanKey zeroes and unsets.
3. `aes_cbc_vectors`: fixed key/IV, plaintext lengths 1, 15, 16, 17, 31,
   32, 33, 48 (padding 15, 1, 16, 15, 1, 16, 15, 16 bytes): Encrypt gives the
   expected ciphertext, Decrypt gives the plaintext back. Length 0: the
   standard ciphertext (one padding block) is in the file, and the test pins
   the CCrypter deviation (Encrypt → true + empty; Decrypt of the padding
   block → false). `SetKey` rejects key 31/33 bytes and IV 15/17 bytes.
4. `decrypt_vectors`: CCrypter decrypt outcomes (`ok` + plaintext):
   damaged last block (padding check fails), damaged first block (decrypts
   to a garbled known plaintext), wrong key, wrong IV (first block changes
   only), length not a multiple of 16, empty, padding byte 0, padding byte
   17, inconsistent padding bytes, valid full padding block.
5. `masterkey_vectors`: `CMasterKey` with the fixed salt/rounds/crypted key
   serialises to the expected bytes and deserialises back; deriving the key
   from the right passphrase and decrypting gives the master key; encrypting
   the master key gives the stored crypted key; the wrong passphrase gives
   the recorded outcome (`ok` false).
6. `keystore_encrypt_unlock`: a `CCryptoKeyStore` subclass that exposes
   `EncryptKeys`/`Unlock`/`DecryptKeys`: plain store behaviour
   (not crypted, not locked); `EncryptKeys` with the fixed master key stores
   exactly the expected crypted secrets (IV = first 16 bytes of the
   public key's double SHA-256), clears the plain keys, a second call fails;
   locked: GetKey/AddKeyPubKey fail, GetPubKey works; Unlock with the wrong
   master key or with no keys fails; Unlock with the right one works and
   GetKey returns the original keys; AddKeyPubKey while unlocked stores the
   expected crypted secret; Lock() locks again; Lock() on a plain store with
   keys fails, on an empty one makes it crypted; AddCryptedKey fails on a
   plain store with keys; crypted secrets of wrong length or for a different
   public key make GetKey fail; `EncryptKeys` with a 31-byte master key
   fails.
7. `keystore_decrypt_keys`: `DecryptKeys` on a plain store fails, with the
   wrong master key fails, with a wrong-length secret fails; with the right
   key it pins today's behaviour (found in the first test run): locked it
   fails, unlocked it re-encrypts every key (through the virtual
   `AddKeyPubKey`) and then clears the crypted map – returns true, keys
   gone. Its only caller `CWallet::DecryptWallet` has no caller (known
   issue).

### Edge cases

- Both build configurations: nothing here depends on chain parameters; the
  same expected values in mainnet and lowdiff.
- Run time: the KDF vectors cost ~150k SHA-512 rounds in C++ (ms) and in
  Python (< 1 s).
- `fKeySet` after a failed `SetKeyFromPassphrase` on an already-keyed
  crypter stays true while key/IV are zeroed (a quirk of the code; no
  caller reuses a crypter after failure). Pinned as is and noted in known
  issues.
- `Unlock` with some keys decrypting and others not hits `assert(false)`;
  not tested (would abort the test binary); its two lines stay uncovered.
- Unreachable lines (`Encrypt` `nLen < size`, `AddCryptedKey` failure
  inside `AddKeyPubKey`/`EncryptKeys`, `AddKey` failure in `DecryptKeys`)
  stay uncovered; ≥ 95 % lines is still reachable.
- The empty-vector `&v[0]` cases are only run where current behaviour is
  well defined in practice (libstdc++ without `_GLIBCXX_ASSERTIONS`); if
  a future build enables assertions, that test documents why it fails.
- Python 3.12, standard library only (the build image has no
  `cryptography`); `--cross-check` is optional and used once at generation.
- Independence: expected values come from the Python model (hashlib +
  FIPS-197 AES + secp256k1 arithmetic), cross-checked against the OpenSSL
  3 CLI; the C++ oracle in the same file also agrees (it runs as before).

### How to test

| Criterion | Test / command | Expected |
|---|---|---|
| Fixed vectors committed, independent | `contrib/testing/crypter_vectors.py --check` and `--cross-check` | exit 0, 0 mismatches |
| Node agrees with the vectors | `build.sh --config mainnet --unit`, `--config lowdiff --unit --functional` | 381 (master after merge) + 7 unit cases pass in both; 48/48 functional; vector check in `vectors.log` OK |
| Oracle removable | the new cases use no OpenSSL symbol (grep) | – |
| crypter.cpp ≥ 95 % lines | `build.sh --coverage --unit` both configs + `--coverage-report`, `coverage_gate.py` | ≥ 95 % lines, gate passes; ratchet with `--suggest` |
| CI | PR checks | green incl. coverage gate |

### Risks

None for consensus: no node code changes. Risk of a wrong vector is
covered by the second, independent source (OpenSSL CLI) and by the
existing OpenSSL oracle in the same binary.

## Implementation plan

1. `contrib/testing/crypter_vectors.py`: model (SHA-512 KDF, AES-256
   FIPS-197 with self-test vectors FIPS-197 C.3 and SP 800-38A F.2.5/F.2.6,
   CBC/PKCS#7, CCrypter decrypt rules, secp256k1 compressed/uncompressed
   public key, SHA256d, CMasterKey serialisation), `--write`, `--check`
   (default; byte-for-byte compare), `--cross-check` (OpenSSL CLI
   `enc -aes-256-cbc -K -iv [-nopad]`, optional `cryptography`). Verify:
   `--write`, `--check`, `--cross-check` all exit 0; break one hex digit in
   the file → `--check` exits 1.
2. `src/test/data/crypter_vectors.json` written by step 1; add to
   `JSON_TEST_FILES` in `src/Makefile.test.include`.
3. `src/wallet/test/crypto_tests.cpp`: JSON loader (format/version check,
   as `header_hash_tests.cpp`), helper statics in `TestCrypter`, a
   `TestCryptoKeyStore` subclass, the seven cases of the description.
   Verify: mainnet unit build and run of `--run_test=wallet_crypto`.
4. `build.sh`: add `crypter_vectors.py --check` to the checker loop. Verify
   in `vectors.log`.
5. Full test runs (both configs), coverage runs (both configs +
   `--coverage-report`), `coverage_gate.py --suggest` → ratchet the
   crypter gate in `coverage-gates.toml` with a measured comment.
6. Docs: `src/test/README.md` format section, `contrib/testing/README.md`
   (checker section + list in step 6 of build.sh description), test counts,
   plan 0.2j status, `project/known-issues.md` (empty input; fKeySet after
   failed derivation). No logging changes (test code only; rule 5 applies
   to node behaviour, none changed).
7. Code review (self-review, no Agent tool), doc review, commit, push, PR,
   CI.

## Log

- 2026-10-03 step 0: dependency P0-01 done; branch
  `task/P0-22-wallet-crypter-vectors` (from master 5d95667); moved to
  inprogress (51ad2b2).
- 2026-10-03 step 1: claims verified (see "Verified facts"). Corrections:
  the wallet `crypto_tests.cpp` is a real OpenSSL oracle (the P0-50 "stale
  includes" note is about `src/test/crypto_tests.cpp`); the task's
  "generated against the OpenSSL oracle" became "generated by an
  independent Python model, cross-checked with the OpenSSL CLI and the
  `cryptography` package" (brief: independent source); "0/15/16/17 bytes of
  padding" read as plaintext lengths 0/15/16/17 (padding is 1–16 bytes),
  extended to 1…48. `CWallet::DecryptWallet` (only caller of
  `DecryptKeys`) has no caller – known issue.
- 2026-10-03 step 3, description review (self-review, no Agent tool):
  re-read against crypter.cpp and the checklist. Added: on a keyed
  crypter, 0 rounds / bad salt keep the old key (not only the method-1
  zeroing); `DecryptWallet` is dead, so the "store stays crypted" quirk has
  no user impact; the `&v[0]`-on-empty UB is recorded, and the test runs it
  only where it is harmless today (no sanitizer job in CI). Not applied:
  testing the `Unlock` partial-failure path (it is `assert(false)` and would
  abort `test_bitcoin`).
- 2026-10-03 step 5, plan review (self-review, no Agent tool): include path
  `test/data/crypter_vectors.json.h` (found through `-I$(builddir)` in
  out-of-tree builds); the generator is pure standard library because the
  build image has no `cryptography` (checked: it has `openssl` 3 and Python
  3.12); the new cases must stay in suite `wallet_crypto` because
  `crypter.h` befriends `wallet_crypto::TestCrypter` (a second class of that
  name in another file would break the ODR) – so no new file and no change
  to `crypter.h`. The Python source is kept ASCII (`\u` escapes).
- 2026-10-03 step 6: `contrib/testing/crypter_vectors.py` written;
  `--selftest` ok (FIPS-197 C.3, SP 800-38A F.2.5/F.2.6, 1G/2G, oracle
  answer); `--write`, `--check` ok; `--cross-check` 53 comparisons
  (openssl 3.0.13, cryptography 49.0.0), 0 disagree; a changed value in a
  copy of the file makes `--check` exit 1. Seven cases added to
  `wallet_crypto`; checker added to `build.sh --unit`.
- 2026-10-03 step 8, first run: `keystore_decrypt_keys` failed – my
  expectation was wrong, not the vectors: `DecryptKeys` re-adds keys through
  the virtual `AddKeyPubKey`, so it fails on a locked store and loses the
  keys on an unlocked one. Test changed to pin that (known issue, dead
  caller `DecryptWallet`). Then: mainnet 384/384, lowdiff 384/384 + 48/48
  functional, all four vector checkers ok. `wallet_crypto` new cases take
  ~0.2 s (-O2).
- 2026-10-03 step 7, code review (`code-review` skill, medium) on the staged
  diff: no correctness bugs; two low findings, both applied – the JSON
  loader now resets on a bad format/version so every case fails, and the
  known-issues text on crypter reuse in `CWallet` was wrong (Unlock /
  ChangeWalletPassphrase do reuse one crypter; `wallet.cpp:429,433` ignore
  the result, `:441` re-checks) – corrected.
- 2026-10-03 coverage (local, mainnet `--coverage --unit` + lowdiff
  `--coverage --unit --functional` + `--coverage-report`, code of
  341702d): `wallet/crypter.cpp` 96.62 % lines (200/207), 100 % functions
  (before: 73.43 / 94.12); gate passed. Ratcheted the crypter gate to
  lines 96 / functions 100 (`--suggest`); the other gates' suggestions come
  from other tasks' tests and are left to them. Uncovered: `Encrypt`'s
  short-output return, the `Unlock` LogPrintf/assert pair, the
  unreachable `AddCryptedKey`/`AddKey` failure returns, and `Unlock` on a
  plain store with keys (`:176`) – the last one is covered by one more
  check added after the measurement (f71e4db).
- 2026-10-03 step 10, documentation review (self-review, no Agent tool):
  checked `src/test/README.md`, `contrib/testing/README.md`, known issues,
  plan 0.2j against the code and the runs; fixed a line reference
  (`crypter.cpp:106`), the runtime claim, the "not in the image" claim
  (the image has `openssl`, not `cryptography`), a paragraph wrap.
- 2026-10-03 merged origin/master (P0-55, #79, #80; d44bbf2); counts now
  381 + 7 = 388 unit, 48 functional. No Boost ≥ 1.59-only macros in the
  new cases (BOOST_CHECK/REQUIRE/_EQUAL/_MESSAGE only).
- 2026-10-03 step 8, final runs on d44bbf2 (merged master): mainnet
  388/388 unit; lowdiff 388/388 unit and 48/48 functional; all four vector
  checkers ok in both.
- 2026-10-03 step 11: PR https://github.com/dev34253/yacoin/pull/82
