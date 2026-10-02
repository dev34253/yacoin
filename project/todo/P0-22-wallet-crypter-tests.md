# P0-22: Wallet encryption known-answer tests and fixtures

- Plan section: 0.2h
- Depends on: P0-06
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Pin wallet encryption so encrypted wallets keep working after OpenSSL is removed.

## Steps

1. Known-answer vectors: EVP_BytesToKey (SHA-512, N rounds) and AES-256-CBC with 0/15/16/17 bytes of padding.
2. Wrong passphrase, damaged ciphertext, empty input.
3. Master-key encrypt/decrypt round trip; decrypt a stored encrypted key created by the baseline binary (fixture).

## Acceptance criteria

- [ ] wallet/crypter.cpp ≥ 95% lines covered.
- [ ] Fixture of encrypted key material committed.

## Notes

Existing tests: src/wallet/test/crypto_tests.cpp.

## Log

-
