# P0-22: Wallet encryption known-answer vectors

- Plan section: 0.2j
- Depends on: P0-01
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Replace the OpenSSL test oracle with fixed vectors and pin the already-internal AES/KDF.

## Steps

1. Known-answer vectors for BytesToKeySHA512AES (several round counts) and AES-256-CBC with 0/15/16/17 bytes of padding, generated once against the OpenSSL oracle in wallet/test/crypto_tests.cpp and stored as fixed data.
2. Wrong passphrase, damaged ciphertext, empty input; master-key round trip.

## Acceptance criteria

- [ ] wallet/crypter.cpp ≥ 95% lines.
- [ ] Fixed vectors committed; OpenSSL oracle can later be removed without losing coverage.

## Notes

wallet/crypter.cpp already uses crypto/aes.h and crypto/sha512.h. Review: A1.

## Log

-
