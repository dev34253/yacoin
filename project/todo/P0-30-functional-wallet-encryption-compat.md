# P0-30: Functional test: wallets from older releases

- Plan section: 0.5
- Depends on: P0-00, P0-22, P0-54
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Verify that the OpenSSL → internal AES/KDF switch keeps old encrypted wallets working.

## Steps

1. Create encrypted wallets with v1.0.0 and v1.1.0 (which used OpenSSL EVP_BytesToKey) and with the baseline; store as fixtures. Mainnet release binaries are fine for offline wallet creation.
2. Test: load, unlock, change passphrase, keypool top-up, dumpprivkey, sign and send.

## Acceptance criteria

- [ ] test/functional/wallet_encryption_compat.py passes and is in test_runner.py.

## Notes

Review: A1, E2.

## Log

-
