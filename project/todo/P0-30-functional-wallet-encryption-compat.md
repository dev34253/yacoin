# P0-30: Functional test: wallet encryption compatibility

- Plan section: 0.5
- Depends on: P0-00, P0-06, P0-22
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Prove encrypted wallets created by older binaries keep working.

## Steps

1. Fixture wallets: encrypted wallet from the baseline binary; optionally from v1.0.0/v1.1.0 releases (per P0-00).
2. Test: load, unlock, change passphrase, keypool top-up, dumpprivkey, sign and send.

## Acceptance criteria

- [ ] test/functional/wallet_encryption_compat.py passes and is in test_runner.py.

## Notes

-

## Log

-
