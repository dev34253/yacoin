# P0-33: Functional test: RPC output snapshots

- Plan section: 0.5
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Detect unintended changes to RPC output.

## Steps

1. Deterministic regtest chain; call getblock, getblockheader, getdifficulty, getmininginfo, getblocktemplate, getblockchaininfo.
2. Mask volatile fields (times, sizes that depend on randomness); compare with stored JSON.
3. Option to regenerate snapshots deliberately.

## Acceptance criteria

- [ ] test/functional/rpc_output_snapshots.py passes and is in test_runner.py.

## Notes

-

## Log

-
