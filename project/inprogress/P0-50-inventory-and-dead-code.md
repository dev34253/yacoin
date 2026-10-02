# P0-50: Inventory correction and dead-code list

- Plan section: 0.1
- Depends on: none
- Size: S
- Owner: Claude (subagent of the owner's Claude Code session)
- Started: 2026-10-02
- Finished:

## Goal

Keep the plans factually right and list dead code for removal.

## Steps

1. Verify the corrected OpenSSL/CBigNum inventory in plans/overview.md against the source (review A1, A2, A5, A8, A10, B5).
2. Dead-code list: unused scrypt.cpp functions (scrypt_blockhash, salted, multiround, scanhash_scrypt), pbkdf2.cpp, random_nonce.cpp, unused CBigNum methods (from P0-12), dead fTestNet branches.
3. Propose removal as a separate PR (outside Phase 0 consensus freeze rules, since none of it is reachable).

## Acceptance criteria

- [ ] Inventory confirmed; dead-code list committed to plans/; removal PR proposed.

## Notes

Feeds P0-04 coverage exclusions. Review: A1, A2, A5, A8, B5.

## Log

-
