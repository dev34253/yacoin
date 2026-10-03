# P0-11: Compact (nBits) encoding tests

- Plan section: 0.2a
- Depends on: P0-10
- Size: S
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Pin SetCompact/GetCompact exactly.

## Steps

1. Every exponent 0–34, sign bit, mantissa overflow, 0x00800000, zero, values ≥ 2^256.
2. Port Bitcoin Core's arith_uint256 compact tests; list every difference from Yacoin's behaviour.

## Acceptance criteria

- [ ] All cases pass against current code.
- [ ] Differences from arith_uint256 listed in Log (Phase 4 special cases).

## Notes

-

## Log

-
