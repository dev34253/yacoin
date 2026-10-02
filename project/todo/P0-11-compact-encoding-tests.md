# P0-11: Compact (nBits) encoding tests

- Plan section: 0.2a
- Depends on: P0-10
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Pin SetCompact/GetCompact behaviour exactly, including edge cases.

## Steps

1. Every exponent 0–34, sign bit set, mantissa overflow, 0x00800000, zero.
2. Port Bitcoin Core's arith_uint256 compact tests; record every case where Yacoin's result differs.

## Acceptance criteria

- [ ] All cases pass against current code.
- [ ] Differences from Bitcoin's arith_uint256 listed in Log (these are the cases Phase 4 must special-case).

## Notes

-

## Log

-
