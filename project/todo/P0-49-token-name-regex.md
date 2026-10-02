# P0-49: Token-name validation characterisation

- Plan section: 0.2g
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Pin the std::regex-based token-name rules, which are consensus.

## Steps

1. Generate all names up to length 4 over the relevant alphabet plus adversarial cases (brackets, punctuation, unicode bytes, very long names).
2. Record the accept/reject result of IsTokenNameValid and the tag validators (tokens/tokens.cpp:67-74, used from consensus/tx_verify.cpp:227,328,587) as a golden set.
3. Test replays the golden set.

## Acceptance criteria

- [ ] Golden set committed; test passes in both build configurations and is part of P0-53.

## Notes

libstdc++ regex changed between GCC 5 and 13; mingw and libc++ differ. Review: B3.

## Log

-
