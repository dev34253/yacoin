# P0-39: Port bench_bitcoin framework

- Plan section: 0.7
- Depends on: P0-01
- Size: M
- Owner:
- Started:
- Finished:

## Goal

Add a microbenchmark framework; there is no src/bench in this tree.

## Steps

1. Port src/bench (framework + bench_bitcoin.cpp) from Bitcoin Core 0.16.
2. Wire into configure (--enable-bench) and the Makefile.
3. Add one trivial benchmark to prove it works.

## Acceptance criteria

- [ ] bench_bitcoin builds and runs in the P0-01 build.

## Notes

-

## Log

-
