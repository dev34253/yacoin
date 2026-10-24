# YACoin

YACoin node: a Bitcoin Core 0.15-era C++11 code base with YACoin's own consensus (scrypt-jane proof of work at N-factor 21, `nTime` in transactions, a
token layer). It is being modernised in phases.

## Build and test

- `./dev.sh` without arguments lists the commands: `depends`, `build dev|release`, `unit`, `ftest`, `asan`, `cov`.
- `depends/` does not build with gcc 14 or newer (Boost 1.64). Use gcc 13 or older, or the CI image `dev34253/yacoin-build:ubuntu.22.04-2`.
- CI (`.github/workflows/yacoinbuildmultiplatform.yml`) runs 9 jobs on every push and pull request, about 20 minutes.

## Rules

- **Consensus-critical code** (`src/consensus/`, `src/validation.cpp`, `src/pow.*`, `src/kernel.*`, `src/script/`, `src/primitives/`,
  `src/chainparams*`, `src/scrypt*`, `src/bignum.h`, `src/arith_uint256.*`, token validation, serialisation of blocks, transactions and coins): never
  mixed with refactoring or formatting; say whether a change is neutral or a rule change; needs the owner's approval.
- Work on branch `task/<id>-<slug>`. Pull requests go to `dev34253/yacoin` `master`, never to `yacoin/yacoin`. No direct pushes to `master`.
- No new or upgraded dependency without the owner's approval.
- This repository is public: do not describe security findings in commits, pull requests or code comments.
