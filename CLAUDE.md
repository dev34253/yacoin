# YACoin

YACoin node: a Bitcoin Core 0.15-era C++11 code base with YACoin's own consensus (scrypt-jane proof of work at N-factor 21, `nTime` in transactions, a
token layer). It is being modernised in phases.

## Where the plan is

Plan, tasks and documentation live in the private repository `dev34253/yacoin-modernization-plan-agile`:

- `plan/working-agreement.md`: how work is done; binding.
- `project/todo/`, `inprogress/`, `done/`: one file per task. Every change here belongs to a task; read its file before starting.
- `docs/`: how this code works at commit `6d72383`, the gap register (`MG-nnn`) and the security findings (`S-nn`).

## Build and test

- `./dev.sh` without arguments lists the commands: `depends`, `build dev|release`, `unit`, `ftest`, `asan`, `cov`.
- `depends/` does not build with gcc 14 or newer (Boost 1.64). Use gcc 13 or older, or the CI image `dev34253/yacoin-build:ubuntu.22.04-2`.
- CI (`.github/workflows/yacoinbuildmultiplatform.yml`) runs 9 jobs on every push and pull request, about 20 minutes.

## Rules

- **Safety net first:** no defect fixes and no changes to product code (anything compiled into `yacoind`, `yacoin-cli`, `yacoin-qt`) until the Phase 1
  coverage work is done.
- **Consensus-critical code** (`src/consensus/`, `src/validation.cpp`, `src/pow.*`, `src/kernel.*`, `src/script/`, `src/primitives/`,
  `src/chainparams*`, `src/scrypt*`, `src/bignum.h`, `src/arith_uint256.*`, token validation, serialisation of blocks, transactions and coins): never
  mixed with refactoring or formatting; say whether a change is neutral or a rule change; needs the owner's approval.
- Work on branch `task/<id>-<slug>`. Pull requests go to `dev34253/yacoin` `master`, never to `yacoin/yacoin`. No direct pushes to `master`.
- No new or upgraded dependency without the owner's approval.
- This repository is public: do not describe security findings in commits, pull requests or code comments.
