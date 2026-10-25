# YACoin

YACoin node: a Bitcoin Core 0.15-era C++11 code base with YACoin's own consensus (scrypt-jane proof of work at N-factor 21, `nTime` in transactions, a
token layer). It is being modernised in phases.

## Workflow

Always develop test-first (TDD): write a failing test, make it pass, then clean up. Every change also adds or extends functional tests in
`test/functional/`, not only unit tests; test coverage only goes up.

1. **Take a task:** claim it and read its task file and the documents it links (where tasks live: `CLAUDE.local.md`).
2. **TDD with a dev subagent:** it writes the tests first, then the code, on branch `task/<id>-<slug>`.
3. **Code review with another subagent:** it sees only the task and the diff. Fix the findings and review again, at most 3 rounds; if findings remain
   after the third, stop and ask the owner.
4. **Test with a QA subagent:** build, run the unit and functional tests, and check every acceptance criterion end to end.
5. **Push and create the pull request** to `dev34253/yacoin` `master`, using the template.
6. **Pull request review:** by another agent, which may run additional tests, or by a human. Merge only after it approves, and after the
   owner's approval where the task or the rules require it.
7. **Compound engineering:** once the task is merged, look at what made it harder than it needed to be and fix that for the next task: update
   this file, test helpers, scripts or the subagent instructions. Record what changed in the task's `## Outcome`.

Throughout, keep the task's two log files (where: `CLAUDE.local.md`):

- the processing log: what was done, findings, review rounds, QA and decisions, newest last;
- the outside log: ideas, defects and improvements that surfaced but are outside the task. Do not do them now; they become new tasks.

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
- Files here (code, comments, READMEs, docs) describe only the current state: no task ids, no planned work, and no history of where files came
  from. That belongs in commit messages and the task logs.
