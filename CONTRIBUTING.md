# Contributing to YACoin

These rules apply to every contributor, human or coding agent.

## Pull requests

- Work on a branch named `task/<id>-<slug>`. Pull requests go to `dev34253/yacoin` `master`, never to `yacoin/yacoin`. No direct pushes to
  `master`.
- Fill in the pull request template, [`.github/pull_request_template.md`](.github/pull_request_template.md): the task, what changed, how it
  was tested, the acceptance criteria with their evidence, and the checks.
- A pull request is merged after an independent review approves it and CI is green, and after the owner's approval where these rules
  require it.

## Tests

- Develop test-first: write a failing test, then the code that makes it pass. Every change adds or extends functional tests in
  `test/functional/`, not only unit tests.
- Test coverage only goes up. The coverage check (`./dev.sh cov-check` after `./dev.sh cov`, and the CI job `coverage-report`) compares the
  coverage against the targets in [`contrib/devtools/coverage-targets.json`](contrib/devtools/coverage-targets.json). A file that now meets
  its target is recorded as met, and a recorded value that rises is written there, in the same pull request (see
  [`doc/developer-build.md`](doc/developer-build.md)).
- Compiler warnings only go down. The CI job `warnings` (`./dev.sh container warnings`) builds with `-Wall -Wextra` and fails when a class
  of warnings has more unique locations than [`contrib/devtools/warning-counts.json`](contrib/devtools/warning-counts.json) records; a pull
  request that removes warnings lowers the values there. A value rises only in a pull request of its own for a toolchain change (a
  compiler or library version, or the warning flags) that adds locations without a code change, with the old and the new count of each
  class in its description.
- Before opening a pull request, build and run the unit and functional tests: `./dev.sh all`, or the container modes
  `./dev.sh container unit-tests` and `./dev.sh container functional-tests` (see [`doc/developer-build.md`](doc/developer-build.md)). CI must
  pass; it also runs the unit tests under AddressSanitizer with LeakSanitizer and under UBSan (the two legs of the
  `unit-tests-asan` job) and under ThreadSanitizer (the `unit-tests-tsan` job), and the functional tests under
  AddressSanitizer, LeakSanitizer and UBSan (the `functional-tests-asan` job, two shards). `./dev.sh asan` or
  `./dev.sh container unit-tests-asan`, `./dev.sh container unit-tests-tsan` and `./dev.sh container functional-tests-asan`
  run them locally. `SANITIZE=address ./dev.sh container unit-tests-asan` (or `undefined`) runs one leg of
  `unit-tests-asan`, `FTEST_SHARD=1/2 ./dev.sh container functional-tests-asan` (or `2/2`) one shard of
  `functional-tests-asan`, as CI does. `unit-tests-asan` and `./dev.sh asan` leave out the test cases listed in
  `test/sanitizer_suppressions/asan-excluded-cases`, and `functional-tests-asan` the scripts listed in
  `test/sanitizer_suppressions/asan-excluded-scripts`.

## Rules

- Consensus-critical code is `src/consensus/`, `src/validation.cpp`, `src/pow.*`, `src/kernel.*`, `src/script/`, `src/primitives/`,
  `src/chainparams*`, `src/scrypt*`, `src/bignum.h`, `src/arith_uint256.*`, the token validation code, and the serialisation of blocks,
  transactions and coins. A change to it is never mixed with refactoring or formatting. The pull request says whether the change is neutral
  (no block changes validity) or a rule change. It carries a replay result
  ([`contrib/replay/README.md`](contrib/replay/README.md#replay-of-a-pull-request)) and merges only with a green `replay` status on its
  reviewed head commit; a rule change also needs the owner's approval.
- A new or upgraded dependency has its upstream signature or hash checked. Each `depends/` recipe pins the SHA-256 hash of its source, which
  every download is checked against; [`ci/depends-sources.sh`](ci/depends-sources.sh) checks that every source can still be downloaded over
  https and that the mirror's copy matches that hash.
- Files in this repository describe only the current state: no task ids, no planned work, no history of where files came from. That
  belongs in commit messages.
- This repository is public: do not describe security findings in commits, pull requests or code comments. Report a vulnerability
  privately, as [`SECURITY.md`](SECURITY.md) describes.
