# Contributing to YACoin

The workflow and the rules of this repository are in [`CLAUDE.md`](CLAUDE.md). They apply to every contributor, human or coding agent.
This file is a short guide to them.

## Tasks and pull requests

- Work is planned in tasks kept outside this repository. Each pull request names its task.
- Work on a branch `task/<id>-<slug>`. Pull requests go to `master` of `dev34253/yacoin`, not to the upstream repository `yacoin/yacoin`.
  Nobody pushes to `master` directly.
- Fill in the pull request template, [`.github/pull_request_template.md`](.github/pull_request_template.md): the task, what changed, how it
  was tested, the acceptance criteria with their evidence, and the checks.
- A pull request is merged after an independent review approves it, and after the owner's approval where the task or the rules in
  [`CLAUDE.md`](CLAUDE.md) require it.

## Changes

- Develop test-first. Every change adds or extends functional tests in `test/functional/`, not only unit tests.
- Before opening a pull request, build and run the unit and functional tests: `./dev.sh all`, or the container modes
  `./dev.sh container unit-tests` and `./dev.sh container functional-tests` (see [`doc/developer-build.md`](doc/developer-build.md)). CI must
  pass. `./dev.sh asan` runs the unit tests under the sanitizers as well (optional).
- Consensus-critical code (the paths are listed in [`CLAUDE.md`](CLAUDE.md)) is never mixed with refactoring or formatting. The pull request
  says whether the change is neutral or a rule change, and it needs the owner's approval.
- A new or upgraded dependency needs the owner's approval.
- Files in this repository describe only the current state: no task ids, no planned work, no history of where files came from. That
  belongs in commit messages.
- This repository is public: do not describe security findings in issues, commits, pull requests or code comments.
