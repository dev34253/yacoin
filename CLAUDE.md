# CLAUDE.md

Yacoin is a Bitcoin Core 0.16-derived PoW/PoS cryptocurrency (C++11, autotools,
`depends` build system). This fork (dev34253/yacoin) tracks yacoin/yacoin and is
modernising the dependencies (OpenSSL, Boost, compiler) so it builds on current
Linux. Work is organised in `project/` – read `project/README.md` first; plans
are in `project/plans/`, tasks in `project/{todo,inprogress,done}/`, operational
guides in `project/runbooks/`.

## Implementing a task

To implement a task from the project board (e.g. "do P0-14"), **spawn a
subagent (Agent tool) and have it run the `implement-task` skill on that
task** (`.claude/skills/implement-task/SKILL.md`). The skill is the required
process: read the task → detailed description with edge cases and tests →
reviewed by a subagent → implementation plan → reviewed → implement → code
review → tests until all pass → documentation → documentation review →
commit, push and pull request. Give the subagent the task id and the branch
to use, and report its result (PR link, test results, open points) back. If
the subagent has no Agent tool of its own, the skill tells it to do the
reviews as separate, logged self-review passes.

## Rules for every change

1. **Consensus safety.** Never change consensus behaviour (difficulty, block
   trust, stake kernel, rewards, block size, block hash, script/token rules)
   unless the plan explicitly calls for it and the Phase 0 tests cover it.
   Phase 0 records current behaviour, bugs included – pin it, don't fix it.
2. **Run the tests locally before every commit** (see *Testing*). At minimum
   the unit tests; the functional suite for anything touching node, wallet,
   RPC, P2P or consensus code. Paste the results (pass counts) into the PR or
   task log. Never commit with new failures; never skip or disable a test.
3. **Static analysis** (once P0-58 lands): run it on the changed files before
   committing; CI fails on findings that are not in the recorded baseline.
4. **Review the code before every commit.** Run the `code-review` skill (or a
   reviewer subagent) on the staged diff, fix or explicitly answer every
   finding, then commit. Mention in the commit message body that it was
   reviewed and anything deliberately left as is.
5. **Logging.** New or changed behaviour must be observable in `debug.log`:
   - `LogPrintf(...)` for important, always-on events (start-up, errors,
     consensus-relevant decisions, rejections with their reason).
   - `LogPrint(BCLog::<CATEGORY>, ...)` for detail/debug output, using an
     existing category from `src/util.h` (NET, MEMPOOL, RPC, DB, …) or a new
     one if none fits.
   - Include the values needed to diagnose (hashes, heights, sizes), never
     secrets (keys, passphrases, RPC passwords). No `printf`/`std::cout` in
     daemon code.
6. **Documentation.** Add or update documentation for everything new or
   changed in the same commit/PR: `doc/` for builds and user-facing behaviour,
   RPC help text for RPCs, `project/` for plans, tasks and runbooks, code
   comments for non-obvious logic. **Documentation is reviewed like code** –
   include it in the review in rule 4 and check it against what was actually
   built and run.
7. **Task board.** Move task files with `git mv` (todo → inprogress → done),
   fill in Owner/Started/Finished and a short Log with results and links.

## Building

The supported build uses `depends` inside a pinned Docker image:
`dev34253/yacoin-build:ubuntu.24.04-gcc11-1` (Ubuntu 24.04, GCC 11 – task P0-57;
pin `dev34253/yacoin-build@sha256:b7365321bd98ce7297c30bc2eb555f56407548d4cea1836cfbd4b806ba934f7a`; legacy:
`dev34253/yacoin-build:ubuntu.22.04-1`; GCC 13 variant:
`dev34253/yacoin-build:ubuntu.24.04-1`).
The easiest way is `contrib/testing/build.sh` (P0-01; see
`contrib/testing/README.md`). It builds out of tree in the pinned image and
can run the tests:

```bash
contrib/testing/build.sh --config mainnet --unit                 # unit tests
contrib/testing/build.sh --config lowdiff --unit --functional    # all tests
```

Equivalent manual steps, run inside the build image. They modify the
checkout (`autogen.sh` rewrites some tracked build files, `depends` writes
into `depends/`), which `build.sh` avoids by building from a copy:

```bash
make -C depends -j"$(nproc)" HOST=x86_64-pc-linux-gnu NO_QT=1   # Qt is deferred
./autogen.sh
mkdir -p build-lowdiff && cd build-lowdiff
../configure --prefix=$PWD/../depends/x86_64-pc-linux-gnu \
  --with-gui=no --enable-low-difficulty-for-development
make -j"$(nproc)"
```

- **Two configurations:** *mainnet* (no extra flag) for unit tests and
  anything mainnet-related; *low difficulty*
  (`--enable-low-difficulty-for-development`) for functional tests.
- **Coverage:** `build.sh --config <cfg> --coverage --unit [--functional]`
  writes `<builddir>/coverage/` (lcov `.info`, HTML, summary);
  `build.sh --coverage-report` merges mainnet + lowdiff (union; see
  `contrib/testing/README.md`).
- **CI:** `.github/workflows/tests.yml` runs unit tests (both configs) and
  functional tests (lowdiff) on every push to any branch; coverage (HTML as
  a run artifact) on `master` and via *Run workflow*. The release builds
  (`yacoinbuildmultiplatform.yml`) run on `master`, tags and by hand (P0-03).
- Binaries built on Ubuntu 24.04 need glibc ≥ 2.38 (dev/CI only, not release).

## Testing

```bash
src/test/test_bitcoin --log_level=test_suite          # unit tests (306)
python3 test/functional/test_runner.py -j4            # functional tests (45)
```

- Expected today: 306/306 unit tests in both builds (mainnet and low
  difficulty) and 45/45 functional (low-difficulty build); `build.sh` (see
  *Building*) exits 0 for both configurations. Tests whose results depend on
  the chain parameters pin the expected value per build with `#ifdef
  LOW_DIFFICULTY_FOR_DEVELOPMENT` (e.g. `pow_tests/get_next_work_pow_limit`,
  P0-02) – never skip a test in one build.
- The functional runner reads `test/config.ini` next to its own source dir; for
  out-of-tree builds copy `<builddir>/test/config.ini` to `test/config.ini`.
- Any stderr output (including Python warnings) fails a functional test.
- Consensus unit tests use the harness in `src/test/consensus_harness.h`
  (P0-47; usage in `src/test/README.md`): explicit, restored globals,
  block-index chains, blocks on disk, index-chain CSV loader.
- Functional tests do **not** use regtest: they run main params with the
  low-difficulty genesis, `-epochinterval=10`, N-factor 4. Unit tests run with
  the fork globals (`nMainnetNewLogicBlockNumber`, `nFactorAtHardfork`) at 0.
- RPCs that do not exist here: `getblockchaininfo`, `gettxoutsetinfo` (use
  `getinfo`; `gettxoutsetinfo` is task P0-48).

## Environment notes

- **Cloud sessions:** Docker is installed but not running – start `dockerd`.
  Containers need the proxy and CA: `--network host -e HTTPS_PROXY -e
  https_proxy=$HTTPS_PROXY -e SSL_CERT_FILE=/ca.crt -e CURL_CA_BUNDLE=/ca.crt
  -v /root/.ccr/ca-bundle.crt:/ca.crt:ro`. Docker Hub may answer 429 – retry
  with backoff. Outbound P2P (port 7688) is blocked, so no mainnet node here.
- **Mainnet node:** runs on the owner's laptop (`yacoind.service`, datadir
  `/srv/yacoin/datadir`), set up per `project/runbooks/mainnet-node-setup.md`
  and reachable through the owner's Remote Control session.
- **Build images** are defined in dev34253/yacoin-build-ubuntu and published
  to Docker Hub as `dev34253/yacoin-build:<tag>`.
