# CLAUDE.md

Yacoin is a Bitcoin Core 0.16-derived PoW/PoS cryptocurrency (C++11, autotools,
`depends` build system). This fork (dev34253/yacoin) tracks yacoin/yacoin and is
modernising the dependencies (OpenSSL, Boost, compiler) so it builds on current
Linux. Work is organised in `project/` – read `project/README.md` first; plans
are in `project/plans/`, tasks in `project/{todo,inprogress,done}/`, operational
guides in `project/runbooks/`.

**Yacoin's future is proof-of-work only** (owner, 2026-10-03). Proof-of-stake
matters only so that the existing chain still validates (initial sync,
reindex, reorgs over historical blocks); there will be no new PoS. Keep PoS
work to what reproducing the historical chain needs – do not add PoS features,
PoS mining/staking support or tests of hypothetical future PoS behaviour.

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
   A pull request is merged only when its CI run is green.
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
   comments for non-obvious logic. Keep `doc/functional-specification.md`
   (behaviour), `doc/architecture.md` (structure) and
   `doc/design-decisions.md` (one entry per significant decision) current.
   **Documentation is reviewed like code** –
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
- **Compiler cache:** `build.sh` keeps a ccache cache shared by all work
  dirs in `$YACOIN_CCACHE_DIR` (default `~/.cache/yacoin-ccache`, limit
  `$YACOIN_CCACHE_MAXSIZE`, default 5G), so a new work dir or a merge of
  master recompiles only what changed; the log shows the hit rate.
  `--no-ccache` turns it off; clear it with `rm -rf` on the directory. CI
  caches it per job (P0-65; `contrib/testing/README.md`).
- **Coverage:** `build.sh --config <cfg> --coverage --unit [--functional]`
  writes `<builddir>/coverage/` (lcov `.info`, HTML, summary);
  `build.sh --coverage-report` merges mainnet + lowdiff (union; see
  `contrib/testing/README.md`) and runs the coverage gate (P0-04,
  minimums in `contrib/testing/coverage-gates.toml`; exit 1 below a
  minimum). A task that raises coverage raises the minimums (README
  "Coverage gate", `coverage_gate.py --suggest`).
- **CI:** `.github/workflows/tests.yml` runs unit tests (both configs) and
  functional tests (lowdiff) on every push to any branch; coverage (HTML as
  a run artifact) and the coverage gate on `master`, via *Run workflow*, and
  on branches that change a file the gate watches (gated/excluded files in
  `coverage-gates.toml`, the gate's own files; P0-63). The release builds
  (`yacoinbuildmultiplatform.yml`) run on `master`, tags and by hand (P0-03). Branches that change only
  documentation (`*.md`, `doc/`, `project/`, `.claude/`) skip the build and
  test jobs (P0-64); `[skip ci]` in a commit message skips CI for that push.
- Binaries built on Ubuntu 24.04 need glibc ≥ 2.38 (dev/CI only, not release).

## Testing

```bash
src/test/test_bitcoin --log_level=test_suite          # unit tests
python3 test/functional/test_runner.py -j4            # functional tests
```

- Expected: every unit test passes in both builds (mainnet and low
  difficulty) and every functional test in the low-difficulty build;
  `build.sh` (see *Building*) exits 0 for both configurations. The exact
  counts are deliberately not written down here (they change with every
  task and made every PR conflict): take them from `unit.log` /
  `functional.log` or the CI run, and record them in the PR and task Log.
  Tests whose results depend on the chain parameters pin the expected value
  per build with `#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT` (e.g.
  `pow_tests/get_next_work_pow_limit`, P0-02) – never skip a test in one
  build.
- **Local test scope** (P0-66). While developing, build the affected
  configuration and run only the affected tests:
  `build.sh --config <mainnet|lowdiff> --unit --unit-args "--run_test=<suite>"`,
  `build.sh --config lowdiff --functional --functional-args "-j2 <test>.py"`.
  These targeted runs are for the edit–build loop and never replace
  rule 2: before every commit run the full unit suite (and the functional
  suite where rule 2 requires it), and before the pull request run both
  `--config mainnet --unit` and `--config lowdiff --unit --functional`
  in full.
  Coverage and the coverage gate run in CI (P0-63: on `master` and on
  branches that change a watched file); run `--coverage` locally only to
  get `--suggest` values when raising a gate minimum, or to debug a gate
  failure. CI on the PR runs the unit tests (both configurations) and the
  functional tests again, plus coverage and the gate when a watched file
  changed (branches that change only documentation skip the build and
  test jobs, P0-64); paste its result into the PR and merge only when it
  is green.
- **Waiting** for a background build or a CI run: wait on a completion
  marker (the background command's exit, a `build.sh exit N` line appended
  to its log, the CI run's `completed` status) – never a fixed `sleep N`.
  Ready-made snippets are in the implement-task skill ("Waiting").
- Chain parameters, checkpoints, stake-modifier checkpoints and the fork
  defaults are pinned (P0-20: `src/test/chainparams_snapshot_tests.cpp`,
  `test/functional/feature_params_snapshot.py`; table in plan section
  0.2h). Changing one on purpose means updating the test as well.
  `test_bitcoin` fails (exit 1) if node code calls `StartShutdown()`, e.g.
  through a failed release-build `Yassert`.
- The functional runner reads `test/config.ini` next to its own source dir; for
  out-of-tree builds copy `<builddir>/test/config.ini` to `test/config.ini`.
- Any stderr output (including Python warnings) fails a functional test.
- Test code must also compile with Boost 1.58: the release workflow's
  `build-ubuntu-1604-functional-test` job builds with Ubuntu 16.04's system
  Boost (no `BOOST_TEST_CONTEXT`, `BOOST_TEST(...)` or data-driven test
  cases unless guarded by `BOOST_VERSION`; see `reward_tests.cpp`).
- Consensus unit tests use the harness in `src/test/consensus_harness.h`
  (P0-47; usage in `src/test/README.md`): explicit, restored globals,
  block-index chains, blocks on disk, index-chain CSV loader.
- Functional tests do **not** use regtest: they run main params with the
  low-difficulty genesis, `-epochinterval=10`, N-factor 4. Unit tests run with
  the fork globals (`nMainnetNewLogicBlockNumber`, `nFactorAtHardfork`) at 0.
- RPCs that do not exist here: `getblockchaininfo` (use `getinfo` /
  `gettimechaininfo`). `gettxoutsetinfo` exists (P0-48) but its
  `hash_serialized` is Yacoin's own definition (doc/functional-specification.md §7).

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
