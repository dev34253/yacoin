# P0-65: Persistent compiler cache (ccache) for local builds and CI

- Plan section: 0.9
- Depends on: P0-61, P0-63, P0-64
- Size: S
- Priority: top – do before all other open tasks (owner, 2026-10-08)
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-08
- Finished:

## Goal

Stop compiling everything from scratch. A measurement of the last 20
task agents (2026-10-07) showed about 10 % of a task's wall time is model
work and about 70 % is waiting for builds and CI. A full `make` takes 8–11 min
locally (4 CPUs, two configurations at `-j2` each; 71 builds = 5.6 h of
`make`), and the CI "Build and test" step takes 8–17 min per job (Tests
workflow 13 min, 21 min with coverage). Every new work dir, every merge of
master and every CI run currently compiles all ~300 files again.

## Background

- `depends` already builds `native_ccache` (`depends/packages/packages.mk`),
  and `configure` uses ccache automatically when it finds it
  (`--enable-ccache`, default auto).
- But `build.sh` runs the build in a throw-away container, so ccache's cache
  (default `$HOME/.ccache` inside the container) is lost after every run,
  and every task has its own work dir. CI has no ccache cache either.

## Steps

1. Confirm ccache is actually used today (configure output, `ccache -s`).
2. `build.sh`: put the cache in a persistent directory shared by all work
   dirs (e.g. `$YACOIN_CCACHE_DIR`, default `~/.cache/yacoin-ccache`),
   mounted into the container; set `CCACHE_DIR`, a size limit
   (`CCACHE_MAXSIZE`, e.g. 5G) and whatever is needed for hits across work
   dirs (`CCACHE_BASEDIR`/`hash_dir`, `CCACHE_NOHASHDIR`, compiler check);
   option `--no-ccache` to switch it off. Concurrent runs (P0-61 port slots)
   must be able to share the cache safely (ccache supports this).
   Print `ccache -s` (hits/misses) at the end of the build in the log.
3. `tests.yml`: cache the ccache directory per job/config with
   `actions/cache` (key with the image digest and config, restore-keys for
   partial hits), and log the hit rate. Coverage builds (-O0 --coverage) get
   their own key.
4. Measure before/after: local full build in a fresh work dir with a warm
   cache, rebuild after merging master, and CI job durations. Record the
   numbers in the Log and in `contrib/testing/README.md`.
5. Check correctness risks: coverage data (`.gcno`) with ccache, the
   `__DATE__`/`__TIME__` macros, and that a changed compiler flag or image
   digest never reuses stale objects.

## Acceptance criteria

- A second build of the same commit in a new work dir compiles from cache
  (ccache hit rate > 90 %, `make` well under 2 min) – measured and logged.
- CI "Build and test" for unit (mainnet) and unit + functional (lowdiff) is
  clearly faster on a second run of the same branch (numbers in the Log).
- Results identical: unit and functional pass counts unchanged in both
  configurations; coverage report and gate unchanged on master.
- `--no-ccache` works; docs (`contrib/testing/README.md`, CLAUDE.md
  "Building") describe the cache, its location, size and how to clear it.

## Notes

- Do not change the build image for this; ccache comes from `depends`.
- Keep the release workflow (`yacoinbuildmultiplatform.yml`) as it is.

## Detailed description

**Verified facts (step 1 of the task, 2026-10-08).** `depends` builds
ccache 3.3.4 (`depends/packages/native_ccache.mk`), `depends/config.site.in:67`
sets `CCACHE=$depends_prefix/native/bin/ccache` and `configure.ac:1063-1077`
prepends it to `CC`/`CXX` (`config.log` of an existing work dir:
`CXX='/work/src/depends/x86_64-pc-linux-gnu/share/../native/bin/ccache g++
-m64 -std=c++11'`). The container runs with `-e HOME=/tmp`, so the cache
goes to `/tmp/.ccache` inside the throw-away container and is lost after
every run; CI has no ccache cache either. ccache 3.3.4 defaults:
`max_size 5.0G`, `compression false`, `hash_dir true`, `compiler_check
mtime`, `direct_mode true`, `sloppiness` empty.

**Scope.** `contrib/testing/build.sh` (cache dir, container mount and
environment, `--no-ccache`, stats at the end of the build),
`.github/workflows/tests.yml` (restore/save the cache per job, hit rate in
the run summary), docs (`contrib/testing/README.md`, `CLAUDE.md`
"Building"), task board. Not changed: build image, `depends`, `configure`,
the release workflow, any C++ code. No consensus impact (build tooling only).
P0-66 edits `build.sh` at the same time (`--unit-args`); the changes here
stay in the option parsing, the docker arguments and the make step.

**Behaviour.**
- Cache dir on the host: `$YACOIN_CCACHE_DIR`, default
  `~/.cache/yacoin-ccache`, shared by all work dirs and all configurations
  (mainnet, lowdiff, coverage, sanitizers – the flags are part of ccache's
  hash, so they never share objects wrongly). Mounted at `/ccache` in the
  container; `CCACHE_DIR` points there. With `--no-docker` the host path is
  used directly.
- Hits across work dirs: every work dir is mounted at `/work`, so source
  paths, include paths and the compile directory (hashed because of
  `hash_dir`/`-g`, and stored in the `.gcno` files of coverage builds) are
  identical in every work dir. No `CCACHE_BASEDIR`/`CCACHE_NOHASHDIR` is
  needed, and none is set: base_dir rewrites paths passed to the compiler
  to relative ones, which would change `__FILE__`, debug info and the
  paths lcov reads from `.gcno` files. With `--no-docker` the paths differ
  per work dir, so hits come from earlier runs in the same work dir only
  (documented).
- Size: `CCACHE_MAXSIZE` from `$YACOIN_CCACHE_MAXSIZE`, default 5G (ccache
  evicts the oldest entries itself). `CCACHE_COMPRESS=1` (zlib) keeps the
  `-g` objects small on disk and in the CI cache.
- Compiler check: `CCACHE_COMPILERCHECK='%compiler% -v'` – the full GCC
  version and configuration of the image's compiler are hashed, so a
  different image with a different GCC never reuses objects. Headers
  (system and depends) are hashed by content anyway.
- `--no-ccache`: sets `CCACHE_DISABLE=1` (ccache then just runs the
  compiler; no reconfigure needed) and mounts no cache dir.
- Concurrent runs (different work dirs, P0-61) share the cache safely:
  ccache 3.3 writes results atomically (temp file + rename) and locks its
  stats files.
- Stats: before `make`, a snapshot of `ccache -s`; after `make`, the
  difference is printed as one log line, e.g.
  `ccache: 297 hits, 1 misses (99.7 % hit rate), cache 1.2 GB / 5.0 GB, dir /ccache`
  and the full `ccache -s` goes to `<builddir>/ccache.log`. Concurrent runs
  using the same cache can show up in each other's difference (documented).
  `-z` is not used: it would reset the counters of runs in progress.
- CI: cache dir `$RUNNER_TEMP/yacoin-ccache`, restored with
  `actions/cache/restore` (key `ccache-<image>-<matrix.id>-<sha>-<attempt>`,
  restore-keys `ccache-<image>-<matrix.id>-`, i.e. the newest cache of the
  same job, from this branch or master) and saved with `actions/cache/save`
  also when the tests fail (`if: always()` but not when cancelled, and only
  when the build produced a stats file). The coverage jobs have their own
  `matrix.id` (`mainnet-cov`, `lowdiff-cov`) and so their own key. The hit
  rate line goes to the job's step summary. Max size in CI smaller (set from
  the measured size of one configuration) to keep the upload small and the
  repository's 10 GB cache budget.

**Edge cases.**
- Cache dir inside the checkout: it would be mirrored into the work dir
  (untracked files are copied) – rejected with an error.
- Cache dir does not exist: created (`mkdir -p`); not writable: ccache
  then fails every compile, so `build.sh` checks writability and dies with
  a clear message.
- `YACOIN_CCACHE_MAXSIZE` not a size (`5G`, `500M`, `1.5G`, `0` = no
  limit): rejected before the build.
- `--coverage-report` does not compile; the cache is set up anyway (one
  code path), which costs nothing.
- File ownership: the container runs as the host user (`--user`), so cache
  files belong to the host user.
- `__DATE__`/`__TIME__` (`src/clientversion.cpp:93`): ccache 3.3 disables
  direct mode for a file containing them and hashes the preprocessed
  output. `share/genbuild.sh` writes `#define BUILD_DATE ""` to
  `obj/build.h`, so the macros are never expanded; `BUILD_SUFFIX` (the
  commit id) is in the preprocessed output, so a new commit recompiles
  the file. Checked: the warm build had exactly 1 preprocessed hit
  (this file) and 224 direct hits; `yacoind -version` shows the commit.
- Coverage: ccache 3.3 caches the `.gcno` file with the object and hashes
  the compile directory for `-fprofile-arcs`; checked by comparing the CI
  coverage summary and gate on this branch with master.
- Changed compiler flags (coverage, sanitizers, lowdiff via
  `bitcoin-config.h`): part of the hash, so a miss, never a stale object.
- A cold cache (first run, `--no-ccache`, new image) behaves as before.
- Disk: 12 GB free on the cloud machine; compression and the 5 G limit
  bound the cache.

**How to test.**
1. Before: build of master in a fresh work dir (copied depends cache),
   `--jobs 2`, make time from the log.
2. After, cold: same with the new `build.sh` and an empty cache dir;
   ccache line shows ~0 % hits.
3. After, warm: second fresh work dir, same commit: ccache hit rate > 90 %,
   make well under 2 min.
4. `--no-ccache`: a third run in the warm work dir after touching one
   source file: the log says ccache is off and the cache stats do not
   change; the build passes.
5. Full matrix once before the PR: mainnet `--unit` 397/397, lowdiff
   `--unit --functional` 397/397 unit and 48/48 functional (current
   numbers of `contrib/testing/README.md` "Expected results"; the 239/45
   in CLAUDE.md are outdated – P0-66 makes the counts single-source).
6. CI: first run (cold) and a re-run of the same commit (warm); job
   durations of "Build and test" and hit rates from the summary; coverage
   summary and gate equal to the latest master run.
7. `bash -n` / shellcheck on `build.sh`; the workflow YAML parses.

**Risks.** Stale objects from a wrong hash (mitigated by ccache's design,
the compiler check and keeping paths identical); cache eviction in CI
(the 10 GB repository budget is shared with the depends cache – a miss is
only slower, never wrong); disk use locally.

## Implementation plan

1. **Baseline** (before any change): `build.sh --config mainnet --jobs 2`
   on master in a fresh work dir with a copied depends cache; record the
   `make` time. *Verify:* times from the log's timestamps.
2. **build.sh, host side:** option `--no-ccache` (variable `USE_CCACHE`),
   help text and `YACOIN_CCACHE_DIR` / `YACOIN_CCACHE_MAXSIZE` in the
   environment list. Resolve the cache dir (`realpath -m`), refuse a dir
   inside the checkout, validate the max size, `mkdir -p`, check it is
   writable. Docker: `-v "$CCACHE_HOST_DIR:/ccache"` and
   `--ccache-dir /ccache` (internal option, like `--port-min`);
   `--no-docker`: `--ccache-dir "$CCACHE_HOST_DIR"`; `--no-ccache`:
   `--no-ccache` to the inner run, no mount. *Verify:* `bash -n`,
   shellcheck, `--help`, error cases (dir in checkout, bad size).
3. **build.sh, container side:** before `depends` (so `configure`'s
   compile tests use the same settings), export `CCACHE_DIR`,
   `CCACHE_MAXSIZE`, `CCACHE_COMPRESS=1`,
   `CCACHE_COMPILERCHECK='%compiler% -v'`, or `CCACHE_DISABLE=1` with
   `--no-ccache`; log one line with the settings. Snapshot the stats
   (`ccache -s` of the ccache that `configure` chose, the `CCACHE =` line
   of the build dir's `Makefile`; none → log "not used by configure"), run make,
   then log hits/misses/hit rate/size from the difference and write
   `ccache -s` to `<builddir>/ccache.log` and the one-line summary to
   `<builddir>/ccache-summary.txt` (for CI). Stats failures never fail the
   build. *Verify:* cold and warm builds (step 5).
4. **tests.yml:** in the `test` job, `env YACOIN_CCACHE_DIR=$RUNNER_TEMP/yacoin-ccache`
   and a CI size limit; `actions/cache/restore@v4` before the build,
   `actions/cache/save@v4` after it (`if: always() && !cancelled()` and the
   stats file exists), step summary line with the hit rate. Comment at the
   top updated. *Verify:* YAML parses (python yaml), CI runs twice.
5. **Measure locally:** cold (new cache dir, fresh work dir), warm (second
   fresh work dir), `--no-ccache` run, incremental rebuild after merging
   master (final run). Record in the Log.
6. **Code review** (self-review, no Agent tool) of the staged diff.
7. **Full matrix** once (mainnet unit; lowdiff unit + functional), after
   merging origin/master.
8. **Docs:** `contrib/testing/README.md` (options table, environment
   variables, "What it does", new section "Compiler cache (ccache)" with
   location, size, how to clear, numbers; CI section: cache + timings),
   `CLAUDE.md` "Building" (cache location, `--no-ccache`, clearing),
   remove P0-65 from `project/README.md` "Priority". Doc self-review.
9. **CI:** push, wait for the run, re-run it for the warm numbers; compare
   coverage summary/gate with the latest master run. Then task file to
   `done/`, PR.

Logging: build.sh is a tool, not daemon code; its log lines (`log`) are the
observable output (CLAUDE.md rule 5 applies to `debug.log` only).

## Log

- 2026-10-08 – Picked up (branch `task/P0-65-ccache-local-and-ci`, from
  master 9e5809be). Dependencies P0-61, P0-63, P0-64 are done.
- 2026-10-08 – Step 1 verified: ccache 3.3.4 from depends is in front of
  `CC`/`CXX` in every build dir (`config.log`), its cache went to
  `/tmp/.ccache` in the throw-away container.
- 2026-10-08 – Description and plan written; self-review (no Agent tool):
  the test counts in the description were the outdated CLAUDE.md ones
  (now 397/397 and 48/48 from README "Expected results"); added the max
  size validation and the `--coverage-report` case; the ccache settings
  are exported before `depends` so `configure`'s compile tests use them;
  the stats use the `CCACHE` of the build dir's `Makefile`. Not applied:
  `CCACHE_BASEDIR`/`CCACHE_NOHASHDIR` (not needed with the fixed `/work`
  mount, and would change `__FILE__`/debug/`.gcno` paths).
- 2026-10-08 – Local measurements, `--config mainnet --jobs 2`, fresh work
  dir with a copied depends cache, 4-CPU cloud machine shared with another
  agent's builds:
  - before (master `build.sh`): `make` 13 min 46 s (01:43:42–01:57:28),
    whole run 19 min 24 s (depends 4 min 51 s, unrelated to ccache);
  - after, empty cache: `make` 13 min 41 s, 0 hits / 225 misses, cache
    208.9 MB compressed;
  - after, warm cache, second fresh work dir: `make` **19 s**, whole run
    **62 s**, 225 hits (224 direct, 1 preprocessed) / 0 misses = 100 %;
  - `--no-ccache` (two files touched): log `ccache: off`, cache counters
    unchanged, no `ccache.log`, build ok.
- 2026-10-08 – Code review of the staged diff, self-review (no Agent
  tool), against `/home/user/wt/P0-65`: `set -e` safety of the `&&`
  lists, cache dir checks, inner/outer argument passing (`--ccache-dir`,
  `YACOIN_CCACHE_MAXSIZE` into the container), stats parsing against the
  real ccache 3.3.4 `-s` output, `hashFiles` only seeing the workspace
  (the save step now uses a step output instead). shellcheck: only the
  SC2015 infos the file already had.
- 2026-10-08 – CI run 37716925834 (commit c49016ef), attempt 1 (empty
  caches) vs attempt 2 (re-run, caches of attempt 1), "Build and test"
  step; master 9e5809be (run 37713759102) for comparison:

  | Job | master | attempt 1 | attempt 2 | hits attempt 2 |
  |---|---|---|---|---|
  | unit (mainnet) | 407 s | 414 s | 530 s | 0 / 225 |
  | unit + functional (lowdiff) | 746 s | 748 s | 744 s | 0 / 225 |
  | coverage (mainnet) | 819 s | 828 s | **523 s** | 225 / 225 |
  | coverage (lowdiff) | 1061 s | 1051 s | 1119 s | 225 / 225 |

  **Bug found:** the `-O2` jobs restored the wrong cache – restore prefix
  `ccache-<image>-mainnet-` also matches `ccache-<image>-mainnet-cov-…`
  (the log shows the cache growing from 149.8 MB, the coverage cache, to
  358.5 MB). Fixed: keys are now `ccache-<image>-<id>-sha-<sha>-<attempt>`
  with restore prefix `…-<id>-sha-`. The coverage jobs (no prefix clash)
  show the effect: 100 % hits, compile part of coverage (mainnet) down by
  about 5 min; coverage (lowdiff) is dominated by the -O0 functional tests
  and runner variance. Coverage with cached objects and `.gcno` files:
  merged report of attempt 2 vs master has the identical set of 36614
  instrumented lines; 10 lines differ in hit/not hit (net.cpp,
  httpserver.cpp, wallet.cpp, … – timing-dependent functional test
  paths, in both directions), gate result unchanged (all ok, overall
  73.69 % vs 73.68 % lines).
- 2026-10-08 – Merged origin/master (P0-66, 0f104a60): conflicts in
  `build.sh` (`--unit-args` next to the ccache options) and the Priority
  list (now empty) resolved.
- 2026-10-08 – Final local runs after the merge (`--jobs 2`):
  mainnet `--unit`: 397/397 unit test cases, vector checkers ok, exit 0;
  `make` 24 s with the build dir deleted (224/225 hits). lowdiff
  `--unit --functional`: 397/397 unit, 48/48 functional (ALL Passed),
  exit 0; incremental `make` 8 s (1 miss: `clientversion.cpp`). Before the
  merge the cold lowdiff build took 13 min 35 s (0/225 hits; mainnet and
  lowdiff share no objects because every file includes
  `bitcoin-config.h`).
