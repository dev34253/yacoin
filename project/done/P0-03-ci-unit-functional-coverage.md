# P0-03: CI jobs for unit, functional and coverage

- Plan section: 0.1, 0.9
- Depends on: P0-01
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished: 2026-10-03

## Goal

Run unit and functional tests on every push and publish coverage reports.

## Steps

1. GitHub Actions workflow using the P0-01 script: unit tests in the configuration chosen in P0-01; functional tests (test_runner.py -j4) in the low-diff configuration.
2. Collect lcov per configuration; define and document how the two .info files are merged (different #ifdef line maps) or reported separately.
3. Exclude /usr, depends, test, leveldb, secp256k1, univalue, bench.
4. Upload HTML and .info files as artifacts; print summaries in the log.

## Acceptance criteria

- [x] Workflow runs on push and is green apart from known failures tracked in tasks. (Run 37088055181, all five jobs green; no known failures left.)
- [x] Coverage HTML downloadable from each run; merge method documented. (Artifacts `coverage-mainnet`, `coverage-lowdiff`, `coverage-merged`; merge method in `contrib/testing/README.md`. Since the owner decision below, "each run" means each run on `master` or started by hand.)

## Notes

Review: C5.

## Detailed description

### Scope

Will be done:

- A new workflow `.github/workflows/tests.yml` (GitHub Actions, hosted
  `ubuntu-24.04` runners) that runs on every push (and manually via
  `workflow_dispatch`); the coverage jobs and the report only on `master`
  and `workflow_dispatch` (owner decision 2026-10-03, see Log):
  - `unit (mainnet)`: `build.sh --config mainnet --unit` (`-O2`).
  - `unit + functional (lowdiff)`: `build.sh --config lowdiff --unit
    --functional` (`-O2`, `test_runner.py -j4`).
  - `coverage (mainnet)` and `coverage (lowdiff)`: the same tests in a
    `--coverage` build (`-O0`), each producing an lcov `.info`, an HTML report
    and a text summary.
  - `coverage report`: merges the two `.info` files into one, produces the
    merged HTML report and prints all three summaries in the log and the
    run's job summary.
- `contrib/testing/build.sh` extensions (used by CI and locally):
  - With `--coverage` and a test option: reset the counters before the tests
    (so repeated runs in one build dir do not add up), record a zero
    baseline (`lcov -c -i`, so files no test touches count as 0 % instead of
    being missing), capture after the tests, filter, write
    `<builddir>/coverage/{coverage.info,summary.txt,html/}`. Captured even when
    tests fail (the exit code stays non-zero).
  - New `--coverage-report`: no build; merges the `coverage.info` of
    `build-mainnet-cov` and `build-lowdiff-cov` in the work dir (both must
    exist) into `WORK_DIR/coverage-report/{merged.info,summary.txt,html/}`.
- Filter (task step 3): remove `/usr/*`, `*/depends/*`, `*/test/*` (unit-test
  sources `src/test`, `src/wallet/test`), `*/src/leveldb/*`,
  `*/src/secp256k1/*`, `*/src/univalue/*`, `*/src/bench/*`, and generated
  files in the build dir.
- Branch coverage on (`--rc branch_coverage=1`), so P0-04 can gate branches.
  Exception branches stay in the numbers (`--rc no_exception_branch=1` drops
  all branch data with lcov 2.0, see Log); P0-04 may filter them.
- Caching the depends cache (`WORK_DIR/depends-cache`: downloaded sources and
  built packages) with `actions/cache`, keyed on the image digest and
  `hashFiles('depends/**')`.
- Documentation: `contrib/testing/README.md` (coverage options, merge
  method, CI), plan 0.1/0.9 rows, `CLAUDE.md` testing notes. (No separate
  `doc/` section: `doc/` holds the upstream build guides; the test-build
  and CI documentation lives in `contrib/testing/README.md`, which
  `CLAUDE.md` points to.)

Will not be done (other tasks): coverage thresholds/gates (P0-04), schedule,
self-hosted runner, image mirroring to GHCR, artifact storage beyond the
default retention (P0-44), sanitizers (P0-29), changes to the existing
release-build workflow `yacoinbuildmultiplatform.yml` (unchanged apart from
the concurrency group and its trigger: `master`, tags and by hand).

### Design choices

- **Docker on the runner, not a `container:` job.** `build.sh` in its
  default Docker mode is exactly what developers run locally (same sync,
  lock, version string, paths `/work/...` in the `.info` files), the runner
  has Docker, git, Python and flock, and the image needs neither Node.js
  (for JavaScript actions inside a container job) nor a git checkout inside
  it. The image is pulled once per job by digest with a retry loop (Docker
  Hub may answer 429 for anonymous pulls).
- **Coverage in separate jobs** from the `-O2` test jobs: the `-O2` jobs test
  the optimised code that is closest to a release, the `-O0` jobs measure
  coverage; the four jobs run in parallel, so wall time is that of the
  slowest job plus the report job.
- **Merge method (review finding C5):** gcov records coverage against the
  original source file and line, not the preprocessed text, so both
  configurations use the same line numbers for the same file. Lines inside
  `#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT` / `#ifndef` exist (are
  instrumented) in only one build. `lcov -a mainnet.info -a lowdiff.info`
  therefore produces the **union**: a line is counted in the denominator if
  it is instrumented in at least one configuration and as hit if it ran in
  at least one; hit counts are added. Per-configuration reports are kept
  next to the merged one, so a reader can see what one configuration alone
  covers. The merged number is the one P0-04 gates on.

### Behaviour

- A push to any branch starts the `Tests` workflow with the two test jobs;
  green when 277/277 unit tests pass in both configurations and 45/45
  functional tests pass. On `master` and by hand, the two coverage jobs and
  the report run as well.
- Artifacts per run: `coverage-mainnet`, `coverage-lowdiff`,
  `coverage-merged` (each `coverage.info`/`merged.info`, `summary.txt`,
  `html/`), and on failure `logs-mainnet`, `logs-lowdiff`,
  `logs-mainnet-cov`, `logs-lowdiff-cov` (build and test logs,
  functional-test datadirs).
- Locally:
  ```
  build.sh --config mainnet --coverage --unit
  build.sh --config lowdiff --coverage --unit --functional
  build.sh --coverage-report
  ```
  gives the same three reports under the work dir.

### Edge cases

- Repeated coverage runs in one build dir: counters reset each run.
- Test failure in a coverage job: coverage still captured and uploaded; job
  fails.
- `--coverage-report` with a missing configuration: clear error naming the
  missing file.
- `--coverage-report` combined with build/test options: rejected.
- `--no-docker` without lcov installed: clear error.
- lcov 2.0 (image) is strict about inconsistent data; the flags needed are
  documented in the script, warnings are not hidden wholesale.
- The `.info` paths are absolute (`/work/src/...` under Docker); merging
  `.info` files from Docker and `--no-docker` runs is not supported
  (documented).
- Cache: a depends change gives a new key (restore-keys fall back to the
  newest cache for the same image; depends' own hashes decide what is
  rebuilt). Concurrent jobs with the same key: only one saves, harmless.
- Disk on hosted runners (~14 GB free on the root fs advertised; estimate):
  one `-O0` build is about 2–3 GB (estimate); the CI coverage jobs passed.
- Superseded pushes on the same branch cancel the older run (concurrency
  group).

### How to test

| Acceptance criterion | Test | Expected |
|---|---|---|
| Workflow runs on push and is green | push the branch; inspect run with the GitHub tools | all five jobs succeed; record run URL |
| Unit both configs, functional lowdiff | job logs | 277/277 mainnet, 277/277 lowdiff, 45/45 functional |
| Coverage HTML downloadable | run artifacts | `coverage-mainnet`, `coverage-lowdiff`, `coverage-merged` present |
| Merge method documented | README + task log | section in `contrib/testing/README.md` |
| Exclusions applied | `lcov --list merged.info` | no `/usr`, depends, test, leveldb, secp256k1, univalue, bench paths |
| build.sh changes do not break normal runs | local `build.sh --config mainnet --unit`, `--config lowdiff --unit --functional` | 277/277, 277/277, 45/45 (done in CI only, see Log) |
| Coverage path locally | local mainnet and lowdiff coverage runs and `--coverage-report` | three summaries; merged lines ≥ each config (mainnet locally; lowdiff and merge in CI only, see Log) |
| Counter reset | re-run capture in the same dir | numbers do not grow |

### Risks

- No consensus code is touched (CI and test scripts only).
- Hosted-runner runtime of `-O0` unit tests (estimated 7–10 min; the
  mainnet coverage job took ~15 min in CI including the build) and Docker
  Hub rate limits are the main operational risks; recorded in the log.

## Implementation plan

1. `build.sh`: add `--coverage-report` option (validation: no build/test
   options with it; host side forwards it), `coverage_start` (zero counters
   + baseline before tests), `coverage_finish` and `coverage_html`
   (capture/filter/HTML/summary after) and a `coverage_report` function (merge both configs). Common lcov
   options in one variable. Verify: `bash -n`, `shellcheck` if available,
   local mainnet coverage run.
2. `.github/workflows/tests.yml`: matrix job (4 entries) + report job, image
   pull with retry, depends cache, artifact uploads, job summary. Verify:
   YAML parses (`python3 -c yaml.safe_load`), then push and read the run.
3. Local tests: plain mainnet unit, lowdiff unit+functional, mainnet and
   lowdiff coverage (one at a time because of disk: keep only
   `coverage/`, delete the rest of each `-cov` build dir I created), then
   `--coverage-report`.
4. Docs: `contrib/testing/README.md` (coverage + CI sections, merge method),
   plan 0.1/0.9, `CLAUDE.md` (no `doc/` note, see Scope).
5. Iterate on CI until green; record run URL, runtimes, coverage summary.

## Log

- 2026-10-03: moved to inprogress (commit 65e7512). Dependency P0-01 done; P0-02 (PR #51, branch base of this task) treated as done.
- 2026-10-03: detailed description and implementation plan written.
- 2026-10-03: description review – self-review (no Agent tool), a separate pass against the step-3 checklist. Applied: lcov rc names checked against the image's `/etc/lcovrc` (lcov 2.0-1: `branch_coverage`, `no_exception_branch`, `--parallel`); build-dir filter made path-independent (`$WORK_DIR/build-*`, works under Docker and `--no-docker`); report job fails with a clear error when a configuration's `.info` is missing; job timeout added. Noted, not changed: the upstream job `build-ubuntu-1604-functional-test` stays (out of scope; P0-44 decides about removing duplicates).
- 2026-10-03: plan review – self-review (no Agent tool). Applied: README "Expected results" and the job summary (`$GITHUB_STEP_SUMMARY`) added to steps 4/2; local coverage runs ordered one at a time because of ~6 GB free disk. No consensus impact (CI and test scripts only).
- 2026-10-03: implementation findings while testing locally (lcov 2.0-1, GCC 11.5): (1) capturing the whole build dir failed with lcov's "mismatched end line" error for Boost.Test case functions in `src/test` and on a stale `conftest.gcno` from configure – fixed by capturing `<builddir>/src` with the exclusions applied at capture time (`--exclude`, `--ignore-errors unused` because `src/secp256k1` is not instrumented); (2) a negative branch count in `crypto/sha256.cpp:206` (lost updates from threads) – fixed with `-fprofile-update=atomic` in the coverage flags; (3) changing `CFLAGS` re-ran configure but make rebuilt nothing (pre-existing P0-01 gap) – `build.sh` now runs `make clean` after configure when the configure arguments of an existing build dir changed; (4) `--rc no_exception_branch=1` dropped *all* branch data – not used, exception branches stay in the branch numbers (P0-04 may filter them).
- 2026-10-03: code review of the build.sh/workflow diff – self-review (no Agent tool; the `code-review` skill is not available to this subagent). Checked: option validation of `--coverage-report`, coverage capture also after failed tests, stale `.gcda` (removed by `--zerocounters` before each run), container user/HOME on the runner, `pipefail` in workflow steps (`defaults.run.shell: bash`), artifact paths vs. download paths in the report job, cache key/restore-keys. No further changes needed; shellcheck: only the existing SC2015 info notes (same `a && b || die` idiom as the rest of the script).
- 2026-10-03: at the coordinator's request (Actions queue backed up by runs of superseded pushes): `concurrency: group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true` in `tests.yml` and, as a separate small hunk, in `yacoinbuildmultiplatform.yml`. First run 37085301900 was queued behind other runs (waiting for runners, not a failure).
- 2026-10-03: cancelled this branch's two superseded queued runs (Tests 37085301900, multi-platform 37085301820; their concurrency group predates the change). Current runs for f40295c: Tests 37085971721, multi-platform 37085971696 – queued for runners.
- 2026-10-03: CLAUDE.md (coverage and CI bullets) and plan 0.1 CI row updated.
- 2026-10-03: **paused** – waiting on the local lowdiff coverage run (unit + functional) was denied by the session's permission classifier; local lowdiff/merge results and the CI result are still open. Open: local `--config mainnet --unit`, `--config lowdiff --unit --functional`, lowdiff coverage + `--coverage-report`; CI run green; coverage summary; documentation review; move to done.
- 2026-10-03: CI, first run of `tests.yml` with all jobs (Tests run 37086040249 on 7d6b5d0): unit (mainnet), unit + functional (lowdiff), coverage (mainnet), coverage (lowdiff) green (~8, ~14, ~15, ~19 min incl. build); `coverage report (merged)` failed with "--coverage-report does not build or test": the outer `build.sh` always passed `--config` to the inner run in the container. Fixed in bfbf47e (`--config` only for build runs); tested with two small lcov tracefiles in a scratch work dir (merged, exit 0; `--coverage-report --config lowdiff` still rejected; shellcheck clean). Master merged in (2267f36, now includes P0-02/P0-10/P0-47/P0-50).
- 2026-10-03: CI, Tests run 37088055181 on 2267f36 (https://github.com/dev34253/yacoin/actions/runs/37088055181): **all five jobs green** – unit (mainnet) 8 min, unit + functional (lowdiff) 12 min, coverage (mainnet) 11 min, coverage (lowdiff) 16.5 min, coverage report (merged) 1 min. Unit tests 277/277 in both configurations, functional 45/45. Coverage (lines / functions / branches): mainnet 41.1 % / 50.0 % / 14.6 %, lowdiff 69.9 % / 76.9 % / 32.0 %, merged 69.9 % (25168 of 36015 lines) / 76.9 % / 32.0 %. (The 75.6 % of the earlier manual measurement used other exclusions; these numbers are the baseline for P0-04.)
- 2026-10-03: **Local test runs:** only the mainnet coverage run (239/239 at the time) was done locally. The plain mainnet and lowdiff runs, the lowdiff coverage run and `--coverage-report` on real data were not completed locally (waiting on the build log was denied by the session's permission classifier); with the owner's agreement the task was verified through the CI runs above instead.
- 2026-10-03: documentation review by a reviewer subagent (12 findings). Applied: exception-branch wording, test counts 277, release workflow "unchanged apart from concurrency group/trigger", `doc/` note dropped from scope (test-build docs live in `contrib/testing/README.md`), plan 0.9 row, log of CI results, `logs-*` artifact names, report job runs after failed test jobs, exact options `--coverage-report` rejects, one-time `make clean` of old build dirs, current function names, estimates marked as such, CLAUDE.md "any branch". Nothing left out.
- 2026-10-03: owner decision (CI took too long: every push ran 5 Tests jobs plus the 8 release-build jobs, ~20 runners shared by all branches): coverage jobs and the merged report run only on `master` and via *Run workflow*; `yacoinbuildmultiplatform.yml` runs only on `master`, tags and *Run workflow*. Task-branch pushes now run the two test jobs (~8–12 min). actionlint clean (apart from the pre-existing `actions/checkout@v3` warnings in the release workflow). ccache in CI left for P0-44.
- 2026-10-03: done. PR https://github.com/dev34253/yacoin/pull/56.
