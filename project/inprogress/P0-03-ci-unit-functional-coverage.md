# P0-03: CI jobs for unit, functional and coverage

- Plan section: 0.1, 0.9
- Depends on: P0-01
- Size: M
- Owner: Claude (subagent of session_01WsmJnB8GRWou3iWwRMffgf)
- Started: 2026-10-03
- Finished:

## Goal

Run unit and functional tests on every push and publish coverage reports.

## Steps

1. GitHub Actions workflow using the P0-01 script: unit tests in the configuration chosen in P0-01; functional tests (test_runner.py -j4) in the low-diff configuration.
2. Collect lcov per configuration; define and document how the two .info files are merged (different #ifdef line maps) or reported separately.
3. Exclude /usr, depends, test, leveldb, secp256k1, univalue, bench.
4. Upload HTML and .info files as artifacts; print summaries in the log.

## Acceptance criteria

- [ ] Workflow runs on push and is green apart from known failures tracked in tasks.
- [ ] Coverage HTML downloadable from each run; merge method documented.

## Notes

Review: C5.

## Detailed description

### Scope

Will be done:

- A new workflow `.github/workflows/tests.yml` (GitHub Actions, hosted
  `ubuntu-24.04` runners) that runs on every push (and manually via
  `workflow_dispatch`):
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
- Branch coverage on (`--rc branch_coverage=1`, exception branches excluded
  with `--rc no_exception_branch=1`), so P0-04 can gate branches.
- Caching the depends cache (`WORK_DIR/depends-cache`: downloaded sources and
  built packages) with `actions/cache`, keyed on the image digest and
  `hashFiles('depends/**')`.
- Documentation: `contrib/testing/README.md` (coverage options, merge
  method, CI), a short CI section in `doc/` (where to find the reports),
  plan 0.1/0.9 rows, `CLAUDE.md` testing notes.

Will not be done (other tasks): coverage thresholds/gates (P0-04), schedule,
self-hosted runner, image mirroring to GHCR, artifact storage beyond the
default retention (P0-44), sanitizers (P0-29), changes to the existing
release-build workflow `yacoinbuildmultiplatform.yml` (kept unchanged).

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

- A push to any branch starts the `Tests` workflow with five jobs; the run is
  green when 239/239 unit tests pass in both configurations, 45/45
  functional tests pass and both coverage jobs and the report succeed.
- Artifacts per run: `coverage-mainnet`, `coverage-lowdiff`,
  `coverage-merged` (each `coverage.info`/`merged.info`, `summary.txt`,
  `html/`), and `logs-<job>` on failure (build and test logs, functional-test
  datadirs).
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
- Disk on hosted runners (~14 GB free on the root fs advertised): one
  `-O0` build is about 2–3 GB; fine.
- Superseded pushes on the same branch cancel the older run (concurrency
  group).

### How to test

| Acceptance criterion | Test | Expected |
|---|---|---|
| Workflow runs on push and is green | push the branch; inspect run with the GitHub tools | all five jobs succeed; record run URL |
| Unit both configs, functional lowdiff | job logs | 239/239 mainnet, 239/239 lowdiff, 45/45 functional |
| Coverage HTML downloadable | run artifacts | `coverage-mainnet`, `coverage-lowdiff`, `coverage-merged` present |
| Merge method documented | README + task log | section in `contrib/testing/README.md` |
| Exclusions applied | `lcov --list merged.info` | no `/usr`, depends, test, leveldb, secp256k1, univalue, bench paths |
| build.sh changes do not break normal runs | local `build.sh --config mainnet --unit`, `--config lowdiff --unit --functional` | 239/239, 239/239, 45/45 |
| Coverage path locally | local mainnet and lowdiff coverage runs and `--coverage-report` | three summaries; merged lines ≥ each config |
| Counter reset | re-run capture in the same dir | numbers do not grow |

### Risks

- No consensus code is touched (CI and test scripts only).
- Hosted-runner runtime of `-O0` unit tests (7–10 min locally) and Docker
  Hub rate limits are the main operational risks; recorded in the log.

## Implementation plan

1. `build.sh`: add `--coverage-report` option (validation: no build/test
   options with it; host side forwards it), a `coverage_capture` function
   (zero counters + baseline before tests, capture/filter/HTML/summary after)
   and a `coverage_report` function (merge both configs). Common lcov
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
   `doc/` CI note, plan 0.1/0.9, `CLAUDE.md`.
5. Iterate on CI until green; record run URL, runtimes, coverage summary.

## Log

- 2026-10-03: moved to inprogress (commit 65e7512). Dependency P0-01 done; P0-02 (PR #51, branch base of this task) treated as done.
- 2026-10-03: detailed description and implementation plan written.
- 2026-10-03: description review – self-review (no Agent tool), a separate pass against the step-3 checklist. Applied: lcov rc names checked against the image's `/etc/lcovrc` (lcov 2.0-1: `branch_coverage`, `no_exception_branch`, `--parallel`); build-dir filter made path-independent (`$WORK_DIR/build-*`, works under Docker and `--no-docker`); report job fails with a clear error when a configuration's `.info` is missing; job timeout added. Noted, not changed: the upstream job `build-ubuntu-1604-functional-test` stays (out of scope; P0-44 decides about removing duplicates).
- 2026-10-03: plan review – self-review (no Agent tool). Applied: README "Expected results" and the job summary (`$GITHUB_STEP_SUMMARY`) added to steps 4/2; local coverage runs ordered one at a time because of ~6 GB free disk. No consensus impact (CI and test scripts only).
- 2026-10-03: implementation findings while testing locally (lcov 2.0-1, GCC 11.5): (1) capturing the whole build dir failed with lcov's "mismatched end line" error for Boost.Test case functions in `src/test` and on a stale `conftest.gcno` from configure – fixed by capturing `<builddir>/src` with the exclusions applied at capture time (`--exclude`, `--ignore-errors unused` because `src/secp256k1` is not instrumented); (2) a negative branch count in `crypto/sha256.cpp:206` (lost updates from threads) – fixed with `-fprofile-update=atomic` in the coverage flags; (3) changing `CFLAGS` re-ran configure but make rebuilt nothing (pre-existing P0-01 gap) – `build.sh` now runs `make clean` after configure when the configure arguments of an existing build dir changed; (4) `--rc no_exception_branch=1` dropped *all* branch data – not used, exception branches stay in the branch numbers (P0-04 may filter them).
- 2026-10-03: code review of the build.sh/workflow diff – self-review (no Agent tool; the `code-review` skill is not available to this subagent). Checked: option validation of `--coverage-report`, coverage capture also after failed tests, stale `.gcda` (removed by `--zerocounters` before each run), container user/HOME on the runner, `pipefail` in workflow steps (`defaults.run.shell: bash`), artifact paths vs. download paths in the report job, cache key/restore-keys. No further changes needed; shellcheck: only the existing SC2015 info notes (same `a && b || die` idiom as the rest of the script).
