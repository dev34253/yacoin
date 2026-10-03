# Test builds

`build.sh` builds YaCoin reproducibly for testing: the `depends` libraries and
YaCoin itself are built inside the pinned build image, out of tree, so the git
checkout is never modified (task P0-01).

## Quick start

```bash
# mainnet parameters, run the unit tests
contrib/testing/build.sh --config mainnet --unit

# low-difficulty parameters (needed by the functional tests), all tests
contrib/testing/build.sh --config lowdiff --unit --functional

# coverage of both configurations, then the merged report and the
# coverage gate (see "Coverage" and "Coverage gate")
contrib/testing/build.sh --config mainnet --coverage --unit
contrib/testing/build.sh --config lowdiff --coverage --unit --functional
contrib/testing/build.sh --coverage-report
```

Requirements: `git`, `bash`, `python3`, `flock` (util-linux) and Docker
(with `--no-docker`: the build image's toolchain instead of Docker). In
Claude Code cloud sessions start the Docker daemon first (`dockerd &`). The
first run downloads and builds the `depends` libraries (OpenSSL 1.0.1k,
Boost 1.64, BDB 4.8, libevent, miniupnpc, zeromq; Qt is not built) – about
10–15 minutes in total on a 4-core cloud machine (depends about 4 minutes),
longer on slower machines; later runs reuse the cache and only rebuild what
changed.

## Options

| Option | Meaning |
|---|---|
| `--config mainnet\|lowdiff` | Chain parameters. `lowdiff` adds `--enable-low-difficulty-for-development`. Default `mainnet`. |
| `--coverage` | `-O0 -g --coverage -fprofile-update=atomic` in `CFLAGS` and `CXXFLAGS` (the scrypt-jane C code is instrumented too), `--coverage` in `LDFLAGS`. With `--unit`/`--functional` also writes an lcov report to `<builddir>/coverage/` (see "Coverage"). |
| `--coverage-report` | No build and no tests: merges the reports of the mainnet and lowdiff `--coverage` runs in this work dir into `WORK_DIR/coverage-report/`, then runs the coverage gate (exit 1 if a gate fails, see "Coverage gate"). Rejects `--config`, `--coverage`, `--unit`, `--functional`, `--clean`, `--reconfigure` and `--sanitizers`; `--jobs` (lcov `--parallel`), `--image`, `--work-dir` and `--no-docker` work. |
| `--sanitizers LIST` | `-fsanitize=LIST`, e.g. `address,undefined`. Implemented but not yet validated – sanitizer runs are task P0-29. |
| `--unit` | Run `src/test/test_bitcoin`. |
| `--functional` | Run `test/functional/test_runner.py` (requires `--config lowdiff`). |
| `--functional-args "ARGS"` | Arguments for `test_runner.py`, replacing the default `-j4`; e.g. `"-j4 wallet_dump.py"`. |
| `--jobs N` | Parallel make jobs (default: CPU count). |
| `--reconfigure` | Force `configure` to run again. It also re-runs automatically when the configure arguments (including `CFLAGS`/`CXXFLAGS`) change; the build dir is then cleaned (`make clean`) so every object is rebuilt with the new flags. `--reconfigure` alone does not clean. A build dir created before this behaviour existed has no record of its arguments, so its first run cleans and rebuilds once. |
| `--clean` | Delete the source copy and this configuration's build directory first; the `depends` cache is kept. Because every file is copied again with a new time, other configurations' build dirs also rebuild completely on their next run. |
| `--image IMAGE` | Build image. Default: the pinned P0-57 image `dev34253/yacoin-build@sha256:…` (Ubuntu 24.04, GCC 11). Also `YACOIN_BUILD_IMAGE`. |
| `--no-docker` | Build on the current machine, e.g. when already running inside the build image in CI. |
| `--work-dir DIR` | Where everything is built. Default `$YACOIN_WORK_DIR` or `~/.cache/yacoin-build`. Must be a dedicated directory: not inside the checkout, not containing it, not `/` or `$HOME`. |

Environment variables (besides `YACOIN_WORK_DIR`, `YACOIN_BUILD_IMAGE`
and the proxy settings): `TEST_RUNNER_PORT_MIN` – port base for the
functional tests instead of a port slot (1024–55535, no slot lock; see
"Concurrent runs"); `YACOIN_PORT_LOCK_DIR` – directory of the port slot
locks (default `/tmp/yacoin-build-ports`).

The exit code is non-zero if the build or any requested test run fails,
if `unit.log` has no Boost summary `N test cases out of N passed` (e.g.
`test_bitcoin` ended early with status 0, or a test case was skipped), or
if a vector checker reports a mismatch (see step 6 below).
All unit tests pass in both configurations; tests whose results depend on
the chain parameters (e.g. `pow_tests/get_next_work_pow_limit`, task P0-02)
check the exact value for each configuration.

## What it does

1. Takes a lock on `WORK_DIR/.lock` – only one run per work directory at a
   time; use different work directories for parallel runs. With
   `--functional` it also claims a port slot (see "Concurrent runs").
2. Mirrors the checkout (tracked and untracked, non-ignored files, so
   uncommitted changes are included) to `WORK_DIR/src` with
   `sync_tree.py`: files changed in the checkout since the last run are
   copied (with the current time, so make always rebuilds what depends on
   them), files deleted or renamed are removed, and
   files that the build regenerates in the copy (`autogen.sh` rewrites some
   tracked files such as `aclocal.m4` and `build-aux/*`) are left alone
   unless you change them in the checkout.
3. Passes the commit id as `BUILD_GIT_COMMIT` (with `-dirty` when there are
   modified, deleted or untracked files) to `share/genbuild.sh`, so it ends up
   in the version string (`yacoind -version`).
4. Builds `depends` for `x86_64-pc-linux-gnu` with `NO_QT=1`, caching sources
   and built packages in `WORK_DIR/depends-cache`.
5. Runs `autogen.sh` when needed and configures in
   `WORK_DIR/build-<config>[-cov][-san-…]` with
   `--prefix=<src>/depends/x86_64-pc-linux-gnu`, so automatic `configure`
   re-runs keep using the `depends` libraries. Different configurations can
   coexist; `configure` re-runs when its arguments change.
6. Builds, then runs the requested tests. `--unit` runs `test_bitcoin`,
   checks its summary, then the three independent vector checkers
   `bignum_vectors_check.py`, `reward_vectors.py --check` and
   `header_hash_vectors.py --check` (P0-13, P0-46, P0-19; about 5 s
   together, in both configurations, so CI runs them in its unit jobs).
   Logs: `WORK_DIR/depends.log`, `WORK_DIR/autogen.log`,
   `<builddir>/{configure,make,unit,vectors,functional}.log`.
   Datadirs and node logs of **failed** functional tests are kept in
   `<builddir>/functional-tmp/` (the test framework deletes those of passing
   tests; the directory is emptied at the start of each functional run).

### Concurrent runs

Runs in different work directories can build and test at the same time,
also the functional tests (task P0-61). The functional tests bind fixed
ports derived from `TEST_RUNNER_PORT_MIN` (`test_framework/util.py`:
p2p `PORT_MIN + 12 * seed + node`, rpc 5000 higher; `test_runner.py`
gives the tests the seeds 0…N−1 and the cache step the seed N), and with
`--network host` (whenever `HTTPS_PROXY` is set) all containers share the
machine's ports. So each `--functional` run claims one of 10 **port
slots** and sets `TEST_RUNNER_PORT_MIN` for it:

| Slots | `TEST_RUNNER_PORT_MIN` | p2p ports | rpc ports |
|---|---|---|---|
| 0–4 | 11000, 12000, …, 15000 | slot base + 0…999 | slot base + 5000…5999 (16000–20999) |
| 5–9 | 21000, 22000, …, 25000 | slot base + 0…999 | slot base + 5000…5999 (26000–30999) |

The slots do not overlap and stay below the Linux ephemeral port range
(32768). A slot holds runs of up to 83 tests (12 × 83 < 1000; 46 today).
The preferred slot is `cksum(work dir) % 10`; the run holds
`flock` on `/tmp/yacoin-build-ports/slot-<k>.lock` (`YACOIN_PORT_LOCK_DIR`)
until it ends. If another run holds the preferred slot, the next free one
is used; if all ten are held, the run waits for its preferred slot. The
log shows the choice, e.g.

```
== 13:05:52 port slot 8 is in use by another run; using slot 9
== 13:05:52 functional test ports: slot 9, p2p 25000-25999, rpc 30000-30999 (lock /tmp/yacoin-build-ports/slot-9.lock)
```

No external lock around functional runs is needed any more. Setting
`TEST_RUNNER_PORT_MIN` yourself skips the slot (no lock; you keep runs
apart). A `test_runner.py` started by hand uses 11000 (slot 0's ports)
unless `TEST_RUNNER_PORT_MIN` is set.

The work directory must not be inside another git work tree (e.g. a
dotfiles repository in `$HOME`): `share/genbuild.sh` would then pick up that
repository's commit for the version string.

Binaries end up in `<builddir>/src/` (`yacoind`, `yacoin-cli`,
`test/test_bitcoin`). They need glibc ≥ 2.38 (Ubuntu 24.04 or newer), so they
are for testing, not release.

## Expected results (2026-10-03, after P0-02, P0-10, P0-47, P0-12, P0-16, P0-20, P0-11, P0-13, P0-27, P0-46 and P0-19)

| Configuration | Unit tests | Functional tests |
|---|---|---|
| `mainnet` | 345/345 | – (not supported) |
| `lowdiff` | 345/345 | 46/46 |

`pow_tests/get_next_work_pow_limit` expects a different result per
configuration because `powLimit` differs: mainnet clamps the retarget to
`powLimit` (0x1e0fffff), low difficulty does not (0x1e1a19f8) and checks the
clamp from its own `powLimit` (0x201fffff) instead.

## Coverage

`--coverage` together with `--unit` and/or `--functional` (task P0-03):

1. Before the tests: `lcov --zerocounters` on the build dir (so repeated
   runs do not add up) and a zero baseline (`lcov --capture --initial`), so
   source files that no test runs show up with 0 % instead of being left
   out.
2. After the tests – also when they failed; the exit code still reports the
   failure – capture the counters and add the baseline.
   Both captures read `<builddir>/src` and leave out what is not YaCoin code
   under test: `/usr/*`, `*/depends/*`, `*/test/*` (unit-test sources and
   test data), `src/leveldb`, `src/secp256k1`, `src/univalue`, `src/bench`
   and files generated in the build dirs.
3. Write `<builddir>/coverage/coverage.info`, `html/` (genhtml) and
   `summary.txt` (lines, functions, branches), and print the summary.
   `lcov.log` has the lcov output.

Branch coverage is recorded (`--rc branch_coverage=1`). It includes the
branches GCC generates for C++ exception handling, which inflate the branch
count: lcov 2.0's `--rc no_exception_branch=1` would drop them, but with
GCC 11's gcov output it drops *all* branch data (tested), so the coverage
gate leaves them out itself (see "Coverage gate"); `summary.txt` and the
HTML reports still count them.
The counters are updated atomically (`-fprofile-update=atomic`): YaCoin and
its tests are multi-threaded, and with plain counters lcov 2.0 rejected the
data (a negative branch count in `crypto/sha256.cpp`).
lcov and genhtml come from the build image (lcov 2.0); with `--no-docker`
they must be installed, with the same gcov as the compiler.

`--coverage-report` merges the two configurations into
`WORK_DIR/coverage-report/{merged.info,summary.txt,html/}`, prints all
three summaries and runs the coverage gate (`gate.txt`). It needs `build-mainnet-cov/coverage/coverage.info` and
`build-lowdiff-cov/coverage/coverage.info` in the work dir.

**How the two configurations are merged.** gcov records coverage per line
of the *original* source file, not of the preprocessed code, so both builds
use the same file names and line numbers. Code inside `#ifdef` /
`#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT` is compiled – and instrumented – in
one build only. The merge (`lcov --add-tracefile` of both files) is the
**union**: a line, function or branch is in the denominator if it exists in
at least one build, and it counts as covered if it ran in at least one; hit
counts are added. The per-configuration reports stay available next to the
merged one, so it is visible what one configuration alone covers. The
merged numbers are the ones the coverage gate uses (P0-04). The paths in the
`.info` files are absolute (`/work/...` under Docker), so only merge files
produced the same way (all with Docker, or all with `--no-docker` in the
same work dir).

## Coverage gate

`--coverage-report` ends with the coverage gate (task P0-04):
`coverage_gate.py` reads `merged.info`, removes the excluded code from the
denominators and compares each gate with its minimum from
`coverage-gates.toml`. The report (`merged.info`, `html/`, summaries) is
written first; the gate output goes to the console and to
`coverage-report/gate.txt`, and its exit code becomes the exit code of
`build.sh`: 0 all checks passed, 1 a check is below its minimum, 2 config
or data error (for example an exclusion that no longer finds its target).
In CI this is the `coverage report (merged)` job, so the gate runs where
the coverage jobs run: on `master` and when the workflow is started by
hand.

The script also runs on its own, on any merged tracefile made from the
same commit as the checkout (the exclusions find their lines in the source
text):

```bash
contrib/testing/coverage_gate.py WORK_DIR/coverage-report/merged.info \
    [--verbose] [--suggest] [--config FILE] [--source-root CHECKOUT]
python3 contrib/testing/test_coverage_gate.py   # its own tests (also in CI)
```

Requirements: Python ≥ 3.11 (`tomllib`) and `c++filt` (binutils); both
are in the build image and on the CI runner.

**Numbers.** The gate's numbers differ from lcov's `summary.txt` on
purpose: excluded code is not counted, and *branches* are only the
branches of the source code – the branches GCC adds for C++ exception
handling (marked `e` in the tracefile) are left out
(`settings.exception_branches`). Both are printed; the gate decides.

**Exclusions** (`[[exclude]]`, each with a `reason`):

| `kind` | Removes | Used for |
|---|---|---|
| `file` | the whole file | dead files (`pbkdf2.cpp`, `random_nonce.cpp`, `scrypt-generic.cpp`) |
| `function` | the lines, branches and function records between a function's first and last line (all overloads, or one signature) | dead functions in `scrypt.cpp` and `pow.cpp` |
| `lines` | the line matched by `match` (`extent = "line"`), or the whole statement that starts there (`extent = "block"`: up to its `;`, or the `}` closing its first `{`) | the testnet `else` arm in `primitives/block.h`, the `if (fDebug …)` logging blocks in `kernel.cpp` |
| `branches` | the branch outcomes `outcomes` (`"<block>,<branch>"` ids from the tracefile) on the matched line, whether they ran or not | the dead `fTestNet` operands (one outcome each) |

The list follows [`dead-code.md`](../../project/plans/dead-code.md) a)
and b) (task P0-50) and the task's kernel debug logging. `match` is a
regex on the source text, so line shifts do not break it; it must match
exactly one line, or for `lines` any number with `all = true`. Every exclusion must find its target
(file, function, line with data, branch outcome), otherwise the gate
stops with exit code 2. When code on the list is removed (task P0-59) or
changes, update its entry. A `block` exclusion refuses a statement with an
`else` arm.

The `fTestNet` outcomes need ids because unit tests set `fTestNet` on
purpose through the consensus harness to pin the testnet behaviour
(`chain_trust_tests`, `kernel_tests`, `chainparams_snapshot_tests`,
`consensus_harness_tests`), so a dead outcome can have run and cannot be
told apart by its count. The ids were found by a unit-test run without
those suites (the outcomes that ran there are the live ones) and, for
`kernel.cpp:656`, by the outcome the functional tests add to; see the
P0-04 task log. Lines that no test reaches carry `verified = false`: their
id could not be checked, which does not change the numbers while nothing
on the line runs, and the gate stops (exit 2) as soon as something does,
so the id gets checked then. gcov numbers the
outcomes per line in the order GCC emits them, so they can change with
the code on that line or with the compiler: `branches_on_line` (the number
of non-exception outcomes on the line) must match, otherwise the gate
stops and the ids have to be checked again – for example after the GCC 13
switch (Phase 1).

**Gates** (`[[gate]]`): `name`, optional `paths` (default: every file),
optional `select_functions` (one path; the gate then counts only the lines
and branches between those functions' first and last lines, and those
functions), and `min` with any of `lines`, `functions`, `branches` in
percent. Constructor/destructor variants count as one function. The gates
follow the plan 0.10 table: overall, `pow.cpp`, `GetBlockTrust`,
`kernel.cpp`, the reward functions in `validation.cpp`
(`GetProofOfWorkReward`, `LoadBlockRewardAndHighestDiff`, `GetCoinAge`;
P0-46), `GetMaxSize` in `consensus/consensus.cpp` (P0-46), the used
methods of `bignum.h` (the "used" lists of `dead-code.md` c), selected by
name), `wallet/crypter.cpp` and `random.cpp`.

**Ratchet.** Minimums are set from the merged numbers with one rule:
`floor(measured − 0.5)` percent, i.e. 0.5 to 1.5 points below the
measurement (room for the small run-to-run differences of the
multi-threaded functional tests – at P0-04 overall functions were 77.49 %
in CI and 77.58 % locally for the same code); a measured 100 % stays 100. `--suggest`
prints that value next to each check and marks `<- raise` where it is
above the config (`build.sh` always passes it, so `gate.txt` has the
suggestions). A task that raises coverage raises the minimums in the same
PR, from the merged report of a coverage run of its branch (*Run
workflow*, or the local commands under "Quick start"). A minimum is only lowered
with a reason in the PR and the task log (for example code removed that
was well covered).

## CI

`.github/workflows/tests.yml` runs on every push to any branch (and by hand
via *Run workflow*). The two test jobs run on every push; the coverage
jobs and the merged report run only on `master` and when the workflow is
started by hand (*Run workflow* on any branch), because the `-O0` coverage
jobs take about twice as long. Each job runs `build.sh` with Docker on a
GitHub-hosted `ubuntu-24.04` runner, in the pinned image, with the work dir
in `$RUNNER_TEMP/yacoin-build`:

| Job | Runs | Command (`build.sh` options) | Time (2026-10-03) |
|---|---|---|---|
| unit (mainnet) | every push | `--config mainnet --unit` | ~8 min |
| unit + functional (lowdiff) | every push | `--config lowdiff --unit --functional` | ~12–14 min |
| coverage (mainnet) | master, by hand | `--config mainnet --coverage --unit` | ~15 min |
| coverage (lowdiff) | master, by hand | `--config lowdiff --coverage --unit --functional` | ~16–19 min |
| coverage report (merged) | master, by hand | `test_coverage_gate.py`, then `--coverage-report` with the coverage gate, after the jobs above (also when a test job failed; it fails itself if a coverage job uploaded no report or a gate is below its minimum) | ~1 min |

- The `-O2` jobs test the optimised build; the coverage jobs (`-O0`)
  measure coverage. All jobs of a run start in parallel (times above
  exclude waiting for a runner).
- Artifacts of each run: `coverage-mainnet`, `coverage-lowdiff` and
  `coverage-merged` (`.info`, `summary.txt`, `html/` – open
  `html/index.html`), and, when a job fails, `logs-mainnet`, `logs-lowdiff`,
  `logs-mainnet-cov` or `logs-lowdiff-cov` (build and test logs, datadirs of
  failed functional tests). The coverage summaries are
  also in the run's summary page and in the job logs.
- `depends-cache` (downloaded sources and built packages) is cached with
  `actions/cache`, keyed on the image digest and the contents of
  `depends/`; the cache is saved by jobs that succeed.
- The image is pulled from Docker Hub with a few retries; anonymous pulls
  can hit Docker Hub's rate limit (`429 Too Many Requests`). If all retries
  fail, re-run the job. Mirroring the image to GHCR is task P0-44, as are
  schedules, the self-hosted runner and long-running jobs.
- When the image digest changes, update both `DEFAULT_IMAGE` in `build.sh`
  and `YACOIN_BUILD_IMAGE` in the workflow.
- Both workflows (this one and the older `yacoinbuildmultiplatform.yml`,
  which builds the release binaries for all platforms) have a
  `concurrency` group per workflow and branch with `cancel-in-progress`: a
  newer push to the same branch cancels the older run, so runners are not
  tied up by superseded commits.
- The release-build workflow runs only on pushes to `master`, on tags and
  by hand (*Run workflow*), no longer on every push to every branch: its 8
  jobs (15–25 min each) do not run tests, and on task branches they kept
  the runners busy. Its jobs are otherwise unchanged.

## CBigNum golden vectors (P0-13)

`bignum_vectors_check.py` checks the golden vectors
(`src/test/data/bignum_vectors.json.xz`, format in `src/test/README.md`)
with an independent Python model – Python integers plus the OpenSSL
behaviour `CBigNum` exposes, without `CBigNum` or OpenSSL. It needs only
Python 3 (standard library), so it runs on the host as well (no build
image needed; `build.sh --unit` runs it in the image):

```bash
contrib/testing/bignum_vectors_check.py            # the committed file
contrib/testing/bignum_vectors_check.py FILE.json  # or a regenerated one
```

It prints the number of vectors per operation and every disagreement, and
exits 1 if there is one (expected today: 100000 vectors, 0 disagree, under a
second). Every `build.sh --unit` run (so also CI's unit jobs) runs it after
`test_bitcoin` and fails on a mismatch (P0-61); the `test_bitcoin` replay
(`bignum_vectors_tests`) runs in the same `--unit` run.

## Reward golden table (P0-46)

`reward_vectors.py` writes and checks the reward and block-size golden
table `src/test/data/reward_vectors.json` (format in `src/test/README.md`,
"Rewards and block size"). It computes every value without `CBigNum` or
node code (Python integers; IEEE-754 doubles for the post-fork forms;
`SetCompact` from `bignum_vectors_check.py`). Python 3, standard library,
on the host:

```bash
contrib/testing/reward_vectors.py                    # check the committed file
contrib/testing/reward_vectors.py --write            # rewrite it (keeps mainnet rows)
contrib/testing/reward_vectors.py --write --mainnet-nbits LIST   # add mainnet nBits
```

`--check` (the default) compares the file byte for byte with the model and
prints the first 20 differing lines; expected today: 226 pre-fork, 79
post-fork, 60 epoch, 18 PoS rows agree. `LIST` has one hex `nBits` per line
(`#` comments allowed); P0-23 adds the pre-fork `nBits` of the mainnet dump
this way. `build.sh --unit` runs the check (P0-61; a mismatch fails the
run), and `reward_tests` in the same run replays the file through the node
code.

## Block-header hash vectors (P0-19)

`header_hash_vectors.py` writes and checks the block-header hash known
answers `src/test/data/header_hash_vectors.json` (format in
`src/test/README.md`, "Block-header hash"). The hashes come from a pure
Python model of scrypt-jane as the node builds it (Keccak-512 with the
original padding, HMAC/PBKDF2, ChaCha20/8 BlockMix, ROMix; N = 2^(Nf+1),
r = p = 1), not from the node code. Before anything else it self-tests the
model: the Keccak permutation against `hashlib.sha3_512`, the scrypt-jane
power-on-self-test vector for Keccak-512/ChaCha, and the mainnet and
low-difficulty genesis hashes of `chainparams.cpp`. Python 3, standard
library, on the host:

```bash
contrib/testing/header_hash_vectors.py --selftest                 # model only, < 1 s
contrib/testing/header_hash_vectors.py                            # check, N-factor ≤ 12
contrib/testing/header_hash_vectors.py --max-nfactor 21 --jobs 4  # check all real N-factors
contrib/testing/header_hash_vectors.py --reference ./refhash      # + N-factor 13-25 via upstream
contrib/testing/header_hash_vectors.py --write --max-nfactor 21 --jobs 4 --reference ./refhash
```

Pure Python needs about 0.8 s at N-factor 12 and twice as long per step
(about 7 min and 512 MiB at 21, about 2 h and 8 GiB at 25), so `--check`
checks N-factors up to `--max-nfactor` (default 12) with Python, higher
ones with `--reference BIN` if given, and lists the rest as not checked
(not a failure). `--check` also compares every field except `hash` and
`source` with the case list. Exit code 1 on any disagreement.
`build.sh --unit` runs the default check (self-test plus N-factor ≤ 12,
about 4 s; P0-61), so a mismatch fails the run.

`BIN` is `scrypt_jane_refhash.c` built against the **upstream**
scrypt-jane (floodyberry, commit 0ab6125), a second implementation
independent of `src/scrypt-jane`; the build commands are in the file's
header comment. In the committed file N-factors 0-21 have `source`
`python` and 22-25 `reference`; the upstream build agrees with Python on
every vector up to 21. The checks above N-factor 12 (`--max-nfactor`,
`--reference`) are not run by `build.sh` or CI; `header_hash_tests` in
every `--unit` run replays the file through the node code.

## Restricted networks (proxy and CA)

In environments where outbound HTTPS goes through a proxy that re-signs TLS
(for example Claude Code cloud sessions), `depends` downloads inside the
container need the proxy and its CA certificate:

- If `HTTPS_PROXY`/`https_proxy` is set, the container runs with
  `--network host` and gets `HTTPS_PROXY`, `https_proxy`, `NO_PROXY`,
  `no_proxy`.
- The CA bundle is taken from `YACOIN_CA_BUNDLE`, or `/root/.ccr/ca-bundle.crt`
  when that exists and `HTTPS_PROXY` (upper case) is set, and is mounted as
  `SSL_CERT_FILE` / `CURL_CA_BUNDLE`.

In cloud sessions Docker is installed but not started: run `dockerd &` first.
Docker Hub may answer `429 Too Many Requests` for anonymous pulls; wait and
retry.

## Files

The container runs as the calling user (`--user $(id -u):$(id -g)`), so files
in the work directory are not owned by root.
