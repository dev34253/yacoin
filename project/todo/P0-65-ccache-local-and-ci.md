# P0-65: Persistent compiler cache (ccache) for local builds and CI

- Plan section: 0.9
- Depends on: P0-61, P0-63, P0-64
- Size: S
- Priority: top – do before all other open tasks (owner, 2026-10-08)
- Owner:
- Started:
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
