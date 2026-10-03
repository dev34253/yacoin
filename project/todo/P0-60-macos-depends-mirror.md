# P0-60: Working download source for the macOS depends toolchain

- Plan section: 0.1
- Depends on: P0-01
- Size: S
- Owner:
- Started:
- Finished:

## Goal

The macOS release build (`build-macos` in `.github/workflows/yacoinbuildmultiplatform.yml`)
must not fail when llvm.org is unreachable (open question Q3, answered yes by the
owner on 2026-10-03).

## Steps

1. Reproduce: `depends/packages/native_cctools.mk` downloads
   `clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz` from llvm.org; the
   `bitcoincore.org/depends-sources` fallback answers 404 (seen on PR #52 and
   run 267 of the #50 branch).
2. Choose a stable source for the exact tarball (same SHA-256 as in
   `native_cctools.mk`): e.g. the LLVM GitHub releases page, or a copy
   published by this project (GitHub release asset of dev34253/yacoin), and
   wire it into depends' `FALLBACK_DOWNLOAD_PATH` or the package's URL.
3. Keep the hash check; no change to what is built.
4. Run the macOS job by hand (`workflow_dispatch`) and record the result.

## Acceptance criteria

- [ ] The macOS release job succeeds with llvm.org blocked or unreachable (show
      it, e.g. by pointing the primary URL at an unreachable host in a test run).
- [ ] Same tarball hash as before; documented in `depends/` or `doc/`.

## Notes

Release workflow runs on master, tags and by hand only (P0-03).

## Log

-
