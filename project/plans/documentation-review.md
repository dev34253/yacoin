# Documentation review (2026-10-03)

A review of the existing documentation, done before writing the
[functional specification](../../doc/functional-specification.md), the
[architecture](../../doc/architecture.md) and the
[design decisions](../../doc/design-decisions.md) (decision D-22).

**Scope:**

- `README.md`, `doc/`, `CLAUDE.md`, `project/`, `contrib/testing/README.md`
- RPC/option help text in `src/init.cpp`
- the Trello board "YACoin Development"

**Method:** each document was checked against the code (tree at
`651e82e`, version 1.11.0) and against the other documents.

## Summary

The newer documents are accurate and consistent with the code: `CLAUDE.md`,
`project/` and `contrib/testing/README.md`.

`doc/` is mostly material inherited from Bitcoin Core 0.15, PPCoin/NovaCoin
and Yacoin 0.4.x. Much of it describes build systems, platforms or
behaviour that no longer exist.

There was no documentation of:

- the consensus rules,
- the Heliopolis hard fork,
- tokens,
- the architecture,
- the reasons behind any of them.

That knowledge was spread over code comments, merge-commit messages,
Trello cards and the Phase 0 review.

## Findings

Severity:

- **High:** misleading about current behaviour or broken.
- **Medium:** outdated, but obviously so.
- **Low:** cosmetic.

| # | Sev | Document | Finding | Action |
|---|---|---|---|---|
| R1 | High | `README.md` | Describes the pre-2021 coin: "10 minute PoS block targets", "subsidy decreases as difficulty increases", "maximum PoW reward is 100 coins". It also refers to a "YACoin testing" testnet that cannot be started (`-testnet` throws "Unknown chain"). It does not mention the Heliopolis hard fork (PoW only, 2 % inflation, tokens, timelocks). | **Fixed:** a current summary, links to the new documents, and the old text kept as history. |
| R2 | High | – | No functional, architecture or decision documentation. | **Fixed:** three new documents in `doc/`. |
| R3 | Medium | `doc/build-unix.md`, `doc/build-openbsd.md` | Link to `dependencies.md`, which did not exist. | **Fixed:** added `doc/dependencies.md`, listing the versions from `depends/packages/`. |
| R4 | Medium | `doc/build-unix.md` | Bitcoin Core 0.15 text with distribution packages for Ubuntu 14.04–18.04. It does not say that only the `depends` build is supported, that OpenSSL 3 / Boost 1.83 / BDB 5.3 fail, or that the pinned Docker image and `contrib/testing/build.sh` exist. It lists ZMQ as optional, but ZMQ is not compiled in. | **Partly fixed:** a note at the top points to the supported build. A full rewrite is left for Phase 5 ("plain `apt install` build docs for 24.04"). |
| R5 | Medium | `doc/README`, `doc/README_windows.txt` | NovaCoin 0.3/0.4, PPCoin and Bitcoin 0.6 readmes (port 9901, `ppcoind`). | Open: follow-up F1. |
| R6 | Medium | `doc/README_ubuntu.txt` | Ubuntu 12.04 VirtualBox guide for `src/makefile.ubuntu`, which no longer exists. | Open: F1. |
| R7 | Medium | `doc/coding.txt` | The style rules are still valid. The "Threads" and "Locking" sections describe 0.4.x: IRC seeding, `CRITICAL_BLOCK`, ports 8333/8332, `ThreadBitcoinMiner`. | Open: F1. Current threads are now in `architecture.md` §6.2. |
| R8 | Medium | `doc/release-process.txt` | Starts with "TODO – update the rest of these text files for YAC"; describes gitian, `yacoin-qt.pro` and `share/setup.nsi`. There is no current release process. | Open: F2. |
| R9 | Medium | `doc/readme-qt.rst`, `doc/build-osx.md`, `doc/build-windows.md`, `doc/translation_process.md` | Qt4/qmake, Ubuntu 14.04/17.04, and Bitcoin-specific steps. Qt is deferred (D-15). | Open: F1/F3, when the Qt phase starts. |
| R10 | Medium | `build-windows-in-docker.sh` | Calls `yacoin-qt-tdm32.pro` and `makefile.mingw`; neither file exists. | Open: F1. |
| R11 | Medium | `src/init.cpp` help | `-testnetnewlogicblocknumber` is spelled differently from the option that is read (`-testnetNewLogicBlockNumber`). `-epochinterval`, `-nFactorAtHardfork` and `-tokenSupportBlockNumber` have no help entry. `-testnet` and the testnet ports are offered although testnet cannot be selected. | Open: F4. A code change; behaviour must stay the same. Documented in `functional-specification.md` §8 for now. |
| R12 | Low | `README.md` | The CI badge points to yacoin/yacoin branch `1.0.0`. | Kept: the fork tracks upstream (D-20). |
| R13 | Low | Code comments | `init.cpp` still mentions `ThreadImport` (the import runs synchronously). `Makefile.am` has an unused scrypt-jane `-O3 -DUSE_ASM` rule. | Recorded in `architecture.md`. Clean-up belongs to P0-50 (inventory and dead code). |
| R14 | Low | `CLAUDE.md`, `project/README.md` | Accurate. They did not point to the new documents. | **Fixed:** links added. |

## Checked and found accurate

- `CLAUDE.md`: build commands, test counts (239 unit, 45 functional), the
  known low-difficulty unit failure, and the parameter sets.
- `project/plans/overview.md`: the inventory figures and file references
  that were sampled.
- `project/plans/phase0-review.md`: the facts reused in the new documents,
  e.g. the reward bisection, the block-hash path, and that tests do not run
  on regtest.
- `contrib/testing/README.md`: options and behaviour of `build.sh`.

## Trello board

The board "YACoin Development" was read on 2026-10-03. It holds 93 open
cards in these lists: Bugs, To Do, Doing, Review, Done.

Cards used as sources for rationale:

- minimum difficulty
- epoch reward
- min relay fee and block size
- TXID malleability fix
- OP codes CLTV/CSV
- timelock coins
- asset management system
- UTC time bug
- hard-fork transition
- build process / depends
- run on Ubuntu 20.04+
- release hard-coding
- "Yacoind improvement points + important notes" (the CLTV block-time rule)

Open bugs and improvement points are summarised in
`functional-specification.md` §10. Cards about external projects (YASwap,
miners, pools, explorer) are out of scope.

## Follow-ups (proposed, not yet on the task board)

| # | Follow-up |
|---|---|
| F1 | Move obsolete documents to `doc/legacy/` or delete them, after the owner agrees: `doc/README`, `README_windows.txt`, `README_ubuntu.txt`, `build-windows-in-docker.sh`, the 0.4.x parts of `coding.txt`. |
| F2 | Write a current release process: `depends`, CI artefacts, version bump in `configure.ac`, checksums. |
| F3 | Update the GUI and macOS/Windows build documents when the Qt phase starts. |
| F4 | Fix the option help text in `init.cpp` (spelling, missing entries, testnet), with a functional test that the options are still read. |
| F5 | Keep the three new documents current. Every consensus-relevant pull request in Phases 1–5 checks `functional-specification.md` and adds a decision entry where one is made. |
