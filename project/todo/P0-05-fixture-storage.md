# P0-05: Fixture storage, download convention and source pre-fetch

- Plan section: 0.1
- Depends on: P0-00
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Agree how fixtures are stored and make old build inputs durable.

## Steps

1. Small fixtures: src/test/data/ and test/functional/data/.
2. Large fixtures: location from P0-00; manifest in repo with URL, size, SHA-256; download-and-verify script; tests skip with a clear message when absent.
3. Pre-fetch and checksum the depends source tarballs (current and those needed for old tags) into fixture storage, since upstream URLs disappear (bintray is already gone).

## Acceptance criteria

- [ ] Manifest format and script committed and documented.
- [ ] depends sources available from fixture storage.

## Notes

Review: E6.

## Log

-
