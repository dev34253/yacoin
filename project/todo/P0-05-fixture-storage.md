# P0-05: Fixture storage and download convention

- Plan section: 0.1
- Depends on: P0-00
- Size: S
- Owner:
- Started:
- Finished:

## Goal

Agree on how test fixtures are stored: small ones in the repo, large ones outside with checksums.

## Steps

1. Small fixtures: src/test/data/ (JSON, compressed if needed) and test/functional/data/.
2. Large fixtures: versioned location decided in P0-00; manifest file in repo with URL, size and SHA-256.
3. Script to download and verify large fixtures into a cache directory; tests skip with a clear message if absent.

## Acceptance criteria

- [ ] Manifest format and download script committed and documented.
- [ ] A test can request a large fixture by name and gets a verified local path.

## Notes

-

## Log

-
