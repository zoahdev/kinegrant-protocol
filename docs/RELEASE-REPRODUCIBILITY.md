# Release Reproducibility

> Status: verified as of 2026-08-19 for v2.65.5. This document records what
> is reproducible and what is not, so users and auditors know exactly what a
> local build can and cannot prove.

## Verified

- **Wheel**: byte-deterministic with `SOURCE_DATE_EPOCH` set (verified: three
  builds produced identical SHA-256). Release workflow sets
  `SOURCE_DATE_EPOCH` from the tag commit time (PR #288).
- **sdist**: file-level deterministic — all 204 file members have identical
  mtime (after fixing file times), content, and order across builds. The only
  remaining byte difference is the top-level directory mtime, which
  setuptools recreates at build time.
- **Authoritative hashes**: the release workflow derives the build timestamp
  from the tagged commit, rejects tags that disagree with both package version
  declarations, and publishes `SHA256SUMS-v<version>.txt` alongside the SLSA
  provenance attestation. Use these for release verification.

## Not byte-reproducible (known limit)

- sdist top-level directory mtime (setuptools behavior). Not fixable without
  changing the build backend; acceptable because file content is stable and
  the authoritative hash comes from CI.

## What a local build proves

A local build from a release tag verifies that: the package builds, the
version is correct, the source layout matches, and (with
`SOURCE_DATE_EPOCH`) the wheel matches CI byte-for-byte. For the sdist,
compare file contents rather than the archive bytes.

## Reproduce

```bash
git checkout v2.65.5
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
python -m build --sdist --wheel
sha256sum dist/*
# compare against SHA256SUMS-v2.65.5.txt
```
