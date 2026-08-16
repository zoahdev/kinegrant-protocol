# OSS-Fuzz integration

These files prepare KineGrant for continuous coverage-guided fuzzing on
Google's OSS-Fuzz.

## What is here

- `fuzz_envelope.py` — fuzzes signed-envelope verification (`verify_envelope`).
- `fuzz_gate.py` — fuzzes the fail-closed action gate (`ActionGate.authorize`).
- `build.sh` / `Dockerfile` — OSS-Fuzz build plumbing (same as upstream).
- `project.yaml.example` — the integration manifest (reference copy).

## Status

OSS-Fuzz integration has been submitted upstream:

- Upstream PR: <https://github.com/google/oss-fuzz/pull/16008>
- Canonical project files live in `google/oss-fuzz` under `projects/kinegrant/`.
- The upstream `build` check passes (both fuzz targets compile and run).

Once the Google CLA is signed and the upstream PR is merged, every commit to
`main` is fuzzed continuously and crashes are reported to
`kinegrant-security@googlegroups.com`.

## Remaining step (human action)

1. Sign the Google Contributor License Agreement (CLA) at
   <https://cla.developers.google.com/> (Individual CLA, GitHub account
   `zoahdev`), then trigger the "New Contributors" rescan on upstream
   PR #16008.
2. OSS-Fuzz maintainers review the PR.

The local deterministic harness (`kinegrant-fuzz`) continues to run in CI
regardless of OSS-Fuzz acceptance.
