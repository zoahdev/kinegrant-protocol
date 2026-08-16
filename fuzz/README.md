# OSS-Fuzz integration

These files prepare KineGrant for continuous coverage-guided fuzzing on
Google's OSS-Fuzz.

## What is here

- `fuzz_envelope.py` — fuzzes signed-envelope verification (`verify_envelope`).
- `fuzz_gate.py` — fuzzes the fail-closed action gate (`ActionGate.authorize`).
- `build.sh` / `Dockerfile` — OSS-Fuzz build plumbing.
- `project.yaml.example` — the integration manifest (needs a contact email).

## Remaining step (human action)

1. Create a public security contact (recommended: a Google Group such as
   `kinegrant-security@googlegroups.com`).
2. Copy `project.yaml.example` into the `google/oss-fuzz` repository as
   `projects/kinegrant/project.yaml`, replace `PRIMARY_CONTACT`, and open a PR.
3. OSS-Fuzz maintainers review the PR; once accepted, every commit is fuzzed
   continuously and crashes are reported to the contact email.

The local deterministic harness (`kinegrant-fuzz`) continues to run in CI
regardless of OSS-Fuzz acceptance.
