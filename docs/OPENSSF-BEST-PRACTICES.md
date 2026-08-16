# OpenSSF Best Practices badge — fill-in reference

> **Status: PASSING badge achieved (2026-08-16).**
> Project 14103: <https://www.bestpractices.dev/projects/14103>
>
> Silver is not yet achieved. Blocking Silver criteria: us_factor (needs two unassociated maintainers), signed_releases / ersion_tags_signed (signed git tags), and dco (Developer Certificate of Origin).

Copy these answers into
<https://bestpractices.coreinfrastructure.org/>. Values reflect the current
state of `zoahdev/kinegrant-protocol` (Apache-2.0, v2.65.x). For any question
not listed here, answer with the nearest supported statement and keep the
justification to one sentence with a link.

## Identification / basics

| Question | Answer | Evidence / note |
|---|---|---|
| Project name | KineGrant | `README.md` |
| One-line description | Authorization and accountability layer for physical AI | `README.md` |
| Project website | https://kinegrant.com | — |
| Repository | https://github.com/zoahdev/kinegrant-protocol | — |
| License | Apache-2.0 | `LICENSE.txt` |
| Is it FLOSS? | Yes | Apache-2.0 is OSI-approved |

Justification (English): "KineGrant is an Apache-2.0 licensed open-source
protocol; the website is https://kinegrant.com and the canonical repository is
https://github.com/zoahdev/kinegrant-protocol."

## Change control

| Question | Answer | Evidence |
|---|---|---|
| Public version-controlled repository | Yes | GitHub |
| Public issue tracker | Yes | GitHub Issues |
| Reviewed changes (pull requests) | Yes | `main` is branch-protected; status checks required |
| Public roadmap | Yes | `ROADMAP.md` |
| Release notes | Yes | `CHANGELOG.md`, GitHub Releases |
| Semantic versioning | Yes | `2.65.x` |
| Explicit code of conduct | Yes | `CODE_OF_CONDUCT.md` |

Justification: "Development is public on GitHub with issue tracking and
pull-request review; main is protected and requires passing status checks.
Releases use semantic versioning and publish notes (CHANGELOG.md and GitHub
Releases)."

## Reporting

| Question | Answer | Evidence |
|---|---|---|
| Public bug reporting | Yes | GitHub Issues + `CONTRIBUTING.md` |
| Private vulnerability reporting | Yes | GitHub Security Advisories + `SECURITY.md` |
| Public archive of releases | Yes | PyPI + GitHub Releases |

Justification: "Bugs are reported via GitHub Issues and vulnerabilities via
GitHub Security Advisories (see SECURITY.md). Releases are archived on PyPI and
GitHub Releases."

## Quality

| Question | Answer | Evidence |
|---|---|---|
| Automated test suite | Yes | `unittest` (see `tests/`) |
| Tests run in CI | Yes | `.github/workflows/ci.yml` |
| Static analysis | Yes | CodeQL (`.github/workflows/codeql.yml`) |
| Supply-chain scoring | Yes | OpenSSF Scorecard (`.github/workflows/scorecard.yml`) |
| Fuzzing | Yes | deterministic fuzz in CI (`.github/workflows/fuzz.yml`) |
| Conformance / evidence | Yes | `kinegrant-conformance`, MPT |

Justification: "The repository runs unit and integration tests, CodeQL static
analysis, OpenSSF Scorecard, and deterministic fuzzing on every push in GitHub
Actions. A machine-readable conformance report covers levels L1-L4."

## Security

| Question | Answer | Evidence |
|---|---|---|
| HTTPS for the website | Yes | https://kinegrant.com |
| Secrets kept out of the repo | Yes | `.gitignore` |
| Threat model | Yes | `THREAT_MODEL.md` |
| Security policy | Yes | `SECURITY.md` |
| Cryptography | Yes | Ed25519 (default) + experimental ML-DSA-65 |
| Memory-safe language? | Partially | Python reference impl is memory-safe; adapters are JSON-only |

Justification: "The website is served over HTTPS. The repository documents a
threat model (THREAT_MODEL.md) and a vulnerability policy (SECURITY.md), uses
Ed25519 signatures with an experimental post-quantum ML-DSA-65 option, and does
not commit secrets."

## Analysis (gold-level items, optional)

| Question | Answer | Evidence |
|---|---|---|
| Dynamic analysis | Partial | fuzz harness + sanitizer-ready OSS-Fuzz targets under `fuzz/` |
| Memory-safety hardening | N/A | Python reference implementation |

Justification: "Dynamic analysis is provided through a deterministic fuzz
harness (kinegrant-fuzz) and prepared OSS-Fuzz targets; the reference
implementation is Python and therefore memory-safe."

## Honest limits (do not overclaim)

- No independent third-party security audit has been performed yet.
- Conformance is a self-assessment.
- The protocol is an experimental draft, not a certified standard.
