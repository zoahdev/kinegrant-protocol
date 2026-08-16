# OpenSSF Best Practices badge — self-assessment notes

These are the reference answers for the
[OpenSSF Best Practices (CII) badge](https://bestpractices.coreinfrastructure.org/)
at the "passing" level. Fill the web form from these notes; this file is a
working record, not the badge itself.

## Basics

| Criterion | Answer | Evidence |
|---|---|---|
| Project name / description | KineGrant — authorization & accountability layer for physical AI | `README.md` |
| Website | https://kinegrant.com | — |
| Repository | https://github.com/zoahdev/kinegrant-protocol | — |
| License | Apache-2.0 | `LICENSE.txt` |
| FLOSS | Yes | Apache-2.0 |

## Change control

| Criterion | Answer | Evidence |
|---|---|---|
| Public version-controlled repo | Yes (Git, GitHub) | — |
| Issue tracker | Yes (GitHub Issues) | — |
| Change review (PRs) | Yes; main is protected and requires status checks | `.github` + branch protection |
| Version tagging | Yes (`v2.65.2`, …) | Releases |
| Release notes | Yes | `CHANGELOG.md`, GitHub Releases |
| Semantic versioning | Yes (`MAJOR.MINOR.PATCH`) | Releases |

## Reporting

| Criterion | Answer | Evidence |
|---|---|---|
| Bug reporting process | GitHub Issues + `CONTRIBUTING.md` | — |
| Vulnerability reporting | GitHub Security Advisories | `SECURITY.md` |
| Public archive | PyPI + GitHub Releases + site | — |

## Quality

| Criterion | Answer | Evidence |
|---|---|---|
| Automated test suite | Yes | `pytest` in CI (`ci.yml`) |
| Test in CI on commits | Yes | `ci.yml` |
| Static analysis | CodeQL (CI) | `codeql.yml` |
| OpenSSF Scorecard | Yes (CI) | `scorecard.yml` |
| Reproducible test surface | Yes | `REPRODUCING.md`, `reproduce.yml` |

## Security

| Criterion | Answer | Evidence |
|---|---|---|
| Secure transport (site) | HTTPS | kinegrant.com |
| Secrets not in repo | Yes | `.gitignore` |
| Threat model | Yes | `THREAT_MODEL.md` |
| Security policy | Yes | `SECURITY.md` |
| Fuzz testing | Harness present; not yet in OSS-Fuzz | `src/kinegrant/fuzz.py` |

## Gaps to close for a higher score

- Publish Scorecard results publicly (needs a `SCORECARD_TOKEN` repo secret).
- Wire the fuzz harness into OSS-Fuzz or a CI fuzz job.
- Add a hardening/Go or Rust independent verifier alongside the Python and
  JavaScript implementations.
