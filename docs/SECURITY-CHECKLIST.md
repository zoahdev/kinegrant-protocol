# Security readiness checklist

Working checklist toward independent security review and (eventually)
standardization. Status is honest and dated; nothing here is a certification
claim.

## Done

- [x] Threat model (`THREAT_MODEL.md`).
- [x] Vulnerability disclosure policy (`SECURITY.md`).
- [x] Reproducible build + test surface (`docs/SECURITY-AUDIT.md`,
  `REPRODUCING.md`).
- [x] Machine-readable conformance report (L1–L4, self-assessment).
- [x] Machine Permission Test (physical-boundary cases).
- [x] Release checksums (`SHA256SUMS-v2.65.5.txt`).
- [x] CodeQL analysis in CI.

## Next (recommended order)

- [ ] Run OpenSSF Scorecard and publish the result on the README.
- [ ] Apply for the OpenSSF Best Practices (CII) badge.
- [ ] Add a fuzz target for envelope/capability parsing (the repo has a fuzz
  harness; wire it into OSS-Fuzz or a CI fuzz job).
- [ ] Publish a signed, dated security-review request (scope + artifacts +
  checksums) and contact an independent auditor.
- [ ] Collect at least one public third-party review.

## Later

- [ ] Freeze KGP-001 as a stable draft and open an RFC in a standards body
  (W3C WoT / IEEE) after community review.
- [ ] Functional-safety assessment only if/when the protocol is embedded in a
  real safety-critical product (out of scope for the reference implementation).
