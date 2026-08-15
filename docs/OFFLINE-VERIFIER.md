# Run the verifier offline (one page)

Everything in `verify/` is dependency-free and runs without network access.
You only need the files themselves — clone the repo once (or download a
release source archive) and then everything below works fully offline.

## 1. Browser verifier (no install)

`verify/policy-bundle-verifier.html` + `verify/policy-bundle-verifier.js` use
only the browser's built-in WebCrypto (Ed25519, SHA-256) and a small RFC 8785
JCS implementation. No CDN, no build step.

Copy both files to any machine and open the HTML file directly
(`file://...policy-bundle-verifier.html`), or serve the folder locally:

```bash
python -m http.server 8000 --directory verify   # air-gapped machine is fine
```

Paste the signed bundle JSON into the first box and the trusted-authority
kid list into the second box, then verify. All checking happens locally;
nothing leaves your machine.

## 2. Node CLI (`verify/verify_policy_bundle.mjs`)

Same verifier as a command-line tool. Requires only Node.js 18+; no npm
packages to install.

```bash
# verify a signed policy bundle against your trusted authorities
node verify/verify_policy_bundle.mjs verify bundle.json authorities.json urn:kinegrant:policy:front-door

# pick the current (highest non-revoked) version from a bundle list
node verify/verify_policy_bundle.mjs current bundles.json revoked.json

# verify a single capability or a receipt chain
node verify/verify_policy_bundle.mjs capability envelope.json request.json issuers.json
node verify/verify_policy_bundle.mjs receipts entries.json executors.json
```

Every command prints a single-line verdict and exits non-zero on failure.

## 3. Verify Machine Permission Test (MPT) evidence offline

Download the checksum-addressed packet and reference evidence from the
[`mpt-v0.2` release](https://github.com/zoahdev/kinegrant-protocol/releases/tag/mpt-v0.2)
while you still have a connection, then verify with no network:

```bash
node verify/verify_policy_bundle.mjs mpt machine-permission-test.evidence.json
# -> MPT EVIDENCE VALID (PASS: 22/22)
```

The evidence is self-contained: the verifier checks case results, digests and
cross-implementation records inside the file. No re-run, no network.

## 4. Verify conformance evidence offline

A conformance report is also self-contained:

```bash
node verify/verify_policy_bundle.mjs conformance conformance-report.json
# -> CONFORMANCE REPORT VALID (PASS: N/N marks, independent=PASS, M checks)
```

## 5. Verify a whole release packet (checksums + proofs, one command)

Stable releases publish a checksum-addressed packet (`SHA256SUMS.txt`, source
archive, conformance report, MPT evidence). After downloading the assets into
one directory:

```bash
python scripts/verify_release.py <packet-directory>
# -> RELEASE PACKET VERIFIED
```

This checks every SHA-256 digest, requires the conformance report to be
`PASS`, and runs the independent MPT evidence verifier — all offline (Python
3.11+, no third-party packages). Any mismatch exits `2` and lists each
`INVALID` reason.

## Notes

- Signing/verifying uses only standard WebCrypto Ed25519 (plus optional
  ML-DSA-65 envelopes where the browser supports them).
- A valid signature proves the evidence is intact and who signed it; it does
  not prove an authority is trustworthy or that a physical action occurred.
- See [REPRODUCING.md](../REPRODUCING.md) for publishing your own evidence.
