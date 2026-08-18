# Security audit guide

This guide is the entry point for an independent security reviewer. It says
what to review, how to build and test reproducibly, which security properties
to challenge, and where the release artifacts and checksums live.

## 1. Review scope (priority order)

1. `src/kinegrant/crypto.py` — envelope signing and verification (Ed25519,
   experimental ML-DSA-65), key identifiers, canonical JSON.
2. `src/kinegrant/canonical.py` — canonical encoding and content digests.
3. `src/kinegrant/gate.py` — the fail-closed action gate, schema checks, time
   window, replay protection.
4. `src/kinegrant/capability.py` — capability issuance and binding.
5. `src/kinegrant/policy.py` — default-deny / deny-overrides evaluation.
6. `src/kinegrant/receipt.py` — signed receipt chain.
7. `src/kinegrant/revocation.py`, `attenuation.py`, `attestation.py`,
   `checkpoint.py`, `sensor_evidence.py` — secondary trust features.
8. `src/kinegrant/server.py` — the HTTP gate service (localhost reference
   deployment).

The protocol text is KGP-001 (see `paper/`), and the threat model is
[`THREAT_MODEL.md`](../THREAT_MODEL.md).

## 2. Reproducible build

Python 3.11 or newer:

```bash
git clone https://github.com/zoahdev/kinegrant-protocol.git
cd kinegrant-protocol
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip build
python -m pip install -e '.[test]'
python -m build
```

The build produces `kinegrant_protocol-<version>.tar.gz` and a wheel under
`dist/`. Published artifacts and their SHA-256 sums are listed in
`SHA256SUMS-v2.65.5.txt`.

## 3. Test surface

```bash
pytest
python -m kinegrant.conformance
python -m kinegrant.mpt
python challenge/reproduce.py --output-dir reproduction-output
python challenge/verify_reproduction.py reproduction-output/reproduction-report.json
```

- `pytest` runs the unit and integration suites.
- `kinegrant.conformance` emits a machine-readable report across conformance
  levels L1–L4 and cross-checks generated artifacts with the independent
  JavaScript verifier when the Node toolchain is present.
- `kinegrant.mpt` runs the Machine Permission Test (the physical-boundary
  cases).
- The `challenge/` path produces a packet an outside party can re-verify.

See [`REPRODUCING.md`](../REPRODUCING.md) for the exact reproduction contract.

## 4. Security properties to challenge

The reviewer should try to break, at minimum:

1. Replay a consumed capability.
2. Modify any capability field (agent, target, action, purpose, window)
   without invalidating signature or binding.
3. Get the gate to accept a capability from an issuer outside the allowlist.
4. Make an ambiguous or untrusted policy rule grant authority.
5. Reorder, remove, or forge a receipt while the chain still verifies.
6. Make the gate fail **open** on malformed input.

## 5. Known limitations

- This is an **experimental draft**, not a certified standard.
- The reference service is a single-node, localhost-first deployment; TLS,
  firewalling, and key management for multi-node production are out of scope.
- Hardware root of trust and trusted clocks are experimental.
- The conformance report is a self-assessment; independent verifier coverage
  depends on the available toolchains (JavaScript present, Go optional).

## 6. Artifacts

- Source and binary distributions: https://pypi.org/project/kinegrant-protocol/
- GitHub releases: https://github.com/zoahdev/kinegrant-protocol/releases
- Deploy bundles: https://kinegrant.com/kinegrant-deploy.zip (Python) and
  https://kinegrant.com/kinegrant-deploy-win.zip (Windows, no Python required)
- Conformance report (self-assessment): https://github.com/zoahdev/kinegrant-protocol/blob/main/CONFORMANCE.md
