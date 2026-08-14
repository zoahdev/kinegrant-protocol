# Policy trust lifecycle (signed policy bundles)

Status: draft for v2.0.

## Problem

KineGrant already distributes signed revocation bundles, but the policy
documents themselves have no authenticated distribution story: a gate
operator must trust whatever bytes a policy channel delivers. A compromised
or stale policy feed can authorize the wrong actions, and an emergency policy
change has no verifiable way to roll back to the previous version.

## Design

A policy bundle is a signed envelope (`alg` + `kid` + `payload` + `signature`,
the same envelope format as capabilities and revocation bundles). The payload
is a `kinegrant:PolicyBundle`:

```json
{
  "type": "kinegrant:PolicyBundle",
  "schema_version": "0.1",
  "bundle_id": "kinegrant:policy-bundle:<sha256>",
  "policy_id": "urn:kinegrant:policy:space-7",
  "issuer": "kinegrant:key:ed25519:<...>",
  "version": 2,
  "previous_version_digest": "sha256:<...>",
  "issued_at": "2026-08-15T00:00:00Z",
  "not_before": "2026-08-15T00:00:00Z",
  "not_after": "2026-08-16T00:00:00Z",
  "policy_digest": "sha256:<...>",
  "rules": [ { "policy_id": "...", "effect": "allow", "...": "..." } ]
}
```

## Verification (fail-closed)

`verify_policy_bundle` rejects a bundle unless:

1. the envelope signature verifies;
2. the signer key id is in the caller's trusted authorities;
3. `issuer` equals the envelope `kid`;
4. the payload type and schema version match;
5. the policy id matches the caller's expectation (when supplied);
6. the version is a positive integer and the digest format is valid;
7. every rule parses into a valid `PolicyRule`;
8. `policy_digest` equals the canonical digest of the rules;
9. the current time is inside `[not_before, not_after)`.

## Registry semantics

`PolicyRegistry` stores activated bundles per policy id and version. The
"current" version is the highest version that is not revoked and whose window
covers the current time. Revoking a version is a local, signed-free operation
recorded in registry state; the registry state is a machine-readable JSON
document so a fleet can persist and exchange it without a central service.

## CLI

`kinegrant-policy-bundle` supports:

- `--verify <bundle.json> --authorities <ids.json> [--policy-id <id>]`;
- `--activate <bundle.json> --authorities <ids.json> [--registry <state.json>]
  [--out <state.json>]`;
- `--current <state.json> --policy-id <id>`;
- `--self-test` for CI smoke.

## Cross-implementation verification

The independent JavaScript verifier (`implementations/kinegrant-js`) and Go
verifier (`implementations/kinegrant-go`) both implement
`verifyPolicyBundle` / `VerifyPolicyBundle` and current-version selection
(`currentPolicyVersion` / `CurrentPolicyVersion`). The conformance report
signs bundles in Python and requires both implementations to accept the
bundle, select version 2 as current, and roll back to version 1 after
revocation; a missing toolchain is recorded as skipped, never as passed.

## Fleet distribution

`PolicyDistributor` verifies one signed policy bundle under the caller's
trusted authorities and applies it to many `PolicyRegistry` instances.
Distribution is fail-closed: nothing is touched until the bundle verifies.
A registry already running a version at least as new is left untouched
(idempotent no-op); downgrades are never applied automatically.
`verify_policy_distribution_report` re-validates the per-registry
acknowledgements against the bundle (policy, bundle id, version, and count
integrity).

## Static analysis

`analyze_policy_bundle` verifies a signed bundle (fail-closed) and emits a
machine-readable `kinegrant:PolicyBundleAnalysis` with conservative findings:
overlapping allow/deny rules (conflict), duplicate rules, unknown
constraints/obligations, rule issuers that differ from the bundle signer, and
unconditional broad allows. `kinegrant-policy-bundle --analyze` returns exit
code 1 when any error-level finding exists, so CI can fail closed on a bad
bundle. `policy_bundle_coverage` (`--coverage`) additionally evaluates the
policy engine over a bounded Cartesian request space and reports
allowed/denied/exceptions, per-rule applicability, and allow rules that never
win (shadowed by deny-overrides).

## Audit aggregation

`audit_policy_bundles` (`--audit-summary`) evaluates many labeled bundles in
one run: each bundle is verified, statically analyzed, and coverage-checked;
unverifiable bundles are recorded as failed instead of aborting the audit.
The machine-readable `kinegrant:PolicyAuditSummary` reports verified/failed
counts, analysis and coverage failures, findings grouped by code, and
aggregate allowed/denied/exception/shadowed totals. `overall_result` is PASS
only when every bundle verifies and has no error findings or coverage
exceptions.

## Browser verification

`verify/policy-bundle-verifier.js` is a zero-dependency, offline verifier that
runs in any modern browser (WebCrypto Ed25519 + SHA-256, RFC 8785 JCS subset).
`verify/policy-bundle-verifier.html` is a standalone page: paste a signed
bundle and trusted authorities, verify locally, and select the current policy
version from a list of payloads with a revocation set; it also verifies
capabilities (v0.1/v0.2/1.0), receipt chains (v0.1/1.0), and MPT evidence
(schema 0.5, required cases, summary consistency), revocation bundles, and
policy distribution reports, plus self-verifying receipt evidence packets
(`kinegrant:ReceiptEvidencePacket` integrity and receipt structure) in the
browser.
`verify/verify_policy_bundle.mjs` exposes the same logic as a Node CLI for CI
cross-checks.

## Non-goals

- No ledger, token, or consensus mechanism is required or implied.
- The registry does not invent trust: it only enforces the caller's
  `trusted_authorities`.
- The bundle format does not replace ODRL profiles; rules remain `PolicyRule`
  objects that adapters can map to ODRL.
