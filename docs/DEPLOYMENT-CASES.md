# KineGrant Deployment Cases

> Status: v1.0 draft

## 1. Home robot delivery (runnable)

`examples/home-robot/` demonstrates a delivery robot opening one door for a
delivery: scoped capability, physical constraints (force, zone), single-use
gate, and a signed receipt chain.

## 2. Camera consent (runnable)

`examples/camera-consent/` demonstrates recording for security while training
is denied by policy and by a forbidden combination.

## 3. Industrial cell

A fixed robotic cell exposes an OPC UA method (`openGuard`) and a ROS 2 action
(`pick`) governed by one policy: same targets, same purposes, different
transports. This is the `kinegrant-bridge-demo` scenario; deployment adds
device attestation (L4) and a signed revocation bundle for maintenance
windows.

## 4. Obligation enforcement

When a policy rule carries an obligation (e.g. `emitActionReceipt` or
`logAuditEvent`), the
deployment MUST be able to demonstrate that the obligation was fulfilled.
`kinegrant.compliance.ObligationCompliance` is the fail-closed auditor for
this step:

- the executor must provide a signed receipt for the exact capability;
- the receipt chain must verify under the caller-supplied executor trust set;
- a receipt 1.0 must report each obligation as `satisfied`; a `0.1` receipt is
  itself the fulfillment of `emitActionReceipt`, while `logAuditEvent`
  requires the explicit audit-log commitment in a `1.0` receipt;
- unknown obligations, missing receipts, receipts for other capabilities, and
  unverified executors all fail compliance.

The runnable home-robot and camera-consent traces now run this check after
every allowed action and include `obligation_compliant` in their machine-
readable output.

## 5. Gatekeeper (one-call deployment boundary)

`kinegrant.gatekeeper.Gatekeeper` composes the whole boundary in one
`execute()` call, in the exact deployment order:

1. sequence check against the action journal (forbidden combinations);
2. revocation check against the deployment's revocation list;
3. gate verification and atomic one-time consumption;
4. actuator execution (only after consumption);
5. signed receipt append, including failure receipts when the actuator fails;
6. obligation compliance against the full receipt chain;
7. action-journal record on a fully compliant success.

Every stage fails closed and the outcome is machine-readable
(`allowed`, `stage`, `reason`, `capability_id`, `receipt_id`,
`obligation_compliant`, `journal_recorded`). Deployments should use
`Gatekeeper` instead of hand-composing these steps. The runnable demos
(`kinegrant-robot-demo`, `kinegrant-bridge-demo`, `kinegrant-ros2-demo`) and
both deployment traces (home-robot, camera-consent) now run through
`Gatekeeper`.

## 6. Receipt auditing

`kinegrant.audit.ReceiptAuditor` is the deployable audit surface:

- `chain_valid()` verifies the whole receipt chain under the caller-supplied
  executor trust set;
- `query(...)` filters verified receipts by capability, agent, target, action,
  purpose, result, and time window;
- `summary()` emits a machine-readable audit summary (totals by result and
  action, first/last timestamps);
- `compliance_for(capability)` checks that the capability's obligations are
  fulfilled by the chain.
- `export_csv()` renders matched receipts for spreadsheets and archives;
- `export_packet()` builds a self-verifying evidence packet
  (`kinegrant:ReceiptEvidencePacket` with a content-addressed digest).

Auditing is fail-closed: queries on an invalid chain are rejected unless the
auditor explicitly opts out (`strict=False`), and obligation checks require a
non-empty executor trust set. The `kinegrant-audit` CLI wraps this for
operators (`--csv FILE` / `--packet FILE` export the matched set;
`--self-test` validates the tool itself).

## 7. Revocation distribution

`kinegrant.distribution.RevocationDistributor` applies one verified,
signed revocation bundle to every gate in a fleet:

- the bundle must verify under the caller-supplied revocation authorities
  (and an optional expected previous-bundle digest) before any gate is
  touched;
- application is idempotent per capability id: re-distributing the same
  bundle reports `already_present` instead of re-adding;
- the machine-readable report records per-gate acknowledgements (added /
  already-present counts) plus the bundle id and version.

The `kinegrant-revoke-distribute` CLI wraps this for operators
(`bundle.json gates.json authorities.json`; `--self-test` validates the
tool itself).

`verify_distribution_report(report, bundle, trusted_authorities=...)`
re-validates a fleet report after the fact: the report must reference the
exact bundle id and version, its summary must match the per-gate
acknowledgements, and the bundle must verify under the caller-supplied
authorities. Any inconsistency is rejected (fail-closed).

## Acceptance for deployment

- pass the conformance level that matches the deployment (L1-L4);
- pin the wire format version and run `check_compatibility`;
- publish receipt checkpoints for external audit;
- verify every capability obligation with `ObligationCompliance` and retain
  the verdict;
- keep unauthenticated discovery restriction-only.
