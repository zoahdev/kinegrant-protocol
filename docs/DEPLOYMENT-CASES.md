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
2. gate verification and atomic one-time consumption;
3. actuator execution (only after consumption);
4. signed receipt append, including failure receipts when the actuator fails;
5. obligation compliance against the full receipt chain;
6. action-journal record on a fully compliant success.

Every stage fails closed and the outcome is machine-readable
(`allowed`, `stage`, `reason`, `capability_id`, `receipt_id`,
`obligation_compliant`, `journal_recorded`). Deployments should use
`Gatekeeper` instead of hand-composing these steps.

## Acceptance for deployment

- pass the conformance level that matches the deployment (L1-L4);
- pin the wire format version and run `check_compatibility`;
- publish receipt checkpoints for external audit;
- verify every capability obligation with `ObligationCompliance` and retain
  the verdict;
- keep unauthenticated discovery restriction-only.
