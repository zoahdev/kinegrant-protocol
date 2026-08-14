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

When a policy rule carries an obligation (e.g. `emitActionReceipt`), the
deployment MUST be able to demonstrate that the obligation was fulfilled.
`kinegrant.compliance.ObligationCompliance` is the fail-closed auditor for
this step:

- the executor must provide a signed receipt for the exact capability;
- the receipt chain must verify under the caller-supplied executor trust set;
- a receipt 1.0 must report the obligation as `satisfied`; a `0.1` receipt is
  itself the fulfillment of `emitActionReceipt`;
- unknown obligations, missing receipts, receipts for other capabilities, and
  unverified executors all fail compliance.

The runnable home-robot and camera-consent traces now run this check after
every allowed action and include `obligation_compliant` in their machine-
readable output.

## Acceptance for deployment

- pass the conformance level that matches the deployment (L1-L4);
- pin the wire format version and run `check_compatibility`;
- publish receipt checkpoints for external audit;
- verify every capability obligation with `ObligationCompliance` and retain
  the verdict;
- keep unauthenticated discovery restriction-only.
