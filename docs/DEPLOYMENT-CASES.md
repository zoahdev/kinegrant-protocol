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

## Acceptance for deployment

- pass the conformance level that matches the deployment (L1-L4);
- pin the wire format version and run `check_compatibility`;
- publish receipt checkpoints for external audit;
- keep unauthenticated discovery restriction-only.
