# Threat model

## Protected properties

- unauthorized agents cannot obtain a valid capability;
- a capability cannot be reused for another target, action, purpose, or request;
- expired and replayed capabilities fail closed;
- receipt modification and chain deletion are detectable when a later checkpoint exists;
- raw personal data is not required for ordinary receipts.

## Adversaries considered in v0.1

- malicious network participant altering requests or tokens;
- compromised robot application attempting a different action;
- replaying a previously valid capability;
- untrusted policy source attempting to grant permission;
- receipt log tampering;
- ambiguous or unsupported adapter input.

## Not solved by software-only v0.1

- stolen signing keys;
- compromised actuator firmware that bypasses the gate;
- a sensor or executor lying about physical reality;
- coercion, disputed ownership, or invalid legal authority;
- denial of service;
- side channels and traffic analysis;
- safe motion planning and collision avoidance.

## Required deployment hardening

1. Store authority and executor keys in hardware-backed keystores.
2. Put the gate in the trusted actuator control path, not in an optional app.
3. Maintain issuer trust and revocation locally.
4. Pin adapter profiles and reject unknown fields in safety-critical deployments.
5. Use monotonic time or secure time synchronization.
6. Persist one-time capability consumption across restarts.
7. Anchor receipt-log checkpoints outside the executor.
8. Separate authorization from functional-safety controllers.
9. Complete independent cryptographic and robotics safety review before real machinery.

## Reference implementation trust boundaries

- `PolicyEngine` trusts no allow issuer unless it appears in
  `trusted_policy_issuers`; untrusted rules may only deny.
- `ActionGate` trusts no capability issuer unless explicitly configured.
- `verify_receipt_chain` proves integrity only unless `trusted_executors` is passed.
- `InMemoryReplayStore` is simulator-only. `SQLiteReplayStore` demonstrates durable,
  atomic replay protection but is not a substitute for deployment review.
