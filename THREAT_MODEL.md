# Threat model

This document is the working threat model for the KineGrant protocol
(KGP-001 Experimental Open Draft 0.1) and its Python reference implementation.
It is a living document for security reviewers, not a certification claim.

Status: experimental. The reference implementation has **not** received an
independent security audit and must not be the sole safety control for real
machinery.

## 1. What we protect (assets)

| Asset | Why it matters |
|---|---|
| A physical action (actuator movement) | The event we decide and record. |
| A capability (short-lived authorization token) | Proves a specific action was allowed. |
| The policy (who may do what, when) | The rules that encode intent. |
| The receipt chain (audit trail) | Proves what happened, in order. |
| Issuer / executor private keys | The cryptographic authority. |

## 2. Roles and trust boundaries

```
Policy authority  ->  Issuer  ->  Capability  ->  Gate  ->  Actuator  ->  Receipt
   (writes rules)      (signs)     (short TTL)     (verify)   (moves)      (audit)
```

- **Policy authority** writes rules. Allow rules from an untrusted authority
  are ignored (they may restrict but never grant).
- **Issuer** signs capabilities. The gate trusts only issuers on its allowlist.
- **Gate** is the fail-closed enforcement point immediately before the
  actuator. It verifies the signature, binding, issuer, time window, and
  single-use replay protection.
- **Executor** signs receipts after the action.

## 3. Threats and mitigations

### 3.1 Forge or replay an authorization

**Threat.** Attacker presents a capability they did not receive, or replays a
captured one.

**Mitigation.**

- Capabilities are Ed25519 (or experimental ML-DSA-65) signed envelopes.
- A capability is bound to a request digest, so it cannot be reused for a
  different agent, target, action, or purpose.
- Capabilities expire (`expires_at`), with a protocol maximum lifetime of 300 s.
- The gate's replay store consumes each capability exactly once; a second
  presentation is rejected.

### 3.2 Modify a capability in transit

**Threat.** Attacker changes the agent, target, action, purpose, or time window.

**Mitigation.** Any field change breaks the signature (`verify_envelope`) or the
`request_digest` / field binding, and the gate fails closed.

### 3.3 Issue from an untrusted authority

**Threat.** A key the gate does not trust signs a capability.

**Mitigation.** The gate checks `issuer` against an explicit trusted-issuer set.
An omitted trust store means "trust nobody", not "trust everybody".

### 3.4 Policy grants more than intended

**Threat.** A permissive or ambiguous rule lets an action through.

**Mitigation.**

- The policy engine is **default-deny** and **deny-overrides**.
- Unknown actions, unknown constraints, and future/stale requests fail closed.
- Allow rules from untrusted policy issuers are ignored.

### 3.5 Forge or tamper with the audit trail

**Threat.** Attacker deletes, reorders, or rewrites receipts.

**Mitigation.** Each receipt is executor-signed and links to the previous
receipt through `previous_receipt_hash`, forming a hash chain
(`verify_receipt_chain`). A single capability may produce only one terminal
receipt.

### 3.6 Compromise a private key

**Threat.** Issuer or executor key is stolen.

**Mitigation.** Keys are generated and stored as local PEM files in the
reference deployment. Rotation and revocation are protocol features; hardware
key backends (`SigningBackend`) exist so private keys can stay inside a secure
element. The reference service is intentionally single-node and does not claim
distributed key management.

### 3.7 Denial of service

**Threat.** Attacker floods the service or fills the replay/receipt stores.

**Mitigation.** The reference service is a local single-node gate, not a
public-facing component; it is expected to sit behind a reverse proxy and
firewall in production. No availability guarantees are made.

## 4. Explicitly out of scope

- **Functional safety.** KineGrant is an authorization layer, not a
  functional-safety controller (IEC 61508 / ISO 26262 / ISO 10218).
- **Hardware root of trust.** Hardware-backed keys and trusted clocks are
  experimental and not part of the default deployment.
- **Network/transport security.** The reference service exposes plain HTTP on
  localhost; TLS termination is the operator's responsibility.
- **Certification.** Reference mappings to ROS 2, OPC UA, Matter, W3C WoT, and
  ODRL are adapters, not endorsements.

## 5. Questions for a reviewer

1. Can a capability be replayed after the gate has consumed it?
2. Can any field of a capability be modified without invalidating the signature
   or request binding?
3. Can a non-allowlisted issuer cause the gate to allow an action?
4. Can an ambiguous or untrusted policy rule grant authority?
5. Can a receipt be reordered, removed, or forged while the chain still
   verifies?
