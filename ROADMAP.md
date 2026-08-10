# KineGrant roadmap

## v0.1 — executable kernel (complete)

- normalized physical action request;
- default-deny and deny-overrides policy evaluation;
- Ed25519 short-lived capability;
- one-time local action gate;
- signed, hash-chained action receipt;
- boundary adapters and threat model.

## v0.2 — precise profiles

- publish a strict JSON Schema for every core object;
- replace draft canonical JSON with RFC 8785 JCS or deterministic CBOR;
- define versioned ODRL and IEEE 7012 profiles;
- add policy provenance, revocation, delegation, and capability attenuation;
- create a machine-readable action vocabulary for `observe`, `record`, `touch`,
  `grasp`, `move`, `open`, `enter`, `retain`, and `train_on_data`.

Exit criterion: independent implementations produce byte-identical decisions and
verify each other's capabilities and receipts.

## v0.3 — real robot bridge

- ROS 2 action-gate package and SROS2 policy generator;
- W3C WoT discovery service;
- Matter and OPC UA bridge demonstrations;
- persisted replay cache and offline revocation bundle;
- simulated robot demonstration with fault injection.

Exit criterion: two different robot stacks obey the same external policy.

## v0.4 — hardware trust

- secure-element-backed authority/executor keys;
- measured boot and signed actuator-gate build;
- trustworthy time source;
- sensor-evidence commitments with explicit confidence and provenance;
- external receipt checkpoints.

Exit criterion: bypassing the application layer cannot silently bypass the gate.

## v0.5 — privacy and formal methods

- rotating identifiers and selective disclosure;
- zero-knowledge proof of policy satisfaction for sensitive contexts;
- formal policy semantics and model checking;
- adapter fuzzing and third-party security review;
- red-team corpus covering conflict, replay, downgrade, and confused-deputy attacks.

## v1.0 — open standard candidate

- stable wire format and compatibility policy;
- public RFC process and independent maintainers;
- conformance test suite and certification marks;
- at least three interoperable implementations;
- deployments across home robotics, industrial automation, and camera/data consent;
- neutral governance that cannot be controlled by one vendor or token holder.

## Success metrics

KineGrant is not successful because its repository is popular. It succeeds when:

1. unrelated robot vendors can request the same capability;
2. a person or space can publish one rule understood by all of them;
3. a safety auditor can reproduce the decision;
4. an actuator cannot execute without the verified capability;
5. receipts reveal less personal data than raw operational logs.
