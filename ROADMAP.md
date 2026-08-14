# KineGrant roadmap

## v0.1 — executable kernel (complete)

- normalized physical action request;
- default-deny and deny-overrides policy evaluation;
- Ed25519 short-lived capability;
- one-time local action gate;
- signed, hash-chained action receipt;
- boundary adapters and threat model.

## v0.1.1 — security hardening (complete)

- authenticated policy-issuer boundary and trusted-clock request freshness;
- strict fail-closed adapter profiles and reserved-context protection;
- policy-snapshot digest binding;
- strict capability time/version/field checks;
- atomic in-memory and crash-persistent SQLite replay stores;
- trusted-executor and single-terminal-receipt verification;
- strict schemas and 33 automated protocol/security regression tests;
- GitHub Actions across Python 3.11–3.13.

## Machine Permission Test v0.2 — reproducible challenge (complete)

- fourteen executable permission-boundary cases with real sandbox actuator counts;
- no-grant, valid-once, replay, request mutation, issuer, expiry, concurrency,
  restart persistence, and receipt-trust assertions;
- v0.2 surface: physical constraints, attenuation with parent verification,
  cross-agent delegation, approval-tier propagation into receipts, and
  forbidden combinations;
- strict Draft 2020-12 evidence Schema and independent verifier;
- source commit, runner digest, and runtime-environment provenance;
- public reference run with 14/14 PASS and checksum-addressed release assets;
- production Challenge page aligned with the executable runner.

Exit criterion: an external implementer can download one packet, reproduce all
fourteen cases, and submit Schema-valid evidence without trusting the website UI.

## Low-risk ESP32-C3 permission proof — software boundary complete

- locked-by-default ESP-IDF firmware for the ESP32-C3;
- exact device/action/position, expiry, sequence, boot-counter, and challenge checks;
- Ed25519 command verification and device-signed acknowledgement;
- replay state committed to NVS before the actuator call;
- secret-safe provisioning helper and public provisioning record;
- strict host serial bridge and no-actuation HIL preflight;
- official ESP-IDF container build and unsigned firmware artifacts in GitHub Actions;
- 82 repository tests across Python 3.11–3.13.

Physical evidence remains **NOT_RUN**. Procurement, assembly, wiring review,
filming, and the acceptance matrix in
[issue #7](https://github.com/zoahdev/kinegrant-protocol/issues/7) require a real
device and must not be inferred from software or CI results.

## v0.2 — precise profiles

- replace draft canonical JSON with RFC 8785 JCS or deterministic CBOR;
- define versioned ODRL and IEEE 7012 profiles;
- add policy provenance, revocation, delegation, and capability attenuation;
- create a machine-readable action vocabulary for `observe`, `record`, `touch`,
  `grasp`, `move`, `open`, `enter`, `retain`, and `train_on_data`.

Progress on main:

- RFC 8785 JCS canonical encoding implemented in the reference implementation,
  with ECMAScript number semantics, UTF-16 member ordering, and strict safe
  integer bounds (`canonical.py` + `tests/test_canonical_jcs.py`).
- Machine-readable `kg.action.*` vocabulary with risk tiers and
  data-sensitivity metadata, a strict Draft 2020-12 schema, and an optional
  fail-closed `require_known_actions` policy mode.
- Physical constraints (`max_force_newtons`, `max_velocity_mps`,
  `allowed_zones`) enforced fail-closed against request context.
- Scoped v0.2 capabilities with same-agent attenuation: child capabilities can
  only narrow target/actions/purposes/lifetime/physical limits, and the gate
  can verify attenuation against a supplied parent.
- Approval tiers: `min_approval_tier` policy constraint, decision-level
  `required_approval_tier`, and tier binding in scoped capabilities.
- Receipt evidence chain: v0.2 authorization context (approval tier,
  physical constraints, parent capability id) is recorded in signed receipts.
- Cross-agent delegation: opt-in bounded delegation (max depth 1-3) with a
  delegate-bound request digest; delegates cannot re-delegate.
- Delegation revocation and fleet allowlists: offline `RevocationList` with
  root-chain revocation, and glob `delegate_allowlist` on delegation roots.
- Signed revocation bundles: versioned, content-addressed, chain-linked
  bundles signed by a revocation authority and loadable into the gate.
- WoT-style discovery service with the authenticated/unauthenticated boundary
  from KGP-001 section 3.
- Simulated two-stack robot demonstration (`kinegrant-robot-demo`) with
  replay, untrusted-issuer, prompt-injection, physical-limit, and
  forbidden-combination fault injection.
- ROS 2 reference bridge: `Ros2GoalGate` and a deterministic `Sros2PolicyMapping`
  generator, plus a Matter/OPC UA/ROS 2 bridge demo with adapter-fidelity
  checks.
- Hardware-trust groundwork: monotonic `TrustedClock`, signed sensor-evidence
  commitments bound into receipts, notarized receipt checkpoints, signing
  backends for hardware keys, and device attestations with measured-boot
  claims.
- Privacy groundwork: rotating ephemeral identifiers and selective-disclosure
  envelopes with Merkle inclusion proofs; a bounded model checker for policy
  reachability and shadowing; an executable red-team corpus covering replay, mutation,
  confused deputy, conflict, downgrade, clock, revocation, delegation,
  adapter, and sequence attacks.
- Static policy analysis (allow-all / deny-shadow / untrusted-allow /
  empty-policy invariants and per-request decision explanations) and a
  deterministic adapter fuzz harness with fail-closed assertions.
- Bounded model checking: enumerates a finite request space and verifies
  deny-overrides, reachability, shadowing, and exception-freedom.
- Governance: vendor-neutral charter and RFC lifecycle documentation.
- Conformance: executable L1-L4 suite with machine-readable marks, and a
  wire-format compatibility policy for the 1.0 stabilization path.
- Interoperability: an independent JavaScript verifier (`kinegrant-js`)
  cross-tested against the Python reference implementation in CI.
- Interoperability: an independent Go verifier (`kinegrant-go`) and the first
  stable wire-format RFC draft plus certification-program draft.
- Deployment cases: runnable home-robot and camera-consent examples with
  policy -> capability -> gate -> receipt traces.
- Stable wire format: `1.0` capability support in the reference
  implementation with a published schema; KGP-RFC-0001 accepted (comment
  window open until v1.0.0).
- Three-way stable-format interoperability: JavaScript and Go verifiers accept
  `0.2`/`1.0` scoped capabilities cross-tested against Python in CI.
- Experimental ML-DSA-65 (FIPS 204) post-quantum envelopes alongside Ed25519.
- Forbidden combinations and cross-action sequence policy with an append-only
  action journal, time windows, and trigger patterns.
- Canonical `urn:kinegrant:*` identifier grammar for agents, targets, and
  policies.
- Versioned ODRL profile (`kgp-v0.2`) and IEEE 7012 bridge metadata with
  fail-closed constraint mapping and interop tests.

Exit criterion: independent implementations produce byte-identical decisions and
verify each other's capabilities and receipts.

## v0.3 — real robot bridge

- ROS 2 action-gate package and SROS2 policy generator;
- W3C WoT discovery service;
- Matter and OPC UA bridge demonstrations;
- production replay-store adapters and offline revocation bundle;
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

## v1.0 — open standard candidate (complete with v1.0.0)

- stable wire format `1.0` and compatibility policy (KGP-RFC-0001 accepted);
- public RFC process and independent maintainers (RFC lifecycle in docs/);
- conformance suite (L1-L4) and certification-program draft;
- three interoperable implementations (Python, JavaScript, Go) cross-verified
  on the stable format;
- deployments across home robotics, industrial automation, and
  camera/data consent (runnable examples and deployment guide);
- neutral governance charter with an interim committee record.

## v1.1 — accountability and audit (complete with v1.1.0)

- additive receipt version 1.0 with obligation execution results and failure
  reasons;
- fail-closed obligation compliance with three known obligations
  (`emitActionReceipt`, `logAuditEvent`, `preserveEvidence`);
- Gatekeeper one-call deployment boundary (sequence, revocation, gate,
  actuator, receipt, compliance, journal) used by every demo and trace;
- receipt auditing (`ReceiptAuditor` + `kinegrant-audit` CLI);
- conformance suite at 19/19 including obligation and boundary marks;
- cross-system ROS 2 + MCP demo and ODRL forbidden-combination mapping.

## v1.2 — fleet management (complete with v1.2.0)

- fleet revocation distribution (`RevocationDistributor` +
  `kinegrant-revoke-distribute` CLI) with per-gate acknowledgements;
- receipt-audit exports: CSV and self-verifying evidence packets;
- conformance suite at 20/20 including the `revocation_distribution` mark.

## v1.3 — performance and verifiability (complete with v1.3.0)

- bounded policy-decision cache (`CachedPolicyEngine`) with LRU decisions,
  hit/miss statistics, and automatic invalidation on policy change;
- verifiable fleet revocation distribution reports
  (`verify_distribution_report`): bundle binding, count integrity, trusted
  authorities;
- benchmark metrics for cached policy evaluation and fleet distribution.

## v1.4 — integrated operations (complete with v1.4.0)

- every runnable demo and deployment trace evaluates policy through
  `CachedPolicyEngine`;
- the audit CLI verifies and includes fleet revocation distribution status
  alongside receipt audits.

## v1.5 — verifiable challenge (complete with v1.5.0)

- Machine Permission Test v0.3 with 17 reproducible cases, including receipt
  1.0 obligations, compliance evasion detection, and fleet revocation
  distribution;
- the v0.1 issuer accepts all known obligations.

## v1.6 — formal boundary checks (complete with v1.6.0)

- Gatekeeper boundary model check (`check_gatekeeper_boundary`) verifies the
  one-call composition invariants;
- conformance suite at 21/21 including the `gatekeeper_boundary_modelcheck`
  mark.

## v1.7 — cross-implementation trust (complete with v1.7.0)

- the conformance report cross-checks generated capabilities and receipt
  chains with the independent JavaScript and Go verifiers.

## Success metrics

KineGrant is not successful because its repository is popular. It succeeds when:

1. unrelated robot vendors can request the same capability;
2. a person or space can publish one rule understood by all of them;
3. a safety auditor can reproduce the decision;
4. an actuator cannot execute without the verified capability;
5. receipts reveal less personal data than raw operational logs.
