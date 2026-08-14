# Changelog

## Unreleased

- Released **v1.0.0**: stable wire format `1.0` accepted (KGP-RFC-0001),
  reference implementation version 1.0.0, interim steering committee record,
  and certification-program draft adopted. See the v1.0.0 GitHub release.
- JavaScript and Go verifiers now accept `0.2`/`1.0` scoped capabilities,
  giving three-way stable-format interoperability in CI.
- Added stable wire format `1.0`: reference implementation issues and verifies
  frozen-scoped capabilities, published `capability-1.0` schema, and KGP-RFC-0001
  accepted (comment window open). Reference implementation version bumped to
  `0.2.0`.
- Added runnable deployment examples (home-robot delivery, camera consent)
  with full protocol traces and a deployment-cases guide.
- Added the second independent implementation (`kinegrant-go`, standard
  library only), the first stable wire-format RFC draft, and the conformance
  certification-program draft.
- Added the first independent implementation: `kinegrant-js`, a dependency-free
  JavaScript verifier for JCS, Ed25519 envelopes, v0.1 capabilities, and
  receipt chains, cross-tested against the Python reference implementation in
  CI.
- Added Merkle selective disclosure (inclusion proofs without revealing the
  full document) and a bounded model checker for policy semantics.
- Added the executable conformance suite (`kinegrant-conformance`, levels
  L1-L4) and the wire-format compatibility policy.
- Added static policy analysis (`PolicyInvariants`, `explain_decision`), a
  deterministic adapter fuzz harness, and the governance charter + RFC
  process documents.
- Added v0.5 privacy groundwork: rotating ephemeral identifiers and
  selective-disclosure envelopes, plus the executable red-team suite
  (`kinegrant-red-team`, 10 probes).
- Added signing backends (`SigningBackend`, `BackedKeyPair`) for hardware keys
  and device attestations with firmware digest, boot counter, and measured
  boot chain.
- Added v0.4 hardware-trust groundwork: `TrustedClock` (rejects backwards and
  anomalous-jumping time), signed sensor-evidence commitments bound into
  receipts, and notarized receipt checkpoints.
- Added the ROS 2 reference bridge (`Ros2GoalGate`, `Sros2PolicyMapping`)
  and the Matter/OPC UA/ROS 2 bridge demo (`kinegrant-bridge-demo`) with
  adapter-fidelity checks.
- Added the simulated two-stack robot demonstration
  (`kinegrant-robot-demo`): a ROS 2-style and a Matter-style stack obey one
  shared policy under replay, untrusted-issuer, prompt-injection,
  physical-limit, and forbidden-combination fault injection.
- Added signed revocation bundles: versioned, content-addressed, chain-linked
  distribution for `RevocationList`, signed by a revocation authority
  (Ed25519 or ML-DSA-65) and verifiable into the gate.
- Added a WoT-style discovery service (`ThingRegistry`) with the
  authenticated/unauthenticated boundary: unauthenticated discovery cannot
  carry a granting policy pointer.
- Added offline delegation revocation: `RevocationList` bundles, gate-side
  checks, and `root_capability_id` chain propagation so revoking a root
  revokes every descendant.
- Added fleet-level `delegate_allowlist` (glob patterns) on delegation roots,
  enforced at issuance and by the independent attenuation verifier.
- Extended the Machine Permission Test to v0.2: five new executable cases for
  physical constraints, scoped attenuation with parent verification,
  cross-agent delegation, approval-tier propagation into receipts, and
  forbidden combinations (14 total, schema_version 0.2).
- Implemented RFC 8785 JCS canonical JSON (deterministic key ordering by UTF-16
  code units, ECMAScript number formatting, strict safe-integer bounds) as the
  encoding behind all digests and signatures.
- Added the machine-readable `kg.action.*` physical action vocabulary with
  risk tiers, data-sensitivity metadata, a strict Draft 2020-12 schema, and an
  optional fail-closed `require_known_actions` policy mode.
- Added fail-closed physical constraints to policy rules: `max_force_newtons`,
  `max_velocity_mps`, and `allowed_zones`, validated against request context
  and published in the PolicyRule schema.
- Added scoped v0.2 capabilities and same-agent attenuation
  (`attenuation.py`): child capabilities can only narrow target patterns,
  action/purpose lists, lifetime, and physical constraints; the gate can
  verify a child against its parent envelope.
- Added approval tiers: `min_approval_tier` policy constraints,
  decision-level `required_approval_tier`, and tier binding in v0.2
  capabilities with a published v0.2 capability schema.
- Receipts now record the v0.2 authorization context (approval tier,
  physical constraints, parent capability id); v0.1 receipts remain
  byte-identical.
- Added a versioned KineGrant ODRL profile (`kgp-v0.2`) that maps
  force/velocity/zone/approval constraints with strict validation, plus
  profile/version metadata in the IEEE 7012 bridge and interop tests.
- Added opt-in cross-agent delegation to scoped capabilities: a principal can
  authorize one specific delegate for a narrowed scope with a delegate-bound
  request digest; delegates cannot re-delegate.
- Added experimental post-quantum envelopes using FIPS 204 ML-DSA-65
  (`alg: "ML-DSA-65"`) as a parallel to Ed25519.
- Added forbidden combinations: `ActionJournal` + `SequencePolicy` deny
  requests once a dangerous set of actions has all been observed, with
  optional time windows and trigger patterns.
- Added canonical `urn:kinegrant:*` identifiers for agents, targets, and
  policies with strict validation and round-trip parsing.
- Published the nine-case KineGrant Machine Permission Test v0.1.
- Added machine-readable PASS/FAIL evidence, an independent verifier, source
  commit and runner-digest provenance, and CI execution across Python 3.11–3.13.
- Published the checksum-addressed `mpt-v0.1` Challenge release while keeping
  reference implementation `v0.1.1` as the latest implementation release.
- Added a one-command external reproduction packet, strict report Schema,
  independent digest verifier, source-commit binding, generated report checksum,
  downloadable CI evidence artifact, and structured result-submission form.
- Added citation and CodeMeta records for release-accurate scholarly and
  machine-readable discovery.
- Added a non-normative ESP32-C3 paper-barrier boundary model with strict device
  commands, live challenges, persistent replay state, signed acknowledgements,
  machine-readable physical-evidence tooling, and 26 profile/transport/evidence tests.
  Physical validation remains pending.

## 0.1.1 — 2026-08-10

Security-hardening release of the KGP-001 v0.1 reference implementation.

- Trust no policy issuer by default; untrusted rules cannot grant permission.
- Evaluate request freshness and policy windows against trusted time.
- Bind capabilities to a digest of the complete policy snapshot.
- Reject unsupported ODRL/MyTerms authorization semantics instead of widening access.
- Prevent caller context from spoofing adapter-owned identity fields.
- Enforce strict capability fields, version, nonce, time order, and maximum lifetime.
- Make capability consumption atomic and add crash-persistent SQLite replay protection.
- Require gate-verified claims for receipts; support trusted executor verification and
  reject conflicting terminal receipts.
- Publish strict schemas for ActionRequest, PolicyRule, Decision, Capability, and Receipt.
- Expand the automated suite from 12 to 33 tests and add GitHub Actions.

Wire object version remains `0.1`; this is a compatible implementation hardening release.

## 0.1.0 — 2026-08-10

Initial experimental KGP-001 v0.1 reference implementation.
