# Changelog

## Unreleased

## 1.0.1 — 2026-08-15

- The conformance suite now runs its `obligation_compliance` mark through
  `Gatekeeper` with both obligations (`emitActionReceipt`, `logAuditEvent`)
  and adds a `gatekeeper_boundary` mark (allow, replay denial, sequence
  denial, journal) — L1-L4 is now 19 marks.
- All three runnable demos and both deployment traces now run through
  `Gatekeeper.execute()` instead of hand-composing sequence/gate/receipt/
  compliance/journal steps; the micro-benchmarks gained a
  `gatekeeper_execute` throughput metric.
- Added `kinegrant.gatekeeper.Gatekeeper`: one-call composition of sequence
  check, gate verification and one-time consumption, actuator execution,
  signed receipt (including failure receipts), obligation compliance, and the
  action journal, with a machine-readable fail-closed outcome.
- Patch release on the stable 1.0 wire format: reference implementation
  version 1.0.1; the deployment traces (home-robot, camera-consent) now carry
  both obligations (`emitActionReceipt`, `logAuditEvent`) and report them as
  satisfied in receipt 1.0.
- Added the `logAuditEvent` obligation (audit-log commitment) to the known
  obligation vocabulary across Python, JavaScript, and Go, the capability and
  receipt-1.0 schemas, the ODRL kgp-v0.2 duty mapping, and obligation
  compliance; the conformance suite gained an `obligation_compliance` mark
  (L1-L4 now 18 marks).
- Obligation compliance now runs inside every runnable demo: the two-stack
  robot demo, the Matter/OPC UA/ROS 2 bridge demo, and the cross-system
  ROS 2 + MCP demo all append signed receipts after allowed actions, verify
  them with `ObligationCompliance`, and report `obligation_compliance_ok`;
  the micro-benchmarks gained an `obligation_compliance` throughput metric.
- Added fail-closed obligation compliance (`kinegrant.compliance.
  ObligationCompliance`): after execution, every capability obligation must
  have a verifiable fulfillment — a signed receipt for `emitActionReceipt`
  (0.1 receipts count, 1.0 receipts must report `satisfied`); unknown
  obligations, missing receipts, wrong-capability receipts, invalid chains,
  and unverified executors fail. The red-team suite gained probe RT-011
  (suppressed-receipt evasion), and the home-robot and camera-consent
  deployment traces now include the compliance verdict.
- Added additive receipt version `1.0`: optional `obligation_results`
  (obligation execution status with failure reasons) and `failure_reason`
  (why an attempted action failed), validated and verified by the Python
  reference implementation and the independent JavaScript and Go verifiers,
  with a published `receipt-1.0` schema. Plain receipts stay byte-identical
  `0.1`.
- Added the cross-system ROS 2 + MCP action-gate demo (`kinegrant-ros2-demo`)
  and the MCP tool-call adapter (`kinegrant.adapters.mcp`): one shared policy,
  gate, signed receipt log, and sequence policy govern a ROS 2-style stack and
  an MCP-style agent stack, with replay, untrusted-issuer, purpose,
  physical-limit, and forbidden-combination fault injection.
- Extended the ODRL `kgp-v0.2` profile adapter: known `emitActionReceipt`
  duties map to obligations (unknown duties fail closed), a
  `kg:prohibitedCombination` extension maps to `SequencePolicy` rules, and
  `rules_to_odrl()` serializes rules and forbidden combinations back into
  profile documents for a faithful round trip; the deterministic adapter
  fuzz harness now covers the sequence mapping.
- Added the complete Chinese README (`README.zh-CN.md`) and refreshed the
  English README to the v1.0.0 / stable wire format 1.0 status; Machine
  Permission Test packet links now point at the `mpt-v0.2` release.
- SECURITY.md now documents the stable-version support policy: the latest
  `1.x` release and the default branch are supported; `0.x` drafts are not.
- REPRODUCING.md now documents offline verification of release packets with
  `scripts/verify_release.py`.
- Added offline release-packet verification (`scripts/verify_release.py`) and
  machine-readable micro-benchmarks (`benchmarks/bench.py`) with CI smoke.
- Added ready-to-send standards submissions (W3C ODRL, IEEE) and GitHub issue
  templates for bugs, features, and RFC proposals.
- Added KGP-RFC-0002 (versioned ODRL profile `kgp-v0.2`) draft and CI smoke
  tests for every released CLI.
- Added the standards-outreach package (`docs/STANDARDS-OUTREACH.md`) and
  synced v1.0.0 assets and metadata to the static mirror repositories.
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
