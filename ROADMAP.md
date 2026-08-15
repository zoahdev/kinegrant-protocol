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

## v1.8 — audit readiness (complete with v1.8.0)

- the security review kit generator runs every evidence suite and emits an
  auditor-ready machine-readable checklist.

## v1.9 — shipped evidence (complete with v1.9.0)

- the security review kit is published as a checksummed, offline-verifiable
  release asset with every stable release.

## v2.0 - policy trust lifecycle (complete with v2.0.0)

- signed, versioned policy bundles (`PolicyAuthority` / `PolicyRegistry` /
  `verify_policy_bundle`): an authority can publish, replace, and revoke
  policy documents without a central ledger; every consumer verifies the
  signature, authority, validity window, and rules digest itself (first item
  landed via PR #80, conformance at 22/22);
- independent JavaScript/Go verification of policy bundles and current-
  version selection (complete via PR #81);
- policy-bundle cases in the Machine Permission Test (complete via PR #82,
  MPT v0.4 with 20 cases);
- a conformance mark set that requires rollback on revocation and fail-closed
  behavior when no trusted policy is available.

Exit criterion: a fleet can receive a policy update from a trusted authority,
roll back an emergency revocation without a central service, and an external
implementer can reproduce current-version selection from the signed bundles
alone. Released as v2.0.0 (2026-08-15).

## v2.1 - fleet policy operations (complete with v2.1.0)

- fleet policy distribution (`PolicyDistributor` + `verify_policy_distribution_report`): one signed policy bundle is applied to many registries idempotently (never auto-downgrading) with per-registry acknowledgements and machine-readable fleet reports (landed via PR #84, conformance at 23/23);
- policy-bundle JavaScript/Go evidence in the Machine Permission Test cases (complete via PR #85);
- policy-bundle verification in the browser public verifier (needs site source);
- governance and stability documentation hardening.

Exit criterion: a fleet can receive a policy update, acknowledge it per gate, and audit the acknowledgement against the signed bundle without a central service. Released as v2.1.0 (2026-08-15).

## v2.2 - standards alignment and stability (complete with v2.2.0)

- signed policy bundles serialize to ODRL (`bundle_to_odrl`, kgp-v0.2 profile round-trip) (complete via PR #87);
- stability and compatibility policy for policy bundles and schemas (`docs/STABILITY.md`, COMPATIBILITY/GOVERNANCE updates) (complete via PR #87);
- policy-bundle verification in the browser public verifier (needs site source).

Exit criterion: an ODRL consumer can ingest a KineGrant policy bundle's rules through a documented, versioned profile, and adopters can rely on explicit stability levels for wire formats and schemas. Released as v2.2.0 (2026-08-15).

## v2.3 - audit tooling and schema governance (complete with v2.3.0)

- policy bundle static analysis (`analyze_policy_bundle` + `kinegrant-policy-bundle --analyze`): conservative conflict, duplicate, unknown-constraint/obligation, issuer-mismatch, and broad-allow findings, with CI fail-closed exit codes (complete via PR #89);
- bounded request-space coverage analysis (`policy_bundle_coverage` + `--coverage`): default-denies, per-rule applicability, and shadowed allows (complete via PR #90);
- KGP-RFC-0003 draft: policy bundle schema stability (frozen 0.1 / normative ODRL mapping);
- policy-bundle verification in the browser public verifier (needs site source).

Exit criterion: an auditor can run one command on a signed bundle and get machine-readable conflict and coverage findings before deployment. Released as v2.3.0 (2026-08-15).

## v2.4 - adoption examples and schema governance (complete with v2.4.0)

- executable policy-bundle lifecycle example (`examples/policy-bundle`, machine-readable PASS trace covering publish, enforce, ODRL round trip, fleet distribution, audit, coverage, and revocation rollback) (complete via PR #92);
- RFC-0003 acceptance vote (community/steering action);
- policy-bundle verification in the browser public verifier (needs site source).

Exit criterion: an adopter can run one example and see the full signed policy lifecycle pass end to end, then reproduce it with their own authority keys. Released as v2.4.0 (2026-08-15).

## v2.5 - fleet audit and governance (complete with v2.5.0)

- policy bundle audit aggregation (`audit_policy_bundles` + `--audit-summary`): one machine-readable report over a fleet of bundles covering verification, static analysis, coverage, and findings-by-code (complete via PR #94);
- RFC-0003 acceptance vote (community/steering action);
- policy-bundle verification in the browser public verifier (needs site source).

Exit criterion: an auditor can audit an entire policy fleet with one command and get a machine-readable, fail-closed summary. Released as v2.5.0 (2026-08-15).

## v2.6 - browser verification and governance (complete with v2.6.0)

- standalone offline browser policy-bundle verifier (`verify/`): zero-dependency WebCrypto verification, current-version selection, and a hostable HTML page (complete via PR #96);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: anyone can verify a signed policy bundle in a browser without installing anything or uploading data. Released as v2.6.0 (2026-08-15).

## v2.7 - full browser verification (complete with v2.7.0)

- browser verifier extended to capabilities (v0.1/v0.2/1.0) and receipt chains (v0.1/1.0) alongside policy bundles (complete via PR #98);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a visitor can verify a policy bundle, a capability, and a receipt chain in the browser without installing anything. Released as v2.12.0 (2026-08-15). Released as v2.7.0 (2026-08-15).

## v2.8 - browser challenge verification (complete with v2.8.0)

- browser verifier validates MPT evidence locally (schema 0.4, required cases MPT-001..020, summary and overall-result consistency) (complete via PR #100);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a visitor can validate a Machine Permission Test evidence file in the browser without installing anything. Released as v2.8.0 (2026-08-15).

## v2.9 - browser operations verification (complete with v2.9.0)

- browser verifier validates revocation bundles and policy distribution reports (complete via PR #102);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a fleet operator can verify a revocation bundle and a policy distribution report in the browser without installing anything. Released as v2.14.0 (2026-08-15). Released as v2.13.0 (2026-08-15). Released as v2.9.0 (2026-08-15).

## v2.10 - reproducible fleet operations (complete with v2.10.0)

- Machine Permission Test v0.5 with 22 reproducible cases: new MPT-021 fleet policy distribution (upgrades without downgrades) and MPT-022 policy bundle analysis (conflict detection + coverage) (complete via PR #104);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an external implementer can reproduce fleet policy distribution and policy analysis from one evidence packet. Released as mpt-v0.5 + v2.10.0 (2026-08-15).

## v2.11 - browser evidence verification (complete with v2.11.0)

- browser verifier validates self-verifying receipt evidence packets (`kinegrant:ReceiptEvidencePacket` integrity and receipt structure) (complete via PR #106);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can validate an exported receipt evidence packet in the browser without installing anything. Released as v2.11.0 (2026-08-15).

## v2.12 - browser audit verification (complete with v2.12.0)

- browser verifier validates audit CSV exports (header and row consistency) (complete via PR #108);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can validate an exported audit CSV in the browser without installing anything.

## v2.13 - browser reproduction verification (complete with v2.13.0)

- browser verifier validates external reproduction reports (`kinegrant:ReproductionReport` structure and verification consistency) (complete via PR #110);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an external implementer can validate a reproduction report in the browser without installing anything.

## v2.14 - browser fleet verification (complete with v2.14.0)

- browser verifier validates revocation distribution reports (structure, summary consistency, optional bundle binding) (complete via PR #112);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a fleet operator can validate a revocation distribution report in the browser without installing anything.

## v2.15 - browser standards alignment (complete with v2.15.0)

- browser verifier maps verified policy bundles to ODRL (`policyBundleToOdrl`, kgp-v0.2 profile) (complete via PR #114);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an ODRL consumer can see the ODRL representation of a verified bundle in the browser. Released as v2.15.0 (2026-08-15).

## v2.16 - browser vocabulary verification (complete with v2.16.0)

- browser verifier validates the `kg.action.*` action vocabulary (fail-closed on unknown terms) (complete via PR #116);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a user can validate an action list against the canonical vocabulary in the browser. Released as v2.17.0 (2026-08-15). Released as v2.16.0 (2026-08-15).

## v2.17 - browser obligation verification (complete with v2.17.0)

- browser verifier validates the known obligation vocabulary (fail-closed on unknown obligations) (complete via PR #118);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a user can validate an obligation list against the known vocabulary in the browser.

## v2.18 - browser identity verification (complete with v2.18.0)

- browser verifier validates canonical KineGrant identifier syntax (`urn:kinegrant:<kind>:<namespace>:<local-id>`, fail-closed on malformed identifiers) (complete via PR #120);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a user can validate agent/target/policy identifiers against the canonical syntax in the browser. Released as v2.18.0 (2026-08-15).

## v2.19 - browser policy analysis verification (complete with v2.19.0)

- browser verifier re-verifies `kinegrant:PolicyBundleAnalysis` reports against the signed bundle (findings recomputed locally, fail-closed on any mismatch) (complete via PR #122);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify a policy analysis report in the browser without trusting the report generator. Released as v2.19.0 (2026-08-15).

## v2.20 - browser delegation chain verification (complete with v2.20.0)

- browser verifier verifies scoped delegation chains end to end (`verifyDelegationChain`: signatures, per-hop attenuation, delegation bounds, terminal request binding) (complete via PR #124);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a gate operator can verify a delegated capability chain in the browser without trusting the chain generator. Released as v2.20.0 (2026-08-15).

## v2.21 - browser forbidden-combination verification (complete with v2.21.0)

- browser verifier evaluates forbidden combinations and sequence policies end to end (`evaluateSequencePolicy`: journal entries, pattern sets, optional windows and triggers, fail-closed verdicts) and re-verifies `kinegrant:SequenceCheckReport` artifacts (`verifySequenceCheckReport`) (complete via PR #126);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a gate operator can verify a forbidden-combination verdict in the browser without trusting the policy or journal generator. Released as v2.21.0 (2026-08-15).

## v2.22 - browser post-quantum verification (complete with v2.22.0)

- browser verifier verifies post-quantum FIPS 204 ML-DSA-65 signed envelopes (`verifyMldsaEnvelope`; every envelope path accepts `alg: "ML-DSA-65"`) (complete via PR #129);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can verify an ML-DSA-65 signed bundle or receipt in the browser without installing anything. Released as v2.22.0 (2026-08-15).

## v2.23 - browser conformance verification (complete with v2.23.0)

- browser verifier re-verifies `kinegrant:ConformanceReport` artifacts (`verifyConformanceReport`: L1-L4 marks, summary consistency, overall result, independent-verification statuses) (complete via PR #131);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify a conformance report in the browser without trusting the report generator. Released as v2.23.0 (2026-08-15).

## v2.24 - browser fleet audit verification (complete with v2.24.0)

- browser verifier re-verifies `kinegrant:PolicyAuditSummary` reports (`verifyPolicyAuditSummary`: per-bundle verified/failure fields, aggregated counts, findings-by-code, overall fleet result) (complete via PR #133);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a fleet operator can re-verify a policy audit summary in the browser without trusting the report generator. Released as v2.24.0 (2026-08-15).

## v2.25 - browser security kit verification (complete with v2.25.0)

- browser verifier re-verifies `kinegrant:SecurityReviewKit` artifacts (`verifySecurityReviewKit`: check statuses, MPT schema binding, benchmark output, checklist/commands/artifacts structure, overall result) (complete via PR #135);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify a security review kit in the browser without trusting the kit generator. Released as v2.25.0 (2026-08-15).

## v2.26 - browser hardware evidence verification (complete with v2.26.0)

- browser verifier re-verifies `kinegrant:ESP32C3PaperBarrierProofEvidence` (`verifyEsp32c3Evidence`: HWP-001..011 acceptance profiles, NOT_RUN/PASS/FAIL consistency, trust-check flags, physical-mode artifact/role/digest requirements) (complete via PR #137);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify ESP32-C3 hardware evidence in the browser without installing anything. Released as v2.26.0 (2026-08-15).

## v2.27 - browser fleet operations verification (complete with v2.27.0)

- browser verifier re-verifies combined `kinegrant:FleetOperationsReport` artifacts (`verifyFleetOperationsReport`: policy + revocation distribution reports joined per gate, fleet totals and overall result checked) (complete via PR #139);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: a fleet operator can re-verify the combined policy + revocation distribution state of the fleet in the browser without trusting the report generator. Released as v2.27.0 (2026-08-15).

## v2.28 - browser benchmark verification (complete with v2.28.0)

- browser verifier re-verifies `kinegrant:BenchmarkReport` artifacts (`verifyBenchmarkReport`: iteration counts, ten-operation throughput surface, fail-closed on missing or non-positive values) (complete via PR #141);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an engineer can re-verify a benchmark report in the browser without trusting the report generator. Released as v2.28.0 (2026-08-15).

## v2.29 - browser lifecycle trace verification (complete with v2.29.0)

- browser verifier re-verifies one-stop `kinegrant:PolicyLifecycleTrace` artifacts (`verifyPolicyLifecycleTrace`: signed-bundle binding, canonical phase order, per-phase statuses, summary, overall result) (complete via PR #143);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an operator can re-verify the full policy lifecycle trace of a signed bundle in the browser without trusting the trace generator. Released as v2.29.0 (2026-08-15).

## v2.30 - browser hardware groundwork verification (complete with v2.30.0)

- browser verifier re-verifies sensor-evidence commitments and receipt checkpoints (`verifySensorCommitment` / `sensorEvidenceHash` / `verifyReceiptCheckpoint`: reading digests, content-addressed ids, optional signatures, evidence-hash binding, notary binding) (complete via PR #145);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify v0.4 sensor commitments and receipt checkpoints in the browser without trusting the generator. Released as v2.30.0 (2026-08-15).

## v2.31 - browser device attestation verification (complete with v2.31.0)

- browser verifier re-verifies `kinegrant:DeviceAttestation` (`verifyDeviceAttestation`: device binding, firmware digest, boot counter, measured-boot stages, content-addressed id) (complete via PR #147);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify a device attestation in the browser without trusting the device or the attestation generator. Released as v2.31.0 (2026-08-15).

## v2.32 - browser bridge verification (complete with v2.32.0)

- browser verifier re-verifies `kinegrant:Ros2McpDemoReport` and `kinegrant:BridgeDemoReport` (`verifyBridgeDemoReport`: outcome structure, expected/allowed/passed consistency, summary counts, bridge flags, overall result) (complete via PR #149);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an engineer can re-verify a ROS2/MCP or adapter bridge demo report in the browser without trusting the report generator. Released as v2.32.0 (2026-08-15).

## v2.33 - browser hardware trust packet verification (complete with v2.33.0)

- browser verifier re-verifies combined `kinegrant:HardwareTrustPacket` artifacts (`verifyHardwareTrustPacket`: device attestation + sensor commitments + receipt checkpoints, device binding, summary) (complete via PR #152);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify the combined hardware trust evidence of a device in the browser without trusting the packet generator. Released as v2.33.0 (2026-08-15).

## v2.34 - browser gateway compliance verification (complete with v2.34.0)

- browser verifier re-verifies `kinegrant:RobotDemoReport` (`verifyRobotDemoReport`: outcome structure, expected/allowed/passed consistency, actuator-call counts, summary, obligation compliance, overall result) (complete via PR #154);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify a gateway robot demo report in the browser without trusting the report generator. Released as v2.34.0 (2026-08-15).

## v2.35 - browser camera consent verification (complete with v2.35.0)

- browser verifier re-verifies camera-consent scenario traces (`verifyCameraConsentTrace`: record/consume/policy/sequence/obligation flags consistent with passed) (complete via PR #156);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify a camera-consent scenario trace in the browser without trusting the trace generator. Released as v2.35.0 (2026-08-15).

## v2.36 - browser full lifecycle verification (complete with v2.36.0)

- browser verifier re-verifies one-stop `kinegrant:FullLifecycleReport` artifacts (`verifyFullLifecycleReport`: signed bundle binding, policy distribution, fleet audit summary, revocation distribution) (complete via PR #158);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify the full publish -> distribute -> audit -> revoke lifecycle of a signed bundle in the browser without trusting the report generator. Released as v2.36.0 (2026-08-15).

## v2.37 - browser evidence export verification (complete with v2.37.0)

- browser verifier re-verifies `kinegrant:EvidenceExportPacket` (`verifyEvidenceExportPacket`: artifact names/kinds/sha256 manifest, unique names, consistent summary) (complete via PR #160);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify an evidence export manifest in the browser without trusting the export generator. Released as v2.37.0 (2026-08-15).

## v2.38 - browser device-to-policy end-to-end export verification

- browser verifier re-verifies `kinegrant:DeviceToPolicyExportPacket`
  (`verifyDeviceToPolicyExport`: policy bundle, capability, gate decision,
  receipt, sensor commitment, receipt checkpoint, and device attestation
  each verified and cross-bound; capability policy digest recomputed from
  exported rules and trust set; receipt evidence bound to sensor
  commitment; checkpoint anchored to the receipt chain; sensor readings
  bound to the attested device);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify the full device-to-policy chain
of a physical action in the browser without trusting the export generator.

## v2.39 - browser fleet device export verification

- browser verifier re-verifies `kinegrant:FleetDeviceExportPacket`
  (`verifyFleetDeviceExport`: every embedded device-to-policy export is
  re-verified and must share the same policy bundle and trust set;
  device/capability/receipt ids unique across the fleet; consistent
  summary);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify multi-device physical-action
evidence under one policy in the browser without trusting the export
generator.

## v2.40 - browser end-to-end audit export verification

- browser verifier re-verifies `kinegrant:EndToEndAuditExportPacket`
  (`verifyEndToEndAuditExport`: full lifecycle report and multi-device
  fleet export share one policy bundle and trust anchors; consistent
  summary);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify governance lifecycle and
multi-device execution evidence in one browser export without trusting
the export generator.

## v2.41 - browser revocation-reissue closure verification

- browser verifier re-verifies `kinegrant:RevocationReissueClosurePacket`
  (`verifyRevocationReissueClosure`: revoked id present in the signed
  revocation bundle; fresh reissued capability bound to the same request
  and policy digest; gate log records revoked denial before reissue
  allow; receipt binds the reissued capability);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify a revocation -> denial ->
reissue -> allow -> receipt closure in the browser without trusting the
export generator.

## v2.42 - browser unified audit export verification

- browser verifier re-verifies `kinegrant:UnifiedAuditExportPacket`
  (`verifyUnifiedAuditExport`: lifecycle report, fleet device export, and
  revocation-reissue closure share one policy bundle, revocation bundle,
  and trust anchors; consistent summary);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify governance lifecycle, multi-device
execution evidence, and revocation-reissue closure in one browser export
without trusting the export generator.

## v2.43 - browser policy migration audit verification

- browser verifier re-verifies `kinegrant:PolicyMigrationAuditPacket`
  (`verifyPolicyMigrationAudit`: new bundle exactly one version ahead and
  chained to the old digest; distribution bound to the new bundle; old
  capability bound to the old policy digest and new capability to the new
  policy digest; gate log old denial before new allow; receipt binds the
  new capability);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify a policy version migration
(rules change -> distribution -> reissue -> receipt) in the browser
without trusting the export generator.

## v2.44 - browser compliance timeline verification

- browser verifier re-verifies `kinegrant:ComplianceTimelinePacket`
  (`verifyComplianceTimeline`: issue/allow/receipt/revoke/deny/reissue
  events chronologically monotonic, policy-bound, and cross-referenced;
  unique receipts; at least one revocation);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify the chronological event stream
of a device's authorization lifecycle in the browser without trusting
the export generator.

## v2.45 - browser obligation fulfillment verification

- browser verifier re-verifies `kinegrant:ObligationFulfillmentPacket`
  (`verifyObligationFulfillment`: every capability obligation covered by
  receipt obligation results, satisfied or explicitly failed; pending
  fails closed; receipts 1.0 and chain-valid);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify that every obligation attached
to an authorization was fulfilled or explicitly failed in the browser
without trusting the export generator.

## v2.46 - browser selective disclosure verification

- browser verifier re-verifies `kinegrant:SelectiveDisclosurePacket`
  (`verifySelectiveDisclosure`: Merkle inclusion proofs recomputed per
  revealed field against the committed root; unique field names;
  fail-closed on any non-matching proof);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can verify that a disclosed subset belongs to
a committed document in the browser without seeing the full document.

## v2.47 - browser identifier rotation verification

- browser verifier re-verifies `kinegrant:IdentifierRotationPacket`
  (`verifyIdentifierRotation`: ephemeral id grammar, strictly increasing
  issue order, unique ids, exactly one active identifier which must be
  the latest entry, revoked_at after issued_at);
- RFC-0003 acceptance vote (community/steering action);
- integrate the verifier page into the public site (deployment action).

Exit criterion: an auditor can re-verify the rotation and revocation
state of a privacy-preserving identifier in the browser without trusting
the export generator.

## Success metrics

KineGrant is not successful because its repository is popular. It succeeds when:

1. unrelated robot vendors can request the same capability;
2. a person or space can publish one rule understood by all of them;
3. a safety auditor can reproduce the decision;
4. an actuator cannot execute without the verified capability;
5. receipts reveal less personal data than raw operational logs.
