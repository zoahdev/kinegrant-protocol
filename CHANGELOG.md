# Changelog

## Unreleased

## 2.65.3 2026-08-16

- Added a `kinegrant-fuzz` CLI and a fail-closed core fuzz harness that
  mutates signed capability payloads and request bindings, asserting the
  action gate never accepts a mutated input.

- Added a CI fuzz job and OpenSSF Scorecard workflow, plus a threat model,
  independent-review guide, and release checksums.

## 2.65.2 2026-08-16

- Persist the gate service receipt log to disk so the audit chain survives a
  restart (`receipt-log.json` next to `gate-replay.sqlite3`).

- Friendlier error handling for malformed requests: a non-object capability
  and unsupported HTTP methods now return clean JSON errors instead of an
  internal traceback or an HTML 501.

## 2.65.1 2026-08-16

- Improved the gate service error messages for a malformed `policy.json` or
  `config.json`: it now reports a clear "format error, check JSON syntax"
  message instead of a raw traceback, both at startup and during hot-reload.

## 2.65.0 2026-08-16

- Added a one-command HTTP gate service (`kinegrant-serve`) and a
  deployment scaffolder (`kinegrant-init`) so a policy decision point,
  capability issuer, fail-closed verifier, and audit receipt log can run
  as plain HTTP/JSON with no web framework.

- `kinegrant-serve` exposes `POST /authorize`, `POST /verify`,
  `POST /receipt`, `POST /run`, and `GET /health`, and re-reads
  `policy.json` on every request so policy edits apply without a restart.

## 2.64.0 2026-08-16

- Milestone release: reference implementation version 2.64.0, improving
  PyPI package metadata.

- Added PyPI classifiers, keywords, authors, and project URLs
  (Homepage / Documentation / Source / Tracker) for discoverability
  and trust.

## 2.63.0 2026-08-16

- Milestone release: reference implementation version 2.63.0, making
  the conformance suite clean when run from an installed wheel.

- The independent JavaScript and Go cross-verification checks are now
  reported as SKIP (with detail `toolchain unavailable`) instead of
  FAIL when their sources are not present (for example, after
  `pip install kinegrant-protocol`), so `kinegrant-conformance`
  reports PASS from a clean install while still failing closed when
  the toolchains are present but disagree.

## 2.62.0 2026-08-16

- Milestone release: reference implementation version 2.62.0, adding
  distribution and contributor-facing packaging.

- `kinegrant-protocol` is published to PyPI; `pip install
  kinegrant-protocol` followed by `kinegrant-demo` is the documented
  30-second quickstart.
- Docker image published to GitHub Container Registry on every release
  (`docker run --rm ghcr.io/zoahdev/kinegrant-protocol`).
- `kinegrant-js` is prepared for npm publication with a CLI bin and a
  release-triggered publish workflow (activates once NPM_TOKEN is set).
- Added `.well-known/security.txt` and README quickstart blocks in
  English and Chinese.

## 2.61.0 2026-08-15

- Milestone release: reference implementation version 2.61.0 on the
  stable 1.0 wire format, adding model check audit verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:ModelCheckAuditPacket`
  (`verifyModelCheckAudit`: the request space is re-enumerated in the
  exact agent x target x action x purpose order; every outcome must
  match its space slot and be an allowed/denied decision or an
  explicit exception; allowed/denied/exception counts, per-rule
  applicable/winning/reachable stats, shadowed allows, overall_result
  and the summary must all be recomputed consistently; fail-closed on
  any inconsistency); the HTML page and Node CLI (`model-check`
  command) expose it, cross-tested against Python model check
  reports; `bounded_model_check` gains an additive `include_outcomes`
  flag.

## 2.60.0 2026-08-15

- Milestone release: reference implementation version 2.60.0 on the
  stable 1.0 wire format, adding SROS2 policy mapping verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:Sros2PolicyMappingPacket`
  (`verifySros2PolicyMapping`: the signed policy bundle is verified;
  every declaration must be exactly reproducible from the bundle's
  rules (sorted by policy_id and actions, one declaration per action
  with `kg/<action>/goal` topic patterns); declaration fields and
  summary counts must be consistent; fail-closed on any mismatch);
  the HTML page and Node CLI (`sros2-mapping` command) expose it,
  cross-tested against Python-generated SROS2 mappings.

## 2.59.0 2026-08-15

- Milestone release: reference implementation version 2.59.0 on the
  stable 1.0 wire format, adding red team report verification to the
  browser verifier.

- Browser verifier re-verifies `kinegrant:RedTeamReport`
  (`verifyRedTeamReport`: all 11 required RT-001..RT-011 cases must be
  present with unique identifiers; each case must carry the exact
  id/category/name/expected/observed/passed/detail fields; expected
  must be DENY and observed must be DENY or ALLOW/ERROR; the passed
  flag must exactly match observed; summary counts and overall_result
  must be consistent; fail-closed on any inconsistency); the HTML
  page and Node CLI (`red-team` command) expose it, cross-tested
  against Python-built red team reports.

## 2.58.0 2026-08-15

- Milestone release: reference implementation version 2.58.0 on the
  stable 1.0 wire format, adding rule coverage audit verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:RuleCoverageAuditPacket`
  (`verifyRuleCoverageAudit`: every request must be a valid v0.1
  action request with unique request ids; rules are matched by
  target/action/subject/purpose glob semantics identical to the
  Python policy engine; covered rule ids, uncovered rule ids, and
  requests_matched must exactly match a recomputation from the
  signed bundle; summary counts and completeness flags must be
  consistent; fail-closed on any inconsistency); the HTML page and
  Node CLI (`rule-coverage` command) expose it, cross-tested against
  Python-built rule coverage packets.

## 2.57.0 于 2026-08-15

- Milestone release: reference implementation version 2.57.0 on the
  stable 1.0 wire format, adding obligation batch audit verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:ObligationBatchAuditPacket`
  (`verifyObligationBatchAudit`: every entry's capability is bound to the
  batch policy and request; every receipt is a verified 1.0 chain bound
  to its capability; each entry must cover all of its own obligations
  with satisfied or explicitly failed results (pending fails closed);
  the union of covered obligations must equal the union of required
  obligations across the batch; summary counts and flags must be
  consistent; fail-closed on any inconsistency); the HTML page and Node
  CLI (`obligation-batch` command) expose it, cross-tested against
  Python-built receipt batches.

## 2.56.0 于 2026-08-15

- Milestone release: reference implementation version 2.56.0 on the
  stable 1.0 wire format, adding policy template audit verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:PolicyTemplateAuditPacket`
  (`verifyPolicyTemplateAudit`: every rule must match the template's
  fixed fields exactly (canonical comparison), only use fields covered
  by the template or rule identity, and keep variable fields within the
  template's allowed values; summary counts and flags must be
  consistent; fail-closed on any inconsistency); the HTML page and Node
  CLI (`policy-template` command) expose it, cross-tested against
  Python-published template-compliant bundles.

## 2.55.0 于 2026-08-15

- Milestone release: reference implementation version 2.55.0 on the
  stable 1.0 wire format, adding cross implementation consistency
  verification to the browser verifier.

- Browser verifier re-verifies `kinegrant:CrossImplementationReportPacket`
  (`verifyCrossImplementationReport`: every check must come from a known
  implementation (python/js/go), carry a PASS/FAIL/SKIP result and a
  non-empty detail, and be marked verified; for every check name, the
  results across all tools must agree and none may be FAIL; summary
  counts and flags must be consistent; fail-closed on any
  inconsistency); the HTML page and Node CLI (`cross-implementation`
  command) expose it, cross-tested against Python-built reports.

## 2.54.0 于 2026-08-15

- Milestone release: reference implementation version 2.54.0 on the
  stable 1.0 wire format, adding audit query verification to the browser
  verifier.

- Browser verifier re-verifies `kinegrant:AuditQueryPacket`
  (`verifyAuditQuery`: each query condition is translated into an
  executable matcher (action/purpose/target/result/evidence hash/time
  windows) and its match count is recomputed over the provided records;
  every reported match count must match exactly and conditions must be
  marked verified; summary counts and flags must be consistent;
  fail-closed on any inconsistency); the HTML page and Node CLI
  (`audit-query` command) expose it, cross-tested against Python-built
  receipt records.

## 2.53.0 于 2026-08-15

- Milestone release: reference implementation version 2.53.0 on the
  stable 1.0 wire format, adding cross domain audit verification to the
  browser verifier.

- Browser verifier re-verifies `kinegrant:CrossDomainAuditPacket`
  (`verifyCrossDomainAudit`: every domain's signed bundle is verified
  against its own trust anchors; domain ids must be unique; every cross
  reference must connect two existing domains, use a known kind, point
  at the target domain's actual policy id, and be marked verified;
  summary counts and flags must be consistent; fail-closed on any
  inconsistency); the HTML page and Node CLI (`cross-domain` command)
  expose it, cross-tested against Python-published domain pairs.

## 2.52.0 于 2026-08-15

- Milestone release: reference implementation version 2.52.0 on the
  stable 1.0 wire format, adding policy impact audit verification to the
  browser verifier.

- Browser verifier re-verifies `kinegrant:PolicyImpactAuditPacket`
  (`verifyPolicyImpactAudit`: the diff must match the two signed bundles
  exactly; the affected rule set is the union of added and changed rules;
  affected targets, actions, and purposes are recomputed from those rules
  and must match the report; summary counts and flags must be consistent;
  fail-closed on any inconsistency); the HTML page and Node CLI
  (`policy-impact` command) expose it, cross-tested against
  Python-published bundle pairs.

## 2.51.0 于 2026-08-15

- Milestone release: reference implementation version 2.51.0 on the
  stable 1.0 wire format, adding policy diff audit verification to the
  browser verifier.

- Browser verifier re-verifies `kinegrant:PolicyDiffAuditPacket`
  (`verifyPolicyDiffAudit`: the new bundle must chain to the old bundle
  digest at exactly version + 1; added, removed, unchanged, and changed
  rule ids are recomputed from the two rule sets by canonical digest and
  must match the report exactly; summary counts and flags must be
  consistent; fail-closed on any inconsistency); the HTML page and Node
  CLI (`policy-diff` command) expose it, cross-tested against
  Python-published bundle pairs.

## 2.50.0 于 2026-08-15

- Milestone release: reference implementation version 2.50.0 on the
  stable 1.0 wire format, adding denial explainability verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:DenialExplainabilityPacket`
  (`verifyDenialExplainability`: every denial must bind the audited
  policy digest and a valid request digest, carry a non-empty reason and
  explanation, reference a real policy rule when a rule is cited, and
  have unique ids; summary counts and flags must be consistent;
  fail-closed on any inconsistency); the HTML page and Node CLI
  (`denial-explainability` command) expose it, cross-tested against
  Python PolicyEngine denials.

## 2.49.0 于 2026-08-15

- Milestone release: reference implementation version 2.49.0 on the
  stable 1.0 wire format, adding least privilege audit verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:LeastPrivilegeAuditPacket`
  (`verifyLeastPrivilegeAudit`: the scoped capability must be bound to
  the policy and request, and its actions, purposes, and target scope
  must each be exactly the executed action, purpose, and target -- no
  extra permissions; the receipt must bind the capability and request;
  summary counts and flags must be consistent; fail-closed on any
  inconsistency); the HTML page and Node CLI (`least-privilege` command)
  expose it, cross-tested against Python-issued scoped capabilities.

## 2.48.0 于 2026-08-15

- Milestone release: reference implementation version 2.48.0 on the
  stable 1.0 wire format, adding minimal disclosure audit verification
  to the browser verifier.

- Browser verifier re-verifies `kinegrant:MinimalDisclosureAuditPacket`
  (`verifyMinimalDisclosure`: every revealed field's Merkle inclusion
  proof must reach the committed root; the disclosed field set must cover
  every required field and must not contain any extra field, proving
  minimal necessary disclosure; summary counts and flags must be
  consistent; fail-closed on any inconsistency); the HTML page and Node
  CLI (`minimal-disclosure` command) expose it, cross-tested against
  Python-built Merkle redactions.

## 2.47.0 于 2026-08-15

- Milestone release: reference implementation version 2.47.0 on the
  stable 1.0 wire format, adding identifier rotation verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:IdentifierRotationPacket`
  (`verifyIdentifierRotation`: rotation entries must follow the ephemeral
  id grammar for the namespace, have strictly increasing issue times,
  unique ids, and exactly one active identifier which must be the latest
  entry; revoked entries require a revoked_at after issued_at; summary
  counts and flags must be consistent; fail-closed on any inconsistency);
  the HTML page and Node CLI (`identifier-rotation` command) expose it,
  cross-tested against the Python rotating identifier registry.

## 2.46.0 于 2026-08-15

- Milestone release: reference implementation version 2.46.0 on the
  stable 1.0 wire format, adding selective disclosure verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:SelectiveDisclosurePacket`
  (`verifySelectiveDisclosure`: each revealed field's Merkle inclusion
  proof is recomputed from the field name and value up to the committed
  root using the protocol's JCS digest rules; field names must be unique;
  any proof that does not reach the root fails closed; summary counts and
  flags must be consistent); the HTML page and Node CLI
  (`selective-disclosure` command) expose it, cross-tested against
  Python-built Merkle redactions.

## 2.45.0 于 2026-08-15

- Milestone release: reference implementation version 2.45.0 on the
  stable 1.0 wire format, adding obligation fulfillment verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:ObligationFulfillmentPacket`
  (`verifyObligationFulfillment`: every obligation carried by the
  capability must be covered by receipt obligation results with status
  satisfied or explicitly failed with a reason; pending obligations
  fail closed; receipts must be 1.0, bind the capability and request
  digest, and form a valid chain; summary counts and flags must be
  consistent); the HTML page and Node CLI (`obligation-fulfillment`
  command) expose it, cross-tested against a Python-built packet.

## 2.44.0 于 2026-08-15

- Milestone release: reference implementation version 2.44.0 on the
  stable 1.0 wire format, adding compliance timeline verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:ComplianceTimelinePacket`
  (`verifyComplianceTimeline`: capability issue, gate allow, receipt,
  revocation, gate deny, and reissue events must be chronologically
  monotonic, bound to the timeline policy, and cross-referenced so that
  every allow/receipt/revocation/denial/reissue references a previously
  issued capability and receipts are unique; at least one revocation must
  be present; summary counts and flags must be consistent; fail-closed on
  any inconsistency); the HTML page and Node CLI (`timeline` command)
  expose it, cross-tested against a Python-built timeline.

## 2.43.0 于 2026-08-15

- Milestone release: reference implementation version 2.43.0 on the
  stable 1.0 wire format, adding policy migration audit verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:PolicyMigrationAuditPacket`
  (`verifyPolicyMigrationAudit`: the new bundle must be exactly one
  version ahead and chain to the old bundle digest; the distribution
  report must bind the new bundle; the old capability must bind the old
  policy digest and the new capability the new policy digest; the gate
  log must record the old denial before the new allow; the receipt must
  bind the new capability; fail-closed on any inconsistency); the HTML
  page and Node CLI (`migration-audit` command) expose it, cross-tested
  against a Python-built packet.

## 2.42.0 于 2026-08-15

- Milestone release: reference implementation version 2.42.0 on the
  stable 1.0 wire format, adding unified audit export verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:UnifiedAuditExportPacket`
  (`verifyUnifiedAuditExport`: the full lifecycle report, the multi-device
  fleet export, and the revocation-reissue closure are each re-verified
  and must share the same policy bundle, revocation bundle, and trust
  anchors; summary counts and flags must be consistent; fail-closed on
  any inconsistency); the HTML page and Node CLI (`unified-audit`
  command) expose it, cross-tested against a Python-built packet.

## 2.41.0 于 2026-08-15

- Milestone release: reference implementation version 2.41.0 on the
  stable 1.0 wire format, adding revocation-reissue closure verification
  to the browser verifier.

- Browser verifier re-verifies `kinegrant:RevocationReissueClosurePacket`
  (`verifyRevocationReissueClosure`: the revoked capability id must be in
  the signed revocation bundle; the reissued capability must be fresh,
  bound to the same request and policy digest; the gate log must record
  the revoked denial before the reissue allow; the receipt must bind the
  reissued capability; fail-closed on any inconsistency); the HTML page
  and Node CLI (`revocation-reissue` command) expose it, cross-tested
  against a Python-built packet.

## 2.40.0 于 2026-08-15

- Milestone release: reference implementation version 2.40.0 on the
  stable 1.0 wire format, adding end-to-end audit export verification
  to the browser verifier.

- Browser verifier re-verifies `kinegrant:EndToEndAuditExportPacket`
  (`verifyEndToEndAuditExport`: the full publish -> distribute -> audit
  -> revoke lifecycle report and the multi-device fleet export are both
  re-verified and must share the same policy bundle and trust anchors;
  summary counts and flags must be consistent; fail-closed on any
  inconsistency); the HTML page and Node CLI (`end-to-end-audit`
  command) expose it, cross-tested against a Python-built packet.

## 2.39.0 于 2026-08-15

- Milestone release: reference implementation version 2.39.0 on the
  stable 1.0 wire format, adding fleet device export verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:FleetDeviceExportPacket`
  (`verifyFleetDeviceExport`: every embedded device-to-policy export
  packet is re-verified and must share the same policy bundle and trust
  set; device, capability, and receipt ids must each be unique across
  the fleet; summary counts and flags must be consistent; fail-closed on
  any inconsistency); the HTML page and Node CLI (`fleet-device-export`
  command) expose it, cross-tested against a Python-built fleet packet.

## 2.38.0 于 2026-08-15

- Milestone release: reference implementation version 2.38.0 on the
  stable 1.0 wire format, adding device-to-policy end-to-end export
  verification to the browser verifier.

- Browser verifier re-verifies `kinegrant:DeviceToPolicyExportPacket`
  artifacts (`verifyDeviceToPolicyExport`: policy bundle, capability,
  gate decision, receipt, sensor commitment, receipt checkpoint, and
  device attestation each verified and cross-bound; the capability
  policy digest is recomputed from the exported rules and trust set;
  receipt evidence is bound to the sensor commitment; the checkpoint
  is anchored to the exact receipt chain; sensor readings are bound to
  the attested device; fail-closed on any inconsistency); the HTML page
  and Node CLI (`device-to-policy` command) expose it, cross-tested
  against a Python-built export packet.

## 2.37.0 бк 2026-08-15

- Milestone release: reference implementation version 2.37.0 on the
  stable 1.0 wire format, adding evidence export packet verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:EvidenceExportPacket` artifacts
  (`verifyEvidenceExportPacket`: export manifest binding artifact names to
  known kinds and sha256 digests, unique names, consistent summary;
  fail-closed on any inconsistency); the HTML page and Node CLI
  (`evidence-export` command) expose it, cross-tested against a Python-built
  export manifest.

## 2.36.0 бк 2026-08-15

- Milestone release: reference implementation version 2.36.0 on the
  stable 1.0 wire format, adding full lifecycle report verification to
  the browser verifier.

- Browser verifier re-verifies one-stop `kinegrant:FullLifecycleReport`
  artifacts (`verifyFullLifecycleReport`: signed bundle verified and bound,
  then policy distribution, fleet audit summary, and revocation distribution
  each re-verified against the same bundle; fail-closed on any
  inconsistency); the HTML page and Node CLI (`full-lifecycle` command)
  expose it, cross-tested against the Python lifecycle example components.

## 2.35.0 бк 2026-08-15

- Milestone release: reference implementation version 2.35.0 on the
  stable 1.0 wire format, adding camera consent trace verification to
  the browser verifier.

- Browser verifier re-verifies camera-consent scenario traces
  (`verifyCameraConsentTrace`: record/consume/policy/sequence/obligation
  flags mutually consistent with the passed result; fail-closed on any
  inconsistency); the HTML page and Node CLI (`camera-consent` command)
  expose it, cross-tested against the Python camera-consent example.

## 2.34.0 бк 2026-08-15

- Milestone release: reference implementation version 2.34.0 on the
  stable 1.0 wire format, adding gateway robot demo report verification
  to the browser verifier.

- Browser verifier re-verifies gateway `kinegrant:RobotDemoReport` artifacts
  (`verifyRobotDemoReport`: outcome structure, expected/allowed/passed
  consistency, actuator-call counts, summary, obligation compliance, overall
  result; fail-closed on any inconsistency); the HTML page and Node CLI
  (`robot-demo` command) expose it, cross-tested against the Python robot
  demo runner.

## 2.33.0 бк 2026-08-15

- Milestone release: reference implementation version 2.33.0 on the
  stable 1.0 wire format, adding hardware trust packet verification to
  the browser verifier.

- Browser verifier re-verifies combined `kinegrant:HardwareTrustPacket`
  artifacts (`verifyHardwareTrustPacket`: device attestation, sensor
  commitments, and receipt checkpoints each re-verified; packet device id
  bound to the attestation; summary checked; fail-closed on any
  inconsistency); the HTML page and Node CLI (`hardware-packet` command)
  expose it, cross-tested against the Python v0.4 hardware-trust builders.

## 2.32.0 бк 2026-08-15

- Milestone release: reference implementation version 2.32.0 on the
  stable 1.0 wire format, adding bridge demo report verification to the
  browser verifier.

- Browser verifier re-verifies v0.3 bridge demo reports
  (`verifyBridgeDemoReport`: `kinegrant:Ros2McpDemoReport` and
  `kinegrant:BridgeDemoReport` outcome structure, expected/allowed/passed
  consistency, summary counts, bridge flags, overall result; fail-closed on
  any inconsistency); the HTML page and Node CLI (`bridge` command) expose
  it, cross-tested against the Python ROS2 and bridge demo runners.

## 2.31.0 бк 2026-08-15

- Milestone release: reference implementation version 2.31.0 on the
  stable 1.0 wire format, adding device attestation verification to the
  browser verifier.

- Browser verifier re-verifies v0.4 device attestations
  (`verifyDeviceAttestation`: device binding, firmware digest, boot counter,
  ordered measured-boot stages, content-addressed attestation id, optional
  trusted-device checks; fail-closed on any inconsistency); the HTML page and
  Node CLI (`attestation` command) expose it, cross-tested against the Python
  v0.4 device attestation builder.

## 2.30.0 бк 2026-08-15

- Milestone release: reference implementation version 2.30.0 on the
  stable 1.0 wire format, adding sensor-evidence commitment and receipt
  checkpoint verification to the browser verifier.

- Browser verifier re-verifies v0.4 hardware-trust groundwork artifacts
  (`verifySensorCommitment` / `sensorEvidenceHash` /
  `verifyReceiptCheckpoint`): sensor-evidence commitment structure, reading
  digests, content-addressed ids, optional sensor signatures, evidence-hash
  binding, and signed receipt checkpoints (notary binding, chain digest,
  content-addressed id); fail-closed on any inconsistency; the HTML page and
  Node CLI (`sensor` / `checkpoint` commands) expose them, cross-tested
  against the Python v0.4 builders.

## 2.29.0 бк 2026-08-15

- Milestone release: reference implementation version 2.29.0 on the
  stable 1.0 wire format, adding policy lifecycle trace verification to
  the browser verifier.

- Browser verifier re-verifies one-stop `kinegrant:PolicyLifecycleTrace`
  artifacts (`verifyPolicyLifecycleTrace`: exact binding to the signed policy
  bundle, canonical publish → enforce → odrl → distribute → audit → revoke
  order, per-phase statuses, summary, and overall result; fail-closed on any
  deviation); the HTML page and Node CLI (`lifecycle` command) expose it,
  cross-tested against a Python-generated lifecycle trace.

## 2.28.0 бк 2026-08-15

- Milestone release: reference implementation version 2.28.0 on the
  stable 1.0 wire format, adding benchmark report verification to the
  browser verifier.

- Browser verifier re-verifies `kinegrant:BenchmarkReport` artifacts
  (`verifyBenchmarkReport`: iteration counts and the full ten-operation
  operations-per-second surface, fail-closed on any missing or non-positive
  value); the HTML page and Node CLI (`bench` command) expose it,
  cross-tested against the Python benchmark runner output.

## 2.27.0 бк 2026-08-15

- Milestone release: reference implementation version 2.27.0 on the
  stable 1.0 wire format, adding fleet operations report verification to
  the browser verifier.

- Browser verifier re-verifies combined `kinegrant:FleetOperationsReport`
  artifacts (`verifyFleetOperationsReport`: embedded policy distribution and
  revocation distribution reports re-verified against their signed bundles,
  then gate sets and fleet totals joined and checked for consistency;
  fail-closed on any inconsistency); the HTML page and Node CLI
  (`fleet-ops` command) expose it, cross-tested against Python
  `PolicyDistributor` + `RevocationDistributor` output.

## 2.26.0 бк 2026-08-15

- Milestone release: reference implementation version 2.26.0 on the
  stable 1.0 wire format, adding ESP32-C3 hardware evidence verification
  to the browser verifier.

- Browser verifier re-verifies ESP32-C3 hardware-trust evidence
  (`verifyEsp32c3Evidence`: schema fields, HWP-001..011 acceptance profiles,
  NOT_RUN/PASS/FAIL consistency, trust-check flags, physical-mode artifact,
  role, and digest requirements; fail-closed on any inconsistency); the HTML
  page and Node CLI (`esp32` command) expose it, cross-tested against the
  Python hardware evidence verifier and the repository template.

## 2.25.0 бк 2026-08-15

- Milestone release: reference implementation version 2.25.0 on the
  stable 1.0 wire format, adding security review kit verification to the
  browser verifier.

- Browser verifier re-verifies `kinegrant:SecurityReviewKit` artifacts
  (`verifySecurityReviewKit`: check statuses, MPT schema binding, benchmark
  output, checklist/commands/artifacts structure, overall result; fail-closed
  on any inconsistency); the HTML page and Node CLI (`kit` command) expose it,
  cross-tested against the Python security review kit generator output shape.

## 2.24.0 бк 2026-08-15

- Milestone release: reference implementation version 2.24.0 on the
  stable 1.0 wire format, adding fleet audit summary verification to the
  browser verifier.

- Browser verifier re-verifies fleet-level `kinegrant:PolicyAuditSummary`
  reports (`verifyPolicyAuditSummary`: per-bundle verified/failure fields,
  aggregated counts, findings-by-code, shadowed-allow totals, overall fleet
  result; fail-closed on any inconsistency); the HTML page and Node CLI
  (`fleet-audit` command) expose it, cross-tested against the Python
  `audit_policy_bundles` output.

## 2.23.0 бк 2026-08-15

- Milestone release: reference implementation version 2.23.0 on the
  stable 1.0 wire format, adding conformance report verification to the
  browser verifier.

- Browser verifier re-verifies `kinegrant:ConformanceReport` artifacts
  (`verifyConformanceReport`: type/schema, L1-L4 marks, summary consistency,
  overall result, independent-verification statuses and result; fail-closed
  on any inconsistency); the HTML page and Node CLI (`conformance` command)
  expose it, cross-tested against the Python conformance runner output.

## 2.22.0 бк 2026-08-15

- Milestone release: reference implementation version 2.22.0 on the
  stable 1.0 wire format, adding post-quantum ML-DSA-65 envelope
  verification to the browser verifier.

- Browser verifier verifies post-quantum FIPS 204 ML-DSA-65 signed envelopes
  (`verifyMldsaEnvelope`; `verifyEnvelope` now accepts `alg: "ML-DSA-65"`
  everywhere, so policy bundles, capabilities, receipts, revocation bundles,
  distribution reports, and delegation chains can be post-quantum signed);
  WebCrypto SPKI import + native verification, fail-closed with a clear
  message when the browser lacks ML-DSA support; cross-tested against Python
  `cryptography` ML-DSA-65 signatures. CI pins Node 24 so the ML-DSA tests
  run in every pipeline.

## 2.21.0 бк 2026-08-15

- Milestone release: reference implementation version 2.21.0 on the
  stable 1.0 wire format, adding forbidden-combination sequence checks to
  the browser verifier.

- Browser verifier evaluates forbidden combinations and sequence policies
  end to end (`evaluateSequencePolicy`: journal entries, pattern sets,
  optional windows and triggers, fail-closed verdicts) and re-verifies
  `kinegrant:SequenceCheckReport` artifacts (`verifySequenceCheckReport`:
  request/journal digests bound, verdict re-derived locally); the HTML page
  and Node CLI (`sequence` / `sequence-eval` commands) expose it,
  cross-tested against the Python `SequencePolicy`.

## 2.20.0 бк 2026-08-15

- Milestone release: reference implementation version 2.20.0 on the
  stable 1.0 wire format, adding delegation chain verification to the
  browser verifier.

- Browser verifier verifies scoped delegation chains end to end
  (`verifyDelegationChain` + `verifyAttenuation`: envelope signatures,
  scoped structure, per-hop narrowing, delegation depth/allowlist bounds,
  and terminal request binding; fail-closed on any violation); the HTML page
  and Node CLI (`delegation` command) expose it, cross-tested against Python
  `CapabilityIssuer.issue_scoped` / `issue_attenuated`.

## 2.19.0 бк 2026-08-15

- Milestone release: reference implementation version 2.19.0 on the
  stable 1.0 wire format, adding policy analysis report verification to
  the browser verifier.

- Browser verifier re-verifies `kinegrant:PolicyBundleAnalysis` reports
  against the signed bundle (`verifyPolicyAnalysisReport`: type/schema,
  bundle binding, summary consistency, and findings recomputed locally and
  compared exactly; fail-closed on any mismatch); the HTML page and Node CLI
  (`analysis` command) expose it, cross-tested against the Python
  `analyze_policy_bundle`.

## 2.18.0 бк 2026-08-15

- Milestone release: reference implementation version 2.18.0 on the
  stable 1.0 wire format, adding identity syntax validation to the
  browser verifier.

- Browser verifier validates canonical KineGrant identifier syntax
  (`validateIdentitySyntax`: `urn:kinegrant:<agent|target|policy>:<namespace>:<local-id>`,
  fail-closed on malformed identifiers); the HTML page and Node CLI
  (`identities` command) expose it, cross-tested against the Python
  `kinegrant.identity` builders.

## 2.17.0 бк 2026-08-15

- Milestone release: reference implementation version 2.17.0 on the
  stable 1.0 wire format, adding obligation vocabulary validation to the
  browser verifier.

- Browser verifier validates the known obligation vocabulary (`validateObligationVocabulary`: emitActionReceipt, logAuditEvent, preserveEvidence; fail-closed on unknown obligations); the HTML page and Node CLI (`obligations` command) expose it, cross-tested against the Python `KNOWN_OBLIGATIONS`.

## 2.16.0 бк 2026-08-15

- Milestone release: reference implementation version 2.16.0 on the
  stable 1.0 wire format, adding action vocabulary validation to the
  browser verifier.

- Browser verifier validates the `kg.action.*` action vocabulary (`validateActionVocabulary`: canonical terms, fail-closed on unknown actions); the HTML page and Node CLI (`vocabulary` command) expose it, cross-tested against the Python `ACTION_TERMS`.

## 2.15.0 бк 2026-08-15

- Milestone release: reference implementation version 2.15.0 on the
  stable 1.0 wire format, adding ODRL mapping of verified policy bundles
  to the browser verifier.

- Browser verifier maps verified policy bundles to ODRL (`policyBundleToOdrl`: kgp-v0.2 profile, permissions/prohibitions, constraints, duties); the HTML page and Node CLI (`bundle-odrl` command) expose it, cross-tested against the Python `bundle_to_odrl` output.

## 2.14.0 бк 2026-08-15

- Milestone release: reference implementation version 2.14.0 on the
  stable 1.0 wire format, adding revocation distribution report
  validation to the browser verifier.

- Browser verifier validates revocation distribution reports (`verifyRevocationDistributionReport`: type/schema, acknowledgement structure, summary consistency, optional revocation-bundle binding); the HTML page and Node CLI (`revocation-distribution` command) expose it, cross-tested against a Python-generated fleet report.

## 2.13.0 бк 2026-08-15

- Milestone release: reference implementation version 2.13.0 on the
  stable 1.0 wire format, adding reproduction report validation to the
  browser verifier.

- Browser verifier validates external reproduction reports (`verifyReproductionReport`: report id, protocol, source, environment, materials, artifacts, verification consistency, overall-result consistency); the HTML page and Node CLI (`reproduction-report` command) expose it, cross-tested against a Python-generated report.

## 2.12.0 бк 2026-08-15

- Milestone release: reference implementation version 2.12.0 on the
  stable 1.0 wire format, adding audit CSV validation to the browser
  verifier.

- Browser verifier validates audit CSV exports (`verifyAuditCsv`: expected header columns, per-row column consistency, non-empty receipt/capability ids); the HTML page and Node CLI (`audit-csv` command) expose it, cross-tested against a Python-exported CSV.

## 2.11.0 бк 2026-08-15

- Milestone release: reference implementation version 2.11.0 on the
  stable 1.0 wire format, adding receipt evidence packet verification to
  the browser verifier.

- Browser verifier validates self-verifying receipt evidence packets (`verifyReceiptEvidencePacket`: packet digest integrity, receipt structure, unique capability ids, content-addressed receipt ids); the HTML page and Node CLI (`evidence-packet` command) expose it, cross-tested against a Python-exported packet.

## 2.10.0 бк 2026-08-15

- Milestone release: reference implementation version 2.10.0 on the
  stable 1.0 wire format, adding Machine Permission Test v0.5 with fleet
  policy distribution and policy bundle analysis cases (22/22).

- Machine Permission Test v0.5: 22 reproducible cases (new MPT-021 fleet policy distribution with upgrades and no downgrades, MPT-022 policy bundle analysis detecting conflicts with clean coverage); evidence schema bumped to 0.5 (minItems 22), independent verifier requires MPT-001..022.

## 2.9.0 бк 2026-08-15

- Milestone release: reference implementation version 2.9.0 on the stable
  1.0 wire format, adding revocation-bundle and policy-distribution
  report verification to the browser verifier.

- Browser verifier now validates revocation bundles (`verifyRevocationBundle`: signature, authority, version, digest, revocation entries, content-addressed id) and policy distribution reports (`verifyPolicyDistributionReport`: policy/bundle/version binding, acknowledgement structure, summary consistency); HTML page and Node CLI (`revocation`, `distribution-report` commands) expose them, cross-tested against Python-generated bundles and reports.

## 2.8.0 бк 2026-08-15

- Milestone release: reference implementation version 2.8.0 on the stable
  1.0 wire format, adding MPT evidence validation to the browser
  verifier.

- Browser verifier now validates Machine Permission Test evidence (schema 0.4, required cases MPT-001..020, summary and overall-result consistency) via `verifyMptEvidence`; the HTML page and Node CLI (`mpt` command) expose it, cross-tested against a Python-generated 20/20 evidence file.

## 2.7.0 бк 2026-08-15

- Milestone release: reference implementation version 2.7.0 on the stable
  1.0 wire format, extending the browser verifier to capabilities and
  receipt chains.

- Extended the browser verifier to capabilities (v0.1/v0.2/1.0) and receipt chains (v0.1/1.0) alongside policy bundles; the standalone HTML page and the Node CLI (`capability`, `receipts` commands) expose all three verifications, cross-tested against Python-generated objects.

## 2.6.0 бк 2026-08-15

- Milestone release: reference implementation version 2.6.0 on the stable
  1.0 wire format, adding the standalone offline browser policy-bundle
  verifier.

- Added a standalone offline browser policy-bundle verifier (`verify/policy-bundle-verifier.js` + hostable HTML page + Node CLI): zero-dependency RFC 8785 JCS subset, WebCrypto Ed25519 and SHA-256, signature/authority/policy-id/time-window/rules-digest checks, and current-version selection with revocation, all in the browser.

## 2.5.0 бк 2026-08-15

- Milestone release: reference implementation version 2.5.0 on the stable
  1.0 wire format, adding fleet policy audit aggregation.

- Added `audit_policy_bundles`: aggregates verification, static analysis, and bounded coverage across many labeled policy bundles into a machine-readable `kinegrant:PolicyAuditSummary` (verified/failed counts, analysis and coverage failures, findings-by-code, aggregate allowed/denied/exception/shadowed totals); unverifiable bundles are recorded as failed instead of aborting the run.
- `kinegrant-policy-bundle --audit-summary` exits 1 unless every bundle verifies and has no error findings or coverage exceptions.

## 2.4.0 бк 2026-08-15

- Milestone release: reference implementation version 2.4.0 on the stable
  1.0 wire format, adding the executable policy-bundle lifecycle example.

- Added an executable policy-bundle lifecycle example (`examples/policy-bundle`): publish -> enforce -> ODRL round trip -> fleet distribution -> upgrade (no downgrade) -> static analysis -> bounded coverage -> revocation rollback -> fail-closed, with a machine-readable `kinegrant:PolicyBundleLifecycleDemo` trace and a single `passed` verdict.

## 2.3.0 бк 2026-08-15

- Milestone release: reference implementation version 2.3.0 on the stable
  1.0 wire format, adding policy bundle static analysis, bounded
  request-space coverage checks, and the KGP-RFC-0003 schema stability
  draft.

- Added `analyze_policy_bundle`: verifies a signed policy bundle (fail-closed) and emits a machine-readable `kinegrant:PolicyBundleAnalysis` with conservative findings (conflicting allow/deny overlaps, duplicate rules, unknown constraints/obligations, rule issuers differing from the bundle signer, unconditional broad allows).
- `kinegrant-policy-bundle --analyze` exits 1 on error-level findings for CI fail-closed use.
- Added `policy_bundle_coverage`: bounded request-space evaluation of a verified bundle (allowed/denied/exceptions, per-rule applicability, shadowed allows); `kinegrant-policy-bundle --coverage` exits 1 when exceptions or shadowed allows exist.
- Added KGP-RFC-0003 draft (policy bundle schema stability).

## 2.2.0 бк 2026-08-15

- Milestone release: reference implementation version 2.2.0 on the stable
  1.0 wire format, adding ODRL mapping for signed policy bundles and the
  stability policy (docs/STABILITY.md).

- Added `bundle_to_odrl`: verifies a signed policy bundle (signature, authority, time window, rules digest) and serializes its rules into an ODRL document using the versioned `kgp-v0.2` profile, so `odrl_to_rules` round-trips the policy faithfully.
- Added `docs/STABILITY.md` (stability levels, deprecation process, security support) and updated COMPATIBILITY.md and GOVERNANCE.md with the policy-bundle compatibility and stability policy.

## 2.1.0 бк 2026-08-15

- Milestone release: reference implementation version 2.1.0 on the stable
  1.0 wire format, adding fleet policy distribution with per-registry
  acknowledgements (conformance 23/23) and MPT policy-trust evidence with
  independent JavaScript/Go cross-verification.

- Added fleet policy distribution (`PolicyDistributor`): one verified signed policy bundle is applied to many registries idempotently (never auto-downgrading) with per-registry acknowledgements in a machine-readable `kinegrant:PolicyDistributionReport`; `verify_policy_distribution_report` re-validates a fleet report against its bundle (policy/bundle/version binding, count integrity, fail-closed); `kinegrant-policy-bundle --distribute` and `--verify-report` are the deployable CLI paths.
- Conformance suite is now 23/23 with the new L3 `policy_fleet_distribution` mark (fleet applied, upgrades applied, no auto-downgrade).
- The MPT policy-trust cases (MPT-018/019/020) now record independent
  JavaScript/Go cross-verification evidence (PASS/FAIL/SKIP) alongside the
  Python checks, so challenge evidence shows cross-implementation agreement
  when the toolchains are available.

## 2.0.0 бк 2026-08-15

- Milestone release: reference implementation version 2.0.0 on the stable
  1.0 wire format, completing the policy trust lifecycle: signed policy
  bundles with versioning and revocation, JavaScript/Go cross-implementation
  verification, Machine Permission Test v0.4 (20 cases), and conformance 22/22.

- Added signed, versioned policy bundles (`kinegrant.policy_bundle`):
  `PolicyAuthority` publishes policy documents with a monotonic version, a
  validity window, and a link to the previous version's digest;
  `PolicyRegistry` activates bundles under the caller's trusted authorities,
  answers "current version" with highest-version-wins among non-revoked
  in-window bundles, and rolls back on per-version revocation;
  `verify_policy_bundle` / `rules_from_bundle` enforce signature, authority,
  policy-id, time-window, and rules-digest checks before the policy engine
  consumes the rules; `kinegrant-policy-bundle` is the deployable CLI.
- Conformance suite is now 22/22 with the new L3 `policy_bundle_trust` mark
  (signed versions verified, revoked version rolled back, tampering rejected).
- Independent JavaScript and Go verifiers now check policy bundles and
  current-version selection: the conformance report cross-verifies a
  Python-signed v2 bundle plus current-version rollback with both
  implementations (missing toolchains are recorded as skipped).
- Machine Permission Test v0.4 with 20 reproducible cases: three new policy
  trust cases (MPT-018 signed bundle accepted and enforced, MPT-019
  tampering/wrong-authority/wrong-policy rejected, MPT-020 version rollback
  and fail-closed with no current version); evidence schema bumped to 0.4
  with `minItems` 20.

## 1.9.0 — 2026-08-15

- Milestone release: reference implementation version 1.9.0 on the stable
  1.0 wire format, shipping the checksummed security review kit packet as a
  release asset with offline verification support.

## 1.8.0 — 2026-08-15

- The security review kit generator now supports `--packet-dir` (checksummed
  kit packet with reproduce commands) and `--verify-packet` (offline
  re-validation), so the kit can be shipped as a release asset.
- Milestone release: reference implementation version 1.8.0 on the stable
  1.0 wire format, adding the security review kit generator
  (`scripts/security_review_kit.py`) for third-party audits.

## 1.7.0 — 2026-08-15

- Added the security review kit generator (`scripts/security_review_kit.py`):
  it runs the conformance, MPT, red-team, benchmark, and unit-test suites,
  records reproduce commands and artifacts, and emits a checklist backed by
  those results; CI-smoked and covered by tests.
- Milestone release: reference implementation version 1.7.0 on the stable
  1.0 wire format, adding independent JavaScript/Go cross-verification to
  the conformance report.

## 1.6.0 — 2026-08-15

- The conformance report now includes `independent_verification`: the
  independent JavaScript and Go verifiers cross-check Python-generated
  capabilities and receipt chains (tools that are unavailable are recorded
  as skipped).
- Milestone release: reference implementation version 1.6.0 on the stable
  1.0 wire format, adding the Gatekeeper boundary model check
  (`check_gatekeeper_boundary`) and the `gatekeeper_boundary_modelcheck`
  conformance mark (L1-L4 at 21/21).

## 1.5.0 — 2026-08-15

- The conformance suite now includes a `gatekeeper_boundary_modelcheck` mark
  (L2: bounded composition-invariant verification of the one-call boundary)
  — L1-L4 is now 21 marks.
- Added the Gatekeeper boundary model check (`kinegrant.gatekeeper_modelcheck.
  check_gatekeeper_boundary`): bounded enumeration over allow/deny/actuator-
  failure scenarios verifying composition invariants (actuator after the
  boundary, receipts after gate consumption, journal only on compliant
  success, no replay double-execution, denials carry stages).
- Milestone release: reference implementation version 1.5.0 on the stable
  1.0 wire format, with the Machine Permission Test upgraded to v0.3 (17/17,
  receipt-1.0 obligations, compliance evasion, fleet revocation
  distribution) and the v0.1 issuer obligation fix.

## 1.4.0 — 2026-08-15

- Machine Permission Test upgraded to **v0.3 (17/17)**: three new reproducible
  cases — MPT-015 receipt 1.0 obligation satisfaction, MPT-016 obligation
  compliance detects suppressed commitments, MPT-017 fleet revocation
  distribution; the evidence schema and independent verifier now require 17
  cases.
- Milestone release: reference implementation version 1.4.0 on the stable
  1.0 wire format, adding cached policy evaluation across every runnable demo
  and deployment trace, and fleet revocation distribution status integrated
  into the audit CLI.

## 1.3.0 — 2026-08-15

- `kinegrant-audit` now accepts `--distribution-report`,
  `--revocation-bundle`, and `--revocation-authorities` to verify and include
  a fleet revocation distribution status in the audit report; unverifiable
  reports exit non-zero.
- All runnable demos (`kinegrant-robot-demo`, `kinegrant-bridge-demo`,
  `kinegrant-ros2-demo`) and both deployment traces (home-robot,
  camera-consent) now evaluate policy through `CachedPolicyEngine`.
- Milestone release: reference implementation version 1.3.0 on the stable
  1.0 wire format, adding the bounded policy-decision cache
  (`CachedPolicyEngine`), verifiable fleet revocation distribution reports
  (`verify_distribution_report`), and their benchmark metrics.

## 1.2.0 — 2026-08-15

- Added `verify_distribution_report`: re-validates a fleet revocation
  distribution report against its bundle (id/version binding, summary vs
  per-gate acknowledgement integrity, trusted authorities) and rejects any
  inconsistency fail-closed.
- Added the bounded policy-decision cache (`kinegrant.cache.
  CachedPolicyEngine`): LRU decisions keyed by policy+request digest, hit/miss
  statistics, automatic invalidation on policy change, and future requests
  never cached; the micro-benchmarks gained a `cached_policy_evaluate`
  metric.
- Milestone release: reference implementation version 1.2.0 on the stable
  1.0 wire format, adding fleet revocation distribution
  (`RevocationDistributor` + `kinegrant-revoke-distribute`), audit CSV and
  self-verifying evidence-packet export (`kinegrant-audit --csv/--packet`),
  and the `revocation_distribution` conformance mark (L1-L4 at 20/20).

## 1.1.0 — 2026-08-15

- The conformance suite now includes a `revocation_distribution` mark (L3:
  verified signed bundle applied to two gates) — L1-L4 is 20/20 — and the
  micro-benchmarks gained a `revocation_distribute` metric.
- Receipt auditing now exports CSV (`ReceiptAuditor.export_csv`) and
  self-verifying evidence packets (`export_packet` with a content-addressed
  digest); `kinegrant-audit` gained `--csv FILE` and `--packet FILE`.
- Added fleet revocation distribution (`kinegrant.distribution.
  RevocationDistributor`) and the `kinegrant-revoke-distribute` CLI: one
  verified signed revocation bundle is applied idempotently to many gates,
  with per-gate acknowledgements and a machine-readable fleet report.
- Milestone release: reference implementation version 1.1.0 on the stable
  1.0 wire format, with additive receipt 1.0, three known obligations
  (`emitActionReceipt`, `logAuditEvent`, `preserveEvidence`), fail-closed
  obligation compliance, the Gatekeeper one-call boundary (including a
  revocation stage), receipt auditing (`kinegrant-audit`), conformance
  19/19, the cross-system ROS 2 + MCP demo, ODRL forbidden-combination
  mapping, the Chinese README, and the security support policy.

## 1.0.1 — 2026-08-15

- Added the third known obligation `preserveEvidence` (evidence-preservation
  commitment) across Python, JavaScript, Go, the capability/decision/
  receipt-1.0 schemas, the ODRL kgp-v0.2 duty mapping, and obligation
  compliance; like `logAuditEvent`, it requires an explicit receipt 1.0
  commitment.
- `Gatekeeper` now accepts a `revocation_list` and rejects revoked
  capabilities at a dedicated `revocation` stage before the gate; the
  conformance `gatekeeper_boundary` mark covers revocation denial, and the
  micro-benchmarks gained an `audit_summary` metric (10-receipt chain).
- Added the receipt audit interface (`kinegrant.audit.ReceiptAuditor`) and
  `kinegrant-audit` CLI: verified-chain queries by capability/agent/target/
  action/purpose/result/time, machine-readable summaries, and obligation
  compliance checks, all fail-closed; `--self-test` is CI-smoked.
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
