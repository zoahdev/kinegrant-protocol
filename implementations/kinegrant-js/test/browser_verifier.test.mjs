import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import {
  canonicalJson,
  currentPolicyVersion,
  verifyCapability,
  verifyAuditCsv,
  verifyMptEvidence,
  verifyPolicyDistributionReport,
  verifyPolicyBundle,
  verifyReceiptChain,
  verifyReceiptEvidencePacket,
  verifyReproductionReport,
  verifyRevocationBundle,
  verifyRevocationDistributionReport,
  policyBundleToOdrl,
  validateActionVocabulary,
  validateObligationVocabulary,
  validateIdentitySyntax,
  verifyPolicyAnalysisReport,
  verifyDelegationChain,
  verifyMldsaEnvelope,
  evaluateSequencePolicy,
  verifySequenceCheckReport,
  verifyConformanceReport,
  verifyPolicyAuditSummary,
  verifySecurityReviewKit,
  verifyEsp32c3Evidence,
  verifyFleetOperationsReport,
  verifyBenchmarkReport,
  verifyPolicyLifecycleTrace,
  verifySensorCommitment,
  sensorEvidenceHash,
  verifyReceiptCheckpoint,
  verifyDeviceAttestation,
  verifyBridgeDemoReport,
  verifyHardwareTrustPacket,
  verifyDeviceToPolicyExport,
  verifyFleetDeviceExport,
  verifyEndToEndAuditExport,
  verifyRevocationReissueClosure,
  verifyUnifiedAuditExport,
  verifyPolicyMigrationAudit,
  verifyComplianceTimeline,
  verifyObligationFulfillment,
  verifySelectiveDisclosure,
  verifyIdentifierRotation,
  verifyMinimalDisclosure,
  verifyLeastPrivilegeAudit,
  verifyDenialExplainability,
  verifyPolicyDiffAudit,
  verifyRobotDemoReport,
  verifyCameraConsentTrace,
  verifyFullLifecycleReport,
  verifyEvidenceExportPacket,
} from "../../../verify/policy-bundle-verifier.js";

const MLDSA65_SPKI_HEADER_B64 = "MIIHsjALBglghkgBZQMEAxIDggehAA==";
const MLDSA_FIXTURE_PATH = new URL(
  "./fixtures/mldsa65-policy-bundle.json",
  import.meta.url
);
const ESP32_CASE_PROFILE = {
  "HWP-001": [20, 0, 0, 20],
  "HWP-002": [20, 20, 20, 0],
  "HWP-003": [20, 0, 0, 20],
  "HWP-004": [3, 0, 0, 3],
  "HWP-005": [1, 0, 0, 1],
  "HWP-006": [2, 0, 0, 2],
  "HWP-007": [64, 1, 1, 63],
  "HWP-008": [1, 0, 0, 1],
  "HWP-009": [2, 0, 0, 2],
  "HWP-010": [4, 0, 0, 0],
  "HWP-011": [100, 100, 100, 0],
};

function buildEsp32Cases(passed, useProfileAttempts) {
  return Object.entries(ESP32_CASE_PROFILE).map(
    ([id, [attempts, calls, movements, denials]]) => ({
      id,
      name: "case " + id,
      attempts: useProfileAttempts ? attempts : 0,
      passed,
      measurements: {
        actuator_calls: useProfileAttempts ? calls : 0,
        observed_movements: useProfileAttempts ? movements : 0,
        denials: useProfileAttempts ? denials : 0,
        abnormal_resets: 0,
        overheat_events: 0,
      },
      artifact_digests: [],
      notes: passed ? "ok" : "NOT RUN",
    })
  );
}

function b64urlDecode(value) {
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function mldsa65Supported() {
  try {
    const fixture = JSON.parse(readFileSync(MLDSA_FIXTURE_PATH, "utf8"));
    const rawKey = b64urlDecode(fixture.kid.slice("kinegrant:key:mldsa65:".length));
    const header = atob(MLDSA65_SPKI_HEADER_B64);
    const spki = new Uint8Array(header.length + rawKey.length);
    for (let index = 0; index < header.length; index += 1) {
      spki[index] = header.charCodeAt(index);
    }
    spki.set(rawKey, header.length);
    await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "ML-DSA-65" },
      false,
      ["verify"]
    );
    return true;
  } catch {
    return false;
  }
}

const DOMAIN = Buffer.from("KINEGRANT-SIGNED-ENVELOPE-V1\u0000", "utf8");

function b64url(data) {
  return data.toString("base64url");
}

function kidOf(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  const raw = der.subarray(der.length - 32);
  return "kinegrant:key:ed25519:" + b64url(raw);
}

function signEnvelope(privateKey, payload) {
  const kid = kidOf(createPublicKey(privateKey));
  const protectedData = { alg: "EdDSA", kid, payload };
  const data = Buffer.concat([
    DOMAIN,
    Buffer.from(canonicalJson(protectedData), "utf8"),
  ]);
  const signature = sign(null, data, privateKey);
  return { alg: "EdDSA", kid, payload, signature: b64url(signature) };
}

function buildBundle(
  privateKey,
  publicKey,
  {
    version = 1,
    purposes = ["delivery"],
    constraints = {},
    obligations = [],
    extraRules = [],
    previousVersionDigest = null,
  } = {}
) {
  const now = Date.now();
  const kid = kidOf(publicKey);
  const policyId = "urn:policy:browser";
  const body = {
    type: "kinegrant:PolicyBundle",
    schema_version: "0.1",
    policy_id: policyId,
    issuer: kid,
    version,
    previous_version_digest: previousVersionDigest,
    issued_at: new Date(now).toISOString(),
    not_before: new Date(now).toISOString(),
    not_after: new Date(now + 3600 * 1000).toISOString(),
    rules: [
      {
        policy_id: policyId,
        issuer: kid,
        target: "urn:space:door-1",
        effect: "allow",
        actions: ["open"],
        subjects: ["*"],
        purposes,
        constraints,
        obligations,
        priority: 0,
        source: {},
      },
      ...extraRules,
    ],
  };
  body.policy_digest =
    "sha256:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson({ rules: body.rules }), "utf8"))
      .digest("hex");
  body.bundle_id =
    "kinegrant:policy-bundle:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(body), "utf8"))
      .digest("hex");
  return signEnvelope(privateKey, body);
}

function buildCapability(privateKey, publicKey, request) {
  const now = Date.now();
  const issuedAt = new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z");
  const expiresAt = new Date(now + 300 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const kid = kidOf(publicKey);
  const body = {
    type: "kinegrant:PhysicalActionCapability",
    version: "0.1",
    issuer: kid,
    agent: request.agent,
    target: request.target,
    action: request.action,
    purpose: request.purpose,
    request_digest:
      "sha256:" +
      createHash("sha256")
        .update(Buffer.from(canonicalJson(request), "utf8"))
        .digest("hex"),
    policy_digest: "sha256:" + "0".repeat(64),
    matched_policy_ids: ["policy-1"],
    obligations: ["emitActionReceipt"],
    issued_at: issuedAt,
    not_before: issuedAt,
    expires_at: expiresAt,
    nonce: "n".repeat(32),
  };
  const unsigned = { ...body };
  body.capability_id =
    "kinegrant:cap:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  return signEnvelope(privateKey, body);
}

function buildScopedCapability(privateKey, publicKey, request, options = {}) {
  const now = Date.now();
  const issuedAt = new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z");
  const expiresAt = new Date(
    now + (options.ttl ?? 120) * 1000
  ).toISOString().replace(/\.\d{3}Z$/, "Z");
  const body = {
    type: "kinegrant:PhysicalActionCapability",
    version: options.version ?? "1.0",
    issuer: kidOf(publicKey),
    agent: options.agent ?? (options.parent ? options.parent.payload.agent : request.agent),
    target: options.target ?? request.target,
    actions: options.actions ?? ["open"],
    purposes: options.purposes ?? ["delivery"],
    request_digest:
      "sha256:" +
      createHash("sha256")
        .update(Buffer.from(canonicalJson(request), "utf8"))
        .digest("hex"),
    policy_digest: options.policyDigest ?? "sha256:" + "0".repeat(64),
    matched_policy_ids: options.matchedPolicyIds ?? ["policy-1"],
    obligations: options.obligations ?? ["emitActionReceipt"],
    issued_at: issuedAt,
    not_before: issuedAt,
    expires_at: expiresAt,
    nonce: options.nonce ?? "n".repeat(32),
    parent_capability_id: options.parent
      ? options.parent.payload.capability_id
      : null,
    constraints: options.constraints ?? {},
    approval_tier: options.approvalTier ?? 0,
    delegation_allowed: options.delegationAllowed ?? false,
    max_delegation_depth: options.maxDepth ?? 0,
    delegate_agent: options.delegate ?? null,
    delegation_depth: options.depth ?? 0,
    delegate_allowlist: options.allowlist ?? null,
  };
  const unsigned = { ...body };
  delete unsigned.capability_id;
  delete unsigned.root_capability_id;
  body.capability_id =
    "kinegrant:cap:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  body.root_capability_id = options.rootCapabilityId ?? body.capability_id;
  return signEnvelope(privateKey, body);
}

function buildSensorCommitment(
  privateKey,
  publicKey,
  { signed = true, sourceId = "sensor-1" } = {}
) {
  const readings = [
    {
      kind: "force",
      value_hash: "sha256:" + "a".repeat(64),
      source_id: sourceId,
      confidence: 0.9,
      observed_at: "2026-08-15T00:00:00Z",
    },
  ];
  const body = {
    type: "kinegrant:SensorEvidenceCommitment",
    schema_version: "0.1",
    readings,
    readings_digest:
      "sha256:" +
      createHash("sha256")
        .update(Buffer.from(canonicalJson({ readings }), "utf8"))
        .digest("hex"),
    sensor: signed ? kidOf(publicKey) : null,
    committed_at: "2026-08-15T00:00:00Z",
  };
  const unsigned = { ...body };
  body.commitment_id =
    "kinegrant:sensor-evidence:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  return signed ? signEnvelope(privateKey, body) : body;
}

function buildCheckpoint(
  privateKey,
  publicKey,
  { chainDigest = "sha256:" + "b".repeat(64) } = {}
) {
  const body = {
    type: "kinegrant:ReceiptCheckpoint",
    schema_version: "0.1",
    notary: kidOf(publicKey),
    chain_digest: chainDigest,
    period: "daily",
    issued_at: "2026-08-15T00:00:00Z",
  };
  const unsigned = { ...body };
  body.checkpoint_id =
    "kinegrant:receipt-checkpoint:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  return signEnvelope(privateKey, body);
}

function buildAttestation(
  privateKey,
  publicKey,
  { deviceId = "device:esp32c3:paper-barrier:unit-1" } = {}
) {
  const body = {
    type: "kinegrant:DeviceAttestation",
    schema_version: "0.1",
    device_id: deviceId,
    firmware_digest: "sha256:" + "c".repeat(64),
    boot_counter: 3,
    measured_boot: [
      { stage: "bootloader", digest: "sha256:" + "d".repeat(64) },
    ],
    device: kidOf(publicKey),
    issued_at: "2026-08-15T00:00:00Z",
  };
  const unsigned = { ...body };
  body.attestation_id =
    "kinegrant:device-attestation:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  return signEnvelope(privateKey, body);
}

function buildBridgeOutcomes(includePurpose = true) {
  const specs = [
    {
      scenario: "allow-open",
      stack: "ros2",
      action: "open",
      allowed: true,
      expected: "ALLOW",
      obligation: true,
    },
    {
      scenario: "deny-replay",
      stack: "ros2",
      action: "open",
      allowed: false,
      expected: "DENY",
      obligation: null,
    },
  ];
  return specs.map((spec) => {
    const outcome = {
      scenario: spec.scenario,
      stack: spec.stack,
      action: spec.action,
      allowed: spec.allowed,
      reason: spec.allowed ? "allow" : "denied",
      expected: spec.expected,
      obligation_compliant: spec.obligation,
      passed: spec.allowed === (spec.expected === "ALLOW"),
    };
    if (includePurpose) outcome.purpose = "delivery";
    return outcome;
  });
}

function buildRobotOutcomes() {
  const specs = [
    {
      scenario: "allow-open",
      stack: "ros2",
      action: "open",
      allowed: true,
      expected: "ALLOW",
      obligation: true,
      actuatorCalls: 1,
    },
    {
      scenario: "deny-violation",
      stack: "matter",
      action: "open",
      allowed: false,
      expected: "DENY",
      obligation: null,
      actuatorCalls: 0,
    },
  ];
  return specs.map((spec) => ({
    scenario: spec.scenario,
    stack: spec.stack,
    action: spec.action,
    allowed: spec.allowed,
    reason: spec.allowed ? "allow" : "denied",
    actuator_calls: spec.actuatorCalls,
    expected: spec.expected,
    obligation_compliant: spec.obligation,
    passed: spec.allowed === (spec.expected === "ALLOW"),
  }));
}

function buildReceipt(
  privateKey,
  publicKey,
  {
    capabilityId,
    previous = null,
    evidenceHash = null,
    requestDigest = "sha256:" + "0".repeat(64),
    target = "door-7",
    version = "0.1",
    obligationResults = null,
  } = {}
) {
  const kid = kidOf(publicKey);
  const body = {
    type: "kinegrant:PhysicalActionReceipt",
    version,
    executor: kid,
    capability_id: capabilityId || "kinegrant:cap:" + "a".repeat(64),
    request_digest: requestDigest,
    agent: "robot-1",
    target,
    action: "open",
    purpose: "delivery",
    result: "succeeded",
    started_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    evidence_hash: evidenceHash,
    previous_receipt_hash:
      previous === null
        ? null
        : "sha256:" +
          createHash("sha256")
            .update(Buffer.from(canonicalJson(previous), "utf8"))
            .digest("hex"),
  };
  if (obligationResults !== null) {
    body.obligation_results = obligationResults;
  }
  const unsigned = { ...body };
  body.receipt_id =
    "kinegrant:receipt:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  return signEnvelope(privateKey, body);
}

async function buildDeviceToPolicyPacket(
  authorityPrivateKey,
  authorityPublicKey,
  devicePrivateKey,
  devicePublicKey,
  { deviceId, requestId, bundle } = {}
) {
  const policyBundle = bundle || buildBundle(authorityPrivateKey, authorityPublicKey);
  const bundlePayload = policyBundle.payload;
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: requestId || "req-" + deviceId,
    agent: "robot-1",
    target: "urn:space:door-1",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const expectedPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: bundlePayload.rules,
            trusted_policy_issuers: [bundlePayload.issuer].sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const capability = buildScopedCapability(
    authorityPrivateKey,
    authorityPublicKey,
    request,
    {
      policyDigest: expectedPolicyDigest,
      matchedPolicyIds: [bundlePayload.policy_id],
    }
  );
  const commitment = buildSensorCommitment(
    devicePrivateKey,
    devicePublicKey,
    { signed: true, sourceId: deviceId }
  );
  const sensorHash = await sensorEvidenceHash(commitment);
  const receipt = buildReceipt(devicePrivateKey, devicePublicKey, {
    capabilityId: capability.payload.capability_id,
    requestDigest: capability.payload.request_digest,
    evidenceHash: sensorHash,
    target: request.target,
  });
  const chainDigest =
    "sha256:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson([receipt]), "utf8"))
      .digest("hex");
  const checkpoint = buildCheckpoint(devicePrivateKey, devicePublicKey, {
    chainDigest,
  });
  const attestation = buildAttestation(devicePrivateKey, devicePublicKey, {
    deviceId,
  });
  const packet = {
    type: "kinegrant:DeviceToPolicyExportPacket",
    schema_version: "0.1",
    device_id: deviceId,
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    trusted_policy_issuers: [bundlePayload.issuer],
    policy_bundle: policyBundle,
    capability,
    request,
    gate_decision: {
      allowed: true,
      reason: "allow",
      checked_at: "2026-08-15T00:30:00Z",
      capability_id: capability.payload.capability_id,
      policy_digest: capability.payload.policy_digest,
    },
    receipt,
    sensor_commitment: commitment,
    receipt_checkpoint: checkpoint,
    device_attestation: attestation,
    summary: {
      artifacts_total: 9,
      policy_verified: true,
      capability_verified: true,
      decision_consistent: true,
      receipt_bound: true,
      sensor_bound: true,
      checkpoint_bound: true,
      attestation_bound: true,
      cross_references_ok: true,
    },
  };
  return { packet, bundle: policyBundle };
}

function buildMptEvidence() {
  const cases = Array.from({ length: 22 }, (_, index) => ({
    id: `MPT-${String(index + 1).padStart(3, "0")}`,
    name: "case " + (index + 1),
    expected: "PASS",
    observed: "PASS",
    passed: true,
    evidence: {},
  }));
  return {
    schema_version: "0.5",
    run_id: "urn:kinegrant:mpt:run:" + "0".repeat(36),
    overall_result: "PASS",
    summary: { total: 22, passed: 22, failed: 0 },
    cases,
    limitations: [],
  };
}

function buildRevocationBundle(
  privateKey,
  publicKey,
  { capabilityId = "kinegrant:cap:" + "c".repeat(64) } = {}
) {
  const kid = kidOf(publicKey);
  const body = {
    type: "kinegrant:RevocationBundle",
    schema_version: "0.1",
    issuer: kid,
    version: 1,
    previous_bundle_digest: null,
    issued_at: new Date().toISOString(),
    revocations: [
      {
        capability_id: capabilityId,
        reason: null,
        at: new Date().toISOString(),
      },
    ],
  };
  const unsigned = { ...body };
  body.bundle_id =
    "kinegrant:revocation-bundle:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  return signEnvelope(privateKey, body);
}

function buildEvidencePacket(privateKey, publicKey) {
  const receipt = buildReceipt(privateKey, publicKey);
  const packet = {
    type: "kinegrant:ReceiptEvidencePacket",
    schema_version: "0.1",
    summary: { total: 1, matched: 1, obligation_compliant: 1 },
    receipts: [receipt.payload],
  };
  const unsigned = { ...packet };
  packet.packet_digest =
    "sha256:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  return packet;
}

function buildReproductionReport() {
  return {
    schema_version: "0.1",
    report_id: "urn:kinegrant:reproduction:" + "0".repeat(36),
    generated_at: new Date().toISOString(),
    protocol: "KGP-001 Experimental Open Draft 0.1",
    reference_implementation: "2.12.0",
    source: { commit: "a".repeat(40), working_tree_dirty: false },
    environment: {
      python_version: "3.12",
      python_implementation: "CPython",
      platform: "test",
    },
    materials: Array.from({ length: 7 }, (_, index) => ({
      path: "materials/file" + index + ".md",
      sha256: "sha256:" + String(index).repeat(64),
    })),
    artifacts: [
      {
        path: "machine-permission-test.evidence.json",
        media_type: "application/json",
        bytes: 10,
        sha256: "sha256:" + "a".repeat(64),
      },
      {
        path: "sample-receipt-v0.1.json",
        media_type: "application/json",
        bytes: 10,
        sha256: "sha256:" + "b".repeat(64),
      },
    ],
    verification: {
      verifier: "challenge/verify_reproduction.py",
      required_cases: 22,
      passed_cases: 22,
    },
    overall_result: "PASS",
    limitations: ["test"],
  };
}

function buildRevocationDistributionReport(bundle) {
  return {
    type: "kinegrant:RevocationDistributionReport",
    schema_version: "0.1",
    bundle_id: bundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { gates: 1, added_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        bundle_id: bundle.payload.bundle_id,
        applied: true,
        added_count: 1,
        already_present: 0,
        detail: "applied",
      },
    ],
  };
}

test("browser verifier canonicalizes JCS", () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJson({ x: "a\u2028b" }), '{"x":"a\\u2028b"}');
});

test("browser verifier accepts a valid policy bundle", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const payload = await verifyPolicyBundle(
    bundle,
    new Set([bundle.kid]),
    { expectedPolicyId: "urn:policy:browser" }
  );
  assert.equal(payload.version, 1);
});

test("browser verifier rejects tampering and wrong authority", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const { publicKey: otherPublicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  bundle.payload.rules[0].effect = "deny";
  await assert.rejects(() =>
    verifyPolicyBundle(bundle, new Set([bundle.kid]))
  );
  bundle.payload.rules[0].effect = "allow";
  await assert.rejects(() =>
    verifyPolicyBundle(bundle, new Set([kidOf(otherPublicKey)]))
  );
});

test("browser verifier selects current version and honors revocation", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const v1 = buildBundle(privateKey, publicKey, { version: 1 });
  const v2 = buildBundle(privateKey, publicKey, {
    version: 2,
    purposes: ["delivery", "maintenance"],
  });
  const payloads = [v1.payload, v2.payload];
  assert.equal(currentPolicyVersion(payloads).version, 2);
  assert.equal(
    currentPolicyVersion(payloads, { revoked: ["urn:policy:browser:2"] }).version,
    1
  );
  assert.equal(
    currentPolicyVersion(payloads, {
      revoked: ["urn:policy:browser:1", "urn:policy:browser:2"],
    }),
    null
  );
});

test("browser verifier accepts a valid capability and rejects tampering", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const request = {
    request_id: "req-1",
    agent: "robot-1",
    target: "door-7",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const envelope = buildCapability(privateKey, publicKey, request);
  const payload = await verifyCapability(
    envelope,
    request,
    new Set([envelope.kid])
  );
  assert.equal(payload.capability_id.startsWith("kinegrant:cap:"), true);
  envelope.payload.action = "record";
  await assert.rejects(() =>
    verifyCapability(envelope, request, new Set([envelope.kid]))
  );
});

test("browser verifier accepts a receipt chain and rejects inconsistency", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const first = buildReceipt(privateKey, publicKey, {
    capabilityId: "kinegrant:cap:" + "a".repeat(64),
  });
  const second = buildReceipt(privateKey, publicKey, {
    capabilityId: "kinegrant:cap:" + "b".repeat(64),
    previous: first,
  });
  await verifyReceiptChain([first, second], new Set([first.kid]));
  second.payload.previous_receipt_hash = null;
  await assert.rejects(() =>
    verifyReceiptChain([first, second], new Set([first.kid]))
  );
});

test("browser verifier validates MPT evidence and rejects tampering", () => {
  const evidence = buildMptEvidence();
  const result = verifyMptEvidence(evidence);
  assert.equal(result.overall_result, "PASS");
  assert.equal(result.summary.passed, 22);
  evidence.summary.passed = 21;
  assert.throws(() => verifyMptEvidence(evidence));
  const missing = buildMptEvidence();
  missing.cases.pop();
  assert.throws(() => verifyMptEvidence(missing));
});

test("browser verifier validates revocation bundles and rejects tampering", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildRevocationBundle(privateKey, publicKey);
  const payload = await verifyRevocationBundle(
    bundle,
    new Set([bundle.kid])
  );
  assert.equal(payload.version, 1);
  bundle.payload.revocations[0].capability_id = "kinegrant:cap:" + "d".repeat(64);
  await assert.rejects(() =>
    verifyRevocationBundle(bundle, new Set([bundle.kid]))
  );
});

test("browser verifier validates policy distribution reports", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const report = {
    type: "kinegrant:PolicyDistributionReport",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: bundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { registries: 1, applied_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        policy_id: "urn:policy:browser",
        bundle_id: bundle.payload.bundle_id,
        applied: true,
        current_before: null,
        current_after: 1,
        detail: "policy bundle activated",
      },
    ],
  };
  await verifyPolicyDistributionReport(
    report,
    bundle,
    new Set([bundle.kid])
  );
  report.acks[0].applied = false;
  await assert.rejects(() =>
    verifyPolicyDistributionReport(report, bundle, new Set([bundle.kid]))
  );
});

test("browser verifier validates receipt evidence packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const packet = buildEvidencePacket(privateKey, publicKey);
  const result = await verifyReceiptEvidencePacket(packet);
  assert.equal(result.receipts, 1);
  packet.receipts[0].capability_id = "kinegrant:cap:" + "e".repeat(64);
  await assert.rejects(() => verifyReceiptEvidencePacket(packet));
});

const AUDIT_CSV_HEADER =
  "receipt_id,capability_id,agent,target,action,purpose,result," +
  "started_at,finished_at,evidence_hash,previous_receipt_hash," +
  "failure_reason,obligation_results";

test("browser verifier validates audit CSV", () => {
  const csv =
    AUDIT_CSV_HEADER +
    "\n" +
    [
      "kinegrant:receipt:" + "a".repeat(64),
      "kinegrant:cap:" + "a".repeat(64),
      "robot-1",
      "door-7",
      "open",
      "delivery",
      "succeeded",
      new Date().toISOString(),
      new Date().toISOString(),
      "",
      "",
      "",
      "",
    ].join(",") +
    "\n";
  const result = verifyAuditCsv(csv);
  assert.equal(result.rows, 1);
  assert.throws(() => verifyAuditCsv("a,b,c\n1,2,3"));
  assert.throws(() => verifyAuditCsv(AUDIT_CSV_HEADER + "\nonly-one-field"));
});

test("browser verifier validates reproduction reports", () => {
  const report = buildReproductionReport();
  const result = verifyReproductionReport(report);
  assert.equal(result.passed_cases, 22);
  assert.equal(result.required_cases, 22);
  report.verification.passed_cases = 21;
  assert.throws(() => verifyReproductionReport(report));
});

test("browser verifier validates revocation distribution reports", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildRevocationBundle(privateKey, publicKey);
  const report = buildRevocationDistributionReport(bundle);
  const result = await verifyRevocationDistributionReport(
    report,
    bundle,
    new Set([bundle.kid])
  );
  assert.equal(result.gates, 1);
  assert.equal(result.added_total, 1);
  report.summary.added_total = 2;
  await assert.rejects(() =>
    verifyRevocationDistributionReport(report, bundle, new Set([bundle.kid]))
  );
  report.summary.added_total = 1;
  report.acks[0].bundle_id = "kinegrant:revocation-bundle:" + "0".repeat(64);
  await assert.rejects(() =>
    verifyRevocationDistributionReport(report, bundle, new Set([bundle.kid]))
  );
});

test("browser verifier maps policy bundles to ODRL", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey, {
    constraints: { max_force_newtons: 5 },
    obligations: ["emitActionReceipt"],
  });
  const document = await policyBundleToOdrl(bundle, new Set([bundle.kid]));
  assert.equal(document.uid, "urn:policy:browser");
  assert.equal(
    document.profile,
    "https://kinegrant.com/profiles/odrl/kgp-v0.2"
  );
  assert.equal(document.permission.length, 1);
  assert.equal(document.permission[0].duty[0].action, "emitActionReceipt");
  assert.equal(
    document.permission[0].constraint[0].leftOperand,
    "maxForceNewtons"
  );
  bundle.payload.rules[0].effect = "deny";
  await assert.rejects(() =>
    policyBundleToOdrl(bundle, new Set([bundle.kid]))
  );
});

test("browser verifier validates the action vocabulary", () => {
  const result = validateActionVocabulary(["kg.action.open", "kg.action.record"]);
  assert.equal(result.valid, true);
  assert.equal(result.actions, 2);
  assert.throws(() => validateActionVocabulary(["kg.action.explode"]));
  assert.throws(() => validateActionVocabulary([]));
});

test("browser verifier validates the obligation vocabulary", () => {
  const result = validateObligationVocabulary([
    "emitActionReceipt",
    "logAuditEvent",
    "preserveEvidence",
  ]);
  assert.equal(result.valid, true);
  assert.equal(result.obligations, 3);
  assert.throws(() => validateObligationVocabulary(["eraseMemory"]));
  assert.throws(() => validateObligationVocabulary([]));
});

test("browser verifier validates KineGrant identity syntax", () => {
  const result = validateIdentitySyntax([
    "urn:kinegrant:agent:zoah:delivery-robot-07",
    "urn:kinegrant:target:zoah:door-7",
    "urn:kinegrant:policy:zoah:delivery-door#permission-0",
  ]);
  assert.equal(result.valid, true);
  assert.equal(result.count, 3);
  assert.equal(result.identifiers[0].kind, "agent");
  assert.equal(result.identifiers[0].namespace, "zoah");
  assert.equal(result.identifiers[0].local_id, "delivery-robot-07");
  assert.throws(() => validateIdentitySyntax(["urn:kinegrant:agent:ZOAH:robot"]));
  assert.throws(() => validateIdentitySyntax(["urn:kinegrant:robot:zoah:r1"]));
  assert.throws(() => validateIdentitySyntax(["urn:kinegrant:agent:zoah:" + "x".repeat(129)]));
  assert.throws(() => validateIdentitySyntax([]));
});

test("browser verifier validates policy analysis reports", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const kid = kidOf(publicKey);
  const bundle = buildBundle(privateKey, publicKey, {
    extraRules: [
      {
        policy_id: "urn:policy:browser",
        issuer: kid,
        target: "urn:space:door-*",
        effect: "deny",
        actions: ["open"],
        subjects: ["*"],
        purposes: ["delivery"],
        constraints: {},
        obligations: [],
        priority: 0,
        source: {},
      },
    ],
  });
  const report = {
    type: "kinegrant:PolicyBundleAnalysis",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: bundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "FAIL",
    summary: { findings: 1, errors: 1, warnings: 0, info: 0 },
    findings: [
      {
        severity: "error",
        code: "conflicting_effect",
        rule_ids: ["urn:policy:browser", "urn:policy:browser"],
      },
    ],
  };
  const result = await verifyPolicyAnalysisReport(
    report,
    bundle,
    new Set([bundle.kid])
  );
  assert.equal(result.overall_result, "FAIL");
  assert.equal(result.findings.length, 1);
  report.summary.errors = 0;
  await assert.rejects(() =>
    verifyPolicyAnalysisReport(report, bundle, new Set([bundle.kid]))
  );
});

test("browser verifier validates delegation chains", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const principalRequest = {
    request_id: "req-principal",
    agent: "robot-1",
    target: "door-*",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const delegateRequest = {
    request_id: "req-delegate",
    agent: "delegate-1",
    target: "door-7",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const root = buildScopedCapability(privateKey, publicKey, principalRequest, {
    target: "door-*",
    actions: ["open", "close"],
    purposes: ["delivery"],
    delegationAllowed: true,
    maxDepth: 2,
    allowlist: ["delegate-*"],
  });
  const child = buildScopedCapability(privateKey, publicKey, delegateRequest, {
    parent: root,
    target: "door-7",
    actions: ["open"],
    purposes: ["delivery"],
    delegate: "delegate-1",
    depth: 1,
    rootCapabilityId: root.payload.capability_id,
    allowlist: ["delegate-*"],
  });
  const result = await verifyDelegationChain(
    [root, child],
    new Set([root.kid]),
    delegateRequest
  );
  assert.equal(result.depth, 1);
  assert.equal(result.terminal_capability_id, child.payload.capability_id);
  const badChild = buildScopedCapability(privateKey, publicKey, delegateRequest, {
    parent: root,
    target: "door-7",
    actions: ["open", "record"],
    purposes: ["delivery"],
    delegate: "delegate-1",
    depth: 1,
    rootCapabilityId: root.payload.capability_id,
    allowlist: ["delegate-*"],
  });
  await assert.rejects(() =>
    verifyDelegationChain([root, badChild], new Set([root.kid]), delegateRequest)
  );
});

test("browser verifier evaluates forbidden combinations and verifies reports", async () => {
  const now = new Date("2026-08-15T00:10:00Z").getTime();
  const policy = {
    combinations: [
      {
        combination_id: "forbid-camera",
        patterns: [
          ["record", "*"],
          ["train_on_data", "*"],
        ],
        trigger: ["train_on_data", "*"],
      },
    ],
  };
  const journal = [
    { action: "record", target: "cam-1", at: "2026-08-15T00:08:00Z" },
    { action: "train_on_data", target: "cam-1", at: "2026-08-15T00:09:00Z" },
  ];
  const deniedRequest = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-train",
    agent: "robot-1",
    target: "cam-1",
    action: "train_on_data",
    purpose: "training",
    issued_at: "2026-08-15T00:10:00Z",
    context: {},
  };
  const allowedRequest = {
    ...deniedRequest,
    request_id: "req-open",
    action: "open",
    purpose: "delivery",
  };
  const denied = evaluateSequencePolicy(policy, deniedRequest, journal, { now });
  assert.equal(denied.allowed, false);
  assert.equal(denied.reason, "forbidden_combination");
  assert.deepEqual(denied.matched_combination_ids, ["forbid-camera"]);
  const allowed = evaluateSequencePolicy(policy, allowedRequest, journal, { now });
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.reason, "sequence_allowed");
  const report = {
    type: "kinegrant:SequenceCheckReport",
    schema_version: "0.1",
    policy_id: "forbid-camera-policy",
    request_digest:
      "sha256:" +
      createHash("sha256")
        .update(Buffer.from(canonicalJson(deniedRequest), "utf8"))
        .digest("hex"),
    journal_digest:
      "sha256:" +
      createHash("sha256")
        .update(Buffer.from(canonicalJson(journal), "utf8"))
        .digest("hex"),
    checked_at: "2026-08-15T00:10:00Z",
    verdict: denied,
  };
  const result = await verifySequenceCheckReport(
    report,
    policy,
    deniedRequest,
    journal,
    { now }
  );
  assert.equal(result.allowed, false);
  report.verdict = { ...denied, allowed: true };
  await assert.rejects(() =>
    verifySequenceCheckReport(report, policy, deniedRequest, journal, { now })
  );
});

test("browser verifier accepts ML-DSA-65 signed policy bundles", async (t) => {
  if (!(await mldsa65Supported())) {
    return t.skip("ML-DSA-65 WebCrypto is not available");
  }
  const fixture = JSON.parse(readFileSync(MLDSA_FIXTURE_PATH, "utf8"));
  const payload = await verifyPolicyBundle(
    fixture,
    new Set([fixture.kid]),
    { expectedPolicyId: "urn:kinegrant:policy:mldsa:1" }
  );
  assert.equal(payload.version, 1);
  const direct = await verifyMldsaEnvelope(fixture);
  assert.equal(direct.type, "kinegrant:PolicyBundle");
  const tampered = JSON.parse(JSON.stringify(fixture));
  tampered.payload.rules = [];
  await assert.rejects(() =>
    verifyPolicyBundle(tampered, new Set([fixture.kid]))
  );
});

test("browser verifier validates conformance reports", () => {
  const report = {
    type: "kinegrant:ConformanceReport",
    schema_version: "0.1",
    overall_result: "PASS",
    summary: { total: 2, passed: 2, failed: 0 },
    marks: [
      { name: "default_deny", level: "L1", passed: true, detail: "default_deny" },
      {
        name: "post_quantum_envelopes",
        level: "L4",
        passed: true,
        detail: "ML-DSA-65 verified",
      },
    ],
    independent_verification: {
      schema_version: "0.1",
      overall_result: "PASS",
      checks: [
        {
          tool: "kinegrant-js",
          detail: "cross-verified",
          capability: "PASS",
          receipts: "SKIP",
          policy_bundle: "PASS",
          policy_current_version: "PASS",
        },
      ],
    },
    limitations: ["self-assessment"],
  };
  const result = verifyConformanceReport(report);
  assert.equal(result.marks, 2);
  assert.equal(result.summary.passed, 2);
  report.summary.passed = 1;
  assert.throws(() => verifyConformanceReport(report));
  report.summary.passed = 2;
  report.overall_result = "FAIL";
  assert.throws(() => verifyConformanceReport(report));
});

test("browser verifier validates policy audit summaries", () => {
  const report = {
    type: "kinegrant:PolicyAuditSummary",
    schema_version: "0.1",
    overall_result: "PASS",
    summary: {
      bundles_total: 1,
      verified: 1,
      failed: 0,
      analysis_failures: 0,
      coverage_failures: 0,
      findings_by_code: {},
      allowed: 0,
      denied: 1,
      exceptions: 0,
      shadowed_allows: 0,
    },
    bundles: [
      {
        label: "fleet-a",
        verified: true,
        policy_id: "urn:kinegrant:policy:audit:1",
        bundle_version: 1,
        analysis_result: "PASS",
        coverage_result: "PASS",
        error_findings: [],
        shadowed_allows: [],
        error: null,
      },
    ],
  };
  const result = verifyPolicyAuditSummary(report);
  assert.equal(result.overall_result, "PASS");
  assert.equal(result.bundles, 1);
  report.summary.verified = 0;
  assert.throws(() => verifyPolicyAuditSummary(report));
  report.summary.verified = 1;
  report.overall_result = "FAIL";
  assert.throws(() => verifyPolicyAuditSummary(report));
});

test("browser verifier validates security review kits", () => {
  const kit = {
    type: "kinegrant:SecurityReviewKit",
    schema_version: "0.1",
    generated_at: "2026-08-15T01:00:00Z",
    reference_implementation: "2.25.0",
    source_commit: "0".repeat(40),
    overall_result: "PASS",
    checks: {
      conformance: { status: "PASS", detail: "23/23" },
      machine_permission_test: {
        status: "PASS",
        detail: "22/22",
        schema_version: "0.5",
      },
      red_team: { status: "PASS", detail: "11/11" },
      benchmarks: {
        status: "PASS",
        detail: "machine-readable throughput emitted",
        operations_per_second: 1234.5,
      },
      unit_tests: { status: "PASS", detail: "OK (skipped=10)" },
      release_packet: { status: "SKIP", detail: "no release directory supplied" },
    },
    checklist: [
      {
        id: "default-deny",
        name: "Default deny and deny-overrides",
        evidence: "spec/KGP-001.md",
        status: "PASS",
      },
    ],
    commands: ["python -m unittest discover -s tests"],
    artifacts: {
      specification: "spec/KGP-001.md",
      threat_model: "spec/THREAT-MODEL.md",
      standards_mapping: "spec/STANDARD-MAPPING.md",
      reproducing: "REPRODUCING.md",
      deployment_cases: "docs/DEPLOYMENT-CASES.md",
      releases: ["https://github.com/zoahdev/kinegrant-protocol/releases/tag/v2.24.0"],
    },
    limitations: ["not a security audit"],
  };
  const result = verifySecurityReviewKit(kit);
  assert.equal(result.checks, 6);
  assert.equal(result.overall_result, "PASS");
  kit.overall_result = "FAIL";
  assert.throws(() => verifySecurityReviewKit(kit));
  kit.overall_result = "PASS";
  kit.checks.unit_tests.status = "FAIL";
  assert.throws(() => verifySecurityReviewKit(kit));
  kit.checks.unit_tests.status = "PASS";
  kit.checks.unit_tests.status = "SKIP";
  assert.throws(() => verifySecurityReviewKit(kit));
});

test("browser verifier validates ESP32-C3 hardware evidence", () => {
  const base = {
    schema_version: "0.1",
    evidence_type: "kinegrant:ESP32C3PaperBarrierProofEvidence",
    evidence_mode: "simulation",
    run_id: "urn:kinegrant:esp32c3-proof:run:" + "a".repeat(36),
    generated_at: "2026-08-15T01:00:00Z",
    started_at: null,
    finished_at: null,
    protocol: "KGP-001 Experimental Open Draft 0.1",
    reference_implementation: "0.1.1",
    source_commit: null,
    device: {
      board_model: "UNSELECTED",
      device_id: "device:esp32c3:paper-barrier:UNPROVISIONED",
      device_key: null,
      firmware_version: "NOT_BUILT",
      firmware_digest: null,
      pinout_record_digest: null,
    },
    environment: {
      host_platform: "NOT_RECORDED",
      servo_model: "NOT_PURCHASED",
      load: "lightweight-paper-barrier",
      servo_supply_voltage: null,
      power_plan_reviewed: false,
    },
    verification: {
      allow_receipts_verified: false,
      deny_receipts_verified: false,
      tampered_receipts_rejected: false,
      untrusted_executor_rejected: false,
      device_acks_verified: false,
    },
    artifacts: [],
    limitations: ["template"],
  };
  const notRun = {
    ...base,
    overall_result: "NOT_RUN",
    cases: buildEsp32Cases(false, false),
  };
  const result = verifyEsp32c3Evidence(notRun);
  assert.equal(result.overall_result, "NOT_RUN");
  assert.equal(result.cases, 11);
  const simPass = {
    ...base,
    overall_result: "SIMULATION_PASS",
    started_at: "2026-08-15T00:00:00Z",
    finished_at: "2026-08-15T00:30:00Z",
    verification: {
      allow_receipts_verified: true,
      deny_receipts_verified: true,
      tampered_receipts_rejected: true,
      untrusted_executor_rejected: true,
      device_acks_verified: true,
    },
    cases: buildEsp32Cases(true, true),
  };
  assert.equal(verifyEsp32c3Evidence(simPass).overall_result, "SIMULATION_PASS");
  simPass.overall_result = "FAIL";
  assert.throws(() => verifyEsp32c3Evidence(simPass));
  simPass.overall_result = "SIMULATION_PASS";
  simPass.cases[0].passed = false;
  assert.throws(() => verifyEsp32c3Evidence(simPass));
});

test("browser verifier validates fleet operations reports", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const policyBundle = buildBundle(privateKey, publicKey);
  const revocationBundle = buildRevocationBundle(privateKey, publicKey);
  const policyReport = {
    type: "kinegrant:PolicyDistributionReport",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: policyBundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { registries: 1, applied_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        policy_id: "urn:policy:browser",
        bundle_id: policyBundle.payload.bundle_id,
        applied: true,
        current_before: null,
        current_after: 1,
        detail: "policy bundle activated",
      },
    ],
  };
  const revocationReport = {
    type: "kinegrant:RevocationDistributionReport",
    schema_version: "0.1",
    bundle_id: revocationBundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { gates: 1, added_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        bundle_id: revocationBundle.payload.bundle_id,
        applied: true,
        added_count: 1,
        already_present: 0,
        detail: "applied",
      },
    ],
  };
  const fleet = {
    type: "kinegrant:FleetOperationsReport",
    schema_version: "0.1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    summary: {
      gates_total: 1,
      policy_applied: 1,
      policy_failures: 0,
      revocation_applied: 1,
      revocation_failures: 0,
    },
    policy_distribution: policyReport,
    revocation_distribution: revocationReport,
  };
  const result = await verifyFleetOperationsReport(
    fleet,
    policyBundle,
    revocationBundle,
    new Set([policyBundle.kid])
  );
  assert.equal(result.overall_result, "PASS");
  assert.equal(result.gates, 1);
  fleet.summary.policy_applied = 0;
  await assert.rejects(() =>
    verifyFleetOperationsReport(
      fleet,
      policyBundle,
      revocationBundle,
      new Set([policyBundle.kid])
    )
  );
  fleet.summary.policy_applied = 1;
  fleet.revocation_distribution.acks[0].gate_id = "gate-b";
  await assert.rejects(() =>
    verifyFleetOperationsReport(
      fleet,
      policyBundle,
      revocationBundle,
      new Set([policyBundle.kid])
    )
  );
});

test("browser verifier validates benchmark reports", () => {
  const report = {
    type: "kinegrant:BenchmarkReport",
    schema_version: "0.1",
    iterations: 2000,
    operations_per_second: {
      policy_evaluate: 1000,
      cached_policy_evaluate: 2000,
      capability_issue: 1500,
      gate_authorize: 800,
      receipt_append: 600,
      obligation_compliance: 400,
      gatekeeper_execute: 300,
      audit_summary: 500,
      revocation_distribute: 200,
      jcs_digest: 5000,
    },
  };
  const result = verifyBenchmarkReport(report);
  assert.equal(result.operations, 10);
  assert.equal(result.iterations, 2000);
  report.iterations = 0;
  assert.throws(() => verifyBenchmarkReport(report));
  report.iterations = 2000;
  delete report.operations_per_second.jcs_digest;
  assert.throws(() => verifyBenchmarkReport(report));
});

test("browser verifier validates policy lifecycle traces", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const trace = {
    type: "kinegrant:PolicyLifecycleTrace",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: bundle.payload.bundle_id,
    bundle_version: 1,
    generated_at: "2026-08-15T01:00:00Z",
    phases: [
      { phase: "publish", status: "PASS", detail: "signed bundle verified", artifact: null },
      {
        phase: "enforce",
        status: "PASS",
        detail: "capability and receipt verified",
        artifact: "kinegrant:receipt:" + "a".repeat(64),
      },
      { phase: "odrl", status: "PASS", detail: "kgp-v0.2 mapping", artifact: null },
      { phase: "distribute", status: "PASS", detail: "fleet policy distribution", artifact: null },
      { phase: "audit", status: "PASS", detail: "fleet audit summary", artifact: null },
      { phase: "revoke", status: "PASS", detail: "revocation rollback", artifact: null },
    ],
    summary: { phases_total: 6, passed: 6, failed: 0 },
    overall_result: "PASS",
  };
  const result = await verifyPolicyLifecycleTrace(
    trace,
    bundle,
    new Set([bundle.kid])
  );
  assert.equal(result.overall_result, "PASS");
  trace.summary.passed = 5;
  await assert.rejects(() =>
    verifyPolicyLifecycleTrace(trace, bundle, new Set([bundle.kid]))
  );
  trace.summary.passed = 6;
  trace.phases[2].status = "FAIL";
  trace.summary.failed = 1;
  trace.overall_result = "PASS";
  await assert.rejects(() =>
    verifyPolicyLifecycleTrace(trace, bundle, new Set([bundle.kid]))
  );
});

test("browser verifier validates sensor commitments and checkpoints", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const kid = kidOf(publicKey);
  const unsigned = buildSensorCommitment(privateKey, publicKey, { signed: false });
  const payload = await verifySensorCommitment(unsigned);
  assert.equal(payload.readings.length, 1);
  const evidenceHash = await sensorEvidenceHash(unsigned);
  assert.match(evidenceHash, /^sha256:[0-9a-f]{64}$/);
  const signed = buildSensorCommitment(privateKey, publicKey, { signed: true });
  await verifySensorCommitment(signed, { trustedSensors: new Set([kid]) });
  await assert.rejects(() =>
    verifySensorCommitment(signed, { trustedSensors: new Set(["other"]) })
  );
  const tampered = JSON.parse(JSON.stringify(unsigned));
  tampered.readings[0].confidence = 1.5;
  await assert.rejects(() => verifySensorCommitment(tampered));
  const checkpoint = buildCheckpoint(privateKey, publicKey);
  const result = await verifyReceiptCheckpoint(checkpoint);
  assert.equal(result.chain_digest, "sha256:" + "b".repeat(64));
  const bad = JSON.parse(JSON.stringify(checkpoint));
  bad.payload.period = "hourly";
  await assert.rejects(() => verifyReceiptCheckpoint(bad));
});

test("browser verifier validates device attestations", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const kid = kidOf(publicKey);
  const attestation = buildAttestation(privateKey, publicKey);
  const result = await verifyDeviceAttestation(attestation, {
    trustedDevices: new Set([kid]),
  });
  assert.equal(result.boot_counter, 3);
  assert.equal(result.stages, 1);
  assert.equal(result.device_id, "device:esp32c3:paper-barrier:unit-1");
  await assert.rejects(() =>
    verifyDeviceAttestation(attestation, { trustedDevices: new Set(["other"]) })
  );
  const bad = JSON.parse(JSON.stringify(attestation));
  bad.payload.boot_counter = -1;
  await assert.rejects(() => verifyDeviceAttestation(bad));
});

test("browser verifier validates bridge demo reports", () => {
  const report = {
    type: "kinegrant:Ros2McpDemoReport",
    schema_version: "0.1",
    overall_result: "PASS",
    summary: { total: 2, passed: 2, failed: 0 },
    receipt_count: 2,
    receipts_verified: true,
    obligation_compliance_ok: true,
    outcomes: buildBridgeOutcomes(),
    limitations: ["software demonstration only"],
  };
  let result = verifyBridgeDemoReport(report);
  assert.equal(result.overall_result, "PASS");
  report.summary.passed = 1;
  assert.throws(() => verifyBridgeDemoReport(report));
  report.summary.passed = 2;
  report.receipt_count = 1;
  assert.throws(() => verifyBridgeDemoReport(report));
  report.receipt_count = 2;
  report.overall_result = "FAIL";
  assert.throws(() => verifyBridgeDemoReport(report));
  report.overall_result = "PASS";
  const bridge = {
    ...report,
    type: "kinegrant:BridgeDemoReport",
    fidelity_ok: true,
    outcomes: buildBridgeOutcomes(false),
  };
  delete bridge.receipt_count;
  delete bridge.receipts_verified;
  result = verifyBridgeDemoReport(bridge);
  assert.equal(result.type, "kinegrant:BridgeDemoReport");
});

test("browser verifier validates hardware trust packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const attestation = buildAttestation(privateKey, publicKey);
  const commitment = buildSensorCommitment(privateKey, publicKey, { signed: true });
  const checkpoint = buildCheckpoint(privateKey, publicKey);
  const packet = {
    type: "kinegrant:HardwareTrustPacket",
    schema_version: "0.1",
    device_id: "device:esp32c3:paper-barrier:unit-1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    device_attestation: attestation,
    sensor_commitments: [commitment],
    receipt_checkpoints: [checkpoint],
    summary: {
      device_attestations: 1,
      sensor_commitments: 1,
      receipt_checkpoints: 1,
    },
  };
  const result = await verifyHardwareTrustPacket(packet);
  assert.equal(result.device_id, "device:esp32c3:paper-barrier:unit-1");
  assert.equal(result.sensor_commitments, 1);
  assert.equal(result.receipt_checkpoints, 1);
  packet.summary.sensor_commitments = 2;
  await assert.rejects(() => verifyHardwareTrustPacket(packet));
  packet.summary.sensor_commitments = 1;
  packet.device_id = "other-device";
  await assert.rejects(() => verifyHardwareTrustPacket(packet));
});

test("browser verifier validates device-to-policy export packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const bundlePayload = bundle.payload;
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-1",
    agent: "robot-1",
    target: "urn:space:door-1",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const expectedPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: bundlePayload.rules,
            trusted_policy_issuers: [bundlePayload.issuer].sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const capability = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
  });
  const deviceId = "device:esp32c3:paper-barrier:unit-1";
  const commitment = buildSensorCommitment(privateKey, publicKey, {
    signed: true,
    sourceId: deviceId,
  });
  const sensorHash = await sensorEvidenceHash(commitment);
  const receipt = buildReceipt(privateKey, publicKey, {
    capabilityId: capability.payload.capability_id,
    requestDigest: capability.payload.request_digest,
    evidenceHash: sensorHash,
    target: request.target,
  });
  const chainDigest =
    "sha256:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson([receipt]), "utf8"))
      .digest("hex");
  const checkpoint = buildCheckpoint(privateKey, publicKey, { chainDigest });
  const attestation = buildAttestation(privateKey, publicKey, { deviceId });
  const packet = {
    type: "kinegrant:DeviceToPolicyExportPacket",
    schema_version: "0.1",
    device_id: deviceId,
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    trusted_policy_issuers: [bundlePayload.issuer],
    policy_bundle: bundle,
    capability,
    request,
    gate_decision: {
      allowed: true,
      reason: "allow",
      checked_at: "2026-08-15T00:30:00Z",
      capability_id: capability.payload.capability_id,
      policy_digest: capability.payload.policy_digest,
    },
    receipt,
    sensor_commitment: commitment,
    receipt_checkpoint: checkpoint,
    device_attestation: attestation,
    summary: {
      artifacts_total: 9,
      policy_verified: true,
      capability_verified: true,
      decision_consistent: true,
      receipt_bound: true,
      sensor_bound: true,
      checkpoint_bound: true,
      attestation_bound: true,
      cross_references_ok: true,
    },
  };
  const result = await verifyDeviceToPolicyExport(packet);
  assert.equal(result.device_id, deviceId);
  assert.equal(result.policy_id, bundlePayload.policy_id);
  assert.equal(result.capability_id, capability.payload.capability_id);
  assert.equal(result.artifacts_total, 9);

  const mismatchedReceipt = buildReceipt(privateKey, publicKey, {
    capabilityId: capability.payload.capability_id,
    requestDigest: capability.payload.request_digest,
    evidenceHash: "sha256:" + "a".repeat(64),
  });
  await assert.rejects(() =>
    verifyDeviceToPolicyExport({ ...packet, receipt: mismatchedReceipt })
  );

  const mismatchedCheckpoint = buildCheckpoint(privateKey, publicKey, {
    chainDigest: "sha256:" + "b".repeat(64),
  });
  await assert.rejects(() =>
    verifyDeviceToPolicyExport({
      ...packet,
      receipt_checkpoint: mismatchedCheckpoint,
    })
  );

  await assert.rejects(() =>
    verifyDeviceToPolicyExport({
      ...packet,
      summary: { ...packet.summary, cross_references_ok: false },
    })
  );
});

test("browser verifier validates fleet device export packets", async () => {
  const authority = generateKeyPairSync("ed25519");
  const device1 = generateKeyPairSync("ed25519");
  const device2 = generateKeyPairSync("ed25519");
  const bundle = buildBundle(authority.privateKey, authority.publicKey);
  const first = await buildDeviceToPolicyPacket(
    authority.privateKey,
    authority.publicKey,
    device1.privateKey,
    device1.publicKey,
    { deviceId: "device:a-1", requestId: "req-1", bundle }
  );
  const second = await buildDeviceToPolicyPacket(
    authority.privateKey,
    authority.publicKey,
    device2.privateKey,
    device2.publicKey,
    { deviceId: "device:a-2", requestId: "req-2", bundle }
  );
  const fleet = {
    type: "kinegrant:FleetDeviceExportPacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T02:00:00Z",
    overall_result: "PASS",
    trusted_policy_issuers: first.packet.trusted_policy_issuers,
    policy_bundle: bundle,
    devices: [first.packet, second.packet],
    summary: {
      devices_total: 2,
      policy_shared: true,
      devices_verified: 2,
      device_ids_unique: true,
      cross_references_ok: true,
    },
  };
  const result = await verifyFleetDeviceExport(fleet);
  assert.equal(result.policy_id, bundle.payload.policy_id);
  assert.equal(result.devices_total, 2);
  assert.deepEqual(result.device_ids, ["device:a-1", "device:a-2"]);

  const duplicate = await buildDeviceToPolicyPacket(
    authority.privateKey,
    authority.publicKey,
    device2.privateKey,
    device2.publicKey,
    { deviceId: "device:a-1", requestId: "req-3", bundle }
  );
  await assert.rejects(() =>
    verifyFleetDeviceExport({
      ...fleet,
      devices: [first.packet, duplicate.packet],
      summary: { ...fleet.summary },
    })
  );

  await assert.rejects(() =>
    verifyFleetDeviceExport({
      ...fleet,
      summary: { ...fleet.summary, cross_references_ok: false },
    })
  );
});

test("browser verifier validates end-to-end audit export packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const policyBundle = buildBundle(privateKey, publicKey);
  const revocationBundle = buildRevocationBundle(privateKey, publicKey);
  const distribution = {
    type: "kinegrant:PolicyDistributionReport",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: policyBundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { registries: 1, applied_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        policy_id: "urn:policy:browser",
        bundle_id: policyBundle.payload.bundle_id,
        applied: true,
        current_before: null,
        current_after: 1,
        detail: "policy bundle activated",
      },
    ],
  };
  const audit = {
    type: "kinegrant:PolicyAuditSummary",
    schema_version: "0.1",
    overall_result: "PASS",
    summary: {
      bundles_total: 1,
      verified: 1,
      failed: 0,
      analysis_failures: 0,
      coverage_failures: 0,
      findings_by_code: {},
      allowed: 0,
      denied: 1,
      exceptions: 0,
      shadowed_allows: 0,
    },
    bundles: [
      {
        label: "fleet-a",
        verified: true,
        policy_id: "urn:policy:browser",
        bundle_version: 1,
        analysis_result: "PASS",
        coverage_result: "PASS",
        error_findings: [],
        shadowed_allows: [],
        error: null,
      },
    ],
    independent_verification: {
      schema_version: "0.1",
      overall_result: "PASS",
      checks: [
        {
          tool: "kinegrant-js",
          detail: "cross-verified",
          capability: "PASS",
          receipts: "SKIP",
          policy_bundle: "PASS",
          policy_current_version: "PASS",
        },
      ],
    },
    limitations: ["self-assessment"],
  };
  const revocation = {
    type: "kinegrant:RevocationDistributionReport",
    schema_version: "0.1",
    bundle_id: revocationBundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { gates: 1, added_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        bundle_id: revocationBundle.payload.bundle_id,
        applied: true,
        added_count: 1,
        already_present: 0,
        detail: "applied",
      },
    ],
  };
  const lifecycleReport = {
    type: "kinegrant:FullLifecycleReport",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: policyBundle.payload.bundle_id,
    bundle_version: 1,
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    summary: { phases_total: 4, passed: 4, failed: 0 },
    policy_distribution: distribution,
    audit_summary: audit,
    revocation_distribution: revocation,
  };
  const device1 = generateKeyPairSync("ed25519");
  const device2 = generateKeyPairSync("ed25519");
  const first = await buildDeviceToPolicyPacket(
    privateKey,
    publicKey,
    device1.privateKey,
    device1.publicKey,
    { deviceId: "device:a-1", requestId: "req-1", bundle: policyBundle }
  );
  const second = await buildDeviceToPolicyPacket(
    privateKey,
    publicKey,
    device2.privateKey,
    device2.publicKey,
    { deviceId: "device:a-2", requestId: "req-2", bundle: policyBundle }
  );
  const fleetExport = {
    type: "kinegrant:FleetDeviceExportPacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T02:00:00Z",
    overall_result: "PASS",
    trusted_policy_issuers: [policyBundle.kid],
    policy_bundle: policyBundle,
    devices: [first.packet, second.packet],
    summary: {
      devices_total: 2,
      policy_shared: true,
      devices_verified: 2,
      device_ids_unique: true,
      cross_references_ok: true,
    },
  };
  const packet = {
    type: "kinegrant:EndToEndAuditExportPacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T03:00:00Z",
    overall_result: "PASS",
    trusted_authorities: [policyBundle.kid],
    policy_bundle: policyBundle,
    revocation_bundle: revocationBundle,
    lifecycle_report: lifecycleReport,
    fleet_export: fleetExport,
    summary: {
      artifacts_total: 7,
      phases_total: 4,
      devices_total: 2,
      policy_shared: true,
      lifecycle_verified: true,
      fleet_verified: true,
      cross_references_ok: true,
    },
  };
  const result = await verifyEndToEndAuditExport(packet);
  assert.equal(result.policy_id, "urn:policy:browser");
  assert.equal(result.phases_total, 4);
  assert.equal(result.devices_total, 2);
  assert.equal(result.artifacts_total, 7);

  await assert.rejects(() =>
    verifyEndToEndAuditExport({
      ...packet,
      summary: { ...packet.summary, lifecycle_verified: false },
    })
  );
  await assert.rejects(() =>
    verifyEndToEndAuditExport({
      ...packet,
      lifecycle_report: {
        ...packet.lifecycle_report,
        summary: { ...packet.lifecycle_report.summary, passed: 3 },
      },
    })
  );
});

test("browser verifier validates revocation-reissue closure packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const bundlePayload = bundle.payload;
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-1",
    agent: "robot-1",
    target: "urn:space:door-1",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const expectedPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: bundlePayload.rules,
            trusted_policy_issuers: [bundlePayload.issuer].sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const capabilityOptions = {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
  };
  const revokedCapability = buildScopedCapability(
    privateKey,
    publicKey,
    request,
    { ...capabilityOptions, nonce: "old-nonce-value-000000000000" }
  );
  const reissuedCapability = buildScopedCapability(
    privateKey,
    publicKey,
    request,
    { ...capabilityOptions, nonce: "new-nonce-value-000000000000" }
  );
  const revokedId = revokedCapability.payload.capability_id;
  const revocationBundle = buildRevocationBundle(privateKey, publicKey, {
    capabilityId: revokedId,
  });
  const receipt = buildReceipt(privateKey, publicKey, {
    capabilityId: reissuedCapability.payload.capability_id,
    requestDigest: reissuedCapability.payload.request_digest,
    evidenceHash: "sha256:" + "a".repeat(64),
    target: request.target,
  });
  const packet = {
    type: "kinegrant:RevocationReissueClosurePacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T03:00:00Z",
    overall_result: "PASS",
    trusted_authorities: [bundlePayload.issuer],
    trusted_policy_issuers: [bundlePayload.issuer],
    policy_bundle: bundle,
    revocation_bundle: revocationBundle,
    revoked_capability_id: revokedId,
    request,
    reissued_capability: reissuedCapability,
    gate_log: {
      revoked_denied: {
        allowed: false,
        reason: "revoked",
        checked_at: "2026-08-15T00:20:00Z",
        capability_id: revokedId,
        policy_digest: expectedPolicyDigest,
      },
      reissued_allowed: {
        allowed: true,
        reason: "allow",
        checked_at: "2026-08-15T00:30:00Z",
        capability_id: reissuedCapability.payload.capability_id,
        policy_digest: expectedPolicyDigest,
      },
    },
    receipt,
    summary: {
      artifacts_total: 8,
      policy_verified: true,
      revocation_verified: true,
      revoked_capability_revoked: true,
      deny_recorded: true,
      reissue_verified: true,
      allow_recorded: true,
      receipt_bound: true,
      closure_complete: true,
    },
  };
  const result = await verifyRevocationReissueClosure(packet);
  assert.equal(result.policy_id, bundlePayload.policy_id);
  assert.equal(result.revoked_capability_id, revokedId);
  assert.equal(result.reissued_capability_id, reissuedCapability.payload.capability_id);

  const unrelatedRevocation = buildRevocationBundle(privateKey, publicKey);
  await assert.rejects(() =>
    verifyRevocationReissueClosure({
      ...packet,
      revocation_bundle: unrelatedRevocation,
    })
  );
  await assert.rejects(() =>
    verifyRevocationReissueClosure({
      ...packet,
      gate_log: {
        ...packet.gate_log,
        revoked_denied: {
          ...packet.gate_log.revoked_denied,
          capability_id: "kinegrant:cap:" + "b".repeat(64),
        },
      },
    })
  );
  await assert.rejects(() =>
    verifyRevocationReissueClosure({
      ...packet,
      summary: { ...packet.summary, closure_complete: false },
    })
  );
});

test("browser verifier validates unified audit export packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const bundlePayload = bundle.payload;
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-1",
    agent: "robot-1",
    target: "urn:space:door-1",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const expectedPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: bundlePayload.rules,
            trusted_policy_issuers: [bundlePayload.issuer].sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const capabilityOptions = {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
  };
  const revokedCapability = buildScopedCapability(
    privateKey,
    publicKey,
    request,
    { ...capabilityOptions, nonce: "old-nonce-value-000000000000" }
  );
  const reissuedCapability = buildScopedCapability(
    privateKey,
    publicKey,
    request,
    { ...capabilityOptions, nonce: "new-nonce-value-000000000000" }
  );
  const revokedId = revokedCapability.payload.capability_id;
  const revocationBundle = buildRevocationBundle(privateKey, publicKey, {
    capabilityId: revokedId,
  });
  const closureReceipt = buildReceipt(privateKey, publicKey, {
    capabilityId: reissuedCapability.payload.capability_id,
    requestDigest: reissuedCapability.payload.request_digest,
    evidenceHash: "sha256:" + "a".repeat(64),
    target: request.target,
  });
  const closure = {
    type: "kinegrant:RevocationReissueClosurePacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T03:00:00Z",
    overall_result: "PASS",
    trusted_authorities: [bundlePayload.issuer],
    trusted_policy_issuers: [bundlePayload.issuer],
    policy_bundle: bundle,
    revocation_bundle: revocationBundle,
    revoked_capability_id: revokedId,
    request,
    reissued_capability: reissuedCapability,
    gate_log: {
      revoked_denied: {
        allowed: false,
        reason: "revoked",
        checked_at: "2026-08-15T00:20:00Z",
        capability_id: revokedId,
        policy_digest: expectedPolicyDigest,
      },
      reissued_allowed: {
        allowed: true,
        reason: "allow",
        checked_at: "2026-08-15T00:30:00Z",
        capability_id: reissuedCapability.payload.capability_id,
        policy_digest: expectedPolicyDigest,
      },
    },
    receipt: closureReceipt,
    summary: {
      artifacts_total: 8,
      policy_verified: true,
      revocation_verified: true,
      revoked_capability_revoked: true,
      deny_recorded: true,
      reissue_verified: true,
      allow_recorded: true,
      receipt_bound: true,
      closure_complete: true,
    },
  };
  const distribution = {
    type: "kinegrant:PolicyDistributionReport",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: bundlePayload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { registries: 1, applied_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        policy_id: "urn:policy:browser",
        bundle_id: bundlePayload.bundle_id,
        applied: true,
        current_before: null,
        current_after: 1,
        detail: "policy bundle activated",
      },
    ],
  };
  const audit = {
    type: "kinegrant:PolicyAuditSummary",
    schema_version: "0.1",
    overall_result: "PASS",
    summary: {
      bundles_total: 1,
      verified: 1,
      failed: 0,
      analysis_failures: 0,
      coverage_failures: 0,
      findings_by_code: {},
      allowed: 0,
      denied: 1,
      exceptions: 0,
      shadowed_allows: 0,
    },
    bundles: [
      {
        label: "fleet-a",
        verified: true,
        policy_id: "urn:policy:browser",
        bundle_version: 1,
        analysis_result: "PASS",
        coverage_result: "PASS",
        error_findings: [],
        shadowed_allows: [],
        error: null,
      },
    ],
    independent_verification: {
      schema_version: "0.1",
      overall_result: "PASS",
      checks: [
        {
          tool: "kinegrant-js",
          detail: "cross-verified",
          capability: "PASS",
          receipts: "SKIP",
          policy_bundle: "PASS",
          policy_current_version: "PASS",
        },
      ],
    },
    limitations: ["self-assessment"],
  };
  const revocation = {
    type: "kinegrant:RevocationDistributionReport",
    schema_version: "0.1",
    bundle_id: revocationBundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { gates: 1, added_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        bundle_id: revocationBundle.payload.bundle_id,
        applied: true,
        added_count: 1,
        already_present: 0,
        detail: "applied",
      },
    ],
  };
  const lifecycleReport = {
    type: "kinegrant:FullLifecycleReport",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: bundlePayload.bundle_id,
    bundle_version: 1,
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    summary: { phases_total: 4, passed: 4, failed: 0 },
    policy_distribution: distribution,
    audit_summary: audit,
    revocation_distribution: revocation,
  };
  const device1 = generateKeyPairSync("ed25519");
  const device2 = generateKeyPairSync("ed25519");
  const first = await buildDeviceToPolicyPacket(
    privateKey,
    publicKey,
    device1.privateKey,
    device1.publicKey,
    { deviceId: "device:a-1", requestId: "req-1", bundle }
  );
  const second = await buildDeviceToPolicyPacket(
    privateKey,
    publicKey,
    device2.privateKey,
    device2.publicKey,
    { deviceId: "device:a-2", requestId: "req-2", bundle }
  );
  const fleetExport = {
    type: "kinegrant:FleetDeviceExportPacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T02:00:00Z",
    overall_result: "PASS",
    trusted_policy_issuers: [bundlePayload.issuer],
    policy_bundle: bundle,
    devices: [first.packet, second.packet],
    summary: {
      devices_total: 2,
      policy_shared: true,
      devices_verified: 2,
      device_ids_unique: true,
      cross_references_ok: true,
    },
  };
  const packet = {
    type: "kinegrant:UnifiedAuditExportPacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T04:00:00Z",
    overall_result: "PASS",
    trusted_authorities: [bundlePayload.issuer],
    policy_bundle: bundle,
    revocation_bundle: revocationBundle,
    lifecycle_report: lifecycleReport,
    fleet_export: fleetExport,
    closure,
    summary: {
      artifacts_total: 8,
      phases_total: 4,
      devices_total: 2,
      policy_shared: true,
      lifecycle_verified: true,
      fleet_verified: true,
      closure_verified: true,
      cross_references_ok: true,
    },
  };
  const result = await verifyUnifiedAuditExport(packet);
  assert.equal(result.policy_id, "urn:policy:browser");
  assert.equal(result.phases_total, 4);
  assert.equal(result.devices_total, 2);
  assert.equal(result.closure_revoked, revokedId);

  const otherBundle = buildBundle(privateKey, publicKey);
  await assert.rejects(() =>
    verifyUnifiedAuditExport({
      ...packet,
      closure: {
        ...packet.closure,
        policy_bundle: otherBundle,
      },
    })
  );
  await assert.rejects(() =>
    verifyUnifiedAuditExport({
      ...packet,
      summary: { ...packet.summary, closure_verified: false },
    })
  );
});

test("browser verifier validates policy migration audit packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const oldBundle = buildBundle(privateKey, publicKey, { version: 1 });
  const oldPayload = oldBundle.payload;
  const newBundle = buildBundle(privateKey, publicKey, {
    version: 2,
    previousVersionDigest: oldPayload.policy_digest,
    extraRules: [
      {
        policy_id: "urn:policy:browser",
        issuer: oldPayload.issuer,
        target: "urn:space:door-2",
        effect: "deny",
        actions: ["close"],
        subjects: ["*"],
        purposes: ["maintenance"],
        constraints: {},
        obligations: [],
        priority: 1,
        source: {},
      },
    ],
  });
  const newPayload = newBundle.payload;
  const trusted = [oldPayload.issuer];
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-1",
    agent: "robot-1",
    target: "urn:space:door-1",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const expectedOldPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: oldPayload.rules,
            trusted_policy_issuers: trusted.sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const expectedNewPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: newPayload.rules,
            trusted_policy_issuers: trusted.sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const oldCapability = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedOldPolicyDigest,
    matchedPolicyIds: [oldPayload.policy_id],
    nonce: "old-migration-nonce-000000000000",
  });
  const newCapability = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedNewPolicyDigest,
    matchedPolicyIds: [newPayload.policy_id],
    nonce: "new-migration-nonce-000000000000",
  });
  const oldId = oldCapability.payload.capability_id;
  const distribution = {
    type: "kinegrant:PolicyDistributionReport",
    schema_version: "0.1",
    policy_id: newPayload.policy_id,
    bundle_id: newPayload.bundle_id,
    bundle_version: 2,
    overall_result: "PASS",
    summary: { registries: 1, applied_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        policy_id: newPayload.policy_id,
        bundle_id: newPayload.bundle_id,
        applied: true,
        current_before: 1,
        current_after: 2,
        detail: "policy bundle activated",
      },
    ],
  };
  const receipt = buildReceipt(privateKey, publicKey, {
    capabilityId: newCapability.payload.capability_id,
    requestDigest: newCapability.payload.request_digest,
    evidenceHash: "sha256:" + "a".repeat(64),
    target: request.target,
  });
  const packet = {
    type: "kinegrant:PolicyMigrationAuditPacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T04:00:00Z",
    overall_result: "PASS",
    trusted_authorities: trusted,
    old_policy_bundle: oldBundle,
    new_policy_bundle: newBundle,
    distribution_report: distribution,
    old_capability_id: oldId,
    request,
    old_capability: oldCapability,
    new_capability: newCapability,
    migration: {
      gate_log: {
        old_denied: {
          allowed: false,
          reason: "policy_migrated",
          checked_at: "2026-08-15T00:20:00Z",
          capability_id: oldId,
          policy_digest: expectedOldPolicyDigest,
        },
        new_allowed: {
          allowed: true,
          reason: "allow",
          checked_at: "2026-08-15T00:30:00Z",
          capability_id: newCapability.payload.capability_id,
          policy_digest: expectedNewPolicyDigest,
        },
      },
    },
    receipt,
    summary: {
      artifacts_total: 10,
      old_policy_verified: true,
      new_policy_verified: true,
      version_chain: true,
      distribution_verified: true,
      migration_verified: true,
      gate_order_ok: true,
      receipt_bound: true,
      closure_complete: true,
    },
  };
  const result = await verifyPolicyMigrationAudit(packet);
  assert.equal(result.policy_id, "urn:policy:browser");
  assert.equal(result.old_version, 1);
  assert.equal(result.new_version, 2);
  assert.equal(result.old_capability_id, oldId);

  const unlinkedBundle = buildBundle(privateKey, publicKey, {
    version: 2,
    previousVersionDigest: "sha256:" + "0".repeat(64),
  });
  await assert.rejects(() =>
    verifyPolicyMigrationAudit({
      ...packet,
      new_policy_bundle: unlinkedBundle,
    })
  );
  await assert.rejects(() =>
    verifyPolicyMigrationAudit({
      ...packet,
      summary: { ...packet.summary, version_chain: false },
    })
  );
});

test("browser verifier validates compliance timelines", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const bundlePayload = bundle.payload;
  const trusted = [bundlePayload.issuer];
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-1",
    agent: "robot-1",
    target: "urn:space:door-1",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const expectedPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: bundlePayload.rules,
            trusted_policy_issuers: trusted.sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const capabilityA = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
    nonce: "timeline-a-nonce-00000000000000",
  });
  const capabilityB = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
    nonce: "timeline-b-nonce-00000000000000",
  });
  const capIdA = capabilityA.payload.capability_id;
  const capIdB = capabilityB.payload.capability_id;
  const events = [
    {
      kind: "capability_issued",
      at: "2026-08-15T00:10:00Z",
      capability_id: capIdA,
      request_digest: capabilityA.payload.request_digest,
      policy_digest: expectedPolicyDigest,
      actor: "robot-1",
    },
    {
      kind: "gate_allowed",
      at: "2026-08-15T00:11:00Z",
      capability_id: capIdA,
      policy_digest: expectedPolicyDigest,
      reason: "allow",
    },
    {
      kind: "receipt_signed",
      at: "2026-08-15T00:12:00Z",
      capability_id: capIdA,
      receipt_id: "kinegrant:receipt:" + "a".repeat(64),
      evidence_hash: "sha256:" + "b".repeat(64),
    },
    {
      kind: "capability_revoked",
      at: "2026-08-15T00:13:00Z",
      capability_id: capIdA,
      reason: "operator decision",
    },
    {
      kind: "gate_denied",
      at: "2026-08-15T00:14:00Z",
      capability_id: capIdA,
      policy_digest: expectedPolicyDigest,
      reason: "revoked",
    },
    {
      kind: "capability_reissued",
      at: "2026-08-15T00:15:00Z",
      old_capability_id: capIdA,
      new_capability_id: capIdB,
      policy_digest: expectedPolicyDigest,
    },
  ];
  const packet = {
    type: "kinegrant:ComplianceTimelinePacket",
    schema_version: "0.1",
    device_id: "device:esp32c3:paper-barrier:unit-1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    trusted_authorities: trusted,
    policy_bundle: bundle,
    events,
    summary: {
      events_total: 6,
      kinds_unique: 6,
      monotonic: true,
      policy_bound: true,
      device_bound: true,
      references_ok: true,
      timeline_complete: true,
    },
  };
  const result = await verifyComplianceTimeline(packet);
  assert.equal(result.events_total, 6);
  assert.equal(result.device_id, "device:esp32c3:paper-barrier:unit-1");

  const outOfOrder = events.map((event) => ({ ...event }));
  [outOfOrder[1], outOfOrder[4]] = [outOfOrder[4], outOfOrder[1]];
  await assert.rejects(() =>
    verifyComplianceTimeline({
      ...packet,
      events: outOfOrder,
      summary: { ...packet.summary },
    })
  );
  await assert.rejects(() =>
    verifyComplianceTimeline({
      ...packet,
      events: [
        ...events.slice(0, 2),
        {
          kind: "gate_allowed",
          at: "2026-08-15T00:09:00Z",
          capability_id: "kinegrant:cap:" + "c".repeat(64),
          policy_digest: expectedPolicyDigest,
          reason: "allow",
        },
        ...events.slice(2),
      ],
      summary: { ...packet.summary },
    })
  );
  await assert.rejects(() =>
    verifyComplianceTimeline({
      ...packet,
      summary: { ...packet.summary, timeline_complete: false },
    })
  );
});

test("browser verifier validates obligation fulfillment packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const bundlePayload = bundle.payload;
  const trusted = [bundlePayload.issuer];
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-1",
    agent: "robot-1",
    target: "urn:space:door-1",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const expectedPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: bundlePayload.rules,
            trusted_policy_issuers: trusted.sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const capability = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
    nonce: "obligation-nonce-000000000000000",
    obligations: ["emitActionReceipt", "logAuditEvent"],
  });
  const receipt = buildReceipt(privateKey, publicKey, {
    capabilityId: capability.payload.capability_id,
    requestDigest: capability.payload.request_digest,
    evidenceHash: "sha256:" + "a".repeat(64),
    target: request.target,
    version: "1.0",
    obligationResults: [
      { obligation: "emitActionReceipt", status: "satisfied" },
      { obligation: "logAuditEvent", status: "satisfied" },
    ],
  });
  const packet = {
    type: "kinegrant:ObligationFulfillmentPacket",
    schema_version: "0.1",
    device_id: "device:esp32c3:paper-barrier:unit-1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    trusted_authorities: trusted,
    policy_bundle: bundle,
    request,
    capability,
    receipts: [receipt],
    summary: {
      artifacts_total: 6,
      capabilities: 1,
      receipts_total: 1,
      obligations_required: 2,
      obligations_covered: 2,
      references_ok: true,
    },
  };
  const result = await verifyObligationFulfillment(packet);
  assert.equal(result.obligations_required, 2);
  assert.equal(result.obligations_covered, 2);
  assert.equal(result.receipts_total, 1);

  const partialReceipt = buildReceipt(privateKey, publicKey, {
    capabilityId: capability.payload.capability_id,
    requestDigest: capability.payload.request_digest,
    evidenceHash: "sha256:" + "a".repeat(64),
    target: request.target,
    version: "1.0",
    obligationResults: [{ obligation: "emitActionReceipt", status: "satisfied" }],
  });
  await assert.rejects(() =>
    verifyObligationFulfillment({ ...packet, receipts: [partialReceipt] })
  );

  const pendingReceipt = buildReceipt(privateKey, publicKey, {
    capabilityId: capability.payload.capability_id,
    requestDigest: capability.payload.request_digest,
    evidenceHash: "sha256:" + "a".repeat(64),
    target: request.target,
    version: "1.0",
    obligationResults: [
      { obligation: "emitActionReceipt", status: "satisfied" },
      { obligation: "logAuditEvent", status: "pending" },
    ],
  });
  await assert.rejects(() =>
    verifyObligationFulfillment({ ...packet, receipts: [pendingReceipt] })
  );

  await assert.rejects(() =>
    verifyObligationFulfillment({
      ...packet,
      summary: { ...packet.summary, obligations_covered: 1 },
    })
  );
});

test("browser verifier validates selective disclosure proofs", async () => {
  const merkleLeaf = (field, value) =>
    "sha256:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson({ field, value }), "utf8"))
      .digest("hex");
  const merkleNode = (left, right) =>
    "sha256:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson({ left, right }), "utf8"))
      .digest("hex");
  const document = {
    action: "open",
    agent: "robot-1",
    purpose: "delivery",
    target: "door-7",
  };
  const fields = Object.keys(document).sort();
  const leaves = fields.map((field) => merkleLeaf(field, document[field]));
  const layer1 = [merkleNode(leaves[0], leaves[1]), merkleNode(leaves[2], leaves[3])];
  const root = merkleNode(layer1[0], layer1[1]);
  const proofFor = (field) => {
    const index = fields.indexOf(field);
    const pair = index >> 1;
    return [
      { hash: leaves[index ^ 1], left: index % 2 === 1 },
      { hash: pair === 0 ? layer1[1] : layer1[0], left: pair === 1 },
    ];
  };
  const packet = {
    type: "kinegrant:SelectiveDisclosurePacket",
    schema_version: "0.1",
    document_id: "receipt-1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    root,
    visible: [
      { field: "action", value: "open", proof: proofFor("action") },
      { field: "purpose", value: "delivery", proof: proofFor("purpose") },
    ],
    summary: {
      artifacts_total: 3,
      fields_total: 2,
      proofs_verified: 2,
      root_bound: true,
      document_bound: true,
    },
  };
  const result = await verifySelectiveDisclosure(packet);
  assert.equal(result.fields_total, 2);
  assert.equal(result.document_id, "receipt-1");

  await assert.rejects(() =>
    verifySelectiveDisclosure({
      ...packet,
      visible: [
        { field: "action", value: "open", proof: proofFor("action") },
        { field: "purpose", value: "deliver", proof: proofFor("purpose") },
      ],
    })
  );
  await assert.rejects(() =>
    verifySelectiveDisclosure({
      ...packet,
      visible: [
        {
          field: "action",
          value: "open",
          proof: [{ hash: "sha256:" + "0".repeat(64), left: false }, ...proofFor("action").slice(1)],
        },
        { field: "purpose", value: "delivery", proof: proofFor("purpose") },
      ],
    })
  );
  await assert.rejects(() =>
    verifySelectiveDisclosure({
      ...packet,
      summary: { ...packet.summary, proofs_verified: 1 },
    })
  );
});

test("browser verifier validates identifier rotation chains", async () => {
  const packet = {
    type: "kinegrant:IdentifierRotationPacket",
    schema_version: "0.1",
    namespace: "robot-a",
    static_id: "robot-1",
    generated_at: "2026-08-15T02:00:00Z",
    overall_result: "PASS",
    rotations: [
      {
        ephemeral_id: "urn:kinegrant:ephemeral:robot-a:000000000000000000000001",
        issued_at: "2026-08-15T00:10:00Z",
        status: "revoked",
        revoked_at: "2026-08-15T00:20:00Z",
      },
      {
        ephemeral_id: "urn:kinegrant:ephemeral:robot-a:000000000000000000000002",
        issued_at: "2026-08-15T00:30:00Z",
        status: "active",
        revoked_at: null,
      },
    ],
    summary: {
      artifacts_total: 3,
      rotations_total: 2,
      active_total: 1,
      revoked_total: 1,
      statuses_ok: true,
      chain_complete: true,
    },
  };
  const result = await verifyIdentifierRotation(packet);
  assert.equal(result.rotations_total, 2);
  assert.equal(result.active_total, 1);

  await assert.rejects(() =>
    verifyIdentifierRotation({
      ...packet,
      rotations: [
        { ...packet.rotations[0], status: "active", revoked_at: null },
        packet.rotations[1],
      ],
      summary: { ...packet.summary },
    })
  );
  await assert.rejects(() =>
    verifyIdentifierRotation({
      ...packet,
      rotations: [
        packet.rotations[0],
        { ...packet.rotations[1], issued_at: "2026-08-15T00:05:00Z" },
      ],
      summary: { ...packet.summary },
    })
  );
  await assert.rejects(() =>
    verifyIdentifierRotation({
      ...packet,
      summary: { ...packet.summary, active_total: 2 },
    })
  );
});

test("browser verifier validates minimal disclosure audits", async () => {
  const merkleLeaf = (field, value) =>
    "sha256:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson({ field, value }), "utf8"))
      .digest("hex");
  const merkleNode = (left, right) =>
    "sha256:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson({ left, right }), "utf8"))
      .digest("hex");
  const document = {
    action: "open",
    agent: "robot-1",
    purpose: "delivery",
    target: "door-7",
  };
  const fields = Object.keys(document).sort();
  const leaves = fields.map((field) => merkleLeaf(field, document[field]));
  const layer1 = [merkleNode(leaves[0], leaves[1]), merkleNode(leaves[2], leaves[3])];
  const root = merkleNode(layer1[0], layer1[1]);
  const proofFor = (field) => {
    const index = fields.indexOf(field);
    const pair = index >> 1;
    return [
      { hash: leaves[index ^ 1], left: index % 2 === 1 },
      { hash: pair === 0 ? layer1[1] : layer1[0], left: pair === 1 },
    ];
  };
  const packet = {
    type: "kinegrant:MinimalDisclosureAuditPacket",
    schema_version: "0.1",
    document_id: "receipt-1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    root,
    required_fields: ["action", "purpose"],
    visible: [
      { field: "action", value: "open", proof: proofFor("action") },
      { field: "purpose", value: "delivery", proof: proofFor("purpose") },
    ],
    summary: {
      artifacts_total: 4,
      fields_total: 2,
      proofs_verified: 2,
      required_covered: true,
      no_extra_fields: true,
      root_bound: true,
      document_bound: true,
      minimal_disclosure: true,
    },
  };
  const result = await verifyMinimalDisclosure(packet);
  assert.equal(result.fields_total, 2);
  assert.equal(result.required_total, 2);

  await assert.rejects(() =>
    verifyMinimalDisclosure({
      ...packet,
      visible: [
        { field: "action", value: "open", proof: proofFor("action") },
        { field: "purpose", value: "delivery", proof: proofFor("purpose") },
        { field: "agent", value: "robot-1", proof: proofFor("agent") },
      ],
      summary: { ...packet.summary, fields_total: 3, proofs_verified: 3 },
    })
  );
  await assert.rejects(() =>
    verifyMinimalDisclosure({
      ...packet,
      visible: [
        { field: "action", value: "open", proof: proofFor("action") },
      ],
      summary: { ...packet.summary, fields_total: 1, proofs_verified: 1 },
    })
  );
  await assert.rejects(() =>
    verifyMinimalDisclosure({
      ...packet,
      summary: { ...packet.summary, minimal_disclosure: false },
    })
  );
});

test("browser verifier validates least privilege audits", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const bundlePayload = bundle.payload;
  const trusted = [bundlePayload.issuer];
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-1",
    agent: "robot-1",
    target: "urn:space:door-1",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const expectedPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: bundlePayload.rules,
            trusted_policy_issuers: trusted.sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const capability = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
    nonce: "least-privilege-nonce-0000000000",
    actions: ["open"],
    purposes: ["delivery"],
    target: request.target,
  });
  const receipt = buildReceipt(privateKey, publicKey, {
    capabilityId: capability.payload.capability_id,
    requestDigest: capability.payload.request_digest,
    evidenceHash: "sha256:" + "a".repeat(64),
    target: request.target,
  });
  const packet = {
    type: "kinegrant:LeastPrivilegeAuditPacket",
    schema_version: "0.1",
    device_id: "device:esp32c3:paper-barrier:unit-1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    trusted_authorities: trusted,
    policy_bundle: bundle,
    request,
    capability,
    receipt,
    summary: {
      artifacts_total: 5,
      capability_verified: true,
      policy_bound: true,
      request_bound: true,
      actions_minimal: true,
      purposes_minimal: true,
      targets_minimal: true,
      scope_minimal: true,
      receipt_bound: true,
    },
  };
  const result = await verifyLeastPrivilegeAudit(packet);
  assert.equal(result.request_action, "open");
  assert.equal(result.request_target, "urn:space:door-1");

  const wideCapability = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
    nonce: "wide-privilege-nonce-0000000000",
    actions: ["open", "close"],
    purposes: ["delivery"],
    target: request.target,
  });
  await assert.rejects(() =>
    verifyLeastPrivilegeAudit({ ...packet, capability: wideCapability })
  );
  const globCapability = buildScopedCapability(privateKey, publicKey, request, {
    policyDigest: expectedPolicyDigest,
    matchedPolicyIds: [bundlePayload.policy_id],
    nonce: "glob-privilege-nonce-00000000000",
    actions: ["open"],
    purposes: ["delivery"],
    target: "urn:space:door-*",
  });
  await assert.rejects(() =>
    verifyLeastPrivilegeAudit({ ...packet, capability: globCapability })
  );
  await assert.rejects(() =>
    verifyLeastPrivilegeAudit({
      ...packet,
      summary: { ...packet.summary, scope_minimal: false },
    })
  );
});

test("browser verifier validates denial explainability packets", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bundle = buildBundle(privateKey, publicKey);
  const bundlePayload = bundle.payload;
  const trusted = [bundlePayload.issuer];
  const expectedPolicyDigest =
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          canonicalJson({
            rules: bundlePayload.rules,
            trusted_policy_issuers: trusted.sort(),
          }),
          "utf8"
        )
      )
      .digest("hex");
  const packet = {
    type: "kinegrant:DenialExplainabilityPacket",
    schema_version: "0.1",
    device_id: "device:esp32c3:paper-barrier:unit-1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    trusted_authorities: trusted,
    policy_bundle: bundle,
    denials: [
      {
        denial_id: "denial-1",
        denied_at: "2026-08-15T00:10:00Z",
        request_digest: "sha256:" + "1".repeat(64),
        policy_digest: expectedPolicyDigest,
        rule_id: bundlePayload.rules[0].policy_id,
        reason: "denied",
        explanation: "rule matched and denied the request",
      },
      {
        denial_id: "denial-2",
        denied_at: "2026-08-15T00:11:00Z",
        request_digest: "sha256:" + "2".repeat(64),
        policy_digest: expectedPolicyDigest,
        rule_id: null,
        reason: "unknown_action",
        explanation: "the requested action is not in the known action vocabulary",
      },
    ],
    summary: {
      artifacts_total: 3,
      denials_total: 2,
      reasons_explained: 2,
      explanations_complete: 2,
      rules_referenced: 1,
      policy_bound: true,
      request_bound: true,
    },
  };
  const result = await verifyDenialExplainability(packet);
  assert.equal(result.denials_total, 2);
  assert.equal(result.rules_referenced, 1);

  await assert.rejects(() =>
    verifyDenialExplainability({
      ...packet,
      denials: [
        ...packet.denials,
        {
          denial_id: "denial-3",
          denied_at: "2026-08-15T00:12:00Z",
          request_digest: "sha256:" + "3".repeat(64),
          policy_digest: expectedPolicyDigest,
          rule_id: "urn:policy:not-in-bundle",
          reason: "denied",
          explanation: "references an unknown rule",
        },
      ],
      summary: { ...packet.summary },
    })
  );
  await assert.rejects(() =>
    verifyDenialExplainability({
      ...packet,
      denials: [
        { ...packet.denials[0], explanation: "" },
        packet.denials[1],
      ],
      summary: { ...packet.summary },
    })
  );
  await assert.rejects(() =>
    verifyDenialExplainability({
      ...packet,
      summary: { ...packet.summary, rules_referenced: 2 },
    })
  );
});

test("browser verifier validates policy diff audits", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const oldBundle = buildBundle(privateKey, publicKey, { version: 1 });
  const oldPayload = oldBundle.payload;
  const newBundle = buildBundle(privateKey, publicKey, {
    version: 2,
    previousVersionDigest: oldPayload.policy_digest,
    purposes: ["delivery", "maintenance"],
    extraRules: [
      {
        policy_id: "urn:policy:browser:rule-2",
        issuer: oldPayload.issuer,
        target: "urn:space:door-2",
        effect: "deny",
        actions: ["close"],
        subjects: ["*"],
        purposes: ["maintenance"],
        constraints: {},
        obligations: [],
        priority: 1,
        source: {},
      },
    ],
  });
  const newPayload = newBundle.payload;
  const packet = {
    type: "kinegrant:PolicyDiffAuditPacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T02:00:00Z",
    overall_result: "PASS",
    trusted_authorities: [oldPayload.issuer],
    old_policy_bundle: oldBundle,
    new_policy_bundle: newBundle,
    diff: {
      added_rule_ids: ["urn:policy:browser:rule-2"],
      removed_rule_ids: [],
      unchanged_rule_ids: [],
      changed_rule_ids: ["urn:policy:browser"],
    },
    summary: {
      artifacts_total: 4,
      rules_total: 2,
      rules_added: 1,
      rules_removed: 0,
      rules_unchanged: 0,
      rules_changed: 1,
      version_chain: true,
      diff_complete: true,
      policy_bound: true,
    },
  };
  const result = await verifyPolicyDiffAudit(packet);
  assert.equal(result.old_version, 1);
  assert.equal(result.new_version, 2);
  assert.deepEqual(result.added, ["urn:policy:browser:rule-2"]);
  assert.deepEqual(result.changed, ["urn:policy:browser"]);

  await assert.rejects(() =>
    verifyPolicyDiffAudit({
      ...packet,
      diff: {
        ...packet.diff,
        added_rule_ids: ["urn:policy:browser:rule-2", "urn:policy:ghost"],
      },
      summary: { ...packet.summary },
    })
  );
  await assert.rejects(() =>
    verifyPolicyDiffAudit({
      ...packet,
      summary: { ...packet.summary, rules_added: 2 },
    })
  );
  const brokenChain = buildBundle(privateKey, publicKey, {
    version: 2,
    previousVersionDigest: "sha256:" + "0".repeat(64),
  });
  await assert.rejects(() =>
    verifyPolicyDiffAudit({
      ...packet,
      new_policy_bundle: brokenChain,
      diff: {
        ...packet.diff,
        added_rule_ids: [],
        changed_rule_ids: [],
        unchanged_rule_ids: ["urn:policy:browser"],
      },
      summary: {
        ...packet.summary,
        rules_total: 1,
        rules_added: 0,
        rules_changed: 0,
        rules_unchanged: 1,
      },
    })
  );
});

test("browser verifier validates robot demo reports", () => {
  const report = {
    type: "kinegrant:RobotDemoReport",
    schema_version: "0.1",
    overall_result: "PASS",
    summary: { total: 2, passed: 2, failed: 0 },
    actuator_calls: { ros2: 1, matter: 0 },
    obligation_compliance_ok: true,
    outcomes: buildRobotOutcomes(),
    limitations: ["software simulation only"],
  };
  const result = verifyRobotDemoReport(report);
  assert.equal(result.overall_result, "PASS");
  assert.equal(result.actuator_calls, 2);
  report.summary.passed = 1;
  assert.throws(() => verifyRobotDemoReport(report));
  report.summary.passed = 2;
  report.obligation_compliance_ok = false;
  report.overall_result = "PASS";
  assert.throws(() => verifyRobotDemoReport(report));
  report.obligation_compliance_ok = true;
  report.outcomes[0].actuator_calls = -1;
  assert.throws(() => verifyRobotDemoReport(report));
});

test("browser verifier validates camera consent traces", () => {
  const trace = {
    scenario: "camera-consent",
    record_allowed: true,
    record_consumed: true,
    train_policy_denied: true,
    train_sequence_denied: true,
    obligation_compliant: true,
    passed: true,
  };
  const result = verifyCameraConsentTrace(trace);
  assert.equal(result.passed, true);
  trace.passed = false;
  assert.throws(() => verifyCameraConsentTrace(trace));
  trace.passed = true;
  trace.record_allowed = false;
  assert.throws(() => verifyCameraConsentTrace(trace));
  trace.record_allowed = true;
  trace.scenario = "other";
  assert.throws(() => verifyCameraConsentTrace(trace));
});

test("browser verifier validates full lifecycle reports", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const policyBundle = buildBundle(privateKey, publicKey);
  const revocationBundle = buildRevocationBundle(privateKey, publicKey);
  const distribution = {
    type: "kinegrant:PolicyDistributionReport",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: policyBundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { registries: 1, applied_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        policy_id: "urn:policy:browser",
        bundle_id: policyBundle.payload.bundle_id,
        applied: true,
        current_before: null,
        current_after: 1,
        detail: "policy bundle activated",
      },
    ],
  };
  const audit = {
    type: "kinegrant:PolicyAuditSummary",
    schema_version: "0.1",
    overall_result: "PASS",
    summary: {
      bundles_total: 1,
      verified: 1,
      failed: 0,
      analysis_failures: 0,
      coverage_failures: 0,
      findings_by_code: {},
      allowed: 0,
      denied: 1,
      exceptions: 0,
      shadowed_allows: 0,
    },
    bundles: [
      {
        label: "fleet-a",
        verified: true,
        policy_id: "urn:policy:browser",
        bundle_version: 1,
        analysis_result: "PASS",
        coverage_result: "PASS",
        error_findings: [],
        shadowed_allows: [],
        error: null,
      },
    ],
    independent_verification: {
      schema_version: "0.1",
      overall_result: "PASS",
      checks: [
        {
          tool: "kinegrant-js",
          detail: "cross-verified",
          capability: "PASS",
          receipts: "SKIP",
          policy_bundle: "PASS",
          policy_current_version: "PASS",
        },
      ],
    },
    limitations: ["self-assessment"],
  };
  const revocation = {
    type: "kinegrant:RevocationDistributionReport",
    schema_version: "0.1",
    bundle_id: revocationBundle.payload.bundle_id,
    bundle_version: 1,
    overall_result: "PASS",
    summary: { gates: 1, added_total: 1, already_present_total: 0 },
    acks: [
      {
        gate_id: "gate-a",
        bundle_id: revocationBundle.payload.bundle_id,
        applied: true,
        added_count: 1,
        already_present: 0,
        detail: "applied",
      },
    ],
  };
  const report = {
    type: "kinegrant:FullLifecycleReport",
    schema_version: "0.1",
    policy_id: "urn:policy:browser",
    bundle_id: policyBundle.payload.bundle_id,
    bundle_version: 1,
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    summary: { phases_total: 4, passed: 4, failed: 0 },
    policy_distribution: distribution,
    audit_summary: audit,
    revocation_distribution: revocation,
  };
  const result = await verifyFullLifecycleReport(
    report,
    policyBundle,
    revocationBundle,
    new Set([policyBundle.kid])
  );
  assert.equal(result.phases, 4);
  assert.equal(result.policy_id, "urn:policy:browser");
  report.summary.passed = 3;
  await assert.rejects(() =>
    verifyFullLifecycleReport(
      report,
      policyBundle,
      revocationBundle,
      new Set([policyBundle.kid])
    )
  );
  report.summary.passed = 4;
  report.audit_summary.bundles[0].policy_id = "other";
  await assert.rejects(() =>
    verifyFullLifecycleReport(
      report,
      policyBundle,
      revocationBundle,
      new Set([policyBundle.kid])
    )
  );
});

test("browser verifier validates evidence export packets", () => {
  const packet = {
    type: "kinegrant:EvidenceExportPacket",
    schema_version: "0.1",
    generated_at: "2026-08-15T01:00:00Z",
    overall_result: "PASS",
    artifacts: [
      {
        kind: "mpt_evidence",
        name: "machine-permission-test.evidence.json",
        sha256: "sha256:" + "a".repeat(64),
      },
      {
        kind: "conformance_report",
        name: "conformance-report.json",
        sha256: "sha256:" + "b".repeat(64),
      },
    ],
    summary: { artifacts_total: 2, unique_kinds: 2, digest_verified: true },
  };
  const result = verifyEvidenceExportPacket(packet);
  assert.equal(result.artifacts, 2);
  assert.equal(result.unique_kinds, 2);
  packet.artifacts[1].name = packet.artifacts[0].name;
  assert.throws(() => verifyEvidenceExportPacket(packet));
  packet.artifacts[1].name = "conformance-report.json";
  packet.summary.artifacts_total = 1;
  assert.throws(() => verifyEvidenceExportPacket(packet));
  packet.summary.artifacts_total = 2;
  packet.artifacts[0].sha256 = "sha256:" + "x".repeat(63);
  assert.throws(() => verifyEvidenceExportPacket(packet));
});
