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
  verifyRobotDemoReport,
  verifyCameraConsentTrace,
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

function buildBundle(privateKey, publicKey, { version = 1, purposes = ["delivery"], constraints = {}, obligations = [], extraRules = [] } = {}) {
  const now = Date.now();
  const kid = kidOf(publicKey);
  const policyId = "urn:policy:browser";
  const body = {
    type: "kinegrant:PolicyBundle",
    schema_version: "0.1",
    policy_id: policyId,
    issuer: kid,
    version,
    previous_version_digest: null,
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
    policy_digest: "sha256:" + "0".repeat(64),
    matched_policy_ids: ["policy-1"],
    obligations: ["emitActionReceipt"],
    issued_at: issuedAt,
    not_before: issuedAt,
    expires_at: expiresAt,
    nonce: "n".repeat(32),
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

function buildSensorCommitment(privateKey, publicKey, { signed = true } = {}) {
  const readings = [
    {
      kind: "force",
      value_hash: "sha256:" + "a".repeat(64),
      source_id: "sensor-1",
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

function buildCheckpoint(privateKey, publicKey) {
  const body = {
    type: "kinegrant:ReceiptCheckpoint",
    schema_version: "0.1",
    notary: kidOf(publicKey),
    chain_digest: "sha256:" + "b".repeat(64),
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

function buildAttestation(privateKey, publicKey) {
  const body = {
    type: "kinegrant:DeviceAttestation",
    schema_version: "0.1",
    device_id: "device:esp32c3:paper-barrier:unit-1",
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

function buildReceipt(privateKey, publicKey, { capabilityId, previous = null } = {}) {
  const kid = kidOf(publicKey);
  const body = {
    type: "kinegrant:PhysicalActionReceipt",
    version: "0.1",
    executor: kid,
    capability_id: capabilityId || "kinegrant:cap:" + "a".repeat(64),
    request_digest: "sha256:" + "0".repeat(64),
    agent: "robot-1",
    target: "door-7",
    action: "open",
    purpose: "delivery",
    result: "succeeded",
    started_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    evidence_hash: null,
    previous_receipt_hash:
      previous === null
        ? null
        : "sha256:" +
          createHash("sha256")
            .update(Buffer.from(canonicalJson(previous), "utf8"))
            .digest("hex"),
  };
  const unsigned = { ...body };
  body.receipt_id =
    "kinegrant:receipt:" +
    createHash("sha256")
      .update(Buffer.from(canonicalJson(unsigned), "utf8"))
      .digest("hex");
  return signEnvelope(privateKey, body);
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

function buildRevocationBundle(privateKey, publicKey) {
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
        capability_id: "kinegrant:cap:" + "c".repeat(64),
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
