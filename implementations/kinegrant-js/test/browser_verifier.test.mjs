import { test } from "node:test";
import assert from "node:assert/strict";
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
} from "../../../verify/policy-bundle-verifier.js";

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

function buildBundle(privateKey, publicKey, { version = 1, purposes = ["delivery"] } = {}) {
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
        constraints: {},
        obligations: [],
        priority: 0,
        source: {},
      },
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
