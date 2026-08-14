import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { canonicalJson } from "../src/jcs.mjs";
import {
  contentId,
  publicKeyFromKid,
  verifyCapability,
  verifyEnvelope,
  verifyReceiptChain,
} from "../src/verify.mjs";

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
  const data = Buffer.concat([DOMAIN, Buffer.from(canonicalJson(protectedData), "utf8")]);
  const signature = sign(null, data, privateKey);
  return { alg: "EdDSA", kid, payload, signature: b64url(signature) };
}

test("JCS canonicalizes objects and arrays", () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJson([3, 1, 2]), "[3,1,2]");
  assert.equal(canonicalJson({ x: -0 }), '{"x":0}');
  assert.equal(canonicalJson({ x: "a\u2028b" }), '{"x":"a\\u2028b"}');
});

test("envelope round trip and tamper rejection", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const envelope = signEnvelope(privateKey, { hello: "world" });
  assert.deepEqual(verifyEnvelope(envelope), { hello: "world" });
  envelope.payload.hello = "tampered";
  assert.throws(() => verifyEnvelope(envelope));
});

test("public key from kid round trips", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const key = publicKeyFromKid(kidOf(publicKey));
  assert.ok(key.type === "public");
});

function buildCapability(privateKey, publicKey, request, { ttlSeconds = 300 } = {}) {
  const now = Date.now();
  const issuedAt = new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z");
  const expiresAt = new Date(now + ttlSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const body = {
    type: "kinegrant:PhysicalActionCapability",
    version: "0.1",
    issuer: kidOf(publicKey),
    agent: request.agent,
    target: request.target,
    action: request.action,
    purpose: request.purpose,
    request_digest: "sha256:" + createHash("sha256")
      .update(canonicalJson(request)).digest("hex"),
    policy_digest: "sha256:" + "0".repeat(64),
    matched_policy_ids: ["policy-1"],
    obligations: ["emitActionReceipt"],
    issued_at: issuedAt,
    not_before: issuedAt,
    expires_at: expiresAt,
    nonce: "n".repeat(24),
  };
  const unsigned = { ...body };
  body.capability_id = contentId("kinegrant:cap", unsigned);
  return signEnvelope(privateKey, body);
}

test("capability verification accepts a valid v0.1 capability", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-1",
    agent: "robot-1",
    target: "door-7",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const envelope = buildCapability(privateKey, publicKey, request);
  const payload = verifyCapability(envelope, request, new Set([envelope.kid]));
  assert.equal(payload.capability_id.startsWith("kinegrant:cap:"), true);
});

test("capability verification rejects a tampered request binding", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const request = {
    type: "kinegrant:ActionRequest",
    version: "0.1",
    request_id: "req-2",
    agent: "robot-1",
    target: "door-7",
    action: "open",
    purpose: "delivery",
    issued_at: new Date().toISOString(),
    context: {},
  };
  const envelope = buildCapability(privateKey, publicKey, request);
  const other = { ...request, request_id: "req-other" };
  assert.throws(() => verifyCapability(envelope, other, new Set([envelope.kid])));
});

test("receipt chain round trip", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const body = {
    type: "kinegrant:PhysicalActionReceipt",
    version: "0.1",
    executor: kidOf(publicKey),
    capability_id: "kinegrant:cap:" + "a".repeat(64),
    request_digest: "sha256:" + "0".repeat(64),
    agent: "robot-1",
    target: "door-7",
    action: "open",
    purpose: "delivery",
    result: "succeeded",
    started_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    evidence_hash: null,
    previous_receipt_hash: null,
  };
  const unsigned = { ...body };
  body.receipt_id = contentId("kinegrant:receipt", unsigned);
  const envelope = signEnvelope(privateKey, body);
  assert.equal(verifyReceiptChain([envelope], new Set([envelope.kid])), true);
});
