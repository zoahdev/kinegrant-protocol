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
  verifyPolicyBundle,
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
