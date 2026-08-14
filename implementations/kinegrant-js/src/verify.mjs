// Independent KGP-001 verifier: signed envelopes, v0.1 capabilities, and
// receipt chains. No dependency beyond Node's crypto.

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { canonicalJson } from "./jcs.mjs";

const DOMAIN = Buffer.from("KINEGRANT-SIGNED-ENVELOPE-V1\u0000", "utf8");
const CAPABILITY_FIELDS = new Set([
  "type", "version", "issuer", "agent", "target", "action", "purpose",
  "request_digest", "policy_digest", "matched_policy_ids", "obligations",
  "issued_at", "not_before", "expires_at", "nonce", "capability_id",
]);

function b64urlDecode(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid base64url");
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const text = Buffer.from(base64, "base64").toString("latin1");
  if (text.length === 0 && value.length !== 0) throw new Error("invalid base64url");
  return Buffer.from(text, "latin1");
}

export function publicKeyFromKid(kid) {
  const prefix = "kinegrant:key:ed25519:";
  if (!kid.startsWith(prefix)) throw new Error("unsupported key identifier");
  const raw = b64urlDecode(kid.slice(prefix.length));
  if (raw.length !== 32) throw new Error("invalid Ed25519 public key length");
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

export function verifyEnvelope(envelope) {
  if (envelope?.alg !== "EdDSA") throw new Error("unsupported signature algorithm");
  const kid = envelope?.kid;
  const payload = envelope?.payload;
  const signature = envelope?.signature;
  if (typeof kid !== "string" || typeof payload !== "object" || payload === null ||
      typeof signature !== "string") {
    throw new Error("malformed signed envelope");
  }
  const protectedData = { alg: "EdDSA", kid, payload };
  const data = Buffer.concat([DOMAIN, Buffer.from(canonicalJson(protectedData), "utf8")]);
  const rawSignature = b64urlDecode(signature);
  if (rawSignature.length !== 64) throw new Error("invalid Ed25519 signature length");
  const valid = nodeVerify(null, data, publicKeyFromKid(kid), rawSignature);
  if (!valid) throw new Error("invalid signature");
  return payload;
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function contentId(prefix, value) {
  return `${prefix}:${sha256Hex(canonicalJson(value))}`;
}

function parseTime(value) {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) throw new Error("invalid time");
  return new Date(ms).getTime();
}

function digestOfObject(value) {
  return "sha256:" + sha256Hex(canonicalJson(value));
}

export function verifyCapability(envelope, request, trustedIssuers) {
  const payload = verifyEnvelope(envelope);
  const fields = new Set(Object.keys(payload));
  if (fields.size !== CAPABILITY_FIELDS.size ||
      [...fields].some((key) => !CAPABILITY_FIELDS.has(key))) {
    throw new Error("capability fields do not match the v0.1 schema");
  }
  if (payload.type !== "kinegrant:PhysicalActionCapability") {
    throw new Error("wrong capability type");
  }
  if (payload.version !== "0.1") throw new Error("unsupported capability version");
  if (payload.issuer !== envelope.kid) {
    throw new Error("capability issuer does not match signing key");
  }
  if (!trustedIssuers.has(payload.issuer)) throw new Error("untrusted capability issuer");
  const requestDigest = digestOfObject(request);
  if (payload.request_digest !== requestDigest) {
    throw new Error("capability does not authorize this request");
  }
  for (const field of ["agent", "target", "action", "purpose"]) {
    if (payload[field] !== request[field]) {
      throw new Error(`capability ${field} mismatch`);
    }
  }
  const now = Date.now();
  const issuedAt = parseTime(payload.issued_at);
  const notBefore = parseTime(payload.not_before);
  const expiresAt = parseTime(payload.expires_at);
  if (notBefore < issuedAt || expiresAt <= notBefore) {
    throw new Error("invalid capability time window");
  }
  if (expiresAt - notBefore > 300_000) {
    throw new Error("capability lifetime exceeds protocol maximum");
  }
  if (now < notBefore) throw new Error("capability is not active yet");
  if (now >= expiresAt) throw new Error("capability has expired");
  if (typeof payload.nonce !== "string" || payload.nonce.length < 20) {
    throw new Error("capability nonce is invalid");
  }
  if (!Array.isArray(payload.matched_policy_ids) || payload.matched_policy_ids.length === 0) {
    throw new Error("capability has no matching policy");
  }
  if (!Array.isArray(payload.obligations) ||
      payload.obligations.some((item) => item !== "emitActionReceipt")) {
    throw new Error("capability obligations are invalid");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(payload.policy_digest || "")) {
    throw new Error("capability policy digest is invalid");
  }
  const unsigned = { ...payload };
  delete unsigned.capability_id;
  if (payload.capability_id !== contentId("kinegrant:cap", unsigned)) {
    throw new Error("capability identifier is inconsistent");
  }
  return payload;
}

export function verifyReceiptChain(entries, trustedExecutors) {
  let previous = null;
  const seen = new Set();
  for (const envelope of entries) {
    const payload = verifyEnvelope(envelope);
    if (payload.type !== "kinegrant:PhysicalActionReceipt") {
      throw new Error("wrong receipt type");
    }
    if (payload.version !== "0.1") throw new Error("unsupported receipt version");
    if (payload.executor !== envelope.kid) {
      throw new Error("receipt executor does not match signing key");
    }
    if (trustedExecutors && !trustedExecutors.has(payload.executor)) {
      throw new Error("untrusted executor");
    }
    if (typeof payload.capability_id !== "string" || seen.has(payload.capability_id)) {
      throw new Error("duplicate terminal receipt");
    }
    seen.add(payload.capability_id);
    const unsigned = { ...payload };
    delete unsigned.receipt_id;
    if (payload.receipt_id !== contentId("kinegrant:receipt", unsigned)) {
      throw new Error("receipt identifier is inconsistent");
    }
    const expected = previous === null ? null : "sha256:" + sha256Hex(canonicalJson(previous));
    if (payload.previous_receipt_hash !== expected) {
      throw new Error("receipt chain is inconsistent");
    }
    previous = envelope;
  }
  return true;
}
