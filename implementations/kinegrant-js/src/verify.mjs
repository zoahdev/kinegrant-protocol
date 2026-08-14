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
const CAPABILITY_FIELDS_V2 = new Set([
  ...CAPABILITY_FIELDS,
  "actions", "purposes", "parent_capability_id", "constraints", "approval_tier",
  "delegation_allowed", "max_delegation_depth", "delegate_agent", "delegation_depth",
  "root_capability_id", "delegate_allowlist",
]);
CAPABILITY_FIELDS_V2.delete("action");
CAPABILITY_FIELDS_V2.delete("purpose");
const OBLIGATION_STATUSES = new Set(["satisfied", "pending", "failed"]);
const KNOWN_OBLIGATIONS = new Set([
  "emitActionReceipt", "logAuditEvent", "preserveEvidence",
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
  const version = payload.version;
  if (version === "0.1") {
    return verifyCapabilityV1(payload, envelope, request, trustedIssuers);
  }
  if (version === "0.2" || version === "1.0") {
    return verifyCapabilityV2(payload, envelope, request, trustedIssuers);
  }
  throw new Error("unsupported capability version");
}

function requireNonEmptyString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`invalid policy rule: missing ${name}`);
  }
  return value;
}

export function verifyPolicyBundle(envelope, trustedAuthorities, { expectedPolicyId, now } = {}) {
  const payload = verifyEnvelope(envelope);
  if (payload.type !== "kinegrant:PolicyBundle") {
    throw new Error("wrong policy bundle type");
  }
  if (payload.schema_version !== "0.1") {
    throw new Error("unsupported policy bundle version");
  }
  if (payload.issuer !== envelope.kid) {
    throw new Error("policy bundle issuer does not match signing key");
  }
  if (!trustedAuthorities.has(payload.issuer)) {
    throw new Error("untrusted policy authority");
  }
  const policyId = requireNonEmptyString(payload.policy_id, "policy_id");
  if (expectedPolicyId !== undefined && policyId !== expectedPolicyId) {
    throw new Error("policy bundle is for a different policy");
  }
  if (!Number.isInteger(payload.version) || payload.version < 1) {
    throw new Error("bundle version must be a positive integer");
  }
  if (
    payload.previous_version_digest != null &&
    !/^sha256:[0-9a-f]{64}$/.test(payload.previous_version_digest)
  ) {
    throw new Error("previous_version_digest must be a sha256 digest or null");
  }
  if (!Array.isArray(payload.rules) || payload.rules.length === 0) {
    throw new Error("a policy bundle must contain at least one rule");
  }
  for (const rule of payload.rules) {
    if (typeof rule !== "object" || rule === null || Array.isArray(rule)) {
      throw new Error("each policy rule must be an object");
    }
    for (const field of ["policy_id", "issuer", "target", "effect"]) {
      requireNonEmptyString(rule[field], field);
    }
    if (
      !Array.isArray(rule.actions) ||
      rule.actions.length === 0 ||
      rule.actions.some((action) => typeof action !== "string")
    ) {
      throw new Error("invalid policy rule: actions must be a non-empty string array");
    }
  }
  const expectedDigest = "sha256:" + sha256Hex(canonicalJson({ rules: payload.rules }));
  if (payload.policy_digest !== expectedDigest) {
    throw new Error("policy rules do not match the signed digest");
  }
  const notBefore = parseTime(payload.not_before);
  const notAfter = parseTime(payload.not_after);
  if (!(notAfter > notBefore)) {
    throw new Error("invalid policy bundle time window");
  }
  const current = now !== undefined ? now : Date.now();
  if (current < notBefore) {
    throw new Error("policy bundle is not active yet");
  }
  if (current >= notAfter) {
    throw new Error("policy bundle has expired");
  }
  return payload;
}

export function currentPolicyVersion(payloads, { revoked = [], now } = {}) {
  const revokedSet = new Set(revoked);
  const current = now !== undefined ? now : Date.now();
  let best = null;
  for (const payload of payloads) {
    if (typeof payload.policy_id !== "string" || payload.policy_id.length === 0) {
      throw new Error("payload is missing policy_id");
    }
    const policyId = payload.policy_id;
    if (!Number.isInteger(payload.version) || payload.version < 1) {
      throw new Error("bundle version must be a positive integer");
    }
    if (revokedSet.has(`${policyId}:${payload.version}`)) continue;
    const notBefore = parseTime(payload.not_before);
    const notAfter = parseTime(payload.not_after);
    if (current < notBefore || current >= notAfter) continue;
    if (best === null || payload.version > best.version) best = payload;
  }
  return best;
}

function verifyCapabilityV1(payload, envelope, request, trustedIssuers) {
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
      payload.obligations.some((item) => !KNOWN_OBLIGATIONS.has(item))) {
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

function globMatch(pattern, value) {
  if (pattern === "*") return true;
  const escaped = pattern.split("*").map((part) =>
    part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  ).join(".*");
  return new RegExp(`^${escaped}$`).test(value);
}

function verifyCapabilityV2(payload, envelope, request, trustedIssuers) {
  const fields = new Set(Object.keys(payload));
  if (fields.size !== CAPABILITY_FIELDS_V2.size ||
      [...fields].some((key) => !CAPABILITY_FIELDS_V2.has(key))) {
    throw new Error("capability fields do not match the scoped schema");
  }
  if (payload.type !== "kinegrant:PhysicalActionCapability") {
    throw new Error("wrong capability type");
  }
  if (payload.issuer !== envelope.kid) {
    throw new Error("capability issuer does not match signing key");
  }
  if (!trustedIssuers.has(payload.issuer)) {
    throw new Error("untrusted capability issuer");
  }
  const requestDigest = digestOfObject(request);
  if (payload.request_digest !== requestDigest) {
    throw new Error("capability does not authorize this request");
  }
  if (payload.agent !== request.agent) {
    throw new Error("capability agent mismatch");
  }
  if (!globMatch(payload.target, request.target)) {
    throw new Error("capability target scope mismatch");
  }
  if (!Array.isArray(payload.actions) || !payload.actions.includes(request.action)) {
    throw new Error("capability action scope mismatch");
  }
  if (!Array.isArray(payload.purposes) || !payload.purposes.includes(request.purpose)) {
    throw new Error("capability purpose scope mismatch");
  }
  const parentId = payload.parent_capability_id;
  if (parentId !== null && (typeof parentId !== "string" || parentId.length === 0)) {
    throw new Error("capability parent id must be a string or null");
  }
  const constraints = payload.constraints;
  if (typeof constraints !== "object" || constraints === null || Array.isArray(constraints)) {
    throw new Error("capability constraints must be an object");
  }
  for (const name of ["max_force_newtons", "max_velocity_mps"]) {
    const value = constraints[name];
    if (value !== undefined && (typeof value !== "number" || value < 0)) {
      throw new Error(`capability ${name} must be a non-negative number`);
    }
  }
  const zones = constraints.allowed_zones;
  if (zones !== undefined && (!Array.isArray(zones) || zones.length === 0 ||
      zones.some((zone) => typeof zone !== "string" || zone.length === 0))) {
    throw new Error("capability allowed_zones must be a non-empty list");
  }
  const tier = payload.approval_tier;
  if (!Number.isInteger(tier) || tier < 0 || tier > 2) {
    throw new Error("capability approval_tier must be an integer between 0 and 2");
  }
  if (typeof payload.delegation_allowed !== "boolean") {
    throw new Error("capability delegation_allowed must be a boolean");
  }
  const maxDepth = payload.max_delegation_depth;
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > 3) {
    throw new Error("capability max_delegation_depth must be an integer between 0 and 3");
  }
  const depth = payload.delegation_depth;
  if (!Number.isInteger(depth) || depth < 0 || depth > 3) {
    throw new Error("capability delegation_depth must be an integer between 0 and 3");
  }
  const delegate = payload.delegate_agent;
  if (delegate !== null && (typeof delegate !== "string" || delegate.length === 0)) {
    throw new Error("capability delegate_agent must be a non-empty string or null");
  }
  if (typeof payload.root_capability_id !== "string" || payload.root_capability_id.length === 0) {
    throw new Error("capability root_capability_id must be a non-empty string");
  }
  const allowlist = payload.delegate_allowlist;
  if (allowlist !== null && (!Array.isArray(allowlist) ||
      allowlist.some((item) => typeof item !== "string" || item.length === 0))) {
    throw new Error("capability delegate_allowlist must be a list or null");
  }
  validateCommon(payload, request, envelope);
  return payload;
}

function validateCommon(payload, request, envelope) {
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
      payload.obligations.some((item) => !KNOWN_OBLIGATIONS.has(item))) {
    throw new Error("capability obligations are invalid");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(payload.policy_digest || "")) {
    throw new Error("capability policy digest is invalid");
  }
  const unsigned = { ...payload };
  delete unsigned.capability_id;
  delete unsigned.root_capability_id;
  if (payload.capability_id !== contentId("kinegrant:cap", unsigned)) {
    throw new Error("capability identifier is inconsistent");
  }
}

export function verifyReceiptChain(entries, trustedExecutors) {
  let previous = null;
  const seen = new Set();
  for (const envelope of entries) {
    const payload = verifyEnvelope(envelope);
    if (payload.type !== "kinegrant:PhysicalActionReceipt") {
      throw new Error("wrong receipt type");
    }
    if (payload.version !== "0.1" && payload.version !== "1.0") {
      throw new Error("unsupported receipt version");
    }
    if (payload.version === "1.0") validateReceiptV10(payload);
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

function validateReceiptV10(payload) {
  const hasObligations = Object.prototype.hasOwnProperty.call(
    payload, "obligation_results",
  );
  const hasFailureReason = Object.prototype.hasOwnProperty.call(
    payload, "failure_reason",
  );
  if (!hasObligations && !hasFailureReason) {
    throw new Error("receipt 1.0 requires an additive extension");
  }
  if (hasFailureReason) {
    const reason = payload.failure_reason;
    if (typeof reason !== "string" || reason.length === 0) {
      throw new Error("receipt failure_reason is invalid");
    }
  }
  if (hasObligations) {
    const results = payload.obligation_results;
    if (!Array.isArray(results) || results.length === 0) {
      throw new Error("receipt obligation_results are invalid");
    }
    for (const item of results) {
      if (typeof item !== "object" || item === null) {
        throw new Error("receipt obligation result must be an object");
      }
      const allowed = new Set(["obligation", "status", "failure_reason"]);
      if (Object.keys(item).some((key) => !allowed.has(key))) {
        throw new Error("receipt obligation result has unknown fields");
      }
      if (!KNOWN_OBLIGATIONS.has(item.obligation)) {
        throw new Error("receipt obligation is unknown");
      }
      if (!OBLIGATION_STATUSES.has(item.status)) {
        throw new Error("receipt obligation status is invalid");
      }
      const reason = item.failure_reason;
      if (reason !== undefined && reason !== null &&
          (typeof reason !== "string" || reason.length === 0)) {
        throw new Error("receipt obligation failure_reason is invalid");
      }
      if (item.status === "failed" &&
          (typeof reason !== "string" || reason.length === 0)) {
        throw new Error("a failed obligation requires a failure_reason");
      }
    }
  }
}
