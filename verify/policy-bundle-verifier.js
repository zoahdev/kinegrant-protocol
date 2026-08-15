// Universal (browser + Node) verifier for KineGrant policy bundles.
// Zero dependencies: RFC 8785 JCS subset + WebCrypto Ed25519 + SHA-256.
// Works offline and can be embedded in a static page.

const DOMAIN = "KINEGRANT-SIGNED-ENVELOPE-V1\u0000";
const MLDSA65_SPKI_HEADER_B64 = "MIIHsjALBglghkgBZQMEAxIDggehAA==";
const CAPABILITY_FIELDS = new Set([
  "type", "version", "issuer", "agent", "target", "action", "purpose",
  "request_digest", "policy_digest", "matched_policy_ids", "obligations",
  "issued_at", "not_before", "expires_at", "nonce", "capability_id",
]);
const CAPABILITY_FIELDS_V2 = new Set([
  ...CAPABILITY_FIELDS,
  "actions", "purposes", "parent_capability_id", "constraints", "approval_tier",
  "delegation_allowed", "max_delegation_depth", "delegate_agent",
  "delegation_depth", "root_capability_id", "delegate_allowlist",
]);
CAPABILITY_FIELDS_V2.delete("action");
CAPABILITY_FIELDS_V2.delete("purpose");
const KNOWN_OBLIGATIONS = new Set([
  "emitActionReceipt", "logAuditEvent", "preserveEvidence",
]);
const OBLIGATION_STATUSES = new Set(["satisfied", "pending", "failed"]);

function escapeJsonString(value) {
  return JSON.stringify(value)
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

export function canonicalJson(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return escapeJsonString(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    if (Object.is(value, -0)) return "0";
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys
        .map((key) => escapeJsonString(key) + ":" + canonicalJson(value[key]))
        .join(",") +
      "}"
    );
  }
  throw new Error("cannot canonicalize " + typeof value);
}

function b64urlDecode(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid base64url");
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function parseTime(value) {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) throw new Error("invalid time");
  return ms;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function digestOfObject(value) {
  return "sha256:" + (await sha256Hex(new TextEncoder().encode(canonicalJson(value))));
}

async function contentId(prefix, value) {
  return prefix + ":" + (await sha256Hex(new TextEncoder().encode(canonicalJson(value))));
}

function globMatch(pattern, value) {
  if (pattern === "*") return true;
  const escaped = pattern
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`).test(value);
}

function mldsa65Spki(rawKey) {
  const header = atob(MLDSA65_SPKI_HEADER_B64);
  const spki = new Uint8Array(header.length + rawKey.length);
  for (let index = 0; index < header.length; index += 1) {
    spki[index] = header.charCodeAt(index);
  }
  spki.set(rawKey, header.length);
  return spki;
}

async function verifyEnvelope(envelope) {
  const alg = envelope?.alg;
  if (alg !== "EdDSA" && alg !== "ML-DSA-65") {
    throw new Error("unsupported signature algorithm");
  }
  const kid = envelope?.kid;
  const payload = envelope?.payload;
  const signature = envelope?.signature;
  if (
    typeof kid !== "string" ||
    typeof payload !== "object" ||
    payload === null ||
    typeof signature !== "string"
  ) {
    throw new Error("malformed signed envelope");
  }
  const canonical = canonicalJson({ alg, kid, payload });
  const data = new TextEncoder().encode(DOMAIN + canonical);
  if (alg === "ML-DSA-65") {
    const prefix = "kinegrant:key:mldsa65:";
    if (!kid.startsWith(prefix)) throw new Error("unsupported key identifier");
    const rawKey = b64urlDecode(kid.slice(prefix.length));
    if (rawKey.length !== 1952) {
      throw new Error("invalid ML-DSA-65 public key length");
    }
    const rawSignature = b64urlDecode(signature);
    if (rawSignature.length !== 3309) {
      throw new Error("invalid ML-DSA-65 signature length");
    }
    let key;
    try {
      key = await crypto.subtle.importKey(
        "spki",
        mldsa65Spki(rawKey),
        { name: "ML-DSA-65" },
        false,
        ["verify"]
      );
    } catch (error) {
      throw new Error(
        "ML-DSA-65 is not supported by this browser's WebCrypto: " +
          error.message
      );
    }
    const valid = await crypto.subtle.verify("ML-DSA-65", key, rawSignature, data);
    if (!valid) throw new Error("invalid signature");
    return payload;
  }
  const prefix = "kinegrant:key:ed25519:";
  if (!kid.startsWith(prefix)) throw new Error("unsupported key identifier");
  const rawKey = b64urlDecode(kid.slice(prefix.length));
  if (rawKey.length !== 32) throw new Error("invalid Ed25519 public key length");
  const key = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  const rawSignature = b64urlDecode(signature);
  if (rawSignature.length !== 64) throw new Error("invalid Ed25519 signature length");
  const valid = await crypto.subtle.verify("Ed25519", key, rawSignature, data);
  if (!valid) throw new Error("invalid signature");
  return payload;
}

function requireNonEmptyString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`invalid policy rule: missing ${name}`);
  }
  return value;
}

export async function verifyPolicyBundle(
  bundle,
  trustedAuthorities,
  { expectedPolicyId, now } = {}
) {
  const payload = await verifyEnvelope(bundle);
  if (payload.type !== "kinegrant:PolicyBundle") {
    throw new Error("wrong policy bundle type");
  }
  if (payload.schema_version !== "0.1") {
    throw new Error("unsupported policy bundle version");
  }
  if (payload.issuer !== bundle.kid) {
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
  const expectedDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(canonicalJson({ rules: payload.rules }))
    ));
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
    if (!Number.isInteger(payload.version) || payload.version < 1) {
      throw new Error("bundle version must be a positive integer");
    }
    if (revokedSet.has(`${payload.policy_id}:${payload.version}`)) continue;
    const notBefore = parseTime(payload.not_before);
    const notAfter = parseTime(payload.not_after);
    if (current < notBefore || current >= notAfter) continue;
    if (best === null || payload.version > best.version) best = payload;
  }
  return best;
}

async function validateCommon(payload, request, envelope) {
  const now = Date.now();
  const issuedAt = parseTime(payload.issued_at);
  const notBefore = parseTime(payload.not_before);
  const expiresAt = parseTime(payload.expires_at);
  if (notBefore < issuedAt || expiresAt <= notBefore) {
    throw new Error("invalid capability time window");
  }
  if (expiresAt - notBefore > 300000) {
    throw new Error("capability lifetime exceeds protocol maximum");
  }
  if (now < notBefore) throw new Error("capability is not active yet");
  if (now >= expiresAt) throw new Error("capability has expired");
  if (typeof payload.nonce !== "string" || payload.nonce.length < 20) {
    throw new Error("capability nonce is invalid");
  }
  if (
    !Array.isArray(payload.matched_policy_ids) ||
    payload.matched_policy_ids.length === 0
  ) {
    throw new Error("capability has no matching policy");
  }
  if (
    !Array.isArray(payload.obligations) ||
    payload.obligations.some((item) => !KNOWN_OBLIGATIONS.has(item))
  ) {
    throw new Error("capability obligations are invalid");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(payload.policy_digest || "")) {
    throw new Error("capability policy digest is invalid");
  }
  const unsigned = { ...payload };
  delete unsigned.capability_id;
  delete unsigned.root_capability_id;
  const expected = await contentId("kinegrant:cap", unsigned);
  if (payload.capability_id !== expected) {
    throw new Error("capability identifier is inconsistent");
  }
}

async function verifyCapabilityV1(payload, envelope, request, trustedIssuers) {
  const fields = new Set(Object.keys(payload));
  if (
    fields.size !== CAPABILITY_FIELDS.size ||
    [...fields].some((key) => !CAPABILITY_FIELDS.has(key))
  ) {
    throw new Error("capability fields do not match the v0.1 schema");
  }
  if (payload.type !== "kinegrant:PhysicalActionCapability") {
    throw new Error("wrong capability type");
  }
  if (payload.version !== "0.1") throw new Error("unsupported capability version");
  if (payload.issuer !== envelope.kid) {
    throw new Error("capability issuer does not match signing key");
  }
  if (!trustedIssuers.has(payload.issuer)) {
    throw new Error("untrusted capability issuer");
  }
  const requestDigest = await digestOfObject(request);
  if (payload.request_digest !== requestDigest) {
    throw new Error("capability does not authorize this request");
  }
  for (const field of ["agent", "target", "action", "purpose"]) {
    if (payload[field] !== request[field]) {
      throw new Error(`capability ${field} mismatch`);
    }
  }
  await validateCommon(payload, request, envelope);
  const unsigned = { ...payload };
  delete unsigned.capability_id;
  const expected = await contentId("kinegrant:cap", unsigned);
  if (payload.capability_id !== expected) {
    throw new Error("capability identifier is inconsistent");
  }
  return payload;
}

function validateScopedCapabilityStructure(payload) {
  const fields = new Set(Object.keys(payload));
  if (
    fields.size !== CAPABILITY_FIELDS_V2.size ||
    [...fields].some((key) => !CAPABILITY_FIELDS_V2.has(key))
  ) {
    throw new Error("capability fields do not match the scoped schema");
  }
  if (payload.type !== "kinegrant:PhysicalActionCapability") {
    throw new Error("wrong capability type");
  }
  if (typeof payload.target !== "string" || payload.target.length === 0) {
    throw new Error("capability target must be a non-empty string");
  }
  if (
    !Array.isArray(payload.actions) ||
    payload.actions.length === 0 ||
    payload.actions.some(
      (action) => typeof action !== "string" || action.length === 0
    )
  ) {
    throw new Error("capability actions must be a non-empty string array");
  }
  if (
    !Array.isArray(payload.purposes) ||
    payload.purposes.length === 0 ||
    payload.purposes.some(
      (purpose) => typeof purpose !== "string" || purpose.length === 0
    )
  ) {
    throw new Error("capability purposes must be a non-empty string array");
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
  if (
    zones !== undefined &&
    (!Array.isArray(zones) ||
      zones.length === 0 ||
      zones.some((zone) => typeof zone !== "string" || zone.length === 0))
  ) {
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
  if (
    allowlist !== null &&
    (!Array.isArray(allowlist) ||
      allowlist.some((item) => typeof item !== "string" || item.length === 0))
  ) {
    throw new Error("capability delegate_allowlist must be a list or null");
  }
}

async function verifyCapabilityV2(payload, envelope, request, trustedIssuers) {
  if (payload.version !== "0.2" && payload.version !== "1.0") {
    throw new Error("unsupported capability version");
  }
  validateScopedCapabilityStructure(payload);
  if (payload.issuer !== envelope.kid) {
    throw new Error("capability issuer does not match signing key");
  }
  if (!trustedIssuers.has(payload.issuer)) {
    throw new Error("untrusted capability issuer");
  }
  const requestDigest = await digestOfObject(request);
  if (payload.request_digest !== requestDigest) {
    throw new Error("capability does not authorize this request");
  }
  const delegateAgent = payload.delegate_agent;
  if (delegateAgent === null) {
    if (payload.agent !== request.agent) {
      throw new Error("capability agent mismatch");
    }
  } else if (request.agent !== delegateAgent) {
    throw new Error("capability delegate agent mismatch");
  }
  if (!globMatch(payload.target, request.target)) {
    throw new Error("capability target scope mismatch");
  }
  if (!payload.actions.includes(request.action)) {
    throw new Error("capability action scope mismatch");
  }
  if (!payload.purposes.includes(request.purpose)) {
    throw new Error("capability purpose scope mismatch");
  }
  await validateCommon(payload, request, envelope);
  return payload;
}

export async function verifyCapability(envelope, request, trustedIssuers) {
  const payload = await verifyEnvelope(envelope);
  const version = payload.version;
  if (version === "0.1") {
    return verifyCapabilityV1(payload, envelope, request, trustedIssuers);
  }
  if (version === "0.2" || version === "1.0") {
    return verifyCapabilityV2(payload, envelope, request, trustedIssuers);
  }
  throw new Error("unsupported capability version");
}

function validateReceiptV10(payload) {
  const hasObligations = Object.prototype.hasOwnProperty.call(
    payload,
    "obligation_results"
  );
  const hasFailureReason = Object.prototype.hasOwnProperty.call(
    payload,
    "failure_reason"
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
      const hasReason = Object.prototype.hasOwnProperty.call(item, "failure_reason");
      if (hasReason && (typeof reason !== "string" || reason.length === 0)) {
        throw new Error("receipt obligation failure_reason is invalid");
      }
      if (item.status === "failed" && (typeof reason !== "string" || reason.length === 0)) {
        throw new Error("a failed obligation requires a failure_reason");
      }
    }
  }
}

export async function verifyReceiptChain(entries, trustedExecutors) {
  let previous = null;
  const seen = new Set();
  for (const envelope of entries) {
    const payload = await verifyEnvelope(envelope);
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
    const expectedId = await contentId("kinegrant:receipt", unsigned);
    if (payload.receipt_id !== expectedId) {
      throw new Error("receipt identifier is inconsistent");
    }
    const expectedHash =
      previous === null
        ? null
        : "sha256:" + (await sha256Hex(new TextEncoder().encode(canonicalJson(previous))));
    if (payload.previous_receipt_hash !== expectedHash) {
      throw new Error("receipt chain is inconsistent");
    }
    previous = envelope;
  }
  return true;
}

const MPT_REQUIRED_CASES = new Set(
  Array.from({ length: 22 }, (_, index) => `MPT-${String(index + 1).padStart(3, "0")}`)
);

export function verifyMptEvidence(evidence) {
  if (typeof evidence !== "object" || evidence === null || Array.isArray(evidence)) {
    throw new Error("MPT evidence must be an object");
  }
  if (evidence.schema_version !== "0.5") {
    throw new Error("unsupported MPT evidence schema version");
  }
  if (!Array.isArray(evidence.cases) || evidence.cases.length === 0) {
    throw new Error("MPT evidence has no cases");
  }
  const identifiers = evidence.cases.map((caseItem) => caseItem.id);
  if (new Set(identifiers).size !== identifiers.length) {
    throw new Error("MPT case identifiers must be unique");
  }
  const missing = [...MPT_REQUIRED_CASES].filter(
    (required) => !identifiers.includes(required)
  );
  if (missing.length > 0) {
    throw new Error("missing required MPT cases: " + missing.join(", "));
  }
  for (const caseItem of evidence.cases) {
    if (typeof caseItem !== "object" || caseItem === null) {
      throw new Error("each MPT case must be an object");
    }
    for (const field of ["id", "name", "expected", "observed"]) {
      if (typeof caseItem[field] !== "string" || caseItem[field].length === 0) {
        throw new Error(`MPT case ${field} is invalid`);
      }
    }
    if (typeof caseItem.passed !== "boolean") {
      throw new Error("MPT case passed flag is invalid");
    }
  }
  const passed = evidence.cases.filter((caseItem) => caseItem.passed).length;
  const failed = evidence.cases.length - passed;
  const summary = evidence.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    summary.total !== evidence.cases.length ||
    summary.passed !== passed ||
    summary.failed !== failed
  ) {
    throw new Error("MPT summary is inconsistent with case results");
  }
  const expectedResult = failed === 0 ? "PASS" : "FAIL";
  if (evidence.overall_result !== expectedResult) {
    throw new Error("MPT overall_result is inconsistent with case results");
  }
  return {
    run_id: evidence.run_id,
    overall_result: evidence.overall_result,
    summary: evidence.summary,
  };
}

export async function verifyRevocationBundle(bundle, trustedAuthorities) {
  const payload = await verifyEnvelope(bundle);
  if (payload.type !== "kinegrant:RevocationBundle") {
    throw new Error("wrong revocation bundle type");
  }
  if (payload.schema_version !== "0.1") {
    throw new Error("unsupported revocation bundle version");
  }
  if (payload.issuer !== bundle.kid) {
    throw new Error("revocation bundle issuer does not match signing key");
  }
  if (!trustedAuthorities.has(payload.issuer)) {
    throw new Error("untrusted revocation authority");
  }
  if (!Number.isInteger(payload.version) || payload.version < 1) {
    throw new Error("bundle version must be a positive integer");
  }
  if (
    payload.previous_bundle_digest != null &&
    !/^sha256:[0-9a-f]{64}$/.test(payload.previous_bundle_digest)
  ) {
    throw new Error("previous_bundle_digest must be a sha256 digest or null");
  }
  if (!Array.isArray(payload.revocations)) {
    throw new Error("revocations must be an array");
  }
  for (const entry of payload.revocations) {
    if (typeof entry !== "object" || entry === null) {
      throw new Error("each revocation entry must be an object");
    }
    if (typeof entry.capability_id !== "string" || entry.capability_id.length === 0) {
      throw new Error("revocation capability_id is invalid");
    }
    if (
      entry.reason !== null &&
      (typeof entry.reason !== "string" || entry.reason.length === 0)
    ) {
      throw new Error("revocation reason is invalid");
    }
    if (typeof entry.at !== "string" || Number.isNaN(Date.parse(entry.at))) {
      throw new Error("revocation timestamp is invalid");
    }
  }
  const unsigned = { ...payload };
  delete unsigned.bundle_id;
  const expected = await contentId("kinegrant:revocation-bundle", unsigned);
  if (payload.bundle_id !== expected) {
    throw new Error("revocation bundle identifier is inconsistent");
  }
  return payload;
}

export async function verifyPolicyDistributionReport(
  report,
  bundle,
  trustedAuthorities,
  { now } = {}
) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("policy distribution report must be an object");
  }
  if (report.type !== "kinegrant:PolicyDistributionReport") {
    throw new Error("wrong policy distribution report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported policy distribution report version");
  }
  if (report.overall_result !== "PASS") {
    throw new Error("policy distribution report is not PASS");
  }
  const payload = await verifyPolicyBundle(bundle, trustedAuthorities, { now });
  if (report.policy_id !== payload.policy_id) {
    throw new Error("policy distribution report references a different policy");
  }
  if (report.bundle_id !== payload.bundle_id) {
    throw new Error("policy distribution report references a different bundle");
  }
  if (report.bundle_version !== payload.version) {
    throw new Error("policy distribution report references a different version");
  }
  if (!Array.isArray(report.acks) || report.acks.length === 0) {
    throw new Error("policy distribution report has no acknowledgements");
  }
  for (const ack of report.acks) {
    if (typeof ack !== "object" || ack === null) {
      throw new Error("each acknowledgement must be an object");
    }
    if (typeof ack.gate_id !== "string" || ack.gate_id.length === 0) {
      throw new Error("acknowledgement gate_id is invalid");
    }
    if (ack.policy_id !== payload.policy_id || ack.bundle_id !== payload.bundle_id) {
      throw new Error("acknowledgement references a different bundle");
    }
    if (typeof ack.applied !== "boolean") {
      throw new Error("acknowledgement applied flag is invalid");
    }
  }
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null) {
    throw new Error("policy distribution report summary is invalid");
  }
  if (summary.registries !== report.acks.length) {
    throw new Error("policy distribution report summary is inconsistent");
  }
  if (
    summary.applied_total !== report.acks.filter((ack) => ack.applied).length ||
    summary.already_present_total !==
      report.acks.filter((ack) => !ack.applied).length
  ) {
    throw new Error("policy distribution report summary is inconsistent");
  }
  return report;
}

export async function verifyReceiptEvidencePacket(packet) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("evidence packet must be an object");
  }
  if (packet.type !== "kinegrant:ReceiptEvidencePacket") {
    throw new Error("wrong evidence packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported evidence packet version");
  }
  if (typeof packet.summary !== "object" || packet.summary === null) {
    throw new Error("evidence packet summary is invalid");
  }
  if (!Array.isArray(packet.receipts)) {
    throw new Error("evidence packet receipts must be an array");
  }
  const seen = new Set();
  for (const receipt of packet.receipts) {
    if (typeof receipt !== "object" || receipt === null) {
      throw new Error("each receipt must be an object");
    }
    if (receipt.type !== "kinegrant:PhysicalActionReceipt") {
      throw new Error("wrong receipt type in evidence packet");
    }
    if (receipt.version !== "0.1" && receipt.version !== "1.0") {
      throw new Error("unsupported receipt version in evidence packet");
    }
    if (
      typeof receipt.capability_id !== "string" ||
      receipt.capability_id.length === 0
    ) {
      throw new Error("receipt capability_id is invalid");
    }
    if (seen.has(receipt.capability_id)) {
      throw new Error("duplicate receipt in evidence packet");
    }
    seen.add(receipt.capability_id);
    const unsigned = { ...receipt };
    delete unsigned.receipt_id;
    const expected = await contentId("kinegrant:receipt", unsigned);
    if (receipt.receipt_id !== expected) {
      throw new Error("receipt identifier is inconsistent");
    }
  }
  const unsignedPacket = { ...packet };
  delete unsignedPacket.packet_digest;
  const expectedDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(canonicalJson(unsignedPacket))
    ));
  if (packet.packet_digest !== expectedDigest) {
    throw new Error("evidence packet digest is inconsistent");
  }
  return {
    receipts: packet.receipts.length,
    packet_digest: packet.packet_digest,
  };
}

const AUDIT_CSV_COLUMNS = [
  "receipt_id",
  "capability_id",
  "agent",
  "target",
  "action",
  "purpose",
  "result",
  "started_at",
  "finished_at",
  "evidence_hash",
  "previous_receipt_hash",
  "failure_reason",
  "obligation_results",
];

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (inQuotes) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
    } else if (char === '"') {
      inQuotes = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
    } else if (char !== "\r") {
      field += char;
    }
  }
  row.push(field);
  rows.push(row);
  return rows;
}

export function verifyAuditCsv(text) {
  if (typeof text !== "string" || text.length === 0) {
    throw new Error("audit CSV text is required");
  }
  const rows = parseCsv(text);
  const header = rows[0];
  if (
    !header ||
    header.length !== AUDIT_CSV_COLUMNS.length ||
    AUDIT_CSV_COLUMNS.some((column, index) => header[index] !== column)
  ) {
    throw new Error("audit CSV header does not match the expected columns");
  }
  let dataRows = 0;
  for (const row of rows.slice(1)) {
    if (row.every((field) => field === "")) continue;
    if (row.length !== AUDIT_CSV_COLUMNS.length) {
      throw new Error("audit CSV row has inconsistent column count");
    }
    if (row[0].length === 0 || row[1].length === 0) {
      throw new Error("audit CSV row is missing receipt_id or capability_id");
    }
    dataRows += 1;
  }
  return {
    rows: dataRows,
    columns: AUDIT_CSV_COLUMNS.length,
  };
}

export function verifyReproductionReport(report) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("reproduction report must be an object");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported reproduction report version");
  }
  if (
    typeof report.report_id !== "string" ||
    !/^urn:kinegrant:reproduction:[0-9a-f-]{36}$/.test(report.report_id)
  ) {
    throw new Error("report_id is invalid");
  }
  if (
    typeof report.generated_at !== "string" ||
    Number.isNaN(Date.parse(report.generated_at))
  ) {
    throw new Error("generated_at is invalid");
  }
  if (report.protocol !== "KGP-001 Experimental Open Draft 0.1") {
    throw new Error("protocol is invalid");
  }
  if (
    typeof report.reference_implementation !== "string" ||
    !/^\d+\.\d+\.\d+$/.test(report.reference_implementation)
  ) {
    throw new Error("reference_implementation is invalid");
  }
  const source = report.source;
  if (typeof source !== "object" || source === null) {
    throw new Error("source is invalid");
  }
  if (
    source.commit !== null &&
    (typeof source.commit !== "string" ||
      !/^[0-9a-f]{40,64}$/.test(source.commit))
  ) {
    throw new Error("source commit is invalid");
  }
  if (
    source.working_tree_dirty !== null &&
    typeof source.working_tree_dirty !== "boolean"
  ) {
    throw new Error("working_tree_dirty is invalid");
  }
  const environment = report.environment;
  if (typeof environment !== "object" || environment === null) {
    throw new Error("environment is invalid");
  }
  for (const field of ["python_version", "python_implementation", "platform"]) {
    if (typeof environment[field] !== "string" || environment[field].length === 0) {
      throw new Error(`environment ${field} is invalid`);
    }
  }
  if (!Array.isArray(report.materials) || report.materials.length !== 7) {
    throw new Error("materials must contain 7 items");
  }
  for (const material of report.materials) {
    if (typeof material !== "object" || material === null) {
      throw new Error("material must be an object");
    }
    if (typeof material.path !== "string" || material.path.length === 0) {
      throw new Error("material path is invalid");
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(material.sha256 || "")) {
      throw new Error("material sha256 is invalid");
    }
  }
  if (!Array.isArray(report.artifacts) || report.artifacts.length !== 2) {
    throw new Error("artifacts must contain 2 items");
  }
  const allowedArtifacts = new Set([
    "machine-permission-test.evidence.json",
    "sample-receipt-v0.1.json",
  ]);
  for (const artifact of report.artifacts) {
    if (typeof artifact !== "object" || artifact === null) {
      throw new Error("artifact must be an object");
    }
    if (!allowedArtifacts.has(artifact.path)) {
      throw new Error("artifact path is invalid");
    }
    if (artifact.media_type !== "application/json") {
      throw new Error("artifact media_type is invalid");
    }
    if (!Number.isInteger(artifact.bytes) || artifact.bytes < 1) {
      throw new Error("artifact bytes is invalid");
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(artifact.sha256 || "")) {
      throw new Error("artifact sha256 is invalid");
    }
  }
  const verification = report.verification;
  if (typeof verification !== "object" || verification === null) {
    throw new Error("verification is invalid");
  }
  if (
    typeof verification.verifier !== "string" ||
    verification.verifier.length === 0
  ) {
    throw new Error("verifier is invalid");
  }
  if (verification.required_cases !== 22) {
    throw new Error("required_cases must be 22");
  }
  if (
    !Number.isInteger(verification.passed_cases) ||
    verification.passed_cases < 0 ||
    verification.passed_cases > 22
  ) {
    throw new Error("passed_cases is invalid");
  }
  const expectedResult = verification.passed_cases === 22 ? "PASS" : "FAIL";
  if (report.overall_result !== expectedResult) {
    throw new Error("overall_result is inconsistent");
  }
  if (!Array.isArray(report.limitations) || report.limitations.length === 0) {
    throw new Error("limitations must be non-empty");
  }
  return {
    passed_cases: verification.passed_cases,
    required_cases: verification.required_cases,
  };
}

export async function verifyRevocationDistributionReport(
  report,
  bundle,
  trustedAuthorities
) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("revocation distribution report must be an object");
  }
  if (report.type !== "kinegrant:RevocationDistributionReport") {
    throw new Error("wrong revocation distribution report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported revocation distribution report version");
  }
  if (report.overall_result !== "PASS") {
    throw new Error("revocation distribution report is not PASS");
  }
  if (bundle !== undefined && bundle !== null) {
    const payload = await verifyRevocationBundle(
      bundle,
      trustedAuthorities || new Set()
    );
    if (report.bundle_id !== payload.bundle_id) {
      throw new Error("revocation distribution report references a different bundle");
    }
    if (report.bundle_version !== payload.version) {
      throw new Error("revocation distribution report references a different version");
    }
  }
  if (!Array.isArray(report.acks) || report.acks.length === 0) {
    throw new Error("revocation distribution report has no acknowledgements");
  }
  for (const ack of report.acks) {
    if (typeof ack !== "object" || ack === null) {
      throw new Error("each acknowledgement must be an object");
    }
    if (typeof ack.gate_id !== "string" || ack.gate_id.length === 0) {
      throw new Error("acknowledgement gate_id is invalid");
    }
    if (ack.bundle_id !== report.bundle_id) {
      throw new Error("acknowledgement references a different bundle");
    }
    if (typeof ack.applied !== "boolean") {
      throw new Error("acknowledgement applied flag is invalid");
    }
    if (!Number.isInteger(ack.added_count) || ack.added_count < 0) {
      throw new Error("acknowledgement added_count is invalid");
    }
    if (!Number.isInteger(ack.already_present) || ack.already_present < 0) {
      throw new Error("acknowledgement already_present is invalid");
    }
  }
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null) {
    throw new Error("revocation distribution report summary is invalid");
  }
  if (summary.gates !== report.acks.length) {
    throw new Error("revocation distribution report summary is inconsistent");
  }
  if (
    summary.added_total !==
      report.acks.reduce((total, ack) => total + ack.added_count, 0) ||
    summary.already_present_total !==
      report.acks.reduce((total, ack) => total + ack.already_present, 0)
  ) {
    throw new Error("revocation distribution report summary is inconsistent");
  }
  return {
    gates: summary.gates,
    added_total: summary.added_total,
  };
}

function constraintToOdrl(key, value) {
  if (key === "max_force_newtons") {
    return { leftOperand: "maxForceNewtons", operator: "eq", rightOperand: value };
  }
  if (key === "max_velocity_mps") {
    return { leftOperand: "maxVelocityMps", operator: "eq", rightOperand: value };
  }
  if (key === "allowed_zones") {
    return { leftOperand: "allowedZones", operator: "eq", rightOperand: value };
  }
  if (key === "min_approval_tier") {
    return { leftOperand: "minApprovalTier", operator: "eq", rightOperand: value };
  }
  if (key === "not_before") {
    return { leftOperand: "dateTime", operator: "gt", rightOperand: value };
  }
  if (key === "not_after") {
    return { leftOperand: "dateTime", operator: "lt", rightOperand: value };
  }
  if (key === "required_context" && typeof value === "object" && value !== null) {
    return Object.keys(value).map((operand) => ({
      leftOperand: operand,
      operator: "eq",
      rightOperand: value[operand],
    }));
  }
  throw new Error("cannot serialize unknown KineGrant constraint: " + key);
}

export async function policyBundleToOdrl(
  bundle,
  trustedAuthorities,
  { now } = {}
) {
  const payload = await verifyPolicyBundle(bundle, trustedAuthorities, { now });
  const permission = [];
  const prohibition = [];
  for (const rule of payload.rules) {
    const statement = {
      target: rule.target,
      assignee: [...rule.subjects],
      action: [...rule.actions],
    };
    const constraints = [];
    for (const key of Object.keys(rule.constraints || {})) {
      const mapped = constraintToOdrl(key, rule.constraints[key]);
      if (Array.isArray(mapped)) {
        constraints.push(...mapped);
      } else {
        constraints.push(mapped);
      }
    }
    if (constraints.length > 0) {
      statement.constraint = constraints;
    }
    if (Array.isArray(rule.obligations) && rule.obligations.length > 0) {
      const duties = rule.obligations.map((obligation) => {
        if (!KNOWN_OBLIGATIONS.has(obligation)) {
          throw new Error("cannot serialize unknown obligation: " + obligation);
        }
        return { action: obligation };
      });
      statement.duty = duties;
    }
    if (rule.effect === "allow") {
      permission.push(statement);
    } else {
      prohibition.push(statement);
    }
  }
  const document = {
    "@context": "http://www.w3.org/ns/odrl/2/",
    "@type": "Offer",
    uid: payload.policy_id,
    profile: "https://kinegrant.com/profiles/odrl/kgp-v0.2",
    assigner: payload.issuer,
  };
  if (permission.length > 0) {
    document.permission = permission;
  }
  if (prohibition.length > 0) {
    document.prohibition = prohibition;
  }
  return document;
}

const ACTION_VOCABULARY = new Set([
  "kg.action.observe",
  "kg.action.record",
  "kg.action.touch",
  "kg.action.grasp",
  "kg.action.move",
  "kg.action.open",
  "kg.action.enter",
  "kg.action.retain",
  "kg.action.train_on_data",
]);

export function validateActionVocabulary(actions) {
  if (!Array.isArray(actions) || actions.length === 0) {
    throw new Error("actions must be a non-empty array");
  }
  const unknown = [];
  for (const action of actions) {
    if (typeof action !== "string") {
      throw new Error("each action must be a string");
    }
    if (!ACTION_VOCABULARY.has(action)) {
      unknown.push(action);
    }
  }
  if (unknown.length > 0) {
    throw new Error(
      "unknown actions: " +
        unknown.sort().join(", ") +
        "; known terms: " +
        [...ACTION_VOCABULARY].sort().join(", ")
    );
  }
  return {
    valid: true,
    actions: actions.length,
    known_terms: [...ACTION_VOCABULARY].sort(),
  };
}

const OBLIGATION_VOCABULARY = new Set([
  "emitActionReceipt",
  "logAuditEvent",
  "preserveEvidence",
]);

export function validateObligationVocabulary(obligations) {
  if (!Array.isArray(obligations) || obligations.length === 0) {
    throw new Error("obligations must be a non-empty array");
  }
  const unknown = [];
  for (const obligation of obligations) {
    if (typeof obligation !== "string") {
      throw new Error("each obligation must be a string");
    }
    if (!OBLIGATION_VOCABULARY.has(obligation)) {
      unknown.push(obligation);
    }
  }
  if (unknown.length > 0) {
    throw new Error(
      "unknown obligations: " +
        unknown.sort().join(", ") +
        "; known obligations: " +
        [...OBLIGATION_VOCABULARY].sort().join(", ")
    );
  }
  return {
    valid: true,
    obligations: obligations.length,
    known_obligations: [...OBLIGATION_VOCABULARY].sort(),
  };
}

const IDENTITY_KINDS = new Set(["agent", "target", "policy"]);
const IDENTITY_NAMESPACE_RE = /^[a-z0-9.-]{1,63}$/;
const IDENTITY_LOCAL_ID_RE = /^[a-z0-9._:#-]{1,128}$/;
const IDENTITY_RE =
  /^urn:kinegrant:(agent|target|policy):([a-z0-9.-]{1,63}):([a-z0-9._:#-]{1,128})$/;

export function validateIdentitySyntax(identifiers) {
  if (!Array.isArray(identifiers) || identifiers.length === 0) {
    throw new Error("identifiers must be a non-empty array");
  }
  const parsed = [];
  for (const identifier of identifiers) {
    if (typeof identifier !== "string") {
      throw new Error("each identifier must be a string");
    }
    const match = IDENTITY_RE.exec(identifier);
    if (match === null) {
      throw new Error(
        "invalid KineGrant identifier " +
          JSON.stringify(identifier) +
          "; expected urn:kinegrant:<agent|target|policy>:<namespace>:<local-id> " +
          "(namespace 1-63 chars of lowercase letters, digits, '-' or '.'; " +
          "local-id 1-128 chars of lowercase letters, digits, '-', '_', '.', ':' or '#')"
      );
    }
    const kind = match[1];
    const namespace = match[2];
    const localId = match[3];
    if (!IDENTITY_KINDS.has(kind)) {
      throw new Error(`invalid KineGrant identifier kind: ${kind}`);
    }
    if (!IDENTITY_NAMESPACE_RE.test(namespace)) {
      throw new Error(`invalid KineGrant identifier namespace: ${namespace}`);
    }
    if (!IDENTITY_LOCAL_ID_RE.test(localId)) {
      throw new Error(`invalid KineGrant identifier local-id: ${localId}`);
    }
    parsed.push({
      value: identifier,
      kind,
      namespace,
      local_id: localId,
    });
  }
  return {
    valid: true,
    count: parsed.length,
    identifiers: parsed,
  };
}

const ANALYSIS_CONSTRAINTS = new Set([
  "not_before",
  "not_after",
  "required_context",
  "requires_human_present",
  "max_risk_tier",
  "max_force_newtons",
  "max_velocity_mps",
  "allowed_zones",
  "min_approval_tier",
]);
const ANALYSIS_FINDING_CODES = new Set([
  "rule_issuer_mismatch",
  "unknown_constraint",
  "unknown_obligation",
  "broad_allow",
  "conflicting_effect",
  "duplicate_rule",
]);
const ANALYSIS_SEVERITIES = new Set(["error", "warning", "info"]);

function patternOverlaps(patternA, patternB) {
  if (patternA === patternB) return true;
  if (!patternA.includes("*") && !patternB.includes("*")) return false;
  return globMatch(patternB, patternA) || globMatch(patternA, patternB);
}

function tupleOverlaps(tupleA, tupleB) {
  if (!Array.isArray(tupleA) || !Array.isArray(tupleB)) {
    throw new Error("policy rule scopes must be arrays");
  }
  if (tupleA.includes("*") || tupleB.includes("*")) return true;
  return tupleA.some((item) => tupleB.includes(item));
}

function scopeOverlaps(ruleA, ruleB) {
  return (
    patternOverlaps(ruleA.target, ruleB.target) &&
    tupleOverlaps(ruleA.actions, ruleB.actions) &&
    tupleOverlaps(ruleA.purposes, ruleB.purposes)
  );
}

function analyzePolicyBundlePayload(payload) {
  const findings = [];
  const rules = payload.rules;
  const bundleIssuer = payload.issuer;
  for (const rule of rules) {
    if (rule.issuer !== bundleIssuer) {
      findings.push({
        severity: "error",
        code: "rule_issuer_mismatch",
        rule_ids: [rule.policy_id],
      });
    }
    if (typeof rule.constraints !== "object" || rule.constraints === null || Array.isArray(rule.constraints)) {
      throw new Error("policy rule constraints must be an object");
    }
    const unknownConstraints = Object.keys(rule.constraints).filter(
      (key) => !ANALYSIS_CONSTRAINTS.has(key)
    );
    if (unknownConstraints.length > 0) {
      findings.push({
        severity: "error",
        code: "unknown_constraint",
        rule_ids: [rule.policy_id],
      });
    }
    if (!Array.isArray(rule.obligations)) {
      throw new Error("policy rule obligations must be an array");
    }
    const unknownObligations = rule.obligations.filter(
      (obligation) => !OBLIGATION_VOCABULARY.has(obligation)
    );
    if (unknownObligations.length > 0) {
      findings.push({
        severity: "error",
        code: "unknown_obligation",
        rule_ids: [rule.policy_id],
      });
    }
    if (
      rule.effect === "allow" &&
      rule.target === "*" &&
      Array.isArray(rule.actions) &&
      rule.actions.length === 1 &&
      rule.actions[0] === "*" &&
      Array.isArray(rule.purposes) &&
      rule.purposes.length === 1 &&
      rule.purposes[0] === "*" &&
      Object.keys(rule.constraints).length === 0
    ) {
      findings.push({
        severity: "warning",
        code: "broad_allow",
        rule_ids: [rule.policy_id],
      });
    }
  }
  for (let indexA = 0; indexA < rules.length; indexA += 1) {
    for (let indexB = indexA + 1; indexB < rules.length; indexB += 1) {
      const ruleA = rules[indexA];
      const ruleB = rules[indexB];
      if (!scopeOverlaps(ruleA, ruleB)) continue;
      if (ruleA.effect !== ruleB.effect) {
        findings.push({
          severity: "error",
          code: "conflicting_effect",
          rule_ids: [ruleA.policy_id, ruleB.policy_id],
        });
      } else if (canonicalJson(ruleA) === canonicalJson(ruleB)) {
        findings.push({
          severity: "warning",
          code: "duplicate_rule",
          rule_ids: [ruleA.policy_id, ruleB.policy_id],
        });
      }
    }
  }
  return findings;
}

export async function verifyPolicyAnalysisReport(
  report,
  bundle,
  trustedAuthorities,
  { now } = {}
) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("policy analysis report must be an object");
  }
  if (report.type !== "kinegrant:PolicyBundleAnalysis") {
    throw new Error("wrong policy analysis report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported policy analysis report version");
  }
  const payload = await verifyPolicyBundle(bundle, trustedAuthorities, { now });
  if (
    report.policy_id !== payload.policy_id ||
    report.bundle_id !== payload.bundle_id ||
    report.bundle_version !== payload.version
  ) {
    throw new Error("policy analysis report does not match the policy bundle");
  }
  if (!Array.isArray(report.findings)) {
    throw new Error("policy analysis report findings must be an array");
  }
  for (const finding of report.findings) {
    if (typeof finding !== "object" || finding === null || Array.isArray(finding)) {
      throw new Error("each finding must be an object");
    }
    if (!ANALYSIS_SEVERITIES.has(finding.severity)) {
      throw new Error("unknown finding severity: " + finding.severity);
    }
    if (!ANALYSIS_FINDING_CODES.has(finding.code)) {
      throw new Error("unknown finding code: " + finding.code);
    }
    if (
      !Array.isArray(finding.rule_ids) ||
      finding.rule_ids.length === 0 ||
      finding.rule_ids.some((id) => typeof id !== "string" || id.length === 0)
    ) {
      throw new Error("finding rule_ids must be a non-empty string array");
    }
  }
  const expected = analyzePolicyBundlePayload(payload);
  const findingKey = (finding) =>
    finding.severity + "|" + finding.code + "|" + [...finding.rule_ids].sort().join(",");
  const expectedKeys = expected.map(findingKey);
  const reportKeys = report.findings.map(findingKey);
  const missing = expectedKeys.filter((key) => !reportKeys.includes(key));
  const extra = reportKeys.filter((key) => !expectedKeys.includes(key));
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(
      "policy analysis findings do not match a fresh recomputation" +
        (missing.length > 0 ? " (missing: " + missing.join(", ") + ")" : "") +
        (extra.length > 0 ? " (extra: " + extra.join(", ") + ")" : "")
    );
  }
  const errors = report.findings.filter(
    (finding) => finding.severity === "error"
  ).length;
  const warnings = report.findings.filter(
    (finding) => finding.severity === "warning"
  ).length;
  const info = report.findings.filter(
    (finding) => finding.severity === "info"
  ).length;
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("policy analysis report summary must be an object");
  }
  if (
    summary.findings !== report.findings.length ||
    summary.errors !== errors ||
    summary.warnings !== warnings ||
    summary.info !== info
  ) {
    throw new Error("policy analysis report summary is inconsistent");
  }
  const expectedResult = errors === 0 ? "PASS" : "FAIL";
  if (report.overall_result !== expectedResult) {
    throw new Error("policy analysis report overall_result is inconsistent");
  }
  return {
    valid: true,
    policy_id: report.policy_id,
    bundle_version: report.bundle_version,
    overall_result: report.overall_result,
    summary: report.summary,
    findings: report.findings,
  };
}

const CONSTRAINT_KEYS = new Set([
  "max_force_newtons",
  "max_velocity_mps",
  "allowed_zones",
]);

export function verifyAttenuation(child, parent) {
  try {
    if (parent.type !== "kinegrant:PhysicalActionCapability") return false;
    if (parent.version !== "0.2" && parent.version !== "1.0") return false;
    if (child.type !== "kinegrant:PhysicalActionCapability") return false;
    if (child.version !== "0.2" && child.version !== "1.0") return false;
    if (parent.version !== child.version) return false;
    if (child.parent_capability_id !== parent.capability_id) return false;
    if (child.root_capability_id !== (parent.root_capability_id || parent.capability_id)) {
      return false;
    }
    const childAllowlist = child.delegate_allowlist;
    const parentAllowlist = parent.delegate_allowlist;
    const allowlistsEqual =
      childAllowlist === parentAllowlist ||
      (childAllowlist !== null &&
        parentAllowlist !== null &&
        Array.isArray(childAllowlist) &&
        Array.isArray(parentAllowlist) &&
        canonicalJson(childAllowlist) === canonicalJson(parentAllowlist));
    if (!allowlistsEqual) return false;
    if (child.issuer !== parent.issuer) return false;
    if (child.agent !== parent.agent) return false;
    if (child.policy_digest !== parent.policy_digest) return false;
    const childPolicies = child.matched_policy_ids;
    const parentPolicies = parent.matched_policy_ids;
    if (!Array.isArray(childPolicies) || !Array.isArray(parentPolicies)) {
      return false;
    }
    if (
      childPolicies.length === 0 ||
      childPolicies.some((id) => !parentPolicies.includes(id))
    ) {
      return false;
    }
    const parentTarget = parent.target;
    const parentActions = parent.actions;
    const parentPurposes = parent.purposes;
    if (typeof parentTarget !== "string" || parentTarget.length === 0) return false;
    if (!Array.isArray(parentActions) || parentActions.length === 0) return false;
    if (!Array.isArray(parentPurposes) || parentPurposes.length === 0) return false;
    const childTarget = child.target;
    if (childTarget !== parentTarget && !globMatch(parentTarget, childTarget)) {
      return false;
    }
    const childActions = child.actions;
    const childPurposes = child.purposes;
    if (
      !Array.isArray(childActions) ||
      childActions.length === 0 ||
      childActions.some((action) => !parentActions.includes(action))
    ) {
      return false;
    }
    if (
      !Array.isArray(childPurposes) ||
      childPurposes.length === 0 ||
      childPurposes.some((purpose) => !parentPurposes.includes(purpose))
    ) {
      return false;
    }

    const parentAllowed = parent.delegation_allowed;
    const parentMaxDepth = parent.max_delegation_depth;
    const parentDelegate = parent.delegate_agent;
    const parentDepth = parent.delegation_depth;
    const childAllowed = child.delegation_allowed;
    const childMaxDepth = child.max_delegation_depth;
    const childDelegate = child.delegate_agent;
    const childDepth = child.delegation_depth;
    if (typeof parentAllowed !== "boolean" || typeof childAllowed !== "boolean") {
      return false;
    }
    for (const value of [parentMaxDepth, childMaxDepth, parentDepth, childDepth]) {
      if (!Number.isInteger(value) || value < 0 || value > 3) return false;
    }
    if (childDelegate === parentDelegate) {
      if (childDepth !== parentDepth) return false;
      if (child.request_digest !== parent.request_digest) return false;
    } else {
      if (!parentAllowed) return false;
      if (parentDepth >= parentMaxDepth) return false;
      if (childDepth !== parentDepth + 1) return false;
      if (typeof childDelegate !== "string" || childDelegate.length === 0) {
        return false;
      }
      if (childDelegate === child.agent) return false;
      if (childAllowed !== false) return false;
      if (childMaxDepth !== 0) return false;
      if (parentAllowlist !== null && !Array.isArray(parentAllowlist)) return false;
      if (
        Array.isArray(parentAllowlist) &&
        parentAllowlist.length > 0 &&
        !parentAllowlist.some((pattern) => globMatch(pattern, childDelegate))
      ) {
        return false;
      }
    }
    if (childMaxDepth > parentMaxDepth) return false;
    if (childAllowed && !parentAllowed) return false;
    if (parseTime(child.not_before) < parseTime(parent.not_before)) return false;
    if (parseTime(child.expires_at) > parseTime(parent.expires_at)) return false;
    if ((child.approval_tier ?? 0) !== (parent.approval_tier ?? 0)) return false;

    const childConstraints = child.constraints;
    const parentConstraints = parent.constraints;
    if (
      typeof childConstraints !== "object" ||
      childConstraints === null ||
      Array.isArray(childConstraints) ||
      typeof parentConstraints !== "object" ||
      parentConstraints === null ||
      Array.isArray(parentConstraints)
    ) {
      return false;
    }
    if (Object.keys(childConstraints).some((key) => !CONSTRAINT_KEYS.has(key))) {
      return false;
    }
    for (const name of ["max_force_newtons", "max_velocity_mps"]) {
      const childValue = childConstraints[name];
      if (childValue === undefined) continue;
      if (typeof childValue !== "number" || childValue < 0) return false;
      const parentValue = parentConstraints[name];
      if (parentValue !== undefined && childValue > parentValue) return false;
    }
    const childZones = childConstraints.allowed_zones;
    if (childZones !== undefined) {
      const parentZones = parentConstraints.allowed_zones;
      if (!Array.isArray(childZones)) return false;
      if (parentZones !== undefined) {
        if (!Array.isArray(parentZones)) return false;
        if (
          !childZones.every((zone) =>
            parentZones.some((pattern) => globMatch(pattern, zone))
          )
        ) {
          return false;
        }
      }
    }
    return true;
  } catch {
    return false;
  }
}

export async function verifyDelegationChain(
  chain,
  trustedIssuers,
  request,
  { now } = {}
) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new Error("delegation chain must be a non-empty array");
  }
  if (typeof request !== "object" || request === null || Array.isArray(request)) {
    throw new Error("delegation request must be an object");
  }
  const payloads = [];
  for (let index = 0; index < chain.length; index += 1) {
    const envelope = chain[index];
    const payload = await verifyEnvelope(envelope);
    if (payload.type !== "kinegrant:PhysicalActionCapability") {
      throw new Error("delegation chain contains a non-capability envelope");
    }
    if (payload.version !== "0.2" && payload.version !== "1.0") {
      throw new Error("delegation chains require scoped capabilities (0.2/1.0)");
    }
    validateScopedCapabilityStructure(payload);
    if (payload.issuer !== envelope.kid) {
      throw new Error("capability issuer does not match signing key");
    }
    if (!trustedIssuers.has(payload.issuer)) {
      throw new Error("untrusted capability issuer");
    }
    await validateCommon(payload, request, envelope);
    payloads.push(payload);
  }
  for (let index = 1; index < payloads.length; index += 1) {
    if (!verifyAttenuation(payloads[index], payloads[index - 1])) {
      throw new Error(
        `capability at chain position ${index + 1} is not a valid attenuation of position ${index}`
      );
    }
  }
  const terminalEnvelope = chain[chain.length - 1];
  const terminalPayload = payloads[payloads.length - 1];
  if (terminalPayload.issuer !== terminalEnvelope.kid) {
    throw new Error("capability issuer does not match signing key");
  }
  if (!trustedIssuers.has(terminalPayload.issuer)) {
    throw new Error("untrusted capability issuer");
  }
  const requestDigest = await digestOfObject(request);
  if (terminalPayload.request_digest !== requestDigest) {
    throw new Error("capability does not authorize this request");
  }
  const delegateAgent = terminalPayload.delegate_agent;
  if (delegateAgent === null) {
    if (terminalPayload.agent !== request.agent) {
      throw new Error("capability agent mismatch");
    }
  } else if (request.agent !== delegateAgent) {
    throw new Error("capability delegate agent mismatch");
  }
  if (!globMatch(terminalPayload.target, request.target)) {
    throw new Error("capability target scope mismatch");
  }
  if (!terminalPayload.actions.includes(request.action)) {
    throw new Error("capability action scope mismatch");
  }
  if (!terminalPayload.purposes.includes(request.purpose)) {
    throw new Error("capability purpose scope mismatch");
  }
  const root = payloads[0];
  const terminal = payloads[payloads.length - 1];
  return {
    valid: true,
    depth: payloads.length - 1,
    root_capability_id: root.root_capability_id || root.capability_id,
    terminal_capability_id: terminal.capability_id,
    agent: terminal.agent,
    target: terminal.target,
    actions: terminal.actions,
    purposes: terminal.purposes,
  };
}

export async function verifyMldsaEnvelope(envelope) {
  if (envelope?.alg !== "ML-DSA-65") {
    throw new Error("not an ML-DSA-65 envelope");
  }
  const payload = await verifyEnvelope(envelope);
  return payload;
}

const SEQUENCE_COMBINATION_FIELDS = new Set([
  "combination_id",
  "patterns",
  "window_seconds",
  "trigger",
]);

function validateSequencePolicy(policy) {
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
    throw new Error("sequence policy must be an object");
  }
  if (!Array.isArray(policy.combinations)) {
    throw new Error("sequence policy combinations must be an array");
  }
  const ids = [];
  for (const combination of policy.combinations) {
    if (
      typeof combination !== "object" ||
      combination === null ||
      Array.isArray(combination)
    ) {
      throw new Error("each forbidden combination must be an object");
    }
    if (
      Object.keys(combination).some(
        (key) => !SEQUENCE_COMBINATION_FIELDS.has(key)
      )
    ) {
      throw new Error(
        "forbidden combination has unknown fields: " +
          Object.keys(combination).join(", ")
      );
    }
    if (
      typeof combination.combination_id !== "string" ||
      combination.combination_id.length === 0
    ) {
      throw new Error("combination_id must be a non-empty string");
    }
    ids.push(combination.combination_id);
    if (!Array.isArray(combination.patterns) || combination.patterns.length === 0) {
      throw new Error("patterns must be a non-empty array");
    }
    for (const pattern of combination.patterns) {
      if (
        !Array.isArray(pattern) ||
        pattern.length !== 2 ||
        typeof pattern[0] !== "string" ||
        pattern[0].length === 0 ||
        typeof pattern[1] !== "string" ||
        pattern[1].length === 0
      ) {
        throw new Error("each pattern must be [action, target] of non-empty strings");
      }
    }
    const windowSeconds = combination.window_seconds;
    if (
      windowSeconds !== undefined &&
      windowSeconds !== null &&
      (!Number.isInteger(windowSeconds) || windowSeconds < 1)
    ) {
      throw new Error("window_seconds must be a positive integer or null");
    }
    const trigger = combination.trigger;
    if (trigger !== undefined && trigger !== null) {
      if (
        !Array.isArray(trigger) ||
        trigger.length !== 2 ||
        typeof trigger[0] !== "string" ||
        trigger[0].length === 0 ||
        typeof trigger[1] !== "string" ||
        trigger[1].length === 0
      ) {
        throw new Error("trigger must be [action, target] of non-empty strings or null");
      }
    }
  }
  if (new Set(ids).size !== ids.length) {
    throw new Error("combination_id values must be unique");
  }
  return policy;
}

function validateJournal(journal) {
  if (!Array.isArray(journal)) {
    throw new Error("journal must be an array");
  }
  for (const entry of journal) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error("each journal entry must be an object");
    }
    const keys = Object.keys(entry).sort().join(",");
    if (keys !== "action,at,target") {
      throw new Error("journal entry must have exactly action, target, and at");
    }
    if (typeof entry.action !== "string" || entry.action.length === 0) {
      throw new Error("journal entry action must be a non-empty string");
    }
    if (typeof entry.target !== "string" || entry.target.length === 0) {
      throw new Error("journal entry target must be a non-empty string");
    }
    if (typeof entry.at !== "string" || !/Z$|[+-]\d{2}:\d{2}$/.test(entry.at)) {
      throw new Error(
        "journal entry at must be a timezone-aware ISO timestamp"
      );
    }
    parseTime(entry.at);
  }
}

export function evaluateSequencePolicy(policy, request, journal, { now } = {}) {
  validateSequencePolicy(policy);
  if (typeof request !== "object" || request === null || Array.isArray(request)) {
    throw new Error("request must be an object");
  }
  for (const field of ["action", "target"]) {
    if (typeof request[field] !== "string" || request[field].length === 0) {
      throw new Error(`request ${field} must be a non-empty string`);
    }
  }
  validateJournal(journal);
  const current = now !== undefined ? now : Date.now();
  const matched = [];
  for (const combination of policy.combinations) {
    const windowSeconds = combination.window_seconds ?? null;
    const cutoff = windowSeconds === null ? null : current - windowSeconds * 1000;
    const complete = combination.patterns.every(([actionPattern, targetPattern]) =>
      journal.some((entry) => {
        const at = parseTime(entry.at);
        if (cutoff !== null && at < cutoff) return false;
        return (
          globMatch(actionPattern, entry.action) &&
          globMatch(targetPattern, entry.target)
        );
      })
    );
    if (!complete) continue;
    const trigger = combination.trigger ?? null;
    const denies =
      trigger === null ||
      (globMatch(trigger[0], request.action) &&
        globMatch(trigger[1], request.target));
    if (denies) matched.push(combination.combination_id);
  }
  return {
    allowed: matched.length === 0,
    reason: matched.length > 0 ? "forbidden_combination" : "sequence_allowed",
    matched_combination_ids: matched,
  };
}

export async function verifySequenceCheckReport(
  report,
  policy,
  request,
  journal,
  { now } = {}
) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("sequence check report must be an object");
  }
  if (report.type !== "kinegrant:SequenceCheckReport") {
    throw new Error("wrong sequence check report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported sequence check report version");
  }
  if (report.policy_id !== undefined && report.policy_id !== null) {
    if (typeof report.policy_id !== "string" || report.policy_id.length === 0) {
      throw new Error("sequence check report policy_id must be a non-empty string or null");
    }
  }
  const requestDigest = await digestOfObject(request);
  if (report.request_digest !== requestDigest) {
    throw new Error("sequence check report does not bind this request");
  }
  const journalDigest =
    "sha256:" +
    (await sha256Hex(new TextEncoder().encode(canonicalJson(journal))));
  if (report.journal_digest !== journalDigest) {
    throw new Error("sequence check report does not bind this journal");
  }
  if (
    typeof report.checked_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(report.checked_at)
  ) {
    throw new Error(
      "sequence check report checked_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(report.checked_at);
  const verdict = evaluateSequencePolicy(policy, request, journal, { now });
  const reported = report.verdict;
  if (typeof reported !== "object" || reported === null || Array.isArray(reported)) {
    throw new Error("sequence check report verdict must be an object");
  }
  const verdictFields = new Set([
    "allowed",
    "reason",
    "matched_combination_ids",
  ]);
  if (Object.keys(reported).some((key) => !verdictFields.has(key))) {
    throw new Error(
      "sequence check report verdict has unknown fields: " +
        Object.keys(reported).join(", ")
    );
  }
  if (typeof reported.allowed !== "boolean") {
    throw new Error("sequence check report verdict allowed must be a boolean");
  }
  if (reported.reason !== verdict.reason) {
    throw new Error("sequence check report reason is inconsistent");
  }
  if (reported.allowed !== verdict.allowed) {
    throw new Error("sequence check report verdict is inconsistent");
  }
  if (
    !Array.isArray(reported.matched_combination_ids) ||
    reported.matched_combination_ids.some(
      (id) => typeof id !== "string" || id.length === 0
    )
  ) {
    throw new Error(
      "sequence check report matched_combination_ids must be a string array"
    );
  }
  if (
    reported.matched_combination_ids.join(",") !==
    verdict.matched_combination_ids.join(",")
  ) {
    throw new Error(
      "sequence check report matched combinations are inconsistent"
    );
  }
  return {
    valid: true,
    policy_id: report.policy_id ?? null,
    allowed: verdict.allowed,
    reason: verdict.reason,
    matched_combination_ids: verdict.matched_combination_ids,
  };
}

const CONFORMANCE_LEVELS = new Set(["L1", "L2", "L3", "L4"]);
const IV_STATUSES = new Set(["PASS", "SKIP", "FAIL", "ERROR"]);
const IV_CHECK_FIELDS = [
  "capability",
  "receipts",
  "policy_bundle",
  "policy_current_version",
];

export function verifyConformanceReport(report) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("conformance report must be an object");
  }
  if (report.type !== "kinegrant:ConformanceReport") {
    throw new Error("wrong conformance report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported conformance report version");
  }
  if (!Array.isArray(report.marks) || report.marks.length === 0) {
    throw new Error("conformance report marks must be a non-empty array");
  }
  let passed = 0;
  for (const mark of report.marks) {
    if (typeof mark !== "object" || mark === null || Array.isArray(mark)) {
      throw new Error("each conformance mark must be an object");
    }
    const fields = new Set(Object.keys(mark));
    if (
      fields.size !== 4 ||
      !fields.has("name") ||
      !fields.has("level") ||
      !fields.has("passed") ||
      !fields.has("detail")
    ) {
      throw new Error(
        "each conformance mark must have exactly name, level, passed, detail"
      );
    }
    if (typeof mark.name !== "string" || mark.name.length === 0) {
      throw new Error("conformance mark name must be a non-empty string");
    }
    if (!CONFORMANCE_LEVELS.has(mark.level)) {
      throw new Error("conformance mark level must be L1, L2, L3, or L4");
    }
    if (typeof mark.passed !== "boolean") {
      throw new Error("conformance mark passed must be a boolean");
    }
    if (typeof mark.detail !== "string") {
      throw new Error("conformance mark detail must be a string");
    }
    if (mark.passed) passed += 1;
  }
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("conformance report summary must be an object");
  }
  if (
    summary.total !== report.marks.length ||
    summary.passed !== passed ||
    summary.failed !== report.marks.length - passed
  ) {
    throw new Error("conformance report summary is inconsistent");
  }
  const expectedResult = passed === report.marks.length ? "PASS" : "FAIL";
  if (report.overall_result !== expectedResult) {
    throw new Error("conformance report overall_result is inconsistent");
  }
  const iv = report.independent_verification;
  if (typeof iv !== "object" || iv === null || Array.isArray(iv)) {
    throw new Error("conformance report independent_verification must be an object");
  }
  if (iv.schema_version !== "0.1") {
    throw new Error("unsupported independent verification version");
  }
  if (!Array.isArray(iv.checks) || iv.checks.length === 0) {
    throw new Error("independent verification checks must be a non-empty array");
  }
  let ivPass = true;
  for (const check of iv.checks) {
    if (typeof check !== "object" || check === null || Array.isArray(check)) {
      throw new Error("each independent verification check must be an object");
    }
    if (typeof check.tool !== "string" || check.tool.length === 0) {
      throw new Error("independent verification check tool must be a non-empty string");
    }
    if (typeof check.detail !== "string") {
      throw new Error("independent verification check detail must be a string");
    }
    for (const field of IV_CHECK_FIELDS) {
      if (!IV_STATUSES.has(check[field])) {
        throw new Error(
          `independent verification check ${field} must be PASS, SKIP, FAIL, or ERROR`
        );
      }
      if (check[field] !== "PASS" && check[field] !== "SKIP") ivPass = false;
    }
  }
  const expectedIvResult = ivPass ? "PASS" : "FAIL";
  if (iv.overall_result !== expectedIvResult) {
    throw new Error("independent verification overall_result is inconsistent");
  }
  if (!Array.isArray(report.limitations)) {
    throw new Error("conformance report limitations must be an array");
  }
  if (report.limitations.some((item) => typeof item !== "string")) {
    throw new Error("conformance report limitations must be strings");
  }
  return {
    valid: true,
    overall_result: report.overall_result,
    summary: report.summary,
    marks: report.marks.length,
    independent_verification: {
      overall_result: iv.overall_result,
      checks: iv.checks.length,
    },
  };
}

const AUDIT_ENTRY_FIELDS = new Set([
  "label",
  "verified",
  "policy_id",
  "bundle_version",
  "analysis_result",
  "coverage_result",
  "error_findings",
  "shadowed_allows",
  "error",
]);
const AUDIT_RESULTS = new Set(["PASS", "FAIL"]);

export function verifyPolicyAuditSummary(report) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("policy audit summary must be an object");
  }
  if (report.type !== "kinegrant:PolicyAuditSummary") {
    throw new Error("wrong policy audit summary type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported policy audit summary version");
  }
  if (!Array.isArray(report.bundles) || report.bundles.length === 0) {
    throw new Error("policy audit summary bundles must be a non-empty array");
  }
  let verifiedCount = 0;
  let analysisFailures = 0;
  let coverageFailures = 0;
  const findingsByCode = {};
  let shadowedAllowsTotal = 0;
  for (const entry of report.bundles) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error("each audit entry must be an object");
    }
    const fields = new Set(Object.keys(entry));
    if (
      fields.size !== AUDIT_ENTRY_FIELDS.size ||
      [...fields].some((key) => !AUDIT_ENTRY_FIELDS.has(key))
    ) {
      throw new Error("audit entry fields do not match the expected schema");
    }
    if (typeof entry.label !== "string" || entry.label.length === 0) {
      throw new Error("audit entry label must be a non-empty string");
    }
    if (typeof entry.verified !== "boolean") {
      throw new Error("audit entry verified must be a boolean");
    }
    if (!Array.isArray(entry.error_findings)) {
      throw new Error("audit entry error_findings must be an array");
    }
    if (
      entry.error_findings.some(
        (code) => typeof code !== "string" || code.length === 0
      )
    ) {
      throw new Error("audit entry error_findings must be non-empty strings");
    }
    if (!Array.isArray(entry.shadowed_allows)) {
      throw new Error("audit entry shadowed_allows must be an array");
    }
    shadowedAllowsTotal += entry.shadowed_allows.length;
    for (const code of entry.error_findings) {
      findingsByCode[code] = (findingsByCode[code] ?? 0) + 1;
    }
    if (entry.verified) {
      verifiedCount += 1;
      if (
        typeof entry.policy_id !== "string" ||
        entry.policy_id.length === 0 ||
        !Number.isInteger(entry.bundle_version) ||
        entry.bundle_version < 1 ||
        !AUDIT_RESULTS.has(entry.analysis_result) ||
        !AUDIT_RESULTS.has(entry.coverage_result) ||
        entry.error !== null
      ) {
        throw new Error("verified audit entry has invalid result fields");
      }
      if (entry.analysis_result === "FAIL") analysisFailures += 1;
      if (entry.coverage_result === "FAIL") coverageFailures += 1;
    } else {
      if (
        entry.policy_id !== null ||
        entry.bundle_version !== null ||
        entry.analysis_result !== null ||
        entry.coverage_result !== null ||
        typeof entry.error !== "string" ||
        entry.error.length === 0
      ) {
        throw new Error("unverified audit entry has invalid failure fields");
      }
    }
  }
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("policy audit summary summary must be an object");
  }
  if (
    summary.bundles_total !== report.bundles.length ||
    summary.verified !== verifiedCount ||
    summary.failed !== report.bundles.length - verifiedCount ||
    summary.analysis_failures !== analysisFailures ||
    summary.coverage_failures !== coverageFailures
  ) {
    throw new Error("policy audit summary counts are inconsistent");
  }
  const reportedFindings = summary.findings_by_code;
  if (
    typeof reportedFindings !== "object" ||
    reportedFindings === null ||
    Array.isArray(reportedFindings)
  ) {
    throw new Error("policy audit summary findings_by_code must be an object");
  }
  const reportedKeys = Object.keys(reportedFindings).sort();
  const expectedKeys = Object.keys(findingsByCode).sort();
  if (
    reportedKeys.join(",") !== expectedKeys.join(",") ||
    reportedKeys.some((key) => reportedFindings[key] !== findingsByCode[key])
  ) {
    throw new Error("policy audit summary findings_by_code is inconsistent");
  }
  for (const name of ["allowed", "denied", "exceptions", "shadowed_allows"]) {
    const value = summary[name];
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`policy audit summary ${name} must be a non-negative integer`);
    }
  }
  if (summary.shadowed_allows !== shadowedAllowsTotal) {
    throw new Error("policy audit summary shadowed_allows total is inconsistent");
  }
  const expectedResult =
    verifiedCount === report.bundles.length &&
    analysisFailures === 0 &&
    coverageFailures === 0
      ? "PASS"
      : "FAIL";
  if (report.overall_result !== expectedResult) {
    throw new Error("policy audit summary overall_result is inconsistent");
  }
  return {
    valid: true,
    overall_result: report.overall_result,
    summary: report.summary,
    bundles: report.bundles.length,
  };
}

const KIT_CHECK_KEYS = new Set([
  "conformance",
  "machine_permission_test",
  "red_team",
  "benchmarks",
  "unit_tests",
  "release_packet",
]);
const KIT_AUTOMATED_KEYS = [
  "conformance",
  "machine_permission_test",
  "red_team",
  "benchmarks",
  "unit_tests",
];
const KIT_STATUSES = new Set(["PASS", "FAIL", "SKIP"]);
const KIT_CHECKLIST_KEYS = new Set(["id", "name", "evidence", "status"]);
const KIT_ARTIFACT_KEYS = new Set([
  "specification",
  "threat_model",
  "standards_mapping",
  "reproducing",
  "deployment_cases",
  "releases",
]);

export function verifySecurityReviewKit(report) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("security review kit must be an object");
  }
  if (report.type !== "kinegrant:SecurityReviewKit") {
    throw new Error("wrong security review kit type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported security review kit version");
  }
  if (
    typeof report.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(report.generated_at)
  ) {
    throw new Error(
      "security review kit generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(report.generated_at);
  if (
    typeof report.reference_implementation !== "string" ||
    report.reference_implementation.length === 0
  ) {
    throw new Error("security review kit reference_implementation is invalid");
  }
  if (
    report.source_commit !== null &&
    (typeof report.source_commit !== "string" ||
      !/^[0-9a-f]{40}$/i.test(report.source_commit))
  ) {
    throw new Error("security review kit source_commit must be null or a 40-hex sha");
  }
  const checks = report.checks;
  if (typeof checks !== "object" || checks === null || Array.isArray(checks)) {
    throw new Error("security review kit checks must be an object");
  }
  const checkKeys = Object.keys(checks);
  if (
    checkKeys.length !== KIT_CHECK_KEYS.size ||
    checkKeys.some((key) => !KIT_CHECK_KEYS.has(key))
  ) {
    throw new Error("security review kit checks must have exactly the known check keys");
  }
  for (const key of KIT_AUTOMATED_KEYS) {
    const check = checks[key];
    if (typeof check !== "object" || check === null || Array.isArray(check)) {
      throw new Error(`security review kit check ${key} must be an object`);
    }
    if (check.status !== "PASS" && check.status !== "FAIL") {
      throw new Error(`security review kit check ${key} status must be PASS or FAIL`);
    }
    if (typeof check.detail !== "string") {
      throw new Error(`security review kit check ${key} detail must be a string`);
    }
  }
  const mpt = checks.machine_permission_test;
  if (mpt.schema_version !== "0.5") {
    throw new Error("security review kit MPT check schema_version must be 0.5");
  }
  const bench = checks.benchmarks;
  if (
    typeof bench.operations_per_second !== "number" ||
    !Number.isFinite(bench.operations_per_second) ||
    bench.operations_per_second <= 0
  ) {
    throw new Error("security review kit benchmarks operations_per_second is invalid");
  }
  const release = checks.release_packet;
  if (
    typeof release !== "object" ||
    release === null ||
    Array.isArray(release) ||
    !KIT_STATUSES.has(release.status) ||
    typeof release.detail !== "string"
  ) {
    throw new Error("security review kit release_packet check is invalid");
  }
  const automatedPass = KIT_AUTOMATED_KEYS.every(
    (key) => checks[key].status === "PASS"
  );
  const expectedResult = automatedPass ? "PASS" : "FAIL";
  if (report.overall_result !== expectedResult) {
    throw new Error("security review kit overall_result is inconsistent");
  }
  if (!Array.isArray(report.checklist) || report.checklist.length === 0) {
    throw new Error("security review kit checklist must be a non-empty array");
  }
  for (const item of report.checklist) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error("each security review kit checklist item must be an object");
    }
    const fields = new Set(Object.keys(item));
    if (
      fields.size !== KIT_CHECKLIST_KEYS.size ||
      [...fields].some((key) => !KIT_CHECKLIST_KEYS.has(key))
    ) {
      throw new Error("security review kit checklist item fields are invalid");
    }
    for (const field of ["id", "name", "evidence"]) {
      if (typeof item[field] !== "string" || item[field].length === 0) {
        throw new Error(`security review kit checklist ${field} must be a non-empty string`);
      }
    }
    if (!KIT_STATUSES.has(item.status)) {
      throw new Error("security review kit checklist status must be PASS, FAIL, or SKIP");
    }
  }
  if (!Array.isArray(report.commands) || report.commands.length === 0) {
    throw new Error("security review kit commands must be a non-empty array");
  }
  if (
    report.commands.some(
      (command) => typeof command !== "string" || command.length === 0
    )
  ) {
    throw new Error("security review kit commands must be non-empty strings");
  }
  const artifacts = report.artifacts;
  if (typeof artifacts !== "object" || artifacts === null || Array.isArray(artifacts)) {
    throw new Error("security review kit artifacts must be an object");
  }
  if (
    Object.keys(artifacts).some((key) => !KIT_ARTIFACT_KEYS.has(key))
  ) {
    throw new Error("security review kit artifacts has unknown keys");
  }
  for (const key of [
    "specification",
    "threat_model",
    "standards_mapping",
    "reproducing",
    "deployment_cases",
  ]) {
    if (typeof artifacts[key] !== "string" || artifacts[key].length === 0) {
      throw new Error(`security review kit artifacts ${key} must be a non-empty string`);
    }
  }
  if (
    !Array.isArray(artifacts.releases) ||
    artifacts.releases.some(
      (releaseUrl) => typeof releaseUrl !== "string" || releaseUrl.length === 0
    )
  ) {
    throw new Error("security review kit artifacts releases must be non-empty strings");
  }
  if (!Array.isArray(report.limitations)) {
    throw new Error("security review kit limitations must be an array");
  }
  if (report.limitations.some((item) => typeof item !== "string")) {
    throw new Error("security review kit limitations must be strings");
  }
  return {
    valid: true,
    overall_result: report.overall_result,
    reference_implementation: report.reference_implementation,
    source_commit: report.source_commit,
    checks: checkKeys.length,
    checklist: report.checklist.length,
  };
}

const ESP32_EXPECTED_CASES = {
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
const ESP32_REQUIRED_PHYSICAL_ROLES = new Set([
  "firmware",
  "pinout_record",
  "wiring_photo",
  "serial_log",
  "host_log",
  "video",
  "receipts",
  "device_acks",
]);
const ESP32_ARTIFACT_ROLES = new Set([
  ...ESP32_REQUIRED_PHYSICAL_ROLES,
  "other",
]);
const ESP32_VERIFICATION_FIELDS = new Set([
  "allow_receipts_verified",
  "deny_receipts_verified",
  "tampered_receipts_rejected",
  "untrusted_executor_rejected",
  "device_acks_verified",
]);
const ESP32_MEASUREMENT_FIELDS = new Set([
  "actuator_calls",
  "observed_movements",
  "denials",
  "abnormal_resets",
  "overheat_events",
]);
const ESP32_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

function requireDigest(value, label) {
  if (typeof value !== "string" || !ESP32_DIGEST_RE.test(value)) {
    throw new Error(`${label} must be a sha256 digest or null`);
  }
}

function requireIsoTime(value, label, allowNull) {
  if (value === null && allowNull) return;
  if (typeof value !== "string" || !/Z$|[+-]\d{2}:\d{2}$/.test(value)) {
    throw new Error(`${label} must be a timezone-aware ISO timestamp or null`);
  }
  parseTime(value);
}

export function verifyEsp32c3Evidence(evidence) {
  if (typeof evidence !== "object" || evidence === null || Array.isArray(evidence)) {
    throw new Error("ESP32-C3 evidence must be an object");
  }
  if (evidence.schema_version !== "0.1") {
    throw new Error("unsupported ESP32-C3 evidence version");
  }
  if (evidence.evidence_type !== "kinegrant:ESP32C3PaperBarrierProofEvidence") {
    throw new Error("wrong ESP32-C3 evidence type");
  }
  if (evidence.evidence_mode !== "simulation" && evidence.evidence_mode !== "physical") {
    throw new Error("ESP32-C3 evidence_mode must be simulation or physical");
  }
  if (
    !/^urn:kinegrant:esp32c3-proof:run:[0-9a-f-]{36}$/.test(evidence.run_id)
  ) {
    throw new Error("ESP32-C3 run_id is invalid");
  }
  requireIsoTime(evidence.generated_at, "generated_at", false);
  requireIsoTime(evidence.started_at, "started_at", true);
  requireIsoTime(evidence.finished_at, "finished_at", true);
  if (evidence.protocol !== "KGP-001 Experimental Open Draft 0.1") {
    throw new Error("ESP32-C3 evidence protocol is invalid");
  }
  if (evidence.reference_implementation !== "0.1.1") {
    throw new Error("ESP32-C3 evidence reference_implementation is invalid");
  }
  if (
    evidence.source_commit !== null &&
    (typeof evidence.source_commit !== "string" ||
      !/^[0-9a-f]{40,64}$/.test(evidence.source_commit))
  ) {
    throw new Error("ESP32-C3 source_commit must be null or a hex commit");
  }
  const allowedResults =
    evidence.evidence_mode === "simulation"
      ? new Set(["NOT_RUN", "SIMULATION_PASS", "FAIL"])
      : new Set(["NOT_RUN", "PHYSICAL_PASS", "FAIL"]);
  if (!allowedResults.has(evidence.overall_result)) {
    throw new Error("ESP32-C3 overall_result is invalid for this mode");
  }
  const device = evidence.device;
  if (typeof device !== "object" || device === null || Array.isArray(device)) {
    throw new Error("ESP32-C3 device must be an object");
  }
  for (const field of ["board_model", "device_id", "firmware_version"]) {
    if (typeof device[field] !== "string" || device[field].length === 0) {
      throw new Error(`ESP32-C3 device ${field} must be a non-empty string`);
    }
  }
  if (
    device.device_key !== null &&
    (typeof device.device_key !== "string" ||
      !/^kinegrant:key:ed25519:[A-Za-z0-9_-]{43}$/.test(device.device_key))
  ) {
    throw new Error("ESP32-C3 device_key is invalid");
  }
  if (device.firmware_digest !== null) {
    requireDigest(device.firmware_digest, "device firmware_digest");
  }
  if (device.pinout_record_digest !== null) {
    requireDigest(device.pinout_record_digest, "device pinout_record_digest");
  }
  const environment = evidence.environment;
  if (
    typeof environment !== "object" ||
    environment === null ||
    Array.isArray(environment)
  ) {
    throw new Error("ESP32-C3 environment must be an object");
  }
  for (const field of ["host_platform", "servo_model"]) {
    if (typeof environment[field] !== "string" || environment[field].length === 0) {
      throw new Error(`ESP32-C3 environment ${field} must be a non-empty string`);
    }
  }
  if (environment.load !== "lightweight-paper-barrier") {
    throw new Error("ESP32-C3 environment load is invalid");
  }
  if (
    environment.servo_supply_voltage !== null &&
    (typeof environment.servo_supply_voltage !== "number" ||
      environment.servo_supply_voltage < 4.5 ||
      environment.servo_supply_voltage > 5.5)
  ) {
    throw new Error("ESP32-C3 servo_supply_voltage must be null or between 4.5 and 5.5");
  }
  if (typeof environment.power_plan_reviewed !== "boolean") {
    throw new Error("ESP32-C3 power_plan_reviewed must be a boolean");
  }
  const verification = evidence.verification;
  if (
    typeof verification !== "object" ||
    verification === null ||
    Array.isArray(verification) ||
    Object.keys(verification).length !== ESP32_VERIFICATION_FIELDS.size ||
    Object.keys(verification).some((key) => !ESP32_VERIFICATION_FIELDS.has(key)) ||
    Object.values(verification).some((value) => typeof value !== "boolean")
  ) {
    throw new Error("ESP32-C3 verification fields are invalid");
  }
  if (!Array.isArray(evidence.artifacts)) {
    throw new Error("ESP32-C3 artifacts must be an array");
  }
  const artifactDigests = [];
  for (const artifact of evidence.artifacts) {
    if (typeof artifact !== "object" || artifact === null || Array.isArray(artifact)) {
      throw new Error("each ESP32-C3 artifact must be an object");
    }
    const keys = Object.keys(artifact).sort().join(",");
    if (keys !== "bytes,media_type,path,role,sha256") {
      throw new Error("ESP32-C3 artifact fields are invalid");
    }
    if (!ESP32_ARTIFACT_ROLES.has(artifact.role)) {
      throw new Error("ESP32-C3 artifact role is invalid");
    }
    if (
      typeof artifact.path !== "string" ||
      artifact.path.length === 0 ||
      typeof artifact.media_type !== "string" ||
      artifact.media_type.length === 0 ||
      !Number.isInteger(artifact.bytes) ||
      artifact.bytes < 1
    ) {
      throw new Error("ESP32-C3 artifact path/media_type/bytes are invalid");
    }
    requireDigest(artifact.sha256, "artifact sha256");
    artifactDigests.push(artifact.sha256);
  }
  if (new Set(artifactDigests).size !== artifactDigests.length) {
    throw new Error("ESP32-C3 artifact digests must be unique");
  }
  if (!Array.isArray(evidence.cases) || evidence.cases.length !== 11) {
    throw new Error("ESP32-C3 cases must contain exactly 11 cases");
  }
  const caseIds = [];
  for (const caseItem of evidence.cases) {
    if (typeof caseItem !== "object" || caseItem === null || Array.isArray(caseItem)) {
      throw new Error("each ESP32-C3 case must be an object");
    }
    const keys = Object.keys(caseItem).sort().join(",");
    if (keys !== "artifact_digests,attempts,id,measurements,name,notes,passed") {
      throw new Error("ESP32-C3 case fields are invalid");
    }
    if (!/^HWP-[0-9]{3}$/.test(caseItem.id)) {
      throw new Error("ESP32-C3 case id is invalid");
    }
    caseIds.push(caseItem.id);
    if (typeof caseItem.name !== "string" || caseItem.name.length === 0) {
      throw new Error("ESP32-C3 case name must be a non-empty string");
    }
    if (!Number.isInteger(caseItem.attempts) || caseItem.attempts < 0) {
      throw new Error("ESP32-C3 case attempts must be a non-negative integer");
    }
    if (typeof caseItem.passed !== "boolean") {
      throw new Error("ESP32-C3 case passed must be a boolean");
    }
    if (typeof caseItem.notes !== "string") {
      throw new Error("ESP32-C3 case notes must be a string");
    }
    const measurements = caseItem.measurements;
    if (
      typeof measurements !== "object" ||
      measurements === null ||
      Array.isArray(measurements) ||
      Object.keys(measurements).length !== ESP32_MEASUREMENT_FIELDS.size ||
      Object.keys(measurements).some((key) => !ESP32_MEASUREMENT_FIELDS.has(key)) ||
      Object.values(measurements).some(
        (value) => !Number.isInteger(value) || value < 0
      )
    ) {
      throw new Error("ESP32-C3 case measurements are invalid");
    }
    if (!Array.isArray(caseItem.artifact_digests)) {
      throw new Error("ESP32-C3 case artifact_digests must be an array");
    }
    if (
      new Set(caseItem.artifact_digests).size !== caseItem.artifact_digests.length
    ) {
      throw new Error("ESP32-C3 case artifact_digests must be unique");
    }
    for (const digest of caseItem.artifact_digests) {
      requireDigest(digest, "case artifact_digests entry");
      if (!artifactDigests.includes(digest)) {
        throw new Error(
          `${caseItem.id} references an unknown artifact digest`
        );
      }
    }
  }
  if (new Set(caseIds).size !== 11) {
    throw new Error("ESP32-C3 case identifiers must be unique");
  }
  for (const expected of Object.keys(ESP32_EXPECTED_CASES)) {
    if (!caseIds.includes(expected)) {
      throw new Error("ESP32-C3 case set is missing " + expected);
    }
  }
  for (const id of caseIds) {
    if (!Object.prototype.hasOwnProperty.call(ESP32_EXPECTED_CASES, id)) {
      throw new Error("ESP32-C3 case set has an unexpected case: " + id);
    }
  }
  if (!Array.isArray(evidence.limitations) || evidence.limitations.length === 0) {
    throw new Error("ESP32-C3 limitations must be a non-empty array");
  }
  if (
    evidence.limitations.some(
      (item) => typeof item !== "string" || item.length === 0
    )
  ) {
    throw new Error("ESP32-C3 limitations must be non-empty strings");
  }

  const result = evidence.overall_result;
  if (result === "NOT_RUN") {
    if (evidence.cases.some((caseItem) => caseItem.attempts || caseItem.passed)) {
      throw new Error("NOT_RUN evidence cannot contain attempted or passed cases");
    }
    if (evidence.started_at !== null || evidence.finished_at !== null) {
      throw new Error("NOT_RUN evidence cannot contain run timestamps");
    }
    if (Object.values(verification).some(Boolean)) {
      throw new Error("NOT_RUN evidence cannot contain successful trust checks");
    }
    return {
      valid: true,
      overall_result: result,
      evidence_mode: evidence.evidence_mode,
      cases: evidence.cases.length,
    };
  }

  if (evidence.started_at === null || evidence.finished_at === null) {
    throw new Error("completed evidence requires start and finish timestamps");
  }
  const startedAt = parseTime(evidence.started_at);
  const finishedAt = parseTime(evidence.finished_at);
  const generatedAt = parseTime(evidence.generated_at);
  if (finishedAt < startedAt) {
    throw new Error("finished_at cannot precede started_at");
  }
  if (generatedAt < finishedAt) {
    throw new Error("generated_at cannot precede finished_at");
  }
  const allCasesPassed = evidence.cases.every((caseItem) => caseItem.passed);
  const allTrustChecksPassed = Object.values(verification).every(Boolean);
  const expectedResult =
    allCasesPassed && allTrustChecksPassed
      ? evidence.evidence_mode === "physical"
        ? "PHYSICAL_PASS"
        : "SIMULATION_PASS"
      : "FAIL";
  if (result !== expectedResult) {
    throw new Error("overall_result is inconsistent with cases and trust checks");
  }
  if (result === "PHYSICAL_PASS" || result === "SIMULATION_PASS") {
    for (const caseItem of evidence.cases) {
      const expected = ESP32_EXPECTED_CASES[caseItem.id];
      const observed = [
        caseItem.attempts,
        caseItem.measurements.actuator_calls,
        caseItem.measurements.observed_movements,
        caseItem.measurements.denials,
      ];
      if (observed.join(",") !== expected.join(",")) {
        throw new Error(
          `${caseItem.id} measurements differ from the acceptance profile`
        );
      }
    }
    const endurance = evidence.cases.find((caseItem) => caseItem.id === "HWP-011");
    if (endurance.measurements.abnormal_resets !== 0) {
      throw new Error("HWP-011 recorded an abnormal reset");
    }
    if (endurance.measurements.overheat_events !== 0) {
      throw new Error("HWP-011 recorded an overheat event");
    }
  }
  if (evidence.evidence_mode !== "physical" || result !== "PHYSICAL_PASS") {
    return {
      valid: true,
      overall_result: result,
      evidence_mode: evidence.evidence_mode,
      cases: evidence.cases.length,
    };
  }
  if (evidence.source_commit === null) {
    throw new Error("physical evidence requires an exact source commit");
  }
  if (evidence.run_id.endsWith("00000000-0000-0000-0000-000000000000")) {
    throw new Error("physical evidence cannot use the template run identifier");
  }
  for (const field of ["device_key", "firmware_digest", "pinout_record_digest"]) {
    if (device[field] === null) {
      throw new Error(`physical evidence requires device.${field}`);
    }
  }
  for (const field of ["board_model", "device_id", "firmware_version"]) {
    if (device[field].startsWith("UN") || device[field].startsWith("NOT_")) {
      throw new Error(`physical evidence contains placeholder device.${field}`);
    }
  }
  if (environment.servo_supply_voltage === null) {
    throw new Error("physical evidence requires measured servo supply voltage");
  }
  if (!environment.power_plan_reviewed) {
    throw new Error("physical evidence requires power-plan review");
  }
  const roles = new Set(evidence.artifacts.map((artifact) => artifact.role));
  const missingRoles = [...ESP32_REQUIRED_PHYSICAL_ROLES].filter(
    (role) => !roles.has(role)
  );
  if (missingRoles.length > 0) {
    throw new Error(
      "physical evidence is missing artifact roles: " + missingRoles.sort().join(", ")
    );
  }
  if (evidence.cases.some((caseItem) => caseItem.artifact_digests.length === 0)) {
    throw new Error("every physical case must reference at least one artifact");
  }
  const referenced = new Set();
  for (const caseItem of evidence.cases) {
    for (const digest of caseItem.artifact_digests) referenced.add(digest);
  }
  for (const digest of artifactDigests) {
    if (!referenced.has(digest)) {
      throw new Error("every physical artifact must be referenced by a case");
    }
  }
  const firmwareDigests = evidence.artifacts
    .filter((artifact) => artifact.role === "firmware")
    .map((artifact) => artifact.sha256);
  if (!firmwareDigests.includes(device.firmware_digest)) {
    throw new Error("device firmware_digest does not match a firmware artifact");
  }
  const pinoutDigests = evidence.artifacts
    .filter((artifact) => artifact.role === "pinout_record")
    .map((artifact) => artifact.sha256);
  if (!pinoutDigests.includes(device.pinout_record_digest)) {
    throw new Error("device pinout_record_digest does not match a pinout artifact");
  }
  return {
    valid: true,
    overall_result: result,
    evidence_mode: evidence.evidence_mode,
    cases: evidence.cases.length,
  };
}

const FLEET_OPS_SUMMARY_KEYS = [
  "gates_total",
  "policy_applied",
  "policy_failures",
  "revocation_applied",
  "revocation_failures",
];

export async function verifyFleetOperationsReport(
  report,
  policyBundle,
  revocationBundle,
  trustedAuthorities,
  { now } = {}
) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("fleet operations report must be an object");
  }
  if (report.type !== "kinegrant:FleetOperationsReport") {
    throw new Error("wrong fleet operations report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported fleet operations report version");
  }
  if (
    typeof report.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(report.generated_at)
  ) {
    throw new Error(
      "fleet operations report generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(report.generated_at);
  const policy = report.policy_distribution;
  const revocation = report.revocation_distribution;
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
    throw new Error("fleet operations report policy_distribution must be an object");
  }
  if (
    typeof revocation !== "object" ||
    revocation === null ||
    Array.isArray(revocation)
  ) {
    throw new Error(
      "fleet operations report revocation_distribution must be an object"
    );
  }
  await verifyPolicyDistributionReport(policy, policyBundle, trustedAuthorities, {
    now,
  });
  await verifyRevocationDistributionReport(
    revocation,
    revocationBundle,
    trustedAuthorities
  );
  const policyAcks = policy.acks;
  const revocationAcks = revocation.acks;
  if (!Array.isArray(policyAcks) || policyAcks.length === 0) {
    throw new Error("policy distribution acks must be a non-empty array");
  }
  if (!Array.isArray(revocationAcks) || revocationAcks.length === 0) {
    throw new Error("revocation distribution acks must be a non-empty array");
  }
  const policyGates = policyAcks.map((ack) => ack.gate_id).sort();
  const revocationGates = revocationAcks.map((ack) => ack.gate_id).sort();
  if (policyGates.join(",") !== revocationGates.join(",")) {
    throw new Error(
      "fleet operations report gate sets differ between distributions"
    );
  }
  const gatesTotal = new Set(policyGates).size;
  if (gatesTotal === 0) {
    throw new Error("fleet operations report has no gates");
  }
  const policyApplied = policyAcks.filter((ack) => ack.applied === true).length;
  const revocationApplied = revocationAcks.filter(
    (ack) => ack.applied === true
  ).length;
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("fleet operations report summary must be an object");
  }
  if (Object.keys(summary).sort().join(",") !== FLEET_OPS_SUMMARY_KEYS.join(",")) {
    throw new Error("fleet operations report summary fields are invalid");
  }
  if (summary.gates_total !== gatesTotal) {
    throw new Error("fleet operations report gates_total is inconsistent");
  }
  if (summary.policy_applied !== policyApplied) {
    throw new Error("fleet operations report policy_applied is inconsistent");
  }
  if (summary.policy_failures !== gatesTotal - policyApplied) {
    throw new Error("fleet operations report policy_failures is inconsistent");
  }
  if (summary.revocation_applied !== revocationApplied) {
    throw new Error("fleet operations report revocation_applied is inconsistent");
  }
  if (summary.revocation_failures !== gatesTotal - revocationApplied) {
    throw new Error("fleet operations report revocation_failures is inconsistent");
  }
  const expectedResult =
    policyApplied === gatesTotal && revocationApplied === gatesTotal
      ? "PASS"
      : "FAIL";
  if (report.overall_result !== expectedResult) {
    throw new Error("fleet operations report overall_result is inconsistent");
  }
  return {
    valid: true,
    overall_result: report.overall_result,
    summary: report.summary,
    gates: gatesTotal,
  };
}

const BENCHMARK_OPERATIONS = [
  "policy_evaluate",
  "cached_policy_evaluate",
  "capability_issue",
  "gate_authorize",
  "receipt_append",
  "obligation_compliance",
  "gatekeeper_execute",
  "audit_summary",
  "revocation_distribute",
  "jcs_digest",
];

export function verifyBenchmarkReport(report) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("benchmark report must be an object");
  }
  if (report.type !== "kinegrant:BenchmarkReport") {
    throw new Error("wrong benchmark report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported benchmark report version");
  }
  if (!Number.isInteger(report.iterations) || report.iterations < 1) {
    throw new Error("benchmark report iterations must be a positive integer");
  }
  const operations = report.operations_per_second;
  if (
    typeof operations !== "object" ||
    operations === null ||
    Array.isArray(operations)
  ) {
    throw new Error("benchmark report operations_per_second must be an object");
  }
  if (
    Object.keys(operations).sort().join(",") !==
    [...BENCHMARK_OPERATIONS].sort().join(",")
  ) {
    throw new Error("benchmark report operations_per_second keys are invalid");
  }
  for (const name of BENCHMARK_OPERATIONS) {
    const value = operations[name];
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      throw new Error(`benchmark report ${name} must be a positive number`);
    }
  }
  return {
    valid: true,
    iterations: report.iterations,
    operations: BENCHMARK_OPERATIONS.length,
  };
}

const LIFECYCLE_PHASES = [
  "publish",
  "enforce",
  "odrl",
  "distribute",
  "audit",
  "revoke",
];
const LIFECYCLE_STATUSES = new Set(["PASS", "FAIL", "SKIP"]);
const LIFECYCLE_SUMMARY_KEYS = ["phases_total", "passed", "failed"];

export async function verifyPolicyLifecycleTrace(
  trace,
  policyBundle,
  trustedAuthorities,
  { now } = {}
) {
  if (typeof trace !== "object" || trace === null || Array.isArray(trace)) {
    throw new Error("policy lifecycle trace must be an object");
  }
  if (trace.type !== "kinegrant:PolicyLifecycleTrace") {
    throw new Error("wrong policy lifecycle trace type");
  }
  if (trace.schema_version !== "0.1") {
    throw new Error("unsupported policy lifecycle trace version");
  }
  if (
    typeof trace.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(trace.generated_at)
  ) {
    throw new Error(
      "policy lifecycle trace generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(trace.generated_at);
  const payload = await verifyPolicyBundle(policyBundle, trustedAuthorities, {
    now,
  });
  if (trace.policy_id !== payload.policy_id) {
    throw new Error("policy lifecycle trace policy_id does not match the policy bundle");
  }
  if (trace.bundle_id !== payload.bundle_id) {
    throw new Error("policy lifecycle trace bundle_id does not match the policy bundle");
  }
  if (trace.bundle_version !== payload.version) {
    throw new Error(
      "policy lifecycle trace bundle_version does not match the policy bundle"
    );
  }
  if (!Array.isArray(trace.phases) || trace.phases.length !== LIFECYCLE_PHASES.length) {
    throw new Error("policy lifecycle trace phases must contain exactly six phases");
  }
  const seen = new Set();
  for (let index = 0; index < trace.phases.length; index += 1) {
    const phase = trace.phases[index];
    if (typeof phase !== "object" || phase === null || Array.isArray(phase)) {
      throw new Error("each lifecycle phase must be an object");
    }
    const keys = Object.keys(phase).sort().join(",");
    if (keys !== "artifact,detail,phase,status") {
      throw new Error("lifecycle phase fields are invalid");
    }
    if (phase.phase !== LIFECYCLE_PHASES[index]) {
      throw new Error("lifecycle phases must follow the canonical order");
    }
    if (seen.has(phase.phase)) {
      throw new Error("lifecycle phase ids must be unique");
    }
    seen.add(phase.phase);
    if (!LIFECYCLE_STATUSES.has(phase.status)) {
      throw new Error("lifecycle phase status must be PASS, FAIL, or SKIP");
    }
    if (typeof phase.detail !== "string" || phase.detail.length === 0) {
      throw new Error("lifecycle phase detail must be a non-empty string");
    }
    if (
      phase.artifact !== null &&
      (typeof phase.artifact !== "string" || phase.artifact.length === 0)
    ) {
      throw new Error("lifecycle phase artifact must be null or a non-empty string");
    }
  }
  const passed = trace.phases.filter((phase) => phase.status === "PASS").length;
  const failed = trace.phases.filter((phase) => phase.status === "FAIL").length;
  const skipped = trace.phases.filter((phase) => phase.status === "SKIP").length;
  const summary = trace.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("policy lifecycle trace summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    [...LIFECYCLE_SUMMARY_KEYS].sort().join(",")
  ) {
    throw new Error("policy lifecycle trace summary fields are invalid");
  }
  if (
    summary.phases_total !== trace.phases.length ||
    summary.passed !== passed ||
    summary.failed !== failed
  ) {
    throw new Error("policy lifecycle trace summary is inconsistent");
  }
  if (skipped > 0 && passed + failed + skipped !== trace.phases.length) {
    throw new Error("policy lifecycle trace summary does not account for skipped phases");
  }
  const expectedResult = failed > 0 ? "FAIL" : skipped > 0 ? "SKIP" : "PASS";
  if (trace.overall_result !== expectedResult) {
    throw new Error("policy lifecycle trace overall_result is inconsistent");
  }
  return {
    valid: true,
    overall_result: trace.overall_result,
    summary: trace.summary,
    policy_id: trace.policy_id,
    bundle_version: trace.bundle_version,
  };
}

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const SENSOR_COMMITMENT_KEYS = [
  "commitment_id",
  "committed_at",
  "readings",
  "readings_digest",
  "schema_version",
  "sensor",
  "type",
];
const SENSOR_READING_KEYS = [
  "confidence",
  "kind",
  "observed_at",
  "source_id",
  "value_hash",
];

async function sensorCommitmentId(payload) {
  const unsigned = { ...payload };
  delete unsigned.commitment_id;
  return contentId("kinegrant:sensor-evidence", unsigned);
}

export async function verifySensorCommitment(
  commitment,
  { trustedSensors } = {}
) {
  if (typeof commitment !== "object" || commitment === null || Array.isArray(commitment)) {
    throw new Error("sensor commitment must be an object");
  }
  let payload;
  if (commitment.alg !== undefined && commitment.alg !== null) {
    payload = await verifyEnvelope(commitment);
    if (trustedSensors !== undefined && !trustedSensors.has(payload.sensor)) {
      throw new Error("untrusted sensor");
    }
  } else {
    payload = commitment;
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new Error("sensor commitment payload must be an object");
  }
  if (Object.keys(payload).sort().join(",") !== SENSOR_COMMITMENT_KEYS.join(",")) {
    throw new Error("sensor commitment fields are invalid");
  }
  if (payload.type !== "kinegrant:SensorEvidenceCommitment") {
    throw new Error("wrong sensor commitment type");
  }
  if (payload.schema_version !== "0.1") {
    throw new Error("unsupported sensor commitment version");
  }
  if (payload.sensor !== null && (typeof payload.sensor !== "string" || payload.sensor.length === 0)) {
    throw new Error("sensor must be null or a non-empty string");
  }
  if (typeof payload.committed_at !== "string" || payload.committed_at.length === 0) {
    throw new Error("committed_at must be a non-empty string");
  }
  if (!Array.isArray(payload.readings) || payload.readings.length === 0) {
    throw new Error("readings must be a non-empty array");
  }
  for (const reading of payload.readings) {
    if (typeof reading !== "object" || reading === null || Array.isArray(reading)) {
      throw new Error("each sensor reading must be an object");
    }
    if (Object.keys(reading).sort().join(",") !== SENSOR_READING_KEYS.join(",")) {
      throw new Error("sensor reading fields are invalid");
    }
    if (typeof reading.kind !== "string" || reading.kind.length === 0) {
      throw new Error("sensor reading kind must be a non-empty string");
    }
    if (typeof reading.value_hash !== "string" || !SHA256_RE.test(reading.value_hash)) {
      throw new Error("sensor reading value_hash must be a sha256 digest");
    }
    if (typeof reading.source_id !== "string" || reading.source_id.length === 0) {
      throw new Error("sensor reading source_id must be a non-empty string");
    }
    if (
      typeof reading.confidence !== "number" ||
      !Number.isFinite(reading.confidence) ||
      reading.confidence < 0 ||
      reading.confidence > 1
    ) {
      throw new Error("sensor reading confidence must be a number between 0 and 1");
    }
    if (typeof reading.observed_at !== "string" || reading.observed_at.length === 0) {
      throw new Error("sensor reading observed_at must be a non-empty string");
    }
  }
  const expectedReadingsDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(canonicalJson({ readings: payload.readings }))
    ));
  if (payload.readings_digest !== expectedReadingsDigest) {
    throw new Error("readings digest is inconsistent");
  }
  const expectedId = await sensorCommitmentId(payload);
  if (payload.commitment_id !== expectedId) {
    throw new Error("commitment identifier is inconsistent");
  }
  return payload;
}

export async function sensorEvidenceHash(commitment) {
  const payload = await verifySensorCommitment(commitment);
  return (
    "sha256:" +
    (await sha256Hex(new TextEncoder().encode(canonicalJson(payload))))
  );
}

export async function verifyReceiptCheckpoint(
  checkpoint,
  { trustedNotaries } = {}
) {
  if (typeof checkpoint !== "object" || checkpoint === null || Array.isArray(checkpoint)) {
    throw new Error("receipt checkpoint must be an object");
  }
  const payload = await verifyEnvelope(checkpoint);
  if (payload.type !== "kinegrant:ReceiptCheckpoint") {
    throw new Error("wrong checkpoint type");
  }
  if (payload.schema_version !== "0.1") {
    throw new Error("unsupported checkpoint version");
  }
  if (payload.notary !== checkpoint.kid) {
    throw new Error("checkpoint notary does not match signing key");
  }
  if (trustedNotaries !== undefined && !trustedNotaries.has(payload.notary)) {
    throw new Error("untrusted notary");
  }
  if (typeof payload.chain_digest !== "string" || !SHA256_RE.test(payload.chain_digest)) {
    throw new Error("chain_digest must be a sha256 digest");
  }
  if (typeof payload.period !== "string" || payload.period.length === 0) {
    throw new Error("period must be a non-empty string");
  }
  if (typeof payload.issued_at !== "string" || payload.issued_at.length === 0) {
    throw new Error("issued_at must be a non-empty string");
  }
  const unsigned = { ...payload };
  delete unsigned.checkpoint_id;
  const expectedId = await contentId("kinegrant:receipt-checkpoint", unsigned);
  if (payload.checkpoint_id !== expectedId) {
    throw new Error("checkpoint identifier is inconsistent");
  }
  return {
    valid: true,
    chain_digest: payload.chain_digest,
    notary: payload.notary,
    period: payload.period,
    issued_at: payload.issued_at,
  };
}

const ATTESTATION_KEYS = [
  "attestation_id",
  "boot_counter",
  "device",
  "device_id",
  "firmware_digest",
  "issued_at",
  "measured_boot",
  "schema_version",
  "type",
];
const MEASURED_BOOT_KEYS = ["digest", "stage"];

export async function verifyDeviceAttestation(
  attestation,
  { trustedDevices } = {}
) {
  if (typeof attestation !== "object" || attestation === null || Array.isArray(attestation)) {
    throw new Error("device attestation must be an object");
  }
  const payload = await verifyEnvelope(attestation);
  if (Object.keys(payload).sort().join(",") !== ATTESTATION_KEYS.join(",")) {
    throw new Error("device attestation fields are invalid");
  }
  if (payload.type !== "kinegrant:DeviceAttestation") {
    throw new Error("wrong attestation type");
  }
  if (payload.schema_version !== "0.1") {
    throw new Error("unsupported attestation version");
  }
  if (payload.device !== attestation.kid) {
    throw new Error("attestation device does not match signing key");
  }
  if (trustedDevices !== undefined && !trustedDevices.has(payload.device)) {
    throw new Error("untrusted device");
  }
  if (typeof payload.device_id !== "string" || payload.device_id.length === 0) {
    throw new Error("device_id must be a non-empty string");
  }
  if (
    typeof payload.firmware_digest !== "string" ||
    !SHA256_RE.test(payload.firmware_digest)
  ) {
    throw new Error("firmware_digest must be a sha256 digest");
  }
  if (
    !Number.isInteger(payload.boot_counter) ||
    payload.boot_counter < 0
  ) {
    throw new Error("boot_counter must be a non-negative integer");
  }
  if (typeof payload.issued_at !== "string" || payload.issued_at.length === 0) {
    throw new Error("issued_at must be a non-empty string");
  }
  if (!Array.isArray(payload.measured_boot)) {
    throw new Error("measured_boot must be an array");
  }
  for (const stage of payload.measured_boot) {
    if (typeof stage !== "object" || stage === null || Array.isArray(stage)) {
      throw new Error("measured_boot entries must be objects");
    }
    if (Object.keys(stage).sort().join(",") !== MEASURED_BOOT_KEYS.join(",")) {
      throw new Error("measured_boot entry fields are invalid");
    }
    if (typeof stage.stage !== "string" || stage.stage.length === 0) {
      throw new Error("measured_boot stage must be a non-empty string");
    }
    if (typeof stage.digest !== "string" || !SHA256_RE.test(stage.digest)) {
      throw new Error("measured_boot digest must be a sha256 digest");
    }
  }
  const unsigned = { ...payload };
  delete unsigned.attestation_id;
  const expectedId = await contentId("kinegrant:device-attestation", unsigned);
  if (payload.attestation_id !== expectedId) {
    throw new Error("attestation identifier is inconsistent");
  }
  return {
    valid: true,
    device_id: payload.device_id,
    firmware_digest: payload.firmware_digest,
    boot_counter: payload.boot_counter,
    stages: payload.measured_boot.length,
  };
}

const BRIDGE_REPORT_TYPES = new Set([
  "kinegrant:Ros2McpDemoReport",
  "kinegrant:BridgeDemoReport",
]);
const BRIDGE_OUTCOME_KEYS = [
  "action",
  "allowed",
  "expected",
  "obligation_compliant",
  "passed",
  "purpose",
  "reason",
  "scenario",
  "stack",
];
const BRIDGE_OUTCOME_KEYS_WITHOUT_PURPOSE = [
  "action",
  "allowed",
  "expected",
  "obligation_compliant",
  "passed",
  "reason",
  "scenario",
  "stack",
];

export function verifyBridgeDemoReport(report) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("bridge demo report must be an object");
  }
  if (!BRIDGE_REPORT_TYPES.has(report.type)) {
    throw new Error("wrong bridge demo report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported bridge demo report version");
  }
  if (!Array.isArray(report.outcomes) || report.outcomes.length === 0) {
    throw new Error("bridge demo report outcomes must be a non-empty array");
  }
  let passed = 0;
  for (const outcome of report.outcomes) {
    if (typeof outcome !== "object" || outcome === null || Array.isArray(outcome)) {
      throw new Error("each bridge demo outcome must be an object");
    }
    const outcomeKeys = Object.keys(outcome).sort().join(",");
    if (
      outcomeKeys !== BRIDGE_OUTCOME_KEYS.join(",") &&
      outcomeKeys !== BRIDGE_OUTCOME_KEYS_WITHOUT_PURPOSE.join(",")
    ) {
      throw new Error("bridge demo outcome fields are invalid");
    }
    for (const field of ["scenario", "stack", "action", "reason"]) {
      if (typeof outcome[field] !== "string" || outcome[field].length === 0) {
        throw new Error(`bridge demo outcome ${field} must be a non-empty string`);
      }
    }
    if (
      outcome.purpose !== undefined &&
      (typeof outcome.purpose !== "string" || outcome.purpose.length === 0)
    ) {
      throw new Error("bridge demo outcome purpose must be a non-empty string");
    }
    if (outcome.expected !== "ALLOW" && outcome.expected !== "DENY") {
      throw new Error("bridge demo outcome expected must be ALLOW or DENY");
    }
    if (typeof outcome.allowed !== "boolean" || typeof outcome.passed !== "boolean") {
      throw new Error("bridge demo outcome allowed and passed must be booleans");
    }
    if (
      outcome.obligation_compliant !== null &&
      typeof outcome.obligation_compliant !== "boolean"
    ) {
      throw new Error("bridge demo outcome obligation_compliant must be null or a boolean");
    }
    if (outcome.allowed && outcome.obligation_compliant === null) {
      throw new Error("allowed bridge demo outcomes require an obligation_compliant flag");
    }
    const expectedPassed = outcome.allowed === (outcome.expected === "ALLOW");
    if (outcome.passed !== expectedPassed) {
      throw new Error("bridge demo outcome passed flag is inconsistent");
    }
    if (outcome.passed) passed += 1;
  }
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("bridge demo report summary must be an object");
  }
  const summaryKeys = Object.keys(summary).sort().join(",");
  if (summaryKeys !== "failed,passed,total") {
    throw new Error("bridge demo report summary fields are invalid");
  }
  if (
    summary.total !== report.outcomes.length ||
    summary.passed !== passed ||
    summary.failed !== report.outcomes.length - passed
  ) {
    throw new Error("bridge demo report summary is inconsistent");
  }
  let expectedResult =
    passed === report.outcomes.length ? "PASS" : "FAIL";
  if (
    report.receipts_verified !== undefined &&
    report.receipts_verified !== true
  ) {
    expectedResult = "FAIL";
  }
  if (
    report.obligation_compliance_ok !== undefined &&
    report.obligation_compliance_ok !== true
  ) {
    expectedResult = "FAIL";
  }
  if (
    report.fidelity_ok !== undefined &&
    report.fidelity_ok !== true
  ) {
    expectedResult = "FAIL";
  }
  if (report.receipts_verified !== undefined) {
    if (typeof report.receipts_verified !== "boolean") {
      throw new Error("bridge demo report receipts_verified must be a boolean");
    }
  }
  if (report.receipt_count !== undefined) {
    if (!Number.isInteger(report.receipt_count) || report.receipt_count < 0) {
      throw new Error("bridge demo report receipt_count must be a non-negative integer");
    }
    if (
      report.type === "kinegrant:Ros2McpDemoReport" &&
      expectedResult === "PASS" &&
      report.receipt_count !== 2
    ) {
      expectedResult = "FAIL";
    }
  }
  if (report.overall_result !== expectedResult) {
    throw new Error("bridge demo report overall_result is inconsistent");
  }
  if (!Array.isArray(report.limitations)) {
    throw new Error("bridge demo report limitations must be an array");
  }
  if (report.limitations.some((item) => typeof item !== "string")) {
    throw new Error("bridge demo report limitations must be strings");
  }
  return {
    valid: true,
    type: report.type,
    overall_result: report.overall_result,
    summary: report.summary,
    outcomes: report.outcomes.length,
  };
}

const HARDWARE_PACKET_KEYS = [
  "device_attestation",
  "device_id",
  "generated_at",
  "overall_result",
  "receipt_checkpoints",
  "schema_version",
  "sensor_commitments",
  "summary",
  "type",
];

export async function verifyHardwareTrustPacket(
  packet,
  { trustedDevices, trustedSensors, trustedNotaries } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("hardware trust packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== HARDWARE_PACKET_KEYS.join(",")) {
    throw new Error("hardware trust packet fields are invalid");
  }
  if (packet.type !== "kinegrant:HardwareTrustPacket") {
    throw new Error("wrong hardware trust packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported hardware trust packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "hardware trust packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("hardware trust packet overall_result must be PASS");
  }
  if (typeof packet.device_id !== "string" || packet.device_id.length === 0) {
    throw new Error("hardware trust packet device_id must be a non-empty string");
  }
  const attestation = packet.device_attestation;
  if (typeof attestation !== "object" || attestation === null || Array.isArray(attestation)) {
    throw new Error("hardware trust packet device_attestation must be an object");
  }
  const attestationResult = await verifyDeviceAttestation(attestation, {
    trustedDevices,
  });
  if (attestationResult.device_id !== packet.device_id) {
    throw new Error(
      "hardware trust packet device_id does not match the device attestation"
    );
  }
  if (
    !Array.isArray(packet.sensor_commitments) ||
    packet.sensor_commitments.length === 0
  ) {
    throw new Error(
      "hardware trust packet sensor_commitments must be a non-empty array"
    );
  }
  for (const commitment of packet.sensor_commitments) {
    await verifySensorCommitment(commitment, { trustedSensors });
  }
  if (
    !Array.isArray(packet.receipt_checkpoints) ||
    packet.receipt_checkpoints.length === 0
  ) {
    throw new Error(
      "hardware trust packet receipt_checkpoints must be a non-empty array"
    );
  }
  for (const checkpoint of packet.receipt_checkpoints) {
    await verifyReceiptCheckpoint(checkpoint, { trustedNotaries });
  }
  const summary = packet.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("hardware trust packet summary must be an object");
  }
  if (Object.keys(summary).sort().join(",") !== "device_attestations,receipt_checkpoints,sensor_commitments") {
    throw new Error("hardware trust packet summary fields are invalid");
  }
  if (
    summary.device_attestations !== 1 ||
    summary.sensor_commitments !== packet.sensor_commitments.length ||
    summary.receipt_checkpoints !== packet.receipt_checkpoints.length
  ) {
    throw new Error("hardware trust packet summary is inconsistent");
  }
  return {
    valid: true,
    device_id: packet.device_id,
    firmware_digest: attestationResult.firmware_digest,
    boot_counter: attestationResult.boot_counter,
    sensor_commitments: packet.sensor_commitments.length,
    receipt_checkpoints: packet.receipt_checkpoints.length,
  };
}

const DEVICE_TO_POLICY_KEYS = [
  "capability",
  "device_attestation",
  "device_id",
  "gate_decision",
  "generated_at",
  "overall_result",
  "policy_bundle",
  "receipt",
  "receipt_checkpoint",
  "request",
  "schema_version",
  "sensor_commitment",
  "summary",
  "trusted_policy_issuers",
  "type",
];
const GATE_DECISION_KEYS = [
  "allowed",
  "capability_id",
  "checked_at",
  "policy_digest",
  "reason",
];
const DEVICE_TO_POLICY_SUMMARY_KEYS = [
  "artifacts_total",
  "attestation_bound",
  "capability_verified",
  "checkpoint_bound",
  "cross_references_ok",
  "decision_consistent",
  "policy_verified",
  "receipt_bound",
  "sensor_bound",
];

export async function verifyDeviceToPolicyExport(
  packet,
  {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    trustedSensors,
    trustedNotaries,
    trustedDevices,
    now,
  } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("device-to-policy export packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== DEVICE_TO_POLICY_KEYS.join(",")) {
    throw new Error("device-to-policy export packet fields are invalid");
  }
  if (packet.type !== "kinegrant:DeviceToPolicyExportPacket") {
    throw new Error("wrong device-to-policy export packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported device-to-policy export packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "device-to-policy export packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("device-to-policy export packet overall_result must be PASS");
  }
  if (typeof packet.device_id !== "string" || packet.device_id.length === 0) {
    throw new Error("device-to-policy export packet device_id must be non-empty");
  }
  if (
    !Array.isArray(packet.trusted_policy_issuers) ||
    packet.trusted_policy_issuers.length === 0 ||
    packet.trusted_policy_issuers.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "device-to-policy export packet trusted_policy_issuers must be a non-empty string array"
    );
  }

  const policyPayload = await verifyPolicyBundle(
    packet.policy_bundle,
    new Set(packet.trusted_policy_issuers),
    { now }
  );
  const rulePolicyIds = new Set(
    policyPayload.rules.map((rule) => rule.policy_id)
  );

  const request = packet.request;
  if (
    typeof request !== "object" ||
    request === null ||
    Array.isArray(request)
  ) {
    throw new Error("device-to-policy export packet request must be an object");
  }
  if (request.type !== "kinegrant:ActionRequest" || request.version !== "0.1") {
    throw new Error(
      "device-to-policy export packet request must be a v0.1 action request"
    );
  }
  const requestDigest = await digestOfObject(request);
  const capPayload = await verifyCapability(
    packet.capability,
    request,
    trustedIssuers ?? new Set(packet.trusted_policy_issuers)
  );
  if (capPayload.request_digest !== requestDigest) {
    throw new Error("capability does not authorize this request");
  }
  const expectedPolicyDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(
        canonicalJson({
          rules: policyPayload.rules,
          trusted_policy_issuers: [...packet.trusted_policy_issuers].sort(),
        })
      )
    ));
  if (capPayload.policy_digest !== expectedPolicyDigest) {
    throw new Error(
      "capability policy digest does not match the export rules and trust set"
    );
  }
  if (
    !Array.isArray(capPayload.matched_policy_ids) ||
    capPayload.matched_policy_ids.length === 0 ||
    capPayload.matched_policy_ids.some((id) => !rulePolicyIds.has(id))
  ) {
    throw new Error("capability matched policies do not match the policy bundle");
  }

  const decision = packet.gate_decision;
  if (
    typeof decision !== "object" ||
    decision === null ||
    Array.isArray(decision)
  ) {
    throw new Error("gate decision must be an object");
  }
  if (Object.keys(decision).sort().join(",") !== GATE_DECISION_KEYS.join(",")) {
    throw new Error("gate decision fields are invalid");
  }
  if (decision.allowed !== true) {
    throw new Error("gate decision must be allow for a PASS export");
  }
  if (typeof decision.reason !== "string" || decision.reason.length === 0) {
    throw new Error("gate decision reason is invalid");
  }
  if (
    typeof decision.checked_at !== "string" ||
    Number.isNaN(Date.parse(decision.checked_at))
  ) {
    throw new Error("gate decision checked_at is invalid");
  }
  if (decision.capability_id !== capPayload.capability_id) {
    throw new Error("gate decision does not reference the verified capability");
  }
  if (decision.policy_digest !== capPayload.policy_digest) {
    throw new Error("gate decision does not reference the verified policy");
  }

  await verifyReceiptChain([packet.receipt], trustedExecutors);
  const receiptPayload = await verifyEnvelope(packet.receipt);
  if (receiptPayload.type !== "kinegrant:PhysicalActionReceipt") {
    throw new Error("receipt payload type is invalid");
  }
  if (receiptPayload.capability_id !== capPayload.capability_id) {
    throw new Error("receipt does not bind the issued capability");
  }
  if (receiptPayload.request_digest !== requestDigest) {
    throw new Error("receipt request digest does not match the request");
  }
  if (
    receiptPayload.agent !== request.agent ||
    receiptPayload.action !== request.action ||
    receiptPayload.purpose !== request.purpose ||
    !globMatch(receiptPayload.target, request.target)
  ) {
    throw new Error("receipt execution details do not match the request");
  }
  if (
    typeof receiptPayload.evidence_hash !== "string" ||
    !SHA256_RE.test(receiptPayload.evidence_hash)
  ) {
    throw new Error("receipt evidence_hash is invalid");
  }

  const sensorPayload = await verifySensorCommitment(
    packet.sensor_commitment,
    { trustedSensors }
  );
  const sensorHash = await sensorEvidenceHash(packet.sensor_commitment);
  if (receiptPayload.evidence_hash !== sensorHash) {
    throw new Error("receipt evidence does not match the sensor commitment");
  }
  if (
    !Array.isArray(sensorPayload.readings) ||
    sensorPayload.readings.length === 0 ||
    !sensorPayload.readings.some(
      (reading) => reading.source_id === packet.device_id
    )
  ) {
    throw new Error("sensor readings are not bound to the attested device");
  }

  const checkpoint = await verifyReceiptCheckpoint(
    packet.receipt_checkpoint,
    { trustedNotaries }
  );
  const expectedChainDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(canonicalJson([packet.receipt]))
    ));
  if (checkpoint.chain_digest !== expectedChainDigest) {
    throw new Error("receipt checkpoint does not anchor this receipt chain");
  }

  const attestation = await verifyDeviceAttestation(
    packet.device_attestation,
    { trustedDevices }
  );
  if (attestation.device_id !== packet.device_id) {
    throw new Error("device attestation does not match the export device_id");
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("device-to-policy export packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    DEVICE_TO_POLICY_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("device-to-policy export packet summary fields are invalid");
  }
  const expectedSummary = {
    artifacts_total: 9,
    policy_verified: true,
    capability_verified: true,
    decision_consistent: true,
    receipt_bound: true,
    sensor_bound: true,
    checkpoint_bound: true,
    attestation_bound: true,
    cross_references_ok: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(
        `device-to-policy export packet summary ${key} is inconsistent`
      );
    }
  }
  return {
    valid: true,
    device_id: packet.device_id,
    policy_id: policyPayload.policy_id,
    policy_digest: capPayload.policy_digest,
    capability_id: capPayload.capability_id,
    receipt_id: receiptPayload.receipt_id,
    evidence_hash: receiptPayload.evidence_hash,
    boot_counter: attestation.boot_counter,
    artifacts_total: summary.artifacts_total,
  };
}

const FLEET_DEVICE_KEYS = [
  "devices",
  "generated_at",
  "overall_result",
  "policy_bundle",
  "schema_version",
  "summary",
  "trusted_policy_issuers",
  "type",
];
const FLEET_DEVICE_SUMMARY_KEYS = [
  "cross_references_ok",
  "device_ids_unique",
  "devices_total",
  "devices_verified",
  "policy_shared",
];

export async function verifyFleetDeviceExport(
  packet,
  {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    trustedSensors,
    trustedNotaries,
    trustedDevices,
    now,
  } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("fleet device export packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== FLEET_DEVICE_KEYS.join(",")) {
    throw new Error("fleet device export packet fields are invalid");
  }
  if (packet.type !== "kinegrant:FleetDeviceExportPacket") {
    throw new Error("wrong fleet device export packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported fleet device export packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "fleet device export packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("fleet device export packet overall_result must be PASS");
  }
  if (
    !Array.isArray(packet.trusted_policy_issuers) ||
    packet.trusted_policy_issuers.length === 0 ||
    packet.trusted_policy_issuers.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "fleet device export packet trusted_policy_issuers must be a non-empty string array"
    );
  }
  if (!Array.isArray(packet.devices) || packet.devices.length === 0) {
    throw new Error("fleet device export packet devices must be a non-empty array");
  }

  const fleetPolicy = await verifyPolicyBundle(
    packet.policy_bundle,
    new Set(packet.trusted_policy_issuers),
    { now }
  );
  const fleetTrust = [...packet.trusted_policy_issuers].sort();

  const deviceIds = [];
  const capabilityIds = [];
  const receiptIds = [];
  for (const devicePacket of packet.devices) {
    if (
      typeof devicePacket !== "object" ||
      devicePacket === null ||
      Array.isArray(devicePacket)
    ) {
      throw new Error("each fleet device export must be an object");
    }
    if (devicePacket.type !== "kinegrant:DeviceToPolicyExportPacket") {
      throw new Error("fleet device export contains a wrong packet type");
    }
    if (
      typeof devicePacket.policy_bundle !== "object" ||
      devicePacket.policy_bundle === null ||
      devicePacket.policy_bundle.payload?.bundle_id !== fleetPolicy.bundle_id
    ) {
      throw new Error(
        "fleet device export policy bundle does not match the shared policy"
      );
    }
    const deviceTrust = [...devicePacket.trusted_policy_issuers].sort();
    if (deviceTrust.join(",") !== fleetTrust.join(",")) {
      throw new Error(
        "fleet device export trust set does not match the shared policy"
      );
    }
    const result = await verifyDeviceToPolicyExport(devicePacket, {
      trustedAuthorities,
      trustedIssuers,
      trustedExecutors,
      trustedSensors,
      trustedNotaries,
      trustedDevices,
      now,
    });
    deviceIds.push(result.device_id);
    capabilityIds.push(result.capability_id);
    receiptIds.push(result.receipt_id);
  }

  if (new Set(deviceIds).size !== deviceIds.length) {
    throw new Error("fleet device export device ids are not unique");
  }
  if (new Set(capabilityIds).size !== capabilityIds.length) {
    throw new Error("fleet device export capability ids are not unique");
  }
  if (new Set(receiptIds).size !== receiptIds.length) {
    throw new Error("fleet device export receipt ids are not unique");
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("fleet device export packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    FLEET_DEVICE_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("fleet device export packet summary fields are invalid");
  }
  const expectedSummary = {
    devices_total: packet.devices.length,
    policy_shared: true,
    devices_verified: packet.devices.length,
    device_ids_unique: true,
    cross_references_ok: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(`fleet device export packet summary ${key} is inconsistent`);
    }
  }
  return {
    valid: true,
    policy_id: fleetPolicy.policy_id,
    policy_digest: fleetPolicy.policy_digest,
    devices_total: packet.devices.length,
    device_ids: deviceIds,
  };
}

const END_TO_END_AUDIT_KEYS = [
  "fleet_export",
  "generated_at",
  "lifecycle_report",
  "overall_result",
  "policy_bundle",
  "revocation_bundle",
  "schema_version",
  "summary",
  "trusted_authorities",
  "type",
];
const END_TO_END_AUDIT_SUMMARY_KEYS = [
  "artifacts_total",
  "cross_references_ok",
  "devices_total",
  "fleet_verified",
  "lifecycle_verified",
  "phases_total",
  "policy_shared",
];

export async function verifyEndToEndAuditExport(
  packet,
  {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    trustedSensors,
    trustedNotaries,
    trustedDevices,
    now,
  } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("end-to-end audit export packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== END_TO_END_AUDIT_KEYS.join(",")) {
    throw new Error("end-to-end audit export packet fields are invalid");
  }
  if (packet.type !== "kinegrant:EndToEndAuditExportPacket") {
    throw new Error("wrong end-to-end audit export packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported end-to-end audit export packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "end-to-end audit export packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("end-to-end audit export packet overall_result must be PASS");
  }
  if (
    !Array.isArray(packet.trusted_authorities) ||
    packet.trusted_authorities.length === 0 ||
    packet.trusted_authorities.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "end-to-end audit export packet trusted_authorities must be a non-empty string array"
    );
  }

  const trustedAuthoritiesSet = new Set(packet.trusted_authorities);
  const policyPayload = await verifyPolicyBundle(
    packet.policy_bundle,
    trustedAuthoritiesSet,
    { now }
  );
  const lifecycle = await verifyFullLifecycleReport(
    packet.lifecycle_report,
    packet.policy_bundle,
    packet.revocation_bundle,
    trustedAuthoritiesSet,
    { now }
  );
  const fleet = await verifyFleetDeviceExport(packet.fleet_export, {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    trustedSensors,
    trustedNotaries,
    trustedDevices,
    now,
  });

  if (fleet.policy_id !== policyPayload.policy_id) {
    throw new Error("fleet export does not share the lifecycle policy");
  }
  if (
    typeof packet.fleet_export.policy_bundle !== "object" ||
    packet.fleet_export.policy_bundle === null ||
    packet.fleet_export.policy_bundle.payload?.bundle_id !== policyPayload.bundle_id
  ) {
    throw new Error("fleet export does not share the lifecycle policy bundle");
  }
  if (
    packet.lifecycle_report.policy_id !== policyPayload.policy_id ||
    packet.lifecycle_report.bundle_id !== policyPayload.bundle_id
  ) {
    throw new Error("lifecycle report does not bind to the shared policy bundle");
  }
  const fleetTrust = [...packet.fleet_export.trusted_policy_issuers].sort();
  if (fleetTrust.some((item) => !trustedAuthoritiesSet.has(item))) {
    throw new Error(
      "fleet export trust anchors are not covered by the audit export trusted_authorities"
    );
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("end-to-end audit export packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    END_TO_END_AUDIT_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("end-to-end audit export packet summary fields are invalid");
  }
  const expectedSummary = {
    artifacts_total: 5 + fleet.devices_total,
    phases_total: lifecycle.phases,
    devices_total: fleet.devices_total,
    policy_shared: true,
    lifecycle_verified: true,
    fleet_verified: true,
    cross_references_ok: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(
        `end-to-end audit export packet summary ${key} is inconsistent`
      );
    }
  }
  return {
    valid: true,
    policy_id: policyPayload.policy_id,
    phases_total: lifecycle.phases,
    devices_total: fleet.devices_total,
    artifacts_total: summary.artifacts_total,
  };
}

const REVOCATION_REISSUE_KEYS = [
  "gate_log",
  "generated_at",
  "overall_result",
  "policy_bundle",
  "receipt",
  "reissued_capability",
  "request",
  "revocation_bundle",
  "revoked_capability_id",
  "schema_version",
  "summary",
  "trusted_authorities",
  "trusted_policy_issuers",
  "type",
];
const GATE_LOG_KEYS = ["reissued_allowed", "revoked_denied"];
const GATE_ENTRY_KEYS = [
  "allowed",
  "capability_id",
  "checked_at",
  "policy_digest",
  "reason",
];
const REVOCATION_REISSUE_SUMMARY_KEYS = [
  "allow_recorded",
  "artifacts_total",
  "closure_complete",
  "deny_recorded",
  "policy_verified",
  "receipt_bound",
  "reissue_verified",
  "revocation_verified",
  "revoked_capability_revoked",
];

export async function verifyRevocationReissueClosure(
  packet,
  {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    now,
  } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("revocation-reissue closure packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== REVOCATION_REISSUE_KEYS.join(",")) {
    throw new Error("revocation-reissue closure packet fields are invalid");
  }
  if (packet.type !== "kinegrant:RevocationReissueClosurePacket") {
    throw new Error("wrong revocation-reissue closure packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported revocation-reissue closure packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "revocation-reissue closure packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("revocation-reissue closure packet overall_result must be PASS");
  }
  if (
    !Array.isArray(packet.trusted_authorities) ||
    packet.trusted_authorities.length === 0 ||
    packet.trusted_authorities.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "revocation-reissue closure packet trusted_authorities must be a non-empty string array"
    );
  }
  if (
    !Array.isArray(packet.trusted_policy_issuers) ||
    packet.trusted_policy_issuers.length === 0 ||
    packet.trusted_policy_issuers.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "revocation-reissue closure packet trusted_policy_issuers must be a non-empty string array"
    );
  }
  if (
    typeof packet.revoked_capability_id !== "string" ||
    packet.revoked_capability_id.length === 0
  ) {
    throw new Error(
      "revocation-reissue closure packet revoked_capability_id must be non-empty"
    );
  }

  const trustedAuthoritiesSet = new Set(packet.trusted_authorities);
  const policyPayload = await verifyPolicyBundle(
    packet.policy_bundle,
    trustedAuthoritiesSet,
    { now }
  );
  if (!packet.trusted_policy_issuers.includes(policyPayload.issuer)) {
    throw new Error(
      "revocation-reissue closure policy authority is not in trusted_policy_issuers"
    );
  }
  const revocationPayload = await verifyRevocationBundle(
    packet.revocation_bundle,
    trustedAuthoritiesSet
  );
  if (
    !Array.isArray(revocationPayload.revocations) ||
    !revocationPayload.revocations.some(
      (entry) => entry.capability_id === packet.revoked_capability_id
    )
  ) {
    throw new Error(
      "revocation-reissue closure revoked capability id is not in the revocation bundle"
    );
  }

  const request = packet.request;
  if (
    typeof request !== "object" ||
    request === null ||
    Array.isArray(request)
  ) {
    throw new Error("revocation-reissue closure packet request must be an object");
  }
  if (request.type !== "kinegrant:ActionRequest" || request.version !== "0.1") {
    throw new Error(
      "revocation-reissue closure packet request must be a v0.1 action request"
    );
  }
  const requestDigest = await digestOfObject(request);
  const reissuedPayload = await verifyCapability(
    packet.reissued_capability,
    request,
    trustedIssuers ?? new Set(packet.trusted_policy_issuers)
  );
  if (reissuedPayload.request_digest !== requestDigest) {
    throw new Error("reissued capability does not authorize this request");
  }
  if (reissuedPayload.capability_id === packet.revoked_capability_id) {
    throw new Error("reissued capability is the revoked capability");
  }
  const expectedPolicyDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(
        canonicalJson({
          rules: policyPayload.rules,
          trusted_policy_issuers: [...packet.trusted_policy_issuers].sort(),
        })
      )
    ));
  if (reissuedPayload.policy_digest !== expectedPolicyDigest) {
    throw new Error(
      "reissued capability policy digest does not match the policy bundle and trust set"
    );
  }
  const rulePolicyIds = new Set(
    policyPayload.rules.map((rule) => rule.policy_id)
  );
  if (
    !Array.isArray(reissuedPayload.matched_policy_ids) ||
    reissuedPayload.matched_policy_ids.length === 0 ||
    reissuedPayload.matched_policy_ids.some((id) => !rulePolicyIds.has(id))
  ) {
    throw new Error("reissued capability matched policies do not match the policy bundle");
  }

  const gateLog = packet.gate_log;
  if (
    typeof gateLog !== "object" ||
    gateLog === null ||
    Array.isArray(gateLog)
  ) {
    throw new Error("gate log must be an object");
  }
  if (Object.keys(gateLog).sort().join(",") !== GATE_LOG_KEYS.join(",")) {
    throw new Error("gate log fields are invalid");
  }
  const denied = gateLog.revoked_denied;
  const allowed = gateLog.reissued_allowed;
  for (const entry of [denied, allowed]) {
    if (
      typeof entry !== "object" ||
      entry === null ||
      Array.isArray(entry) ||
      Object.keys(entry).sort().join(",") !== GATE_ENTRY_KEYS.join(",")
    ) {
      throw new Error("gate log entries are invalid");
    }
    if (typeof entry.checked_at !== "string" || Number.isNaN(Date.parse(entry.checked_at))) {
      throw new Error("gate log entry checked_at is invalid");
    }
    if (typeof entry.reason !== "string" || entry.reason.length === 0) {
      throw new Error("gate log entry reason is invalid");
    }
    if (entry.policy_digest !== reissuedPayload.policy_digest) {
      throw new Error("gate log entry does not reference the verified policy");
    }
  }
  if (denied.allowed !== false || denied.capability_id !== packet.revoked_capability_id) {
    throw new Error("gate log revoked denial does not reference the revoked capability");
  }
  if (allowed.allowed !== true || allowed.capability_id !== reissuedPayload.capability_id) {
    throw new Error("gate log reissue allow does not reference the reissued capability");
  }
  if (
    Date.parse(allowed.checked_at) <= Date.parse(denied.checked_at)
  ) {
    throw new Error("gate log reissue allow must follow the revoked denial");
  }

  const receipt = packet.receipt;
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
    throw new Error("revocation-reissue closure packet receipt must be an object");
  }
  await verifyReceiptChain([receipt], trustedExecutors);
  const receiptPayload = await verifyEnvelope(receipt);
  if (receiptPayload.type !== "kinegrant:PhysicalActionReceipt") {
    throw new Error("receipt payload type is invalid");
  }
  if (receiptPayload.capability_id !== reissuedPayload.capability_id) {
    throw new Error("receipt does not bind the reissued capability");
  }
  if (receiptPayload.request_digest !== requestDigest) {
    throw new Error("receipt request digest does not match the request");
  }
  if (
    receiptPayload.agent !== request.agent ||
    receiptPayload.action !== request.action ||
    receiptPayload.purpose !== request.purpose ||
    !globMatch(receiptPayload.target, request.target)
  ) {
    throw new Error("receipt execution details do not match the request");
  }
  if (
    typeof receiptPayload.evidence_hash !== "string" ||
    !SHA256_RE.test(receiptPayload.evidence_hash)
  ) {
    throw new Error("receipt evidence_hash is invalid");
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("revocation-reissue closure packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    REVOCATION_REISSUE_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("revocation-reissue closure packet summary fields are invalid");
  }
  const expectedSummary = {
    artifacts_total: 8,
    policy_verified: true,
    revocation_verified: true,
    revoked_capability_revoked: true,
    deny_recorded: true,
    reissue_verified: true,
    allow_recorded: true,
    receipt_bound: true,
    closure_complete: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(
        `revocation-reissue closure packet summary ${key} is inconsistent`
      );
    }
  }
  return {
    valid: true,
    policy_id: policyPayload.policy_id,
    revoked_capability_id: packet.revoked_capability_id,
    reissued_capability_id: reissuedPayload.capability_id,
    receipt_id: receiptPayload.receipt_id,
  };
}

const UNIFIED_AUDIT_KEYS = [
  "closure",
  "fleet_export",
  "generated_at",
  "lifecycle_report",
  "overall_result",
  "policy_bundle",
  "revocation_bundle",
  "schema_version",
  "summary",
  "trusted_authorities",
  "type",
];
const UNIFIED_AUDIT_SUMMARY_KEYS = [
  "artifacts_total",
  "closure_verified",
  "cross_references_ok",
  "devices_total",
  "fleet_verified",
  "lifecycle_verified",
  "phases_total",
  "policy_shared",
];

export async function verifyUnifiedAuditExport(
  packet,
  {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    trustedSensors,
    trustedNotaries,
    trustedDevices,
    now,
  } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("unified audit export packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== UNIFIED_AUDIT_KEYS.join(",")) {
    throw new Error("unified audit export packet fields are invalid");
  }
  if (packet.type !== "kinegrant:UnifiedAuditExportPacket") {
    throw new Error("wrong unified audit export packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported unified audit export packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "unified audit export packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("unified audit export packet overall_result must be PASS");
  }
  if (
    !Array.isArray(packet.trusted_authorities) ||
    packet.trusted_authorities.length === 0 ||
    packet.trusted_authorities.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "unified audit export packet trusted_authorities must be a non-empty string array"
    );
  }

  const trustedAuthoritiesSet = new Set(packet.trusted_authorities);
  const policyPayload = await verifyPolicyBundle(
    packet.policy_bundle,
    trustedAuthoritiesSet,
    { now }
  );
  const lifecycle = await verifyFullLifecycleReport(
    packet.lifecycle_report,
    packet.policy_bundle,
    packet.revocation_bundle,
    trustedAuthoritiesSet,
    { now }
  );
  const fleet = await verifyFleetDeviceExport(packet.fleet_export, {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    trustedSensors,
    trustedNotaries,
    trustedDevices,
    now,
  });
  const closure = await verifyRevocationReissueClosure(packet.closure, {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    now,
  });

  if (fleet.policy_id !== policyPayload.policy_id) {
    throw new Error("fleet export does not share the unified audit policy");
  }
  if (
    typeof packet.fleet_export.policy_bundle !== "object" ||
    packet.fleet_export.policy_bundle === null ||
    packet.fleet_export.policy_bundle.payload?.bundle_id !== policyPayload.bundle_id
  ) {
    throw new Error("fleet export does not share the unified policy bundle");
  }
  if (closure.policy_id !== policyPayload.policy_id) {
    throw new Error("revocation-reissue closure does not share the unified audit policy");
  }
  if (
    typeof packet.closure.policy_bundle !== "object" ||
    packet.closure.policy_bundle === null ||
    packet.closure.policy_bundle.payload?.bundle_id !== policyPayload.bundle_id
  ) {
    throw new Error("revocation-reissue closure does not share the unified policy bundle");
  }
  if (
    typeof packet.closure.revocation_bundle !== "object" ||
    packet.closure.revocation_bundle === null ||
    packet.closure.revocation_bundle.payload?.bundle_id !==
      packet.revocation_bundle.payload.bundle_id
  ) {
    throw new Error(
      "revocation-reissue closure does not share the unified revocation bundle"
    );
  }
  for (const item of packet.fleet_export.trusted_policy_issuers) {
    if (!trustedAuthoritiesSet.has(item)) {
      throw new Error(
        "fleet export trust anchors are not covered by the unified audit trusted_authorities"
      );
    }
  }
  for (const item of [
    ...packet.closure.trusted_authorities,
    ...packet.closure.trusted_policy_issuers,
  ]) {
    if (!trustedAuthoritiesSet.has(item)) {
      throw new Error(
        "revocation-reissue closure trust anchors are not covered by the unified audit trusted_authorities"
      );
    }
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("unified audit export packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    UNIFIED_AUDIT_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("unified audit export packet summary fields are invalid");
  }
  const expectedSummary = {
    artifacts_total: 6 + fleet.devices_total,
    phases_total: lifecycle.phases,
    devices_total: fleet.devices_total,
    policy_shared: true,
    lifecycle_verified: true,
    fleet_verified: true,
    closure_verified: true,
    cross_references_ok: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(`unified audit export packet summary ${key} is inconsistent`);
    }
  }
  return {
    valid: true,
    policy_id: policyPayload.policy_id,
    phases_total: lifecycle.phases,
    devices_total: fleet.devices_total,
    closure_revoked: closure.revoked_capability_id,
    closure_reissued: closure.reissued_capability_id,
    artifacts_total: summary.artifacts_total,
  };
}

const MIGRATION_AUDIT_KEYS = [
  "distribution_report",
  "generated_at",
  "migration",
  "new_capability",
  "new_policy_bundle",
  "old_capability",
  "old_capability_id",
  "old_policy_bundle",
  "overall_result",
  "receipt",
  "request",
  "schema_version",
  "summary",
  "trusted_authorities",
  "type",
];
const MIGRATION_GATE_LOG_KEYS = ["new_allowed", "old_denied"];
const MIGRATION_GATE_ENTRY_KEYS = [
  "allowed",
  "capability_id",
  "checked_at",
  "policy_digest",
  "reason",
];
const MIGRATION_SUMMARY_KEYS = [
  "artifacts_total",
  "closure_complete",
  "distribution_verified",
  "gate_order_ok",
  "migration_verified",
  "new_policy_verified",
  "old_policy_verified",
  "receipt_bound",
  "version_chain",
];

export async function verifyPolicyMigrationAudit(
  packet,
  {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    now,
  } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("policy migration audit packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== MIGRATION_AUDIT_KEYS.join(",")) {
    throw new Error("policy migration audit packet fields are invalid");
  }
  if (packet.type !== "kinegrant:PolicyMigrationAuditPacket") {
    throw new Error("wrong policy migration audit packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported policy migration audit packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "policy migration audit packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("policy migration audit packet overall_result must be PASS");
  }
  if (
    !Array.isArray(packet.trusted_authorities) ||
    packet.trusted_authorities.length === 0 ||
    packet.trusted_authorities.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "policy migration audit packet trusted_authorities must be a non-empty string array"
    );
  }
  if (
    typeof packet.old_capability_id !== "string" ||
    packet.old_capability_id.length === 0
  ) {
    throw new Error("policy migration audit packet old_capability_id must be non-empty");
  }
  const trustedAuthoritiesSet = new Set(packet.trusted_authorities);
  const oldPayload = await verifyPolicyBundle(
    packet.old_policy_bundle,
    trustedAuthoritiesSet,
    { now }
  );
  const newPayload = await verifyPolicyBundle(
    packet.new_policy_bundle,
    trustedAuthoritiesSet,
    { now }
  );
  if (oldPayload.policy_id !== newPayload.policy_id) {
    throw new Error("policy id changed during migration");
  }
  if (newPayload.version !== oldPayload.version + 1) {
    throw new Error("new policy version must be exactly old version + 1");
  }
  if (newPayload.previous_version_digest !== oldPayload.policy_digest) {
    throw new Error("policy version chain is broken");
  }
  await verifyPolicyDistributionReport(
    packet.distribution_report,
    packet.new_policy_bundle,
    trustedAuthoritiesSet,
    { now }
  );

  const request = packet.request;
  if (
    typeof request !== "object" ||
    request === null ||
    Array.isArray(request)
  ) {
    throw new Error("policy migration audit packet request must be an object");
  }
  if (request.type !== "kinegrant:ActionRequest" || request.version !== "0.1") {
    throw new Error(
      "policy migration audit packet request must be a v0.1 action request"
    );
  }
  const requestDigest = await digestOfObject(request);
  const expectedOldPolicyDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(
        canonicalJson({
          rules: oldPayload.rules,
          trusted_policy_issuers: [...packet.trusted_authorities].sort(),
        })
      )
    ));
  const expectedNewPolicyDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(
        canonicalJson({
          rules: newPayload.rules,
          trusted_policy_issuers: [...packet.trusted_authorities].sort(),
        })
      )
    ));
  const oldCapPayload = await verifyCapability(
    packet.old_capability,
    request,
    trustedIssuers ?? trustedAuthoritiesSet
  );
  if (oldCapPayload.request_digest !== requestDigest) {
    throw new Error("old capability does not authorize this request");
  }
  if (oldCapPayload.capability_id !== packet.old_capability_id) {
    throw new Error("old capability id does not match the packet");
  }
  if (oldCapPayload.policy_digest !== expectedOldPolicyDigest) {
    throw new Error("old capability is not bound to the old policy");
  }
  const oldRuleIds = new Set(oldPayload.rules.map((rule) => rule.policy_id));
  if (
    !Array.isArray(oldCapPayload.matched_policy_ids) ||
    oldCapPayload.matched_policy_ids.length === 0 ||
    oldCapPayload.matched_policy_ids.some((id) => !oldRuleIds.has(id))
  ) {
    throw new Error("old capability matched policies do not match the old bundle");
  }
  const newCapPayload = await verifyCapability(
    packet.new_capability,
    request,
    trustedIssuers ?? trustedAuthoritiesSet
  );
  if (newCapPayload.request_digest !== requestDigest) {
    throw new Error("new capability does not authorize this request");
  }
  if (newCapPayload.capability_id === packet.old_capability_id) {
    throw new Error("new capability is the old capability");
  }
  if (newCapPayload.policy_digest !== expectedNewPolicyDigest) {
    throw new Error("new capability is not bound to the new policy");
  }
  const newRuleIds = new Set(newPayload.rules.map((rule) => rule.policy_id));
  if (
    !Array.isArray(newCapPayload.matched_policy_ids) ||
    newCapPayload.matched_policy_ids.length === 0 ||
    newCapPayload.matched_policy_ids.some((id) => !newRuleIds.has(id))
  ) {
    throw new Error("new capability matched policies do not match the new bundle");
  }

  const migration = packet.migration;
  if (
    typeof migration !== "object" ||
    migration === null ||
    Array.isArray(migration) ||
    Object.keys(migration).sort().join(",") !== "gate_log"
  ) {
    throw new Error("migration fields are invalid");
  }
  const gateLog = migration.gate_log;
  if (
    typeof gateLog !== "object" ||
    gateLog === null ||
    Array.isArray(gateLog) ||
    Object.keys(gateLog).sort().join(",") !== MIGRATION_GATE_LOG_KEYS.join(",")
  ) {
    throw new Error("migration gate log fields are invalid");
  }
  const oldDenied = gateLog.old_denied;
  const newAllowed = gateLog.new_allowed;
  for (const entry of [oldDenied, newAllowed]) {
    if (
      typeof entry !== "object" ||
      entry === null ||
      Array.isArray(entry) ||
      Object.keys(entry).sort().join(",") !== MIGRATION_GATE_ENTRY_KEYS.join(",")
    ) {
      throw new Error("migration gate log entries are invalid");
    }
    if (typeof entry.checked_at !== "string" || Number.isNaN(Date.parse(entry.checked_at))) {
      throw new Error("migration gate log entry checked_at is invalid");
    }
    if (typeof entry.reason !== "string" || entry.reason.length === 0) {
      throw new Error("migration gate log entry reason is invalid");
    }
  }
  if (
    oldDenied.allowed !== false ||
    oldDenied.capability_id !== packet.old_capability_id ||
    oldDenied.policy_digest !== expectedOldPolicyDigest
  ) {
    throw new Error("migration gate log old denial does not match the old capability");
  }
  if (
    newAllowed.allowed !== true ||
    newAllowed.capability_id !== newCapPayload.capability_id ||
    newAllowed.policy_digest !== expectedNewPolicyDigest
  ) {
    throw new Error("migration gate log new allow does not match the new capability");
  }
  if (Date.parse(newAllowed.checked_at) <= Date.parse(oldDenied.checked_at)) {
    throw new Error("migration gate log new allow must follow the old denial");
  }

  const receipt = packet.receipt;
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
    throw new Error("policy migration audit packet receipt must be an object");
  }
  await verifyReceiptChain([receipt], trustedExecutors);
  const receiptPayload = await verifyEnvelope(receipt);
  if (receiptPayload.type !== "kinegrant:PhysicalActionReceipt") {
    throw new Error("receipt payload type is invalid");
  }
  if (receiptPayload.capability_id !== newCapPayload.capability_id) {
    throw new Error("receipt does not bind the new capability");
  }
  if (receiptPayload.request_digest !== requestDigest) {
    throw new Error("receipt request digest does not match the request");
  }
  if (
    receiptPayload.agent !== request.agent ||
    receiptPayload.action !== request.action ||
    receiptPayload.purpose !== request.purpose ||
    !globMatch(receiptPayload.target, request.target)
  ) {
    throw new Error("receipt execution details do not match the request");
  }
  if (
    typeof receiptPayload.evidence_hash !== "string" ||
    !SHA256_RE.test(receiptPayload.evidence_hash)
  ) {
    throw new Error("receipt evidence_hash is invalid");
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("policy migration audit packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !== MIGRATION_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("policy migration audit packet summary fields are invalid");
  }
  const expectedSummary = {
    artifacts_total: 10,
    old_policy_verified: true,
    new_policy_verified: true,
    version_chain: true,
    distribution_verified: true,
    migration_verified: true,
    gate_order_ok: true,
    receipt_bound: true,
    closure_complete: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(`policy migration audit packet summary ${key} is inconsistent`);
    }
  }
  return {
    valid: true,
    policy_id: oldPayload.policy_id,
    old_version: oldPayload.version,
    new_version: newPayload.version,
    old_capability_id: packet.old_capability_id,
    new_capability_id: newCapPayload.capability_id,
    receipt_id: receiptPayload.receipt_id,
  };
}

const TIMELINE_KEYS = [
  "device_id",
  "events",
  "generated_at",
  "overall_result",
  "policy_bundle",
  "schema_version",
  "summary",
  "trusted_authorities",
  "type",
];
const TIMELINE_SUMMARY_KEYS = [
  "device_bound",
  "events_total",
  "kinds_unique",
  "monotonic",
  "policy_bound",
  "references_ok",
  "timeline_complete",
];
const TIMELINE_EVENT_KINDS = new Set([
  "capability_issued",
  "gate_allowed",
  "receipt_signed",
  "capability_revoked",
  "gate_denied",
  "capability_reissued",
]);
const TIMELINE_EVENT_KEYS = {
  capability_issued: ["actor", "at", "capability_id", "kind", "policy_digest", "request_digest"],
  gate_allowed: ["at", "capability_id", "kind", "policy_digest", "reason"],
  receipt_signed: ["at", "capability_id", "evidence_hash", "kind", "receipt_id"],
  capability_revoked: ["at", "capability_id", "kind", "reason"],
  gate_denied: ["at", "capability_id", "kind", "policy_digest", "reason"],
  capability_reissued: ["at", "kind", "new_capability_id", "old_capability_id", "policy_digest"],
};

export async function verifyComplianceTimeline(
  packet,
  {
    trustedAuthorities,
    now,
  } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("compliance timeline packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== TIMELINE_KEYS.join(",")) {
    throw new Error("compliance timeline packet fields are invalid");
  }
  if (packet.type !== "kinegrant:ComplianceTimelinePacket") {
    throw new Error("wrong compliance timeline packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported compliance timeline packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "compliance timeline packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("compliance timeline packet overall_result must be PASS");
  }
  if (typeof packet.device_id !== "string" || packet.device_id.length === 0) {
    throw new Error("compliance timeline packet device_id must be non-empty");
  }
  if (
    !Array.isArray(packet.trusted_authorities) ||
    packet.trusted_authorities.length === 0 ||
    packet.trusted_authorities.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "compliance timeline packet trusted_authorities must be a non-empty string array"
    );
  }

  const policyPayload = await verifyPolicyBundle(
    packet.policy_bundle,
    new Set(packet.trusted_authorities),
    { now }
  );
  const expectedPolicyDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(
        canonicalJson({
          rules: policyPayload.rules,
          trusted_policy_issuers: [...packet.trusted_authorities].sort(),
        })
      )
    ));
  if (!Array.isArray(packet.events) || packet.events.length === 0) {
    throw new Error("compliance timeline packet events must be a non-empty array");
  }

  const issued = new Set();
  const allowed = new Set();
  const revoked = new Set();
  const receiptIds = new Set();
  let previousAt = -Infinity;
  for (const event of packet.events) {
    if (typeof event !== "object" || event === null || Array.isArray(event)) {
      throw new Error("each timeline event must be an object");
    }
    if (typeof event.kind !== "string" || !TIMELINE_EVENT_KINDS.has(event.kind)) {
      throw new Error("timeline event kind is unknown");
    }
    const expectedKeys = TIMELINE_EVENT_KEYS[event.kind];
    if (Object.keys(event).sort().join(",") !== expectedKeys.join(",")) {
      throw new Error(`timeline event ${event.kind} fields are invalid`);
    }
    if (typeof event.at !== "string" || Number.isNaN(Date.parse(event.at))) {
      throw new Error("timeline event at is invalid");
    }
    const atMs = Date.parse(event.at);
    if (atMs < previousAt) {
      throw new Error("timeline events are not monotonically ordered");
    }
    previousAt = atMs;
    if (event.kind === "capability_issued") {
      if (
        typeof event.capability_id !== "string" ||
        event.capability_id.length === 0 ||
        typeof event.request_digest !== "string" ||
        event.request_digest.length === 0 ||
        typeof event.actor !== "string" ||
        event.actor.length === 0
      ) {
        throw new Error("capability_issued event fields are invalid");
      }
      if (event.policy_digest !== expectedPolicyDigest) {
        throw new Error("capability_issued event does not bind the timeline policy");
      }
      issued.add(event.capability_id);
    } else if (event.kind === "gate_allowed") {
      if (!issued.has(event.capability_id)) {
        throw new Error("gate_allowed references a capability that was never issued");
      }
      if (event.policy_digest !== expectedPolicyDigest) {
        throw new Error("gate_allowed event does not bind the timeline policy");
      }
      if (typeof event.reason !== "string" || event.reason.length === 0) {
        throw new Error("gate_allowed reason is invalid");
      }
      allowed.add(event.capability_id);
    } else if (event.kind === "receipt_signed") {
      if (!allowed.has(event.capability_id)) {
        throw new Error("receipt_signed references a capability that was never allowed");
      }
      if (typeof event.receipt_id !== "string" || event.receipt_id.length === 0) {
        throw new Error("receipt_signed receipt_id is invalid");
      }
      if (receiptIds.has(event.receipt_id)) {
        throw new Error("receipt_signed receipt_id must be unique");
      }
      receiptIds.add(event.receipt_id);
      if (typeof event.evidence_hash !== "string" || !SHA256_RE.test(event.evidence_hash)) {
        throw new Error("receipt_signed evidence_hash is invalid");
      }
    } else if (event.kind === "capability_revoked") {
      if (!issued.has(event.capability_id)) {
        throw new Error("capability_revoked references a capability that was never issued");
      }
      if (typeof event.reason !== "string" || event.reason.length === 0) {
        throw new Error("capability_revoked reason is invalid");
      }
      revoked.add(event.capability_id);
    } else if (event.kind === "gate_denied") {
      if (!issued.has(event.capability_id)) {
        throw new Error("gate_denied references a capability that was never issued");
      }
      if (event.policy_digest !== expectedPolicyDigest) {
        throw new Error("gate_denied event does not bind the timeline policy");
      }
      if (typeof event.reason !== "string" || event.reason.length === 0) {
        throw new Error("gate_denied reason is invalid");
      }
    } else if (event.kind === "capability_reissued") {
      if (!issued.has(event.old_capability_id)) {
        throw new Error("capability_reissued references a capability that was never issued");
      }
      if (issued.has(event.new_capability_id)) {
        throw new Error("capability_reissued new capability id was already issued");
      }
      if (event.policy_digest !== expectedPolicyDigest) {
        throw new Error("capability_reissued event does not bind the timeline policy");
      }
      issued.add(event.new_capability_id);
    }
  }
  if (revoked.size === 0) {
    throw new Error("compliance timeline has no revocation event");
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("compliance timeline packet summary must be an object");
  }
  if (Object.keys(summary).sort().join(",") !== TIMELINE_SUMMARY_KEYS.join(",")) {
    throw new Error("compliance timeline packet summary fields are invalid");
  }
  const expectedSummary = {
    events_total: packet.events.length,
    kinds_unique: new Set(packet.events.map((event) => event.kind)).size,
    monotonic: true,
    policy_bound: true,
    device_bound: true,
    references_ok: true,
    timeline_complete: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(`compliance timeline packet summary ${key} is inconsistent`);
    }
  }
  return {
    valid: true,
    device_id: packet.device_id,
    policy_id: policyPayload.policy_id,
    events_total: packet.events.length,
    first_at: packet.events[0].at,
    last_at: packet.events[packet.events.length - 1].at,
  };
}

const OBLIGATION_FULFILLMENT_KEYS = [
  "capability",
  "device_id",
  "generated_at",
  "overall_result",
  "policy_bundle",
  "receipts",
  "request",
  "schema_version",
  "summary",
  "trusted_authorities",
  "type",
];
const OBLIGATION_FULFILLMENT_SUMMARY_KEYS = [
  "artifacts_total",
  "capabilities",
  "obligations_covered",
  "obligations_required",
  "receipts_total",
  "references_ok",
];
const OBLIGATION_FULFILLMENT_STATUSES = new Set(["satisfied", "failed", "pending"]);

export async function verifyObligationFulfillment(
  packet,
  {
    trustedAuthorities,
    trustedIssuers,
    trustedExecutors,
    now,
  } = {}
) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("obligation fulfillment packet must be an object");
  }
  if (
    Object.keys(packet).sort().join(",") !==
    OBLIGATION_FULFILLMENT_KEYS.join(",")
  ) {
    throw new Error("obligation fulfillment packet fields are invalid");
  }
  if (packet.type !== "kinegrant:ObligationFulfillmentPacket") {
    throw new Error("wrong obligation fulfillment packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported obligation fulfillment packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "obligation fulfillment packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("obligation fulfillment packet overall_result must be PASS");
  }
  if (typeof packet.device_id !== "string" || packet.device_id.length === 0) {
    throw new Error("obligation fulfillment packet device_id must be non-empty");
  }
  if (
    !Array.isArray(packet.trusted_authorities) ||
    packet.trusted_authorities.length === 0 ||
    packet.trusted_authorities.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(
      "obligation fulfillment packet trusted_authorities must be a non-empty string array"
    );
  }

  const trustedAuthoritiesSet = new Set(packet.trusted_authorities);
  const policyPayload = await verifyPolicyBundle(
    packet.policy_bundle,
    trustedAuthoritiesSet,
    { now }
  );
  const expectedPolicyDigest =
    "sha256:" +
    (await sha256Hex(
      new TextEncoder().encode(
        canonicalJson({
          rules: policyPayload.rules,
          trusted_policy_issuers: [...packet.trusted_authorities].sort(),
        })
      )
    ));
  const request = packet.request;
  if (
    typeof request !== "object" ||
    request === null ||
    Array.isArray(request)
  ) {
    throw new Error("obligation fulfillment packet request must be an object");
  }
  if (request.type !== "kinegrant:ActionRequest" || request.version !== "0.1") {
    throw new Error(
      "obligation fulfillment packet request must be a v0.1 action request"
    );
  }
  const requestDigest = await digestOfObject(request);
  const capPayload = await verifyCapability(
    packet.capability,
    request,
    trustedIssuers ?? trustedAuthoritiesSet
  );
  if (capPayload.request_digest !== requestDigest) {
    throw new Error("capability does not authorize this request");
  }
  if (capPayload.policy_digest !== expectedPolicyDigest) {
    throw new Error("capability policy digest does not match the policy bundle and trust set");
  }
  if (!Array.isArray(capPayload.obligations) || capPayload.obligations.length === 0) {
    throw new Error("capability carries no obligations to track");
  }
  const requiredObligations = new Set(capPayload.obligations);

  if (!Array.isArray(packet.receipts) || packet.receipts.length === 0) {
    throw new Error("obligation fulfillment packet receipts must be a non-empty array");
  }
  await verifyReceiptChain(packet.receipts, trustedExecutors);
  const covered = new Set();
  for (const receipt of packet.receipts) {
    const receiptPayload = await verifyEnvelope(receipt);
    if (receiptPayload.type !== "kinegrant:PhysicalActionReceipt") {
      throw new Error("receipt payload type is invalid");
    }
    if (receiptPayload.version !== "1.0") {
      throw new Error("obligation tracking requires receipt version 1.0");
    }
    if (receiptPayload.capability_id !== capPayload.capability_id) {
      throw new Error("receipt does not bind the tracked capability");
    }
    if (receiptPayload.request_digest !== requestDigest) {
      throw new Error("receipt request digest does not match the request");
    }
    if (
      !Array.isArray(receiptPayload.obligation_results) ||
      receiptPayload.obligation_results.length === 0
    ) {
      throw new Error("receipt has no obligation results");
    }
    for (const result of receiptPayload.obligation_results) {
      if (
        typeof result !== "object" ||
        result === null ||
        Array.isArray(result) ||
        typeof result.obligation !== "string" ||
        !KNOWN_OBLIGATIONS.has(result.obligation) ||
        typeof result.status !== "string" ||
        !OBLIGATION_FULFILLMENT_STATUSES.has(result.status)
      ) {
        throw new Error("receipt obligation result is invalid");
      }
      if (requiredObligations.has(result.obligation)) {
        if (result.status === "pending") {
          throw new Error(
            `required obligation ${result.obligation} is still pending`
          );
        }
        if (
          result.status === "failed" &&
          (typeof result.failure_reason !== "string" ||
            result.failure_reason.length === 0)
        ) {
          throw new Error(
            `failed obligation ${result.obligation} requires a failure_reason`
          );
        }
        covered.add(result.obligation);
      }
    }
  }
  if (covered.size !== requiredObligations.size) {
    throw new Error("receipts do not cover every required obligation");
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("obligation fulfillment packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    OBLIGATION_FULFILLMENT_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("obligation fulfillment packet summary fields are invalid");
  }
  const expectedSummary = {
    artifacts_total: 5 + packet.receipts.length,
    capabilities: 1,
    receipts_total: packet.receipts.length,
    obligations_required: requiredObligations.size,
    obligations_covered: covered.size,
    references_ok: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(`obligation fulfillment packet summary ${key} is inconsistent`);
    }
  }
  return {
    valid: true,
    device_id: packet.device_id,
    policy_id: policyPayload.policy_id,
    capability_id: capPayload.capability_id,
    receipts_total: packet.receipts.length,
    obligations_required: requiredObligations.size,
    obligations_covered: covered.size,
  };
}

const SELECTIVE_DISCLOSURE_KEYS = [
  "document_id",
  "generated_at",
  "overall_result",
  "root",
  "schema_version",
  "summary",
  "type",
  "visible",
];
const SELECTIVE_DISCLOSURE_SUMMARY_KEYS = [
  "artifacts_total",
  "document_bound",
  "fields_total",
  "proofs_verified",
  "root_bound",
];
const PROOF_STEP_KEYS = ["hash", "left"];

export async function verifySelectiveDisclosure(packet, { now } = {}) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("selective disclosure packet must be an object");
  }
  if (
    Object.keys(packet).sort().join(",") !==
    SELECTIVE_DISCLOSURE_KEYS.join(",")
  ) {
    throw new Error("selective disclosure packet fields are invalid");
  }
  if (packet.type !== "kinegrant:SelectiveDisclosurePacket") {
    throw new Error("wrong selective disclosure packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported selective disclosure packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "selective disclosure packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("selective disclosure packet overall_result must be PASS");
  }
  if (typeof packet.document_id !== "string" || packet.document_id.length === 0) {
    throw new Error("selective disclosure packet document_id must be non-empty");
  }
  if (typeof packet.root !== "string" || !SHA256_RE.test(packet.root)) {
    throw new Error("selective disclosure packet root is invalid");
  }
  if (!Array.isArray(packet.visible) || packet.visible.length === 0) {
    throw new Error("selective disclosure packet visible must be a non-empty array");
  }

  const fields = new Set();
  for (const entry of packet.visible) {
    if (
      typeof entry !== "object" ||
      entry === null ||
      Array.isArray(entry) ||
      typeof entry.field !== "string" ||
      entry.field.length === 0 ||
      !Object.prototype.hasOwnProperty.call(entry, "value") ||
      !Array.isArray(entry.proof)
    ) {
      throw new Error("each visible entry must have field, value, and proof");
    }
    if (fields.has(entry.field)) {
      throw new Error("visible field names must be unique");
    }
    fields.add(entry.field);
    let current =
      "sha256:" +
      (await sha256Hex(
        new TextEncoder().encode(
          canonicalJson({ field: entry.field, value: entry.value })
        )
      ));
    for (const step of entry.proof) {
      if (
        typeof step !== "object" ||
        step === null ||
        Array.isArray(step) ||
        Object.keys(step).sort().join(",") !== PROOF_STEP_KEYS.join(",") ||
        typeof step.hash !== "string" ||
        !SHA256_RE.test(step.hash) ||
        typeof step.left !== "boolean"
      ) {
        throw new Error("proof step is invalid");
      }
      const next =
        "sha256:" +
        (await sha256Hex(
          new TextEncoder().encode(
            step.left
              ? canonicalJson({ left: step.hash, right: current })
              : canonicalJson({ left: current, right: step.hash })
          )
        ));
      current = next;
    }
    if (current !== packet.root) {
      throw new Error(`proof for field ${entry.field} does not reach the root`);
    }
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("selective disclosure packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    SELECTIVE_DISCLOSURE_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("selective disclosure packet summary fields are invalid");
  }
  const expectedSummary = {
    artifacts_total: 3,
    fields_total: packet.visible.length,
    proofs_verified: packet.visible.length,
    root_bound: true,
    document_bound: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(`selective disclosure packet summary ${key} is inconsistent`);
    }
  }
  return {
    valid: true,
    document_id: packet.document_id,
    root: packet.root,
    fields_total: packet.visible.length,
  };
}

const IDENTIFIER_ROTATION_KEYS = [
  "generated_at",
  "namespace",
  "overall_result",
  "rotations",
  "schema_version",
  "static_id",
  "summary",
  "type",
];
const IDENTIFIER_ROTATION_SUMMARY_KEYS = [
  "active_total",
  "artifacts_total",
  "chain_complete",
  "revoked_total",
  "rotations_total",
  "statuses_ok",
];
const ROTATION_ENTRY_KEYS = ["ephemeral_id", "issued_at", "revoked_at", "status"];

export async function verifyIdentifierRotation(packet, { now } = {}) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("identifier rotation packet must be an object");
  }
  if (
    Object.keys(packet).sort().join(",") !==
    IDENTIFIER_ROTATION_KEYS.join(",")
  ) {
    throw new Error("identifier rotation packet fields are invalid");
  }
  if (packet.type !== "kinegrant:IdentifierRotationPacket") {
    throw new Error("wrong identifier rotation packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported identifier rotation packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "identifier rotation packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("identifier rotation packet overall_result must be PASS");
  }
  if (
    typeof packet.namespace !== "string" ||
    !/^[a-z0-9.-]{1,63}$/.test(packet.namespace)
  ) {
    throw new Error("identifier rotation packet namespace is invalid");
  }
  if (typeof packet.static_id !== "string" || packet.static_id.length === 0) {
    throw new Error("identifier rotation packet static_id must be non-empty");
  }
  if (!Array.isArray(packet.rotations) || packet.rotations.length === 0) {
    throw new Error("identifier rotation packet rotations must be a non-empty array");
  }

  const ephemeralPrefix = `urn:kinegrant:ephemeral:${packet.namespace}:`;
  const ids = new Set();
  let previousIssuedAt = -Infinity;
  let activeTotal = 0;
  let revokedTotal = 0;
  for (const entry of packet.rotations) {
    if (
      typeof entry !== "object" ||
      entry === null ||
      Array.isArray(entry) ||
      Object.keys(entry).sort().join(",") !== ROTATION_ENTRY_KEYS.join(",")
    ) {
      throw new Error("rotation entry fields are invalid");
    }
    if (
      typeof entry.ephemeral_id !== "string" ||
      !entry.ephemeral_id.startsWith(ephemeralPrefix) ||
      !/^[0-9a-f]{24}$/.test(entry.ephemeral_id.slice(ephemeralPrefix.length))
    ) {
      throw new Error("rotation ephemeral id is invalid for this namespace");
    }
    if (ids.has(entry.ephemeral_id)) {
      throw new Error("rotation ephemeral ids must be unique");
    }
    ids.add(entry.ephemeral_id);
    if (typeof entry.issued_at !== "string" || Number.isNaN(Date.parse(entry.issued_at))) {
      throw new Error("rotation issued_at is invalid");
    }
    const issuedAtMs = Date.parse(entry.issued_at);
    if (issuedAtMs <= previousIssuedAt) {
      throw new Error("rotation issued_at values must be strictly increasing");
    }
    previousIssuedAt = issuedAtMs;
    if (entry.status !== "active" && entry.status !== "revoked") {
      throw new Error("rotation status must be active or revoked");
    }
    if (entry.status === "active") {
      activeTotal += 1;
      if (entry.revoked_at !== null) {
        throw new Error("active rotation must not have revoked_at");
      }
    } else {
      revokedTotal += 1;
      if (typeof entry.revoked_at !== "string" || Number.isNaN(Date.parse(entry.revoked_at))) {
        throw new Error("revoked rotation requires a valid revoked_at");
      }
      if (Date.parse(entry.revoked_at) <= issuedAtMs) {
        throw new Error("revoked_at must follow issued_at");
      }
    }
  }
  if (activeTotal !== 1) {
    throw new Error("a rotation chain must have exactly one active identifier");
  }
  const lastEntry = packet.rotations[packet.rotations.length - 1];
  if (lastEntry.status !== "active") {
    throw new Error("the latest rotation must be the active identifier");
  }

  const summary = packet.summary;
  if (
    typeof summary !== "object" ||
    summary === null ||
    Array.isArray(summary)
  ) {
    throw new Error("identifier rotation packet summary must be an object");
  }
  if (
    Object.keys(summary).sort().join(",") !==
    IDENTIFIER_ROTATION_SUMMARY_KEYS.join(",")
  ) {
    throw new Error("identifier rotation packet summary fields are invalid");
  }
  const expectedSummary = {
    artifacts_total: 3,
    rotations_total: packet.rotations.length,
    active_total: activeTotal,
    revoked_total: revokedTotal,
    statuses_ok: true,
    chain_complete: true,
  };
  for (const [key, value] of Object.entries(expectedSummary)) {
    if (summary[key] !== value) {
      throw new Error(`identifier rotation packet summary ${key} is inconsistent`);
    }
  }
  return {
    valid: true,
    namespace: packet.namespace,
    static_id: packet.static_id,
    rotations_total: packet.rotations.length,
    active_total: activeTotal,
  };
}

const ROBOT_OUTCOME_KEYS = [
  "action",
  "actuator_calls",
  "allowed",
  "expected",
  "obligation_compliant",
  "passed",
  "reason",
  "scenario",
  "stack",
];

export function verifyRobotDemoReport(report) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("robot demo report must be an object");
  }
  if (report.type !== "kinegrant:RobotDemoReport") {
    throw new Error("wrong robot demo report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported robot demo report version");
  }
  if (!Array.isArray(report.outcomes) || report.outcomes.length === 0) {
    throw new Error("robot demo report outcomes must be a non-empty array");
  }
  let passed = 0;
  for (const outcome of report.outcomes) {
    if (typeof outcome !== "object" || outcome === null || Array.isArray(outcome)) {
      throw new Error("each robot demo outcome must be an object");
    }
    if (Object.keys(outcome).sort().join(",") !== ROBOT_OUTCOME_KEYS.join(",")) {
      throw new Error("robot demo outcome fields are invalid");
    }
    for (const field of ["scenario", "stack", "action", "reason"]) {
      if (typeof outcome[field] !== "string" || outcome[field].length === 0) {
        throw new Error(`robot demo outcome ${field} must be a non-empty string`);
      }
    }
    if (!Number.isInteger(outcome.actuator_calls) || outcome.actuator_calls < 0) {
      throw new Error("robot demo outcome actuator_calls must be a non-negative integer");
    }
    if (outcome.expected !== "ALLOW" && outcome.expected !== "DENY") {
      throw new Error("robot demo outcome expected must be ALLOW or DENY");
    }
    if (typeof outcome.allowed !== "boolean" || typeof outcome.passed !== "boolean") {
      throw new Error("robot demo outcome allowed and passed must be booleans");
    }
    if (
      outcome.obligation_compliant !== null &&
      typeof outcome.obligation_compliant !== "boolean"
    ) {
      throw new Error("robot demo outcome obligation_compliant must be null or a boolean");
    }
    if (outcome.allowed && outcome.obligation_compliant === null) {
      throw new Error("allowed robot demo outcomes require an obligation_compliant flag");
    }
    const expectedPassed = outcome.allowed === (outcome.expected === "ALLOW");
    if (outcome.passed !== expectedPassed) {
      throw new Error("robot demo outcome passed flag is inconsistent");
    }
    if (outcome.passed) passed += 1;
  }
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("robot demo report summary must be an object");
  }
  if (Object.keys(summary).sort().join(",") !== "failed,passed,total") {
    throw new Error("robot demo report summary fields are invalid");
  }
  if (
    summary.total !== report.outcomes.length ||
    summary.passed !== passed ||
    summary.failed !== report.outcomes.length - passed
  ) {
    throw new Error("robot demo report summary is inconsistent");
  }
  const actuatorCalls = report.actuator_calls;
  if (
    typeof actuatorCalls !== "object" ||
    actuatorCalls === null ||
    Array.isArray(actuatorCalls) ||
    Object.keys(actuatorCalls).length === 0
  ) {
    throw new Error("robot demo report actuator_calls must be a non-empty object");
  }
  for (const [stack, calls] of Object.entries(actuatorCalls)) {
    if (stack.length === 0 || !Number.isInteger(calls) || calls < 0) {
      throw new Error("robot demo report actuator_calls values must be non-negative integers");
    }
  }
  if (typeof report.obligation_compliance_ok !== "boolean") {
    throw new Error("robot demo report obligation_compliance_ok must be a boolean");
  }
  const expectedResult =
    passed === report.outcomes.length && report.obligation_compliance_ok
      ? "PASS"
      : "FAIL";
  if (report.overall_result !== expectedResult) {
    throw new Error("robot demo report overall_result is inconsistent");
  }
  if (!Array.isArray(report.limitations)) {
    throw new Error("robot demo report limitations must be an array");
  }
  if (report.limitations.some((item) => typeof item !== "string")) {
    throw new Error("robot demo report limitations must be strings");
  }
  return {
    valid: true,
    overall_result: report.overall_result,
    summary: report.summary,
    outcomes: report.outcomes.length,
    actuator_calls: Object.keys(actuatorCalls).length,
  };
}

const CAMERA_CONSENT_KEYS = [
  "obligation_compliant",
  "passed",
  "record_allowed",
  "record_consumed",
  "scenario",
  "train_policy_denied",
  "train_sequence_denied",
];

export function verifyCameraConsentTrace(trace) {
  if (typeof trace !== "object" || trace === null || Array.isArray(trace)) {
    throw new Error("camera consent trace must be an object");
  }
  if (Object.keys(trace).sort().join(",") !== CAMERA_CONSENT_KEYS.join(",")) {
    throw new Error("camera consent trace fields are invalid");
  }
  if (trace.scenario !== "camera-consent") {
    throw new Error("camera consent trace scenario must be camera-consent");
  }
  for (const field of [
    "record_allowed",
    "record_consumed",
    "train_policy_denied",
    "train_sequence_denied",
    "obligation_compliant",
    "passed",
  ]) {
    if (typeof trace[field] !== "boolean") {
      throw new Error(`camera consent trace ${field} must be a boolean`);
    }
  }
  const expectedPassed =
    trace.record_allowed &&
    trace.record_consumed &&
    trace.train_policy_denied &&
    trace.train_sequence_denied &&
    trace.obligation_compliant;
  if (trace.passed !== expectedPassed) {
    throw new Error("camera consent trace passed flag is inconsistent");
  }
  return {
    valid: true,
    passed: trace.passed,
    record_allowed: trace.record_allowed,
    train_sequence_denied: trace.train_sequence_denied,
  };
}

const FULL_LIFECYCLE_KEYS = [
  "audit_summary",
  "bundle_id",
  "bundle_version",
  "generated_at",
  "overall_result",
  "policy_distribution",
  "policy_id",
  "revocation_distribution",
  "schema_version",
  "summary",
  "type",
];

export async function verifyFullLifecycleReport(
  report,
  policyBundle,
  revocationBundle,
  trustedAuthorities,
  { now } = {}
) {
  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new Error("full lifecycle report must be an object");
  }
  if (Object.keys(report).sort().join(",") !== FULL_LIFECYCLE_KEYS.join(",")) {
    throw new Error("full lifecycle report fields are invalid");
  }
  if (report.type !== "kinegrant:FullLifecycleReport") {
    throw new Error("wrong full lifecycle report type");
  }
  if (report.schema_version !== "0.1") {
    throw new Error("unsupported full lifecycle report version");
  }
  if (
    typeof report.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(report.generated_at)
  ) {
    throw new Error(
      "full lifecycle report generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(report.generated_at);
  if (report.overall_result !== "PASS") {
    throw new Error("full lifecycle report overall_result must be PASS");
  }
  const payload = await verifyPolicyBundle(policyBundle, trustedAuthorities, {
    now,
  });
  if (
    report.policy_id !== payload.policy_id ||
    report.bundle_id !== payload.bundle_id ||
    report.bundle_version !== payload.version
  ) {
    throw new Error("full lifecycle report does not bind to the signed policy bundle");
  }
  const distribution = report.policy_distribution;
  if (typeof distribution !== "object" || distribution === null || Array.isArray(distribution)) {
    throw new Error("full lifecycle report policy_distribution must be an object");
  }
  await verifyPolicyDistributionReport(
    distribution,
    policyBundle,
    trustedAuthorities,
    { now }
  );
  if (
    distribution.policy_id !== report.policy_id ||
    distribution.bundle_id !== report.bundle_id ||
    distribution.bundle_version !== report.bundle_version
  ) {
    throw new Error("full lifecycle report policy distribution does not match the bundle");
  }
  const audit = report.audit_summary;
  if (typeof audit !== "object" || audit === null || Array.isArray(audit)) {
    throw new Error("full lifecycle report audit_summary must be an object");
  }
  verifyPolicyAuditSummary(audit);
  if (audit.overall_result !== "PASS") {
    throw new Error("full lifecycle report audit_summary must be PASS");
  }
  const matchingEntry = audit.bundles.find(
    (entry) =>
      entry.verified === true &&
      entry.policy_id === report.policy_id &&
      entry.bundle_version === report.bundle_version
  );
  if (matchingEntry === undefined) {
    throw new Error(
      "full lifecycle report audit_summary has no verified entry for this bundle"
    );
  }
  const revocation = report.revocation_distribution;
  if (typeof revocation !== "object" || revocation === null || Array.isArray(revocation)) {
    throw new Error("full lifecycle report revocation_distribution must be an object");
  }
  await verifyRevocationDistributionReport(
    revocation,
    revocationBundle,
    trustedAuthorities
  );
  if (revocation.overall_result !== "PASS") {
    throw new Error("full lifecycle report revocation_distribution must be PASS");
  }
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("full lifecycle report summary must be an object");
  }
  if (Object.keys(summary).sort().join(",") !== "failed,passed,phases_total") {
    throw new Error("full lifecycle report summary fields are invalid");
  }
  if (
    summary.phases_total !== 4 ||
    summary.passed !== 4 ||
    summary.failed !== 0
  ) {
    throw new Error("full lifecycle report summary is inconsistent");
  }
  return {
    valid: true,
    policy_id: report.policy_id,
    bundle_version: report.bundle_version,
    phases: summary.phases_total,
  };
}

const EVIDENCE_EXPORT_KINDS = new Set([
  "receipt_evidence_packet",
  "audit_csv",
  "mpt_evidence",
  "conformance_report",
  "reproduction_report",
  "policy_analysis",
  "fleet_audit",
  "security_review_kit",
  "sensor_commitment",
  "receipt_checkpoint",
  "device_attestation",
]);
const EVIDENCE_EXPORT_KEYS = [
  "artifacts",
  "generated_at",
  "overall_result",
  "schema_version",
  "summary",
  "type",
];
const EVIDENCE_ARTIFACT_KEYS = ["kind", "name", "sha256"];

export function verifyEvidenceExportPacket(packet) {
  if (typeof packet !== "object" || packet === null || Array.isArray(packet)) {
    throw new Error("evidence export packet must be an object");
  }
  if (Object.keys(packet).sort().join(",") !== EVIDENCE_EXPORT_KEYS.join(",")) {
    throw new Error("evidence export packet fields are invalid");
  }
  if (packet.type !== "kinegrant:EvidenceExportPacket") {
    throw new Error("wrong evidence export packet type");
  }
  if (packet.schema_version !== "0.1") {
    throw new Error("unsupported evidence export packet version");
  }
  if (
    typeof packet.generated_at !== "string" ||
    !/Z$|[+-]\d{2}:\d{2}$/.test(packet.generated_at)
  ) {
    throw new Error(
      "evidence export packet generated_at must be a timezone-aware ISO timestamp"
    );
  }
  parseTime(packet.generated_at);
  if (packet.overall_result !== "PASS") {
    throw new Error("evidence export packet overall_result must be PASS");
  }
  if (!Array.isArray(packet.artifacts) || packet.artifacts.length === 0) {
    throw new Error("evidence export packet artifacts must be a non-empty array");
  }
  const names = new Set();
  const kinds = new Set();
  for (const artifact of packet.artifacts) {
    if (typeof artifact !== "object" || artifact === null || Array.isArray(artifact)) {
      throw new Error("each evidence artifact must be an object");
    }
    if (Object.keys(artifact).sort().join(",") !== EVIDENCE_ARTIFACT_KEYS.join(",")) {
      throw new Error("evidence artifact fields are invalid");
    }
    if (!EVIDENCE_EXPORT_KINDS.has(artifact.kind)) {
      throw new Error("evidence artifact kind is invalid");
    }
    if (typeof artifact.name !== "string" || artifact.name.length === 0) {
      throw new Error("evidence artifact name must be a non-empty string");
    }
    if (names.has(artifact.name)) {
      throw new Error("evidence artifact names must be unique");
    }
    names.add(artifact.name);
    kinds.add(artifact.kind);
    if (typeof artifact.sha256 !== "string" || !SHA256_RE.test(artifact.sha256)) {
      throw new Error("evidence artifact sha256 must be a sha256 digest");
    }
  }
  const summary = packet.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary)) {
    throw new Error("evidence export packet summary must be an object");
  }
  if (Object.keys(summary).sort().join(",") !== "artifacts_total,digest_verified,unique_kinds") {
    throw new Error("evidence export packet summary fields are invalid");
  }
  if (
    summary.artifacts_total !== packet.artifacts.length ||
    summary.unique_kinds !== kinds.size ||
    summary.digest_verified !== true
  ) {
    throw new Error("evidence export packet summary is inconsistent");
  }
  return {
    valid: true,
    artifacts: packet.artifacts.length,
    unique_kinds: kinds.size,
  };
}

if (typeof globalThis !== "undefined") {
  globalThis.KineGrantVerifier = {
    canonicalJson,
    verifyPolicyBundle,
    currentPolicyVersion,
    verifyCapability,
    verifyReceiptChain,
    verifyMptEvidence,
    verifyRevocationBundle,
    verifyPolicyDistributionReport,
    verifyReceiptEvidencePacket,
    verifyAuditCsv,
    verifyReproductionReport,
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
    verifyRobotDemoReport,
    verifyCameraConsentTrace,
    verifyFullLifecycleReport,
    verifyEvidenceExportPacket,
  };
}
