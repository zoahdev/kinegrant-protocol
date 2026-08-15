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
  };
}
