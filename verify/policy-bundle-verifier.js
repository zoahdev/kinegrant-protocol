// Universal (browser + Node) verifier for KineGrant policy bundles.
// Zero dependencies: RFC 8785 JCS subset + WebCrypto Ed25519 + SHA-256.
// Works offline and can be embedded in a static page.

const DOMAIN = "KINEGRANT-SIGNED-ENVELOPE-V1\u0000";
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

async function verifyEnvelope(envelope) {
  if (envelope?.alg !== "EdDSA") throw new Error("unsupported signature algorithm");
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
  const canonical = canonicalJson({ alg: "EdDSA", kid, payload });
  const data = new TextEncoder().encode(DOMAIN + canonical);
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

async function verifyCapabilityV2(payload, envelope, request, trustedIssuers) {
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
  };
}
