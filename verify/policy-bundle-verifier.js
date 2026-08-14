// Universal (browser + Node) verifier for KineGrant policy bundles.
// Zero dependencies: RFC 8785 JCS subset + WebCrypto Ed25519 + SHA-256.
// Works offline and can be embedded in a static page.

const DOMAIN = "KINEGRANT-SIGNED-ENVELOPE-V1\u0000";

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

if (typeof globalThis !== "undefined") {
  globalThis.KineGrantVerifier = {
    canonicalJson,
    verifyPolicyBundle,
    currentPolicyVersion,
  };
}
