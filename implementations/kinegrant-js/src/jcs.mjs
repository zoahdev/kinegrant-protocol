// RFC 8785 JCS subset used by KineGrant wire objects.
// Object members are sorted by UTF-16 code units (JavaScript's default string
// sort); strings use JSON.stringify escaping (well-formed JSON escapes
// U+2028/U+2029); numbers use ECMAScript JSON.stringify semantics.

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
  throw new Error(`cannot canonicalize ${typeof value}`);
}

function escapeJsonString(value) {
  return JSON.stringify(value)
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}
