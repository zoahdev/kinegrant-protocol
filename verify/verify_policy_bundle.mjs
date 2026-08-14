// Universal CLI wrapper around the browser-compatible policy bundle verifier.
import { readFileSync } from "node:fs";
import {
  verifyCapability,
  currentPolicyVersion,
  verifyPolicyBundle,
  verifyReceiptChain,
} from "./policy-bundle-verifier.js";

function load(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

const [command, ...args] = process.argv.slice(2);
try {
  if (command === "verify") {
    const [bundlePath, authoritiesPath, policyId] = args;
    const bundle = load(bundlePath);
    const trustedAuthorities = new Set(load(authoritiesPath));
    await verifyPolicyBundle(bundle, trustedAuthorities, {
      expectedPolicyId: policyId,
    });
    console.log("POLICY BUNDLE VALID");
  } else if (command === "current") {
    const [bundlesPath, revokedPath] = args;
    const bundles = load(bundlesPath);
    const revoked = revokedPath ? load(revokedPath) : [];
    const current = currentPolicyVersion(bundles, { revoked });
    if (current === null) {
      throw new Error("no current policy version");
    }
    console.log(JSON.stringify(current));
  } else if (command === "capability") {
    const [envelopePath, requestPath, issuersPath] = args;
    const envelope = load(envelopePath);
    const request = load(requestPath);
    const trustedIssuers = new Set(load(issuersPath));
    await verifyCapability(envelope, request, trustedIssuers);
    console.log("CAPABILITY VALID");
  } else if (command === "receipts") {
    const [entriesPath, executorsPath] = args;
    const entries = load(entriesPath);
    const trustedExecutors = executorsPath ? new Set(load(executorsPath)) : null;
    await verifyReceiptChain(entries, trustedExecutors);
    console.log("RECEIPT CHAIN VALID");
  } else {
    throw new Error(
      "usage: verify_policy_bundle.mjs verify <bundle.json> <authorities.json> [policy-id] | " +
      "current <bundles.json> [revoked.json] | " +
      "capability <envelope.json> <request.json> <issuers.json> | " +
      "receipts <entries.json> [executors.json]"
    );
  }
} catch (error) {
  console.error(`INVALID: ${error.message}`);
  process.exit(2);
}
