// Universal CLI wrapper around the browser-compatible policy bundle verifier.
import { readFileSync } from "node:fs";
import {
  verifyCapability,
  currentPolicyVersion,
  verifyMptEvidence,
  verifyPolicyDistributionReport,
  verifyPolicyBundle,
  verifyReceiptChain,
  verifyRevocationBundle,
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
  } else if (command === "mpt") {
    const [evidencePath] = args;
    const evidence = load(evidencePath);
    const result = verifyMptEvidence(evidence);
    console.log(
      `MPT EVIDENCE VALID (${result.overall_result}: ${result.summary.passed}/${result.summary.total})`
    );
  } else if (command === "revocation") {
    const [bundlePath, authoritiesPath] = args;
    const bundle = load(bundlePath);
    const trustedAuthorities = new Set(load(authoritiesPath));
    await verifyRevocationBundle(bundle, trustedAuthorities);
    console.log("REVOCATION BUNDLE VALID");
  } else if (command === "distribution-report") {
    const [reportPath, bundlePath, authoritiesPath] = args;
    const report = load(reportPath);
    const bundle = load(bundlePath);
    const trustedAuthorities = new Set(load(authoritiesPath));
    await verifyPolicyDistributionReport(report, bundle, trustedAuthorities);
    console.log("POLICY DISTRIBUTION REPORT VALID");
  } else {
    throw new Error(
      "usage: verify_policy_bundle.mjs verify <bundle.json> <authorities.json> [policy-id] | " +
      "current <bundles.json> [revoked.json] | " +
      "capability <envelope.json> <request.json> <issuers.json> | " +
      "receipts <entries.json> [executors.json] | " +
      "mpt <evidence.json> | " +
      "revocation <bundle.json> <authorities.json> | " +
      "distribution-report <report.json> <bundle.json> <authorities.json>"
    );
  }
} catch (error) {
  console.error(`INVALID: ${error.message}`);
  process.exit(2);
}
