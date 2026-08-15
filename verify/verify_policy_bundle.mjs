// Universal CLI wrapper around the browser-compatible policy bundle verifier.
import { readFileSync } from "node:fs";
import {
  verifyCapability,
  currentPolicyVersion,
  verifyMptEvidence,
  verifyPolicyDistributionReport,
  verifyReceiptEvidencePacket,
  verifyPolicyBundle,
  verifyReceiptChain,
  verifyRevocationBundle,
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
  } else if (command === "evidence-packet") {
    const [packetPath] = args;
    const packet = load(packetPath);
    const result = await verifyReceiptEvidencePacket(packet);
    console.log(
      `EVIDENCE PACKET VALID (${result.receipts} receipts)`
    );
  } else if (command === "audit-csv") {
    const [csvPath] = args;
    const text = readFileSync(csvPath, "utf8");
    const result = verifyAuditCsv(text);
    console.log(`AUDIT CSV VALID (${result.rows} rows)`);
  } else if (command === "reproduction-report") {
    const [reportPath] = args;
    const report = load(reportPath);
    const result = verifyReproductionReport(report);
    console.log(
      `REPRODUCTION REPORT VALID (${result.passed_cases}/${result.required_cases})`
    );
  } else if (command === "revocation-distribution") {
    const [reportPath, bundlePath, authoritiesPath] = args;
    const report = load(reportPath);
    const bundle = bundlePath ? load(bundlePath) : undefined;
    const trustedAuthorities = authoritiesPath
      ? new Set(load(authoritiesPath))
      : undefined;
    const result = await verifyRevocationDistributionReport(
      report,
      bundle,
      trustedAuthorities
    );
    console.log(
      `REVOCATION DISTRIBUTION REPORT VALID (${result.gates} gates, added=${result.added_total})`
    );
  } else if (command === "bundle-odrl") {
    const [bundlePath, authoritiesPath] = args;
    const bundle = load(bundlePath);
    const trustedAuthorities = new Set(load(authoritiesPath));
    const document = await policyBundleToOdrl(bundle, trustedAuthorities);
    console.log(JSON.stringify(document, null, 2));
  } else if (command === "vocabulary") {
    const [actionsPath] = args;
    const actions = load(actionsPath);
    const result = validateActionVocabulary(actions);
    console.log(`ACTION VOCABULARY VALID (${result.actions} actions)`);
  } else if (command === "obligations") {
    const [obligationsPath] = args;
    const obligations = load(obligationsPath);
    const result = validateObligationVocabulary(obligations);
    console.log(`OBLIGATION VOCABULARY VALID (${result.obligations} obligations)`);
  } else if (command === "identities") {
    const [identifiersPath] = args;
    const identifiers = load(identifiersPath);
    const result = validateIdentitySyntax(identifiers);
    console.log(`IDENTITY SYNTAX VALID (${result.count} identifiers)`);
    for (const entry of result.identifiers) {
      console.log(
        `${entry.value} -> kind=${entry.kind} namespace=${entry.namespace} local_id=${entry.local_id}`
      );
    }
  } else if (command === "analysis") {
    const [reportPath, bundlePath, authoritiesPath] = args;
    const report = load(reportPath);
    const bundle = load(bundlePath);
    const trustedAuthorities = new Set(load(authoritiesPath));
    const result = await verifyPolicyAnalysisReport(
      report,
      bundle,
      trustedAuthorities
    );
    console.log(
      `POLICY ANALYSIS VALID (${result.overall_result}: ` +
        `${result.summary.errors} errors, ${result.summary.warnings} warnings, ` +
        `${result.summary.info} info, ${result.findings.length} findings)`
    );
  } else if (command === "delegation") {
    const [chainPath, requestPath, issuersPath] = args;
    const chain = load(chainPath);
    const request = load(requestPath);
    const trustedIssuers = new Set(load(issuersPath));
    const result = await verifyDelegationChain(
      chain,
      trustedIssuers,
      request
    );
    console.log(
      `DELEGATION CHAIN VALID (depth=${result.depth}, terminal=${result.terminal_capability_id})`
    );
  } else if (command === "sequence") {
    const [reportPath, policyPath, requestPath, journalPath] = args;
    const report = load(reportPath);
    const policy = load(policyPath);
    const request = load(requestPath);
    const journal = load(journalPath);
    const result = await verifySequenceCheckReport(
      report,
      policy,
      request,
      journal
    );
    console.log(
      `SEQUENCE CHECK VALID (allowed=${result.allowed}, reason=${result.reason}, ` +
        `matched=${result.matched_combination_ids.join(",") || "-"})`
    );
  } else if (command === "mldsa") {
    const [envelopePath] = args;
    const envelope = load(envelopePath);
    const payload = await verifyMldsaEnvelope(envelope);
    console.log(
      `ML-DSA-65 ENVELOPE VALID (type=${payload.type}, ` +
        `version=${payload.version ?? payload.schema_version ?? "n/a"})`
    );
  } else if (command === "conformance") {
    const [reportPath] = args;
    const report = load(reportPath);
    const result = verifyConformanceReport(report);
    console.log(
      `CONFORMANCE REPORT VALID (${result.overall_result}: ` +
        `${result.summary.passed}/${result.summary.total} marks, ` +
        `independent=${result.independent_verification.overall_result}, ` +
        `${result.independent_verification.checks} checks)`
    );
  } else if (command === "fleet-audit") {
    const [reportPath] = args;
    const report = load(reportPath);
    const result = verifyPolicyAuditSummary(report);
    console.log(
      `POLICY AUDIT SUMMARY VALID (${result.overall_result}: ` +
        `${result.summary.verified}/${result.summary.bundles_total} verified, ` +
        `${result.summary.analysis_failures} analysis failures, ` +
        `${result.summary.coverage_failures} coverage failures, ` +
        `${result.bundles} bundles)`
    );
  } else if (command === "kit") {
    const [kitPath] = args;
    const kit = load(kitPath);
    const result = verifySecurityReviewKit(kit);
    console.log(
      `SECURITY REVIEW KIT VALID (${result.overall_result}: ` +
        `${result.checks} checks, ${result.checklist} checklist items, ` +
        `reference=${result.reference_implementation})`
    );
  } else if (command === "esp32") {
    const [evidencePath] = args;
    const evidence = load(evidencePath);
    const result = verifyEsp32c3Evidence(evidence);
    console.log(
      `ESP32-C3 EVIDENCE VALID (${result.overall_result}, ` +
        `mode=${result.evidence_mode}, ${result.cases} cases)`
    );
  } else if (command === "fleet-ops") {
    const [reportPath, policyBundlePath, revocationBundlePath, authoritiesPath] = args;
    const report = load(reportPath);
    const policyBundle = load(policyBundlePath);
    const revocationBundle = load(revocationBundlePath);
    const trustedAuthorities = new Set(load(authoritiesPath));
    const result = await verifyFleetOperationsReport(
      report,
      policyBundle,
      revocationBundle,
      trustedAuthorities
    );
    console.log(
      `FLEET OPERATIONS REPORT VALID (${result.overall_result}: ` +
        `${result.summary.policy_applied}/${result.summary.gates_total} policy applied, ` +
        `${result.summary.revocation_applied}/${result.summary.gates_total} revocation applied, ` +
        `${result.gates} gates)`
    );
  } else if (command === "bench") {
    const [reportPath] = args;
    const report = load(reportPath);
    const result = verifyBenchmarkReport(report);
    console.log(
      `BENCHMARK REPORT VALID (${result.operations} operations, ` +
        `iterations=${result.iterations})`
    );
  } else if (command === "lifecycle") {
    const [tracePath, bundlePath, authoritiesPath] = args;
    const trace = load(tracePath);
    const bundle = load(bundlePath);
    const trustedAuthorities = new Set(load(authoritiesPath));
    const result = await verifyPolicyLifecycleTrace(
      trace,
      bundle,
      trustedAuthorities
    );
    console.log(
      `POLICY LIFECYCLE TRACE VALID (${result.overall_result}: ` +
        `${result.summary.passed}/${result.summary.phases_total} phases, ` +
        `${result.summary.failed} failed, policy=${result.policy_id})`
    );
  } else if (command === "sensor") {
    const [commitmentPath] = args;
    const commitment = load(commitmentPath);
    const payload = await verifySensorCommitment(commitment);
    const evidenceHash = await sensorEvidenceHash(commitment);
    console.log(
      `SENSOR COMMITMENT VALID (${payload.readings.length} readings, ` +
        `evidence_hash=${evidenceHash})`
    );
  } else if (command === "checkpoint") {
    const [checkpointPath] = args;
    const checkpoint = load(checkpointPath);
    const result = await verifyReceiptCheckpoint(checkpoint);
    console.log(
      `RECEIPT CHECKPOINT VALID (chain_digest=${result.chain_digest}, ` +
        `notary=${result.notary}, period=${result.period})`
    );
  } else if (command === "attestation") {
    const [attestationPath] = args;
    const attestation = load(attestationPath);
    const result = await verifyDeviceAttestation(attestation);
    console.log(
      `DEVICE ATTESTATION VALID (device=${result.device_id}, ` +
        `boot_counter=${result.boot_counter}, firmware=${result.firmware_digest}, ` +
        `${result.stages} measured-boot stages)`
    );
  } else if (command === "bridge") {
    const [reportPath] = args;
    const report = load(reportPath);
    const result = verifyBridgeDemoReport(report);
    console.log(
      `BRIDGE DEMO REPORT VALID (${result.type}: ${result.overall_result}, ` +
        `${result.summary.passed}/${result.summary.total} outcomes)`
    );
  } else if (command === "hardware-packet") {
    const [packetPath] = args;
    const packet = load(packetPath);
    const result = await verifyHardwareTrustPacket(packet);
    console.log(
      `HARDWARE TRUST PACKET VALID (device=${result.device_id}, ` +
        `firmware=${result.firmware_digest}, boot_counter=${result.boot_counter}, ` +
        `${result.sensor_commitments} sensor commitments, ` +
        `${result.receipt_checkpoints} receipt checkpoints)`
    );
  } else if (command === "sequence-eval") {
    const [policyPath, requestPath, journalPath] = args;
    const policy = load(policyPath);
    const request = load(requestPath);
    const journal = load(journalPath);
    const verdict = evaluateSequencePolicy(policy, request, journal);
    console.log(
      `SEQUENCE EVAL (allowed=${verdict.allowed}, reason=${verdict.reason}, ` +
        `matched=${verdict.matched_combination_ids.join(",") || "-"})`
    );
  } else {
    throw new Error(
      "usage: verify_policy_bundle.mjs verify <bundle.json> <authorities.json> [policy-id] | " +
      "current <bundles.json> [revoked.json] | " +
      "capability <envelope.json> <request.json> <issuers.json> | " +
      "receipts <entries.json> [executors.json] | " +
      "mpt <evidence.json> | " +
      "revocation <bundle.json> <authorities.json> | " +
      "distribution-report <report.json> <bundle.json> <authorities.json> | " +
      "evidence-packet <packet.json> | " +
      "audit-csv <file.csv> | " +
      "reproduction-report <report.json> | " +
      "revocation-distribution <report.json> [bundle.json] [authorities.json] | " +
      "bundle-odrl <bundle.json> <authorities.json> | " +
      "vocabulary <actions.json> | " +
      "obligations <obligations.json> | " +
      "identities <identifiers.json> | " +
      "analysis <report.json> <bundle.json> <authorities.json> | " +
      "delegation <chain.json> <request.json> <issuers.json> | " +
      "sequence <report.json> <policy.json> <request.json> <journal.json> | " +
      "sequence-eval <policy.json> <request.json> <journal.json> | " +
      "mldsa <envelope.json> | " +
      "conformance <report.json> | " +
      "fleet-audit <report.json> | " +
      "kit <kit.json> | " +
      "esp32 <evidence.json> | " +
      "fleet-ops <report.json> <policy-bundle.json> <revocation-bundle.json> <authorities.json> | " +
      "bench <report.json> | " +
      "lifecycle <trace.json> <bundle.json> <authorities.json> | " +
      "sensor <commitment.json> | " +
      "checkpoint <checkpoint.json> | " +
      "attestation <attestation.json> | " +
      "bridge <report.json> | " +
      "hardware-packet <packet.json>"
    );
  }
} catch (error) {
  console.error(`INVALID: ${error.message}`);
  process.exit(2);
}
