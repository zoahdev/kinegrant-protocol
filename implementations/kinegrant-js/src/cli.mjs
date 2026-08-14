import { readFileSync } from "node:fs";
import { verifyCapability, verifyReceiptChain } from "./verify.mjs";

function load(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function fail(message) {
  console.error(`INVALID: ${message}`);
  process.exit(2);
}

const [command, ...args] = process.argv.slice(2);
try {
  if (command === "verify-capability") {
    const [envelopePath, requestPath, issuersPath] = args;
    const envelope = load(envelopePath);
    const request = load(requestPath);
    const trustedIssuers = new Set(load(issuersPath));
    verifyCapability(envelope, request, trustedIssuers);
    console.log("CAPABILITY VALID");
  } else if (command === "verify-receipts") {
    const [entriesPath, executorsPath] = args;
    const entries = load(entriesPath);
    const trustedExecutors = executorsPath ? new Set(load(executorsPath)) : null;
    verifyReceiptChain(entries, trustedExecutors);
    console.log("RECEIPT CHAIN VALID");
  } else {
    throw new Error(`unknown command ${command}`);
  }
} catch (error) {
  fail(error.message);
}
