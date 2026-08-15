# kinegrant-js

An independent, dependency-free JavaScript (ESM, Node >= 20) verifier for
KineGrant KGP-001 artifacts: RFC 8785 JCS subset, Ed25519 envelopes, v0.1 and
0.2/1.0 capability verification, and hash-chained receipt chains.

## CLI

```bash
node src/cli.mjs verify-capability <envelope.json> <request.json> <issuers.json>
node src/cli.mjs verify-receipts <entries.json> <executors.json>
node src/cli.mjs verify-policy-bundle <bundle.json> <authorities.json> [policy-id]
node src/cli.mjs current-policy-version <bundles.json> [revoked.json]
```

Exit code 0 means VALID; exit code 2 means INVALID.

## Library

```js
import { verifyCapability, verifyPolicyBundle, verifyReceiptChain } from "./src/verify.mjs";
```

The same primitives are also embedded in the browser verifier page
`verify/policy-bundle-verifier.html` at the repository root.

## Tests

```bash
node --test test/
```

## npm

This package is prepared for npm publication; when published, it exposes the
`kinegrant-js-verify` binary.
