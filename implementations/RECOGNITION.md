# Independent Implementation Recognition (KGP-RFC-0004)

> Status: draft for community review — see `docs/rfcs/0004-independent-implementation-recognition.md`
> This guide is the practical companion to KGP-RFC-0004: how to apply, what
> evidence to submit, and how the public record is maintained.

## What qualifies as independent

An implementation is independent when **all** of the following hold:

- it is not a copy or fork of the Python reference implementation
  (`src/kinegrant`);
- it is written independently by a different author or organization and does
  not share the reference implementation's core codebase;
- it implements at least the stable wire format 1.0 core objects:
  `ActionRequest`, `Capability`, `Receipt`;
- it passes Machine Permission Test evidence validation (schema 0.5) or an
  equivalent conformance case set.

## How to apply

1. Add your implementation under `implementations/<name>/` with a README that
   states: language/platform, wire-format coverage, install/run commands, and
   any safety or audit caveats.
2. Add an interoperability evidence file (see template below) that an
   independent reviewer can reproduce.
3. Open a pull request referencing KGP-RFC-0004. A maintainer reviews, the
   steering committee confirms, and the result is recorded publicly.

## Evidence template

Save as `implementations/<name>/interop-evidence.json`:

```json
{
  "type": "kinegrant:InteropEvidence",
  "schema_version": "0.1",
  "implementation": {
    "name": "your-implementation",
    "language": "Rust",
    "version": "0.1.0",
    "repository": "https://example.com/your-repo"
  },
  "reference_commit": "<sha of kinegrant-protocol main used for the run>",
  "generated_at": "2026-08-18T00:00:00Z",
  "capability": {
    "verified": true,
    "command": ["your-cli", "verify-capability", "capability.json", "request.json", "issuers.json"],
    "output_summary": "VALID: signature, scope, expiry, request binding, one-time nonce all passed"
  },
  "receipt": {
    "verified": true,
    "command": ["your-cli", "verify-receipts", "entries.json", "executors.json"],
    "output_summary": "VALID: hash chain intact, executor trusted, terminal receipt"
  },
  "cross_verification": {
    "tool": "kinegrant-js",
    "command": ["node", "implementations/kinegrant-js/src/cli.mjs", "verify-capability", "capability.json", "request.json", "issuers.json"],
    "result": "PASS"
  },
  "reproducible": true,
  "caveats": "No independent security audit performed."
}
```

## Public record

Recognized implementations are listed in `implementations/README.md` with
name, author/organization, language/platform, evidence link, and recognition
date. Recognition is not an endorsement, safety certification, or
production-readiness claim; it records cross-verified wire-format
compatibility only.