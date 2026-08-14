# Merkle Selective Disclosure

> Status: v0.5 draft

`merkle_redact` upgrades the digest-only redaction envelope to Merkle-tree
inclusion proofs. A prover reveals chosen fields plus per-field proofs
against a root; the verifier needs only the root, the field name, the value,
and the proof -- never the full document.

- `merkle_proofs(document)` builds a deterministic tree (padded to a power of
  two) and returns per-field values, roots, and proofs;
- `verify_field(root, field, value, proof)` checks one inclusion proof;
- `merkle_redact(document, visible)` / `verify_merkle_redaction(envelope)`
  provide the disclosure envelope.

This is an accumulator-style construction and a stepping stone toward
zero-knowledge disclosure; it is not a zero-knowledge proof by itself.
