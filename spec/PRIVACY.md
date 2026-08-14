# Privacy Groundwork (v0.5)

> Status: v0.5 draft

## Rotating identifiers

`RotatingIdentifierRegistry` maps a static identifier to a short-lived
ephemeral identifier (`urn:kinegrant:ephemeral:<namespace>:<hex>`). The
registry resolves the ephemeral id only within its lifetime; `rotate()`
revokes the previous id before issuing a new one. Receipts and logs can carry
ephemeral ids so long-lived identity strings are not repeated in the clear.

## Selective disclosure

`redact()` builds a disclosure envelope over a document: only the requested
fields are revealed, all other fields are replaced with `null`, and the
envelope commits to the full document digest. `verify_redaction()` checks that
the visible fields match the original document exactly and that hidden fields
are not leaked.

The digest envelope is complemented by
[Merkle selective disclosure](MERKLE-DISCLOSURE.md): a verifier checks
revealed fields against a root using inclusion proofs, without seeing the
full document. Neither is a zero-knowledge proof; they are the accumulator
foundation that a future zero-knowledge scheme can replace.
