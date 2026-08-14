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

This is **not** a zero-knowledge proof: the verifier needs the full document
to recompute the digest. It is the draft foundation that a future
zero-knowledge or accumulator-based scheme can replace.
