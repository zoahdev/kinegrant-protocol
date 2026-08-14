# Revocation Lists and Signed Bundles

> Status: v0.2 draft

## RevocationList

`RevocationList` is an offline set of revoked capability ids with optional
reasons and timestamps, serialized as JSON and checksummed with `digest()`.
Every v0.2 capability carries `root_capability_id`, so revoking the root of a
delegation chain revokes every descendant.

## Signed bundles

For distribution, a list is wrapped in a `RevocationBundle`:

- content-addressed `bundle_id`;
- monotonic `version` (positive integer);
- optional `previous_bundle_digest` (SHA-256 of the previous bundle body) for
  chain continuity;
- `issuer` key id and a signed envelope (Ed25519 or ML-DSA-65).

`verify_revocation_bundle()` checks the signature, schema, issuer key binding,
optional trust anchor, chain digest, and bundle id. The resulting
`RevocationList` can be passed straight into `ActionGate(revocation_list=...)`.

Distribution and authentication of bundles are deployment-specific (signed
file, device update, registry, local network cache). No ledger is required.
