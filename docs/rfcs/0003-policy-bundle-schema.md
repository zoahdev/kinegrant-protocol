# KGP-RFC-0003: Policy Bundle Schema Stability

> Status: draft (2026-08-15)

## Summary

Freeze `kinegrant:PolicyBundle` schema version `0.1` as the stable policy
distribution format, so fleets and independent implementations can depend on
byte-stable bundles, current-version selection, and per-registry fleet
acknowledgements.

## Motivation

Policy bundles (v2.0+) are already verified fail-closed, cross-implemented in
JavaScript and Go, distributed fleet-wide with acknowledgements, and mapped
to ODRL. Adopters need a stability promise before treating bundles as a
long-term integration surface.

## Proposal

1. Keep the envelope format (`alg` + `kid` + `payload` + `signature`), the
   payload fields (`type`, `schema_version`, `bundle_id`, `policy_id`,
   `issuer`, `version`, `previous_version_digest`, `issued_at`, `not_before`,
   `not_after`, `policy_digest`, `rules`), and the digest semantics unchanged.
2. New payload fields are additive; verifiers must keep rejecting unknown
   obligations, constraints, and authority sets (fail-closed).
3. `PolicyRule` serialization and the ODRL `kgp-v0.2` mapping are normative;
   changes require a new RFC.
4. Deprecation follows `docs/STABILITY.md` (announce, keep one minor release,
   remove only via RFC).

## Open questions

- Should `schema_version` move to `1.0` on acceptance, or stay `0.1` with a
  frozen guarantee? (Editor recommendation: move to `1.0` and keep `0.1`
  verification for one release.)
- Should fleet distribution reports get a schema freeze in the same RFC?

## Impact

- Reference implementation: validate frozen schema in `verify_policy_bundle`.
- Independent verifiers: JS/Go keep the frozen checks.
- Release process: conformance 23/23 and MPT 20/20 remain the gates.
