# KGP-RFC-0001: Stable Wire Format

Status: Draft
Editor: zoahdev
Related: COMPATIBILITY.md, CONFORMANCE.md

## Motivation

KineGrant now has two interoperable implementations (Python reference and
JavaScript verifier) and a third in progress (Go). Before external vendors
build on the protocol, the wire format must stop changing in breaking ways.

## Scope

- freeze `v0.1` and `v0.2` object shapes exactly as published;
- introduce `1.0` as the first stable version for new deployments;
- additive-only changes within a stable version;
- explicit deprecation policy (announce, deprecate, remove across three
  stable releases minimum).

## Proposal

1. The `1.0` wire format is identical to the published `0.2` capability,
   receipt, request, policy, and evidence schemas plus a version bump.
2. New fields MUST be optional and additive; strict validators reject unknown
   fields only when a profile says so.
3. Breaking changes require a new major version and an RFC.
4. `0.1` and `0.2` continue to verify forever, but new features target `1.0`.

## Security properties

- No wire change weakens default-deny, replay protection, or receipt chaining.
- Version negotiation stays explicit; downgrade to an older draft requires the
  deployment's explicit policy.

## Compatibility

- `check_compatibility` becomes the normative gate for wire versions.
- Each implementation publishes the versions it supports.

## Open questions

- Whether `0.2` draft-only fields (e.g., `root_capability_id`) stay required
  in `1.0` or become optional.
- Canonical CBOR as an alternative encoding.

## Test plan

- All existing 284 Python tests, 6 JavaScript tests, and Go tests stay green.
- Cross-implementation fixtures generated from `1.0` objects verify in every
  implementation.
