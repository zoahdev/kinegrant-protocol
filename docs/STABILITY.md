# KineGrant Stability Policy

> Status: accepted as of v2.2 (2026-08-15).

## Scope

This policy covers:

- wire formats (capabilities, receipts, revocation bundles, policy bundles);
- machine-readable schemas published under `spec/schemas/`;
- the reference implementation's version numbering;
- deprecation and removal of protocol surfaces.

## Stability levels

**Stable** — byte-compatible and covered by the compatibility policy:

- stable wire format `1.0` (KGP-RFC-0001 accepted): capabilities and receipts
  at `1.0` are frozen; new fields are additive and strict validators reject
  unknown fields only when the schema says so.

**Experimental** — may change between releases, always fail-closed:

- `kinegrant:PolicyBundle` schema version `0.1` (v2.0+): signatures,
  authorities, time windows, and rules digests are verified before use; the
  payload shape may evolve until a future RFC freezes it.
- Machine Permission Test evidence schemas (`0.1` through `0.4`).
- ODRL `kgp-v0.2` profile mappings.

**Deprecated** — announced in CHANGELOG and ROADMAP, kept for at least one
minor release, removed only through the RFC process.

## Rules

- Every wire object carries an explicit version; integration layers negotiate
  versions explicitly, never by guessing.
- Draft (`0.x`) versions are compatible only with themselves.
- Within a version, new fields are additive; consumers must keep failing
  closed on unknown obligations, constraints, and authority sets.
- Policy bundles serialize rules as `PolicyRule` objects; the ODRL `kgp-v0.2`
  profile round-trips through `bundle_to_odrl` / `odrl_to_rules`.
- The reference implementation uses semantic versioning: a major bump can
  change experimental surfaces; a minor bump adds features; a patch fixes
  defects without breaking stable wire formats.

## Deprecation process

1. Announce in CHANGELOG and ROADMAP with a replacement path.
2. Keep the surface available for at least one minor release.
3. Remove only with an accepted RFC (see `docs/RFC-PROCESS.md`).

## Security support

See `SECURITY.md`: current 2.x stable versions and the default branch are
supported; 1.x receives security patches while 2.x is supported; 0.x drafts
are not supported.
