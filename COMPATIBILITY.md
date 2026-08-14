# Wire-Format Compatibility Policy

> Status: accepted (KGP-RFC-0001)

Wire objects carry an explicit `version`. The reference implementation
supports `0.1` (exact action triple), `0.2` (scoped capabilities), and `1.0`
(frozen scoped capabilities, identical shape to `0.2` with a version marker).

Rules:

- draft 0.x versions are compatible only with themselves (`check_compatibility`);
- within a version, new fields are additive and must be rejected by strict
  validators only when `additionalProperties: false` applies;
- `0.1` envelopes stay byte-stable; `0.2` may change until its first stable
  release;
- version negotiation is explicit at the integration layer, never guessed.

A stable `1.0` wire format is accepted by KGP-RFC-0001, freezes compatibility,
and starts the deprecation policy.

## Policy bundles (v2.0+)

`kinegrant:PolicyBundle` payloads carry `schema_version: "0.1"` (experimental
until an RFC freezes it). Verification is fail-closed: signature, trusted
authority, policy id, time window, and rules digest must all pass before rules
are used. Rules serialize as `PolicyRule` objects and round-trip through the
ODRL `kgp-v0.2` profile (`bundle_to_odrl` / `odrl_to_rules`). Unknown
obligations and constraints remain rejected, so an experimental schema change
can never silently weaken a policy. The full stability and deprecation rules
are in `docs/STABILITY.md`.
