# Wire-Format Compatibility Policy

> Status: draft for community review

Wire objects carry an explicit `version`. The reference implementation
supports `0.1` (exact action triple) and `0.2` (scoped capabilities).

Rules:

- draft 0.x versions are compatible only with themselves (`check_compatibility`);
- within a version, new fields are additive and must be rejected by strict
  validators only when `additionalProperties: false` applies;
- `0.1` envelopes stay byte-stable; `0.2` may change until its first stable
  release;
- version negotiation is explicit at the integration layer, never guessed.

A stable `1.0` wire format, once accepted by an RFC, freezes compatibility
and starts the deprecation policy.
