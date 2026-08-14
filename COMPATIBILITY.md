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
