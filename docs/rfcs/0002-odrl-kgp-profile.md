# KGP-RFC-0002: Versioned ODRL Profile (kgp-v0.2)

Status: Draft for community review
Editor: zoahdev
Related: KGP-RFC-0001, spec/ACTION-VOCABULARY.md, src/kinegrant/adapters/odrl.py

## Motivation

W3C ODRL is the natural policy-expression layer for KineGrant, but its
constraint vocabulary does not cover physical ceilings (force, velocity,
zones) or approval requirements. This RFC defines a versioned KineGrant
profile that maps those constraints into ODRL while preserving KineGrant's
fail-closed rule: unknown restrictions are rejected, never widened.

## Profile identity

`https://kinegrant.com/profiles/odrl/kgp-v0.2`

## Constraint mapping

| ODRL leftOperand | Operator | rightOperand | KineGrant constraint |
| --- | --- | --- | --- |
| `maxForceNewtons` | `eq` / `lteq` | number >= 0 | `max_force_newtons` |
| `maxVelocityMps` | `eq` / `lteq` | number >= 0 | `max_velocity_mps` |
| `allowedZones` | `eq` | list of strings | `allowed_zones` |
| `minApprovalTier` | `eq` | integer 0-2 | `min_approval_tier` |

Without the profile marker, these leftOperands are rejected by the adapter.
With the marker, values are validated strictly; malformed values are rejected.

## Semantics

- an `allow` permission applies only when the request proves compliance with
  every constraint;
- a `prohibition` with a physical bound applies when evidence is missing or
  the bound is exceeded (deny cannot be bypassed by omitting the measurement);
- adapter output records `source.profile` so provenance is preserved.

## Example

```json
{
  "@context": "http://www.w3.org/ns/odrl/2/",
  "@type": "Offer",
  "uid": "urn:kinegrant:odrl:door-7",
  "profile": "https://kinegrant.com/profiles/odrl/kgp-v0.2",
  "assigner": "trusted-issuer",
  "permission": [{
    "target": "urn:kinegrant:target:door-7",
    "assignee": "*",
    "action": "open",
    "constraint": [
      {"leftOperand": "maxForceNewtons", "operator": "lteq", "rightOperand": 50},
      {"leftOperand": "allowedZones", "operator": "eq", "rightOperand": ["dock-*"]}
    ]
  }]
}
```

## Compatibility

- Profile documents are versioned by their `profile` URI;
- `kgp-v0.2` targets the stable 1.0 wire format;
- future profiles use a new URI, never reuse `kgp-v0.2`.

## Test plan

- `tests/test_profiles_interop.py` covers mapping, enforcement, fail-closed
  rejection without the profile, and invalid values;
- fuzz harness (`kinegrant.fuzz.AdapterFuzzHarness`) includes the ODRL adapter.

## Open questions

- whether to add ODRL `duty` obligations beyond `emitActionReceipt`;
- whether `prohibition` should support lower bounds (e.g., `minForce`).
