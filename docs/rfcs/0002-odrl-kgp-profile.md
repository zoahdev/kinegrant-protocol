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

## Duty obligations

ODRL `duty` actions map to KineGrant capability obligations. The profile
currently recognizes exactly one obligation:

| ODRL duty action | KineGrant obligation |
| --- | --- |
| `emitActionReceipt` | `emitActionReceipt` (must produce a signed receipt) |

Unknown duty actions are **rejected**, never silently dropped: dropping an
obligation would widen permission. A policy rule whose decision carries an
obligation issues a capability that binds the obligation, and the action gate
rejects capabilities with obligations it does not know.

## Forbidden combinations (`kg:prohibitedCombination`)

ODRL 2.2 cannot natively express cross-action invariants such as "once this
space has been recorded, training on it is forbidden". The profile adds a
top-level `kg:prohibitedCombination` member (only valid with the profile
marker) that maps to KineGrant `ForbiddenCombination`/`SequencePolicy` rules:

```json
{
  "uid": "urn:kinegrant:combo:record-train",
  "patterns": [{"action": "record", "target": "space-*"}],
  "windowSeconds": 3600,
  "trigger": {"action": "train_on_data", "target": "space-*"}
}
```

- `patterns` is a non-empty list of `{action, target}` glob pairs that must
  never all be observed in the deployment's action journal;
- `windowSeconds` (optional) limits how recent journal entries must be;
- `trigger` (optional) narrows which requests are denied once the combination
  is complete; without it every subsequent request is denied.

`odrl_to_sequence_policy()` builds a fail-closed `SequencePolicy`, and
`rules_to_odrl()` serializes KineGrant rules plus forbidden combinations back
into a profile document for a faithful round trip.

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
- `tests/test_odrl_sequences.py` covers duty obligations (known/unknown),
  forbidden-combination parsing and enforcement, and ODRL round trips;
- fuzz harness (`kinegrant.fuzz.AdapterFuzzHarness`) includes the ODRL adapter.

## Open questions

- whether `prohibition` should support lower bounds (e.g., `minForce`).
