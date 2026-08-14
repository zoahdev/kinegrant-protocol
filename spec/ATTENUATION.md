# Capability Attenuation and Scoped Delegation

> Status: v0.2 draft

## Model

A v0.2 capability carries a **scope** instead of one exact action triple:

- `target`: a glob pattern the request target must match;
- `actions`: a non-empty list of permitted actions;
- `purposes`: a non-empty list of permitted purposes;
- `constraints`: optional physical ceilings (`max_force_newtons`,
  `max_velocity_mps`, `allowed_zones`);
- `approval_tier`: the minimum human/operator approval required (0 = automatic,
  1 = operator approval, 2 = human present).

A **root** v0.2 capability is issued directly from a decision with
`CapabilityIssuer.issue_scoped(...)` and has `parent_capability_id: null`.

## Attenuation rules

`CapabilityIssuer.issue_attenuated(...)` derives a child that MUST:

- keep the same issuer; the agent stays the principal unless delegation is
  explicitly enabled (see below);
- keep `request_digest`, `policy_digest`, and a non-empty subset of
  `matched_policy_ids`;
- narrow `target` to a literal the parent pattern matches
  (`door-*` -> `door-7`);
- keep `actions` and `purposes` as subsets of the parent's;
- stay inside the parent's validity window and never exceed 300 seconds;
- only tighten `constraints` (lower force/velocity ceilings, fewer zones);
- keep the same `approval_tier`.

Any attempt to widen the scope is rejected at issuance time, and
`verify_attenuation(child_payload, parent_payload)` lets an independent auditor
re-check the narrowing without trusting the issuer.

## Cross-agent delegation

Delegation is opt-in and bounded:

- a root v0.2 capability may set `delegation_allowed: true` and
  `max_delegation_depth` (1-3);
- a delegated child binds one specific `delegate_agent` and its own
  `delegate_request` digest; the principal remains the capability `agent`;
- the delegate cannot re-delegate (`delegation_allowed: false`,
  `max_delegation_depth: 0` on the child);
- the gate requires the executing request's agent to equal `delegate_agent`
  and verifies the child against its parent envelope when one is supplied.

## Gate behavior

`ActionGate.authorize()` accepts v0.1 (exact action triple) and v0.2 (scoped)
capabilities. When `parent_capability=` is supplied, the gate additionally
verifies the child is a valid attenuation of that parent before consuming it.
Consumption stays atomic and single-use for every version.

## Open work

- revocation of a delegated capability before expiry;
- fleet-level delegation sets and sub-agent allowlists;
- evidence that the delegate is the exact enrolled device.
