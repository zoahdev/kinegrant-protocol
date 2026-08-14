# W3C ODRL Community Group Submission (Draft)

> Status: ready for review; send via the ODRL Community Group discussion list.

## Title

KineGrant `kgp-v0.2`: a versioned ODRL profile for physical-AI authorization.

## Summary

KineGrant maps a narrow physical-action authorization boundary onto ODRL:
target, assignee, action, purpose, and constraints. The `kgp-v0.2` profile
adds four physical/approval constraints (`maxForceNewtons`,
`maxVelocityMps`, `allowedZones`, `minApprovalTier`) with strict validation
and fail-closed semantics: unknown restrictions are rejected, never widened.

## Motivation

As robots and embodied agents act in the physical world, policy expression
needs ceilings (force, velocity, zones) and approval requirements that ODRL
does not define today. A versioned profile lets ODRL express these without
changing the core vocabulary.

## Proposal

- profile URI: `https://kinegrant.com/profiles/odrl/kgp-v0.2`;
- full mapping, semantics, example, and test plan:
  `docs/rfcs/0002-odrl-kgp-profile.md`;
- reference implementation: `src/kinegrant/adapters/odrl.py`;
- interop and fuzz tests: `tests/test_profiles_interop.py`,
  `kinegrant.fuzz.AdapterFuzzHarness`.

## Evidence

- stable release: https://github.com/zoahdev/kinegrant-protocol/releases/tag/v1.0.0
- conformance L1-L4 17/17; MPT v0.2 14/14;
- three independent implementations cross-verified on wire format 1.0.

## Contact

Interim committee chair: `zoahdev` (GitHub).
