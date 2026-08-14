# KineGrant Governance Charter

> Status: draft for community review

## Mission

KineGrant is an open authorization and accountability layer for physical AI.
The project succeeds when unrelated robot vendors can request the same
capability, a person or space can publish one rule understood by all of them,
an auditor can reproduce the decision, and receipts reveal less than raw logs.

## Non-goals

- No cryptocurrency, token, or financial mechanism, including governance
  tokens;
- no single-vendor control of the protocol or the reference implementation;
- no claim of certification or functional-safety conformance.

## Roles

- **Contributor**: anyone whose work is merged under Apache-2.0.
- **Maintainer**: a contributor with merge rights, responsible for review
  quality, CI health, and security triage.
- **Editor**: a maintainer appointed per RFC who owns a document through the
  RFC process.
- **Steering committee (interim)**: a small group of maintainers that resolves
  escalation disputes. Membership is documented publicly and rotates.
- **Release manager**: the maintainer who cuts a release and verifies
  checksummed artifacts.

## Decision rules

- Day-to-day changes: maintainer review + required CI + rebase merge.
- RFC acceptance: consensus-seeking discussion; a supermajority of the
  steering committee can accept, reject, or supersede.
- Security-critical changes: at least two maintainers review; emergency fixes
  may land first and be reviewed within 72 hours.
- Conflicts of interest must be disclosed in the discussion; interested
  parties do not cast the deciding vote on their own proposal.

## Vendor neutrality

- The protocol, schemas, and reference implementation are Apache-2.0.
- Implementations may be commercial, but no implementation may require a
  vendor service for protocol-level operation.
- Domain names, trademarks, and registries are community assets governed by
  this charter.

## Amendment

This charter is amended only through the RFC process.
