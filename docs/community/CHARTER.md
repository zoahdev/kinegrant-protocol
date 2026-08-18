# KineGrant Community Charter (No-Token DAO-Style Governance)

> Status: accepted for community operation — 2026-08-18
> The normative protocol charter remains `GOVERNANCE.md`. This document
> describes how the community operates and its hard compliance boundaries.

## Mission

KineGrant is an open authorization and accountability layer for physical AI.
The community succeeds when unrelated robot vendors can request the same
capability, a person or space can publish one rule understood by all of them,
an auditor can reproduce the decision, and receipts reveal less than raw logs.

## What "DAO" means here

KineGrant borrows DAO principles — community ownership, transparent decision
records, open participation — and applies them **without any financial
mechanism**. The community never issues tokens, never raises funds, and never
forms a legal entity.

## Hard non-goals (compliance boundaries)

- No cryptocurrency, token, NFT, or any tradable instrument.
- No fundraising, membership fee, investment, or promise of returns.
- No automated or bulk email outreach, cold-email campaigns, or mailing-list
  solicitation of any kind.
- No legal entity, association, or registered organization is formed by this
  community. Contributors join as individuals under open-source licenses.
- No certification or functional-safety conformance claim.
- Contribution credentials have no economic value and are non-transferable.

These boundaries are structural. Proposals or automation that would cross them
are rejected without a community vote and removed.

## Roles

- **Contributor**: anyone whose work is merged under Apache-2.0.
- **Maintainer**: a contributor with merge rights, responsible for review
  quality, CI health, and security triage.
- **Editor**: a maintainer appointed per RFC who owns a document through the
  RFC lifecycle.
- **Working groups**: implementation, security, standards outreach, and
  documentation; all output is public.
- **Steering committee**: a small group of maintainers that resolves
  escalations and runs RFC final votes. Membership is public and rotates.
- **Release manager**: the maintainer who cuts a release and verifies
  checksummed artifacts.

## Decision rules

- Day-to-day changes: maintainer review + required CI + rebase merge.
- Normative changes: KGP-RFC process (see `docs/RFC-PROCESS.md`): 14-day
  comment window, recorded community vote weighted by contribution record,
  then a steering committee supermajority vote.
- Security-critical changes: at least two maintainers review; emergency fixes
  may land first and be reviewed within 72 hours.
- Conflicts of interest must be disclosed; interested parties do not cast the
  deciding vote on their own proposal.

## Transparency

- RFC status, committee records, and decision logs are public.
- Releases and checksums are verified and published publicly.
- Domain names and registries are community assets governed by the charter.

## Amendment

This charter is amended only through the KGP-RFC process.