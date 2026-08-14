# KineGrant RFC Process

> Status: draft for community review

## Purpose

RFCs are the mechanism for normative changes to KGP-001, wire formats,
security properties, profiles, governance, and compatibility policy.

## Lifecycle

1. **Draft**: an editor files `docs/rfcs/XXXX-title.md` with the template
   below and opens a pull request marked `RFC`.
2. **Comment**: the PR is open for at least 14 days; questions, objections,
   and alternatives are recorded in the PR.
3. **Review**: the steering committee votes after the comment period. A
   supermajority is required to accept.
4. **Accepted / Superseded / Rejected**: accepted RFCs are merged and tracked
   in the roadmap; a later RFC may supersede them.

## Template

```markdown
# KGP-RFC-XXXX: <title>
Status: Draft
Editor: <handle>
Related: <issues or previous RFCs>

## Motivation
## Scope
## Proposal
## Security properties
## Compatibility
## Open questions
## Test plan
```

## Minimum requirements for acceptance

- motivation grounded in a real deployment or adversarial scenario;
- explicit security-property changes;
- compatibility statement for existing wire objects;
- a test plan with at least one executable test per new property;
- named open questions, not hidden assumptions.

## Responsibilities

- The editor keeps the document current through the lifecycle.
- The steering committee resolves escalation and conflicts of interest.
- Contributors review with adversarial intent per `CONTRIBUTING.md`.
