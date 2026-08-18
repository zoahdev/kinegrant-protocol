# Contribution Credentials

## Purpose

Contribution credentials are public, non-transferable records that recognize
work merged into KineGrant. They express reputation and process rights within
the community. They express **no economic value**.

## Hard rules

- Credentials cannot be bought, sold, traded, staked, delegated, or used as
  investment instruments.
- Credentials cannot be reserved, pre-sold, or transferred between accounts.
- Founding Implementer numbers are assigned only after a reproducible external
  implementation, accepted adapter, confirmed issue, or adopted technical
  proposal. They are not equity, shares, or financial claims.

## Credential levels

| Level | Award | Awarded by |
| --- | --- | --- |
| Contributor | Any merged work under Apache-2.0 | Maintainer merge |
| Maintainer | Sustained review and CI responsibility | Steering committee |
| Editor | RFC document ownership | Steering committee |
| Founding Implementer | Early external implementation or accepted contribution | Steering committee |

## Record format

The registry is a public JSON list; each entry:

```json
{
  "id": "kg-cred-0001",
  "level": "contributor",
  "handle": "github-handle",
  "awarded_at": "2026-08-18",
  "reference": "PR-123",
  "transferable": false,
  "economic_value": 0
}
```