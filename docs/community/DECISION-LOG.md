# KineGrant Community Decision Log

Entries are append-only and reference the RFC or pull request that produced
them.

## 2026-08-18 — Community governance established; fundraising outreach removed

- Adopted the no-token DAO-style community model (`docs/community/CHARTER.md`).
- Removed all automated email outreach and fundraising automation from the
  repository: campaign senders, seed-fund reminder, foundation inquiry,
  inbox polling, bounce dump, and their associated Gmail secrets and state.
  Previously queued campaign recipients were never contacted by these
  automated systems beyond the 27 messages already recorded in the removed
  sent-state files; no further messages are sent by the project.
- Confirmed hard non-goals: no tokens, no fundraising, no legal entity, no
  financial mechanism, no bulk email outreach.
- RFC status board adopted: KGP-RFC-0001 accepted; 0002 and 0003 in draft.
- No financial decisions were made or recorded.

## Template

```markdown
## YYYY-MM-DD — <summary>

- Reference: <RFC or PR link>
- Decision: <what was decided>
- Vote record: <link or summary>
- Conflicts of interest: <disclosed or none>
```