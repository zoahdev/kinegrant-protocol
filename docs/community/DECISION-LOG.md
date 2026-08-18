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

## 2026-08-19 — Governance operations and engineering maintenance

- RFC-0003 acceptance vote progressed: half-way status posted on issue #127 (window closes 2026-08-29); vote status surfaced on the README homepage.
- Fixed CI: a YAML syntax error in the lint step name (introduced in PR #252) caused every workflow run to fail during initialization; fixed in PR #272.
- Published governance and participation documentation (bilingual): RFC-0004 Chinese edition, pilot framework Chinese edition, participation guide, RFC voting guide, seat nomination template, technical overview, local verification and release reproducibility records.
- Engineering: deterministic release builds (SOURCE_DATE_EPOCH, PR #288), weekly dependency audit workflow (PR #291), and the five email outreach workflows were disabled.
- No financial decisions were made or recorded.

## Template

```markdown
## YYYY-MM-DD — <summary>

- Reference: <RFC or PR link>
- Decision: <what was decided>
- Vote record: <link or summary>
- Conflicts of interest: <disclosed or none>
```