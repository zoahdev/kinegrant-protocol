# RFC Voting Guide

> How to participate in KineGrant RFC acceptance votes (currently RFC-0003,
> window closes 2026-08-29 — issue #127).

## Who can participate

- **Steering committee members** cast formal votes (supermajority decides).
  External seats are open for nomination (Discussion #246;
  docs/community/STEERING-COMMITTEE.md).
- **Anyone (independent reviewers, implementers, community members)** can post
  advisory comments on the issue — recorded publicly and considered, but not
  counted toward the committee supermajority.

## How to vote (5 minutes)

1. Open the vote issue (currently #127).
2. Read the RFC text (docs/rfcs/0003-policy-bundle-schema.md; Chinese edition
   available as .zh-CN.md).
3. Verify without trusting the thread:
   ```bash
   git clone https://github.com/zoahdev/kinegrant-protocol
   cd kinegrant-protocol
   pip install -e '.[test]'
   python -m kinegrant.conformance
   python -m kinegrant.mpt
   ```
4. Comment with: position (APPROVE / REJECT / ABSTAIN), answers to any open
   questions, 1–3 sentence rationale, and conflict-of-interest disclosure
   (or "none").

## Rules summary

- 14-day comment window; committee supermajority decides afterward.
- Interested parties do not cast the deciding vote on their own proposal.
- All votes are public; outcomes are recorded in
  docs/community/DECISION-LOG.md.
## After the window closes — tally and record

1. The interim chair closes the comment window on the issue and posts a tally comment: committee votes (approve/reject/abstain), advisory comments (count + summary), and any disclosed conflicts of interest.
2. Decision: a supermajority of the steering committee accepts, rejects, or supersedes. With only the interim chair seated, the chair's vote stands as the committee record; the first external seats (Discussion #246) will widen future committees.
3. The outcome is recorded in docs/community/DECISION-LOG.md with: RFC number, window dates, vote record link, result, and any minority positions.
4. Accepted RFCs are merged/tracked in ROADMAP; the RFC header is updated from draft to accepted.
