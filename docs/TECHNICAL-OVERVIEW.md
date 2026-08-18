# Technical Overview: Why Physical AI Needs Action-Level Authorization

> A plain-language overview for developers, robot vendors, and security
> researchers. This document states facts about the protocol; it makes no
> adoption, certification, or production-readiness claim.

## The problem

AI is moving from generating text to controlling real machines: robots opening
doors, arms moving within limits, cameras recording. Most authorization today
is all-or-nothing: either a principal is logged in and can use everything, or
it cannot. A machine that can physically act needs something narrower: *this
action, this target, this purpose, this short window, exactly once* — not a
master key.

## A concrete scenario

A delivery robot requests "open door-7 once, for delivery." The space policy
allows it; a capability valid for 30 seconds is issued. At the door, a local
gate verifies signature, scope, expiry, and single use before the actuator
moves. After the action, a signed receipt is produced for audit. If the same
request becomes "open the door, then record the hallway for training," policy
rejects it — the purpose does not match.

## Core design

- **Default deny**: no explicit allow, no action. Unknown policy is never
  permission.
- **Short-lived, single-use**: capabilities valid 1–300 seconds, consumed
  atomically; replay is rejected.
- **Local gate**: verification happens immediately before the actuator, not
  in a remote cloud round-trip.
- **Signed receipts**: tamper-evident, privacy-minimized records after
  execution.
- **Post-quantum ready**: ML-DSA-65 alongside Ed25519.

## What it is not

KineGrant is not a robot operating system, motion planner,
functional-safety controller, blockchain, or token. It is a narrow boundary
between "what is allowed" and "what executes," with a verifiable, auditable
gate. Native safety systems keep full veto authority.

## Current status (facts)

- Protocol: KGP-001 Experimental Open Draft 0.1; stable wire format 1.0.
- Reference implementation v2.65.x, Apache-2.0; Python/JavaScript/Go
  implementations cross-verify in CI.
- 22 reproducible Machine Permission Test cases; browser verifier runs
  locally.
- 501 automated tests; OSS-Fuzz; SLSA provenance; OpenSSF Best Practices
  passing.
- Reproducible local verification is documented in
  docs/LOCAL-VERIFICATION.md.

## Why this matters

As physical AI spreads, "a machine can prove it was allowed to act" becomes
infrastructure — like TLS, it should be open, auditable, and not owned by any
single vendor. KineGrant is an attempt to build that layer as a community-owned
protocol. Governance is no-token DAO-style: public RFC decisions, recorded
votes, and no financial mechanism.