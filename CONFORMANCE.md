# KineGrant Conformance Levels

> Status: accepted (v1.0.0)

`kinegrant-conformance` runs the reference implementation through four
executable levels and emits a machine-readable report with the marks earned:

| Level | Name | Marks |
| --- | --- | --- |
| L1 | Core semantics | default deny, deny overrides, single use, replay rejection, receipt chains |
| L2 | Scoped capabilities | attenuation, physical constraints, approval tiers, forbidden combinations |
| L3 | Delegation & revocation | delegation binding, delegate allowlists, offline revocation |
| L4 | Hardware trust | trusted clock, sensor evidence, receipt checkpoints, device attestation, post-quantum envelopes |

The suite is a reference self-assessment. Certifying third-party
implementations requires an RFC-approved certification program, independent
reviewers, and reproducible evidence.
