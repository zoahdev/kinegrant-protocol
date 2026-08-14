# Conformance Certification Program (Draft)

> Status: draft for community review

## Purpose

A certification mark lets deployments trust that an implementation meets the
KineGrant conformance levels without auditing every line.

## Levels

- **L1 Core semantics**: default deny, deny overrides, single-use capability,
  replay protection, receipt chains.
- **L2 Scoped capabilities**: attenuation, physical constraints, approval
  tiers, forbidden combinations.
- **L3 Delegation & revocation**: delegation binding, allowlists, revocation.
- **L4 Hardware trust**: trusted clock, sensor evidence, checkpoints,
  attestation, post-quantum envelopes.

## Evidence requirements

1. `kinegrant-conformance` report with all requested marks passing;
2. independent reproduction of the conformance suite by a reviewer who did
   not author the implementation;
3. published source commit and reproducibility packet;
4. security review summary for L3 and L4.

## Marks

Certified implementations may use the mark `KineGrant Certified L<n>` in their
documentation. Marks are not endorsements of safety or physical actuation.

## Governance

The certification program is operated by the KineGrant steering committee and
amended through the RFC process. Certification is not required to implement
the protocol.
