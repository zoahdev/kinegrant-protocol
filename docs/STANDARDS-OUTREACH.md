# KineGrant Standards Outreach Package

> Status: v1.0.0 companion material

## Purpose

This package is the starting point for engaging standards bodies and
consortia. KineGrant does not claim adoption or conformance with any external
standard; it proposes a narrow, testable authorization boundary that those
standards can reference.

## Target bodies and entry points

| Body | Relevant work | KineGrant hook |
| --- | --- | --- |
| W3C ODRL | policy expression | `kgp-v0.2` ODRL profile mapping physical/approval constraints |
| W3C Web of Things | device descriptions | `ThingRegistry` discovery and WoT TD normalization |
| IEEE (e.g., 7012, 7007.x) | machine-readable consent/risk | MyTerms-style bridge, action vocabulary, risk tiers |
| ROS 2 / Open Robotics | middleware security | `Ros2GoalGate` reference, `Sros2PolicyMapping` |
| OPC Foundation / CSA (Matter) | industrial/smart-home | adapter references and bridge demo |
| ISO/IEC JTC1 / ETSI | AI and robotics safety frameworks | position as an authorization layer, not a safety controller |

## Value proposition

- one machine-readable permission object verified by an actuator-adjacent
  gate;
- short-lived, single-use capabilities with replay protection and
  crash-persistent consumption;
- privacy-minimized, hash-chained, signed receipts;
- fail-closed adapters (unknown restrictions are rejected, never widened);
- reproducible evidence: MPT v0.4 (20/20) and conformance L1-L4 (23/23);
- three independent implementations cross-verified on the stable wire format;
- neutral governance, RFC process, no tokens, no vendor lock-in.

## Evidence packet

- v1.0.0 stable release: https://github.com/zoahdev/kinegrant-protocol/releases/tag/v1.0.0
- Conformance report: `conformance-report-v1.0.0.json`
- MPT v0.2 packet: https://github.com/zoahdev/kinegrant-protocol/releases/tag/mpt-v0.2
- Implementations: Python reference, `kinegrant-js`, `kinegrant-go`

## Governance

- Charter: `GOVERNANCE.md`
- RFC process: `docs/RFC-PROCESS.md`
- Interim committee record: `docs/COMMITTEE.md`
- Certification program draft: `CERTIFICATION.md`

## Suggested first engagements

1. ODRL community: submit the `kgp-v0.2` profile (KGP-RFC-0002,
   `docs/rfcs/0002-odrl-kgp-profile.md`) as a discussion/notes contribution
   with interop fixtures. A ready-to-send draft is in
   `docs/SUBMISSIONS/odrl-community-submission.md`.
2. WoT: propose KineGrant as a Thing-behavior profile in the discovery
   discussion.
3. IEEE: position the action vocabulary and MyTerms bridge as input to
   consent/risk ontologies. Draft note: `docs/SUBMISSIONS/ieee-consent-engagement.md`.
4. ROS 2: publish the `Ros2GoalGate` reference as a community package draft.

## Contact

Project maintainers via GitHub Discussions and issues on
`zoahdev/kinegrant-protocol`. The interim committee chair is `zoahdev`.
