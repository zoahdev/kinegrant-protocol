# Contributing to KineGrant

KineGrant is an experimental open draft. Contributions should improve precise,
testable interoperability—not expand the project into a general robot platform.

## Good first contributions

- turn an ambiguous KGP-001 sentence into a deterministic rule and test;
- add negative tests for tampering, replay, confused-deputy, or downgrade cases;
- identify where an adapter could silently widen permission;
- propose a persistent replay or revocation interface;
- build an independent verifier in another language;
- document a cross-device simulation without controlling hazardous machinery.

## Pull-request requirements

1. Explain the security property or interoperability problem.
2. Add or update tests for normative behavior.
3. State compatibility and privacy impact.
4. Do not claim certification by W3C, IEEE, CSA, OPC Foundation, or ROS.
5. Keep the real-time action path ledger-independent.

Normative changes should be proposed as a numbered KGP draft or an issue marked
`protocol-change`. Editorial and implementation-only changes may use a normal
pull request. By contributing, you agree that your contribution is licensed
under Apache-2.0.
