# KineGrant Protocol

**Permission infrastructure for physical AI.**

[![CI](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/zoahdev/kinegrant-protocol)](https://github.com/zoahdev/kinegrant-protocol/releases)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/github/license/zoahdev/kinegrant-protocol)](LICENSE.txt)

[Website](https://kinegrant.com) · [KGP-001](spec/KGP-001.md) · [Threat model](spec/THREAT-MODEL.md) · [Roadmap](ROADMAP.md)

> Status: experimental open draft v0.1. Do not use this implementation as the
> sole safety control for real machinery.

KineGrant is a narrow authorization and accountability layer for robots and
other physical-AI systems. Immediately before an actuator performs an action,
KineGrant verifies a short-lived, one-time capability bound to the exact agent,
target, action, purpose, and policy decision. After execution, the executor can
produce a signed, privacy-minimized receipt.

KineGrant is not a token, blockchain, robot middleware, motion planner, or
functional-safety system. It complements—rather than replaces—W3C ODRL, W3C
Web of Things, IEEE 7012, ROS 2/SROS2, OPC UA, Matter, and native safety logic.

```text
external policy/device description
            │
            ▼
   KineGrant boundary adapters
            │
            ▼
ActionRequest → PolicyEngine → Capability → ActionGate → Actuator
                                                    │
                                                    ▼
                                           Signed Receipt Log
```

## Security properties implemented in v0.1

- default deny and deny-overrides policy evaluation;
- Ed25519-signed capabilities with a 1–300 second lifetime;
- binding to agent, target, action, purpose, request digest, and policy digest;
- one-time local consumption with replay protection;
- explicit trusted-issuer allowlist;
- signed, hash-chained action receipts;
- conservative adapters that do not turn unknown restrictions into permission;
- tests for denial, tampering, expiration, replay, receipt integrity, and adapters.

The included replay cache is in-memory and therefore for demonstration only.
Production deployments need persistent replay state, revocation, hardware-backed
keys, secure time, independent review, and a gate inside the trusted actuator path.

## Quick start

Requires Python 3.11 or newer.

```bash
git clone https://github.com/zoahdev/kinegrant-protocol.git
cd kinegrant-protocol
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .
kinegrant-demo
python -m unittest discover -s tests -v
```

The demo authorizes a delivery robot to open one specific door for delivery,
issues a 60-second capability, consumes it once at the action gate, and emits a
signed receipt. The same policy denies recording and training-data capture.

## Repository map

| Path | Purpose |
| --- | --- |
| `spec/KGP-001.md` | Normative core protocol draft |
| `spec/THREAT-MODEL.md` | Assumptions, adversaries, and unsolved risks |
| `spec/STANDARD-MAPPING.md` | Boundaries with existing standards |
| `src/kinegrant/` | Python reference implementation |
| `tests/` | Executable security and interoperability checks |
| `SECURITY.md` | Vulnerability reporting policy |
| `CONTRIBUTING.md` | Open contribution and RFC process |

## Non-goals

- no cryptocurrency, token, or financial mechanism;
- no blockchain dependency in the real-time action path;
- no claim of formal conformance with external standards;
- no claim that signatures prove physical-world truth;
- no remote-control implementation for hazardous machinery.

## Contributing

The highest-value early contributions are adversarial: identify ambiguous
semantics, bypasses, replay/revocation failures, privacy leaks, and adapter
mismatches. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Apache-2.0 licensed. KineGrant Protocol is currently an independent experimental
open project, not an adopted industry standard.
