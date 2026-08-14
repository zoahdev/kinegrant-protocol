# KineGrant Protocol

**Permission infrastructure for physical AI.**

[![CI](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/ci.yml)
[![ESP32-C3 Firmware](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/firmware.yml/badge.svg)](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/firmware.yml)
[![Release](https://img.shields.io/github/v/release/zoahdev/kinegrant-protocol)](https://github.com/zoahdev/kinegrant-protocol/releases)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/github/license/zoahdev/kinegrant-protocol)](LICENSE.txt)

[Website](https://kinegrant.com) · [Public verifier](https://kinegrant.com/verify) · [Technical whitepaper](docs/whitepaper/KineGrant-KGP-001-Whitepaper-v0.1.pdf) · [KGP-001](spec/KGP-001.md) · [Reproduce](REPRODUCING.md) · [Open in Codespaces](https://codespaces.new/zoahdev/kinegrant-protocol?ref=main&quickstart=1) · [Threat model](spec/THREAT-MODEL.md) · [Roadmap](ROADMAP.md)

> **KGP-001 Experimental Open Draft 0.1**
>
> **Reference implementation v0.1.1 · Apache-2.0**
>
> Do not use this implementation as the sole safety control for real machinery.

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

## Security properties implemented in reference implementation v0.1.1

- default deny and deny-overrides policy evaluation;
- explicit trust boundary for policy issuers: untrusted sources may deny but never allow;
- trusted-clock request freshness and policy-window evaluation;
- Ed25519-signed capabilities with a 1–300 second lifetime;
- binding to agent, target, action, purpose, request digest, and policy digest;
- atomic one-time consumption with in-memory and crash-persistent SQLite replay stores;
- explicit trusted-issuer allowlist;
- signed, hash-chained action receipts;
- strict adapters that reject unknown authorization restrictions;
- strict JSON Schemas for every core object;
- tests for policy provenance, denial, tampering, expiration, concurrent/persistent
  replay, receipt trust, schemas, and adapters.

The default replay cache is in-memory and therefore for demonstration only. The
included `SQLiteReplayStore` persists consumption across process restarts, but
production deployments still need deployment-specific atomic storage, revocation, hardware-backed
keys, secure time, independent review, and a gate inside the trusted actuator path.

## Quick start

Requires Python 3.11 or newer.

```bash
git clone https://github.com/zoahdev/kinegrant-protocol.git
cd kinegrant-protocol
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e '.[test]'
kinegrant-demo
kinegrant-mpt --output machine-permission-test.evidence.json
python -m unittest discover -s tests -v
```

The demo authorizes a delivery robot to open one specific door for delivery,
issues a 60-second capability, consumes it once at the action gate, and emits a
signed receipt. The same policy denies recording and training-data capture.

## Machine Permission Test

The reproducible [Machine Permission Test](challenge/README.md) emits strict JSON
evidence with an explicit `PASS` or `FAIL`. It exercises no-grant denial,
single-use authorization, replay, request binding, issuer and expiry checks,
concurrent consumption, persistent replay state, receipt trust, physical
constraints, attenuation, delegation, approval tiers, and forbidden
combinations across fourteen executable cases. Validate
the output with
[`machine-permission-test-evidence.schema.json`](spec/schemas/machine-permission-test-evidence.schema.json).
Download the checksum-addressed packet and reference evidence from the
[`mpt-v0.1` release](https://github.com/zoahdev/kinegrant-protocol/releases/tag/mpt-v0.1).

The browser-based [public verifier](https://kinegrant.com/verify) checks MPT
evidence locally and can verify the Ed25519 signature, content-addressed ID,
and caller-supplied executor trust anchor for the published
[`sample-receipt-v0.1.json`](examples/sample-receipt-v0.1.json). Signature
validity alone is not treated as executor trust or proof of physical action.

Independent implementers can generate a provenance-bound packet with one
cross-platform command and verify it without trusting hosted output. See
[REPRODUCING.md](REPRODUCING.md).

## Low-risk ESP32-C3 proof

The non-normative [ESP32-C3 proof profile](proof/esp32-c3/README.md) now includes
locked-by-default ESP-IDF firmware, secret-safe provisioning, a strict serial
bridge, persistent device replay state, device-signed acknowledgements, a
no-actuation preflight, and a reproducible firmware build in GitHub Actions.

Its physical evidence status remains **NOT_RUN**. The repository does not claim
that a GPIO, servo, or real machine has moved, and this experiment is not a
functional-safety control or certification. Hardware assembly and the published
acceptance run are tracked in [issue #7](https://github.com/zoahdev/kinegrant-protocol/issues/7).

## v0.2 development on main

- RFC 8785 JCS canonical JSON is now the deterministic encoding behind every
  digest and signature, matching ECMAScript number semantics and UTF-16 member
  ordering so independent implementations can produce byte-identical decisions.
- A machine-readable [`kg.action.*` vocabulary](spec/ACTION-VOCABULARY.md)
  covers `observe`, `record`, `touch`, `grasp`, `move`, `open`, `enter`,
  `retain`, and `train_on_data`, with risk tiers and data-sensitivity
  metadata. Enable `PolicyEngine(require_known_actions=True)` to fail closed on
  unknown action terms.
- Physical constraints are enforced by policy rules: `max_force_newtons`,
  `max_velocity_mps`, and `allowed_zones`. A rule that declares a physical
  limit denies requests that omit or exceed the corresponding context value.
- Scoped v0.2 capabilities support attenuation: a trusted issuer can derive a
  strictly narrower child (target, actions, purposes, lifetime, physical
  limits) that the action gate can verify against its parent. See
  [spec/ATTENUATION.md](spec/ATTENUATION.md).
- Approval tiers: policy decisions carry `required_approval_tier` (automatic /
  operator approval / human present), and scoped capabilities bind the tier.
- Receipts carry the authorization context of v0.2 capabilities: approval
  tier, physical constraints, and parent capability id are recorded in the
  signed receipt so audits see exactly what was authorized.
- Cross-agent delegation is opt-in and bounded: a capability may authorize one
  specific delegate for a narrowed scope, and the delegate can never
  re-delegate.
- Post-quantum signing is available as an experimental parallel to Ed25519 via
  FIPS 204 ML-DSA-65 envelopes (`alg: "ML-DSA-65"`).
- Forbidden combinations: an `ActionJournal` plus `SequencePolicy` denies
  requests once a dangerous set of actions has all been observed (e.g. record
  then train on data), with optional time windows and trigger patterns.
- Canonical identifiers: agents, targets, and policies use the
  `urn:kinegrant:<kind>:<namespace>:<local-id>` grammar. See
  [spec/IDENTITY.md](spec/IDENTITY.md).
- Versioned external profiles: the ODRL adapter supports a KineGrant
  physical-action profile (`kgp-v0.2`) mapping force/velocity/zone/approval
  constraints, and the IEEE 7012 bridge accepts profile/version metadata.
  Unknown constraints still fail closed.

## Repository map

| Path | Purpose |
| --- | --- |
| `spec/KGP-001.md` | Normative core protocol draft |
| `spec/THREAT-MODEL.md` | Assumptions, adversaries, and unsolved risks |
| `spec/STANDARD-MAPPING.md` | Boundaries with existing standards |
| `spec/schemas/` | Strict Draft 2020-12 schemas for all core objects |
| `challenge/` | Reproducible Machine Permission Test instructions |
| `REPRODUCING.md` | External reproduction and evidence-submission guide |
| `examples/` | Public, schema-valid signed sample objects |
| `proof/esp32-c3/` | Non-normative low-risk device-boundary experiment |
| `src/kinegrant/` | Python reference implementation |
| `tests/` | Executable security and interoperability checks |
| `CITATION.cff` | Citation metadata for exact releases and commits |
| `codemeta.json` | Machine-readable software and subject metadata |
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
