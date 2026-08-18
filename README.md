# KineGrant Protocol

**Permission infrastructure for physical AI.**

## What this is, in 30 seconds

Robots and AI agents are starting to touch the real world — opening doors,
moving arms, recording video. Most authorization today is all-or-nothing and
hard to audit after the fact. KineGrant adds a narrow, auditable permission
layer for physical AI:

- **Before a machine acts**, it needs a short-lived, one-time *capability*
  bound to exactly who, what, why, and for how long.
- **If it isn't allowed, it doesn't act** — default-deny, and the actuator
  does not move.
- **After it acts**, there's a signed, tamper-evident receipt proving what was
  authorized and what happened.

One line: **"tickets before motion, receipts after motion."**

KineGrant is not a token, blockchain, robot middleware, or functional-safety
system. It complements W3C ODRL, W3C Web of Things, IEEE 7012, ROS 2/SROS2,
OPC UA, and Matter.

*Everything below — threat model, conformance levels, post-quantum signatures,
reproducible evidence — is the technical body that backs this up.*

[![CI](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/ci.yml)
[![ESP32-C3 Firmware](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/firmware.yml/badge.svg)](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/firmware.yml)
[![Release](https://img.shields.io/github/v/release/zoahdev/kinegrant-protocol)](https://github.com/zoahdev/kinegrant-protocol/releases)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/14103/badge)](https://www.bestpractices.dev/projects/14103)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/zoahdev/kinegrant-protocol/badge)](https://securityscorecards.dev/viewer/?uri=github.com/zoahdev/kinegrant-protocol)
[![License](https://img.shields.io/github/license/zoahdev/kinegrant-protocol)](LICENSE.txt)
[![PyPI](https://img.shields.io/pypi/v/kinegrant-protocol)](https://pypi.org/project/kinegrant-protocol/)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14103/badge)](https://www.bestpractices.dev/projects/14103)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/zoahdev/kinegrant-protocol/badge)](https://securityscorecards.dev/viewer/?uri=github.com/zoahdev/kinegrant-protocol)
[![npm](https://img.shields.io/npm/v/kinegrant-js)](https://www.npmjs.com/package/kinegrant-js)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/github/license/zoahdev/kinegrant-protocol)](LICENSE.txt)

[Website](https://kinegrant.com) · [Community](https://kinegrant.com/community) · [Governance](COMMUNITY.md) · [Public verifier](https://kinegrant.com/verify) · [Technical whitepaper](docs/whitepaper/KineGrant-KGP-001-Whitepaper-v0.1.pdf) · [KGP-001](spec/KGP-001.md) · [Reproduce](REPRODUCING.md) · [Open in Codespaces](https://codespaces.new/zoahdev/kinegrant-protocol?ref=main&quickstart=1) · [Threat model](spec/THREAT-MODEL.md) · [Roadmap](ROADMAP.md) · [中文说明](README.zh-CN.md) · [हिन्दी](README.hi.md)

**Try it now, no install:** run the [one-click demo](https://kinegrant.com/playground.html), or open the [offline browser verifier](https://zoahdev.github.io/verify/policy-bundle-verifier.html) — signed bundles, capabilities, delegation chains, forbidden combinations, receipts, MPT evidence, fleet operations, hardware evidence and more are all verified locally in your browser. If KineGrant is useful to you or your team, **give this repo a ⭐** — it helps independent reviewers and robot vendors find the project.

**Contributing:** read [CONTRIBUTING.md](CONTRIBUTING.md) and pick a [good first issue](https://github.com/zoahdev/kinegrant-protocol/labels/good%20first%20issue) — translations, linter setup, documentation, adapters, and independent implementations are all welcome. New here? Ask anything in [Discussions](https://github.com/zoahdev/kinegrant-protocol/discussions).

## Community and governance

KineGrant is community-governed under a no-token DAO-style model: transparent RFC decisions, contribution-based roles, public records, and **no financial mechanism** — no tokens, no fundraising, no legal entity, and no unsolicited outreach. See [COMMUNITY.md](COMMUNITY.md), [docs/community/](docs/community/), the [steering-committee seat guide](docs/community/STEERING-COMMITTEE.md) ([中文](docs/community/STEERING-COMMITTEE.zh-CN.md)), the [community charter](docs/community/CHARTER.md) ([中文](docs/community/CHARTER.zh-CN.md)), and the [pilot partnership framework](docs/PILOT-PARTNERSHIP.md).

Community hub: https://kinegrant.com/community · 中文社区：https://kinegrant.com/zh/community

## Quick start (30 seconds)

```bash
# pip (Python 3.11+)
pip install kinegrant-protocol
kinegrant-demo

# or Docker
docker run --rm ghcr.io/zoahdev/kinegrant-protocol
```

> **KGP-001 Experimental Open Draft 0.1 · stable wire format 1.0**
>
> **Reference implementation v2.65.5 · Apache-2.0**
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

### 快速开始（中文 · 30 秒）

```bash
# pip（需要 Python 3.11+）
pip install kinegrant-protocol
kinegrant-demo

# 或使用 Docker
docker run --rm ghcr.io/zoahdev/kinegrant-protocol
```

> **KGP-001 实验性开放草案 0.1 · 稳定线格式 1.0**
>
> **参考实现 v2.65.5 · Apache-2.0**
>
> 请勿将该实现作为真实机械设备的唯一安全控制手段。

KineGrant 是为机器人和其它物理 AI 系统提供的窄边界授权与问责层。在执行器执行某个动作之前，KineGrant 会验证一个短期、一次性、且与具体智能体、目标、动作、目的和策略决定绑定的能力凭证（capability）。执行之后，执行方可以产出一份签名、且最小化隐私泄露的回执（receipt）。

KineGrant 不是代币、区块链、机器人中间件、运动规划器或功能安全系统。它补充而非取代 W3C ODRL、W3C Web of Things、IEEE 7012、ROS 2/SROS2、OPC UA、Matter 以及各平台原生的安全逻辑。

```text
外部策略/设备描述
            │
            ▼
   KineGrant 边界适配器
            │
            ▼
ActionRequest → PolicyEngine → Capability → ActionGate → Actuator
                                                    │
                                                    ▼
                                           签名回执日志
```
## Security properties implemented in reference implementation v2.65.5

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

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threat model,
[SECURITY.md](SECURITY.md) for the vulnerability reporting policy, and
[docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md) for the independent-review guide.

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
signed receipt. The same policy denies recording and training-data capture. For a
commented, step-by-step walk-through of the same flow, see the beginner example
[`examples/hello-kinegrant.py`](examples/hello-kinegrant.py).

## Machine Permission Test

The reproducible [Machine Permission Test](challenge/README.md) emits strict JSON
evidence with an explicit `PASS` or `FAIL`. It exercises no-grant denial,
single-use authorization, replay, request binding, issuer and expiry checks,
concurrent consumption, persistent replay state, receipt trust, physical
constraints, attenuation, delegation, approval tiers, and forbidden
combinations, receipt-1.0 obligations, obligation compliance, and fleet
revocation distribution, signed policy bundles, fleet policy distribution,
and policy bundle analysis across twenty-two executable cases; the
policy-trust cases additionally record independent JavaScript/Go
cross-verification evidence when those toolchains are available. Validate
the output with
[`machine-permission-test-evidence.schema.json`](spec/schemas/machine-permission-test-evidence.schema.json).
Download the checksum-addressed packet and reference evidence from the
[`mpt-v0.2` release](https://github.com/zoahdev/kinegrant-protocol/releases/tag/mpt-v0.2).

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

## Current feature surface on main

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
- Receipts can be extended additively as version `1.0`: optional
  `obligation_results` record whether each obligation (e.g. emit a signed
  receipt) was satisfied, is pending, or failed with a reason, and an optional
  `failure_reason` records why an attempted action failed. Plain receipts stay
  byte-identical `0.1`; the Python, JavaScript, and Go verifiers all accept
  both versions (see `spec/schemas/receipt-1.0.schema.json`).
- Obligations are enforced after execution: `ObligationCompliance` checks that
  every capability obligation has a verifiable fulfillment — a signed receipt
  for `emitActionReceipt`, an audit-log commitment for `logAuditEvent`, and an
  evidence-preservation commitment for `preserveEvidence` — and the red-team
  suite probes suppressed-receipt evasion. The home-robot and camera-consent
  deployment traces include the compliance verdict, all three runnable demos
  (`kinegrant-robot-demo`, `kinegrant-bridge-demo`, `kinegrant-ros2-demo`)
  report `obligation_compliance_ok`, the conformance suite L1-L4 includes
  `obligation_compliance`, `gatekeeper_boundary`, and
  `revocation_distribution` marks plus a `gatekeeper_boundary_modelcheck`
  and `policy_bundle_trust` / `policy_fleet_distribution` (23/23); the conformance report also cross-checks generated capabilities
  and receipt chains with the independent JavaScript and Go verifiers, and
  the micro-benchmarks include obligation compliance and
  revocation-distribution throughput.
- One-call deployment boundary: `Gatekeeper` composes sequence check,
  revocation check, gate verification and one-time consumption, actuator
  execution, signed receipt, obligation compliance, and the action journal
  into a single `execute()` call with a machine-readable outcome; every stage
  fails closed. All three runnable demos and both deployment traces use
  `Gatekeeper`, and the micro-benchmarks include its throughput.
- Receipt audit interface: `ReceiptAuditor` verifies the receipt chain,
  filters receipts by capability/agent/target/action/purpose/result/time,
  produces a machine-readable summary, and checks obligation compliance;
  it also exports CSV and self-verifying evidence packets, and
  `kinegrant-audit` exposes it as a deployable CLI (`--self-test` for CI);
  the CLI can also verify and include a fleet revocation distribution report
  (`--distribution-report --revocation-bundle --revocation-authorities`).
- Fleet revocation distribution: `RevocationDistributor` verifies one signed
  revocation bundle under the caller-supplied authorities and applies it to
  many gates idempotently, with per-gate acknowledgements in a machine-
  readable report; `verify_distribution_report` re-validates a fleet report
  against its bundle (id/version binding, count integrity, trusted
  authorities), and `kinegrant-revoke-distribute` is the deployable CLI.
- Signed policy bundles: `PolicyAuthority` publishes versioned, signed policy
  documents with a validity window; `PolicyRegistry` activates bundles under
  the caller's trusted authorities, answers "current version" with
  highest-version-wins, and rolls back on per-version revocation;
  `verify_policy_bundle` / `rules_from_bundle` feed the policy engine after
  signature, authority, time-window, and digest checks, and
  `kinegrant-policy-bundle` is the deployable CLI; the independent
  JavaScript and Go verifiers cross-check Python-signed bundles and
  current-version rollback in the conformance report; `bundle_to_odrl`
  maps verified bundles to ODRL through the versioned `kgp-v0.2` profile, and
  `analyze_policy_bundle` emits conservative conflict/coverage findings
  (`kinegrant-policy-bundle --analyze`, fail-closed exit codes);
  `policy_bundle_coverage` runs a bounded request-space check
  (`--coverage`) reporting default denies, per-rule applicability, and
  shadowed allows; `audit_policy_bundles` (`--audit-summary`) aggregates
  verification, analysis, and coverage across a fleet of bundles into one
  machine-readable audit report.
- Fleet policy distribution: `PolicyDistributor` verifies one signed policy
  bundle under the caller's trusted authorities and applies it to many
  registries idempotently (never auto-downgrading), with per-registry
  acknowledgements in a machine-readable report;
  `verify_policy_distribution_report` re-validates a fleet report against its
  bundle, and `kinegrant-policy-bundle --distribute` is the deployable CLI.
- Bounded policy-decision cache: `CachedPolicyEngine` wraps a policy engine
  with an LRU cache (hit/miss statistics, automatic invalidation on policy
  change, future requests never cached) for high-rate deployments; the
  micro-benchmarks include cached-policy throughput, and all runnable demos
  and deployment traces evaluate through the cache.
- Gatekeeper boundary model check: `check_gatekeeper_boundary` enumerates the
  executable decision space (allow, sequence/gate/revocation/obligation
  denials, actuator failure) and verifies composition invariants — the
  actuator runs only after the boundary admits, receipts follow gate
  consumption, the journal records only fully compliant successes, replay
  cannot double-execute, and every denial carries a stage.
- Security review kit: `python scripts/security_review_kit.py --output kit.json`
  generates a machine-readable audit package that actually runs the
  conformance, MPT, red-team, benchmark, and unit-test suites, records the
  exact commands and artifacts for an external auditor, and emits a
  checklist backed by those results; `--packet-dir` emits a checksummed kit
  packet and `--verify-packet` re-validates it offline.
- Cross-agent delegation is opt-in and bounded: a capability may authorize one
  specific delegate for a narrowed scope, and the delegate can never
  re-delegate. Roots can restrict delegates with a fleet `delegate_allowlist`.
- Offline revocation: `RevocationList` plus `root_capability_id` lets the gate
  reject a revoked capability, and revoking the root revokes the whole
  delegation chain. Signed, versioned `RevocationBundle`s provide authenticated
  distribution (see [spec/REVOCATION.md](spec/REVOCATION.md)).
- WoT-style discovery: an authenticated `ThingRegistry` maps Thing
  Descriptions to actions and policy pointers; unauthenticated discovery can
  never carry a granting pointer (see [spec/DISCOVERY.md](spec/DISCOVERY.md)).
- Simulated two-stack robot demo: `kinegrant-robot-demo` runs a ROS 2-style
  and a Matter-style stack against one shared policy with replay, untrusted
  issuer, prompt-injection, physical-limit, and forbidden-combination faults
  (see [spec/ROBOT-DEMO.md](spec/ROBOT-DEMO.md)).
- Reference bridges: `Ros2GoalGate` + `Sros2PolicyMapping` for ROS 2-shaped
  integration, and `kinegrant-bridge-demo` covering Matter, OPC UA, and ROS 2
  adapters with adapter-fidelity checks (see
  [spec/ROS2-BRIDGE.md](spec/ROS2-BRIDGE.md)).
- Cross-system action-gate demo: `kinegrant-ros2-demo` runs a ROS 2-style
  stack and an MCP-style agent tool-call stack (`kinegrant.adapters.mcp`)
  against one shared policy, gate, signed receipt log, and sequence policy,
  with replay, untrusted-issuer, purpose, physical-limit, and forbidden-
  combination faults (see [spec/ROS2-BRIDGE.md](spec/ROS2-BRIDGE.md)).
- Hardware-trust groundwork: `TrustedClock`, signed sensor-evidence
  commitments bound into receipts, notarized receipt checkpoints, signing
  backends for hardware keys, and device attestations with measured-boot
  claims (see [spec/HARDWARE-TRUST.md](spec/HARDWARE-TRUST.md)).
- Privacy groundwork: rotating ephemeral identifiers and selective-disclosure
  envelopes with Merkle inclusion proofs (see
  [spec/PRIVACY.md](spec/PRIVACY.md),
  [spec/MERKLE-DISCLOSURE.md](spec/MERKLE-DISCLOSURE.md)), plus an executable
  red-team suite `kinegrant-red-team` covering replay, mutation, confused
  deputy, conflict, downgrade, clock, revocation, delegation, adapter, and
  sequence attacks (see [spec/RED-TEAM.md](spec/RED-TEAM.md)).
- Static policy analysis (`PolicyInvariants`, `explain_decision`) and a
  deterministic adapter fuzzer (`AdapterFuzzHarness`), plus a
  [governance charter](GOVERNANCE.md) and [RFC process](docs/RFC-PROCESS.md).
- Conformance levels L1-L4 (`kinegrant-conformance`) and a wire-format
  compatibility policy (see [CONFORMANCE.md](CONFORMANCE.md) and
  [COMPATIBILITY.md](COMPATIBILITY.md)).
- Independent JavaScript verifier (`kinegrant-js`) that verifies JCS,
  Ed25519 envelopes, v0.1 capabilities, and receipt chains signed by the
  Python reference implementation (see
  [implementations/README.md](implementations/README.md)).
- Independent Go verifier (`kinegrant-go`, standard library only) cross-tested
  against the Python reference implementation in CI, plus the first stable
  wire-format RFC draft ([docs/rfcs/0001-stable-wire-format.md](docs/rfcs/0001-stable-wire-format.md))
  and the [certification program draft](CERTIFICATION.md).
- Runnable deployment examples: home-robot delivery and camera-consent traces
  with full policy -> capability -> gate -> receipt flows (see
  [docs/DEPLOYMENT-CASES.md](docs/DEPLOYMENT-CASES.md)); the
  [policy-bundle lifecycle example](examples/policy-bundle/README.md) walks
  publish -> enforce -> ODRL -> fleet distribution -> audit -> revocation
  rollback in one runnable trace.
- A standalone, offline [browser policy-bundle verifier](verify/policy-bundle-verifier.html)
  verifies signed bundles, current-version selection, capabilities, and
  receipt chains, MPT evidence (v0.5), revocation bundles, and policy distribution
  reports, receipt evidence packets, and audit CSV exports, entirely in the
  browser, plus external reproduction and revocation distribution reports
  and ODRL mapping of verified bundles, plus `kg.action.*` and obligation
  vocabulary checks, canonical identity syntax validation, and policy
  analysis report re-verification, plus scoped delegation chain verification
  and forbidden-combination sequence checks, and it verifies both Ed25519 and
  post-quantum ML-DSA-65 signed envelopes, plus conformance report
  re-verification, fleet policy audit summaries, and security review kit
  re-verification, plus ESP32-C3 hardware evidence re-verification (zero
  dependencies), plus combined fleet operations reports (policy + revocation
  distribution), benchmark report re-verification, and one-stop policy
  lifecycle traces, plus sensor evidence commitments and receipt checkpoints
  and device attestations, plus ROS2/MCP and adapter bridge demo reports
  and combined hardware trust packets (zero dependencies; host `verify/`
  anywhere and link the page), plus gateway robot demo reports and the
  camera-consent scenario trace, one-stop full lifecycle reports, and
  evidence export packets.
- Stable wire format: the reference implementation issues and verifies `1.0`
  capabilities (frozen scoped shape), with `capability-1.0` schema and
  KGP-RFC-0001 accepted, and the JavaScript and Go verifiers accept `0.2`/`1.0`
  scoped capabilities. Reference implementation version is now `2.65.5`.
  Standards-outreach materials are in
  [docs/STANDARDS-OUTREACH.md](docs/STANDARDS-OUTREACH.md).
- Release packets can be verified offline with
  `python scripts/verify_release.py <packet-dir>` (checksums, conformance
  report, and MPT evidence), and `python benchmarks/bench.py` reports
  machine-readable throughput for policy, issuance, gating, receipts, and JCS.
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
  constraints and `emitActionReceipt` duty obligations, plus a
  `kg:prohibitedCombination` extension for cross-action forbidden
  combinations; `rules_to_odrl()` serializes rules back into profile
  documents for a faithful round trip. The IEEE 7012 bridge accepts
  profile/version metadata. Unknown constraints and duties still fail closed.

## Repository map

| Path | Purpose |
| --- | --- |
| `spec/KGP-001.md` | Normative core protocol draft |
| `spec/THREAT-MODEL.md` | Assumptions, adversaries, and unsolved risks |
| `spec/STANDARD-MAPPING.md` | Boundaries with existing standards |
| `spec/schemas/` | Strict Draft 2020-12 schemas for all core objects |
| `challenge/` | Reproducible Machine Permission Test instructions |
| `REPRODUCING.md` | External reproduction and evidence-submission guide |
| docs/LOCAL-VERIFICATION.md | Offline reproducible verification record |
| `examples/` | Public, schema-valid signed sample objects |
| `proof/esp32-c3/` | Non-normative low-risk device-boundary experiment |
| `src/kinegrant/` | Python reference implementation |
| `tests/` | Executable security and interoperability checks |
| `CITATION.cff` | Citation metadata for exact releases and commits |
| `codemeta.json` | Machine-readable software and subject metadata |
| `SECURITY.md` | Vulnerability reporting policy |
| `CONTRIBUTING.md` | Open contribution and RFC process |
| `GOVERNANCE.md` | Vendor-neutral governance charter |

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
