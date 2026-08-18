# KGP-RFC-0004: Independent Implementation Recognition

> Status: draft (2026-08-18)
> Editor: zoahdev
> Related: KGP-RFC-0001, CONFORMANCE.md, implementations/README.md, docs/community/CONTRIBUTION-CREDENTIALS.md
> 摘要：本 RFC 定义“独立实现”的承认机制、申请流程、Founding Implementer 贡献凭证（无经济价值）与公开记录形式。任何经济奖励、代币、NFT、股权或可交易凭证，以及安全性认证或“生产就绪”声明，均不在本 RFC 范围内。

## Motivation

KineGrant's value comes from unrelated implementations agreeing on the same
authorization semantics. The Python reference implementation and the
JavaScript and Go verifiers are cross-verified in CI, but there is no formal
mechanism that recognizes third-party independent implementations. Without
recognition, the ecosystem cannot answer a key question: "Besides the
reference implementation, who has implemented this protocol and proven
compatibility with the stable wire format?"

## Scope

This RFC defines:

1. what qualifies as an independent implementation;
2. how an independent implementation is recognized by the community;
3. the conditions for awarding the "Founding Implementer" contribution credential;
4. the public record format after recognition.

This RFC does **not** cover: any economic reward, token, NFT, equity, or
tradable credential; any safety certification of an implementation; or any
production-readiness claim.

## Proposal

### 1. Definition of independent implementation

An implementation is independent when **all** of the following hold:

- it is not a copy or fork of the reference implementation (Python
  `kinegrant-protocol`);
- it is independently written by a different author or organization and does
  not share the reference implementation's core codebase;
- it implements at least the stable wire format 1.0 core objects:
  `ActionRequest`, `Capability`, `Receipt`;
- it passes Machine Permission Test evidence validation (schema 0.5) or an
  equivalent conformance case set.

### 2. Recognition workflow

1. The implementer opens a pull request adding an implementation manifest and
   interoperability evidence under `implementations/<name>/`.
2. Evidence requirements: the implementation must independently generate or
   verify a Capability and a Receipt, with a reproducible run record
   (commands plus output summary) cross-checked against the reference
   implementation.
3. A maintainer reviews; the steering committee confirms based on the public
   record.
4. The result is recorded in the official list in
   `implementations/README.md` and in the community decision log.

### 3. Founding Implementer credential

- Award condition: the author becomes one of the first (up to 12) formally
  recognized independent implementations through this workflow.
- Properties: a reputation record only; no economic value; non-transferable;
  cannot be bought, sold, staked, or used as an investment instrument.
- Record format follows `docs/community/CONTRIBUTION-CREDENTIALS.md`.

### 4. Public record

- Each recognized implementation lists: name, author/organization,
  language/platform, evidence link, and recognition date.
- The record lives in `implementations/README.md`; any change goes through a
  normal pull request plus maintainer review.

## Security properties

- Recognition is not a security endorsement; recognized implementations must
  state in their own documentation when they have not had an independent
  security audit.
- Evidence must be reproducible (commands and pinned versions), preventing
  screenshot-style claims.
- On cross-verification failure or withdrawn evidence, recognition may be
  revoked (normal PR plus steering committee confirmation).

## Compatibility

- This RFC changes no wire format, schema, or protocol semantics.
- It only adds process documentation and public records; fully backward
  compatible.

## Open questions

- Should recognized implementations be required to provide an independent
  security audit? (Current draft: not required, but must explicitly state the
  absence of an audit.)
- Are the first 12 slots locked by recognition order? (Current draft: yes,
  by process time only; slots cannot be bought or reserved.)

## Test plan

- Add a CI check: every recognized entry under `implementations/` must have a
  reachable evidence link.
- Provide an interoperability run-record template that new implementations
  follow (see `implementations/RECOGNITION.md`).