# WoT-Style Discovery Service

> Status: v0.3 draft

`ThingRegistry` is a small, authenticated WoT-style registry for KineGrant
targets. A W3C Web of Things Thing Description is registered with an optional
policy pointer; `resolve(thing_id)` returns normalized actions plus the policy
pointer.

The KGP-001 discovery boundary is enforced at registration:

- an **authenticated** thing may carry a `policy_pointer` that later feeds
  policy evaluation;
- an **unauthenticated** thing may be discovered and its actions inspected, but
  it cannot carry a granting policy pointer; unauthenticated discovery can
  only narrow later decisions.

Unknown things and duplicate registrations fail closed. The service itself is
transport-independent; deployments choose TLS/mTLS, signed discovery bundles,
or a trusted registry as their authenticated channel.
