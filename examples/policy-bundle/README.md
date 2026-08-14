# Policy bundle lifecycle example

One runnable trace through the signed policy distribution lifecycle:

1. **Publish and enforce** — a trusted authority signs policy version 1 and
   the policy engine consumes the verified rules.
2. **ODRL mapping** — `bundle_to_odrl` produces a `kgp-v0.2` document that
   round-trips through `odrl_to_rules`.
3. **Fleet distribution** — `PolicyDistributor` applies the bundle to two
   registries with per-registry acknowledgements; an upgrade applies and a
   downgrade is a no-op.
4. **Audit** — `analyze_policy_bundle` (static conflict findings) and
   `policy_bundle_coverage` (bounded request-space coverage) both pass.
5. **Revocation rollback** — revoking version 2 rolls back to version 1;
   revoking version 1 leaves no current version (fail-closed).
6. **Fail-closed verification** — tampered bundles and wrong authorities are
   rejected.

Run:

```bash
python examples/policy-bundle/policy_bundle.py
```

The output is a machine-readable `kinegrant:PolicyBundleLifecycleDemo` trace
with a single `passed` verdict.
