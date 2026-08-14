# KineGrant Machine Permission Test v0.3

This is a reproducible software test of the KGP-001 permission boundary. It checks that no action is authorized without a capability, a valid capability executes once, replay and request mutation fail, issuer and expiry checks fail closed, concurrent consumption has one winner, replay remains blocked after restart, and receipt tampering or an untrusted executor is rejected.

Version 0.2 adds executable evidence for the v0.2 protocol surface: physical
constraints, scoped capability attenuation with parent verification,
cross-agent delegation, approval-tier propagation into receipts, and forbidden
combinations.

It does not prove functional safety or that a physical action happened.

## Run

```bash
python -m pip install -e '.[test]'
kinegrant-mpt --output machine-permission-test.evidence.json
python challenge/verify_evidence.py machine-permission-test.evidence.json
```

To generate a self-checking external reproduction packet that also binds the
source commit, environment, generator, verifiers, Schemas, and evidence bytes:

```bash
python challenge/reproduce.py --output-dir reproduction-output
python challenge/verify_reproduction.py reproduction-output/reproduction-report.json
```

See [REPRODUCING.md](../REPRODUCING.md) for clean-room steps and reporting.

For publishable evidence, pass the exact tested Git commit with
`--source-commit`. Evidence always includes a SHA-256 digest of the runner and
the Python/runtime platform, even when no repository commit is available.

Success exits with status `0` and prints `"overall_result": "PASS"`. Any failed case exits nonzero while preserving machine-readable evidence.

The independent verifier checks the Draft 2020-12 Schema, all required case IDs,
unique IDs, summary counts, and overall PASS/FAIL consistency. The Schema is:

```text
spec/schemas/machine-permission-test-evidence.schema.json
```

The public browser verifier at <https://kinegrant.com/verify> performs these
evidence consistency checks without uploading the file. It also verifies the
published signed receipt sample. Executor trust requires a caller-supplied
trusted key ID; an embedded key and valid signature are not a trust decision.

## Required cases

| ID | Assertion |
| --- | --- |
| MPT-001 | No capability means zero actuator calls. |
| MPT-002 | A valid capability authorizes exactly one call. |
| MPT-003 | Reusing the capability is denied. |
| MPT-004 | Changing agent, target, action, or purpose is denied. |
| MPT-005 | A capability from an untrusted issuer is denied. |
| MPT-006 | A capability is denied at its exact expiry. |
| MPT-007 | Exactly one of 64 concurrent consumers wins. |
| MPT-008 | Persistent replay state survives a gate restart. |
| MPT-009 | Trusted receipts verify; tampered and untrusted receipts do not. |
| MPT-010 | Physical constraints fail closed: within limit ALLOW; over limit and missing evidence DENY. |
| MPT-011 | Scoped attenuation narrows and is parent-verified; replay, widening, and wrong parent DENY. |
| MPT-012 | Cross-agent delegation binds the delegate request; the principal agent is DENIED. |
| MPT-013 | Approval tiers propagate from policy decision through capability to signed receipt. |
| MPT-014 | Forbidden combinations deny matching requests after a dangerous set is observed. |
| MPT-015 | Receipt 1.0 records obligation satisfaction with a valid chain. |
| MPT-016 | Obligation compliance detects a suppressed audit-log commitment. |
| MPT-017 | Fleet revocation distribution applies a signed bundle to all gates. |
