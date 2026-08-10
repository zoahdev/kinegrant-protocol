# KineGrant Machine Permission Test v0.1

This is a reproducible software test of the KGP-001 permission boundary. It checks that no action is authorized without a capability, a valid capability executes once, replay and request mutation fail, issuer and expiry checks fail closed, concurrent consumption has one winner, replay remains blocked after restart, and receipt tampering or an untrusted executor is rejected.

It does not prove functional safety or that a physical action happened.

## Run

```bash
python -m pip install -e '.[test]'
kinegrant-mpt --output machine-permission-test.evidence.json
python challenge/verify_evidence.py machine-permission-test.evidence.json
```

For publishable evidence, pass the exact tested Git commit with
`--source-commit`. Evidence always includes a SHA-256 digest of the runner and
the Python/runtime platform, even when no repository commit is available.

Success exits with status `0` and prints `"overall_result": "PASS"`. Any failed case exits nonzero while preserving machine-readable evidence.

The independent verifier checks the Draft 2020-12 Schema, all required case IDs,
unique IDs, summary counts, and overall PASS/FAIL consistency. The Schema is:

```text
spec/schemas/machine-permission-test-evidence.schema.json
```

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
