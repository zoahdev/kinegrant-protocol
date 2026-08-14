# Red-Team Corpus (v0.5)

`kinegrant-red-team` runs ten executable adversarial probes against the
reference implementation:

| ID | Category | Attack |
| --- | --- | --- |
| RT-001 | replay | Consumed capability cannot be replayed |
| RT-002 | mutation | Modified request binding is rejected |
| RT-003 | confused-deputy | Wrong agent cannot act |
| RT-004 | conflict | Deny overrides allow |
| RT-005 | downgrade | Unknown capability version is rejected |
| RT-006 | clock | Expired capability is rejected |
| RT-007 | revocation | Revoked capability is rejected |
| RT-008 | delegation | Delegate outside allowlist is rejected |
| RT-009 | adapter | Unknown ODRL constraint fails closed |
| RT-010 | sequence | Forbidden combination is denied |

Every probe records expected vs. observed behavior; the suite prints a
machine-readable report and exits nonzero on any failure. The corpus is
intended to grow with third-party review findings.
