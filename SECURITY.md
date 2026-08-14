# Security policy

KineGrant is an experimental protocol and reference implementation. It has not
received an independent security audit and must not be the sole safety control
for real machinery.

## Reporting a vulnerability

Please do not publish an exploitable vulnerability before maintainers have had
a reasonable opportunity to assess it. Until a dedicated security mailbox is
listed at <https://kinegrant.com>, open a GitHub Security Advisory for this
repository. Include:

- the affected version and component;
- the security property that fails;
- a minimal reproducer or test case;
- likely physical and privacy impact;
- any proposed mitigation.

Do not include private keys, personal data, or access to real devices. Reports
about bypassing the action gate, signature validation, request binding, replay
protection, revocation, adapter fail-open behavior, or receipt integrity receive
the highest priority.

## Supported versions

Security fixes land on the default branch first and are backported to the
current stable release when the change is small and safe to backport.

- The latest stable `1.x` release is the supported stable line (currently
  **v1.0.0**).
- The default branch is always supported.
- `0.x` releases are experimental drafts and are **not** supported. They may
  change or break without notice and must not be used as the sole safety
  control for real machinery.
