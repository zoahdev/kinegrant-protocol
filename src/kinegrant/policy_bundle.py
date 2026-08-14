"""Signed, versioned policy bundles for trustworthy policy distribution (v2.0).

A policy bundle lets a trusted authority publish, replace, and revoke policy
documents without a central ledger. Each bundle is a signed envelope whose
payload names the policy, a positive version, a validity window, and the
canonical rules. Verifiers accept a bundle only when:

- the envelope signature is valid;
- the signer key id is in the caller's trusted authorities;
- the payload is the expected policy (when supplied);
- the current time is inside ``[not_before, not_after)``;
- the signed rules digest matches the canonical digest of the rules.

``PolicyRegistry`` keeps the activated bundles per policy and answers "which
version is current" using highest-version-wins among non-revoked bundles whose
validity window covers the current time. ``PolicyAuthority`` is the reference
signer helper that increments versions and links each release to the previous
version's digest.

The module deliberately does not assume a distribution channel: deployments
choose their own authenticated transport (device update, registry, signed
file), and every consumer verifies the bundle itself.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from datetime import timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import content_id, digest
from .crypto import verify_envelope
from .models import PolicyRule, isoformat, parse_time, utc_now
from .policy import PolicyEngine

_BUNDLE_TYPE = "kinegrant:PolicyBundle"
_SCHEMA_VERSION = "0.1"
_STATE_TYPE = "kinegrant:PolicyRegistryState"
_STATE_VERSION = "0.1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _rules_digest(rules: Any) -> str:
    return digest({"rules": rules})


def _rule_from_dict(value: Mapping[str, Any]) -> PolicyRule:
    if not isinstance(value, Mapping):
        raise ValueError("each policy rule must be an object")
    try:
        return PolicyRule(
            policy_id=value["policy_id"],
            issuer=value["issuer"],
            target=value["target"],
            effect=value["effect"],
            actions=tuple(value["actions"]),
            subjects=tuple(value.get("subjects", ("*",))),
            purposes=tuple(value.get("purposes", ("*",))),
            constraints=dict(value.get("constraints", {})),
            obligations=tuple(value.get("obligations", ())),
            priority=value.get("priority", 0),
            source=dict(value.get("source", {})),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid policy rule: {exc}") from exc


def _validate_window(not_before: datetime, not_after: datetime) -> None:
    if not_before.tzinfo is None or not_after.tzinfo is None:
        raise ValueError("policy bundle times must include a timezone")
    if not_after <= not_before:
        raise ValueError("not_after must be after not_before")


def build_policy_bundle(
    policy_id: str,
    rules: Iterable[PolicyRule],
    *,
    issuer: str,
    version: int = 1,
    previous_version_digest: str | None = None,
    issued_at: datetime | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> dict[str, Any]:
    """Build an unsigned policy bundle body with a content-addressed id."""
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise ValueError("policy_id must be a non-empty string")
    if not isinstance(issuer, str) or not issuer.strip():
        raise ValueError("issuer must be a non-empty string")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("bundle version must be a positive integer")
    if previous_version_digest is not None and _SHA256_RE.fullmatch(
        previous_version_digest
    ) is None:
        raise ValueError("previous_version_digest must be a sha256 digest or None")
    rule_values = [rule.to_dict() for rule in rules]
    if not rule_values:
        raise ValueError("a policy bundle must contain at least one rule")
    now = issued_at or utc_now()
    lower = not_before or now
    upper = not_after
    if upper is None:
        raise ValueError("not_after is required")
    _validate_window(lower, upper)
    body = {
        "type": _BUNDLE_TYPE,
        "schema_version": _SCHEMA_VERSION,
        "policy_id": policy_id,
        "issuer": issuer,
        "version": version,
        "previous_version_digest": previous_version_digest,
        "issued_at": isoformat(now),
        "not_before": isoformat(lower),
        "not_after": isoformat(upper),
        "rules": rule_values,
    }
    body["policy_digest"] = _rules_digest(rule_values)
    body["bundle_id"] = content_id(
        "kinegrant:policy-bundle",
        {key: value for key, value in body.items() if key != "bundle_id"},
    )
    return body


def sign_policy_bundle(body: dict[str, Any], key_pair: Any) -> dict[str, Any]:
    """Sign a policy bundle body with any KineGrant envelope key pair."""
    if not isinstance(body, Mapping) or body.get("type") != _BUNDLE_TYPE:
        raise ValueError("not a policy bundle body")
    return key_pair.sign_envelope(body)


def verify_policy_bundle(
    envelope: Mapping[str, Any],
    *,
    trusted_authorities: set[str] | None = None,
    expected_policy_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a signed policy bundle and return its payload (fail-closed)."""
    payload = verify_envelope(envelope)
    if payload.get("type") != _BUNDLE_TYPE:
        raise ValueError("wrong policy bundle type")
    if payload.get("schema_version") != _SCHEMA_VERSION:
        raise ValueError("unsupported policy bundle version")
    if trusted_authorities is not None and payload.get("issuer") not in trusted_authorities:
        raise ValueError("untrusted policy authority")
    if payload.get("issuer") != envelope.get("kid"):
        raise ValueError("policy bundle issuer does not match signing key")
    policy_id = payload.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise ValueError("policy_id must be a non-empty string")
    if expected_policy_id is not None and policy_id != expected_policy_id:
        raise ValueError("policy bundle is for a different policy")
    version = payload.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("bundle version must be a positive integer")
    previous = payload.get("previous_version_digest")
    if previous is not None and _SHA256_RE.fullmatch(previous) is None:
        raise ValueError("previous_version_digest must be a sha256 digest or None")
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("a policy bundle must contain at least one rule")
    if payload.get("policy_digest") != _rules_digest(rules):
        raise ValueError("policy rules do not match the signed digest")
    for rule in rules:
        _rule_from_dict(rule)
    now_value = now or utc_now()
    if now_value.tzinfo is None:
        raise ValueError("verification time must include a timezone")
    lower = parse_time(payload["not_before"])
    upper = parse_time(payload["not_after"])
    _validate_window(lower, upper)
    if now_value < lower or now_value >= upper:
        raise ValueError("policy bundle is outside its validity window")
    return payload


def rules_from_bundle(
    envelope: Mapping[str, Any],
    *,
    trusted_authorities: set[str] | None = None,
    expected_policy_id: str | None = None,
    now: datetime | None = None,
) -> tuple[PolicyRule, ...]:
    """Verify a bundle and parse its rules for a PolicyEngine."""
    payload = verify_policy_bundle(
        envelope,
        trusted_authorities=trusted_authorities,
        expected_policy_id=expected_policy_id,
        now=now,
    )
    return tuple(_rule_from_dict(rule) for rule in payload["rules"])


def bundle_to_odrl(
    bundle: Mapping[str, Any],
    *,
    trusted_authorities: set[str] | None = None,
    expected_policy_id: str | None = None,
    now: datetime | None = None,
    policy_uid: str | None = None,
    assigner: str | None = None,
) -> dict[str, Any]:
    """Verify a signed policy bundle and serialize its rules as ODRL.

    The output uses the versioned ``kgp-v0.2`` profile, so the resulting
    document can be parsed back with ``kinegrant.adapters.odrl.odrl_to_rules``
    as a faithful round trip. Verification is fail-closed: nothing is mapped
    unless the bundle passes signature, authority, time-window, and digest
    checks.
    """
    payload = verify_policy_bundle(
        bundle,
        trusted_authorities=trusted_authorities,
        expected_policy_id=expected_policy_id,
        now=now,
    )
    rules = rules_from_bundle(
        bundle,
        trusted_authorities=trusted_authorities,
        expected_policy_id=expected_policy_id,
        now=now,
    )
    from .adapters.odrl import rules_to_odrl

    return rules_to_odrl(
        rules,
        policy_uid=policy_uid or payload["policy_id"],
        assigner=assigner or payload["issuer"],
    )


def _pattern_overlaps(pattern_a: str, pattern_b: str) -> bool:
    if pattern_a == "*" or pattern_b == "*" or pattern_a == pattern_b:
        return True
    if "*" not in pattern_a and "*" not in pattern_b:
        return False
    return fnmatchcase(pattern_a, pattern_b) or fnmatchcase(pattern_b, pattern_a)


def _tuple_overlaps(tuple_a: tuple[str, ...], tuple_b: tuple[str, ...]) -> bool:
    if "*" in tuple_a or "*" in tuple_b:
        return True
    return bool(set(tuple_a).intersection(tuple_b))


def _scope_overlaps(rule_a: PolicyRule, rule_b: PolicyRule) -> bool:
    return (
        _pattern_overlaps(rule_a.target, rule_b.target)
        and _tuple_overlaps(rule_a.actions, rule_b.actions)
        and _tuple_overlaps(rule_a.purposes, rule_b.purposes)
    )


def analyze_policy_bundle(
    bundle: Mapping[str, Any],
    *,
    trusted_authorities: set[str] | None = None,
    expected_policy_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Analyze a verified signed policy bundle for audit-relevant findings.

    The bundle must pass signature, authority, time-window, and digest checks
    (fail-closed). Findings are conservative: any scope overlap between an
    allow and a deny rule is reported as a conflict, duplicate rules are
    reported, unknown constraints and obligations are reported, and rules
    whose issuer differs from the bundle signer are errors.
    """
    payload = verify_policy_bundle(
        bundle,
        trusted_authorities=trusted_authorities,
        expected_policy_id=expected_policy_id,
        now=now,
    )
    rules = rules_from_bundle(
        bundle,
        trusted_authorities=trusted_authorities,
        expected_policy_id=expected_policy_id,
        now=now,
    )
    findings: list[dict[str, Any]] = []

    for rule in rules:
        if rule.issuer != payload["issuer"]:
            findings.append(
                {
                    "severity": "error",
                    "code": "rule_issuer_mismatch",
                    "rule_ids": [rule.policy_id],
                    "message": (
                        f"rule issuer {rule.issuer} differs from the bundle "
                        f"signer {payload['issuer']}"
                    ),
                }
            )
        unknown_constraints = set(rule.constraints) - {
            "not_before",
            "not_after",
            "required_context",
            "requires_human_present",
            "max_risk_tier",
            "max_force_newtons",
            "max_velocity_mps",
            "allowed_zones",
            "min_approval_tier",
        }
        if unknown_constraints:
            findings.append(
                {
                    "severity": "error",
                    "code": "unknown_constraint",
                    "rule_ids": [rule.policy_id],
                    "message": (
                        "unsupported policy constraints: "
                        + ", ".join(sorted(unknown_constraints))
                    ),
                }
            )
        from .obligations import KNOWN_OBLIGATIONS

        unknown_obligations = set(rule.obligations) - set(KNOWN_OBLIGATIONS)
        if unknown_obligations:
            findings.append(
                {
                    "severity": "error",
                    "code": "unknown_obligation",
                    "rule_ids": [rule.policy_id],
                    "message": (
                        "unsupported policy obligations: "
                        + ", ".join(sorted(unknown_obligations))
                    ),
                }
            )
        if (
            rule.effect == "allow"
            and rule.target == "*"
            and rule.actions == ("*",)
            and rule.purposes == ("*",)
            and not rule.constraints
        ):
            findings.append(
                {
                    "severity": "warning",
                    "code": "broad_allow",
                    "rule_ids": [rule.policy_id],
                    "message": "unconditional allow rule covering all targets",
                }
            )

    for index_a in range(len(rules)):
        for index_b in range(index_a + 1, len(rules)):
            rule_a = rules[index_a]
            rule_b = rules[index_b]
            if not _scope_overlaps(rule_a, rule_b):
                continue
            if rule_a.effect != rule_b.effect:
                findings.append(
                    {
                        "severity": "error",
                        "code": "conflicting_effect",
                        "rule_ids": [rule_a.policy_id, rule_b.policy_id],
                        "message": (
                            f"overlapping {rule_a.effect} and {rule_b.effect} "
                            "rules; deny-overrides semantics apply"
                        ),
                    }
                )
            elif (
                rule_a.to_dict() == rule_b.to_dict()
            ):
                findings.append(
                    {
                        "severity": "warning",
                        "code": "duplicate_rule",
                        "rule_ids": [rule_a.policy_id, rule_b.policy_id],
                        "message": "duplicate rules with identical content",
                    }
                )

    errors = sum(1 for finding in findings if finding["severity"] == "error")
    warnings = sum(1 for finding in findings if finding["severity"] == "warning")
    info = sum(1 for finding in findings if finding["severity"] == "info")
    return {
        "type": "kinegrant:PolicyBundleAnalysis",
        "schema_version": "0.1",
        "policy_id": payload["policy_id"],
        "bundle_id": payload["bundle_id"],
        "bundle_version": payload["version"],
        "overall_result": "PASS" if errors == 0 else "FAIL",
        "summary": {
            "findings": len(findings),
            "errors": errors,
            "warnings": warnings,
            "info": info,
        },
        "findings": findings,
    }


def policy_bundle_coverage(
    bundle: Mapping[str, Any],
    *,
    trusted_authorities: set[str] | None = None,
    expected_policy_id: str | None = None,
    now: datetime | None = None,
    agents: Iterable[str] = ("urn:kinegrant:coverage:agent:1",),
    targets: Iterable[str] = ("urn:kinegrant:coverage:target:1",),
    actions: Iterable[str] = ("open",),
    purposes: Iterable[str] = ("delivery",),
    max_requests: int = 200,
) -> dict[str, Any]:
    """Run a bounded request-space coverage check over a verified bundle.

    The bundle must pass signature, authority, time-window, and digest checks
    (fail-closed). The policy engine evaluates the Cartesian request space and
    the report records allowed/denied/exceptions, per-rule applicability, and
    allow rules that never win (shadowed by deny-overrides).
    """
    payload = verify_policy_bundle(
        bundle,
        trusted_authorities=trusted_authorities,
        expected_policy_id=expected_policy_id,
        now=now,
    )
    rules = rules_from_bundle(
        bundle,
        trusted_authorities=trusted_authorities,
        expected_policy_id=expected_policy_id,
        now=now,
    )
    engine = PolicyEngine(rules, trusted_policy_issuers={payload["issuer"]})
    from .modelcheck import bounded_model_check

    check = bounded_model_check(
        engine,
        agents=agents,
        targets=targets,
        actions=actions,
        purposes=purposes,
        max_requests=max_requests,
    )
    return {
        "type": "kinegrant:PolicyBundleCoverage",
        "schema_version": "0.1",
        "policy_id": payload["policy_id"],
        "bundle_id": payload["bundle_id"],
        "bundle_version": payload["version"],
        "overall_result": check["overall_result"],
        "summary": {
            "space_size": check["space_size"],
            "evaluated": check["evaluated"],
            "allowed": check["allowed"],
            "denied": check["denied"],
            "exceptions": check["exceptions"],
            "shadowed_allows": len(check["shadowed_allows"]),
        },
        "shadowed_allows": check["shadowed_allows"],
        "rule_stats": check["rules"],
    }


@dataclass(frozen=True)
class PolicyRevocation:
    policy_id: str
    version: int
    reason: str | None
    at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "reason": self.reason,
            "at": isoformat(self.at),
        }


class PolicyRegistry:
    """Local registry of activated policy bundles with per-version revocation."""

    def __init__(self, *, trusted_authorities: set[str] | None = None) -> None:
        self.trusted_authorities = set(trusted_authorities or ())
        self._bundles: dict[tuple[str, int], dict[str, Any]] = {}
        self._revocations: dict[tuple[str, int], PolicyRevocation] = {}

    def activate(
        self,
        envelope: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Verify and store one bundle (same version must not change rules)."""
        payload = verify_policy_bundle(
            envelope,
            trusted_authorities=self.trusted_authorities or None,
            now=now,
        )
        key = (payload["policy_id"], payload["version"])
        existing = self._bundles.get(key)
        if existing is not None and existing != payload:
            raise ValueError("a different bundle is already active for this version")
        self._bundles[key] = payload
        return payload

    def current(
        self,
        policy_id: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Return the highest non-revoked in-window version, or None (fail-closed)."""
        now_value = now or utc_now()
        candidates = []
        for (pid, version), payload in self._bundles.items():
            if pid != policy_id:
                continue
            if (pid, version) in self._revocations:
                continue
            lower = parse_time(payload["not_before"])
            upper = parse_time(payload["not_after"])
            if now_value < lower or now_value >= upper:
                continue
            candidates.append((version, payload))
        if not candidates:
            return None
        return max(candidates, key=lambda item: item[0])[1]

    def revoke(
        self,
        policy_id: str,
        version: int,
        *,
        reason: str | None = None,
        at: datetime | None = None,
    ) -> PolicyRevocation:
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise ValueError("policy_id must be a non-empty string")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValueError("version must be a positive integer")
        record = PolicyRevocation(
            policy_id,
            version,
            reason,
            at or utc_now(),
        )
        self._revocations[(policy_id, version)] = record
        return record

    def is_revoked(self, policy_id: str, version: int) -> bool:
        return (policy_id, version) in self._revocations

    def versions(self, policy_id: str) -> tuple[int, ...]:
        return tuple(
            sorted(
                version
                for (pid, version) in self._bundles
                if pid == policy_id
            )
        )

    def to_dict(self) -> dict[str, Any]:
        bundles: dict[str, dict[str, dict[str, Any]]] = {}
        for (pid, version), payload in self._bundles.items():
            bundles.setdefault(pid, {})[str(version)] = payload
        revocations: dict[str, dict[str, dict[str, Any]]] = {}
        for (pid, version), record in self._revocations.items():
            revocations.setdefault(pid, {})[str(version)] = record.to_dict()
        return {
            "type": _STATE_TYPE,
            "schema_version": _STATE_VERSION,
            "bundles": bundles,
            "revocations": revocations,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        trusted_authorities: set[str] | None = None,
    ) -> "PolicyRegistry":
        if value.get("type") != _STATE_TYPE:
            raise ValueError("wrong registry state type")
        if value.get("schema_version") != _STATE_VERSION:
            raise ValueError("unsupported registry state version")
        registry = cls(trusted_authorities=trusted_authorities)
        for pid, versions in value.get("bundles", {}).items():
            for version_text, payload in versions.items():
                version = int(version_text)
                registry._bundles[(pid, version)] = dict(payload)
        for pid, versions in value.get("revocations", {}).items():
            for version_text, record in versions.items():
                version = int(version_text)
                registry._revocations[(pid, version)] = PolicyRevocation(
                    policy_id=record["policy_id"],
                    version=record["version"],
                    reason=record.get("reason"),
                    at=parse_time(record["at"]),
                )
        return registry


class PolicyAuthority:
    """Reference signer that publishes monotonic, linked policy versions."""

    def __init__(self, key_pair: Any) -> None:
        self.key_pair = key_pair
        self._last: dict[str, dict[str, Any]] = {}

    @property
    def kid(self) -> str:
        return self.key_pair.kid

    def publish(
        self,
        policy_id: str,
        rules: Iterable[PolicyRule],
        *,
        version: int | None = None,
        previous_version_digest: str | None = None,
        issued_at: datetime | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Sign a new version; defaults to the next version after the last one."""
        last = self._last.get(policy_id)
        if version is None:
            version = (last["version"] + 1) if last is not None else 1
        if previous_version_digest is None and last is not None:
            previous_version_digest = last["policy_digest"]
        now = issued_at or utc_now()
        if not_after is None:
            if ttl_seconds is None:
                raise ValueError("not_after or ttl_seconds is required")
            not_after = (not_before or now) + timedelta(seconds=ttl_seconds)
        body = build_policy_bundle(
            policy_id,
            rules,
            issuer=self.kid,
            version=version,
            previous_version_digest=previous_version_digest,
            issued_at=now,
            not_before=not_before,
            not_after=not_after,
        )
        envelope = sign_policy_bundle(body, self.key_pair)
        self._last[policy_id] = body
        return envelope

    def revoke_latest(
        self,
        registry: PolicyRegistry,
        policy_id: str,
        *,
        reason: str | None = None,
    ) -> PolicyRevocation:
        last = self._last.get(policy_id)
        if last is None:
            raise ValueError("no published version to revoke")
        return registry.revoke(policy_id, last["version"], reason=reason)


@dataclass(frozen=True)
class GatePolicyAck:
    gate_id: str
    policy_id: str
    bundle_id: str
    applied: bool
    current_before: int | None
    current_after: int | None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "policy_id": self.policy_id,
            "bundle_id": self.bundle_id,
            "applied": self.applied,
            "current_before": self.current_before,
            "current_after": self.current_after,
            "detail": self.detail,
        }


class PolicyDistributor:
    """Verify one signed policy bundle and apply it to many registries.

    Distribution is fail-closed: the bundle must verify under the caller's
    trusted authorities before any registry is touched. A registry already
    running a version at least as new is left untouched (idempotent no-op);
    downgrades are never applied automatically.
    """

    def __init__(
        self,
        *,
        trusted_authorities: set[str] | None = None,
    ) -> None:
        self.trusted_authorities = set(trusted_authorities or ())

    def distribute(
        self,
        bundle: Mapping[str, Any],
        registries: Mapping[str, PolicyRegistry],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        payload = verify_policy_bundle(
            bundle,
            trusted_authorities=self.trusted_authorities or None,
            now=now,
        )
        policy_id = payload["policy_id"]
        version = payload["version"]
        bundle_id = payload["bundle_id"]
        acks: list[GatePolicyAck] = []
        for gate_id in sorted(registries):
            registry = registries[gate_id]
            current = registry.current(policy_id, now=now)
            current_version = current["version"] if current is not None else None
            if current_version is not None and current_version >= version:
                acks.append(
                    GatePolicyAck(
                        gate_id=gate_id,
                        policy_id=policy_id,
                        bundle_id=bundle_id,
                        applied=False,
                        current_before=current_version,
                        current_after=current_version,
                        detail="already at a current version",
                    )
                )
                continue
            registry.activate(bundle, now=now)
            after = registry.current(policy_id, now=now)
            acks.append(
                GatePolicyAck(
                    gate_id=gate_id,
                    policy_id=policy_id,
                    bundle_id=bundle_id,
                    applied=True,
                    current_before=current_version,
                    current_after=after["version"] if after is not None else None,
                    detail="policy bundle activated",
                )
            )
        return {
            "type": "kinegrant:PolicyDistributionReport",
            "schema_version": "0.1",
            "policy_id": policy_id,
            "bundle_id": bundle_id,
            "bundle_version": version,
            "overall_result": "PASS",
            "summary": {
                "registries": len(acks),
                "applied_total": sum(ack.applied for ack in acks),
                "already_present_total": sum(not ack.applied for ack in acks),
            },
            "acks": [ack.to_dict() for ack in acks],
        }


def verify_policy_distribution_report(
    report: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    trusted_authorities: set[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a fleet report against its bundle (fail-closed)."""
    if not isinstance(report, Mapping):
        raise ValueError("policy distribution report must be an object")
    if report.get("type") != "kinegrant:PolicyDistributionReport":
        raise ValueError("wrong policy distribution report type")
    if report.get("schema_version") != "0.1":
        raise ValueError("unsupported policy distribution report version")
    if report.get("overall_result") != "PASS":
        raise ValueError("policy distribution report is not PASS")
    payload = verify_policy_bundle(
        bundle,
        trusted_authorities=trusted_authorities,
        now=now,
    )
    policy_id = payload["policy_id"]
    version = payload["version"]
    bundle_id = payload["bundle_id"]
    if report.get("policy_id") != policy_id:
        raise ValueError("policy distribution report references a different policy")
    if report.get("bundle_id") != bundle_id:
        raise ValueError("policy distribution report references a different bundle")
    if report.get("bundle_version") != version:
        raise ValueError("policy distribution report references a different version")
    acks = report.get("acks")
    if not isinstance(acks, list) or not acks:
        raise ValueError("policy distribution report has no acknowledgements")
    for ack in acks:
        if not isinstance(ack, Mapping):
            raise ValueError("each acknowledgement must be an object")
        if not isinstance(ack.get("gate_id"), str) or not ack["gate_id"]:
            raise ValueError("acknowledgement gate_id is invalid")
        if ack.get("policy_id") != policy_id or ack.get("bundle_id") != bundle_id:
            raise ValueError("acknowledgement references a different bundle")
        if not isinstance(ack.get("applied"), bool):
            raise ValueError("acknowledgement applied flag is invalid")
    summary = report.get("summary")
    if not isinstance(summary, Mapping):
        raise ValueError("policy distribution report summary is invalid")
    if summary.get("registries") != len(acks):
        raise ValueError("policy distribution report summary is inconsistent")
    if summary.get("applied_total") != sum(ack["applied"] for ack in acks):
        raise ValueError("policy distribution report summary is inconsistent")
    if summary.get("already_present_total") != sum(
        not ack["applied"] for ack in acks
    ):
        raise ValueError("policy distribution report summary is inconsistent")
    return report


def _self_test() -> int:
    from .crypto import Ed25519KeyPair

    authority = PolicyAuthority(Ed25519KeyPair.generate())
    policy_id = "urn:kinegrant:policy:test:door"
    rules_v1 = [
        PolicyRule(
            policy_id,
            authority.kid,
            "urn:space:test:door-1",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
    ]
    v1 = authority.publish(policy_id, rules_v1, ttl_seconds=3600)
    registry = PolicyRegistry(trusted_authorities={authority.kid})
    registry.activate(v1)
    rules_v2 = [
        PolicyRule(
            policy_id,
            authority.kid,
            "urn:space:test:door-1",
            "allow",
            ("open",),
            purposes=("delivery", "maintenance"),
        )
    ]
    v2 = authority.publish(policy_id, rules_v2, ttl_seconds=3600)
    registry.activate(v2)
    checks = [
        registry.current(policy_id) is not None
        and registry.current(policy_id)["version"] == 2,
        verify_policy_bundle(
            v2,
            trusted_authorities={authority.kid},
            expected_policy_id=policy_id,
        )["version"] == 2,
    ]
    registry.revoke(policy_id, 2, reason="replaced by emergency rule")
    checks.append(
        registry.current(policy_id) is not None
        and registry.current(policy_id)["version"] == 1
    )
    tampered = dict(v2)
    tampered["payload"] = dict(v2["payload"])
    tampered["payload"]["rules"] = []
    try:
        verify_policy_bundle(tampered, trusted_authorities={authority.kid})
        checks.append(False)
    except ValueError:
        checks.append(True)
    outsider = PolicyAuthority(Ed25519KeyPair.generate())
    try:
        verify_policy_bundle(v2, trusted_authorities={outsider.kid})
        checks.append(False)
    except ValueError:
        checks.append(True)
    fleet_a = PolicyRegistry(trusted_authorities={authority.kid})
    fleet_b = PolicyRegistry(trusted_authorities={authority.kid})
    fleet_report = PolicyDistributor(
        trusted_authorities={authority.kid}
    ).distribute(
        v1,
        {"gate-a": fleet_a, "gate-b": fleet_b},
    )
    checks.append(
        fleet_report["overall_result"] == "PASS"
        and fleet_report["summary"]["applied_total"] == 2
        and fleet_a.current(policy_id)["version"] == 1
        and fleet_b.current(policy_id)["version"] == 1
    )
    verify_policy_distribution_report(
        fleet_report,
        v1,
        trusted_authorities={authority.kid},
    )
    upgrade = PolicyDistributor(
        trusted_authorities={authority.kid}
    ).distribute(
        v2,
        {"gate-a": fleet_a, "gate-b": fleet_b},
    )
    checks.append(upgrade["summary"]["applied_total"] == 2)
    noop = PolicyDistributor(
        trusted_authorities={authority.kid}
    ).distribute(
        v1,
        {"gate-a": fleet_a},
    )
    checks.append(noop["summary"]["already_present_total"] == 1)
    analysis = analyze_policy_bundle(
        v2,
        trusted_authorities={authority.kid},
    )
    checks.append(analysis["overall_result"] == "PASS")
    coverage = policy_bundle_coverage(
        v2,
        trusted_authorities={authority.kid},
    )
    checks.append(coverage["overall_result"] == "PASS")
    return 0 if all(checks) else 1


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if "--self-test" in args:
        return _self_test()
    if "--verify" in args:
        bundle_path = args[args.index("--verify") + 1]
        authorities_path = args[args.index("--authorities") + 1]
        expected_policy_id = None
        if "--policy-id" in args:
            expected_policy_id = args[args.index("--policy-id") + 1]
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        authorities = json.loads(Path(authorities_path).read_text(encoding="utf-8"))
        payload = verify_policy_bundle(
            bundle,
            trusted_authorities=set(authorities),
            expected_policy_id=expected_policy_id,
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if "--activate" in args:
        bundle_path = args[args.index("--activate") + 1]
        authorities_path = args[args.index("--authorities") + 1]
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        authorities = json.loads(Path(authorities_path).read_text(encoding="utf-8"))
        registry = PolicyRegistry(trusted_authorities=set(authorities))
        if "--registry" in args:
            state_path = Path(args[args.index("--registry") + 1])
            if state_path.exists():
                registry = PolicyRegistry.from_dict(
                    json.loads(state_path.read_text(encoding="utf-8")),
                    trusted_authorities=set(authorities),
                )
        registry.activate(bundle)
        state = registry.to_dict()
        if "--out" in args:
            out_path = Path(args[args.index("--out") + 1])
            out_path.write_text(
                json.dumps(state, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    if "--current" in args:
        state_path = Path(args[args.index("--current") + 1])
        policy_id = args[args.index("--policy-id") + 1]
        registry = PolicyRegistry.from_dict(
            json.loads(state_path.read_text(encoding="utf-8"))
        )
        payload = registry.current(policy_id)
        if payload is None:
            print(json.dumps({"current": None}))
            return 1
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if "--distribute" in args:
        bundle_path = args[args.index("--distribute") + 1]
        authorities_path = args[args.index("--authorities") + 1]
        registries_path = args[args.index("--registries") + 1]
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        authorities = json.loads(Path(authorities_path).read_text(encoding="utf-8"))
        raw_states = json.loads(Path(registries_path).read_text(encoding="utf-8"))
        registries = {
            gate_id: PolicyRegistry.from_dict(
                state,
                trusted_authorities=set(authorities),
            )
            for gate_id, state in raw_states.items()
        }
        report = PolicyDistributor(
            trusted_authorities=set(authorities)
        ).distribute(bundle, registries)
        if "--out" in args:
            out_path = Path(args[args.index("--out") + 1])
            states = {
                gate_id: registry.to_dict()
                for gate_id, registry in registries.items()
            }
            out_path.write_text(
                json.dumps(states, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    if "--verify-report" in args:
        report_path = args[args.index("--verify-report") + 1]
        bundle_path = args[args.index("--bundle") + 1]
        authorities_path = args[args.index("--authorities") + 1]
        report_data = json.loads(Path(report_path).read_text(encoding="utf-8"))
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        authorities = json.loads(Path(authorities_path).read_text(encoding="utf-8"))
        verified = verify_policy_distribution_report(
            report_data,
            bundle,
            trusted_authorities=set(authorities),
        )
        print(json.dumps(verified, indent=2, sort_keys=True))
        return 0
    if "--analyze" in args:
        bundle_path = args[args.index("--analyze") + 1]
        authorities_path = args[args.index("--authorities") + 1]
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        authorities = json.loads(Path(authorities_path).read_text(encoding="utf-8"))
        report = analyze_policy_bundle(
            bundle,
            trusted_authorities=set(authorities),
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["overall_result"] == "PASS" else 1
    if "--coverage" in args:
        bundle_path = args[args.index("--coverage") + 1]
        authorities_path = args[args.index("--authorities") + 1]
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        authorities = json.loads(Path(authorities_path).read_text(encoding="utf-8"))
        kwargs: dict[str, Any] = {}
        for flag in ("agents", "targets", "actions", "purposes"):
            if f"--{flag}" in args:
                kwargs[flag] = tuple(
                    args[args.index(f"--{flag}") + 1].split(",")
                )
        if "--max-requests" in args:
            kwargs["max_requests"] = int(
                args[args.index("--max-requests") + 1]
            )
        report = policy_bundle_coverage(
            bundle,
            trusted_authorities=set(authorities),
            **kwargs,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["overall_result"] == "PASS" else 1
    print(
        "usage: kinegrant-policy-bundle --verify <bundle.json> --authorities <ids.json> "
        "[--policy-id <id>] | --activate <bundle.json> --authorities <ids.json> "
        "[--registry <state.json>] [--out <state.json>] | "
        "--current <state.json> --policy-id <id> | "
        "--distribute <bundle.json> --authorities <ids.json> --registries <states.json> "
        "[--out <states.json>] | "
        "--verify-report <report.json> --bundle <bundle.json> --authorities <ids.json> | "
        "--analyze <bundle.json> --authorities <ids.json> | "
        "--coverage <bundle.json> --authorities <ids.json> "
        "[--agents a,b] [--targets t] [--actions act] [--purposes p] "
        "[--max-requests N] | "
        "--self-test",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
