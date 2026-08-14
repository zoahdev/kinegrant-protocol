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
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import content_id, digest
from .crypto import verify_envelope
from .models import PolicyRule, isoformat, parse_time, utc_now

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
    print(
        "usage: kinegrant-policy-bundle --verify <bundle.json> --authorities <ids.json> "
        "[--policy-id <id>] | --activate <bundle.json> --authorities <ids.json> "
        "[--registry <state.json>] [--out <state.json>] | "
        "--current <state.json> --policy-id <id> | --self-test",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
