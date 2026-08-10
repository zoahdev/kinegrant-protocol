from __future__ import annotations

from fnmatch import fnmatchcase
from datetime import datetime, timedelta
from typing import Any, Iterable

from .canonical import digest
from .models import ActionRequest, Decision, PolicyRule, parse_time, utc_now

SUPPORTED_CONSTRAINTS = {
    "not_before",
    "not_after",
    "required_context",
    "requires_human_present",
    "max_risk_tier",
}


def _matches(patterns: tuple[str, ...], value: str) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _validate_rule(rule: PolicyRule) -> None:
    unknown = set(rule.constraints) - SUPPORTED_CONSTRAINTS
    if unknown:
        raise ValueError(f"unsupported policy constraints: {', '.join(sorted(unknown))}")
    if "required_context" in rule.constraints and not isinstance(
        rule.constraints["required_context"], dict
    ):
        raise ValueError("required_context must be an object")


def _constraints_hold(rule: PolicyRule, request: ActionRequest, now: datetime) -> bool:
    constraints = rule.constraints
    if "not_before" in constraints and now < parse_time(constraints["not_before"]):
        return False
    if "not_after" in constraints and now >= parse_time(constraints["not_after"]):
        return False

    required = constraints.get("required_context", {})
    if not isinstance(required, dict):
        return False
    for key, expected in required.items():
        actual = request.context.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False

    if constraints.get("requires_human_present") is True:
        if request.context.get("human_present") is not True:
            return False

    max_risk = constraints.get("max_risk_tier")
    if max_risk is not None:
        actual_risk = request.context.get("risk_tier")
        if not isinstance(actual_risk, int) or actual_risk > int(max_risk):
            return False
    return True


class PolicyEngine:
    """Deterministic, default-deny policy evaluator with deny-overrides semantics."""

    def __init__(
        self,
        rules: Iterable[PolicyRule] = (),
        *,
        trusted_policy_issuers: set[str] | None = None,
        request_max_age_seconds: int = 300,
        clock_skew_seconds: int = 5,
    ) -> None:
        self._rules = list(rules)
        for rule in self._rules:
            _validate_rule(rule)
        policy_ids = [rule.policy_id for rule in self._rules]
        if len(policy_ids) != len(set(policy_ids)):
            raise ValueError("policy_id values must be unique within a policy snapshot")
        self.trusted_policy_issuers = set(trusted_policy_issuers or ())
        if request_max_age_seconds < 1 or clock_skew_seconds < 0:
            raise ValueError("invalid request freshness settings")
        self.request_max_age = timedelta(seconds=request_max_age_seconds)
        self.clock_skew = timedelta(seconds=clock_skew_seconds)

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return tuple(self._rules)

    def add(self, *rules: PolicyRule) -> None:
        for rule in rules:
            _validate_rule(rule)
        existing = {rule.policy_id for rule in self._rules}
        incoming = [rule.policy_id for rule in rules]
        if existing.intersection(incoming) or len(incoming) != len(set(incoming)):
            raise ValueError("policy_id values must be unique within a policy snapshot")
        self._rules.extend(rules)

    def _policy_digest(self) -> str:
        snapshot = {
            "rules": [rule.to_dict() for rule in sorted(self._rules, key=lambda item: item.policy_id)],
            "trusted_policy_issuers": sorted(self.trusted_policy_issuers),
        }
        return digest(snapshot)

    def evaluate(self, request: ActionRequest, *, now: datetime | None = None) -> Decision:
        current = now or utc_now()
        if current.tzinfo is None:
            raise ValueError("policy evaluation time must include a timezone")
        current = current.astimezone(request.issued_at.tzinfo)
        policy_digest = self._policy_digest()
        if request.issued_at > current + self.clock_skew:
            return Decision(False, "future_request", request.digest, policy_digest)
        if current - request.issued_at > self.request_max_age:
            return Decision(False, "stale_request", request.digest, policy_digest)

        applicable: list[PolicyRule] = []
        for rule in self._rules:
            # Unauthenticated sources may restrict but never grant authority.
            if rule.effect == "allow" and rule.issuer not in self.trusted_policy_issuers:
                continue
            if not fnmatchcase(request.target, rule.target):
                continue
            if not _matches(rule.actions, request.action):
                continue
            if not _matches(rule.subjects, request.agent):
                continue
            if not _matches(rule.purposes, request.purpose):
                continue
            if not _constraints_hold(rule, request, current):
                continue
            applicable.append(rule)

        applicable.sort(key=lambda item: (-item.priority, item.policy_id))
        matched = tuple(rule.policy_id for rule in applicable)

        denies = [rule for rule in applicable if rule.effect == "deny"]
        if denies:
            return Decision(
                allowed=False,
                reason="explicit_deny",
                request_digest=request.digest,
                policy_digest=policy_digest,
                matched_policy_ids=matched,
            )

        allows = [rule for rule in applicable if rule.effect == "allow"]
        if not allows:
            return Decision(
                allowed=False,
                reason="default_deny",
                request_digest=request.digest,
                policy_digest=policy_digest,
                matched_policy_ids=matched,
            )

        obligations = tuple(sorted({item for rule in allows for item in rule.obligations}))
        return Decision(
            allowed=True,
            reason="explicit_allow",
            request_digest=request.digest,
            policy_digest=policy_digest,
            matched_policy_ids=matched,
            obligations=obligations,
        )
