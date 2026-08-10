from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Iterable

from .models import ActionRequest, Decision, PolicyRule, parse_time


def _matches(patterns: tuple[str, ...], value: str) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _constraints_hold(rule: PolicyRule, request: ActionRequest) -> bool:
    constraints = rule.constraints
    if "not_before" in constraints and request.issued_at < parse_time(constraints["not_before"]):
        return False
    if "not_after" in constraints and request.issued_at > parse_time(constraints["not_after"]):
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

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        self._rules = list(rules)

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return tuple(self._rules)

    def add(self, *rules: PolicyRule) -> None:
        self._rules.extend(rules)

    def evaluate(self, request: ActionRequest) -> Decision:
        applicable: list[PolicyRule] = []
        for rule in self._rules:
            if not fnmatchcase(request.target, rule.target):
                continue
            if not _matches(rule.actions, request.action):
                continue
            if not _matches(rule.subjects, request.agent):
                continue
            if not _matches(rule.purposes, request.purpose):
                continue
            if not _constraints_hold(rule, request):
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
                matched_policy_ids=matched,
            )

        allows = [rule for rule in applicable if rule.effect == "allow"]
        if not allows:
            return Decision(
                allowed=False,
                reason="default_deny",
                request_digest=request.digest,
                matched_policy_ids=matched,
            )

        obligations = tuple(sorted({item for rule in allows for item in rule.obligations}))
        return Decision(
            allowed=True,
            reason="explicit_allow",
            request_digest=request.digest,
            matched_policy_ids=matched,
            obligations=obligations,
        )
