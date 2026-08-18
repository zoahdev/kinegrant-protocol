from __future__ import annotations

from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from typing import Iterable

from .canonical import digest
from .models import ActionRequest, Decision, PolicyRule, parse_time, utc_now
from .vocabulary import known_action, validate_actions

SUPPORTED_CONSTRAINTS = {
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


def _matches(patterns: tuple[str, ...], value: str) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _validate_rule(rule: PolicyRule, require_known_actions: bool = False) -> None:
    unknown = set(rule.constraints) - SUPPORTED_CONSTRAINTS
    if unknown:
        raise ValueError(f"unsupported policy constraints: {', '.join(sorted(unknown))}")
    if "required_context" in rule.constraints and not isinstance(
        rule.constraints["required_context"], dict
    ):
        raise ValueError("required_context must be an object")
    for name in ("max_force_newtons", "max_velocity_mps"):
        value = rule.constraints.get(name)
        if value is not None and (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or value < 0
        ):
            raise ValueError(f"{name} must be a non-negative number")
    allowed_zones = rule.constraints.get("allowed_zones")
    if allowed_zones is not None:
        if (
            not isinstance(allowed_zones, list)
            or not allowed_zones
            or any(not isinstance(item, str) or not item.strip() for item in allowed_zones)
        ):
            raise ValueError("allowed_zones must be a non-empty list of non-empty strings")
    min_approval = rule.constraints.get("min_approval_tier")
    if min_approval is not None and (
        not isinstance(min_approval, int)
        or isinstance(min_approval, bool)
        or not 0 <= min_approval <= 2
    ):
        raise ValueError("min_approval_tier must be an integer between 0 and 2")
    if require_known_actions:
        validate_actions(rule.actions, context=f"actions in policy rule {rule.policy_id}")


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

    # Physical constraints are fail-closed for both effects:
    # - an allow rule applies only when the request proves it is within bounds;
    # - a deny rule applies when the request is missing evidence or exceeds bounds.
    is_deny = rule.effect == "deny"
    saw_physical = False

    max_force = constraints.get("max_force_newtons")
    if max_force is not None:
        saw_physical = True
        declared = request.context.get("force_newtons")
        valid = isinstance(declared, (int, float)) and not isinstance(declared, bool)
        violated = not valid or declared > max_force
        if violated:
            if is_deny:
                return True
            return False

    max_velocity = constraints.get("max_velocity_mps")
    if max_velocity is not None:
        saw_physical = True
        declared = request.context.get("velocity_mps")
        valid = isinstance(declared, (int, float)) and not isinstance(declared, bool)
        violated = not valid or declared > max_velocity
        if violated:
            if is_deny:
                return True
            return False

    allowed_zones = constraints.get("allowed_zones")
    if allowed_zones is not None:
        saw_physical = True
        zone = request.context.get("zone")
        in_zone = isinstance(zone, str) and zone.strip() and any(
            fnmatchcase(zone, pattern) for pattern in allowed_zones
        )
        if is_deny:
            if in_zone:
                return True
        elif not in_zone:
            return False

    if is_deny and saw_physical:
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
        require_known_actions: bool = False,
    ) -> None:
        self._rules = list(rules)
        for rule in self._rules:
            _validate_rule(rule, require_known_actions)
        policy_ids = [rule.policy_id for rule in self._rules]
        if len(policy_ids) != len(set(policy_ids)):
            raise ValueError("policy_id values must be unique within a policy snapshot")
        self.trusted_policy_issuers = set(trusted_policy_issuers or ())
        self.require_known_actions = require_known_actions
        if request_max_age_seconds < 1 or clock_skew_seconds < 0:
            raise ValueError("invalid request freshness settings")
        self.request_max_age = timedelta(seconds=request_max_age_seconds)
        self.clock_skew = timedelta(seconds=clock_skew_seconds)

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return tuple(self._rules)

    def add(self, *rules: PolicyRule) -> None:
        for rule in rules:
            _validate_rule(rule, self.require_known_actions)
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
        if self.require_known_actions and not known_action(request.action):
            return Decision(False, "unknown_action", request.digest, policy_digest)
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
        approval_tier = max(
            rule.constraints.get("min_approval_tier", 0)
            for rule in allows
        )
        return Decision(
            allowed=True,
            reason="explicit_allow",
            request_digest=request.digest,
            policy_digest=policy_digest,
            matched_policy_ids=matched,
            obligations=obligations,
            required_approval_tier=approval_tier,
        )
