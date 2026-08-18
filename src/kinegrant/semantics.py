"""Static policy analysis and decision explanation (v0.5).

``PolicyInvariants`` performs deterministic, documented static checks over a
policy snapshot: allow-all detection, deny-shadowed allows (heuristic glob
containment), empty policies, and untrusted allow rules. ``explain_decision``
re-walks the rules for one request and reports which rules applied, which were
excluded and why, and the resulting decision.

These are static-analysis aids, not a full formal model checker; the checks
are intentionally conservative (unknown containment is reported, not assumed).
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Iterable

from .models import ActionRequest, PolicyRule
from .policy import PolicyEngine, _constraints_hold, _matches


def _covers(pattern: str, candidate: str) -> bool | None:
    """Heuristic glob containment: does *pattern* cover *candidate*?

    Returns True/False for cases we can decide, None when unknown.
    """
    if pattern == "*" or pattern == candidate:
        return True
    if candidate == "*":
        return False
    if "*" not in pattern and "?" not in pattern and "[" not in pattern:
        return False
    if "*" not in candidate and "?" not in candidate and "[" not in candidate:
        return fnmatchcase(candidate, pattern)
    return None


def _set_covers(patterns: tuple[str, ...], candidates: tuple[str, ...]) -> bool | None:
    if "*" in patterns:
        return True
    if not candidates:
        return True
    result = True
    for candidate in candidates:
        found = False
        unknown = False
        for pattern in patterns:
            verdict = _covers(pattern, candidate)
            if verdict is True:
                found = True
                break
            if verdict is None:
                unknown = True
        if not found and unknown:
            return None
        if not found:
            return False
    return result


@dataclass(frozen=True)
class RuleInvariant:
    check: str
    rule_id: str | None
    passes: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "rule_id": self.rule_id,
            "passes": self.passes,
            "detail": self.detail,
        }


class PolicyInvariants:
    def __init__(
        self,
        rules: Iterable[PolicyRule],
        *,
        trusted_policy_issuers: set[str] | None = None,
    ) -> None:
        self.rules = tuple(rules)
        self.trusted_policy_issuers = set(trusted_policy_issuers or ())

    def analyze(self) -> tuple[RuleInvariant, ...]:
        findings: list[RuleInvariant] = []
        if not self.rules:
            findings.append(
                RuleInvariant("empty_policy", None, False, "policy has no rules")
            )
            return tuple(findings)

        for rule in self.rules:
            if rule.effect == "allow":
                if rule.issuer not in self.trusted_policy_issuers:
                    findings.append(
                        RuleInvariant(
                            "untrusted_allow",
                            rule.policy_id,
                            False,
                            "allow rule issuer is not trusted; the rule can never grant",
                        )
                    )
                if (
                    rule.actions == ("*",)
                    and rule.subjects == ("*",)
                    and rule.purposes == ("*",)
                    and rule.target == "*"
                ):
                    findings.append(
                        RuleInvariant(
                            "allow_all",
                            rule.policy_id,
                            False,
                            "rule allows every action, subject, purpose, and target",
                        )
                    )

        for allow in [rule for rule in self.rules if rule.effect == "allow"]:
            for deny in [rule for rule in self.rules if rule.effect == "deny"]:
                if allow.policy_id == deny.policy_id:
                    continue
                target_cover = _covers(deny.target, allow.target)
                actions_cover = _set_covers(deny.actions, allow.actions)
                subjects_cover = _set_covers(deny.subjects, allow.subjects)
                purposes_cover = _set_covers(deny.purposes, allow.purposes)
                if (
                    target_cover is True
                    and actions_cover is True
                    and subjects_cover is True
                    and purposes_cover is True
                ):
                    findings.append(
                        RuleInvariant(
                            "deny_shadows_allow",
                            allow.policy_id,
                            False,
                            f"allow can never win: deny rule {deny.policy_id} "
                            "applies on every matching request",
                        )
                    )
        return tuple(findings)


def explain_decision(
    engine: PolicyEngine,
    request: ActionRequest,
    *,
    now: Any = None,
) -> dict[str, Any]:
    """Explain one decision: applicable rules, exclusions, and outcome."""
    from .policy import _validate_rule

    current = now
    if current is None:
        from .models import utc_now

        current = utc_now()
    applicable: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for rule in engine.rules:
        _validate_rule(rule)
        reason = None
        if rule.effect == "allow" and rule.issuer not in engine.trusted_policy_issuers:
            reason = "untrusted_issuer"
        elif not _matches((rule.target,), request.target):
            reason = "target_mismatch"
        elif not _matches(rule.actions, request.action):
            reason = "action_mismatch"
        elif not _matches(rule.subjects, request.agent):
            reason = "subject_mismatch"
        elif not _matches(rule.purposes, request.purpose):
            reason = "purpose_mismatch"
        elif not _constraints_hold(rule, request, current):
            reason = "constraints_not_met"
        if reason is None:
            applicable.append(
                {
                    "policy_id": rule.policy_id,
                    "effect": rule.effect,
                    "priority": rule.priority,
                }
            )
        else:
            excluded.append({"policy_id": rule.policy_id, "reason": reason})
    decision = engine.evaluate(request, now=now)
    return {
        "decision": decision.to_dict(),
        "applicable_rules": applicable,
        "excluded_rules": excluded,
    }
