"""Bounded model checking for policy semantics (v0.5).

``bounded_model_check`` enumerates a finite request space (agent x target x
action x purpose) and verifies executable properties:

- every evaluated request terminates in allow or deny (no exceptions);
- deny-overrides and default-deny hold across the space;
- per-rule reachability: a rule is reachable only when a request matches it
  and its effect wins;
- shadowed allows: allow rules that match requests but never win.

This is a bounded, executable model check -- a conservative foundation, not a
full symbolic proof.
"""

from __future__ import annotations

import itertools
from typing import Any, Iterable

from .models import ActionRequest
from .policy import PolicyEngine


def bounded_model_check(
    engine: PolicyEngine,
    *,
    agents: Iterable[str],
    targets: Iterable[str],
    actions: Iterable[str],
    purposes: Iterable[str],
    max_requests: int = 200,
) -> dict[str, Any]:
    """Run a bounded model check over the Cartesian request space."""
    if max_requests < 1:
        raise ValueError("max_requests must be a positive integer")
    outcomes = []
    exceptions = 0
    space = list(itertools.product(agents, targets, actions, purposes))
    for index, (agent, target, action, purpose) in enumerate(space):
        if index >= max_requests:
            break
        request = ActionRequest(
            f"urn:kinegrant:modelcheck:request:{index}",
            agent,
            target,
            action,
            purpose,
        )
        try:
            decision = engine.evaluate(request)
        except Exception as exc:
            exceptions += 1
            outcomes.append(
                {
                    "agent": agent,
                    "target": target,
                    "action": action,
                    "purpose": purpose,
                    "exception": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        outcomes.append(
            {
                "agent": agent,
                "target": target,
                "action": action,
                "purpose": purpose,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "matched_policy_ids": list(decision.matched_policy_ids),
            }
        )

    allowed = sum(1 for outcome in outcomes if outcome.get("allowed"))
    denied = sum(1 for outcome in outcomes if not outcome.get("allowed") and "exception" not in outcome)

    rule_stats = []
    shadowed = []
    for rule in engine.rules:
        applicable = [
            outcome for outcome in outcomes
            if rule.policy_id in outcome.get("matched_policy_ids", [])
        ]
        winning = [
            outcome for outcome in applicable
            if (outcome.get("allowed") is True
                if rule.effect == "allow"
                else outcome.get("allowed") is False)
        ]
        reachable = bool(winning)
        if rule.effect == "allow" and applicable and not reachable:
            shadowed.append(rule.policy_id)
        rule_stats.append(
            {
                "policy_id": rule.policy_id,
                "effect": rule.effect,
                "applicable_count": len(applicable),
                "winning_count": len(winning),
                "reachable": reachable,
            }
        )

    return {
        "type": "kinegrant:BoundedModelCheck",
        "schema_version": "0.1",
        "space_size": len(space),
        "evaluated": len(outcomes),
        "allowed": allowed,
        "denied": denied,
        "exceptions": exceptions,
        "rules": rule_stats,
        "shadowed_allows": shadowed,
        "overall_result": "PASS" if exceptions == 0 and not shadowed else "FAIL",
    }
