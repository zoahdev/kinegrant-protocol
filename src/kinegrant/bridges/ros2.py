"""Reference ROS 2 action-gate wrapper and SROS2 policy mapping.

No ROS 2 runtime is required. ``Ros2GoalGate`` wraps :class:`ActionGate` with
an action-goal shaped API, and ``Sros2PolicyMapping`` renders KineGrant rules
as a deterministic, machine-readable SROS2-style security mapping. Both are
non-normative references, not certifications.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from xml.sax.saxutils import escape

from ..gate import ActionGate, VerifiedCapability
from ..models import ActionRequest, PolicyRule


class Ros2GoalGate:
    """Action-goal shaped view over a KineGrant action gate."""

    def __init__(self, gate: ActionGate) -> None:
        self.gate = gate

    def accept_goal(
        self,
        capability: Mapping[str, Any],
        request: ActionRequest,
        *,
        now: Any = None,
        parent_capability: Mapping[str, Any] | None = None,
    ) -> VerifiedCapability:
        """Verify and consume a capability as if accepting a ROS 2 action goal."""
        return self.gate.authorize(
            capability,
            request,
            now=now,
            parent_capability=parent_capability,
        )

    def try_accept_goal(
        self,
        capability: Mapping[str, Any],
        request: ActionRequest,
        *,
        parent_capability: Mapping[str, Any] | None = None,
    ) -> tuple[bool, VerifiedCapability | None, str | None]:
        """Non-raising goal acceptance: (accepted, verified, rejection_reason)."""
        try:
            verified = self.accept_goal(
                capability,
                request,
                parent_capability=parent_capability,
            )
            return True, verified, None
        except (PermissionError, ValueError) as exc:
            return False, None, f"{type(exc).__name__}: {exc}"


@dataclass(frozen=True)
class Sros2PolicyMapping:
    """Deterministic, non-normative SROS2-style mapping for KineGrant rules."""

    rules: tuple[PolicyRule, ...]
    domain: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.domain, int) or isinstance(self.domain, bool) or self.domain < 0:
            raise ValueError("domain must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        declarations = []
        for rule in sorted(self.rules, key=lambda item: (item.policy_id, item.actions)):
            for action in rule.actions:
                declarations.append(
                    {
                        "policy_id": rule.policy_id,
                        "action": action,
                        "effect": rule.effect,
                        "target_pattern": rule.target,
                        "subjects": list(rule.subjects),
                        "purposes": list(rule.purposes),
                        "topic_pattern": f"kg/{action}/goal",
                    }
                )
        return {
            "schema": "kinegrant:sros2-mapping:v0.1",
            "domain": self.domain,
            "enforcement": "enforce",
            "declarations": declarations,
            "note": (
                "Non-normative reference mapping. SROS2 conformance and "
                "certification are intentionally out of scope."
            ),
        }

    def to_xml(self) -> str:
        """Render a minimal SROS2-style XML policy document."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<policy version="0.2.0">',
            "  <enforcement>enforce</enforcement>",
            "  <profiles>",
        ]
        for rule in sorted(self.rules, key=lambda item: (item.policy_id, item.actions)):
            for action in rule.actions:
                lines.append('    <profile name="*">')
                lines.append(
                    f'      <topic>{escape(f"kg/{action}/goal")}</topic>'
                )
                lines.append(
                    "      <kgp>"
                    f"policy_id={escape(rule.policy_id)};effect={rule.effect}"
                    "</kgp>"
                )
                lines.append("    </profile>")
        lines.append("  </profiles>")
        lines.append("</policy>")
        return "\n".join(lines) + "\n"
