"""WoT-style discovery for KineGrant targets.

KGP-001 section 3: discovery data MUST be authenticated before it can grant a
capability; unauthenticated discovery MAY only add restrictions. This module
enforces that boundary at registration time: an unauthenticated thing cannot
carry a policy pointer that would grant permission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .adapters.wot import describe_wot_actions


@dataclass(frozen=True)
class ThingActions:
    name: str
    title: str
    safe: bool
    idempotent: bool


@dataclass(frozen=True)
class DiscoveryResolution:
    thing_id: str
    actions: tuple[ThingActions, ...]
    policy_pointer: str | None
    authenticated: bool
    source: str

    def action(self, name: str) -> ThingActions:
        for item in self.actions:
            if item.name == name:
                return item
        raise KeyError(f"unknown action {name!r} on {self.thing_id}")


class ThingRegistry:
    """Authenticated WoT-style registry of KineGrant targets."""

    def __init__(self) -> None:
        self._things: dict[str, dict[str, Any]] = {}

    def register(
        self,
        description: Mapping[str, Any],
        *,
        policy_pointer: str | None = None,
        authenticated: bool = False,
        source: str = "wot-td",
    ) -> str:
        """Register a thing description.

        ``policy_pointer`` MAY only be set for authenticated sources.
        Unauthenticated discovery can only narrow later policy evaluation;
        it can never point at a grant.
        """
        actions = describe_wot_actions(description)
        thing_id = next(iter(actions.values()))["target"] if actions else None
        if thing_id is None:
            raise ValueError("thing description has no actions to discover")
        if thing_id in self._things:
            raise ValueError(f"thing {thing_id!r} is already registered")
        if policy_pointer is not None and not authenticated:
            raise ValueError(
                "unauthenticated discovery cannot carry a granting policy pointer"
            )
        normalized = {
            "actions": {
                name: ThingActions(
                    name=name,
                    title=str(metadata["title"]),
                    safe=bool(metadata["safe"]),
                    idempotent=bool(metadata["idempotent"]),
                )
                for name, metadata in actions.items()
            },
            "policy_pointer": policy_pointer,
            "authenticated": bool(authenticated),
            "source": source if isinstance(source, str) and source else "wot-td",
        }
        self._things[thing_id] = normalized
        return thing_id

    def resolve(self, thing_id: str) -> DiscoveryResolution:
        if thing_id not in self._things:
            raise ValueError(f"unknown thing {thing_id!r}")
        record = self._things[thing_id]
        return DiscoveryResolution(
            thing_id=thing_id,
            actions=tuple(record["actions"].values()),
            policy_pointer=record["policy_pointer"],
            authenticated=record["authenticated"],
            source=record["source"],
        )

    def list_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._things))

    def remove(self, thing_id: str) -> None:
        if thing_id not in self._things:
            raise ValueError(f"unknown thing {thing_id!r}")
        del self._things[thing_id]
