from __future__ import annotations

from typing import Any, Mapping


def trusted_context(system: Mapping[str, Any], supplied: Mapping[str, Any] | None) -> dict[str, Any]:
    """Merge caller context without allowing it to spoof adapter-owned fields."""
    user = dict(supplied or {})
    overlap = set(system).intersection(user)
    if overlap:
        raise ValueError(f"reserved adapter context keys: {', '.join(sorted(overlap))}")
    return {**user, **system}
