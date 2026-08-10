from __future__ import annotations

from typing import Any, Iterable, Mapping

from ..models import PolicyRule


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _id(value: Any, default: str = "*") -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        candidate = value.get("uid") or value.get("@id") or value.get("id")
        if isinstance(candidate, str):
            return candidate
    return default


def _action(value: Any) -> str:
    raw = _id(value)
    aliases = {
        "http://www.w3.org/ns/odrl/2/read": "observe",
        "http://www.w3.org/ns/odrl/2/use": "use",
        "http://www.w3.org/ns/odrl/2/reproduce": "record",
        "read": "observe",
        "reproduce": "record",
    }
    return aliases.get(raw, raw.rsplit("/", 1)[-1])


def _constraints(items: Iterable[Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    required_context: dict[str, Any] = {}
    purposes: list[str] = []
    result: dict[str, Any] = {}
    for item in items:
        if not isinstance(item, Mapping):
            continue
        left = _id(item.get("leftOperand"), "")
        operator = _id(item.get("operator"), "eq")
        right = item.get("rightOperand")
        left = left.rsplit("/", 1)[-1]
        operator = operator.rsplit("/", 1)[-1]
        if left == "purpose" and operator in {"eq", "isA"}:
            purposes.extend(str(value) for value in _list(right))
        elif left in {"dateTime", "elapsedTime"} and operator in {"lt", "lteq"}:
            result["not_after"] = right
        elif left == "dateTime" and operator in {"gt", "gteq"}:
            result["not_before"] = right
        elif operator == "eq" and left:
            required_context[left] = right
    if required_context:
        result["required_context"] = required_context
    return result, tuple(purposes or ["*"])


def odrl_to_rules(policy: Mapping[str, Any]) -> list[PolicyRule]:
    """Map a conservative ODRL 2.2 subset into KineGrant rules.

    Unknown constructs are ignored rather than guessed. Production deployments must
    validate the source document against an explicit ODRL profile before calling this.
    """
    policy_uid = _id(policy.get("uid") or policy.get("@id"), "odrl:anonymous")
    default_issuer = _id(policy.get("assigner"), "odrl:unknown-assigner")
    rules: list[PolicyRule] = []

    for effect, property_name in (("allow", "permission"), ("deny", "prohibition")):
        for index, statement in enumerate(_list(policy.get(property_name))):
            if not isinstance(statement, Mapping):
                continue
            target = _id(statement.get("target"))
            issuer = _id(statement.get("assigner"), default_issuer)
            subjects = tuple(_id(value) for value in _list(statement.get("assignee"))) or ("*",)
            actions = tuple(_action(value) for value in _list(statement.get("action")))
            if not actions:
                continue
            constraints, purposes = _constraints(_list(statement.get("constraint")))
            obligations = tuple(
                _action(item.get("action"))
                for item in _list(statement.get("duty"))
                if isinstance(item, Mapping) and item.get("action") is not None
            )
            rules.append(
                PolicyRule(
                    policy_id=f"{policy_uid}#{property_name}-{index}",
                    issuer=issuer,
                    target=target,
                    effect=effect,
                    actions=actions,
                    subjects=subjects,
                    purposes=purposes,
                    constraints=constraints,
                    obligations=obligations,
                    source={"standard": "W3C ODRL 2.2", "profile": policy.get("profile")},
                )
            )
    return rules
