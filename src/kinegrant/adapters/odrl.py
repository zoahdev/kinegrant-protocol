from __future__ import annotations

from typing import Any, Iterable, Mapping

from ..models import PolicyRule

POLICY_FIELDS = {"@context", "@type", "type", "uid", "@id", "profile", "assigner", "permission", "prohibition"}
STATEMENT_FIELDS = {"target", "assigner", "assignee", "action", "constraint", "duty"}
CONSTRAINT_FIELDS = {"leftOperand", "operator", "rightOperand"}
DUTY_FIELDS = {"action"}


def _reject_unknown_fields(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unsupported {label} fields: {', '.join(sorted(unknown))}")


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


def _required_id(value: Any, field: str) -> str:
    result = _id(value, "")
    if not result:
        raise ValueError(f"ODRL {field} must contain an identifier")
    return result


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
            raise ValueError("ODRL constraints must be objects")
        _reject_unknown_fields(item, CONSTRAINT_FIELDS, "ODRL constraint")
        left = _id(item.get("leftOperand"), "")
        operator = _id(item.get("operator"), "eq")
        right = item.get("rightOperand")
        left = left.rsplit("/", 1)[-1]
        operator = operator.rsplit("/", 1)[-1]
        if right is None:
            raise ValueError("ODRL constraint rightOperand is required")
        if left == "purpose" and operator in {"eq", "isA"}:
            purposes.extend(str(value) for value in _list(right))
        elif left == "dateTime" and operator in {"lt", "lteq"}:
            result["not_after"] = right
        elif left == "dateTime" and operator in {"gt", "gteq"}:
            result["not_before"] = right
        elif operator == "eq" and left:
            required_context[left] = right
        else:
            # Silently dropping an unknown restriction from an allow statement
            # could widen permission. Reject the profile instead.
            raise ValueError(f"unsupported ODRL constraint: {left or '<missing>'} {operator}")
    if required_context:
        result["required_context"] = required_context
    return result, tuple(purposes or ["*"])


def odrl_to_rules(policy: Mapping[str, Any]) -> list[PolicyRule]:
    """Map a conservative ODRL 2.2 subset into KineGrant rules.

    Unsupported or malformed authorization semantics are rejected rather than
    guessed. This prevents an unknown restriction from widening permission.
    """
    _reject_unknown_fields(policy, POLICY_FIELDS, "ODRL policy")
    policy_uid = _id(policy.get("uid") or policy.get("@id"), "odrl:anonymous")
    default_issuer = _id(policy.get("assigner"), "odrl:unknown-assigner")
    rules: list[PolicyRule] = []

    for effect, property_name in (("allow", "permission"), ("deny", "prohibition")):
        for index, statement in enumerate(_list(policy.get(property_name))):
            if not isinstance(statement, Mapping):
                raise ValueError(f"ODRL {property_name} statements must be objects")
            _reject_unknown_fields(statement, STATEMENT_FIELDS, f"ODRL {property_name}")
            target = _required_id(statement.get("target"), "target")
            issuer = _id(statement.get("assigner"), default_issuer)
            if statement.get("assignee") is None:
                raise ValueError("ODRL assignee must be explicit; use '*' intentionally for a wildcard")
            subjects = tuple(_required_id(value, "assignee") for value in _list(statement.get("assignee")))
            actions = tuple(_action(value) for value in _list(statement.get("action")))
            if not actions:
                raise ValueError("ODRL action is required")
            constraints, purposes = _constraints(_list(statement.get("constraint")))
            obligations_list: list[str] = []
            for item in _list(statement.get("duty")):
                if not isinstance(item, Mapping):
                    raise ValueError("ODRL duties must be objects")
                _reject_unknown_fields(item, DUTY_FIELDS, "ODRL duty")
                if item.get("action") is None:
                    raise ValueError("ODRL duty action is required")
                obligations_list.append(_action(item.get("action")))
            obligations = tuple(obligations_list)
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
