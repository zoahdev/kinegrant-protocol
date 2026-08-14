from __future__ import annotations

from typing import Any, Iterable, Mapping

from ..models import PolicyRule
from ..obligations import KNOWN_OBLIGATIONS
from ..sequence import ForbiddenCombination, SequencePolicy

POLICY_FIELDS = {
    "@context", "@type", "type", "uid", "@id", "profile", "assigner",
    "permission", "prohibition", "kg:prohibitedCombination",
}
STATEMENT_FIELDS = {"target", "assigner", "assignee", "action", "constraint", "duty"}
CONSTRAINT_FIELDS = {"leftOperand", "operator", "rightOperand"}
DUTY_FIELDS = {"action"}
COMBINATION_FIELDS = {"uid", "patterns", "windowSeconds", "trigger"}
PATTERN_FIELDS = {"action", "target"}
KGP_ODRL_PROFILE = "https://kinegrant.com/profiles/odrl/kgp-v0.2"


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


def _constraints(
    items: Iterable[Any],
    *,
    allow_kgp: bool = False,
) -> tuple[dict[str, Any], tuple[str, ...]]:
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
        elif allow_kgp and left == "maxForceNewtons" and operator in {"eq", "lteq"}:
            if not isinstance(right, (int, float)) or isinstance(right, bool) or right < 0:
                raise ValueError("ODRL kg:maxForceNewtons must be a non-negative number")
            result["max_force_newtons"] = right
        elif allow_kgp and left == "maxVelocityMps" and operator in {"eq", "lteq"}:
            if not isinstance(right, (int, float)) or isinstance(right, bool) or right < 0:
                raise ValueError("ODRL kg:maxVelocityMps must be a non-negative number")
            result["max_velocity_mps"] = right
        elif allow_kgp and left == "allowedZones" and operator == "eq":
            zones = _list(right)
            if not zones or any(not isinstance(zone, str) or not zone for zone in zones):
                raise ValueError("ODRL kg:allowedZones must be a non-empty list of strings")
            result["allowed_zones"] = zones
        elif allow_kgp and left == "minApprovalTier" and operator == "eq":
            if not isinstance(right, int) or isinstance(right, bool) or not 0 <= right <= 2:
                raise ValueError("ODRL kg:minApprovalTier must be an integer between 0 and 2")
            result["min_approval_tier"] = right
        elif left in {"maxForceNewtons", "maxVelocityMps", "allowedZones", "minApprovalTier"}:
            raise ValueError(
                f"ODRL constraint {left} requires the KineGrant profile "
                f"{KGP_ODRL_PROFILE}"
            )
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
    allow_kgp = policy.get("profile") == KGP_ODRL_PROFILE
    if policy.get("kg:prohibitedCombination") is not None and not allow_kgp:
        raise ValueError(
            f"kg:prohibitedCombination requires the KineGrant profile {KGP_ODRL_PROFILE}"
        )
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
            constraints, purposes = _constraints(
                _list(statement.get("constraint")),
                allow_kgp=allow_kgp,
            )
            obligations_list: list[str] = []
            for item in _list(statement.get("duty")):
                if not isinstance(item, Mapping):
                    raise ValueError("ODRL duties must be objects")
                _reject_unknown_fields(item, DUTY_FIELDS, "ODRL duty")
                if item.get("action") is None:
                    raise ValueError("ODRL duty action is required")
                duty_action = _action(item.get("action"))
                if duty_action not in KNOWN_OBLIGATIONS:
                    raise ValueError(f"unsupported ODRL duty action: {duty_action}")
                obligations_list.append(duty_action)
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


def odrl_forbidden_combinations(
    policy: Mapping[str, Any],
) -> tuple[ForbiddenCombination, ...]:
    """Map the KGP ODRL extension ``kg:prohibitedCombination`` to sequence rules.

    The extension expresses cross-action invariants that ODRL 2.2 cannot
    express natively: a set of ``(action, target)`` patterns that must never
    all be observed, with an optional time window and an optional trigger
    pattern. Unknown or malformed members fail closed.
    """
    _reject_unknown_fields(policy, POLICY_FIELDS, "ODRL policy")
    allow_kgp = policy.get("profile") == KGP_ODRL_PROFILE
    raw_combinations = _list(policy.get("kg:prohibitedCombination"))
    if raw_combinations and not allow_kgp:
        raise ValueError(
            f"kg:prohibitedCombination requires the KineGrant profile {KGP_ODRL_PROFILE}"
        )
    result: list[ForbiddenCombination] = []
    for index, item in enumerate(raw_combinations):
        if not isinstance(item, Mapping):
            raise ValueError("kg:prohibitedCombination entries must be objects")
        _reject_unknown_fields(item, COMBINATION_FIELDS, "kg:prohibitedCombination")
        combination_id = _id(item.get("uid"), f"odrl:prohibited-combination:{index}")
        patterns_raw = item.get("patterns")
        if not isinstance(patterns_raw, list) or not patterns_raw:
            raise ValueError("kg:prohibitedCombination patterns must be a non-empty list")
        patterns: list[tuple[str, str]] = []
        for pattern in patterns_raw:
            if not isinstance(pattern, Mapping):
                raise ValueError("combination patterns must be objects")
            _reject_unknown_fields(pattern, PATTERN_FIELDS, "combination pattern")
            action = _id(pattern.get("action"), "")
            target = _id(pattern.get("target"), "")
            if not action or not target:
                raise ValueError("combination pattern requires action and target")
            patterns.append((action, target))
        window = item.get("windowSeconds")
        if window is not None and (
            not isinstance(window, int) or isinstance(window, bool) or window < 1
        ):
            raise ValueError("windowSeconds must be a positive integer or null")
        trigger_raw = item.get("trigger")
        trigger: tuple[str, str] | None = None
        if trigger_raw is not None:
            if not isinstance(trigger_raw, Mapping):
                raise ValueError("combination trigger must be an object")
            _reject_unknown_fields(trigger_raw, PATTERN_FIELDS, "combination trigger")
            action = _id(trigger_raw.get("action"), "")
            target = _id(trigger_raw.get("target"), "")
            if not action or not target:
                raise ValueError("combination trigger requires action and target")
            trigger = (action, target)
        result.append(
            ForbiddenCombination(
                combination_id,
                tuple(patterns),
                window_seconds=window,
                trigger=trigger,
            )
        )
    return tuple(result)


def odrl_to_sequence_policy(policy: Mapping[str, Any]) -> SequencePolicy:
    """Build a fail-closed :class:`SequencePolicy` from an ODRL policy document."""
    return SequencePolicy(odrl_forbidden_combinations(policy))


def _constraint_to_odrl(key: str, value: Any) -> dict[str, Any]:
    if key == "max_force_newtons":
        return {"leftOperand": "maxForceNewtons", "operator": "eq", "rightOperand": value}
    if key == "max_velocity_mps":
        return {"leftOperand": "maxVelocityMps", "operator": "eq", "rightOperand": value}
    if key == "allowed_zones":
        return {"leftOperand": "allowedZones", "operator": "eq", "rightOperand": value}
    if key == "min_approval_tier":
        return {"leftOperand": "minApprovalTier", "operator": "eq", "rightOperand": value}
    if key == "not_before":
        return {"leftOperand": "dateTime", "operator": "gt", "rightOperand": value}
    if key == "not_after":
        return {"leftOperand": "dateTime", "operator": "lt", "rightOperand": value}
    if key == "required_context" and isinstance(value, Mapping):
        return [
            {"leftOperand": operand, "operator": "eq", "rightOperand": right}
            for operand, right in value.items()
        ]
    raise ValueError(f"cannot serialize unknown KineGrant constraint: {key}")


def rules_to_odrl(
    rules: Iterable[PolicyRule],
    *,
    policy_uid: str,
    assigner: str,
    profile: str = KGP_ODRL_PROFILE,
    forbidden_combinations: Iterable[ForbiddenCombination] = (),
) -> dict[str, Any]:
    """Serialize KineGrant rules and sequence invariants into one ODRL document.

    The output uses the versioned ``kgp-v0.2`` profile so that parsing it back
    with :func:`odrl_to_rules` and :func:`odrl_forbidden_combinations` is a
    faithful round trip. Unknown obligations and constraints fail closed.
    """
    if not isinstance(policy_uid, str) or not policy_uid.strip():
        raise ValueError("policy_uid must be a non-empty string")
    if not isinstance(assigner, str) or not assigner.strip():
        raise ValueError("assigner must be a non-empty string")
    permission: list[dict[str, Any]] = []
    prohibition: list[dict[str, Any]] = []
    for rule in rules:
        statement: dict[str, Any] = {
            "target": rule.target,
            "assignee": list(rule.subjects),
            "action": list(rule.actions),
        }
        constraints: list[dict[str, Any]] = []
        for key, value in rule.constraints.items():
            mapped = _constraint_to_odrl(key, value)
            if isinstance(mapped, list):
                constraints.extend(mapped)
            else:
                constraints.append(mapped)
        if constraints:
            statement["constraint"] = constraints
        if rule.obligations:
            duties: list[dict[str, Any]] = []
            for obligation in rule.obligations:
                if obligation not in KNOWN_OBLIGATIONS:
                    raise ValueError(f"cannot serialize unknown obligation: {obligation}")
                duties.append({"action": obligation})
            statement["duty"] = duties
        if rule.effect == "allow":
            permission.append(statement)
        else:
            prohibition.append(statement)
    document: dict[str, Any] = {
        "@context": "http://www.w3.org/ns/odrl/2/",
        "@type": "Offer",
        "uid": policy_uid,
        "profile": profile,
        "assigner": assigner,
    }
    if permission:
        document["permission"] = permission
    if prohibition:
        document["prohibition"] = prohibition
    combinations = list(forbidden_combinations)
    if combinations:
        serialized: list[dict[str, Any]] = []
        for combination in combinations:
            entry: dict[str, Any] = {
                "uid": combination.combination_id,
                "patterns": [
                    {"action": action, "target": target}
                    for action, target in combination.patterns
                ],
            }
            if combination.window_seconds is not None:
                entry["windowSeconds"] = combination.window_seconds
            if combination.trigger is not None:
                entry["trigger"] = {
                    "action": combination.trigger[0],
                    "target": combination.trigger[1],
                }
            serialized.append(entry)
        document["kg:prohibitedCombination"] = serialized
    return document
