from __future__ import annotations

from typing import Any, Mapping

from ..models import PolicyRule
from ..policy import SUPPORTED_CONSTRAINTS

DOCUMENT_FIELDS = {"id", "subject", "issuer", "target", "terms"}
TERM_FIELDS = {"action", "effect", "target", "agents", "purposes", "constraints", "obligations"}


def _as_tuple(value: Any, default: tuple[str, ...] = ("*",)) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return (str(value),)


def myterms_to_rules(document: Mapping[str, Any]) -> list[PolicyRule]:
    """Experimental bridge for a minimal IEEE 7012/MyTerms-style exchange.

    IEEE 7012 is not reproduced here. This adapter accepts the public KineGrant profile
    documented in spec/KGP-001.md and must not be advertised as certified compliance.
    """
    unknown_document_fields = set(document) - DOCUMENT_FIELDS
    if unknown_document_fields:
        raise ValueError(f"unsupported terms document fields: {', '.join(sorted(unknown_document_fields))}")
    subject = str(document["subject"])
    issuer = str(document.get("issuer", subject))
    document_target = document.get("target")
    document_id = str(document.get("id", "myterms:anonymous"))
    terms = document.get("terms", [])
    if not isinstance(terms, list):
        raise ValueError("terms must be an array")

    rules: list[PolicyRule] = []
    for index, term in enumerate(terms):
        if not isinstance(term, Mapping):
            raise ValueError("terms entries must be objects")
        unknown_term_fields = set(term) - TERM_FIELDS
        if unknown_term_fields:
            raise ValueError(f"unsupported term fields: {', '.join(sorted(unknown_term_fields))}")
        effect = str(term.get("effect", "deny"))
        if effect not in {"allow", "deny"}:
            raise ValueError("term effect must be allow or deny")
        if "action" not in term:
            raise ValueError("term action is required")
        action = str(term["action"])
        if effect == "allow" and "target" not in term and document_target is None:
            raise ValueError("allow term target must be explicit")
        if effect == "allow" and "agents" not in term:
            raise ValueError("allow term agents must be explicit")
        if effect == "allow" and "purposes" not in term:
            raise ValueError("allow term purposes must be explicit")
        constraints = term.get("constraints", {})
        if not isinstance(constraints, Mapping):
            raise ValueError("term constraints must be an object")
        unknown_constraints = set(constraints) - SUPPORTED_CONSTRAINTS
        if unknown_constraints:
            raise ValueError(
                f"unsupported term constraints: {', '.join(sorted(unknown_constraints))}"
            )
        rules.append(
            PolicyRule(
                policy_id=f"{document_id}#term-{index}",
                issuer=issuer,
                target=str(term.get("target", document_target if document_target is not None else "*")),
                effect=effect,
                actions=(action,),
                subjects=_as_tuple(term.get("agents")),
                purposes=_as_tuple(term.get("purposes")),
                constraints=dict(constraints),
                obligations=_as_tuple(term.get("obligations"), ()),
                source={"standard": "IEEE 7012-2025 bridge", "rights_subject": subject},
            )
        )
    return rules
