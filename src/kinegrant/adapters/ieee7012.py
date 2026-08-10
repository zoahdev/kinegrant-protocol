from __future__ import annotations

from typing import Any, Mapping

from ..models import PolicyRule


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
    subject = str(document["subject"])
    issuer = str(document.get("issuer", subject))
    target = str(document.get("target", "*"))
    document_id = str(document.get("id", "myterms:anonymous"))
    terms = document.get("terms", [])
    if not isinstance(terms, list):
        raise ValueError("terms must be an array")

    rules: list[PolicyRule] = []
    for index, term in enumerate(terms):
        if not isinstance(term, Mapping):
            continue
        effect = str(term.get("effect", "deny"))
        if effect not in {"allow", "deny"}:
            raise ValueError("term effect must be allow or deny")
        action = str(term["action"])
        rules.append(
            PolicyRule(
                policy_id=f"{document_id}#term-{index}",
                issuer=issuer,
                target=str(term.get("target", target)),
                effect=effect,
                actions=(action,),
                subjects=_as_tuple(term.get("agents")),
                purposes=_as_tuple(term.get("purposes")),
                constraints=dict(term.get("constraints", {})),
                obligations=_as_tuple(term.get("obligations"), ()),
                source={"standard": "IEEE 7012-2025 bridge", "rights_subject": subject},
            )
        )
    return rules
