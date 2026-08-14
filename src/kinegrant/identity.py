"""Canonical KineGrant identifiers for agents, targets, and policies.

The grammar is deliberately narrow so identifiers are unambiguous across
implementations:

``urn:kinegrant:<kind>:<namespace>:<local-id>``

- ``kind`` is one of ``agent``, ``target``, ``policy``;
- ``namespace`` is lowercase letters, digits, ``-`` or ``.`` (1-63 chars);
- ``local-id`` is lowercase letters, digits, ``-``, ``_``, ``.``, ``:`` or ``#``
  (1-128 chars).

Examples:

- ``urn:kinegrant:agent:zoah:delivery-robot-07``
- ``urn:kinegrant:target:zoah:door-7``
- ``urn:kinegrant:policy:zoah:delivery-door#permission-0``
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

_KIND = r"(agent|target|policy)"
_NAMESPACE = r"[a-z0-9.-]{1,63}"
_LOCAL_ID = r"[a-z0-9._:#-]{1,128}"
_IDENTIFIER_RE = re.compile(
    rf"^urn:kinegrant:{_KIND}:({_NAMESPACE}):({_LOCAL_ID})$"
)
_NAMESPACE_RE = re.compile(rf"^{_NAMESPACE}$")
_LOCAL_ID_RE = re.compile(rf"^{_LOCAL_ID}$")


@dataclass(frozen=True)
class KineGrantIdentifier:
    kind: str
    namespace: str
    local_id: str

    @property
    def value(self) -> str:
        return f"urn:kinegrant:{self.kind}:{self.namespace}:{self.local_id}"


def validate_namespace(namespace: str) -> str:
    if not isinstance(namespace, str) or _NAMESPACE_RE.fullmatch(namespace) is None:
        raise ValueError(
            "namespace must be 1-63 chars of lowercase letters, digits, '-' or '.'"
        )
    return namespace


def validate_local_id(local_id: str) -> str:
    if not isinstance(local_id, str) or _LOCAL_ID_RE.fullmatch(local_id) is None:
        raise ValueError(
            "local_id must be 1-128 chars of lowercase letters, digits, "
            "'-', '_', '.', ':' or '#'"
        )
    return local_id


def _build(kind: str, namespace: str, local_id: str) -> str:
    return f"urn:kinegrant:{kind}:{validate_namespace(namespace)}:{validate_local_id(local_id)}"


def agent_id(namespace: str, local_id: str) -> str:
    return _build("agent", namespace, local_id)


def target_id(namespace: str, local_id: str) -> str:
    return _build("target", namespace, local_id)


def policy_id(namespace: str, local_id: str) -> str:
    return _build("policy", namespace, local_id)


def parse_identifier(value: str) -> KineGrantIdentifier:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{value!r} is not a valid KineGrant identifier")
    kind, namespace, local_id = _IDENTIFIER_RE.fullmatch(value).groups()
    return KineGrantIdentifier(kind, namespace, local_id)


def is_kinegrant_identifier(value: str) -> bool:
    return isinstance(value, str) and _IDENTIFIER_RE.fullmatch(value) is not None


def is_agent_id(value: str) -> bool:
    return is_kinegrant_identifier(value) and value.startswith("urn:kinegrant:agent:")


def is_target_id(value: str) -> bool:
    return is_kinegrant_identifier(value) and value.startswith("urn:kinegrant:target:")


def is_policy_id(value: str) -> bool:
    return is_kinegrant_identifier(value) and value.startswith("urn:kinegrant:policy:")


def _random_local_id() -> str:
    return secrets.token_hex(12)


def random_agent_id(namespace: str) -> str:
    return agent_id(namespace, _random_local_id())


def random_target_id(namespace: str) -> str:
    return target_id(namespace, _random_local_id())


def random_policy_id(namespace: str) -> str:
    return policy_id(namespace, _random_local_id())
