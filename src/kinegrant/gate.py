from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from .canonical import content_id
from .crypto import verify_envelope
from .models import ActionRequest, parse_time, utc_now


class ActionGate:
    """Fail-closed verifier intended to sit immediately before an actuator call."""

    def __init__(self, *, trusted_issuers: set[str] | None = None) -> None:
        # An omitted trust store means trust nobody, not trust everybody.
        self.trusted_issuers = set(trusted_issuers or ())
        self._consumed: set[str] = set()

    def authorize(
        self,
        capability: Mapping[str, Any],
        request: ActionRequest,
        *,
        now: datetime | None = None,
        consume: bool = True,
    ) -> dict[str, Any]:
        payload = verify_envelope(capability)
        if payload.get("type") != "kinegrant:PhysicalActionCapability":
            raise PermissionError("wrong capability type")
        if payload.get("issuer") != capability.get("kid"):
            raise PermissionError("capability issuer does not match signing key")
        if payload.get("issuer") not in self.trusted_issuers:
            raise PermissionError("untrusted capability issuer")
        if payload.get("request_digest") != request.digest:
            raise PermissionError("capability does not authorize this request")

        for field in ("agent", "target", "action", "purpose"):
            if payload.get(field) != getattr(request, field):
                raise PermissionError(f"capability {field} mismatch")

        current = now or utc_now()
        if current < parse_time(payload["not_before"]):
            raise PermissionError("capability is not active yet")
        if current > parse_time(payload["expires_at"]):
            raise PermissionError("capability has expired")

        capability_id = payload.get("capability_id")
        if not isinstance(capability_id, str):
            raise PermissionError("capability has no identifier")
        unsigned_id_body = dict(payload)
        del unsigned_id_body["capability_id"]
        if capability_id != content_id("kinegrant:cap", unsigned_id_body):
            raise PermissionError("capability identifier is inconsistent")
        if capability_id in self._consumed:
            raise PermissionError("capability replay detected")
        if consume:
            self._consumed.add(capability_id)
        return payload
