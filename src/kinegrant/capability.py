from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Any

from .canonical import content_id, digest
from .crypto import Ed25519KeyPair
from .models import ActionRequest, Decision, isoformat, utc_now


class CapabilityIssuer:
    def __init__(self, key_pair: Ed25519KeyPair) -> None:
        self.key_pair = key_pair

    def issue(
        self,
        request: ActionRequest,
        decision: Decision,
        *,
        ttl_seconds: int = 30,
    ) -> dict[str, Any]:
        if not decision.allowed:
            raise PermissionError("cannot issue a capability for a denied request")
        if decision.request_digest != request.digest:
            raise ValueError("decision does not belong to this request")
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("capability TTL must be between 1 and 300 seconds")

        issued_at = utc_now()
        body = {
            "type": "kinegrant:PhysicalActionCapability",
            "version": "0.1",
            "issuer": self.key_pair.kid,
            "agent": request.agent,
            "target": request.target,
            "action": request.action,
            "purpose": request.purpose,
            "request_digest": request.digest,
            "policy_digest": digest(decision.to_dict()),
            "matched_policy_ids": list(decision.matched_policy_ids),
            "obligations": list(decision.obligations),
            "issued_at": isoformat(issued_at),
            "not_before": isoformat(issued_at),
            "expires_at": isoformat(issued_at + timedelta(seconds=ttl_seconds)),
            "nonce": secrets.token_urlsafe(18),
        }
        body["capability_id"] = content_id("kinegrant:cap", body)
        return self.key_pair.sign_envelope(body)
