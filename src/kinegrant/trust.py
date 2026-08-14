"""Trustworthy time groundwork (v0.4).

``TrustedClock`` wraps a time source and rejects time that moves backwards or
jumps forward beyond a configured bound. The reference system source is the
platform clock; production deployments replace it with a secure time source
(secure element, network time with attestation, or a trusted edge gateway).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable

from .models import utc_now


class TrustedClockError(RuntimeError):
    pass


class TrustedClock:
    def __init__(
        self,
        *,
        source: Callable[[], datetime] | None = None,
        max_forward_jump_seconds: int = 3600,
    ) -> None:
        if (
            not isinstance(max_forward_jump_seconds, int)
            or isinstance(max_forward_jump_seconds, bool)
            or max_forward_jump_seconds < 1
        ):
            raise ValueError("max_forward_jump_seconds must be a positive integer")
        self.source = source or utc_now
        self.max_forward_jump = timedelta(seconds=max_forward_jump_seconds)
        self._last: datetime | None = None

    def now(self) -> datetime:
        candidate = self.source()
        if not isinstance(candidate, datetime) or candidate.tzinfo is None:
            raise TrustedClockError("time source must return a timezone-aware datetime")
        if self._last is not None:
            if candidate < self._last:
                raise TrustedClockError(
                    f"time moved backwards: {candidate.isoformat()} < "
                    f"{self._last.isoformat()}"
                )
            if candidate - self._last > self.max_forward_jump:
                raise TrustedClockError(
                    f"time jumped forward beyond {self.max_forward_jump.total_seconds()}s"
                )
        self._last = candidate
        return candidate

    def reset(self) -> None:
        self._last = None
