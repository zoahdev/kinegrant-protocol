"""Bounded policy-decision cache (v1.3 draft).

``CachedPolicyEngine`` wraps a :class:`PolicyEngine` with a bounded LRU cache.
Decisions are keyed by ``(policy_digest, request_digest)`` and the cache is
invalidated automatically whenever the underlying policy snapshot changes
(new rules or trust changes). Time-dependent ``future_request`` denials are
never cached: a request that is in the future can become valid later.

The cache returns the exact decision object produced by the wrapped engine,
so callers must treat decisions as immutable (as with the engine itself).
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from .models import ActionRequest, Decision
from .policy import PolicyEngine


class CachedPolicyEngine:
    """LRU decision cache over a policy engine, with hit/miss statistics."""

    def __init__(self, engine: PolicyEngine, *, capacity: int = 256) -> None:
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        self.engine = engine
        self.capacity = capacity
        self._cache: OrderedDict[tuple[str, str], Decision] = OrderedDict()
        self._policy_digest = engine._policy_digest()
        self.hits = 0
        self.misses = 0

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def clear(self) -> None:
        """Drop all cached decisions and reset statistics."""
        self._cache.clear()
        self._policy_digest = self.engine._policy_digest()
        self.hits = 0
        self.misses = 0

    def evaluate(self, request: ActionRequest, *, now: Any = None) -> Decision:
        policy_digest = self.engine._policy_digest()
        if policy_digest != self._policy_digest:
            self._cache.clear()
            self._policy_digest = policy_digest
        key = (policy_digest, request.digest)
        if now is None and key in self._cache:
            self.hits += 1
            self._cache.move_to_end(key)
            return self._cache[key]
        self.misses += 1
        decision = self.engine.evaluate(request, now=now)
        if now is None and decision.reason != "future_request":
            self._cache[key] = decision
            self._cache.move_to_end(key)
            while len(self._cache) > self.capacity:
                self._cache.popitem(last=False)
        return decision
