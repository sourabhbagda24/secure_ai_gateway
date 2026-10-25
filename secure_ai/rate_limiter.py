"""Rate limiting (request flood) + token budget (denial-of-wallet)."""
from __future__ import annotations

import time
from typing import Callable

from .errors import BudgetExceeded, RateLimitError


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class TokenBucket:
    def __init__(self, capacity: float, refill_per_sec: float,
                 clock: Callable[[], float] = time.monotonic):
        self.capacity, self.refill, self.clock = capacity, refill_per_sec, clock
        self.tokens, self.last = float(capacity), clock()

    def allow(self, cost: float = 1.0) -> bool:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.refill)
        self.last = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def retry_after(self, cost: float = 1.0) -> float:
        return max(0.0, (cost - self.tokens) / self.refill) if self.refill else float("inf")


class RateLimiter:
    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic):
        self.per_minute, self.clock = per_minute, clock
        self._buckets: dict[str, TokenBucket] = {}

    def check(self, user_id: str) -> None:
        b = self._buckets.setdefault(
            user_id, TokenBucket(self.per_minute, self.per_minute / 60.0, self.clock))
        if not b.allow():
            raise RateLimitError("too many requests", retry_after=round(b.retry_after(), 1))


class BudgetTracker:
    """Caps LLM tokens per user per day so an attacker cannot run up your bill."""

    def __init__(self, daily_budget: int, clock: Callable[[], float] = time.time):
        self.daily_budget, self.clock = daily_budget, clock
        self._used: dict[tuple[str, int], int] = {}

    def _key(self, user_id: str) -> tuple[str, int]:
        return user_id, int(self.clock() // 86400)

    def used(self, user_id: str) -> int:
        return self._used.get(self._key(user_id), 0)

    def check(self, user_id: str, tokens: int) -> None:
        if self.used(user_id) + tokens > self.daily_budget:
            raise BudgetExceeded("daily token budget exceeded",
                                 used=self.used(user_id), budget=self.daily_budget)

    def charge(self, user_id: str, tokens: int) -> None:
        k = self._key(user_id)
        self._used[k] = self._used.get(k, 0) + tokens
