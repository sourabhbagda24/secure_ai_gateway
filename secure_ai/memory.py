"""Agent memory that resists poisoning: only user-confirmed writes, scanned, per-user."""
from __future__ import annotations

import time
from typing import Callable

from .auth import Identity, authorize
from .errors import MemoryPoisoning, ValidationError
from .injection_detector import scan_untrusted
from .input_validation import strip_invisible
from .pii_filter import redact


class SecureMemory:
    ALLOWED_SOURCES = {"user_confirmed"}

    def __init__(self, max_items: int = 20, max_chars: int = 300, ttl_s: int = 86_400,
                 threshold: int = 2, clock: Callable[[], float] = time.time):
        self.max_items, self.max_chars, self.ttl_s = max_items, max_chars, ttl_s
        self.threshold, self.clock = threshold, clock
        self._store: dict[tuple[str, str], list[tuple[float, str]]] = {}

    @staticmethod
    def _key(identity: Identity) -> tuple[str, str]:
        return identity.tenant, identity.user_id                # isolation per tenant+user

    def write(self, identity: Identity, text: str, source: str) -> None:
        authorize(identity, "memory:write")
        if source not in self.ALLOWED_SOURCES:
            raise MemoryPoisoning(f"memory writes from '{source}' are not allowed")
        text = strip_invisible(text).strip()
        if not text or len(text) > self.max_chars:
            raise ValidationError("memory entry empty or too long")
        if scan_untrusted(text, self.threshold).blocked:
            raise MemoryPoisoning("memory entry looks like an instruction/injection")
        items = self._store.setdefault(self._key(identity), [])
        items.append((self.clock(), redact(text).text))         # PII minimisation
        del items[:-self.max_items]

    def read(self, identity: Identity) -> list[str]:
        now = self.clock()
        items = [(t, s) for t, s in self._store.get(self._key(identity), []) if now - t < self.ttl_s]
        self._store[self._key(identity)] = items                # TTL / retention
        return [s for _, s in items]

    def forget(self, identity: Identity) -> int:
        """Right-to-erasure."""
        return len(self._store.pop(self._key(identity), []))
