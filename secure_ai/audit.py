"""Tamper-evident audit log (hash chain) + violation monitor (auto-suspend)."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import deque
from typing import Callable

from .pii_filter import redact


def _clean(value, depth=0):
    """Logs must never become a second data leak: redact strings, cap sizes."""
    if isinstance(value, str):
        return redact(value).text[:500]
    if isinstance(value, dict) and depth < 4:
        return {str(k): _clean(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)) and depth < 4:
        return [_clean(v, depth + 1) for v in value][:50]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:200]


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str | None = None, clock: Callable[[], float] = time.time):
        self.path, self.clock = path, clock
        self.records: list[dict] = []
        self._lock = threading.Lock()

    @staticmethod
    def _hash(prev: str, body: dict) -> str:
        return hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()

    def log(self, event: str, **fields) -> dict:
        with self._lock:
            prev = self.records[-1]["hash"] if self.records else self.GENESIS
            body = {"ts": round(self.clock(), 3), "event": event, "fields": _clean(fields)}
            record = {**body, "prev": prev, "hash": self._hash(prev, body)}
            self.records.append(record)
            if self.path:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record) + "\n")
            return record

    def events(self, name: str | None = None) -> list[dict]:
        return [r for r in self.records if name is None or r["event"] == name]

    def verify_chain(self) -> bool:
        for i, rec in enumerate(self.records):
            body = {k: rec[k] for k in ("ts", "event", "fields")}
            if rec["hash"] != self._hash(rec["prev"], body):
                return False
            if i and rec["prev"] != self.records[i - 1]["hash"]:
                return False
        return True

    def purge_older_than(self, seconds: float) -> int:
        """Retention policy. The remaining chain stays verifiable."""
        cutoff = self.clock() - seconds
        keep = [r for r in self.records if r["ts"] >= cutoff]
        removed = len(self.records) - len(keep)
        self.records = keep
        return removed


class SecurityMonitor:
    """Detect -> respond: too many violations in a window suspends the account."""

    def __init__(self, max_violations: int = 3, window_s: int = 600,
                 clock: Callable[[], float] = time.time):
        self.max_violations, self.window_s, self.clock = max_violations, window_s, clock
        self._events: dict[str, deque] = {}
        self._suspended: set[str] = set()

    def record(self, user_id: str, code: str) -> bool:
        now = self.clock()
        q = self._events.setdefault(user_id, deque())
        q.append((now, code))
        while q and now - q[0][0] > self.window_s:
            q.popleft()
        if len(q) >= self.max_violations:
            self._suspended.add(user_id)
        return user_id in self._suspended

    def is_suspended(self, user_id: str) -> bool:
        return user_id in self._suspended

    def reinstate(self, user_id: str) -> None:              # manual, human decision
        self._suspended.discard(user_id)
        self._events.pop(user_id, None)
