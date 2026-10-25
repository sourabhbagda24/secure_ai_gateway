"""Small compliance helpers (consent + erasure) in the spirit of DPDP Act / GDPR.
This is engineering scaffolding, not legal advice."""
from __future__ import annotations

from .auth import Identity
from .memory import SecureMemory


class ConsentRegistry:
    def __init__(self):
        self._granted: set[str] = set()

    def grant(self, user_id: str) -> None:
        self._granted.add(user_id)

    def revoke(self, user_id: str) -> None:
        self._granted.discard(user_id)

    def has(self, user_id: str) -> bool:
        return user_id in self._granted


def erase_user_data(memory: SecureMemory, identity: Identity) -> int:
    """Right to erasure for stored memory. (Audit records are retained by policy.)"""
    return memory.forget(identity)
