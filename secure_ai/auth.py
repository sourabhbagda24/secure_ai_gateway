"""Authentication (who are you?) and authorization (what may you do?).
Tokens are HMAC-SHA256 signed and expire. Roles map to least-privilege permissions."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from .errors import AuthError, AuthzError

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"chat", "rag:read", "tool:calculator"}),
    "analyst": frozenset({
        "chat", "rag:read", "memory:write",
        "tool:calculator", "tool:read_file", "tool:query_db",
        "tool:send_email", "tool:remember",
    }),
    "admin": frozenset({
        "chat", "rag:read", "memory:write",
        "tool:calculator", "tool:read_file", "tool:query_db",
        "tool:send_email", "tool:remember", "tool:delete_record",
    }),
}


@dataclass(frozen=True)
class Identity:
    user_id: str
    role: str
    tenant: str

    def has(self, permission: str) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.role, frozenset())


def authorize(identity: Identity, permission: str) -> None:
    if not identity.has(permission):
        raise AuthzError(f"role '{identity.role}' lacks permission '{permission}'",
                         permission=permission)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenService:
    def __init__(self, secret: bytes):
        if not secret or len(secret) < 16:
            raise ValueError("secret too short")
        self._secret = secret

    def _sign(self, body: str) -> str:
        return hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()

    def issue(self, user_id: str, role: str, tenant: str,
              ttl: int = 3600, now: float | None = None) -> str:
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown role {role!r}")
        now = time.time() if now is None else now
        payload = {"sub": user_id, "role": role, "tenant": tenant,
                   "iat": int(now), "exp": int(now + ttl)}
        body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        return f"{body}.{self._sign(body)}"

    def verify(self, token: str, now: float | None = None) -> Identity:
        if not isinstance(token, str) or token.count(".") != 1:
            raise AuthError("malformed token")
        body, sig = token.split(".")
        if not hmac.compare_digest(sig, self._sign(body)):   # constant-time compare
            raise AuthError("bad signature")
        try:
            payload = json.loads(_unb64(body))
            exp, role = int(payload["exp"]), payload["role"]
            user, tenant = str(payload["sub"]), str(payload["tenant"])
        except Exception as exc:  # noqa: BLE001
            raise AuthError("unreadable token payload") from exc
        if (time.time() if now is None else now) >= exp:
            raise AuthError("token expired")
        if role not in ROLE_PERMISSIONS:
            raise AuthError("unknown role in token")
        return Identity(user_id=user, role=role, tenant=tenant)
