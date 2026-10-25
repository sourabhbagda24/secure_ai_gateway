import pytest

from secure_ai.auth import TokenService, authorize
from secure_ai.errors import AuthError, AuthzError
from secure_ai.demo_world import ALICE, BOB, ROOT

SECRET = b"unit-test-secret-1234567890"


def svc():
    return TokenService(SECRET)


def test_roundtrip():
    t = svc().issue("alice", "analyst", "acme")
    ident = svc().verify(t)
    assert (ident.user_id, ident.role, ident.tenant) == ("alice", "analyst", "acme")


def test_tampered_payload_rejected():
    t = svc().issue("bob", "viewer", "acme")
    body, sig = t.split(".")
    forged = svc().issue("bob", "admin", "acme").split(".")[0] + "." + sig  # role swap, old signature
    with pytest.raises(AuthError):
        svc().verify(forged)


def test_wrong_secret_rejected():
    t = TokenService(b"another-secret-1234567890").issue("a", "admin", "acme")
    with pytest.raises(AuthError):
        svc().verify(t)


def test_expired_token():
    t = svc().issue("a", "viewer", "acme", ttl=10, now=1000)
    with pytest.raises(AuthError, match="expired"):
        svc().verify(t, now=1011)
    assert svc().verify(t, now=1005).user_id == "a"


@pytest.mark.parametrize("bad", ["", "abc", "a.b.c", None, 123])
def test_malformed(bad):
    with pytest.raises(AuthError):
        svc().verify(bad)


def test_short_secret_refused():
    with pytest.raises(ValueError):
        TokenService(b"short")


def test_unknown_role_cannot_be_issued():
    with pytest.raises(ValueError):
        svc().issue("x", "superuser", "acme")


def test_least_privilege_matrix():
    authorize(BOB, "chat")
    with pytest.raises(AuthzError):
        authorize(BOB, "tool:send_email")
    with pytest.raises(AuthzError):
        authorize(ALICE, "tool:delete_record")
    authorize(ROOT, "tool:delete_record")
