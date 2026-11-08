"""Unit tests for API Token Authentication and Policies.  OWNER: Mohammed Siraj."""
import pytest

from vaultlite.api.auth import AuthManager, hash_token, TOKEN_PREFIX
from vaultlite.api.policies import (
    ALL_CAPABILITIES,
    CAP_ADMIN,
    CAP_DELETE,
    CAP_LIST,
    CAP_READ,
    CAP_WRITE,
    PathRule,
    PolicyEngine,
)
from vaultlite.core.storage import Storage


@pytest.fixture
def storage():
    """In-memory storage fixture."""
    st = Storage(":memory:")
    yield st
    st.close()


@pytest.fixture
def auth_mgr(storage: Storage):
    """AuthManager backed by in-memory storage."""
    return AuthManager(storage)


# ------------------------------------------------------------- Policy Tests
def test_builtin_root_and_admin_policies():
    engine = PolicyEngine()
    for pol in ("root", "admin"):
        for cap in ALL_CAPABILITIES:
            assert engine.check_permission(pol, "db/password", cap) is True
            assert engine.check_permission(pol, "app/settings/key", cap) is True
            assert engine.check_permission(pol, "arbitrary/any/path", cap) is True


def test_builtin_dev_policies():
    engine = PolicyEngine()

    # dev-read: read & list on db/* and app/*
    assert engine.check_permission("dev-read", "db/password", CAP_READ) is True
    assert engine.check_permission("dev-read", "db/password", CAP_LIST) is True
    assert engine.check_permission("dev-read", "db/password", CAP_WRITE) is False
    assert engine.check_permission("dev-read", "db/password", CAP_DELETE) is False

    assert engine.check_permission("dev-read", "app/config", CAP_READ) is True
    assert engine.check_permission("dev-read", "sys/audit", CAP_READ) is False  # unlisted path

    # dev-write: read, write & list on db/* and app/*
    assert engine.check_permission("dev-write", "db/password", CAP_WRITE) is True
    assert engine.check_permission("dev-write", "db/password", CAP_DELETE) is False
    assert engine.check_permission("dev-write", "db/password", CAP_ADMIN) is False


def test_custom_policy_registration():
    engine = PolicyEngine()
    rule = PathRule(pattern="billing/*", capabilities=frozenset({CAP_READ}))
    engine.register_policy("finance", [rule])

    assert engine.check_permission("finance", "billing/stripe_key", CAP_READ) is True
    assert engine.check_permission("finance", "billing/stripe_key", CAP_WRITE) is False
    assert engine.check_permission("finance", "db/password", CAP_READ) is False

    with pytest.raises(ValueError, match="policy name must be non-empty"):
        engine.register_policy("", [rule])


def test_unknown_policy():
    engine = PolicyEngine()
    assert engine.check_permission("nonexistent-policy", "db/password", CAP_READ) is False


# --------------------------------------------------------------- Auth Tests
def test_token_creation_and_hash_isolation(auth_mgr: AuthManager, storage: Storage):
    raw_token = auth_mgr.create_token(policy="dev-read", description="CI Runner")
    assert raw_token.startswith(TOKEN_PREFIX)
    assert len(raw_token) == len(TOKEN_PREFIX) + 64

    # Raw token must NEVER exist in the database
    digest = hash_token(raw_token)
    stored_record = storage.get_token(digest)
    assert stored_record is not None
    assert stored_record["token_hash"] == digest
    assert stored_record["policy"] == "dev-read"
    assert stored_record["description"] == "CI Runner"
    assert stored_record["revoked"] is False

    # Verifying storage does not contain raw_token string anywhere in raw queries
    cursor = storage._conn.execute("SELECT * FROM tokens WHERE token_hash = ?", (raw_token,))
    assert cursor.fetchone() is None


def test_token_validation(auth_mgr: AuthManager):
    token = auth_mgr.create_token(policy="admin", description="Admin Token")

    valid_info = auth_mgr.validate_token(token)
    assert valid_info is not None
    assert valid_info["policy"] == "admin"
    assert valid_info["revoked"] is False

    # Tampered or unknown tokens
    assert auth_mgr.validate_token(token + "tamper") is None
    assert auth_mgr.validate_token("s.vaultlite_" + "a" * 64) is None
    assert auth_mgr.validate_token("invalid-prefix") is None
    assert auth_mgr.validate_token("") is None


def test_token_revocation(auth_mgr: AuthManager):
    token = auth_mgr.create_token(policy="dev-write", description="Dev Token")
    assert auth_mgr.validate_token(token) is not None

    # Revoke
    revoked = auth_mgr.revoke_token(token)
    assert revoked is True

    # Validate must now return None
    assert auth_mgr.validate_token(token) is None
    assert auth_mgr.check_access(token, "db/pass", CAP_READ) is False

    # Revoking again returns False
    assert auth_mgr.revoke_token(token) is False
    assert auth_mgr.revoke_token("s.vaultlite_unknown") is False


def test_check_access_integration(auth_mgr: AuthManager):
    admin_token = auth_mgr.create_token("admin")
    read_token = auth_mgr.create_token("dev-read")

    # Admin access
    assert auth_mgr.check_access(admin_token, "db/password", CAP_WRITE) is True
    assert auth_mgr.check_access(admin_token, "sys/keys", CAP_ADMIN) is True

    # Read-only token access
    assert auth_mgr.check_access(read_token, "db/password", CAP_READ) is True
    assert auth_mgr.check_access(read_token, "db/password", CAP_WRITE) is False
    assert auth_mgr.check_access(read_token, "finance/keys", CAP_READ) is False


def test_auth_validation_errors(auth_mgr: AuthManager):
    with pytest.raises(ValueError, match="unknown policy"):
        auth_mgr.create_token("nonexistent_policy")

    with pytest.raises(ValueError, match="policy must be a non-empty string"):
        auth_mgr.create_token("")

    with pytest.raises(ValueError, match="token must be a non-empty string"):
        hash_token("")
