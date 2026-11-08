"""API Token Authentication and Authorization.  OWNER: Mohammed Siraj.

This module handles API token generation, cryptographic hashing, and
validation against the storage layer and policy engine.

Security invariants:
- Tokens are high-entropy random strings generated from the OS CSPRNG
  (secrets.token_bytes).
- Plaintext tokens are NEVER stored on disk. The database stores ONLY the
  SHA-256 digest of the token.
- Validation uses hmac.compare_digest() to prevent timing side channels.
- Revoked tokens are immediately denied.
"""
import hashlib
import hmac
import secrets
from typing import Any, Optional

from vaultlite.api.policies import PolicyEngine
from vaultlite.core.storage import Storage

TOKEN_PREFIX = "s.vaultlite_"
TOKEN_ENTROPY_BYTES = 32


def hash_token(raw_token: str) -> str:
    """Return the SHA-256 hexadecimal digest of a token string."""
    if not isinstance(raw_token, str) or not raw_token:
        raise ValueError("token must be a non-empty string")
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


class AuthManager:
    """Manages API token creation, validation, revocation, and access checks."""

    def __init__(self, storage: Storage, policy_engine: Optional[PolicyEngine] = None) -> None:
        self._storage = storage
        self._policies = policy_engine or PolicyEngine()

    @property
    def policies(self) -> PolicyEngine:
        """Return the attached policy engine."""
        return self._policies

    def create_token(self, policy: str, description: str = "") -> str:
        """Generate a fresh API token with an associated policy.

        The raw token is returned once and must be handed to the client.
        Only the SHA-256 hash is written to the database.
        """
        if not policy or not policy.strip():
            raise ValueError("policy must be a non-empty string")

        # Verify that policy exists
        if self._policies.get_policy(policy.strip()) is None:
            raise ValueError(f"unknown policy '{policy}'")

        # Generate token with 256 bits of CSPRNG entropy
        random_hex = secrets.token_bytes(TOKEN_ENTROPY_BYTES).hex()
        raw_token = f"{TOKEN_PREFIX}{random_hex}"

        # Hash and persist
        token_digest = hash_token(raw_token)
        self._storage.save_token(
            token_hash=token_digest,
            policy=policy.strip(),
            description=description.strip(),
        )

        return raw_token

    def validate_token(self, raw_token: str) -> Optional[dict[str, Any]]:
        """Validate a bearer token string.

        Returns token metadata dictionary if valid and active, or None if
        the token is unknown, malformed, or revoked.
        """
        if not isinstance(raw_token, str) or not raw_token.startswith(TOKEN_PREFIX):
            return None

        digest = hash_token(raw_token)
        record = self._storage.get_token(digest)
        if record is None:
            return None

        # Constant-time comparison
        if not hmac.compare_digest(digest, record["token_hash"]):
            return None

        # Check revocation
        if record["revoked"]:
            return None

        return record

    def revoke_token(self, raw_token: str) -> bool:
        """Revoke a token by its raw string. Returns True if found and revoked."""
        if not isinstance(raw_token, str) or not raw_token.startswith(TOKEN_PREFIX):
            return False
        digest = hash_token(raw_token)
        return self._storage.revoke_token(digest)

    def check_access(self, raw_token: str, path: str, capability: str) -> bool:
        """Validate token and check whether its policy allows `capability` on `path`."""
        token_info = self.validate_token(raw_token)
        if token_info is None:
            return False
        policy_name = token_info["policy"]
        return self._policies.check_permission(policy_name, path, capability)
